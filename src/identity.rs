use alloc::sync::Arc;
use core::fmt;
use std::io;
use std::path::Path;

use coqui_peer::file::{self, Access};
use coqui_peer::{KeyMaterial, PeerId, Random, pem};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::handshake::METHOD;
use crate::message::{SPKI_LEN, Spki};

const PEM_LABEL: &str = "PRIVATE KEY";
/// The label a [`KeyMaterial`] of this method carries, what standard tools read an SPKI under.
const KEY_LABEL: &str = "PUBLIC KEY";
/// Drawing an invalid scalar has a chance near 2^-32, so a source that keeps doing it is broken.
const DRAWS: usize = 8;

struct Inner {
    signing: SigningKey,
    spki: Spki,
}

/// A peer's long-term P-256 key. Cloning shares one copy of the private key, which is zeroed
/// when the last clone is dropped.
#[derive(Clone)]
pub struct Identity(Arc<Inner>);

/// A secret scalar drawn from `random`.
pub(crate) fn draw_scalar<T>(
    random: &Random,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Result<T, Error> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    for _ in 0..DRAWS {
        random.fill(&mut *bytes).map_err(|_| Error::Random)?;
        if let Some(value) = parse(&*bytes) {
            return Ok(value);
        }
    }
    Err(Error::Random)
}

impl Identity {
    fn from_signing(signing: SigningKey) -> Self {
        let spki = Spki::of(signing.verifying_key());
        Self(Arc::new(Inner { signing, spki }))
    }

    /// A new key from the operating system's generator.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the generator fails.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(&crate::random())
    }

    /// A new key from `random`, which must be cryptographically secure.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the source fails.
    pub fn generate_with(random: &Random) -> Result<Self, Error> {
        draw_scalar(random, |bytes| SigningKey::from_slice(bytes).ok()).map(Self::from_signing)
    }

    /// The key in a PKCS#8 DER document.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not a P-256 private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        SigningKey::from_pkcs8_der(der)
            .map(Self::from_signing)
            .map_err(|_| Error::Key)
    }

    /// The key in PKCS#8 PEM text (`-----BEGIN PRIVATE KEY-----`), as `openssl genpkey` writes it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not a P-256 private key.
    pub fn from_pkcs8_pem(text: &str) -> Result<Self, Error> {
        let mut block = pem::decode(text).ok_or(Error::Key)?;
        let identity = if block.label == PEM_LABEL {
            Self::from_pkcs8_der(&block.bytes)
        } else {
            Err(Error::Key)
        };
        block.bytes.zeroize();
        identity
    }

    /// The key as PKCS#8 PEM text, zeroed when dropped.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it cannot be encoded.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, Error> {
        let der = self.0.signing.to_pkcs8_der().map_err(|_| Error::Key)?;
        Ok(Zeroizing::new(pem::encode(PEM_LABEL, der.as_bytes())))
    }

    /// The key in the file at `path`, or `None` when there is no file.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when it cannot be read, [`Error::Key`] when it is not such a key.
    pub fn read(path: &Path) -> Result<Option<Self>, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_pkcs8_pem(&Zeroizing::new(text)).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Writes the key to a new file at `path`, creating its parents. It never replaces a file.
    /// The file is mode `0600` on Unix; on Windows it inherits its directory's ACL.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], of kind `AlreadyExists` when the file exists.
    pub fn write_new(&self, path: &Path) -> Result<(), Error> {
        let pem = self.to_pkcs8_pem()?;
        file::write_new(path, pem.as_bytes(), Access::OwnerOnly)?;
        Ok(())
    }

    /// The key in the file at `path`, generating and writing one when there is none. Of concurrent
    /// creators one wins, and the others read its key.
    ///
    /// # Errors
    ///
    /// As [`read`](Identity::read), [`generate`](Identity::generate) and
    /// [`write_new`](Identity::write_new).
    pub fn open_or_create(path: &Path) -> Result<Self, Error> {
        if let Some(identity) = Self::read(path)? {
            return Ok(identity);
        }
        let identity = Self::generate()?;
        match identity.write_new(path) {
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::read(path)?.ok_or(Error::Key)
            }
            Err(error) => Err(error),
            Ok(()) => Ok(identity),
        }
    }

    /// This peer's id: the SHA-256 of [`spki_der`](Identity::spki_der).
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        PeerId::of(&self.0.spki.der)
    }

    /// The public key, as SubjectPublicKeyInfo DER: always 91 bytes, with an uncompressed point.
    #[must_use]
    pub fn spki_der(&self) -> &[u8; SPKI_LEN] {
        &self.0.spki.der
    }

    /// The public key as a trust store holds it: method `webcrypto`, label `PUBLIC KEY`.
    #[must_use]
    pub fn key_material(&self) -> KeyMaterial {
        key_material(&self.0.spki.der)
    }

    pub(crate) fn signing(&self) -> &SigningKey {
        &self.0.signing
    }

    pub(crate) fn spki(&self) -> &Spki {
        &self.0.spki
    }
}

/// The trust store's form of a proven key.
pub(crate) fn key_material(der: &[u8; SPKI_LEN]) -> KeyMaterial {
    KeyMaterial {
        method: METHOD.to_owned(),
        label: KEY_LABEL.to_owned(),
        bytes: der.to_vec(),
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identity")
            .field(&self.peer_id())
            .finish()
    }
}
