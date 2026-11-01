use core::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use coqui_peer::KeyMaterial;
use coqui_peer::pair::Channel;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::Identity;
use crate::message::PROFILE;
use crate::transcript::Keys;

/// The export label [`Session::pair_channel`] binds a pairing to.
pub const PAIR_EXPORT_LABEL: &str = "EXPORTER-coqui-pair";

/// One direction: AES-256-GCM under its own key, the nonce being the record's position.
struct Direction {
    cipher: Aes256Gcm,
    sequence: u64,
    over: bool,
}

impl Direction {
    fn new(key: &Zeroizing<[u8; 32]>) -> Self {
        let mut bytes = Zeroizing::new(Key::<Aes256Gcm>::default());
        bytes.copy_from_slice(&**key);
        Self {
            cipher: Aes256Gcm::new(&bytes),
            sequence: 0,
            over: false,
        }
    }

    fn nonce(&mut self) -> Result<Nonce<aes_gcm::aead::consts::U12>, Error> {
        if self.over || self.sequence == u64::MAX {
            self.over = true;
            return Err(Error::Record);
        }
        let mut nonce = Nonce::<aes_gcm::aead::consts::U12>::default();
        nonce[4..].copy_from_slice(&self.sequence.to_be_bytes());
        self.sequence += 1;
        Ok(nonce)
    }
}

/// The sending half of a [`Session`].
pub struct Sealer(Direction);

impl Sealer {
    /// One message as one record, to send whole and in this order.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] once the sequence numbers ran out or the cipher refused the length.
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.0.nonce()?;
        self.0.cipher.encrypt(&nonce, message).map_err(|_| {
            self.0.over = true;
            Error::Record
        })
    }
}

/// The receiving half of a [`Session`].
pub struct Opener(Direction);

impl Opener {
    /// The message of the next record.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] when the record was altered, replayed, reordered or made under other
    /// keys. Every later call fails too: nothing after a bad record is believed.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.0.nonce()?;
        self.0.cipher.decrypt(&nonce, record).map_err(|_| {
            self.0.over = true;
            Error::Record
        })
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealer")
    }
}

impl fmt::Debug for Opener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Opener")
    }
}

/// What a finished handshake yields: the id and the keys of this session.
///
/// Only records made with it are tied to the peers that were proved. Anything sent beside them on
/// the same transport comes from whoever controls that transport: a reverse proxy, or a relay that
/// forwarded the whole handshake.
pub struct Session {
    id: [u8; 32],
    sealer: Sealer,
    opener: Opener,
    exporter: Zeroizing<[u8; 32]>,
    trusted: bool,
}

impl Session {
    pub(crate) fn new(id: [u8; 32], keys: Keys, initiator: bool, trusted: bool) -> Self {
        let (sending, receiving) = if initiator {
            (&keys.initiator, &keys.responder)
        } else {
            (&keys.responder, &keys.initiator)
        };
        Self {
            id,
            sealer: Sealer(Direction::new(sending)),
            opener: Opener(Direction::new(receiving)),
            exporter: keys.exporter.clone(),
            trusted,
        }
    }

    /// The id both ends agreed on: a hash of both keys, both nonces, both ephemeral keys and any
    /// outer binding, all of which both signatures cover. It is not secret, since whoever carried
    /// the handshake can compute it; [`export`](Session::export) is.
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// One message as one record, to send whole and in this order.
    ///
    /// # Errors
    ///
    /// See [`Sealer::seal`].
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sealer.seal(message)
    }

    /// The message of the next record.
    ///
    /// # Errors
    ///
    /// See [`Opener::open`].
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, Error> {
        self.opener.open(record)
    }

    /// The two directions apart, for a reader and a writer on different threads. Take any export
    /// first.
    #[must_use]
    pub fn split(self) -> (Sealer, Opener) {
        (self.sealer, self.opener)
    }

    /// Fills `out` with key material only this session's two peers can derive, the same for the
    /// same `label` on both sides and unrelated for another label.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] above 8160 bytes, what HKDF-SHA256 can give.
    pub fn export(&self, label: &str, out: &mut [u8]) -> Result<(), Error> {
        let info = format!("{PROFILE}/export/{label}");
        Hkdf::<Sha256>::new(None, &*self.exporter)
            .expand(info.as_bytes(), out)
            .map_err(|_| Error::TooLong)
    }

    /// Whether [`Trust`](crate::Trust) admitted the peer by a pin or a store. With
    /// [`Trust::AnyWithKeyProof`](crate::Trust::AnyWithKeyProof) this is false: the peer proved
    /// a key and is nobody yet.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        self.trusted
    }

    /// The [`Channel`] a [`coqui_peer::pair`] exchange runs on: `local` this side's key, `remote`
    /// the key the handshake proved ([`Established::key`](coqui_peer::Established)), `verified`
    /// from [`is_trusted`](Session::is_trusted) and `binding` a 32-byte export under
    /// [`PAIR_EXPORT_LABEL`], so the pairing is tied to this session and not to any TLS connection
    /// beneath it. Carry the exchange's messages inside this session.
    ///
    /// # Errors
    ///
    /// None in practice: 32 bytes are within what [`export`](Session::export) gives.
    pub fn pair_channel(&self, local: &Identity, remote: KeyMaterial) -> Result<Channel, Error> {
        let mut binding = vec![0u8; 32];
        self.export(PAIR_EXPORT_LABEL, &mut binding)?;
        Ok(Channel {
            local: local.key_material(),
            remote: Some(remote),
            verified: self.trusted,
            binding: Some(binding),
        })
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("trusted", &self.trusted)
            .finish_non_exhaustive()
    }
}
