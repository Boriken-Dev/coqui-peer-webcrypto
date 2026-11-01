//! What both sides sign, the session id it names, and the keys derived from it.

use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::message::{NONCE_LEN, POINT_LEN, PROFILE, SPKI_LEN};

pub(crate) const ROLE_SERVER: &str = "server";
pub(crate) const ROLE_CLIENT: &str = "client";
pub(crate) const ROLE_ACCEPT: &str = "accept";

/// One AES-256 key per direction and the secret exports are drawn from.
pub(crate) struct Keys {
    pub(crate) initiator: Zeroizing<[u8; 32]>,
    pub(crate) responder: Zeroizing<[u8; 32]>,
    pub(crate) exporter: Zeroizing<[u8; 32]>,
}

/// Everything either side contributed, and the optional outer binding, which is never sent.
pub(crate) struct Transcript {
    pub(crate) initiator_key: [u8; SPKI_LEN],
    pub(crate) responder_key: [u8; SPKI_LEN],
    pub(crate) initiator_nonce: [u8; NONCE_LEN],
    pub(crate) responder_nonce: [u8; NONCE_LEN],
    pub(crate) initiator_ephemeral: [u8; POINT_LEN],
    pub(crate) responder_ephemeral: [u8; POINT_LEN],
    pub(crate) binding: Vec<u8>,
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

impl Transcript {
    fn tail(&self, out: &mut Vec<u8>) {
        field(out, &self.initiator_key);
        field(out, &self.responder_key);
        field(out, &self.initiator_nonce);
        field(out, &self.responder_nonce);
        field(out, &self.initiator_ephemeral);
        field(out, &self.responder_ephemeral);
        field(out, &self.binding);
    }

    /// The bytes signed for `role`.
    pub(crate) fn signed(&self, role: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        field(&mut out, PROFILE.as_bytes());
        field(&mut out, role.as_bytes());
        self.tail(&mut out);
        out
    }

    /// The session id: the same bytes without a role, hashed. Every signature covers what it
    /// hashes, so both ends holding one id means both signed for the same two keys.
    pub(crate) fn id(&self) -> [u8; 32] {
        let mut out = Vec::with_capacity(512);
        field(&mut out, PROFILE.as_bytes());
        self.tail(&mut out);
        Sha256::digest(&out).into()
    }

    pub(crate) fn sign(&self, key: &SigningKey, role: &str) -> Signature {
        key.sign(&self.signed(role))
    }

    pub(crate) fn verify(
        &self,
        key: &VerifyingKey,
        role: &str,
        signature: &Signature,
    ) -> Result<(), Error> {
        key.verify(&self.signed(role), signature)
            .map_err(|_| Error::BadProof)
    }

    /// The session keys from the ECDH shared secret, the point's x coordinate.
    pub(crate) fn keys(&self, shared: &[u8]) -> Result<Keys, Error> {
        let info = format!("{PROFILE}/keys");
        let mut okm = Zeroizing::new([0u8; 96]);
        Hkdf::<Sha256>::new(Some(&self.id()), shared)
            .expand(info.as_bytes(), &mut *okm)
            .map_err(|_| Error::TooLong)?;
        let mut keys = Keys {
            initiator: Zeroizing::new([0; 32]),
            responder: Zeroizing::new([0; 32]),
            exporter: Zeroizing::new([0; 32]),
        };
        keys.initiator.copy_from_slice(&okm[..32]);
        keys.responder.copy_from_slice(&okm[32..64]);
        keys.exporter.copy_from_slice(&okm[64..]);
        Ok(keys)
    }
}
