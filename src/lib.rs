//! Native responder for the browser coqui-peer P-256 / SPKI wire profile.
//! Transport framing and buffering belong to coqui-net-transport.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use coqui_peer::{Established, Framing, Handshake, KeyMaterial, Method, PeerId, TrustStore};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

pub const PROFILE: &str = "dev.boriken.coqui.peer-webcrypto/v1";
pub const METHOD_NAME: &str = "p256-spki";
const MAX_MESSAGE: usize = 3072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    InvalidMessage,
    InvalidProof,
    Untrusted,
    Unsupported,
    Crypto,
}
impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ProofError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    profile: String,
    version: u32,
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
    nonce: Option<String>,
    signature: Option<String>,
}

fn packet(raw: &[u8], kind: &str) -> Result<Packet, ProofError> {
    if raw.len() > MAX_MESSAGE {
        return Err(ProofError::InvalidMessage);
    }
    let value: Packet = serde_json::from_slice(raw).map_err(|_| ProofError::InvalidMessage)?;
    if value.profile != PROFILE || value.version != 1 || value.kind != kind {
        return Err(ProofError::InvalidMessage);
    }
    Ok(value)
}

fn decode(text: &str, max: usize, exact: Option<usize>) -> Result<Vec<u8>, ProofError> {
    if text.len() > 1024 {
        return Err(ProofError::InvalidMessage);
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| ProofError::InvalidMessage)?;
    if bytes.len() > max || exact.is_some_and(|n| bytes.len() != n) ||
       URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(ProofError::InvalidMessage);
    }
    Ok(bytes)
}

fn peer_key(encoded: &str) -> Result<(VerifyingKey, KeyMaterial), ProofError> {
    let der = decode(encoded, 256, None)?;
    let key = VerifyingKey::from_public_key_der(&der).map_err(|_| ProofError::InvalidMessage)?;
    let canonical = key.to_public_key_der().map_err(|_| ProofError::InvalidMessage)?;
    if canonical.as_bytes() != der {
        return Err(ProofError::InvalidMessage);
    }
    let material = KeyMaterial::new(METHOD_NAME, "PUBLIC KEY", der)
        .map_err(|_| ProofError::InvalidMessage)?;
    Ok((key, material))
}

fn nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

struct Transcript {
    initiator_spki: Vec<u8>,
    responder_spki: Vec<u8>,
    initiator_nonce: [u8; 32],
    responder_nonce: [u8; 32],
}
impl Transcript {
    fn bytes(&self, role: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for field in [
            PROFILE.as_bytes(),
            role.as_bytes(),
            &self.initiator_spki,
            &self.responder_spki,
            &self.initiator_nonce,
            &self.responder_nonce,
        ] {
            result.extend_from_slice(&(field.len() as u32).to_be_bytes());
            result.extend_from_slice(field);
        }
        result
    }

    fn sign(&self, signing: &SigningKey, role: &str) -> String {
        let signature: Signature = signing.sign(&self.bytes(role));
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    fn verify(&self, key: &VerifyingKey, role: &str, encoded: &str) -> Result<(), ProofError> {
        let bytes = decode(encoded, 64, Some(64))?;
        let signature = Signature::from_slice(&bytes).map_err(|_| ProofError::InvalidProof)?;
        key.verify(&self.bytes(role), &signature).map_err(|_| ProofError::InvalidProof)
    }
}

#[derive(Clone)]
pub struct WebCryptoMethod {
    signing: SigningKey,
    der: Vec<u8>,
    permitted: Arc<BTreeSet<PeerId>>,
    store: Option<TrustStore>,
}
impl fmt::Debug for WebCryptoMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebCryptoMethod")
            .field("peer_id", &self.peer_id())
            .field("permitted_count", &self.permitted.len())
            .field("uses_store", &self.store.is_some())
            .finish()
    }
}
impl WebCryptoMethod {
    pub fn new(signing: SigningKey, permitted: BTreeSet<PeerId>) -> Result<Self, ProofError> {
        let der = signing.verifying_key().to_public_key_der()
            .map_err(|_| ProofError::Crypto)?.as_bytes().to_vec();
        Ok(Self { signing, der, permitted: Arc::new(permitted), store: None })
    }

    pub fn generate(permitted: BTreeSet<PeerId>) -> Result<Self, ProofError> {
        Self::new(SigningKey::random(&mut OsRng), permitted)
    }

    /// Read trust and revocations from the canonical coqui-peer TrustStore
    /// on each verified connection, rather than snapshotting an allowlist.
    pub fn with_trust_store(signing: SigningKey, store: TrustStore) -> Result<Self, ProofError> {
        let mut method = Self::new(signing, BTreeSet::new())?;
        method.store = Some(store);
        Ok(method)
    }

    fn accepts(&self, material: &KeyMaterial) -> bool {
        if let Some(store) = &self.store {
            return store.accepted_key(&material.id()).as_ref() == Some(material);
        }
        self.permitted.contains(&material.id())
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::of(&self.der)
    }
    pub fn public_der(&self) -> &[u8] {
        &self.der
    }
}
impl Method for WebCryptoMethod {
    type Handshake = WebCryptoHandshake;
    fn name(&self) -> &'static str {
        METHOD_NAME
    }
    fn initiate(&self) -> Result<Self::Handshake, ProofError> {
        Err(ProofError::Unsupported)
    }
    fn respond(&self, _source: Option<SocketAddr>) -> Result<Self::Handshake, ProofError> {
        Ok(WebCryptoHandshake {
            method: self.clone(),
            state: State::Hello,
            outbound: VecDeque::new(),
            peer: None,
        })
    }
}

enum State {
    Hello,
    Proof {
        transcript: Box<Transcript>,
        public: VerifyingKey,
        material: KeyMaterial,
    },
    Done,
    Failed,
}

pub struct WebCryptoHandshake {
    method: WebCryptoMethod,
    state: State,
    outbound: VecDeque<Vec<u8>>,
    peer: Option<KeyMaterial>,
}
impl fmt::Debug for WebCryptoHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebCryptoHandshake")
            .field("complete", &self.is_complete())
            .finish_non_exhaustive()
    }
}
impl Handshake for WebCryptoHandshake {
    type Output = ();
    type Error = ProofError;

    fn framing(&self) -> Framing {
        Framing::Message
    }
    fn receive(&mut self, input: &[u8]) -> Result<(), ProofError> {
        let state = std::mem::replace(&mut self.state, State::Failed);
        match state {
            State::Hello => {
                let message = packet(input, "hello")?;
                let (public, material) = peer_key(
                    message.public_key.as_deref().ok_or(ProofError::InvalidMessage)?
                )?;
                let initiator_nonce: [u8; 32] = decode(
                    message.nonce.as_deref().ok_or(ProofError::InvalidMessage)?, 32, Some(32)
                )?.try_into().map_err(|_| ProofError::InvalidMessage)?;
                let transcript = Transcript {
                    initiator_spki: material.bytes.clone(),
                    responder_spki: self.method.der.clone(),
                    initiator_nonce,
                    responder_nonce: nonce(),
                };
                let challenge = json!({
                    "profile": PROFILE, "version": 1, "type": "challenge",
                    "publicKey": URL_SAFE_NO_PAD.encode(&self.method.der),
                    "nonce": URL_SAFE_NO_PAD.encode(transcript.responder_nonce),
                    "signature": transcript.sign(&self.method.signing, "server"),
                });
                self.outbound.push_back(
                    serde_json::to_vec(&challenge).map_err(|_| ProofError::InvalidMessage)?
                );
                self.state = State::Proof { transcript: Box::new(transcript), public, material };
                Ok(())
            }
            State::Proof { transcript, public, material } => {
                let message = packet(input, "proof")?;
                transcript.verify(
                    &public, "client",
                    message.signature.as_deref().ok_or(ProofError::InvalidMessage)?
                )?;
                if !self.method.accepts(&material) {
                    return Err(ProofError::Untrusted);
                }
                let accepted = json!({
                    "profile": PROFILE, "version": 1, "type": "accept",
                    "signature": transcript.sign(&self.method.signing, "accept"),
                });
                self.outbound.push_back(
                    serde_json::to_vec(&accepted).map_err(|_| ProofError::InvalidMessage)?
                );
                self.peer = Some(material);
                self.state = State::Done;
                Ok(())
            }
            State::Done | State::Failed => Err(ProofError::InvalidMessage),
        }
    }
    fn transmit(&mut self) -> Result<Option<Vec<u8>>, ProofError> {
        if matches!(self.state, State::Failed) {
            return Err(ProofError::InvalidMessage);
        }
        Ok(self.outbound.pop_front())
    }
    fn is_complete(&self) -> bool {
        matches!(self.state, State::Done) && self.outbound.is_empty()
    }
    fn finish(self) -> Result<Established<Self::Output>, ProofError> {
        if !self.is_complete() {
            return Err(ProofError::InvalidMessage);
        }
        let key = self.peer.ok_or(ProofError::InvalidMessage)?;
        Ok(Established { peer: key.id(), key: Some(key), session: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trust_store_acceptance_and_revocation_apply_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let client = WebCryptoMethod::generate(BTreeSet::new()).unwrap();
        let material = KeyMaterial::new(METHOD_NAME, "PUBLIC KEY", client.public_der()).unwrap();
        let signing = SigningKey::random(&mut OsRng);
        let server = WebCryptoMethod::with_trust_store(signing, store.clone()).unwrap();
        assert!(!server.accepts(&material));
        assert_eq!(store.accept_key(&material).unwrap(), client.peer_id());
        assert!(server.accepts(&material));
        assert!(store.remove(&client.peer_id()).unwrap());
        assert!(!server.accepts(&material));
    }

    #[test]
    fn unauthorised_key_is_not_paired() {
        let server = WebCryptoMethod::generate(BTreeSet::new()).unwrap();
        let mut handshake = server.respond(None).unwrap();
        assert!(handshake.transmit().unwrap().is_none());
        assert!(!handshake.is_complete());
        assert!(handshake.finish().is_err());
    }
}
