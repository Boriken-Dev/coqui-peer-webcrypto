use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;
use core::net::SocketAddr;

use coqui_peer::{Established, Framing, Handshake, KeyMaterial, Method, Random, Weakening};
use p256::SecretKey;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::{Identity, draw_scalar, key_material};
use crate::message::{
    Challenge, DEFAULT_MAX_MESSAGE, Hello, NONCE_LEN, Point, Spki, decode_signature,
    encode_signature,
};
use crate::session::Session;
use crate::transcript::{Keys, ROLE_ACCEPT, ROLE_CLIENT, ROLE_SERVER, Transcript};
use crate::trust::Trust;

/// The method name: the `<method>` of `coqui-peer-<method>`, under which a trust store keeps the
/// keys of this method.
pub const METHOD: &str = "webcrypto";

/// The operating system's generator as a [`Random`].
#[must_use]
pub fn random() -> Random {
    Random::from_fn(|out| getrandom::fill(out).map_err(|_| coqui_peer::Error::Random))
}

#[derive(Debug, Clone)]
struct Config {
    identity: Identity,
    responders: Option<Trust>,
    initiators: Option<Trust>,
    max_message: usize,
    random: Random,
}

/// The WebCrypto method: an [`Identity`], and whom it admits in each role. Cloning shares it.
///
/// ```
/// use coqui_peer::{Handshake, Method};
/// use coqui_peer_webcrypto::{Identity, Trust, WebCrypto};
///
/// # fn main() -> Result<(), coqui_peer_webcrypto::Error> {
/// let (dialer, listener) = (Identity::generate()?, Identity::generate()?);
/// let client = WebCrypto::new(dialer.clone()).with_responders(Trust::pinned([listener.peer_id()]));
/// let server = WebCrypto::new(listener).with_initiators(Trust::pinned([dialer.peer_id()]));
///
/// let (mut dialing, mut listening) = (client.initiate()?, server.respond(None)?);
/// while !(dialing.is_complete() && listening.is_complete()) {
///     while let Some(message) = dialing.transmit()? {
///         listening.receive(&message)?;
///     }
///     while let Some(message) = listening.transmit()? {
///         dialing.receive(&message)?;
///     }
/// }
/// let mut at_client = dialing.finish()?.session;
/// let mut at_server = listening.finish()?.session;
/// assert_eq!(at_client.id(), at_server.id());
/// let record = at_client.seal(b"over the proven keys")?;
/// assert_eq!(at_server.open(&record)?, b"over the proven keys");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WebCrypto(Arc<Config>);

impl WebCrypto {
    /// A method for `identity`, configured for neither role until
    /// [`with_responders`](WebCrypto::with_responders) or
    /// [`with_initiators`](WebCrypto::with_initiators).
    #[must_use]
    pub fn new(identity: Identity) -> Self {
        Self(Arc::new(Config {
            identity,
            responders: None,
            initiators: None,
            max_message: DEFAULT_MAX_MESSAGE,
            random: crate::random(),
        }))
    }

    /// Whom [`initiate`](Method::initiate) admits as the responder.
    #[must_use]
    pub fn with_responders(mut self, trust: Trust) -> Self {
        Arc::make_mut(&mut self.0).responders = Some(trust);
        self
    }

    /// Whom [`respond`](Method::respond) admits as the initiator.
    #[must_use]
    pub fn with_initiators(mut self, trust: Trust) -> Self {
        Arc::make_mut(&mut self.0).initiators = Some(trust);
        self
    }

    /// The longest handshake message accepted, before it is parsed; [`DEFAULT_MAX_MESSAGE`] by
    /// default. A value below what the messages need makes every handshake fail.
    #[must_use]
    pub fn with_max_message(mut self, bytes: usize) -> Self {
        Arc::make_mut(&mut self.0).max_message = bytes;
        self
    }

    /// Where nonces and ephemeral keys come from; the operating system by default. It must be
    /// cryptographically secure: a repeated ephemeral key or nonce breaks the session it is used
    /// for. A fixed source is for test vectors.
    #[must_use]
    pub fn with_random(mut self, random: Random) -> Self {
        Arc::make_mut(&mut self.0).random = random;
        self
    }

    /// This method's identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.0.identity
    }

    /// The settings looser than their strict default.
    #[must_use]
    pub fn weakened(&self) -> Vec<Weakening> {
        let mut weakened = Vec::new();
        for (setting, trust) in [
            ("responders", &self.0.responders),
            ("initiators", &self.0.initiators),
        ] {
            if matches!(trust, Some(Trust::AnyWithKeyProof)) {
                weakened.push(Weakening::new(
                    setting,
                    "any-with-key-proof",
                    "pinned or store",
                ));
            }
        }
        if self.0.max_message > DEFAULT_MAX_MESSAGE {
            weakened.push(Weakening::new(
                "max_message",
                self.0.max_message.to_string(),
                DEFAULT_MAX_MESSAGE.to_string(),
            ));
        }
        weakened
    }
}

impl fmt::Debug for WebCrypto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebCrypto")
            .field("identity", &self.0.identity)
            .field("responders", &self.0.responders)
            .field("initiators", &self.0.initiators)
            .field("max_message", &self.0.max_message)
            .finish_non_exhaustive()
    }
}

impl Method for WebCrypto {
    type Handshake = WebCryptoHandshake;

    fn name(&self) -> &'static str {
        METHOD
    }

    /// Starts a handshake as the side that dials; the hello is ready at once.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] without [`with_responders`](WebCrypto::with_responders),
    /// [`Error::Random`] when the generator fails.
    fn initiate(&self) -> Result<WebCryptoHandshake, Error> {
        if self.0.responders.is_none() {
            return Err(Error::Unsupported);
        }
        let own_nonce = nonce(&self.0.random)?;
        let (secret, own) = ephemeral(&self.0.random)?;
        let hello = Hello {
            public_key: self.0.identity.spki().clone(),
            ephemeral: own,
            nonce: own_nonce,
        };
        let outbound = VecDeque::from([hello.encode()]);
        Ok(WebCryptoHandshake {
            config: self.0.clone(),
            source: None,
            binding: Vec::new(),
            state: State::AwaitChallenge(Box::new((hello, secret))),
            outbound,
            result: None,
        })
    }

    /// Starts a handshake as the side that accepts. `source` goes with a waiting entry.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] without [`with_initiators`](WebCrypto::with_initiators).
    fn respond(&self, source: Option<SocketAddr>) -> Result<WebCryptoHandshake, Error> {
        if self.0.initiators.is_none() {
            return Err(Error::Unsupported);
        }
        Ok(WebCryptoHandshake {
            config: self.0.clone(),
            source,
            binding: Vec::new(),
            state: State::AwaitHello,
            outbound: VecDeque::new(),
            result: None,
        })
    }
}

fn nonce(random: &Random) -> Result<[u8; NONCE_LEN], Error> {
    let mut nonce = [0u8; NONCE_LEN];
    random.fill(&mut nonce).map_err(|_| Error::Random)?;
    Ok(nonce)
}

fn ephemeral(random: &Random) -> Result<(SecretKey, Point), Error> {
    let secret = draw_scalar(random, |bytes| SecretKey::from_slice(bytes).ok())?;
    let point = Point::of(secret.public_key());
    Ok((secret, point))
}

fn derive(transcript: &Transcript, secret: &SecretKey, peer: &Point) -> Result<Keys, Error> {
    let shared = secret.diffie_hellman(&peer.key);
    let bytes = Zeroizing::new(shared.raw_secret_bytes().to_vec());
    transcript.keys(&bytes)
}

enum State {
    AwaitChallenge(Box<(Hello, SecretKey)>),
    AwaitAccept(Box<(Transcript, Spki, Keys)>),
    AwaitHello,
    AwaitProof(Box<(Transcript, Spki, Point, SecretKey)>),
    Done,
    Failed,
}

/// One run of the [`WebCrypto`] method, driven by the caller. `Output` is the [`Session`].
pub struct WebCryptoHandshake {
    config: Arc<Config>,
    source: Option<SocketAddr>,
    binding: Vec<u8>,
    state: State,
    outbound: VecDeque<Vec<u8>>,
    result: Option<(KeyMaterial, Session)>,
}

impl WebCryptoHandshake {
    /// Also binds this run to `binding`, a value of the outer channel both ends can read: a TLS
    /// exporter, when each end really terminates that TLS connection itself.
    ///
    /// It is never sent, and both signatures cover it, so two ends holding different values
    /// (a relay terminating TLS between them) fail with [`Error::BadProof`]. Leave it out for a
    /// connection through a TLS-terminating reverse proxy or from a browser, where no end can read
    /// the same value: the [`Session`] protects itself either way. Call it before the first
    /// [`receive`](Handshake::receive).
    #[must_use]
    pub fn with_binding(mut self, binding: &[u8]) -> Self {
        self.binding = binding.to_vec();
        self
    }

    fn step(&mut self, input: &[u8]) -> Result<(), Error> {
        let config = self.config.clone();
        let identity = &config.identity;
        let max = config.max_message;
        match core::mem::replace(&mut self.state, State::Failed) {
            State::AwaitHello => {
                let hello = Hello::decode(input, max)?;
                if hello.public_key.der == identity.spki().der {
                    return Err(Error::Malformed);
                }
                let own_nonce = nonce(&config.random)?;
                let (secret, own) = ephemeral(&config.random)?;
                let transcript = Transcript {
                    initiator_key: hello.public_key.der,
                    responder_key: identity.spki().der,
                    initiator_nonce: hello.nonce,
                    responder_nonce: own_nonce,
                    initiator_ephemeral: hello.ephemeral.bytes,
                    responder_ephemeral: own.bytes,
                    binding: self.binding.clone(),
                };
                let challenge = Challenge {
                    public_key: identity.spki().clone(),
                    ephemeral: own,
                    nonce: own_nonce,
                    signature: transcript.sign(identity.signing(), ROLE_SERVER),
                };
                self.outbound.push_back(challenge.encode());
                self.state = State::AwaitProof(Box::new((
                    transcript,
                    hello.public_key,
                    hello.ephemeral,
                    secret,
                )));
            }
            State::AwaitProof(state) => {
                let (transcript, peer, peer_ephemeral, secret) = *state;
                let signature = decode_signature(input, "proof", max)?;
                transcript.verify(&peer.key, ROLE_CLIENT, &signature)?;
                let trust = config.initiators.as_ref().ok_or(Error::Unsupported)?;
                let material = key_material(&peer.der);
                if !trust.admits(&material, Some(self.source)) {
                    return Err(Error::Untrusted);
                }
                let keys = derive(&transcript, &secret, &peer_ephemeral)?;
                let signature = transcript.sign(identity.signing(), ROLE_ACCEPT);
                self.outbound
                    .push_back(encode_signature("accept", &signature));
                self.result = Some((
                    material,
                    Session::new(transcript.id(), keys, false, trust.identifies()),
                ));
                self.state = State::Done;
            }
            State::AwaitChallenge(state) => {
                let (hello, secret) = *state;
                let challenge = Challenge::decode(input, max)?;
                if challenge.public_key.der == identity.spki().der {
                    return Err(Error::Malformed);
                }
                let transcript = Transcript {
                    initiator_key: hello.public_key.der,
                    responder_key: challenge.public_key.der,
                    initiator_nonce: hello.nonce,
                    responder_nonce: challenge.nonce,
                    initiator_ephemeral: hello.ephemeral.bytes,
                    responder_ephemeral: challenge.ephemeral.bytes,
                    binding: self.binding.clone(),
                };
                transcript.verify(&challenge.public_key.key, ROLE_SERVER, &challenge.signature)?;
                let trust = config.responders.as_ref().ok_or(Error::Unsupported)?;
                if !trust.admits(&key_material(&challenge.public_key.der), None) {
                    return Err(Error::Untrusted);
                }
                let keys = derive(&transcript, &secret, &challenge.ephemeral)?;
                let signature = transcript.sign(identity.signing(), ROLE_CLIENT);
                self.outbound
                    .push_back(encode_signature("proof", &signature));
                self.state = State::AwaitAccept(Box::new((transcript, challenge.public_key, keys)));
            }
            State::AwaitAccept(state) => {
                let (transcript, peer, keys) = *state;
                let signature = decode_signature(input, "accept", max)?;
                transcript.verify(&peer.key, ROLE_ACCEPT, &signature)?;
                let trust = config.responders.as_ref().ok_or(Error::Unsupported)?;
                self.result = Some((
                    key_material(&peer.der),
                    Session::new(transcript.id(), keys, true, trust.identifies()),
                ));
                self.state = State::Done;
            }
            State::Done | State::Failed => return Err(Error::State),
        }
        Ok(())
    }
}

impl fmt::Debug for WebCryptoHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebCryptoHandshake")
            .field("complete", &self.is_complete())
            .finish_non_exhaustive()
    }
}

impl Handshake for WebCryptoHandshake {
    type Output = Session;
    type Error = Error;

    fn framing(&self) -> Framing {
        Framing::Message
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Error> {
        let result = self.step(input);
        if result.is_err() {
            // Nothing queued for a failed exchange leaves, and no key stays behind.
            self.outbound.clear();
            self.result = None;
        }
        result
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if matches!(self.state, State::Failed) {
            return Err(Error::State);
        }
        Ok(self.outbound.pop_front())
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, State::Done) && self.outbound.is_empty()
    }

    fn finish(self) -> Result<Established<Session>, Error> {
        if !self.is_complete() {
            return Err(Error::State);
        }
        let (key, session) = self.result.ok_or(Error::State)?;
        Ok(Established {
            peer: key.id(),
            key: Some(key),
            session,
        })
    }
}
