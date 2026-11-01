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
use crate::session::{DEFAULT_SESSION_LIMIT, Session};
use crate::transcript::{Keys, ROLE_ACCEPT, ROLE_CLIENT, ROLE_SERVER, Transcript};
use crate::trust::{Admit, Gate, Trust, WaitingGate};

/// The method name: the `<method>` of `coqui-peer-<method>`, under which a trust store keeps the
/// keys of this method.
pub const METHOD: &str = "webcrypto";

/// The operating system's generator as a [`Random`].
#[must_use]
pub fn random() -> Random {
    Random::from_fn(|out| getrandom::fill(out).map_err(|_| coqui_peer::Error::Random))
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) identity: Identity,
    pub(crate) responders: Option<Admit>,
    pub(crate) initiators: Option<Admit>,
    pub(crate) max_message: usize,
    pub(crate) session_limit: u64,
    pub(crate) random: Random,
    pub(crate) random_replaced: bool,
    pub(crate) gate: Gate,
}

impl Config {
    pub(crate) fn new(identity: Identity) -> Self {
        Self {
            identity,
            responders: None,
            initiators: None,
            max_message: DEFAULT_MAX_MESSAGE,
            session_limit: DEFAULT_SESSION_LIMIT,
            random: crate::random(),
            random_replaced: false,
            gate: Gate::new(WaitingGate::default()),
        }
    }

    pub(crate) fn weakened(&self) -> Vec<Weakening> {
        let mut weakened = Vec::new();
        for (setting, admit) in [
            ("responders", &self.responders),
            ("initiators", &self.initiators),
        ] {
            if matches!(admit, Some(Admit::Any)) {
                weakened.push(Weakening::new(
                    setting,
                    "any-with-key-proof",
                    "pinned or store",
                ));
            }
        }
        if self.max_message > DEFAULT_MAX_MESSAGE {
            weakened.push(Weakening::new(
                "max_message",
                self.max_message.to_string(),
                DEFAULT_MAX_MESSAGE.to_string(),
            ));
        }
        if self.session_limit > DEFAULT_SESSION_LIMIT {
            weakened.push(Weakening::new(
                "session_limit",
                self.session_limit.to_string(),
                DEFAULT_SESSION_LIMIT.to_string(),
            ));
        }
        if self.random_replaced {
            weakened.push(Weakening::new("random", "caller's", "operating system's"));
        }
        let (gate, strict) = (self.gate.limits, WaitingGate::default());
        if gate.per_source > strict.per_source {
            weakened.push(Weakening::new(
                "waiting_gate.per_source",
                gate.per_source.to_string(),
                strict.per_source.to_string(),
            ));
        }
        if gate.interval < strict.interval {
            weakened.push(Weakening::new(
                "waiting_gate.interval",
                format!("{:?}", gate.interval),
                format!("{:?}", strict.interval),
            ));
        }
        weakened
    }
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
/// assert_eq!(at_server.open(&record)?.as_deref(), Some(&b"over the proven keys"[..]));
/// assert_eq!(at_server.open(&at_client.close()?)?, None);
/// at_server.verify_end()?;
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
        Self(Arc::new(Config::new(identity)))
    }

    /// Whom [`initiate`](Method::initiate) admits as the responder.
    #[must_use]
    pub fn with_responders(mut self, trust: Trust) -> Self {
        Arc::make_mut(&mut self.0).responders = Some(Admit::Trust(trust));
        self
    }

    /// Whom [`respond`](Method::respond) admits as the initiator.
    #[must_use]
    pub fn with_initiators(mut self, trust: Trust) -> Self {
        Arc::make_mut(&mut self.0).initiators = Some(Admit::Trust(trust));
        self
    }

    /// The longest handshake message accepted, before it is parsed; [`DEFAULT_MAX_MESSAGE`] by
    /// default. A value below what the messages need makes every handshake fail.
    #[must_use]
    pub fn with_max_message(mut self, bytes: usize) -> Self {
        Arc::make_mut(&mut self.0).max_message = bytes;
        self
    }

    /// What each direction of a session may carry, each record counting its length and 32;
    /// [`DEFAULT_SESSION_LIMIT`] by default. There is no rekeying: at the limit `seal` and `open`
    /// give [`Error::LimitReached`], a close record still passes, and a new handshake carries on.
    /// Above the default, AES-GCM's confidentiality margin shrinks.
    #[must_use]
    pub fn with_session_limit(mut self, bytes: u64) -> Self {
        Arc::make_mut(&mut self.0).session_limit = bytes;
        self
    }

    /// How proved strangers are recorded as waiting under [`Trust::Store`].
    #[must_use]
    pub fn with_waiting_gate(mut self, gate: WaitingGate) -> Self {
        Arc::make_mut(&mut self.0).gate = Gate::new(gate);
        self
    }

    /// Where nonces and ephemeral keys come from; the operating system by default. It must be
    /// cryptographically secure: a repeated ephemeral key or nonce breaks the session it is used
    /// for. A fixed source is for test vectors. It is reported by [`weakened`](WebCrypto::weakened).
    #[must_use]
    pub fn with_random(mut self, random: Random) -> Self {
        let config = Arc::make_mut(&mut self.0);
        config.random = random;
        config.random_replaced = true;
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
        self.0.weakened()
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
            .field("session_limit", &self.0.session_limit)
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
        Exchange::initiate(&self.0).map(WebCryptoHandshake)
    }

    /// Starts a handshake as the side that accepts. `source` goes with a waiting entry.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] without [`with_initiators`](WebCrypto::with_initiators).
    fn respond(&self, source: Option<SocketAddr>) -> Result<WebCryptoHandshake, Error> {
        Exchange::respond(&self.0, source).map(WebCryptoHandshake)
    }
}

fn nonce(random: &Random) -> Result<[u8; NONCE_LEN], Error> {
    let mut nonce = [0u8; NONCE_LEN];
    random.fill(&mut nonce).map_err(|_| Error::Random)?;
    Ok(nonce)
}

/// A fresh ephemeral key, on the heap so that moving it copies no secret; its `Drop` zeroes it.
fn ephemeral(random: &Random) -> Result<(Box<SecretKey>, Point), Error> {
    let secret = draw_scalar(random, |bytes| {
        SecretKey::from_slice(bytes).ok().map(Box::new)
    })?;
    let point = Point::of(secret.public_key());
    Ok((secret, point))
}

fn derive(transcript: &Transcript, secret: &SecretKey, peer: &Point) -> Result<Keys, Error> {
    let shared = secret.diffie_hellman(&peer.key);
    let bytes = Zeroizing::new(shared.raw_secret_bytes().to_vec());
    transcript.keys(&bytes)
}

/// Secrets sit behind pointers here, so `mem::replace` on the state moves none of their bytes.
enum State {
    AwaitChallenge {
        hello: Box<Hello>,
        secret: Box<SecretKey>,
    },
    AwaitAccept {
        transcript: Box<Transcript>,
        peer: Box<Spki>,
        keys: Keys,
    },
    AwaitHello,
    AwaitProof {
        transcript: Box<Transcript>,
        peer: Box<Spki>,
        peer_ephemeral: Box<Point>,
        secret: Box<SecretKey>,
    },
    Done,
    Failed,
}

/// What a finished exchange leaves, for the handshake type that wraps it.
pub(crate) struct Finished {
    pub(crate) peer: KeyMaterial,
    pub(crate) id: [u8; 32],
    pub(crate) keys: Keys,
    pub(crate) initiator: bool,
    pub(crate) identified: bool,
    pub(crate) limit: u64,
}

/// The state machine both public handshakes run.
pub(crate) struct Exchange {
    config: Arc<Config>,
    source: Option<SocketAddr>,
    binding: Vec<u8>,
    state: State,
    outbound: VecDeque<Vec<u8>>,
    result: Option<Finished>,
}

impl Exchange {
    pub(crate) fn initiate(config: &Arc<Config>) -> Result<Self, Error> {
        if config.responders.is_none() {
            return Err(Error::Unsupported);
        }
        let own_nonce = nonce(&config.random)?;
        let (secret, own) = ephemeral(&config.random)?;
        let hello = Box::new(Hello {
            public_key: config.identity.spki().clone(),
            ephemeral: own,
            nonce: own_nonce,
        });
        let outbound = VecDeque::from([hello.encode()]);
        Ok(Self {
            config: config.clone(),
            source: None,
            binding: Vec::new(),
            state: State::AwaitChallenge { hello, secret },
            outbound,
            result: None,
        })
    }

    pub(crate) fn respond(config: &Arc<Config>, source: Option<SocketAddr>) -> Result<Self, Error> {
        if config.initiators.is_none() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            config: config.clone(),
            source,
            binding: Vec::new(),
            state: State::AwaitHello,
            outbound: VecDeque::new(),
            result: None,
        })
    }

    pub(crate) fn local_key(&self) -> KeyMaterial {
        self.config.identity.key_material()
    }

    fn set_binding(&mut self, binding: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, State::AwaitHello | State::AwaitChallenge { .. }) {
            return Err(Error::State);
        }
        self.binding = binding.to_vec();
        Ok(())
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
                let transcript = Box::new(Transcript {
                    initiator_key: hello.public_key.der,
                    responder_key: identity.spki().der,
                    initiator_nonce: hello.nonce,
                    responder_nonce: own_nonce,
                    initiator_ephemeral: hello.ephemeral.bytes,
                    responder_ephemeral: own.bytes,
                    binding: self.binding.clone(),
                });
                let challenge = Challenge {
                    public_key: identity.spki().clone(),
                    ephemeral: own,
                    nonce: own_nonce,
                    signature: transcript.sign(identity.signing(), ROLE_SERVER),
                };
                self.outbound.push_back(challenge.encode());
                self.state = State::AwaitProof {
                    transcript,
                    peer: Box::new(hello.public_key),
                    peer_ephemeral: Box::new(hello.ephemeral),
                    secret,
                };
            }
            State::AwaitProof {
                transcript,
                peer,
                peer_ephemeral,
                secret,
            } => {
                let signature = decode_signature(input, "proof", max)?;
                transcript.verify(&peer.key, ROLE_CLIENT, &signature)?;
                let admit = config.initiators.as_ref().ok_or(Error::Unsupported)?;
                let material = key_material(&peer.der);
                if !admit.admits(&material, Some((&config.gate, self.source))) {
                    return Err(Error::Untrusted);
                }
                let keys = derive(&transcript, &secret, &peer_ephemeral)?;
                let signature = transcript.sign(identity.signing(), ROLE_ACCEPT);
                self.outbound
                    .push_back(encode_signature("accept", &signature));
                self.result = Some(Finished {
                    peer: material,
                    id: transcript.id(),
                    keys,
                    initiator: false,
                    identified: admit.identifies(),
                    limit: config.session_limit,
                });
                self.state = State::Done;
            }
            State::AwaitChallenge { hello, secret } => {
                let challenge = Challenge::decode(input, max)?;
                if challenge.public_key.der == identity.spki().der {
                    return Err(Error::Malformed);
                }
                let transcript = Box::new(Transcript {
                    initiator_key: hello.public_key.der,
                    responder_key: challenge.public_key.der,
                    initiator_nonce: hello.nonce,
                    responder_nonce: challenge.nonce,
                    initiator_ephemeral: hello.ephemeral.bytes,
                    responder_ephemeral: challenge.ephemeral.bytes,
                    binding: self.binding.clone(),
                });
                transcript.verify(&challenge.public_key.key, ROLE_SERVER, &challenge.signature)?;
                let admit = config.responders.as_ref().ok_or(Error::Unsupported)?;
                if !admit.admits(&key_material(&challenge.public_key.der), None) {
                    return Err(Error::Untrusted);
                }
                let keys = derive(&transcript, &secret, &challenge.ephemeral)?;
                let signature = transcript.sign(identity.signing(), ROLE_CLIENT);
                self.outbound
                    .push_back(encode_signature("proof", &signature));
                self.state = State::AwaitAccept {
                    transcript,
                    peer: Box::new(challenge.public_key),
                    keys,
                };
            }
            State::AwaitAccept {
                transcript,
                peer,
                keys,
            } => {
                let signature = decode_signature(input, "accept", max)?;
                transcript.verify(&peer.key, ROLE_ACCEPT, &signature)?;
                let admit = config.responders.as_ref().ok_or(Error::Unsupported)?;
                self.result = Some(Finished {
                    peer: key_material(&peer.der),
                    id: transcript.id(),
                    keys,
                    initiator: true,
                    identified: admit.identifies(),
                    limit: config.session_limit,
                });
                self.state = State::Done;
            }
            State::Done | State::Failed => return Err(Error::State),
        }
        Ok(())
    }

    pub(crate) fn receive(&mut self, input: &[u8]) -> Result<(), Error> {
        let result = self.step(input);
        if result.is_err() {
            // Nothing queued for a failed exchange leaves, and no key stays behind.
            self.outbound.clear();
            self.result = None;
        }
        result
    }

    pub(crate) fn transmit(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if matches!(self.state, State::Failed) {
            return Err(Error::State);
        }
        Ok(self.outbound.pop_front())
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Done) && self.outbound.is_empty()
    }

    pub(crate) fn finish(self) -> Result<Finished, Error> {
        if !self.is_complete() {
            return Err(Error::State);
        }
        self.result.ok_or(Error::State)
    }
}

/// One run of the [`WebCrypto`] method, driven by the caller. `Output` is the [`Session`].
pub struct WebCryptoHandshake(Exchange);

impl WebCryptoHandshake {
    /// Also binds this run to `binding`, a value of the outer channel both ends can read: a TLS
    /// exporter, when each end really terminates that TLS connection itself.
    ///
    /// It is never sent, and both signatures cover it, so two ends holding different values
    /// (a relay terminating TLS between them) fail with [`Error::BadProof`]. Leave it out for a
    /// connection through a TLS-terminating reverse proxy or from a browser, where no end can read
    /// the same value: the [`Session`] protects itself either way.
    ///
    /// # Errors
    ///
    /// [`Error::State`] after the first [`receive`](Handshake::receive): the transcript is fixed.
    pub fn with_binding(mut self, binding: &[u8]) -> Result<Self, Error> {
        self.0.set_binding(binding)?;
        Ok(self)
    }
}

impl fmt::Debug for WebCryptoHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebCryptoHandshake")
            .field("complete", &self.0.is_complete())
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
        self.0.receive(input)
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.0.transmit()
    }

    fn is_complete(&self) -> bool {
        self.0.is_complete()
    }

    fn finish(self) -> Result<Established<Session>, Error> {
        let Finished {
            peer,
            id,
            keys,
            initiator,
            limit,
            ..
        } = self.0.finish()?;
        Ok(Established {
            peer: peer.id(),
            key: Some(peer),
            session: Session::new(id, &keys, initiator, limit),
        })
    }
}
