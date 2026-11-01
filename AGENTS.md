# `coqui-peer-webcrypto` — API header

Header-file-style reference for the `coqui-peer-webcrypto` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It ships inside
the package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer-webcrypto>.

| Feature | Adds | Needed for | Default |
| --- | --- | --- | --- |
| `pin` | `coqui-peer/pin` (SPAKE2, HKDF, HMAC) | PIN pairing (`pair::Pairing::pin`) | off |

MSRV Rust 1.89. A default build depends on `coqui-peer` (`=0.0.0-alpha.1`), `p256`, `aes-gcm`, `hkdf`,
`sha2`, `data-encoding`, `serde`, `serde_json`, `getrandom` and `zeroize`. Version `0.0.0-alpha.0` is
a pre-release with no independent security review; the wire and API may change in any release before
1.0. This is the method named `webcrypto` of `coqui-peer` (`PeerId`, `TrustStore`, the sans-IO
`Handshake`, `pair`); its API header ships in that crate. `PROTOCOL.md` ships here and is the wire.

Imports: everything is at the crate root, including re-exports of `coqui-peer`'s `Established`,
`KeyMaterial`, `Method`, `PeerId`, `Random`, `TrustStore`, `Weakening` and its module `pair`.

No `unsafe` code (`#![forbid(unsafe_code)]`), no process-wide state. Nothing reads a file or an
environment variable unless the caller names a path. Secrets are zeroed when dropped.

## Identity (`coqui_peer_webcrypto::Identity`)

```rust
pub struct Identity;                       // Clone (one shared copy); Debug shows only the id
impl Identity {
    pub fn generate() -> Result<Identity, Error>;                 // the OS generator
    pub fn generate_with(random: &Random) -> Result<Identity, Error>;
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Identity, Error>;
    pub fn from_pkcs8_pem(text: &str) -> Result<Identity, Error>; // -----BEGIN PRIVATE KEY-----
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, Error>;
    pub fn read(path: &Path) -> Result<Option<Identity>, Error>;  // None when absent
    pub fn write_new(&self, path: &Path) -> Result<(), Error>;    // never replaces; 0600 on Unix; creates parents
    pub fn open_or_create(path: &Path) -> Result<Identity, Error>;
    pub fn peer_id(&self) -> PeerId;                              // SHA-256 of spki_der
    pub fn spki_der(&self) -> &[u8; 91];
    pub fn key_material(&self) -> KeyMaterial;                    // method "webcrypto", label "PUBLIC KEY"
}
```

On Windows a written file inherits its directory's ACL. Errors: `Error::Key` for what is not a P-256
PKCS#8 key (SEC1 `EC PRIVATE KEY` is not), `Error::Io` for the file, `Error::Random`.

## Trust (`coqui_peer_webcrypto::Trust`)

```rust
#[non_exhaustive]
pub enum Trust { Pinned(BTreeSet<PeerId>), Store(TrustStore), AnyWithKeyProof }
impl Trust { pub fn pinned(ids: impl IntoIterator<Item = PeerId>) -> Trust; }
```

Decided after the peer proved its key, never before.

- `Pinned`: fixed at build; an empty set admits nobody; a pin of a digest other than SHA-256 matches
  nothing.
- `Store`: read at each handshake, so a key removed or retired is refused from the next handshake on.
  The stored key must be of this method. A responder records a proved stranger with
  `record_waiting`, under the `source` given to `respond`; an initiator records nobody. The proved
  pending successor of an accepted key gets `prove_successor`, then `promote_successor` unless
  `RotationOptions::require_approval`, in which case it is refused until the caller promotes it.
- `AnyWithKeyProof`: anyone who proves a key. For a connection that only runs `pair`, never one that
  serves anything. `Session::is_trusted` is false and `WebCrypto::weakened` lists it.

## The method (`coqui_peer_webcrypto::{WebCrypto, WebCryptoHandshake, METHOD, random}`)

```rust
pub const METHOD: &str = "webcrypto";
pub const PROFILE: &str = "dev.boriken.coqui.peer-webcrypto/v1";
pub const DEFAULT_MAX_MESSAGE: usize = 3072;
pub fn random() -> Random;                    // the OS generator
pub struct WebCrypto;                         // Clone (shared); Debug shows no secret
impl WebCrypto {
    pub fn new(identity: Identity) -> WebCrypto;                 // neither role until a with_ below
    pub fn with_responders(self, trust: Trust) -> WebCrypto;     // whom initiate() admits
    pub fn with_initiators(self, trust: Trust) -> WebCrypto;     // whom respond() admits
    pub fn with_max_message(self, bytes: usize) -> WebCrypto;    // before parsing; no floor
    pub fn with_random(self, random: Random) -> WebCrypto;       // secure, or for test vectors only
    pub fn identity(&self) -> &Identity;
    pub fn weakened(&self) -> Vec<Weakening>;                    // any-with-proof; a larger max_message
}
impl coqui_peer::Method for WebCrypto { /* name() = "webcrypto"; initiate(); respond(source) */ }
pub struct WebCryptoHandshake;
impl WebCryptoHandshake {
    pub fn with_binding(self, binding: &[u8]) -> WebCryptoHandshake;   // before the first receive
}
impl coqui_peer::Handshake for WebCryptoHandshake { /* Output = Session, Framing::Message */ }
```

Run it with `coqui_peer::drive_messages` over a reliable, ordered message transport, `drive_stream`
over a byte stream (it length-prefixes), their `_until` forms for a deadline (nothing here reads a
clock, so **the caller bounds the handshake**), or a `receive`/`transmit` loop. `initiate` has the
hello ready to `transmit`; `Error::Unsupported` without trust for that role. `finish` gives
`Established { peer, key: Some(key), session }`.

`with_binding` is for an endpoint that really ends a TLS connection itself: pass that connection's
exporter at both ends, and a relay ending TLS on both sides fails with `Error::BadProof`. Never set it
through a reverse proxy, where the two ends read different values. It is never sent.

## The session (`coqui_peer_webcrypto::{Session, Sealer, Opener, PAIR_EXPORT_LABEL}`)

```rust
pub const PAIR_EXPORT_LABEL: &str = "EXPORTER-coqui-pair";
pub struct Session;                           // Debug shows only whether the peer is trusted
impl Session {
    pub fn id(&self) -> &[u8; 32];            // both ends agree; not secret
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn split(self) -> (Sealer, Opener);   // a reader and a writer on two threads; export first
    pub fn export(&self, label: &str, out: &mut [u8]) -> Result<(), Error>;   // at most 8160 bytes
    pub fn is_trusted(&self) -> bool;         // false under Trust::AnyWithKeyProof
    pub fn pair_channel(&self, local: &Identity, remote: KeyMaterial) -> Result<pair::Channel, Error>;
}
impl Sealer { pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>; }
impl Opener { pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, Error>; }
```

Each message is one record, sent whole and in order on a reliable transport; a record is the message
plus 16 bytes, and is not UTF-8, so a WebSocket carries it in binary frames. Any failure to open ends
that direction: `Error::Record` on every later call, and the caller closes the connection. Keep every
application message inside the session: **a plain message on the same transport comes from whoever
carries it**, even after a successful handshake.

## Pairing (`coqui_peer_webcrypto::pair`, feature `pin` for a PIN)

Two strangers run the handshake under `Trust::AnyWithKeyProof`, then:

```rust
let channel = established.session.pair_channel(&identity, established.key.clone().unwrap())?;
let joiner = Pairing::pin(pin, PinRole::Typed).join(channel)?;          // or PairingResponder::new(channel, &store, &desk, source)
// each transmit() goes through session.seal, each received record through session.open, into receive()
```

The channel has `remote` the proved key, `verified` as `is_trusted`, and `binding` a 32-byte export:
the pairing is tied to this session whatever TLS lies under it. On success the responder has
`accept_key`ed the joiner and the joiner stores `Paired::peer`. Close, and reconnect under `Pinned` or
`Store`: from then on the full key is what the handshake proves.

## Errors

`Error` (non-exhaustive): `Malformed` (not valid here: encoding, member, key, or place in the
exchange), `TooLong` (above `with_max_message`, or an export above 8160 bytes), `BadProof` (a signature
does not verify), `Untrusted` (proved, and `Trust` does not admit it), `Unsupported` (no trust for that
role), `State` (the handshake is over, or `finish` too early), `Random`, `Record` (see the session),
`Key`, `Io(io::Error)`. `Display` is one lowercase clause and never quotes input, a key or a path. A
handshake is over after an error: nothing queued leaves, and `transmit` is `State`.

## Gotchas

- The handshake alone authenticates nothing that follows it. Use the session, or a relay that forwarded
  the handshake owns the connection.
- Connection end is not authenticated: a cut looks like a close. A protocol above that needs to know
  says so in a record.
- Removing a peer does not stop its running sessions: the host closes them, polling
  `TrustStore::is_accepted` if it must.
- `Error` and `Trust` are `#[non_exhaustive]`: a `match` needs a `_` arm.
