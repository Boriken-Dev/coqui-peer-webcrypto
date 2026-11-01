# The WebCrypto method: wire profile v1

**Status:** experimental. It has had no independent security review and is not an IETF or ACP
standard. Implementations: Rust (`src/`) and JavaScript (`bindings/js/coqui-peer-webcrypto/`),
checked against each other and against `tests/vectors/handshake.json`.

## What this is

An authenticated key exchange followed by an encrypted channel, between two peers who each hold a
P-256 key. It runs over any reliable, ordered message transport and depends on nothing beneath it:
no TLS session, certificate, origin or host name. Both peers end the handshake holding a session id
and keys, and **only records made with those keys are tied to the peers that were proved**.

The handshake is signed ephemeral Diffie-Hellman with both identities inside the signatures: the
ISO 9798-3 pattern analysed by Canetti and Krawczyk ("Security Analysis of IKE's Signature-based
Key-Exchange Protocol", CRYPTO 2002), which SIGMA and TLS 1.3 refine. Records are AES-256-GCM with a
per-direction key and a sequence-number nonce, as in TLS 1.3 (RFC 8446 section 5.3). This instance has
no formal analysis of its own.

The Noise framework would be the natural alternative, and does not fit: its static keys are
Diffie-Hellman keys, so a Noise identity could not sign; its specification names only Curve25519 and
Curve448, so P-256, the curve WebCrypto implementations have offered from the start for both ECDSA
and ECDH, would make an off-specification pattern with none of Noise's existing analysis; and a
dependency-free browser module cannot supply X25519 where WebCrypto lacks it.

## Identity

| Field | Value |
| --- | --- |
| Method name | `webcrypto` |
| Profile | `dev.boriken.coqui.peer-webcrypto/v1` |
| Public key | SubjectPublicKeyInfo DER of a P-256 key with an uncompressed point: always 91 bytes, the 27 bytes `3059301306072a8648ce3d020106082a8648ce3d03010703420004` then the 64 coordinate bytes |
| Signature | ECDSA with SHA-256, IEEE P1363: 64 bytes `r` then `s` |
| Peer id | `sha256:` and the lowercase hex SHA-256 of the 91 key bytes: coqui-peer's `PeerId` |
| Key material | method `webcrypto`, label `PUBLIC KEY`, the 91 key bytes |

One key has one encoding and so one id. These keys are not `coqui-peer-tls` certificate keys, and a
certificate's fingerprint is not an id here.

## Handshake

A message is a UTF-8 JSON object in exactly one encoding: the members below in this order, no
whitespace, no escapes, nothing else. Binary values are unpadded base64url with zero trailing bits.
Every message starts `"profile":"dev.boriken.coqui.peer-webcrypto/v1","version":1,"type":...`.

| # | From | `type` | Other members |
| --- | --- | --- | --- |
| 1 | Initiator | `hello` | `publicKey`, `ephemeral`, `nonce` |
| 2 | Responder | `challenge` | `publicKey`, `ephemeral`, `nonce`, `signature` for role `server` |
| 3 | Initiator | `proof` | `signature` for role `client` |
| 4 | Responder | `accept` | `signature` for role `accept` |

`nonce` is 32 fresh random bytes. `ephemeral` is a fresh P-256 ECDH key as 65 bytes, `04` then the
coordinates, used for this run only and then erased.

Order of checks. The initiator verifies the `server` signature, then its trust in the responder's
key, and only then signs. The responder verifies the `client` signature, then its trust in the
initiator's key, and only then derives keys and signs `accept`. The initiator verifies `accept`.
Neither side treats the peer as proved before that point. Trust is never decided on an unproved key,
so an unknown key and a bad signature look the same on the wire: the connection ends with no message.

A responder keeping a trust store records a proved, unknown peer as waiting, per coqui-peer's
key-proof contract. Nothing enrolls a peer automatically.

### What is signed

The signature input is these fields, each as a 4-byte big-endian length then its bytes:

1. the profile identifier
2. the role: `server`, `client` or `accept`
3. the initiator's public key
4. the responder's public key
5. the initiator's nonce
6. the responder's nonce
7. the initiator's ephemeral key
8. the responder's ephemeral key
9. the outer binding (empty unless both ends set one; see below)

So each side's signature names both parties' keys, both nonces, both ephemeral keys and the binding:
a signature cannot be replayed into another run, reflected to another role, or made to vouch for
another peer.

### Session id and keys

- **Session id**: SHA-256 of the fields above without the role. Both ends compute it, and both
  signatures cover everything it hashes, so one id at both ends means both signed for one pair of
  keys and one run. It is not secret: whoever carried the handshake can compute it.
- **Keys**: `HKDF-SHA256(salt = session id, ikm = the ECDH shared secret's x coordinate,
  info = "<profile>/keys")`, 96 bytes: the initiator's sending key, the responder's sending key, and
  the export secret.
- **Exports**: `HKDF-SHA256(salt = absent, ikm = export secret, info = "<profile>/export/<label>")`.
  Secret to the two peers, and bound to this run.

## Records

After the handshake, each application message is one record: `AES-256-GCM(key of the sending
direction, nonce = 4 zero bytes then the 8-byte big-endian sequence number, no associated data)`,
ciphertext then the 16-byte tag, carried whole as one binary message. Each direction's sequence
starts at 0 and rises by one per record. A record that fails to open ends that direction for good;
nothing later is believed. The sequence is never reused or wrapped.

## Through a relay

Anything carrying the connection is a relay: a TLS-terminating reverse proxy such as nginx, or an
attacker holding a certificate, or one a user was lured to. The method needs no cooperation from it
and no TLS beneath it.

| A relay **can** | A relay **cannot** |
| --- | --- |
| forward the run unchanged, which only connects the two real parties | read a record, or learn the session's keys or exports |
| see both public keys and peer ids (a `hello` names its sender before the responder is proved), the session id, and each record's size and time | inject, alter, reorder, replay or reflect a record |
| block, delay or cut the connection, which ends a session without any authenticated close, so a lost tail of messages looks like a close | replace a key, ephemeral key or nonce: every signature covers them, so the other side's verification fails |
| run a handshake of its own under its own key, against a peer that trusts that key or accepts any proved key | make a peer that pins another id accept its key, or use a proof from another run |

**The right-hand column holds only for what goes through the session.** A peer that speaks plain
application messages beside the records, trusting the handshake, hands the whole connection to the
relay: it forwards the four messages, both ends succeed, and it then reads and writes as it likes.

It does not protect against a party that serves the page. A browser runs the code its origin sends, so
if the reverse proxy also serves the page's JavaScript, it can replace that code. Ship the module
in the application (an extension, a packaged app), or serve it from where the carrier cannot change it.

### The outer binding

Where each end really terminates one TLS connection itself, both may pass that connection's exporter
as the binding. It is never sent. Both signatures cover it, so a relay ending TLS on both sides gives
the two ends different values and the handshake fails: it refuses such a relay, rather than only
blinding it. It is optional and adds nothing to what the session already protects. Through a
reverse proxy, or from a browser, no two ends can read one value, so it stays empty.

## Pairing

`coqui_peer::pair` runs on a session, bound to the session and not to any TLS beneath it. Each side
runs the handshake trusting any proved key, then builds its `Channel`: `local` its own key, `remote`
the proved key, `verified` false, `binding` a 32-byte export under `EXPORTER-coqui-pair`. The
exchange's messages are carried as records. Once paired, connections are ordinary pinned handshakes,
and the full key is what they prove. A connection admitted by any proved key serves nothing but the
exchange.

Under a PIN, a relay forwarding everything pairs the real parties with each other and learns nothing;
a relay running a handshake with each side presents its own key to both, which the exchange refuses.

The JavaScript module has no PIN exchange: a browser's key is paired by carrying its id out of band.

## Bounds and refusal

Every message is checked before anything else against a limit, a setting that defaults to 3072 bytes
of UTF-8. The exact encoding above is then enforced by decoding and re-encoding, so duplicate or
unknown members, member order, whitespace and escapes are all refused alike. Refused too: any other
profile or version, a key that is not the exact shape above or is off the curve, a signature with `r`
or `s` out of range, either side presenting the other's key. There is no negotiation, so nothing to
downgrade. `s` may be high or low: WebCrypto does not normalise it, so signatures are malleable, and
nothing here uses a signature as an identifier.

Errors never quote what the peer sent. A failed handshake drops what it had queued and stays failed.

## Not in this protocol

- **Identity hiding.** The initiator's key is sent before the responder is proved; a responder signs
  for anyone who says `hello`. A key can be tracked by whoever sees it.
- **Revocation of a running session.** Trust is read at each handshake. A host that removes a peer
  closes that peer's open connections itself.
- **Rekeying.** A session ends when its sequence does; a long-lived one reconnects.
- **Authenticated close.** See the table above.
- **Keeping a page's key from its own origin.** A non-extractable key cannot be copied out, but any
  script in the origin can use it, and IndexedDB's contents can be cleared by the browser or the user.
