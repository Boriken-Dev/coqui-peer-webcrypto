# Peer WebCrypto method: draft wire profile v1

**Status:** experimental, not an IETF or ACP standard. This document specifies the method implemented in [src/index.mjs](src/index.mjs), to support future independent Rust/native implementations.

## Identity and trust material

| Field | Value |
| --- | --- |
| Method name | `p256-spki` |
| Profile | `dev.boriken.coqui.peer-webcrypto/v1` |
| Public key | DER SubjectPublicKeyInfo (SPKI), containing a NIST P-256 ECDSA public key |
| Signature algorithm | ECDSA with SHA-256; **IEEE P1363 / raw 64-byte R||S** output from WebCrypto |
| Peer ID | `sha256:` followed by lowercase SHA-256 hexadecimal digest of the **complete SPKI DER** bytes |
| Coqui KeyMaterial | method `p256-spki`, label `PUBLIC KEY`, bytes containing the exact SPKI DER |
| Nonces | Independent cryptographically random 32-byte values, one from each side |
| JSON encoding | UTF-8 JSON object; binary members are canonical unpadded Base64url strings |

These keys are **not** the TLS certificate keys used by `coqui-peer-tls`. A fingerprint of a TLS certificate must not be substituted for a P-256 SPKI peer ID.

## Handshake messages

All four messages include `{"profile":"dev.boriken.coqui.peer-webcrypto/v1","version":1,"type":"..."}`.

1. Initiator sends `hello` with `publicKey` (initiator SPKI) and `nonce`.
2. Responder sends `challenge` with `publicKey` (responder SPKI), `nonce` and `signature` over the transcript for role `server`.
3. Initiator verifies the responder's exact pinned `PeerId` **and** signature before responding with `proof` containing its signature for role `client`.
4. Responder verifies the initiator's signature and independently checks the client key against its trust/pairing policy; only an accepted client receives `accept` containing the responder's signature for role `accept`. The initiator verifies this final signature before returning an authenticated peer.

No ACP, MCP, browser tool or other privileged application frames may be processed until all four steps succeed. No unknown key is automatically paired. Failure aborts the connection and **does not** trigger a WebTransport-to-WSS fallback.

## Signed transcript format

For role `server`, `client` or `accept`, compute these six byte fields:

1. UTF-8 profile identifier (`dev.boriken.coqui.peer-webcrypto/v1`)
2. UTF-8 role string (`server`, `client`, or `accept`)
3. Initiator SPKI DER
4. Responder SPKI DER
5. Initiator nonce (32 bytes)
6. Responder nonce (32 bytes)

For each field, write its byte length as an **unsigned 32-bit big-endian** integer, followed by the field. Concatenate the six encoded fields without separators. Sign or verify the resulting byte string with ECDSA/SHA-256.

Both role and position are significant. Do not sign JSON serialization directly; key order, whitespace and encoding differences would break interoperability.

## Strict processing

- Refuse unknown `version` or `profile`; do not negotiate down to another method.
- Refuse non-canonical Base64url, invalid SPKI or P-256 keys, invalid nonce lengths, and invalid signature lengths.
- Limit the UTF-8 JSON handshake message to **3,072 bytes**; this profile currently uses only short frames.
- Create a fresh nonce for **every connection** and allow only the expected state transition. A replayed proof from another connection cannot validate because the nonce pair differs.
- Use the exact initiator/responder key order in all signatures and in the responder's trust lookup.
- Transport encryption (WebTransport HTTPS or WSS) is mandatory in the browser. Authentication here authenticates the **peer identity**, not necessarily the website origin or DNS name.
- Use the same pinned expected server `PeerId` on a fallback WSS connection, established **before** this handshake begins.
- Revocation/key rotation and initial pairing require an explicit policy; the `allowClient` hook must query that policy rather than return true for every key.

## Implementation status

The JavaScript WebCrypto method and a native Rust responder implementing `coqui_peer::Method` / `Handshake` are implemented. Cross-language CI tests exercise a JavaScript initiator against the Rust responder, including rejection of an unpaired client. The native responder can consult the canonical `TrustStore` at authorization time, including revocation. A native Rust initiator, a complete pairing workflow, credential persistence and external interoperability/security review are **not yet implemented**; this remains an experimental draft, not a standardized production method.
