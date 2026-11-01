# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `WebCrypto` and `WebCryptoHandshake`: the `coqui_peer::Method` named `webcrypto`, as initiator and
  responder, ending in a `Session`.
- `Session`, `Sealer`, `Opener`: an id both ends agree on, per-direction AES-256-GCM records with an inner
  type, `close` and `verify_end` so a cut stream is reported as `Error::Truncated`, `with_session_limit`
  per direction, and exports bound to their length.
- `Identity`: a P-256 key in PKCS#8, generated, read and written.
- `Trust`: fixed pins, or a live `TrustStore` with rotation and waiting entries under `WaitingGate`, which
  refuses rather than evicts and limits the rate of writes.
- `PairingMethod`, `PairingSession`, `PairDial`: a stranger's handshake ends in a type that runs a sealed
  `coqui_peer::pair` exchange, bound to the session, and carries nothing else.
- `FramedStream`: refuses a frame by its declared length before reading it.
- `WebCryptoHandshake::with_binding`: an optional outer binding for an endpoint that ends TLS itself,
  refused once the transcript is fixed.
- The JavaScript module in `bindings/js/coqui-peer-webcrypto`, with the same wire in both roles.
- `PROTOCOL.md` and the shared vectors in `tests/vectors/handshake.json`.
