# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `WebCrypto` and `WebCryptoHandshake`: the `coqui_peer::Method` named `webcrypto`, as initiator and
  responder, ending in a `Session`.
- `Session`, `Sealer`, `Opener`: an id both ends agree on, per-direction AES-256-GCM records and exports.
- `Identity`: a P-256 key in PKCS#8, generated, read and written.
- `Trust`: fixed pins, a live `TrustStore` with waiting entries and rotation, or any proved key for a
  connection that only pairs.
- `Session::pair_channel`: `coqui_peer::pair` on a session, bound to it.
- `WebCryptoHandshake::with_binding`: an optional outer binding for an endpoint that ends TLS itself.
- The JavaScript module in `bindings/js/coqui-peer-webcrypto`, with the same wire in both roles.
- `PROTOCOL.md` and the shared vectors in `tests/vectors/handshake.json`.
