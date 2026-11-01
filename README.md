# coqui-peer WebCrypto method

Canonical implementation of the draft p256-spki Coqui peer proof.

- JavaScript/WebCrypto initiator and responder: src/index.mjs
- Native Rust responder implementing coqui_peer::Method and Handshake: native/src/lib.rs
- Cross-language test harness: native/examples/responder_jsonl.rs, test/rust_interop.test.mjs

The Rust implementation currently accepts **only explicitly allowlisted PeerId values** and does not enroll unknown clients. It presents its public SPKI identity for out-of-band verification. Use only over a protected reliable channel. The JSONL harness is for testing; it does **not** open a network socket, store trust, or implement ACP.

## Verification

Run Node 22+ tests using npm test and Rust tests using cargo test --manifest-path native/Cargo.toml. The CI workflow also runs node --test test/rust_interop.test.mjs to authenticate an actual browser WebCrypto initiator against the Rust responder.

The core coqui-peer Rust crate and TLS method are unchanged; the native method is an experimental, separate package pending protocol review, key persistence and production trust-store integration.

## Native interoperability

The native Rust responder is in `native/` and is exercised against the real JavaScript WebCrypto initiator in CI. It implements `coqui_peer::Method` and `Handshake` and can enforce a live `TrustStore` so revocations take effect on the next handshake. Run `cargo test --manifest-path native/Cargo.toml` and `node --test test/rust_interop.test.mjs` with Rust and Node 22 installed. The responder CLI is an integration harness, not an ACP/WebSocket network server; Canoa contains a separate WSS echo fixture.
