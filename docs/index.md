# Browser WebCrypto method

An experimental `p256-spki` browser authentication implementation is maintained under [`methods/webcrypto/`](https://github.com/Boriken-Dev/coqui-peer/tree/main/methods/webcrypto).

It uses non-extractable WebCrypto P-256 keys, mutual signed nonce challenges, an explicitly pinned expected server identity, and an independent allow/deny decision for the client key. Its profile identifier is `dev.boriken.coqui.peer-webcrypto/v1`.

The separate native Rust responder now implements the Coqui `Method` and `Handshake` traits. A JavaScript initiator ↔ Rust responder test is exercised in CI, and the Rust method can check accepted keys against a live `TrustStore`. A native initiator and full production pairing flows are still pending.

**Authentication and pairing are distinct.** Proving private-key possession never adds an unknown peer to the trust database automatically. This method is currently JavaScript-only, experimental, and not yet interoperable with `coqui-peer-tls` certificate identities; a native Rust method and cross-language tests are planned.

Applications should import this method as a dependency or a pinned, verified build artifact rather than fork the protocol. The message channel and any unread-message buffering belong below the method, in a generic transport adapter.

[Method README](https://github.com/Boriken-Dev/coqui-peer/blob/main/methods/webcrypto/README.md)
