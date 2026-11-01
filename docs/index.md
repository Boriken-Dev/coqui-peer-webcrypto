# coqui-peer-webcrypto

Two peers prove their P-256 keys to each other and end up with an encrypted session, in a browser or
natively, through anything that carries their messages. This is a method of
[coqui-peer](https://boriken-dev.github.io/coqui-peer/), which holds the peer id, the trust store and
the sans-IO handshake trait.

!!! warning "Alpha, not independently reviewed"
    `0.0.0-alpha.0` is a pre-release: the wire and the API may change in any release before 1.0.

```toml
coqui-peer-webcrypto = "0.0.0-alpha.0"
```

## Why a session, and not only a proof

A proof alone says who was there when it was made. Anything carrying the connection, such as a reverse
proxy that ends TLS or a relay a user was lured to, can forward a proof unchanged, watch both ends
succeed, and then speak for either. This method therefore ends in keys only the two peers hold, and an
application keeps every later message inside that session. Nothing depends on the TLS beneath it.

A party carrying the connection can forward it, see public keys and record sizes, delay it and cut it.
It cannot read or change a record, replace a key, or stand in for a pinned peer. It can, if it also
serves a page's JavaScript, replace that JavaScript, so a browser application ships the module with
itself.

## Pairing

Two strangers run the handshake accepting any proved key, then
[coqui-peer's pairing](https://boriken-dev.github.io/coqui-peer/pairing/) inside that session, bound to
the session and not to any TLS. Afterwards the full key is what each handshake proves. The JavaScript
module has no PIN exchange; a browser's id is carried to its peer out of band.

The API reference is on [docs.rs](https://docs.rs/coqui-peer-webcrypto) and under
[Rust API](https://boriken-dev.github.io/coqui-peer-webcrypto/rust/index.html) for `main`. The source, the
wire protocol (`PROTOCOL.md`), the API headers (`AGENTS.md`) and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-peer-webcrypto).
