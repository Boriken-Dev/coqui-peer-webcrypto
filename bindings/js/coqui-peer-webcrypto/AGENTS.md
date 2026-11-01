# `@boriken/coqui-peer-webcrypto` — API header

Every export of this dependency-free ES module (`src/index.mjs`) with its contract, so it can be used
without reading the source. One file, so it can be vendored by copying it. It needs `crypto.subtle`:
a browser needs a secure context; Node 22 or later has it. The wire is `PROTOCOL.md` of
<https://github.com/Boriken-Dev/coqui-peer-webcrypto>, which the Rust crate of that name also
implements. Not independently reviewed; it may change in any release before 1.0.

```js
export const PROFILE;              // 'dev.boriken.coqui.peer-webcrypto/v1'
export const METHOD;               // 'webcrypto'
export const DEFAULT_MAX_MESSAGE;  // 3072
export const profile;              // {id, version, method}

export async function generateIdentity();              // -> identity
export async function importIdentity(pkcs8);           // PKCS#8 DER P-256 bytes -> identity
export async function loadOrCreateIdentity(name);      // IndexedDB database `name`, required -> identity
// identity: frozen {method, peerId: 'sha256:<hex>', publicKey: base64url SPKI, privateKey: CryptoKey}

export async function createInitiator(identity, expectedPeerId, options);
// -> {hello() -> string, async answer(raw) -> string, async finish(raw) -> {peerId, session}}
export async function createResponder(identity, {allowClient, ...options});
// -> {async challenge(raw) -> string, async accept(raw) -> {reply: string, peerId, session}}
// allowClient: async (peerId) -> exactly true to admit; runs after the peer proved its key

// session (frozen):
//   id                          Uint8Array(32), both ends agree; not secret
//   async seal(bytes | string)  -> Uint8Array record; send whole, in the order of the calls
//   async open(record)          -> Uint8Array message, in the order of the calls
//   async export(label, length) -> Uint8Array, secret to the two peers
```

`raw` is a message as text or bytes, at most `maxMessage` bytes. Options: `maxMessage` (default
`DEFAULT_MAX_MESSAGE`, no floor); `binding`, the bytes of an outer channel both ends really read (a
TLS exporter where each end terminates that TLS itself; never through a reverse proxy or from a
browser); `random` and `ephemeral`, replacing the generators **for test vectors only**.

An identity's private key must be non-extractable, P-256 and able to sign, and `peerId` must be the
hash of `publicKey`, or `createInitiator` and `createResponder` throw. Each application names its own
`loadOrCreateIdentity` database: the name is its identity. Concurrent tabs end up with one key.

The flow: the initiator sends `hello()`; the responder answers `challenge(raw)`; the initiator answers
`answer(raw)`, having verified the responder and its pin; the responder ends with `accept(raw)`,
having verified the client and `allowClient`, and sends `reply`; the initiator ends with `finish(raw)`.

Then **every application message goes through the session**, as a binary message:

```js
socket.binaryType = 'arraybuffer';
socket.send(await session.seal(JSON.stringify(message)));
const text = new TextDecoder().decode(await session.open(new Uint8Array(event.data)));
```

A plain message on the same transport comes from whoever carries it, such as a TLS-terminating reverse
proxy, even after a successful handshake. A record that fails to open ends that direction for good:
close the connection. A cut looks like a close.

## Errors

Every failure is a thrown `Error` whose message quotes nothing the peer sent; a handshake object is
over after one, and a later call says `Unexpected ...`. What is refused is in `PROTOCOL.md`.

## Gotchas

- A non-extractable key cannot be copied out, but any script in the origin can use it.
- A proxy that serves the page can replace this module. Ship it with the application.
- There is no PIN exchange here: a browser's id is carried to its peer out of band.
- Nothing bounds time: the caller sets a deadline on the handshake.
