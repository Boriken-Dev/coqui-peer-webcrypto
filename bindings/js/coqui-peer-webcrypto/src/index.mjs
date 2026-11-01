/**
 * Experimental browser WebCrypto authentication method for coqui-peer.
 * Identity = SHA256(DER SPKI), distinct from coqui-peer-tls certificate IDs.
 * Must run over secure WebTransport/WSS; never auto-enroll an unknown peer.
 */
const PROFILE = 'dev.boriken.coqui.peer-webcrypto/v1';
const enc = new TextEncoder();

function api() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error('Secure-context WebCrypto is required');
  }
  return globalThis.crypto;
}
function b64(bytes) {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function un64(text, max, exact = null) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]+$/.test(text) || text.length > 1024) {
    throw new Error('Invalid base64url peer material');
  }
  let raw;
  try { raw = atob(text.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(text.length / 4) * 4, '=')); }
  catch { throw new Error('Invalid base64url data'); }
  const bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
  if (bytes.length > max || (exact !== null && bytes.length !== exact) || b64(bytes) !== text) {
    throw new Error('Invalid canonical encoding or key length');
  }
  return bytes;
}
function nonce() {
  const bytes = new Uint8Array(32);
  api().getRandomValues(bytes);
  return b64(bytes);
}
async function peerId(spki) {
  const digest = new Uint8Array(await api().subtle.digest('SHA-256', spki));
  return 'sha256:' + [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
async function publicKey(encoded) {
  return api().subtle.importKey('spki', un64(encoded, 256), {
    name: 'ECDSA', namedCurve: 'P-256',
  }, true, ['verify']);
}
function transcript(role, hello, challenge) {
  const fields = [
    enc.encode(PROFILE), enc.encode(role),
    un64(hello.publicKey, 256), un64(challenge.publicKey, 256),
    un64(hello.nonce, 32, 32), un64(challenge.nonce, 32, 32),
  ];
  const output = new Uint8Array(fields.reduce((total, field) => total + 4 + field.length, 0));
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint32(offset, field.length, false);
    offset += 4;
    output.set(field, offset);
    offset += field.length;
  }
  return output;
}
async function sign(identity, role, hello, challenge) {
  return b64(new Uint8Array(await api().subtle.sign(
    {name: 'ECDSA', hash: 'SHA-256'}, identity.privateKey,
    transcript(role, hello, challenge),
  )));
}
async function verify(key, sig, role, hello, challenge) {
  return api().subtle.verify(
    {name: 'ECDSA', hash: 'SHA-256'}, key, un64(sig, 64, 64),
    transcript(role, hello, challenge),
  );
}
function parse(raw, kind) {
  if (typeof raw !== 'string' || raw.length > 3072) throw new Error('Oversized peer frame');
  let obj;
  try { obj = JSON.parse(raw); } catch { throw new Error('Invalid peer JSON'); }
  if (!obj || Array.isArray(obj) || obj.profile !== PROFILE || obj.version !== 1 || obj.type !== kind) {
    throw new Error('Unsupported or unexpected peer handshake');
  }
  return obj;
}
function pack(type, contents) {
  return JSON.stringify({profile: PROFILE, version: 1, type, ...contents});
}
function checkIdentity(id) {
  if (typeof id?.publicKey !== 'string' || !id.privateKey ||
      !/^sha256:[a-f0-9]{64}$/.test(id.peerId)) {
    throw new Error('Valid non-extractable peer identity required');
  }
}

export async function generateIdentity() {
  const pair = await api().subtle.generateKey({
    name: 'ECDSA', namedCurve: 'P-256',
  }, false, ['sign', 'verify']);
  const spki = new Uint8Array(await api().subtle.exportKey('spki', pair.publicKey));
  return Object.freeze({
    method: 'p256-spki', peerId: await peerId(spki),
    publicKey: b64(spki), privateKey: pair.privateKey,
  });
}

export async function createInitiator(identity, expectedPeerId) {
  checkIdentity(identity);
  if (!/^sha256:[a-f0-9]{64}$/.test(expectedPeerId || '')) {
    throw new Error('Pinned expected server ID is mandatory');
  }
  const hello = {publicKey: identity.publicKey, nonce: nonce()};
  let state = 0;
  let challenge;
  return Object.freeze({
    hello() {
      if (state !== 0) throw new Error('Handshake already started');
      state = 1;
      return pack('hello', hello);
    },
    async answer(raw) {
      if (state !== 1) throw new Error('Unexpected challenge');
      state = -1;
      const response = parse(raw, 'challenge');
      const id = await peerId(un64(response.publicKey, 256));
      if (id !== expectedPeerId) throw new Error('Server identity not pinned');
      challenge = {publicKey: response.publicKey, nonce: response.nonce};
      const key = await publicKey(response.publicKey);
      if (!await verify(key, response.signature, 'server', hello, challenge)) {
        throw new Error('Server key proof failed');
      }
      const signature = await sign(identity, 'client', hello, challenge);
      state = 2;
      return pack('proof', {signature});
    },
    async finish(raw) {
      if (state !== 2) throw new Error('Unexpected completion');
      state = -1;
      const response = parse(raw, 'accept');
      const key = await publicKey(challenge.publicKey);
      if (!await verify(key, response.signature, 'accept', hello, challenge)) {
        throw new Error('Server acceptance proof failed');
      }
      state = 3;
      return expectedPeerId;
    },
  });
}

export async function createResponder(identity, {allowClient} = {}) {
  checkIdentity(identity);
  if (typeof allowClient !== 'function') throw new Error('Explicit peer trust lookup is mandatory');
  let state = 0;
  let hello;
  let challenge;
  let clientKey;
  let clientPeerId;
  return Object.freeze({
    async challenge(raw) {
      if (state !== 0) throw new Error('Unexpected hello');
      state = -1;
      const incoming = parse(raw, 'hello');
      clientKey = await publicKey(incoming.publicKey);
      clientPeerId = await peerId(un64(incoming.publicKey, 256));
      hello = {publicKey: incoming.publicKey, nonce: incoming.nonce};
      challenge = {publicKey: identity.publicKey, nonce: nonce()};
      const signature = await sign(identity, 'server', hello, challenge);
      state = 1;
      return pack('challenge', {...challenge, signature});
    },
    async accept(raw) {
      if (state !== 1) throw new Error('Unexpected client proof');
      state = -1;
      const incoming = parse(raw, 'proof');
      if (!await verify(clientKey, incoming.signature, 'client', hello, challenge)) {
        throw new Error('Client key proof failed');
      }
      if (!await allowClient(clientPeerId)) throw new Error('Client is not paired');
      const signature = await sign(identity, 'accept', hello, challenge);
      state = 2;
      return {reply: pack('accept', {signature}), peerId: clientPeerId};
    },
  });
}

/** Store non-extractable CryptoKey by structured clone in origin-local IndexedDB. */
export async function loadOrCreateIdentity(name = 'dev.boriken.coqui.peer-webcrypto') {
  if (!globalThis.indexedDB) throw new Error('IndexedDB storage unavailable');
  const generated = await generateIdentity();
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      const table = tx.objectStore('keys');
      let value;
      const get = table.get('default');
      get.onsuccess = () => {
        value = get.result || generated;
        if (!get.result) table.put(generated, 'default');
      };
      get.onerror = () => reject(get.error);
      tx.oncomplete = () => {
        try { checkIdentity(value); resolve(value); } catch (error) { reject(error); }
      };
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Identity write aborted'));
    });
  } finally {
    db.close();
  }
}

export const profile = Object.freeze({id: PROFILE, version: 1, method: 'p256-spki'});
