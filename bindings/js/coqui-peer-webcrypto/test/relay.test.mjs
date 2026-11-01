// What a party carrying the connection can do, such as a reverse proxy that ends TLS. No TLS is
// involved anywhere here: the relay is the function that moves a message.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createInitiator, createResponder, generateIdentity} from '../src/index.mjs';

async function parties() {
  const client = await generateIdentity();
  const server = await generateIdentity();
  return {
    client, server,
    i: await createInitiator(client, server.peerId),
    r: await createResponder(server, {allowClient: async id => id === client.peerId}),
  };
}

async function through(relay, p) {
  const challenge = await p.r.challenge(relay(p.i.hello()));
  const proof = await p.i.answer(relay(challenge));
  const accepted = await p.r.accept(relay(proof));
  const finished = await p.i.finish(relay(accepted.reply));
  return {atClient: finished.session, atServer: accepted.session, finished, accepted};
}

const reencode = (message, member, value) => {
  const parsed = JSON.parse(message);
  parsed[member] = value;
  return JSON.stringify(parsed);
};

test('a plain relay connects only the real parties, and reads and writes nothing after', async () => {
  const p = await parties();
  const seen = [];
  const {atClient, atServer, finished, accepted} = await through(message => {
    seen.push(message);
    return message;
  }, p);
  assert.equal(finished.peerId, p.server.peerId);
  assert.equal(accepted.peerId, p.client.peerId);
  assert.deepEqual(atClient.id, atServer.id);

  const record = await atClient.seal('secret from the relay');
  assert.ok(!Buffer.from(record).toString('latin1').includes('secret'));
  assert.equal(new TextDecoder().decode(await atServer.open(record)), 'secret from the relay');
  await assert.rejects(() => atServer.open(new TextEncoder().encode('{"method":"session/prompt"}')), /does not open/);
  await assert.rejects(async () => atServer.open(await atClient.seal('genuine')), /session is over/);
});

test('a relay cannot replay, reorder, reflect or alter a record', async () => {
  const replay = await through(m => m, await parties());
  const once = await replay.atClient.seal('one');
  await replay.atServer.open(once);
  await assert.rejects(() => replay.atServer.open(once), /does not open/);

  const reorder = await through(m => m, await parties());
  await reorder.atClient.seal('one');
  await assert.rejects(async () => reorder.atServer.open(await reorder.atClient.seal('two')), /does not open/);

  const reflect = await through(m => m, await parties());
  await assert.rejects(async () => reflect.atClient.open(await reflect.atClient.seal('one')), /does not open/);

  const alter = await through(m => m, await parties());
  const altered = await alter.atClient.seal('one');
  altered[0] ^= 1;
  await assert.rejects(() => alter.atServer.open(altered), /does not open/);

  const other = await through(m => m, await parties());
  const elsewhere = await through(m => m, await parties());
  await assert.rejects(async () => other.atServer.open(await elsewhere.atClient.seal('one')), /does not open/);
});

test('a key swapped in the hello fails the proof the initiator checks', async () => {
  const p = await parties();
  const attacker = await generateIdentity();
  const r = await createResponder(p.server, {allowClient: async () => true});
  const swapped = reencode(p.i.hello(), 'publicKey', attacker.publicKey);
  await assert.rejects(async () => p.i.answer(await r.challenge(swapped)), /key proof failed/);
});

test('an ephemeral key or nonce swapped by a relay fails the proof', async () => {
  for (const member of ['ephemeral', 'nonce']) {
    const other = JSON.parse((await parties()).i.hello());
    const p = await parties();
    const swapped = reencode(p.i.hello(), member, other[member]);
    await assert.rejects(async () => p.i.answer(await p.r.challenge(swapped)), /key proof failed/, member);

    const q = await parties();
    const challenge = await q.r.challenge(q.i.hello());
    await assert.rejects(() => q.i.answer(reencode(challenge, member, other[member])), /key proof failed/, member);
  }
});

test('a relay answering with a key of its own fails the pin', async () => {
  const p = await parties();
  const relay = await generateIdentity();
  const r = await createResponder(relay, {allowClient: async () => true});
  await assert.rejects(async () => p.i.answer(await r.challenge(p.i.hello())), /not pinned/);
});

test('an outer binding is optional, and two different channels are refused', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const pair = async (a, b) => ({
    i: await createInitiator(client, server.peerId, {binding: a}),
    r: await createResponder(server, {allowClient: async () => true, binding: b}),
  });
  const same = await pair(new Uint8Array([1]), new Uint8Array([1]));
  assert.equal(typeof await same.i.answer(await same.r.challenge(same.i.hello())), 'string');
  const two = await pair(new Uint8Array([1]), new Uint8Array([2]));
  await assert.rejects(async () => two.i.answer(await two.r.challenge(two.i.hello())), /key proof failed/);
  const one = await pair(new Uint8Array([1]), new Uint8Array());
  await assert.rejects(async () => one.i.answer(await one.r.challenge(one.i.hello())), /key proof failed/);
});
