import test from 'node:test';
import assert from 'node:assert/strict';
import {generateIdentity, createInitiator, createResponder, profile} from '../src/index.mjs';

async function setup(allow = true) {
  const client = await generateIdentity();
  const server = await generateIdentity();
  return {
    client, server,
    initiator: await createInitiator(client, server.peerId),
    responder: await createResponder(server, {
      allowClient: async id => allow && id === client.peerId,
    }),
  };
}
test('non-extractable identities and Coqui-style IDs', async () => {
  const first = await generateIdentity();
  const second = await generateIdentity();
  assert.match(first.peerId, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(first.peerId, second.peerId);
  assert.equal(first.privateKey.extractable, false);
  assert.equal(profile.id, 'dev.boriken.coqui.peer-webcrypto/v1');
});
test('mutual proof and explicit trust across one connection', async () => {
  const p = await setup();
  const challenge = await p.responder.challenge(p.initiator.hello());
  const proof = await p.initiator.answer(challenge);
  const confirmed = await p.responder.accept(proof);
  assert.equal(confirmed.peerId, p.client.peerId);
  assert.equal(await p.initiator.finish(confirmed.reply), p.server.peerId);
  await assert.rejects(() => p.responder.accept(proof), /Unexpected/);
});
test('unknown client is not auto-paired', async () => {
  const p = await setup(false);
  const response = await p.responder.challenge(p.initiator.hello());
  const proof = await p.initiator.answer(response);
  await assert.rejects(() => p.responder.accept(proof), /not paired/);
});
test('an unpinned server is refused before client proof', async () => {
  const p = await setup();
  const bad = await createInitiator(p.client, (await generateIdentity()).peerId);
  const response = await p.responder.challenge(bad.hello());
  await assert.rejects(() => bad.answer(response), /not pinned/);
});
test('altered signatures and stolen public keys cannot authenticate', async () => {
  const p = await setup();
  const challenge = JSON.parse(await p.responder.challenge(p.initiator.hello()));
  challenge.signature = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  await assert.rejects(() => p.initiator.answer(JSON.stringify(challenge)), /key proof failed/);
  const q = await setup();
  const reply = await q.responder.challenge(q.initiator.hello());
  const proof = JSON.parse(await q.initiator.answer(reply));
  proof.signature = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  await assert.rejects(() => q.responder.accept(JSON.stringify(proof)), /key proof failed/);
});
test('cross-connection proof replay is refused by fresh nonces', async () => {
  const p = await setup();
  const reply = await p.responder.challenge(p.initiator.hello());
  const proof = await p.initiator.answer(reply);
  const newServer = await createResponder(p.server, {
    allowClient: async id => id === p.client.peerId,
  });
  const newClient = await createInitiator(p.client, p.server.peerId);
  await newServer.challenge(newClient.hello());
  await assert.rejects(() => newServer.accept(proof), /key proof failed/);
});
test('malformed version, oversized frames and unexpected state are refused', async () => {
  const p = await setup();
  await assert.rejects(() => p.initiator.finish('{}'), /Unexpected/);
  await assert.rejects(() => p.responder.challenge('x'.repeat(4096)), /Oversized/);
  const q = await setup();
  const hello = JSON.parse(q.initiator.hello());
  hello.version = 0;
  await assert.rejects(() => q.responder.challenge(JSON.stringify(hello)), /Unsupported/);
});
