import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {generateIdentity, createInitiator} from '../src/index.mjs';

const manifest = new URL('../native/Cargo.toml', import.meta.url).pathname;

async function interact(allow) {
  const client = await generateIdentity();
  const permitted = allow ? client.peerId : 'sha256:' + '0'.repeat(64);
  const child = spawn('cargo', [
    'run', '--quiet', '--manifest-path', manifest,
    '--example', 'responder_jsonl', '--', permitted,
  ], {stdio: ['pipe', 'pipe', 'pipe']});
  const reader = createInterface({input: child.stdout})[Symbol.asyncIterator]();
  let errors = '';
  child.stderr.on('data', data => {errors += data.toString();});
  const exitCode = new Promise(resolve => child.once('close', resolve));
  async function next() {
    const line = await reader.next();
    if (line.done) throw new Error('Rust responder closed: ' + errors);
    return line.value;
  }
  try {
    const info = JSON.parse(await next());
    const initiator = await createInitiator(client, info.peerId);
    child.stdin.write(initiator.hello() + '\n');
    const challenge = await next();
    const response = await initiator.answer(challenge);
    child.stdin.write(response + '\n');
    if (allow) {
      assert.equal(await initiator.finish(await next()), info.peerId);
      child.stdin.end();
      assert.equal(await exitCode, 0, errors);
      assert.match(errors, /Verified:/);
    } else {
      child.stdin.end();
      assert.equal(await exitCode, 3, errors);
      assert.match(errors, /Untrusted/);
    }
  } finally {
    child.kill();
  }
}

test('WebCrypto browser initiator authenticates Rust Coqui responder',
  {timeout: 150_000}, async () => {await interact(true);});
test('Rust responder denies an unpaired browser peer',
  {timeout: 150_000}, async () => {await interact(false);});
