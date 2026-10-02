import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { addInbound, loadState, parseInbound, queueReply, saveState } from '../state.mjs';

const credentials = { me: { id: '14155551234:2@s.whatsapp.net' } };
function message(text, id = 'ABC123', remoteJid = '14155551234@s.whatsapp.net') {
  return { key: { id, fromMe: true, remoteJid }, message: { conversation: text } };
}

test('only prefixed owner self-chat text is accepted', () => {
  assert.equal(parseInbound(message('hello'), credentials, {}), null);
  assert.equal(parseInbound(message('@box '), credentials, {}), null);
  assert.equal(parseInbound(message('@box hello', 'A', '19995551234@s.whatsapp.net'), credentials, {}), null);
  assert.equal(parseInbound({ ...message('@box hello'), key: { ...message('@box hello').key, fromMe: false } }, credentials, {}), null);
  assert.equal(parseInbound(message('@box hello'), credentials, { 'wa:ABC123': 1 }), null);
  assert.equal(parseInbound(message('@BOX hello'), credentials, {}).text, 'hello');
});

test('message ids deduplicate and replies cannot change destinations', () => {
  const state = { messages: {}, sentIds: {} };
  const inbound = parseInbound(message('@box hello'), credentials, {});
  assert.equal(addInbound(state, inbound), true);
  assert.equal(addInbound(state, inbound), false);
  assert.equal(queueReply(state, inbound.id, 'done').chat, '14155551234@s.whatsapp.net');
  assert.equal(queueReply(state, inbound.id, 'done').reply.text, 'done');
  assert.throws(() => queueReply(state, inbound.id, 'different'), /different reply/);
  assert.throws(() => queueReply(state, 'unknown', 'done'), /unknown message/);
});

test('inbox survives restart and is private', () => {
  const dir = mkdtempSync(join(tmpdir(), 'local-whatsapp-test-'));
  try {
    const state = loadState(dir);
    addInbound(state, parseInbound(message('@box hello'), credentials, {}));
    saveState(dir, state);
    assert.equal(Object.values(loadState(dir).messages)[0].text, 'hello');
    assert.equal(statSync(join(dir, 'messages.json')).mode & 0o077, 0);
    assert.ok(readFileSync(join(dir, 'messages.json'), 'utf8').includes('hello'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
