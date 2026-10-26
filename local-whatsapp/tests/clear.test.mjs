import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { retireConversation, addInbound, queueReply, queueImageReply, saveState, loadState, MAX_PENDING } from '../state.mjs';

test('clear retires pending messages, rejects late text/image replies, and survives restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wa-clear-'));
  try {
    const old = { id: 'old', text: 'old context', reply: null, ack: { status: 'queued' } };
    const queued = { id: 'queued', text: 'old work', reply: { status: 'queued', text: 'late answer' } };
    const clear = { id: 'clear', text: '/clear', control: true, reply: null };
    const after = { id: 'after', text: 'queued after reset', reply: null };
    const state = { messages: { old, queued, clear, after }, sentIds: {}, acceptMediaUntil: Date.now() + 600000 };
    retireConversation(state, 'clear');
    assert.ok(old.clearedAt); assert.ok(queued.clearedAt); assert.equal(after.clearedAt, undefined); assert.equal(clear.clearedAt, undefined);
    assert.equal(old.ack.status, 'cleared'); assert.equal(queued.reply.status, 'cleared');
    assert.equal(state.acceptMediaUntil, 0);
    assert.throws(() => queueReply(state, 'old', 'late response'), /cleared conversation/);
    assert.throws(() => queueImageReply(state, dir, 'old', '/no-such-image.png'), /cleared conversation/);
    queueReply(state, 'clear', 'Context cleared');
    addInbound(state, { id: 'new', text: 'fresh input', reply: null });
    saveState(dir, state);
    const loaded = loadState(dir);
    assert.ok(loaded.messages.old.clearedAt);
    assert.equal(loaded.messages.new.clearedAt, undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('clear works at the pending-message limit, then retired messages stop consuming capacity', () => {
  const state = { messages: {}, sentIds: {} };
  for (let i = 0; i < MAX_PENDING; i++) addInbound(state, { id: String(i), text: 'old', reply: null });
  assert.throws(() => addInbound(state, { id: 'overflow', reply: null }), /inbox full/);
  addInbound(state, { id: 'clear', text: '/clear', control: true, reply: null });
  retireConversation(state, 'clear');
  addInbound(state, { id: 'fresh', text: 'new', reply: null });
  assert.equal(state.messages.fresh.text, 'new');
});
