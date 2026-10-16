import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, truncateSync } from 'node:fs';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { parseInbound, receiveAttachment, cleanMediaInbox, publicMessage, attachmentNotice, MAX_INBOUND_BYTES, MAX_INBOUND_STORAGE, loadState, addInbound, queueReply, saveState } from '../state.mjs';

const creds = { me: { id: '123:1@s.whatsapp.net' } };
function raw(content, key = {}) {
  return { key: { id: 'MEDIA', fromMe: true, remoteJid: '123@s.whatsapp.net', ...key }, message: content };
}
function media(overrides = {}) {
  return raw({ documentMessage: { caption: '@box', fileName: '../../x\n.pdf', fileLength: 3, mimetype: 'application/pdf', ...overrides } });
}

test('media requires owner self-chat and explicit caption, with wrapper support', () => {
  const msg = media();
  const parsed = parseInbound(msg, creds, {});
  assert.equal(parsed.text, '');
  assert.equal(parsed.attachment.name, '../../x.pdf');
  assert.equal(parseInbound(media({ caption: '' }), creds, {}), null);
  assert.equal(parseInbound(media({ caption: '@boxes test' }), creds, {}), null);
  assert.equal(parseInbound(raw(msg.message, { fromMe: false }), creds, {}), null);
  assert.equal(parseInbound(raw(msg.message, { remoteJid: '456@s.whatsapp.net' }), creds, {}), null);
  assert.equal(parseInbound(msg, creds, { 'wa:MEDIA': 1 }), null);
  assert.equal(parseInbound(raw({ viewOnceMessage: { message: msg.message } }), creds, {}), null);
  assert.ok(parseInbound(raw({ documentWithCaptionMessage: { message: msg.message } }), creds, {}).attachment);
  assert.ok(parseInbound(raw({ ephemeralMessage: { message: msg.message } }), creds, {}).attachment);
});

test('streamed bytes persist privately, survive restart, and cleanup preserves referenced files', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'wa-inbound-'));
  try {
    const inbound = parseInbound(media(), creds, {});
    await receiveAttachment(dir, inbound, async () => Readable.from([Buffer.from('a'), Buffer.from('bc')]));
    assert.equal(inbound.attachment.size, 3);
    assert.equal(readFileSync(inbound.attachment.path, 'utf8'), 'abc');
    assert.equal(statSync(inbound.attachment.path).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, 'media-inbox')).mode & 0o777, 0o700);
    const state = loadState(dir); addInbound(state, inbound); saveState(dir, state);
    assert.deepEqual(publicMessage(loadState(dir).messages[inbound.id]).attachment, inbound.attachment);
    assert.match(attachmentNotice(inbound), /local attachment path/);
    cleanMediaInbox(dir, state);
    assert.equal(readdirSync(join(dir, 'media-inbox')).length, 1);
    cleanMediaInbox(dir, { messages: {} });
    assert.deepEqual(readdirSync(join(dir, 'media-inbox')), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('size declarations, actual bytes, disk quota, and download failures are bounded and reported', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'wa-inbound-limits-'));
  try {
    let calls = 0;
    const oversized = parseInbound(media({ fileLength: MAX_INBOUND_BYTES + 1 }), creds, {});
    await receiveAttachment(dir, oversized, async () => { calls++; });
    assert.equal(calls, 0); assert.match(oversized.attachment.error, /20 MiB/);
    const lied = parseInbound(media(), creds, {});
    await receiveAttachment(dir, lied, async () => Readable.from([Buffer.alloc(MAX_INBOUND_BYTES + 1)]));
    assert.match(lied.attachment.error, /20 MiB/);
    assert.deepEqual(readdirSync(join(dir, 'media-inbox')), []);
    const failed = parseInbound(media(), creds, {});
    await receiveAttachment(dir, failed, async () => { throw new Error('expired'); });
    assert.equal(failed.attachment.error, 'expired');
    const partial = parseInbound(media(), creds, {});
    await receiveAttachment(dir, partial, async () => Readable.from((async function* () { yield Buffer.from('a'); throw new Error('interrupted'); })()));
    assert.equal(partial.attachment.error, 'interrupted');
    assert.deepEqual(readdirSync(join(dir, 'media-inbox')), []);
    const large = join(dir, 'media-inbox', 'quota.bin'); writeFileSync(large, ''); truncateSync(large, MAX_INBOUND_STORAGE);
    const full = parseInbound(media(), creds, {});
    await receiveAttachment(dir, full, async () => { calls++; });
    assert.equal(calls, 0); assert.match(full.attachment.error, /storage is full/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('sent text can be followed by a final reply while retries remain idempotent', () => {
  const state = { messages: {}, sentIds: {} }; const inbound = parseInbound(media(), creds, {}); addInbound(state, inbound);
  queueReply(state, inbound.id, 'ack');
  assert.throws(() => queueReply(state, inbound.id, 'final'), /different reply/);
  inbound.reply.status = 'sent';
  queueReply(state, inbound.id, 'final');
  assert.equal(inbound.reply.text, 'final');
  queueReply(state, inbound.id, 'ack');
  assert.equal(inbound.reply.text, 'final');
});

test('captionless media remains opt-in while unprefixed text needs an empty prefix', () => {
  const upload = media({ caption: '' });
  assert.equal(parseInbound(upload, creds, {}), null);
  assert.ok(parseInbound(upload, creds, {}, '@box', true).attachment);
  assert.equal(parseInbound(raw(upload.message, { remoteJid: '456@s.whatsapp.net' }), creds, {}, '@box', true), null);
  assert.equal(parseInbound(raw(upload.message, { fromMe: false }), creds, {}, '@box', true), null);
  assert.equal(parseInbound(raw({ conversation: 'ordinary text' }), creds, {}, '@box', true), null);
  assert.equal(parseInbound(raw({ conversation: 'ordinary text' }), creds, {}, '', true).text, 'ordinary text');
  const video = raw({ videoMessage: { caption: '', mimetype: 'video/mp4', fileLength: 3 } });
  assert.equal(parseInbound(video, creds, {}), null);
  assert.equal(parseInbound(video, creds, {}, '@box', true).attachment.kind, 'video');
});
