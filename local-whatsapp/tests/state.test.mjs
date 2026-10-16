import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, symlinkSync, truncateSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { addInbound, loadState, parseInbound, queueReply, queueImageReply, imageReplyContent, cleanImageOutbox, MAX_IMAGE_BYTES, MAX_IMAGE_OUTBOX, MAX_TEXT, saveState } from '../state.mjs';

const credentials = { me: { id: '14155551234:2@s.whatsapp.net' } };
function message(text, id = 'ABC123', remoteJid = '14155551234@s.whatsapp.net') {
  return { key: { id, fromMe: true, remoteJid }, message: { conversation: text } };
}

test('a prefix is required unless it is configured empty', () => {
  assert.equal(parseInbound(message('hello'), credentials, {}), null);
  assert.equal(parseInbound(message('/sessions'), credentials, {}), null);
  assert.equal(parseInbound(message('@BOX hello'), credentials, {}).text, 'hello');
  assert.equal(parseInbound(message('@work hello'), credentials, {}, '@work').text, 'hello');
  assert.equal(parseInbound(message('@box hello'), credentials, {}, '@work'), null);
});

test('with an empty prefix, owner self-chat text needs no addressing', () => {
  assert.equal(parseInbound(message('hello'), credentials, {}, '').text, 'hello');
  assert.equal(parseInbound(message('  hello  '), credentials, {}, '').text, 'hello');
  assert.equal(parseInbound(message('@BOX hello'), credentials, {}, '').text, '@BOX hello');
  assert.equal(parseInbound(message('@agent hello'), credentials, {}, '').text, '@agent hello');
  assert.equal(parseInbound(message('/sessions'), credentials, {}, '').text, '/sessions');
  assert.equal(parseInbound(message('hello @box again'), credentials, {}, '').text, 'hello @box again');
  assert.equal(parseInbound(message('@boxes hello'), credentials, {}, '').text, '@boxes hello');
  for (const text of ['', '  ']) {
    assert.equal(parseInbound(message(text), credentials, {}, ''), null);
  }
});

test('plain and prefixed text keep owner, self-chat and sent-message checks', () => {
  for (const text of ['hello', '@box hello', '/sessions', '@box /sessions']) {
    assert.equal(parseInbound(message(text, 'A', '19995551234@s.whatsapp.net'), credentials, {}, ''), null);
    assert.equal(parseInbound(message(text, 'A', '123@g.us'), credentials, {}, ''), null);
    assert.equal(parseInbound({ ...message(text), key: { ...message(text).key, fromMe: false } }, credentials, {}, ''), null);
    assert.equal(parseInbound(message(text), credentials, { 'wa:ABC123': 1 }, ''), null);
    assert.equal(parseInbound(message(text), {}, {}, ''), null);
  }
  const linked = { me: { ...credentials.me, lid: '123456:2@lid' } };
  assert.equal(parseInbound(message('hello', 'A', '123456@lid'), linked, {}, '').text, 'hello');
  assert.equal(parseInbound(message('hello', 'A', '14155551234:3@s.whatsapp.net'), credentials, {}, '').text, 'hello');
});

test('empty-prefix and prefixed text enforce the same message size limit', () => {
  const text = 'a'.repeat(MAX_TEXT);
  for (const prefix of [undefined, '']) {
    const head = prefix === undefined ? '@box ' : '';
    assert.equal(parseInbound(message(head + text), credentials, {}, prefix).text, text);
    assert.equal(parseInbound(message(head + text + 'a'), credentials, {}, prefix), null);
  }
  const extended = message('unused');
  extended.message = { extendedTextMessage: { text: 'reply to a message' } };
  assert.equal(parseInbound(extended, credentials, {}, '').text, 'reply to a message');
  const ephemeral = message('unused');
  ephemeral.message = { ephemeralMessage: { message: { conversation: 'ephemeral text' } } };
  assert.equal(parseInbound(ephemeral, credentials, {}, '').text, 'ephemeral text');
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

const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aK6sAAAAASUVORK5CYII=', 'base64');

test('queued images survive source deletion and restart, deduplicate, and clean up after sending', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whatsapp-images-'));
  try {
    const source = join(dir, 'source.png');
    writeFileSync(source, png);
    const state = loadState(dir);
    const first = parseInbound(message('@box picture'), credentials, {});
    const second = parseInbound(message('@box another picture', 'SECOND'), credentials, {});
    addInbound(state, first); addInbound(state, second);
    queueImageReply(state, dir, first.id, source, 'caption');
    const image = first.reply.image;
    assert.equal(queueImageReply(state, dir, first.id, source, 'caption').reply.image, image);
    assert.throws(() => queueImageReply(state, dir, first.id, source, 'different'), /different reply/);
    assert.throws(() => queueReply(state, first.id, 'text'), /different reply/);
    queueImageReply(state, dir, second.id, source);
    assert.notEqual(second.reply.image, image);
    assert.equal(statSync(join(dir, 'media-outbox', image)).mode & 0o077, 0);
    saveState(dir, state); rmSync(source);
    const restored = loadState(dir);
    cleanImageOutbox(dir, restored);
    assert.deepEqual(imageReplyContent(dir, restored.messages[first.id].reply), { image: png, caption: 'caption', mimetype: 'image/png' });
    restored.messages[first.id].reply.status = 'sent';
    cleanImageOutbox(dir, restored);
    assert.equal(existsSync(join(dir, 'media-outbox', image)), false);
    assert.equal(existsSync(join(dir, 'media-outbox', second.reply.image)), true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('image validation rejects unknown IDs, unsafe inputs, oversized files, and changed replies', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whatsapp-validation-'));
  try {
    const state = loadState(dir);
    const inbound = parseInbound(message('@box hello'), credentials, {});
    addInbound(state, inbound);
    const source = join(dir, 'source.png'); writeFileSync(source, png);
    assert.throws(() => queueImageReply(state, dir, 'unknown', source), /unknown message/);
    assert.throws(() => queueImageReply(state, dir, 'toString', source), /unknown message/);
    assert.throws(() => queueImageReply(state, dir, inbound.id, 'relative.png'), /absolute/);
    assert.throws(() => queueImageReply(state, dir, inbound.id, join(dir, 'messages.json')), /ENOENT/);
    mkdirSync(join(dir, 'directory.png'));
    assert.throws(() => queueImageReply(state, dir, inbound.id, join(dir, 'directory.png')), /regular file/);
    const outside = mkdtempSync(join(tmpdir(), 'whatsapp-outside-'));
    try {
      writeFileSync(join(outside, 'image.png'), png);
      assert.throws(() => queueImageReply(state, dir, inbound.id, join(outside, 'image.png')), /inside the user home/);
      symlinkSync(outside, join(dir, 'outside'));
      assert.throws(() => queueImageReply(state, dir, inbound.id, join(dir, 'outside', 'image.png')), /inside the user home/);
    } finally { rmSync(outside, { recursive: true, force: true }); }
    symlinkSync(source, join(dir, 'symlink.png'));
    assert.throws(() => queueImageReply(state, dir, inbound.id, join(dir, 'symlink.png')));
    assert.throws(() => queueImageReply(state, dir, inbound.id, source, 'a'.repeat(4001)), /caption/);
    writeFileSync(source, 'not an image');
    assert.throws(() => queueImageReply(state, dir, inbound.id, source), /signature/);
    writeFileSync(source, '');
    assert.throws(() => queueImageReply(state, dir, inbound.id, source), /10 MiB/);
    truncateSync(source, MAX_IMAGE_BYTES + 1);
    assert.throws(() => queueImageReply(state, dir, inbound.id, source), /10 MiB/);
    writeFileSync(source, png);
    queueReply(state, inbound.id, 'already answered');
    assert.throws(() => queueImageReply(state, dir, inbound.id, source), /different reply/);
    assert.equal(existsSync(join(dir, 'media-outbox')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('image outbox is bounded and orphaned copies are reclaimed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whatsapp-outbox-limit-'));
  try {
    const state = loadState(dir);
    const source = join(dir, 'picture.png'); writeFileSync(source, png);
    for (let i = 0; i < MAX_IMAGE_OUTBOX; i++) {
      const inbound = parseInbound(message('@box picture', `ID${i}`), credentials, {});
      addInbound(state, inbound); queueImageReply(state, dir, inbound.id, source);
    }
    const extra = parseInbound(message('@box picture', 'EXTRA'), credentials, {});
    addInbound(state, extra);
    assert.throws(() => queueImageReply(state, dir, extra.id, source), /image outbox full/);
    const first = Object.values(state.messages)[0];
    const path = join(dir, 'media-outbox', first.reply.image);
    first.reply = null; // simulates a crash before copied media was saved in the inbox
    cleanImageOutbox(dir, state);
    assert.equal(existsSync(path), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
