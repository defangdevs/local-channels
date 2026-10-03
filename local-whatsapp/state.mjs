import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const MAX_TEXT = 4000;
export const MAX_PENDING = 200;
export const MAX_OUTBOX = 200;

export function stateDir() {
  return process.env.LOCAL_WHATSAPP_STATE_DIR ||
    join(process.env.HOME, '.local', 'state', 'local-whatsapp');
}

export function ensurePrivateDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (lstatSync(dir).isSymbolicLink()) throw new Error('state directory may not be a symlink');
  chmodSync(dir, 0o700);
}

export function loadState(dir) {
  ensurePrivateDir(dir);
  const path = join(dir, 'messages.json');
  if (!existsSync(path)) return { messages: {}, sentIds: {} };
  const value = JSON.parse(readFileSync(path, 'utf8'));
  if (!value || typeof value.messages !== 'object' || typeof value.sentIds !== 'object') {
    throw new Error('invalid messages.json');
  }
  return value;
}

export function saveState(dir, state) {
  ensurePrivateDir(dir);
  const path = join(dir, 'messages.json');
  const temporary = join(dir, `messages.${process.pid}.tmp`);
  writeFileSync(temporary, JSON.stringify(state), { mode: 0o600 });
  renameSync(temporary, path);
}

export function ownChatIds(credentials) {
  return [credentials?.me?.id, credentials?.me?.lid]
    .filter(Boolean)
    .map((jid) => jid.replace(/:\d+@/, '@'));
}

function textOf(message) {
  const value = message?.ephemeralMessage?.message || message?.viewOnceMessage?.message || message;
  return value?.conversation || value?.extendedTextMessage?.text || '';
}

export function parseInbound(message, credentials, sentIds, prefix = '@box') {
  const key = message?.key;
  const chat = key?.remoteJid?.replace(/:\d+@/, '@');
  if (!key?.id || !key?.fromMe || !ownChatIds(credentials).includes(chat)) return null;
  if (Object.hasOwn(sentIds, `wa:${key.id}`)) return null;
  const fullText = textOf(message.message);
  if (typeof fullText !== 'string' || fullText.length > MAX_TEXT + prefix.length + 1) return null;
  const head = `${prefix} `;
  if (!fullText.toLowerCase().startsWith(head.toLowerCase())) return null;
  const text = fullText.slice(head.length).trim();
  if (!text) return null;
  return {
    id: createHash('sha256').update(`${chat}\0${key.id}`).digest('hex').slice(0, 24),
    chat,
    text,
    receivedAt: new Date().toISOString(),
    deliveredTo: null,
    reply: null,
  };
}

export function addInbound(state, inbound) {
  if (state.messages[inbound.id]) return false;
  const pending = Object.values(state.messages).filter((entry) => !entry.reply);
  if (pending.length >= MAX_PENDING) throw new Error('inbox full');
  state.messages[inbound.id] = inbound;
  return true;
}

export function publicMessage(entry) {
  return { id: entry.id, text: entry.text, receivedAt: entry.receivedAt };
}

export function queueReply(state, id, text) {
  const entry = state.messages[id];
  if (!entry) throw new Error('unknown message id');
  if (typeof text !== 'string' || !text.trim() || text.length > MAX_TEXT) {
    throw new Error('reply must be 1-4000 characters');
  }
  if (entry.reply && entry.reply.text !== text) throw new Error('message already has a different reply');
  if (!entry.reply && Object.values(state.messages).filter((message) => message.reply?.status === 'queued').length >= MAX_OUTBOX) {
    throw new Error('reply outbox full');
  }
  entry.reply ||= { text, status: 'queued' };
  return entry;
}
