import { createHash } from 'node:crypto';
import { chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';

export const MAX_TEXT = 4000;
export const MAX_PENDING = 200;
export const MAX_OUTBOX = 200;
export const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
export const MAX_IMAGE_OUTBOX = 20;
// The sender sees only WhatsApp. A turn that runs for many minutes while the
// agent says nothing is indistinguishable from a dead session, and the bridge
// cannot steer a running turn, so the nudge has to ride along with the message.
export const REPLY_GUIDANCE = 'The sender only sees WhatsApp, not this session: reply right away with a one-line acknowledgement, even if it only says you have started; on work that runs more than a few minutes, send a short progress update every few minutes and a final reply when done.';

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
  const entry = Object.hasOwn(state.messages, id) ? state.messages[id] : null;
  if (!entry) throw new Error('unknown message id');
  if (typeof text !== 'string' || !text.trim() || text.length > MAX_TEXT) {
    throw new Error('reply must be 1-4000 characters');
  }
  if (entry.reply && (entry.reply.image || entry.reply.text !== text)) throw new Error('message already has a different reply');
  if (!entry.reply && Object.values(state.messages).filter((message) => message.reply?.status === 'queued').length >= MAX_OUTBOX) {
    throw new Error('reply outbox full');
  }
  entry.reply ||= { text, status: 'queued' };
  return entry;
}

// Read a bounded regular file through one descriptor so validation and copying
// use the same bytes, even if the caller replaces the source after queuing.
function readImage(path, dir) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('image path must be absolute');
  // Resolve parent directories before checking roots; a symlinked directory
  // must not turn an allowed local image into a read outside the user's files.
  const canonicalPath = join(realpathSync(dirname(path)), basename(path));
  const homeRoot = realpathSync(process.env.HOME);
  const stateRoot = realpathSync(dir);
  if (!canonicalPath.startsWith(homeRoot + sep) && !canonicalPath.startsWith(stateRoot + sep)) {
    throw new Error('image must be inside the user home or bridge state directory');
  }
  const fd = openSync(canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error('image must be a regular file');
    if (!info.size || info.size > MAX_IMAGE_BYTES) throw new Error('image must be 1 byte to 10 MiB');
    const data = Buffer.alloc(info.size + 1);
    let size = 0;
    while (size < data.length) {
      const count = readSync(fd, data, size, data.length - size, null);
      if (!count) break;
      size += count;
    }
    if (!size || size > MAX_IMAGE_BYTES) throw new Error('image must be 1 byte to 10 MiB');
    if (size !== info.size) throw new Error('image changed while reading');
    const bytes = data.subarray(0, size);
    let extension;
    if (bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) extension = 'png';
    else if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) extension = 'jpg';
    else if (bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') extension = 'webp';
    else throw new Error('image must have a PNG, JPEG, or WebP signature');
    return { bytes, extension };
  } finally { closeSync(fd); }
}

export function imageReplyPath(dir, image) {
  if (typeof image !== 'string' || !/^[a-f0-9]{64}\.(png|jpg|webp)$/.test(image)) {
    throw new Error('invalid queued image name');
  }
  const outbox = join(dir, 'media-outbox');
  ensurePrivateDir(outbox);
  return join(outbox, image);
}

export function queueImageReply(state, dir, id, path, caption = '') {
  const entry = Object.hasOwn(state.messages, id) ? state.messages[id] : null;
  if (!entry) throw new Error('unknown message id');
  if (typeof caption !== 'string' || caption.length > MAX_TEXT) throw new Error('caption must be at most 4000 characters');
  if (!entry.reply && Object.values(state.messages).filter((message) => message.reply?.status === 'queued').length >= MAX_OUTBOX) {
    throw new Error('reply outbox full');
  }
  if (!entry.reply && Object.values(state.messages).filter((message) => message.reply?.status === 'queued' && message.reply.image).length >= MAX_IMAGE_OUTBOX) {
    throw new Error('image outbox full (20 queued images maximum)');
  }
  const { bytes, extension } = readImage(path, dir);
  // Include the message ID: each reply owns its own file and cleanup cannot
  // remove an identical picture still queued for a different request.
  const image = `${createHash('sha256').update(id).update('\0').update(bytes).digest('hex')}.${extension}`;
  if (entry.reply) {
    if (entry.reply.image !== image || entry.reply.caption !== caption) throw new Error('message already has a different reply');
    return entry;
  }
  const destination = imageReplyPath(dir, image);
  const temporary = `${destination}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, bytes, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, destination);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
  entry.reply = { image, caption, status: 'queued' };
  return entry;
}

export function imageReplyContent(dir, reply) {
  const path = imageReplyPath(dir, reply.image);
  const { bytes, extension } = readImage(path, dir);
  const mimetype = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp' }[extension];
  return { image: bytes, caption: reply.caption, mimetype };
}

export function cleanImageOutbox(dir, state) {
  const outbox = join(dir, 'media-outbox');
  if (!existsSync(outbox)) return;
  ensurePrivateDir(outbox);
  const queued = new Set(Object.values(state.messages)
    .filter((entry) => entry.reply?.status === 'queued' && entry.reply.image)
    .map((entry) => entry.reply.image));
  for (const name of readdirSync(outbox)) {
    if (/^[a-f0-9]{64}\.(png|jpg|webp)(\.\d+\.tmp)?$/.test(name) && !queued.has(name)) {
      unlinkSync(join(outbox, name));
    }
  }
}
