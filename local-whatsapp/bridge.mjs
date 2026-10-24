#!/usr/bin/env node
import { createServer, createConnection } from 'node:net';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync, unlinkSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { userInfo } from 'node:os';
import WebSocket from 'ws';
import pino from 'pino';
import { REPLY_GUIDANCE, retireConversation, attachmentNotice, receiveAttachment, cleanMediaInbox, addInbound, cleanImageOutbox, imageReplyContent, queueImageReply, ensurePrivateDir, loadState, parseInbound, queueReply, saveState, stateDir } from './state.mjs';

process.umask(0o077);
const dir = stateDir();
const socketPath = join(dir, 'bridge.sock');
const targetPath = join(dir, 'target.json');
const configPath = join(dir, 'config.json');
const codexThreadsPath = join(dir, 'codex-threads.json');
const authPath = join(dir, 'auth');
const command = process.argv[2];
const logger = pino({ level: 'silent' });
const debugReceipts = process.env.LOCAL_WHATSAPP_DEBUG === '1';
// LOCAL_WHATSAPP_PREFIX names the agent (default `@<linux user>`). Set it empty
// to accept every self-chat text without a prefix.
const addressPrefix = (() => {
  const raw = process.env.LOCAL_WHATSAPP_PREFIX;
  if (raw !== undefined && raw.trim() === '') return '';
  if (raw?.trim() === '@') return '@';
  const name = (raw ?? userInfo().username).trim().replace(/^@/, '');
  return `@${/^[A-Za-z0-9_.-]{1,64}$/.test(name) ? name : userInfo().username}`;
})();
const sessionBin = process.env.LOCAL_WHATSAPP_SESSION_BIN || '/usr/local/bin/agent-box-session';
const codexBin = process.env.LOCAL_WHATSAPP_CODEX_BIN || join(userInfo().homedir, '.nix-profile', 'bin', 'codex');
if (!isAbsolute(sessionBin) || !isAbsolute(codexBin)) throw new Error('bridge helper paths must be absolute');

function target() {
  if (!existsSync(targetPath)) return null;
  const value = JSON.parse(readFileSync(targetPath, 'utf8'));
  if (!['claude', 'codex'].includes(value.harness) || !/^[A-Za-z0-9_-]{1,200}$/.test(value.session)) {
    throw new Error('invalid target.json');
  }
  if (value.harness === 'codex' && value.name) {
    const registered = codexThreads()[value.name];
    if (registered) return { ...value, session: registered.thread };
  }
  return value;
}

function config() {
  if (!existsSync(configPath)) return { profile: null };
  const value = JSON.parse(readFileSync(configPath, 'utf8'));
  if (!value || Array.isArray(value) ||
      (value.profile !== null && !/^[A-Za-z0-9._-]{1,64}$/.test(value.profile))) {
    throw new Error('invalid config.json');
  }
  return { profile: value.profile };
}

function setProfile(profile) {
  const temporary = `${configPath}.${process.pid}.tmp`;
  writeFileSync(temporary, JSON.stringify({ profile }), { mode: 0o600 });
  renameSync(temporary, configPath);
}

function codexThreads() {
  if (!existsSync(codexThreadsPath)) return {};
  const value = JSON.parse(readFileSync(codexThreadsPath, 'utf8'));
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('invalid codex-threads.json');
  return value;
}

function setTarget(harness, session, name) {
  const temporary = `${targetPath}.${process.pid}.tmp`;
  writeFileSync(temporary, JSON.stringify({ harness, session, ...(name ? { name } : {}) }), { mode: 0o600 });
  renameSync(temporary, targetPath);
}

// Attach directly to the existing Codex daemon. Never launch a replacement
// harness or use the session manager's spawn/activate/clear lifecycle here.
async function resetCodexThread(binding) {
  const socket = process.env.LOCAL_WHATSAPP_CODEX_SOCKET ||
    join(process.env.CODEX_HOME || join(process.env.HOME, '.codex'), 'app-server-control', 'app-server-control.sock');
  if (!isAbsolute(socket) || socket.includes(':')) throw new Error('Codex control socket must be an absolute Unix path');
  const ws = new WebSocket(`ws+unix://${socket}:/`, { handshakeTimeout: 10000, maxPayload: 8 * 1024 * 1024 });
  const pending = new Map();
  let serial = 0;
  const rejectPending = (error) => {
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(error); }
    pending.clear();
  };
  ws.on('error', rejectPending);
  ws.on('close', () => rejectPending(new Error('Codex control connection closed')));
  ws.on('message', (raw) => {
    try {
      const message = JSON.parse(raw.toString());
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id); clearTimeout(request.timer);
      if (message.error) request.reject(new Error(message.error.message || 'Codex reset failed'));
      else request.resolve(message.result);
    } catch (error) { rejectPending(error); }
  });
  function rpc(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++serial;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Codex ${method} timed out`)); }, 30000);
      pending.set(id, { resolve, reject, timer });
      ws.send(JSON.stringify({ id, method, params }), (error) => {
        if (error) { clearTimeout(timer); pending.delete(id); reject(error); }
      });
    });
  }
  try {
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    await rpc('initialize', { clientInfo: { name: 'local_whatsapp', version: '0.5.0' }, capabilities: { experimentalApi: true } });
    ws.send(JSON.stringify({ method: 'initialized', params: {} }));
    const { thread } = await rpc('thread/read', { threadId: binding.session, includeTurns: false });
    if (!thread || thread.id !== binding.session) throw new Error('Codex returned a different current thread');
    if (thread.historyMode !== 'paginated') throw Object.assign(new Error('In-process clear requires a paginated Codex thread; context was not changed'), { resetUnsupported: true });
    await rpc('thread/resume', { threadId: thread.id, excludeTurns: true,
      ...(thread.model ? { model: thread.model } : {}), ...(thread.modelProvider ? { modelProvider: thread.modelProvider } : {}) });
    const page = await rpc('thread/turns/list', { threadId: thread.id, sortDirection: 'asc', limit: 1 });
    if (!Array.isArray(page.data)) throw new Error('Invalid Codex history response');
    if (page.data.length) {
      const firstTurn = page.data[0].id;
      if (typeof firstTurn !== 'string' || !firstTurn) throw new Error('Invalid Codex first turn');
      // Native revert removes this turn and every later turn from the model
      // context and durable thread history. It leaves instructions/settings,
      // the thread identity and the existing harness process intact.
      await rpc('thread/revert', { threadId: thread.id, beforeTurnId: firstTurn });
    }
    const checked = await rpc('thread/turns/list', { threadId: thread.id, sortDirection: 'asc', limit: 1 });
    if (!Array.isArray(checked.data) || checked.data.length) throw new Error('Codex history is not empty after clear');
    return binding;
  } finally { rejectPending(new Error('Codex reset finished')); ws.close(); }
}

async function sessions() {
  return new Promise((resolve, reject) => {
    const child = spawn(sessionBin, ['whatsapp', 'candidates'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let error = '';
    const timeout = setTimeout(() => child.kill(), 10000);
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      if (output.length > 20000) child.kill();
    });
    child.stderr.on('data', (chunk) => { error += chunk.toString().slice(0, 1000); });
    child.on('error', (failure) => { clearTimeout(timeout); reject(failure); });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) return reject(new Error(error.trim() || 'cannot list WhatsApp-enabled sessions'));
      try {
        const records = JSON.parse(output);
        if (!Array.isArray(records) || records.some((item) =>
          !/^[A-Za-z0-9_-]{1,150}$/.test(item.name) ||
          !['claude', 'codex'].includes(item.harness) || typeof item.stopped !== 'boolean' ||
          typeof item.selected !== 'boolean')) {
          throw new Error('invalid session list');
        }
        resolve(records.map((item) => ({ ...item, status: item.stopped ? 'stopped' : 'enabled' })));
      } catch (failure) { reject(failure); }
    });
  });
}

async function sessionCommand(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(sessionBin, ['whatsapp', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let error = '';
    const timeout = setTimeout(() => child.kill(), 10000);
    child.stdout.on('data', (chunk) => { output += chunk.toString().slice(0, 20000); });
    child.stderr.on('data', (chunk) => { error += chunk.toString().slice(0, 1000); });
    child.on('error', (failure) => { clearTimeout(timeout); reject(failure); });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) return reject(new Error(error.trim() || 'WhatsApp session command failed'));
      try { resolve(JSON.parse(output)); }
      catch (failure) { reject(failure); }
    });
  });
}

async function clearTarget() {
  await sessionCommand(['clear']);
  if (existsSync(targetPath)) unlinkSync(targetPath);
}

async function selectTarget(name) {
  const selected = await sessionCommand(['select', name]);
  if (!selected || !['claude', 'codex'].includes(selected.harness) ||
      selected.name !== name || typeof selected.stopped !== 'boolean') {
    throw new Error('invalid selected session');
  }
  setTarget(selected.harness,
    selected.harness === 'claude' ? `${userInfo().username}-${name}` : name,
    name);
  return selected;
}

async function ensureTarget(available) {
  const binding = target();
  const selected = binding && available.find((item) => item.name === binding.name &&
    item.harness === binding.harness);
  if (selected) {
    if (selected.stopped) {
      const activated = await sessionCommand(['activate', selected.name]);
      if (!activated || activated.name !== selected.name ||
          activated.harness !== selected.harness || typeof activated.activated !== 'boolean') {
        throw new Error('invalid activated session');
      }
    }
    return binding;
  }
  if (binding) throw new Error(`selected session ${binding.name} is unavailable`);
  const created = await sessionCommand(['spawn', config().profile || 'default']);
  if (!created || !['claude', 'codex'].includes(created.harness) ||
      !/^[A-Za-z0-9_-]{1,150}$/.test(created.name || '')) {
    throw new Error('invalid spawned session');
  }
  setTarget(created.harness,
    created.harness === 'claude' ? `${userInfo().username}-${created.name}` : created.name,
    created.name);
  return target();
}

function request(value) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let data = '';
    socket.setTimeout(10000);
    socket.on('connect', () => socket.write(`${JSON.stringify(value)}\n`));
    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (!data.includes('\n')) return;
      socket.end();
      try {
        const answer = JSON.parse(data.split('\n')[0]);
        if (answer.ok) resolve(answer);
        else reject(new Error(answer.error));
      } catch (error) { reject(error); }
    });
    socket.on('timeout', () => socket.destroy(new Error('bridge timeout')));
    socket.on('error', reject);
  });
}

async function baileys() {
  const library = await import('@whiskeysockets/baileys');
  return { ...library, makeWASocket: library.default || library.makeWASocket };
}

async function pair() {
  ensurePrivateDir(dir);
  ensurePrivateDir(authPath);
  const phone = (process.env.LOCAL_WHATSAPP_PHONE || readFileSync(0, 'utf8')).trim().replace(/\D/g, '');
  if (!/^\d{7,15}$/.test(phone)) throw new Error('enter an international phone number on stdin');
  const { makeWASocket, useMultiFileAuthState, Browsers } = await baileys();
  let requested = false;
  let linked = false;
  async function connectForPair() {
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    if (state.creds.me && !requested) throw new Error('this device is already paired');
    const socket = makeWASocket({ auth: state, browser: Browsers.macOS('Chrome'), printQRInTerminal: false, logger });
    socket.ev.on('creds.update', saveCreds);
    socket.ev.on('connection.update', async ({ qr, connection, lastDisconnect }) => {
      if (qr && !requested) {
        requested = true;
        try {
          const code = await socket.requestPairingCode(phone);
          process.stdout.write(`WhatsApp pairing code: ${code}\n`);
          process.stdout.write('Enter it in WhatsApp > Linked devices > Link a device > Link with phone number instead.\n');
        } catch (error) { process.stderr.write(`pairing failed: ${error.message}\n`); process.exit(1); }
      }
      if (connection === 'open') {
        if (linked) return;
        linked = true;
        await saveCreds();
        process.stdout.write('WhatsApp device linked.\n');
        socket.end();
        setTimeout(() => process.exit(0), 500);
      } else if (connection === 'close' && lastDisconnect) {
        if (linked) return;
        const code = lastDisconnect.error?.output?.statusCode;
        if (code === 515) {
          setTimeout(() => connectForPair().catch((error) => { process.stderr.write(`${error.message}\n`); process.exit(1); }), 1000);
        } else {
          process.stderr.write(`pairing connection closed: ${lastDisconnect.error?.message || 'unknown'}\n`);
          process.exit(1);
        }
      }
    });
  }
  await connectForPair();
  setTimeout(() => { process.stderr.write('pairing timed out\n'); process.exit(1); }, 180000).unref();
}

async function serve() {
  ensurePrivateDir(dir);
  ensurePrivateDir(authPath);
  const { makeWASocket, useMultiFileAuthState, Browsers, DisconnectReason, downloadMediaMessage } = await baileys();
  const initialAuth = await useMultiFileAuthState(authPath);
  if (!initialAuth.state.creds.me) throw new Error('device not paired: run pair first');
  const state = loadState(dir);
  cleanImageOutbox(dir, state);
  cleanMediaInbox(dir, state, true);
  const peers = new Map();
  const runtimeId = randomUUID();
  let peerSerial = 0;
  let whatsapp = null;
  let connected = false;
  let draining = false;
  let dispatching = false;
  let dispatchFinished = null;
  let resetting = false;
  let handlingControls = false;
  let inboundQueue = Promise.resolve();

  async function sendViaCodex(name, message) {
    const text = `WhatsApp Message Yourself (${message.id}): ${message.text}${attachmentNotice(message)}\nReply in WhatsApp using: node ${fileURLToPath(import.meta.url)} reply ${message.id} <reply text>. For an image, use: node ${fileURLToPath(import.meta.url)} reply-image ${message.id} <absolute image path> [caption]. ${REPLY_GUIDANCE}`;
    return new Promise((resolve) => {
      const child = spawn(codexBin, ['queue', '--thread', name, '--message', text], { stdio: 'ignore' });
      const timeout = setTimeout(() => child.kill(), 10000);
      child.on('error', () => { clearTimeout(timeout); resolve(false); });
      child.on('close', (code) => { clearTimeout(timeout); resolve(code === 0); });
    });
  }

  async function dispatch() {
    if (dispatching || resetting || state.resetPending) return;
    dispatching = true;
    let finishDispatch;
    dispatchFinished = new Promise((resolve) => { finishDispatch = resolve; });
    try {
      if (!Object.values(state.messages).some((message) => !message.reply && !message.control && !message.clearedAt)) return;
      const available = await sessions();
      const binding = await ensureTarget(available);
      for (const message of Object.values(state.messages)) {
        if (resetting || state.resetPending) break;
        if (message.reply || message.control || message.clearedAt) continue;
        if (binding.harness === 'claude') {
          for (const [peer, info] of peers) {
            if (info.session !== binding.session || message.deliveredTo === info.id) continue;
            peer.write(`${JSON.stringify({ op: 'message', message })}\n`);
            message.deliveredTo = info.id;
            saveState(dir, state);
          }
        } else if (message.deliveredTo !== `codex:${binding.session}` &&
                   Date.now() - (message.lastAttemptAt || 0) >= 30000) {
          message.lastAttemptAt = Date.now();
          saveState(dir, state);
          if (await sendViaCodex(binding.session, message)) {
            message.deliveredTo = `codex:${binding.session}`;
            saveState(dir, state);
          }
        }
      }
    } finally {
      dispatching = false;
      finishDispatch();
      dispatchFinished = null;
    }
  }

  async function drainReplies() {
    if (!connected || !whatsapp || draining) return;
    draining = true;
    try {
      for (const entry of Object.values(state.messages)) {
        if (state.resetPending && entry.id !== state.resetPending) continue;
        if (entry.clearedAt) continue;
        if (entry.ack?.status === 'queued' && !debugReceipts) {
          // Do not replay old diagnostic receipts after debug mode is disabled.
          entry.ack.status = 'suppressed';
          saveState(dir, state);
        }
        if (entry.ack?.status === 'queued' && debugReceipts) {
          try {
            const sent = await whatsapp.sendMessage(entry.chat, { text: entry.ack.text });
            if (sent?.key?.id) state.sentIds[`wa:${sent.key.id}`] = Date.now();
            entry.ack.status = 'sent';
            saveState(dir, state);
          } catch (error) { process.stderr.write(`ack send failed: ${error.message}\n`); break; }
        }
        if (entry.reply?.status !== 'queued') continue;
        try {
          const content = entry.reply.image ? imageReplyContent(dir, entry.reply) : { text: entry.reply.text };
          const sent = await whatsapp.sendMessage(entry.chat, content);
          if (sent?.key?.id) state.sentIds[`wa:${sent.key.id}`] = Date.now();
          entry.reply.status = 'sent';
          entry.reply.sentAt = new Date().toISOString();
          for (const [id, timestamp] of Object.entries(state.sentIds)) {
            if (timestamp < Date.now() - 30 * 24 * 3600 * 1000) delete state.sentIds[id];
          }
          const completed = Object.values(state.messages)
            .filter((message) => message.reply?.status === 'sent' || message.clearedAt)
            .sort((left, right) => (left.clearedAt || left.reply.sentAt).localeCompare(right.clearedAt || right.reply.sentAt));
          for (const old of completed.slice(0, Math.max(0, completed.length - 1000))) delete state.messages[old.id];
          saveState(dir, state);
          cleanImageOutbox(dir, state);
          cleanMediaInbox(dir, state);
        } catch (error) { process.stderr.write(`reply send failed: ${error.message}\n`); break; }
      }
    } finally { draining = false; }
  }

  async function handleControls() {
    if (handlingControls) return;
    handlingControls = true;
    try {
      for (const inbound of Object.values(state.messages)) {
        if (!inbound.control || inbound.reply || inbound.clearedAt) continue;
        try {
          if (inbound.text === '/clear') {
            resetting = true;
            // Persist a barrier first: a restart or failed session command must
            // not reroute old pending messages into a new conversation.
            state.resetPending = inbound.id;
            saveState(dir, state);
            try {
              if (dispatchFinished) await dispatchFinished;
              const binding = target();
              if (!binding) throw Object.assign(new Error('No selected conversation to clear'), { resetUnsupported: true });
              if (binding.harness !== 'codex') throw Object.assign(new Error('In-process clear is not supported for this Claude connection; context was not changed and no replacement harness was started'), { resetUnsupported: true });
              await resetCodexThread(binding);
              retireConversation(state, inbound.id);
              saveState(dir, state);
              state.resetPending = Object.values(state.messages).find((entry) => entry.id !== inbound.id && entry.control && entry.text === '/clear' && !entry.reply && !entry.clearedAt)?.id || null;
              queueReply(state, inbound.id, 'Context cleared in the existing Codex thread and process. The system/workspace instructions and settings remain; previous chat turns have been removed.');
            } finally { resetting = false; }
            saveState(dir, state);
            cleanImageOutbox(dir, state);
            continue;
          }
          const available = await sessions();
          if (inbound.text === '/attach') {
            state.acceptMediaUntil = Date.now() + 10 * 60 * 1000;
            queueReply(state, inbound.id, 'Ready: send images, videos, or files here without a caption for the next 10 minutes (up to 20 MiB each).');
          } else if (inbound.text === '/sessions') {
            const listing = available.map(({ name, harness, status, selected }) =>
              `${name} (${harness}, ${status}${selected ? ', selected' : ''})`).join(', ') || 'none available';
            queueReply(state, inbound.id, `Box sessions: ${listing.slice(0, 3900)}`);
          } else {
            const name = inbound.text.match(/^\/target ([A-Za-z0-9_-]{1,150})$/)?.[1];
            const profile = inbound.text.match(/^\/profile (default|[A-Za-z0-9._-]{1,64})$/)?.[1];
            if (name === 'auto') {
              await clearTarget();
              queueReply(state, inbound.id, 'Box target: automatic. The next message starts a session using the selected profile.');
            } else if (name) {
              const selected = available.find((item) => item.name === name);
              if (!selected) throw new Error(`unknown session; send ${addressPrefix ? `${addressPrefix} ` : ''}/sessions`);
              await selectTarget(name);
              queueReply(state, inbound.id, `Box target: ${name} (${selected.harness}, ${selected.status}). Messages will wait if it is unavailable.`);
              await dispatch();
            } else if (profile) {
              setProfile(profile === 'default' ? null : profile);
              await clearTarget();
              queueReply(state, inbound.id, `Box profile: ${profile}. The next message starts a session with this profile.`);
            } else {
              throw new Error('use /target NAME, /target auto, or /profile NAME|default');
            }
          }
        } catch (error) {
          if (error.resetUnsupported) state.resetPending = null;
          queueReply(state, inbound.id, `Box: ${error.message}`);
        }
        saveState(dir, state);
      }
      await drainReplies();
    } finally { handlingControls = false; }
  }

  if (existsSync(socketPath)) {
    const status = await new Promise((resolve) => {
      const probe = createConnection(socketPath);
      probe.once('connect', () => { probe.destroy(); resolve('live'); });
      probe.once('error', (error) => resolve(error.code));
    });
    if (status === 'live') throw new Error('bridge already running');
    if (status !== 'ECONNREFUSED' && status !== 'ENOENT') throw new Error(`cannot inspect bridge socket: ${status}`);
    if (existsSync(socketPath)) unlinkSync(socketPath);
  }
  const server = createServer((peer) => {
    let buffer = '';
    peer.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.length > 20000) { peer.destroy(); return; }
      while (buffer.includes('\n')) {
        const index = buffer.indexOf('\n');
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        try {
          const value = JSON.parse(line);
          if (value.op === 'subscribe' && /^[A-Za-z0-9_-]{1,200}$/.test(value.session)) {
            for (const [oldPeer, info] of peers) {
              if (info.session === value.session) oldPeer.destroy();
            }
            peers.set(peer, { session: value.session, id: `${runtimeId}:${++peerSerial}` });
            dispatch().catch((error) => process.stderr.write(`${error.message}\n`));
          } else if (value.op === 'reply' || value.op === 'reply-image') {
            const entry = value.op === 'reply-image'
              ? queueImageReply(state, dir, value.id, value.path, value.caption)
              : queueReply(state, value.id, value.text);
            saveState(dir, state);
            peer.write(`${JSON.stringify({ ok: true, status: connected ? 'sending' : 'queued until WhatsApp reconnects', id: entry.id })}\n`);
            drainReplies().catch((error) => process.stderr.write(`reply drain failed: ${error.message}\n`));
          } else if (value.op === 'receive-files') {
            state.acceptMediaUntil = Date.now() + 10 * 60 * 1000;
            saveState(dir, state);
            peer.write(`${JSON.stringify({ ok: true, until: new Date(state.acceptMediaUntil).toISOString() })}\n`);
          } else if (value.op === 'status') {
            peer.write(`${JSON.stringify({ ok: true, connected, debugReceipts, resetPending: Boolean(state.resetPending), acceptMediaUntil: state.acceptMediaUntil || null, target: target(), pending: Object.values(state.messages).filter((entry) => !entry.reply && !entry.clearedAt).length })}\n`);
          } else {
            peer.write(`${JSON.stringify({ ok: false, error: 'unknown operation' })}\n`);
          }
        } catch (error) { peer.write(`${JSON.stringify({ ok: false, error: error.message })}\n`); }
      }
    });
    peer.on('close', () => peers.delete(peer));
    peer.on('error', () => peers.delete(peer));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  chmodSync(socketPath, 0o600);
  process.stdout.write('local-whatsapp bridge ready\n');
  let shuttingDown = false;
  async function connect() {
    const { state: credentials, saveCreds } = await useMultiFileAuthState(authPath);
    if (!credentials.creds.me) throw new Error('device not paired: run pair first');
    const socket = makeWASocket({ auth: credentials, browser: Browsers.macOS('Chrome'), printQRInTerminal: false, syncFullHistory: false, logger });
    whatsapp = socket;
    socket.ev.on('creds.update', saveCreds);
    socket.ev.on('messages.upsert', ({ messages, type }) => {
      inboundQueue = inboundQueue.then(async () => {
        if (type !== 'notify') return;
        for (const message of messages) {
          const inbound = parseInbound(message, credentials.creds, state.sentIds, addressPrefix, Date.now() < (state.acceptMediaUntil || 0));
          if (!inbound || Object.hasOwn(state.messages, inbound.id)) continue;
          try {
            if (Object.values(state.messages).filter((m) => !m.reply && !m.clearedAt).length >= 200 && !(!inbound.attachment && inbound.text === '/clear')) throw new Error('inbox full');
            if (inbound.attachment) {
              await receiveAttachment(dir, inbound, () => downloadMediaMessage(message, 'stream', { options: { timeout: 60000 } }, { logger, reuploadRequest: socket.updateMediaMessage }));
            }
            const control = !inbound.attachment && (inbound.text === '/clear' || inbound.text === '/attach' || inbound.text === '/sessions' || inbound.text.startsWith('/target') ||
              inbound.text.startsWith('/profile'));
            if (control) {
              inbound.control = true;
              if (inbound.text === '/clear' && !state.resetPending) state.resetPending = inbound.id;
            }
            else if (debugReceipts) inbound.ack = { text: `Box: received ${inbound.id}; waiting for session selection.`, status: 'queued' };
            if (addInbound(state, inbound)) {
              saveState(dir, state);
              if (control) await handleControls();
              else {
                let dispatchError = null;
                try { await dispatch(); }
                catch (error) { dispatchError = error; }
                const binding = target();
                const destination = binding ? `${binding.harness} session ${binding.session}` : 'a new session';
                const delivery = inbound.deliveredTo ? 'routed to' : 'waiting for';
                if (dispatchError) process.stderr.write(`dispatch failed: ${dispatchError.message}\n`);
                if (debugReceipts) inbound.ack = { text: dispatchError
                  ? `Box: ${dispatchError.message}`
                  : `Box: received ${inbound.id}; ${delivery} ${destination}.`, status: 'queued' };
              }
              saveState(dir, state);
              await drainReplies();
            }
          } catch (error) { process.stderr.write(`inbound failed: ${error.message}\n`); }
        }
      }).catch((error) => process.stderr.write(`inbound batch failed: ${error.message}\n`));
    });
    socket.ev.on('connection.update', ({ connection, lastDisconnect }) => {
      if (whatsapp !== socket) return;
      if (connection === 'open') {
        connected = true;
        drainReplies().catch((error) => process.stderr.write(`reply drain failed: ${error.message}\n`));
        dispatch().catch((error) => process.stderr.write(`dispatch failed: ${error.message}\n`));
      }
      if (connection !== 'close') return;
      connected = false;
      if (shuttingDown) return;
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code === DisconnectReason.loggedOut) {
        process.stderr.write('WhatsApp device logged out; pair again\n');
        return;
      }
      setTimeout(() => connect().catch((error) => process.stderr.write(`reconnect failed: ${error.message}\n`)), 5000);
    });
  }
  try {
    await connect();
    await handleControls();
  } catch (error) {
    server.close();
    throw error;
  }
  const interval = setInterval(() => {
    handleControls().catch((error) => process.stderr.write(`control failed: ${error.message}\n`));
    dispatch().catch((error) => process.stderr.write(`dispatch failed: ${error.message}\n`));
    drainReplies().catch((error) => process.stderr.write(`reply drain failed: ${error.message}\n`));
  }, 3000);
  process.on('SIGTERM', () => {
    shuttingDown = true;
    clearInterval(interval);
    whatsapp?.end();
    server.close(() => {
      if (existsSync(socketPath)) unlinkSync(socketPath);
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 1000).unref();
  });
}

async function main() {
  if (command === 'register') {
    if (process.argv[3] !== 'codex') throw new Error('usage: register codex');
    const prefix = `${userInfo().username}-`;
    const identity = process.env.LOCAL_WHATSAPP_SESSION || process.env.LOCAL_WEBHOOK_SESSION || '';
    const name = identity.startsWith(prefix) ? identity.slice(prefix.length) : '';
    const thread = process.env.CODEX_THREAD_ID || process.env.LOCAL_WEBHOOK_CODEX_THREAD || '';
    if (!/^[A-Za-z0-9_-]{1,150}$/.test(name) || !/^[A-Za-z0-9_-]{1,200}$/.test(thread)) {
      throw new Error('register must run inside a named agent-box Codex task with CODEX_THREAD_ID');
    }
    ensurePrivateDir(dir);
    const registered = codexThreads();
    registered[name] = { thread, registeredAt: new Date().toISOString() };
    const temporary = `${codexThreadsPath}.${process.pid}.tmp`;
    writeFileSync(temporary, JSON.stringify(registered), { mode: 0o600 });
    renameSync(temporary, codexThreadsPath);
    process.stdout.write(`Registered Codex task for ${name}\n`);
    return;
  }
  if (command === 'pair') return pair();
  if (command === 'serve') return serve();
  if (command === 'target') {
    const [harness, name] = process.argv.slice(3);
    if (!['claude', 'codex'].includes(harness) || !/^[A-Za-z0-9_-]{1,150}$/.test(name || '')) throw new Error('usage: target claude|codex AGENT_BOX_SESSION');
    const selected = (await sessions()).find((item) => item.name === name && item.harness === harness);
    if (!selected) throw new Error('unknown agent-box session');
    ensurePrivateDir(dir);
    await selectTarget(name);
    process.stdout.write(`Target: ${harness} session ${name}\n`);
    return;
  }
  if (command === 'reply-image') {
    const [id, path, ...caption] = process.argv.slice(3);
    const result = await request({ op: 'reply-image', id, path, caption: caption.join(' ') });
    process.stdout.write(`${result.status}\n`);
    return;
  }
  if (command === 'reply') {
    const id = process.argv[3];
    const text = process.argv.slice(4).join(' ');
    const result = await request({ op: 'reply', id, text });
    process.stdout.write(`${result.status}\n`);
    return;
  }
  if (command === 'receive-files') {
    const result = await request({ op: 'receive-files' });
    process.stdout.write(`Captionless self-chat uploads enabled until ${result.until}\n`);
    return;
  }
  if (command === 'status') {
    process.stdout.write(`${JSON.stringify({ ...await request({ op: 'status' }), profile: config().profile }, null, 2)}\n`);
    return;
  }
  throw new Error('usage: bridge.mjs pair|serve|target claude|codex AGENT_BOX_SESSION|register codex|receive-files|reply ID TEXT|reply-image ID ABSOLUTE_PATH [CAPTION]|status');
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
