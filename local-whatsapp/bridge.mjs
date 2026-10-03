#!/usr/bin/env node
import { createServer, createConnection } from 'node:net';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync, unlinkSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { userInfo } from 'node:os';
import pino from 'pino';
import { addInbound, ensurePrivateDir, loadState, parseInbound, queueReply, saveState, stateDir } from './state.mjs';

process.umask(0o077);
const dir = stateDir();
const socketPath = join(dir, 'bridge.sock');
const targetPath = join(dir, 'target.json');
const codexThreadsPath = join(dir, 'codex-threads.json');
const authPath = join(dir, 'auth');
const command = process.argv[2];
const logger = pino({ level: 'silent' });
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

async function sessions() {
  return new Promise((resolve, reject) => {
    const child = spawn(sessionBin, ['whatsapp', 'ls'], { stdio: ['ignore', 'pipe', 'pipe'] });
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
          !['claude', 'codex'].includes(item.harness) || typeof item.stopped !== 'boolean')) {
          throw new Error('invalid session list');
        }
        resolve(records.map((item) => ({ ...item, status: item.stopped ? 'stopped' : 'enabled' })));
      } catch (failure) { reject(failure); }
    });
  });
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
  const { makeWASocket, useMultiFileAuthState, Browsers, DisconnectReason } = await baileys();
  const initialAuth = await useMultiFileAuthState(authPath);
  if (!initialAuth.state.creds.me) throw new Error('device not paired: run pair first');
  const state = loadState(dir);
  const peers = new Map();
  const runtimeId = randomUUID();
  let peerSerial = 0;
  let whatsapp = null;
  let connected = false;
  let draining = false;
  let dispatching = false;
  let handlingControls = false;

  async function sendViaCodex(name, message) {
    const text = `WhatsApp Message Yourself (${message.id}): ${message.text}\nReply in WhatsApp using: node ${fileURLToPath(import.meta.url)} reply ${message.id} <reply text>.`;
    return new Promise((resolve) => {
      const child = spawn(codexBin, ['queue', '--thread', name, '--message', text], { stdio: 'ignore' });
      const timeout = setTimeout(() => child.kill(), 10000);
      child.on('error', () => { clearTimeout(timeout); resolve(false); });
      child.on('close', (code) => { clearTimeout(timeout); resolve(code === 0); });
    });
  }

  async function dispatch() {
    if (dispatching) return;
    dispatching = true;
    try {
      const binding = target();
      if (!binding) return;
      if (!Object.values(state.messages).some((message) => !message.reply && !message.control)) return;
      const available = await sessions();
      if (!available.some((item) => item.name === binding.name && item.harness === binding.harness)) return;
      for (const message of Object.values(state.messages)) {
        if (message.reply || message.control) continue;
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
    }
  }

  async function drainReplies() {
    if (!connected || !whatsapp || draining) return;
    draining = true;
    try {
      for (const entry of Object.values(state.messages)) {
        if (entry.ack?.status === 'queued') {
          try {
            const sent = await whatsapp.sendMessage(entry.chat, { text: entry.ack.text });
            if (sent?.key?.id) state.sentIds[`wa:${sent.key.id}`] = Date.now();
            entry.ack.status = 'sent';
            saveState(dir, state);
          } catch (error) { process.stderr.write(`ack send failed: ${error.message}\n`); break; }
        }
        if (entry.reply?.status !== 'queued') continue;
        try {
          const sent = await whatsapp.sendMessage(entry.chat, { text: entry.reply.text });
          if (sent?.key?.id) state.sentIds[`wa:${sent.key.id}`] = Date.now();
          entry.reply.status = 'sent';
          entry.reply.sentAt = new Date().toISOString();
          for (const [id, timestamp] of Object.entries(state.sentIds)) {
            if (timestamp < Date.now() - 30 * 24 * 3600 * 1000) delete state.sentIds[id];
          }
          const completed = Object.values(state.messages)
            .filter((message) => message.reply?.status === 'sent')
            .sort((left, right) => left.reply.sentAt.localeCompare(right.reply.sentAt));
          for (const old of completed.slice(0, Math.max(0, completed.length - 1000))) delete state.messages[old.id];
          saveState(dir, state);
        } catch (error) { process.stderr.write(`reply send failed: ${error.message}\n`); break; }
      }
    } finally { draining = false; }
  }

  async function handleControls() {
    if (handlingControls) return;
    handlingControls = true;
    try {
      for (const inbound of Object.values(state.messages)) {
        if (!inbound.control || inbound.reply) continue;
        try {
          const available = await sessions();
          if (inbound.text === '/sessions') {
            const listing = available.map(({ name, harness, status }) => `${name} (${harness}, ${status})`).join(', ') || 'none enabled';
            queueReply(state, inbound.id, `Box sessions: ${listing.slice(0, 3900)}`);
          } else {
            const name = inbound.text.match(/^\/target ([A-Za-z0-9_-]{1,150})$/)?.[1];
            const selected = available.find((item) => item.name === name);
            if (!selected) throw new Error('session not enabled for WhatsApp; send @box /sessions');
            const session = selected.harness === 'claude' ? `${userInfo().username}-${name}` : name;
            setTarget(selected.harness, session, name);
            queueReply(state, inbound.id, `Box target: ${name} (${selected.harness}, ${selected.status}). Messages will wait if it is unavailable.`);
            await dispatch();
          }
        } catch (error) { queueReply(state, inbound.id, `Box: ${error.message}`); }
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
          } else if (value.op === 'reply') {
            const entry = queueReply(state, value.id, value.text);
            saveState(dir, state);
            peer.write(`${JSON.stringify({ ok: true, status: connected ? 'sending' : 'queued until WhatsApp reconnects', id: entry.id })}\n`);
            drainReplies().catch((error) => process.stderr.write(`reply drain failed: ${error.message}\n`));
          } else if (value.op === 'status') {
            peer.write(`${JSON.stringify({ ok: true, connected, target: target(), pending: Object.values(state.messages).filter((entry) => !entry.reply).length })}\n`);
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
    socket.ev.on('messages.upsert', async ({ messages, type }) => {
      if (type !== 'notify') return;
      for (const message of messages) {
        const inbound = parseInbound(message, credentials.creds, state.sentIds);
        if (!inbound) continue;
        try {
          const control = inbound.text === '/sessions' || inbound.text.startsWith('/target');
          if (control) inbound.control = true;
          else inbound.ack = { text: `Box: received ${inbound.id}; waiting for session selection.`, status: 'queued' };
          if (addInbound(state, inbound)) {
            saveState(dir, state);
            if (control) await handleControls();
            else {
              await dispatch();
              const binding = target();
              const destination = binding ? `${binding.harness} session ${binding.session}` : 'session selection';
              const delivery = inbound.deliveredTo ? 'routed to' : 'waiting for';
              inbound.ack = { text: `Box: received ${inbound.id}; ${delivery} ${destination}.`, status: 'queued' };
            }
            saveState(dir, state);
            await drainReplies();
          }
        } catch (error) { process.stderr.write(`inbound failed: ${error.message}\n`); }
      }
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
    if (!selected) throw new Error('session not enabled for WhatsApp');
    ensurePrivateDir(dir);
    setTarget(harness, harness === 'claude' ? `${userInfo().username}-${name}` : name, name);
    process.stdout.write(`Target: ${harness} session ${name}\n`);
    return;
  }
  if (command === 'reply') {
    const id = process.argv[3];
    const text = process.argv.slice(4).join(' ');
    const result = await request({ op: 'reply', id, text });
    process.stdout.write(`${result.status}\n`);
    return;
  }
  if (command === 'status') {
    process.stdout.write(`${JSON.stringify(await request({ op: 'status' }), null, 2)}\n`);
    return;
  }
  throw new Error('usage: bridge.mjs pair|serve|target claude|codex AGENT_BOX_SESSION|register codex|reply ID TEXT|status');
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
