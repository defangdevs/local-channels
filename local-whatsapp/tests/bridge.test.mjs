import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync, unlinkSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';

const source = fileURLToPath(new URL('../bridge.mjs', import.meta.url));
const stateSource = fileURLToPath(new URL('../state.mjs', import.meta.url));
const peerSource = fileURLToPath(new URL('../peer.mjs', import.meta.url));

async function waitUntil(predicate, detail) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out: ${detail}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  const ended = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  await ended;
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'local-whatsapp-bridge-'));
  const state = join(dir, 'state');
  const fakeOut = join(dir, 'out.jsonl');
  const sessionBin = join(dir, 'agent-box-session');
  mkdirSync(state, { mode: 0o700 });
  mkdirSync(join(dir, 'node_modules', '@whiskeysockets', 'baileys'), { recursive: true });
  mkdirSync(join(dir, 'node_modules', 'pino'));
  cpSync(fileURLToPath(new URL('../node_modules/ws', import.meta.url)), join(dir, 'node_modules', 'ws'), { recursive: true });
  copyFileSync(source, join(dir, 'bridge.mjs'));
  copyFileSync(stateSource, join(dir, 'state.mjs'));
  writeFileSync(sessionBin, `#!/bin/sh
case "$2" in
  candidates) printf '%s\\n' '[{"name":"claude","harness":"claude","stopped":false,"selected":true},{"name":"codex","harness":"codex","stopped":true,"selected":false}]' ;;
  select) printf '%s\\n' '{"name":"'"$3"'","harness":"codex","stopped":true}' ;;
  activate) [ -z "$ACTIVATED" ] || printf '%s' "$3" > "$ACTIVATED"; printf '{"name":"%s","harness":"codex","activated":%s}\\n' "$3" "\${ACTIVATION_RESULT:-true}" ;;
  spawn) printf '%s\\n' '{"name":"claude","harness":"claude","stopped":false}' ;;
  clear) printf '%s\\n' '{}' ;;
esac
`);
  chmodSync(sessionBin, 0o700);
  writeFileSync(join(dir, 'node_modules', '@whiskeysockets', 'baileys', 'package.json'), JSON.stringify({ type: 'module', exports: './index.js' }));
  writeFileSync(join(dir, 'node_modules', 'pino', 'package.json'), JSON.stringify({ type: 'module', exports: './index.js' }));
  writeFileSync(join(dir, 'node_modules', 'pino', 'index.js'), 'export default () => ({ level: "silent" });\n');
  writeFileSync(join(dir, 'node_modules', '@whiskeysockets', 'baileys', 'index.js'), `
    import { EventEmitter } from 'node:events';
    import { Readable } from 'node:stream';
    import { userInfo } from 'node:os';
    import { appendFileSync, existsSync } from 'node:fs';
    export const Browsers = { macOS: () => ['Chrome', 'macOS', '1'] };
    export const DisconnectReason = { loggedOut: 401 };
    export async function useMultiFileAuthState() {
      return { state: { creds: { me: process.env.FAKE_PAIR ? null : { id: '14155551234:1@s.whatsapp.net' } } }, saveCreds: async () => {
        if (process.env.FAKE_FAIL_SAVE_CREDS) {
          throw new Error('private credential write failure');
        }
      } };
    }
    export async function downloadMediaMessage() {
      if (process.env.FAKE_DOWNLOAD_ERROR) throw new Error('media expired');
      return Readable.from([Buffer.from('downloaded attachment')]);
    }
    export default function makeWASocket() {
      const ev = new EventEmitter();
      setTimeout(() => {
        if (process.env.FAKE_PAIR) {
          ev.emit('connection.update', { qr: 'QR' });
          if (process.env.FAKE_CREDS_UPDATE) ev.emit('creds.update');
          return;
        }
        ev.emit('connection.update', { connection: 'open' });
        ev.emit('messages.upsert', { type: 'notify', messages: [{
          key: { id: process.env.FAKE_INBOUND_ID || 'IN1', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' },
          message: process.env.FAKE_MEDIA ? { [process.env.FAKE_MEDIA]: { caption: process.env.FAKE_MEDIA_CAPTION ?? ('@' + userInfo().username + ' inspect this'), mimetype: process.env.FAKE_MEDIA === 'videoMessage' ? 'video/mp4' : 'image/png', fileName: '../../unsafe.pdf', fileLength: 21 } } : { conversation: process.env.FAKE_INBOUND_TEXT || ('@' + userInfo().username + ' hello') },
        }] });
      }, Number(process.env.FAKE_INBOUND_DELAY || 100));
      if (process.env.FAKE_FOLLOWUP_TEXT) setTimeout(() => ev.emit('messages.upsert', { type: 'notify', messages: [{ key: { id: 'AFTER-CLEAR', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' }, message: { conversation: process.env.FAKE_FOLLOWUP_TEXT } }] }), 500);
      return { ev, end() { if (process.env.FAKE_PAIR) ev.emit('connection.update', { connection: 'close', lastDisconnect: { error: new Error('closed after pairing') } }); },
        async requestPairingCode() {
          if (process.env.FAKE_PAIR_REQUEST_FAIL) {
            throw Object.assign(
              new Error('private provider response 14155551234 SECRET-CODE'),
              { output: { statusCode: 400 } },
            );
          }
          setTimeout(() => ev.emit('connection.update', { connection: 'open' }), 20);
          return 'TEST1234';
        }, async sendMessage(jid, payload) {
        if (payload.react && process.env.FAKE_HANG_REACTION) return new Promise(() => {});
        if (payload.react && process.env.FAKE_FAIL_REACTION) throw new Error('simulated reaction failure');
        if (payload.image && process.env.FAKE_FAIL_IMAGE) {
          appendFileSync(process.env.FAKE_FAIL_IMAGE, 'attempt\\n');
          throw new Error('simulated media upload failure');
        }
        appendFileSync(process.env.FAKE_OUT, JSON.stringify({ jid, payload }) + '\\n');
        return { key: { id: 'OUT1' } };
      } };
    }
  `);
  return { dir, state, fakeOut, sessionBin };
}

async function runPairFailure(fixture, envOverrides) {
  const pair = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'pair'], {
    env: { ...process.env, ...envOverrides },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = '';
  pair.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  const code = await new Promise((resolve) => pair.once('close', resolve));
  return { code, errors };
}

function pairingFailureDiagnostic(errors) {
  const diagnostic = errors
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line))
    .find((line) => line.event === 'whatsapp_pairing_failed');
  assert.ok(diagnostic, 'pairing failure diagnostic is present');
  return diagnostic;
}

test('pair exits successfully when the newly linked socket closes', async () => {
  const fixture = setup();
  const pair = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'pair'], {
    env: { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, LOCAL_WHATSAPP_PHONE: '14155551234', FAKE_PAIR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  let errors = '';
  pair.stdout.on('data', (chunk) => { output += chunk.toString(); });
  pair.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  try {
    const code = await new Promise((resolve) => pair.once('close', resolve));
    assert.equal(code, 0, errors);
    assert.match(output, /TEST1234/);
    assert.match(output, /device linked/);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

const pairingFailures = [
  {
    name: 'provider refusal omits provider details and phone data',
    env: (fixture) => ({
      LOCAL_WHATSAPP_STATE_DIR: fixture.state,
      LOCAL_WHATSAPP_PHONE: '14155551234',
      FAKE_PAIR: '1',
      FAKE_PAIR_REQUEST_FAIL: '1',
    }),
    phase: 'request_code',
    category: 'pairing_code_rejected',
    statusCode: 400,
    redacted: /14155551234|SECRET-CODE|private provider response/,
  },
  {
    name: 'connection credential-save failure omits the raw error',
    env: (fixture) => ({
      LOCAL_WHATSAPP_STATE_DIR: fixture.state,
      LOCAL_WHATSAPP_PHONE: '14155551234',
      FAKE_PAIR: '1',
      FAKE_FAIL_SAVE_CREDS: '1',
    }),
    phase: 'connection',
    category: 'pairing_setup_failed',
    redacted: /private credential write failure/,
  },
  {
    name: 'creds.update write failure omits the raw error',
    env: (fixture) => ({
      LOCAL_WHATSAPP_STATE_DIR: fixture.state,
      LOCAL_WHATSAPP_PHONE: '14155551234',
      FAKE_PAIR: '1',
      FAKE_CREDS_UPDATE: '1',
      FAKE_FAIL_SAVE_CREDS: '1',
    }),
    phase: 'credentials',
    category: 'pairing_setup_failed',
    redacted: /private credential write failure/,
  },
  {
    name: 'private-directory setup failure omits filesystem details',
    env: (fixture) => {
      const blockedState = join(fixture.dir, 'blocked-state');
      writeFileSync(blockedState, 'not a directory');
      return {
        LOCAL_WHATSAPP_STATE_DIR: blockedState,
        LOCAL_WHATSAPP_PHONE: '14155551234',
      };
    },
    phase: 'setup',
    category: 'pairing_setup_failed',
    redacted: /blocked-state|EEXIST|not a directory/,
  },
];

for (const scenario of pairingFailures) {
  test(`pairing failure logs safe diagnostic: ${scenario.name}`, async () => {
    const fixture = setup();
    try {
      const result = await runPairFailure(fixture, scenario.env(fixture));
      assert.equal(result.code, 1);
      const diagnostic = pairingFailureDiagnostic(result.errors);
      assert.equal(diagnostic.phase, scenario.phase);
      assert.equal(diagnostic.category, scenario.category);
      if (scenario.statusCode) assert.equal(diagnostic.statusCode, scenario.statusCode);
      assert.match(diagnostic.attemptId, /^[0-9a-f-]{36}$/);
      assert.doesNotMatch(result.errors, scenario.redacted);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  });
}

for (const debug of ['', '0', 'true', '1']) {
for (const plain of [false, true]) {
test(`bridge delivers ${plain ? 'plain' : 'prefixed'} text and replies with debug receipts ${JSON.stringify(debug)}`, async () => {
  const fixture = setup();
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'claude', session: 'agent-claude', name: 'claude' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, LOCAL_WHATSAPP_DEBUG: debug,
    ...(plain ? { FAKE_INBOUND_TEXT: 'hello', LOCAL_WHATSAPP_PREFIX: '' } : {}) };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let peer;
  try {
    await waitUntil(() => existsSync(join(fixture.state, 'bridge.sock')), 'daemon socket');
    peer = spawn(process.execPath, [peerSource], { env: { ...env, LOCAL_WHATSAPP_SESSION: 'agent-claude' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const output = [];
    let data = '';
    peer.stdout.on('data', (chunk) => {
      data += chunk.toString();
      while (data.includes('\n')) {
        const index = data.indexOf('\n');
        output.push(JSON.parse(data.slice(0, index)));
        data = data.slice(index + 1);
      }
    });
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })}\n`);
    await waitUntil(() => output.some((item) => item.id === 1), 'initialize');
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    await waitUntil(() => output.some((item) => item.method === 'notifications/claude/channel'), 'channel message');
    const delivery = output.find((item) => item.method === 'notifications/claude/channel');
    const id = delivery.params.meta.messageId;
    assert.match(delivery.params.content, /hello/);
    const beforeAck = existsSync(fixture.fakeOut) ? readFileSync(fixture.fakeOut, 'utf8') : '';
    assert.ok(!beforeAck.includes('\"react\"'));
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'whatsapp_ack', arguments: { id } } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 3), 'ack tool');
    await waitUntil(() => existsSync(fixture.fakeOut) && readFileSync(fixture.fakeOut, 'utf8').includes('\"react\"'), 'reaction');
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'whatsapp_reply', arguments: { id, text: 'answer' } } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 2), 'reply tool');
    await waitUntil(() => existsSync(fixture.fakeOut) && readFileSync(fixture.fakeOut, 'utf8').includes('answer'), 'WhatsApp send');
    const outbound = readFileSync(fixture.fakeOut, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.ok(outbound.every((item) => item.jid === '14155551234@s.whatsapp.net'));
    assert.ok(outbound.some((item) => item.payload.text === 'answer'));
    assert.equal(outbound.some((item) => item.payload.text?.includes('Box: received')), debug === '1');
    await waitUntil(() => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8')).messages[id].reply?.status === 'sent', 'persisted reply');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages[id].reply.status, 'sent');
    assert.equal(saved.messages[id].ack?.status, 'sent');
    assert.deepEqual(outbound.find((item) => item.payload.react)?.payload.react, { text: '\u{1F440}', key: { id: 'IN1', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' } });
  } finally {
    if (peer) await stop(peer);
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

}
}

test('queued messages cannot be acknowledged before delivery', async () => {
  const f = setup();
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, FAKE_OUT: f.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, FAKE_FAIL_REACTION: '1' };
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const saved = () => JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
  try {
    await waitUntil(() => existsSync(join(f.state, 'messages.json')), 'inbound');
    const id = Object.keys(saved().messages)[0];
    assert.equal(saved().messages[id].ack, undefined);
    const early = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'ack', id], { env, encoding: 'utf8' });
    assert.notEqual(early.status, 0);
    assert.equal(saved().messages[id].ack, undefined);
  } finally { await stop(daemon); rmSync(f.dir, { recursive: true, force: true }); }
});

test('a stalled reaction does not block a reply', async () => {
  const f = setup();
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    m: { id: 'm', chat: '14155551234@s.whatsapp.net', text: 'request', deliveredTo: 'codex:thread',
      reactionKey: { id: 'IN1', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' }, reply: null },
  }, sentIds: {} }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, FAKE_OUT: f.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, FAKE_INBOUND_TEXT: 'not addressed', FAKE_HANG_REACTION: '1' };
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(join(f.state, 'bridge.sock')), 'socket');
    assert.equal(spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'ack', 'm'], { env }).status, 0);
    assert.equal(spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'reply', 'm', 'answer'], { env }).status, 0);
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('answer'), 'reply despite stalled reaction');
  } finally { await stop(daemon); rmSync(f.dir, { recursive: true, force: true }); }
});

test('reaction failure leaves a reply sendable and retries after restart', async () => {
  const f = setup();
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    m: { id: 'm', chat: '14155551234@s.whatsapp.net', text: 'request', deliveredTo: 'codex:thread',
      reactionKey: { id: 'IN1', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' }, reply: null },
  }, sentIds: {} }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, FAKE_OUT: f.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, FAKE_INBOUND_TEXT: 'not addressed' };
  let daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...env, FAKE_FAIL_REACTION: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const saved = () => JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8')).messages.m;
  try {
    await waitUntil(() => existsSync(join(f.state, 'bridge.sock')), 'socket');
    assert.equal(spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'ack', 'm'], { env }).status, 0);
    assert.equal(spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'reply', 'm', 'answer'], { env }).status, 0);
    await waitUntil(() => saved().reply?.status === 'sent', 'reply');
    assert.equal(saved().ack.status, 'queued');
    await stop(daemon);
    daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await waitUntil(() => saved().ack.status === 'sent', 'reaction retry');
    const outbound = readFileSync(f.fakeOut, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(outbound.filter((item) => item.payload.text === 'answer').length, 1);
    assert.equal(outbound.filter((item) => item.payload.react).length, 1);
  } finally { await stop(daemon); rmSync(f.dir, { recursive: true, force: true }); }
});

test('default mode suppresses previously queued receipts while preserving replies', async () => {
  const fixture = setup();
  writeFileSync(join(fixture.state, 'messages.json'), JSON.stringify({ messages: {
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'old request',
      receivedAt: new Date().toISOString(), deliveredTo: null,
      ack: { text: 'Box: received old', status: 'queued' },
      reply: { text: 'old answer', status: 'queued' } },
  }, sentIds: {} }));
  const env = { ...process.env, LOCAL_WHATSAPP_DEBUG: '',
    LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(fixture.fakeOut), 'queued reply');
    const outbound = readFileSync(fixture.fakeOut, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(outbound.filter((item) => item.payload.text).map((item) => item.payload.text), ['old answer']);
    await waitUntil(() => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8')).messages.old.reply?.status === 'sent', 'persisted queued reply');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages.old.ack.status, 'suppressed');
    assert.equal(saved.messages.old.reply.status, 'sent');
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

for (const activationResult of ['true', 'false']) {
test(`bridge routes to Codex after activation returns ${activationResult}`, async () => {
  const fixture = setup();
  const bin = join(fixture.dir, 'bin');
  const argsFile = join(fixture.dir, 'codex-args.txt');
  const activated = join(fixture.dir, 'activated.txt');
  mkdirSync(bin);
  writeFileSync(join(bin, 'codex'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$CODEX_ARGS_FILE"\n');
  chmodSync(join(bin, 'codex'), 0o700);
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    CODEX_ARGS_FILE: argsFile, LOCAL_WHATSAPP_CODEX_BIN: join(bin, 'codex'),
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, ACTIVATED: activated,
    ACTIVATION_RESULT: activationResult };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(argsFile), 'Codex queue');
    assert.equal(readFileSync(activated, 'utf8'), 'codex');
    const args = readFileSync(argsFile, 'utf8');
    assert.match(args, /queue\n--thread\ncodex\n--message\n/);
    assert.match(args, /WhatsApp Message Yourself/);
    assert.match(args, /send a short progress update/);
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});
}

test('failed cold activation keeps the inbound message pending', async () => {
  const fixture = setup();
  writeFileSync(fixture.sessionBin, `#!/bin/sh
case "$2" in
  candidates) printf '%s\\n' '[{"name":"codex","harness":"codex","stopped":true,"selected":true}]' ;;
  activate) echo 'Session limit reached' >&2; exit 75 ;;
esac
`);
  chmodSync(fixture.sessionBin, 0o700);
  writeFileSync(join(fixture.state, 'target.json'),
    JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, FAKE_OUT: fixture.fakeOut };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], {
    env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = '';
  daemon.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  try {
    await waitUntil(() => existsSync(join(fixture.state, 'messages.json')), 'saved message');
    await waitUntil(() => errors.includes('Session limit reached'), 'activation refusal');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(Object.values(saved.messages)[0].deliveredTo, null);
    assert.deepEqual(JSON.parse(readFileSync(join(fixture.state, 'target.json'), 'utf8')),
      { harness: 'codex', session: 'codex', name: 'codex' });
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('a missing selected session stays bound and receives no messages', async () => {
  const fixture = setup();
  const spawned = join(fixture.dir, 'spawned.txt');
  writeFileSync(fixture.sessionBin, "#!/bin/sh\ncase \"$2\" in candidates) printf '%s\\n' '[]' ;; spawn) touch \"$SPAWNED\"; exit 1 ;; esac\n");
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, FAKE_OUT: fixture.fakeOut,
    SPAWNED: spawned };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], {
    env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = '';
  daemon.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  try {
    await waitUntil(() => existsSync(join(fixture.state, 'messages.json')), 'saved message');
    await waitUntil(() => errors.includes('selected session codex is unavailable'),
      'missing target refusal');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(Object.values(saved.messages)[0].deliveredTo, null);
    assert.equal(existsSync(spawned), false);
    assert.deepEqual(JSON.parse(readFileSync(join(fixture.state, 'target.json'), 'utf8')),
      { harness: 'codex', session: 'codex', name: 'codex' });
    const selected = spawnSync(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'target', 'codex', 'codex'], {
      env, encoding: 'utf8',
    });
    assert.equal(selected.status, 1);
    assert.match(selected.stderr, /unknown agent-box session/);
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('an unselected bridge target starts one session using the configured profile', async () => {
  const fixture = setup();
  const spawned = join(fixture.dir, 'spawned.txt');
  writeFileSync(fixture.sessionBin, `#!/bin/sh
case "$2" in
  candidates) printf '%s\\n' '[]' ;;
  spawn) printf '%s' "$3" > "$SPAWNED"; printf '%s\\n' '{"name":"from-profile","harness":"claude","stopped":false}' ;;
  clear) printf '%s\\n' '{}' ;;
esac
`);
  chmodSync(fixture.sessionBin, 0o700);
  writeFileSync(join(fixture.state, 'config.json'), JSON.stringify({ profile: 'phone-agent' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, SPAWNED: spawned };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(spawned), 'profile session spawn');
    assert.equal(readFileSync(spawned, 'utf8'), 'phone-agent');
    await waitUntil(() => existsSync(join(fixture.state, 'target.json')), 'spawned target');
    assert.deepEqual(JSON.parse(readFileSync(join(fixture.state, 'target.json'), 'utf8')),
      { harness: 'claude', session: `${userInfo().username}-from-profile`, name: 'from-profile' });
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('plain self-chat control selects a registered agent-box session without re-pairing', async () => {
  const fixture = setup();
  const bin = join(fixture.dir, 'bin');
  mkdirSync(bin);
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    FAKE_INBOUND_TEXT: '/target codex', LOCAL_WHATSAPP_PREFIX: '', LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin };
  const registration = spawnSync(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'register', 'codex'], {
    env: { ...env, LOCAL_WEBHOOK_SESSION: `${userInfo().username}-codex`, CODEX_THREAD_ID: 'thread-1234' }, encoding: 'utf8',
  });
  assert.equal(registration.status, 0, registration.stderr);
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(fixture.fakeOut), 'target reply');
    assert.deepEqual(JSON.parse(readFileSync(join(fixture.state, 'target.json'), 'utf8')),
      { harness: 'codex', session: 'codex', name: 'codex' });
    const status = spawnSync(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'status'], { env, encoding: 'utf8' });
    assert.equal(status.status, 0, status.stderr);
    assert.equal(JSON.parse(status.stdout).target.session, 'thread-1234');
    const outbound = JSON.parse(readFileSync(fixture.fakeOut, 'utf8').trim());
    assert.match(outbound.payload.text, /Box target: codex \(codex, stopped\)/);
    assert.match(outbound.payload.text, /wait if it is unavailable/);
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('reply-image CLI queues a durable image, retries after restart, and cleans up after native send', async () => {
  const fixture = setup();
  const sourceImage = join(fixture.state, 'picture.png');
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aK6sAAAAASUVORK5CYII=', 'base64');
  writeFileSync(sourceImage, png);
  const attempts = join(fixture.dir, 'attempts');
  const env = { ...process.env, LOCAL_WHATSAPP_DEBUG: '', LOCAL_WHATSAPP_STATE_DIR: fixture.state,
    FAKE_OUT: fixture.fakeOut, LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin };
  let daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], {
    env: { ...env, FAKE_FAIL_IMAGE: attempts }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const saved = () => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
  try {
    await waitUntil(() => existsSync(join(fixture.state, 'messages.json')), 'inbound request');
    const id = Object.keys(saved().messages)[0];
    const result = spawnSync(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'reply-image', id, sourceImage, 'my picture'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    await waitUntil(() => existsSync(attempts), 'failed upload');
    const image = saved().messages[id].reply.image;
    assert.equal(saved().messages[id].reply.status, 'queued');
    await stop(daemon);
    rmSync(sourceImage);
    daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await waitUntil(() => saved().messages[id].reply.status === 'sent', 'native image sent');
    const outbound = readFileSync(fixture.fakeOut, 'utf8').trim().split('\n').map(JSON.parse);
    const images = outbound.filter((item) => item.payload.image);
    assert.equal(images.length, 1);
    assert.equal(images[0].jid, '14155551234@s.whatsapp.net');
    assert.equal(images[0].payload.caption, 'my picture');
    assert.equal(images[0].payload.mimetype, 'image/png');
    assert.deepEqual(Buffer.from(images[0].payload.image.data), png);
    await waitUntil(() => !existsSync(join(fixture.state, 'media-outbox', image)), 'media cleanup');
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

for (const kind of ['imageMessage', 'documentMessage', 'videoMessage']) {
for (const harness of ['codex', 'claude']) {
test(`incoming ${kind} downloads and reaches ${harness} with a private local path`, async () => {
  const f = setup();
  const argsFile = join(f.dir, 'args');
  const codexBin = join(f.dir, 'codex');
  writeFileSync(codexBin, '#!/bin/sh\nprintf "%s\\n" "$@" > "$CODEX_ARGS_FILE"\n');
  chmodSync(codexBin, 0o700);
  writeFileSync(join(f.state, 'target.json'), JSON.stringify({ harness, session: harness, name: harness }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, FAKE_OUT: f.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, LOCAL_WHATSAPP_CODEX_BIN: codexBin,
    CODEX_ARGS_FILE: argsFile, FAKE_MEDIA: kind, LOCAL_WHATSAPP_SESSION: harness };
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env });
  daemon.stderr.on('data', (chunk) => process.stderr.write(chunk));
  let peer;
  let content = '';
  try {
    if (harness === 'claude') {
      peer = spawn(process.execPath, [peerSource], { env });
      peer.stdout.on('data', (chunk) => { content += chunk; });
      peer.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
      await waitUntil(() => content.includes('Attachment'), 'Claude attachment notice');
    } else {
      await waitUntil(() => existsSync(argsFile), 'Codex attachment notice');
      content = readFileSync(argsFile, 'utf8');
    }
    assert.match(content, /Attachment/);
    assert.match(content, /untrusted/);
    const saved = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    const [entry] = Object.values(saved.messages);
    assert.equal(entry.attachment.size, 21);
    assert.ok(entry.attachment.path.startsWith(join(f.state, 'media-inbox') + '/'));
    assert.equal(readFileSync(entry.attachment.path, 'utf8'), 'downloaded attachment');
    assert.ok(content.includes('media-inbox'));
    // Acknowledgement and final answer must both reach WhatsApp.
    for (const text of ['Working on it', 'Finished']) {
      const reply = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'reply', entry.id, text], { env, encoding: 'utf8' });
      assert.equal(reply.status, 0, reply.stderr);
      await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes(text), 'sequential reply');
    }
  } finally {
    if (peer) await stop(peer);
    await stop(daemon);
    rmSync(f.dir, { recursive: true, force: true });
  }
});
}
}

for (const kind of ['videoMessage', 'documentMessage']) {
test(`receive-files CLI enables captionless ${kind} and persists its expiry`, async () => {
  const f = setup();
  const argsFile = join(f.dir, 'args');
  const codexBin = join(f.dir, 'codex');
  writeFileSync(codexBin, '#!/bin/sh\nprintf "%s\\n" "$@" > "$CODEX_ARGS_FILE"\n');
  chmodSync(codexBin, 0o700);
  writeFileSync(join(f.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, FAKE_OUT: f.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, LOCAL_WHATSAPP_CODEX_BIN: codexBin,
    CODEX_ARGS_FILE: argsFile, FAKE_MEDIA: kind, FAKE_MEDIA_CAPTION: '', FAKE_INBOUND_DELAY: '700' };
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env });
  try {
    await waitUntil(() => existsSync(join(f.state, 'bridge.sock')), 'bridge socket');
    const result = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'receive-files'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /enabled until/);
    await waitUntil(() => existsSync(argsFile), 'captionless upload queued');
    const state = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    assert.ok(state.acceptMediaUntil > Date.now());
    assert.ok(state.acceptMediaUntil <= Date.now() + 600000);
    const [entry] = Object.values(state.messages);
    assert.equal(entry.text, '');
    assert.equal(readFileSync(entry.attachment.path, 'utf8'), 'downloaded attachment');
    if (kind === 'videoMessage') assert.ok(entry.attachment.path.endsWith('.mp4'));
  } finally {
    await stop(daemon);
    rmSync(f.dir, { recursive: true, force: true });
  }
});
}


async function resetFixture(harness = 'codex') {
  const f = setup();
  const calls = [];
  const http = createServer();
  const wsServer = new WebSocketServer({ server: http });
  const socket = join(f.dir, 'codex.sock');
  const lifecycle = join(f.dir, 'lifecycle');
  const argsFile = join(f.dir, 'args');
  const codexBin = join(f.dir, 'codex');
  const rollout = join(f.dir, 'old.jsonl');
  writeFileSync(rollout, JSON.stringify({ type: 'session_meta', payload: { base_instructions: { text: 'BASE_SYSTEM_INSTRUCTIONS' } } }) + '\n' + JSON.stringify({ type: 'user', text: 'SECRET_OLD_CONTEXT' }) + '\n');
  writeFileSync(codexBin, '#!/bin/sh\nprintf "%s\\n" "$@" >> "$CODEX_ARGS_FILE"\n');
  chmodSync(codexBin, 0o700);
  writeFileSync(f.sessionBin, `#!/bin/sh
case "$2" in
  candidates) printf '%s\\n' '[{"name":"existing","harness":"${harness}","stopped":false,"selected":true}]' ;;
  spawn|activate|clear) printf '%s\\n' "$2" >> "$LIFECYCLE_FILE"; exit 1 ;;
esac
`);
  writeFileSync(join(f.state, 'target.json'), JSON.stringify({ harness, session: 'old-thread', name: 'existing' }));
  writeFileSync(join(f.state, 'codex-threads.json'), JSON.stringify({ existing: { thread: 'old-thread' } }));
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'SECRET_OLD_CONTEXT', reply: null, deliveredTo: 'codex:old-thread' },
  }, sentIds: {}, acceptMediaUntil: Date.now() + 600000 }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, LOCAL_WHATSAPP_DEBUG: '',
    LOCAL_WHATSAPP_PREFIX: '', LOCAL_WHATSAPP_CODEX_SOCKET: socket,
    FAKE_OUT: f.fakeOut, LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin,
    LOCAL_WHATSAPP_CODEX_BIN: codexBin, CODEX_ARGS_FILE: argsFile, LIFECYCLE_FILE: lifecycle,
    FAKE_INBOUND_TEXT: '/clear', FAKE_FOLLOWUP_TEXT: 'fresh question' };
  let rejectStart = false;
  let historyEmpty = false;
  wsServer.on('connection', (ws) => ws.on('message', (raw) => {
    const m = JSON.parse(raw.toString()); calls.push(m);
    if (m.id === undefined) return;
    let result;
    if (m.method === 'initialize') result = {};
    else if (m.method === 'thread/read') result = { thread: { id: m.params.threadId, model: 'keep-model', modelProvider: 'openai', historyMode: 'paginated' } };
    else if (m.method === 'thread/resume') result = {
      model: 'keep-model', modelProvider: 'openai', cwd: f.dir, approvalPolicy: 'never',
      reasoningEffort: 'high', runtimeWorkspaceRoots: [f.dir],
      sandbox: { type: 'workspaceWrite', writableRoots: [f.dir], networkAccess: false, excludeTmpdirEnvVar: true, excludeSlashTmp: true },
    };
    else if (m.method === 'thread/turns/list') {
      // A server request that reuses the pending response id must not be mistaken for the response.
      ws.send(JSON.stringify({ id: m.id, method: 'item/commandExecution/requestApproval', params: {} }));
      result = { data: historyEmpty ? [] : [{ id: 'first-turn' }], nextCursor: null };
    }
    else if (m.method === 'thread/revert') {
      if (rejectStart) { ws.send(JSON.stringify({ id: m.id, error: { code: -1, message: 'reset rejected' } })); return; }
      historyEmpty = true;
      result = { thread: { id: 'old-thread', turns: [] } };
    } else throw new Error('Unexpected method ' + m.method);
    ws.send(JSON.stringify({ id: m.id, result }));
  }));
  await new Promise((resolve) => http.listen(socket, resolve));
  return { ...f, calls, env, lifecycle, argsFile, rejectStart(value) { rejectStart = value; }, emptyHistory() { historyEmpty = true; }, async cleanup() {
    for (const client of wsServer.clients) client.terminate();
    await new Promise((resolve) => wsServer.close(resolve));
    await new Promise((resolve) => http.close(resolve));
    rmSync(f.dir, { recursive: true, force: true });
  } };
}

for (const plain of [false, true]) {
test(`/clear reuses the existing Codex process (${plain ? 'plain' : 'prefixed'}) without session lifecycle calls`, async () => {
  const f = await resetFixture();
  const head = plain ? '' : '@' + userInfo().username + ' ';
  const env = { ...f.env, LOCAL_WHATSAPP_PREFIX: plain ? '' : userInfo().username,
    FAKE_INBOUND_TEXT: head + '/clear', FAKE_FOLLOWUP_TEXT: head + 'fresh question' };
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('Context cleared'), 'reset confirmation');
    await waitUntil(() => existsSync(f.argsFile), 'fresh Codex queue');
    const output = readFileSync(f.argsFile, 'utf8');
    assert.match(output, /old-thread/); assert.match(output, /fresh question/);
    assert.doesNotMatch(output, /SECRET_OLD_CONTEXT|\/clear/);
    assert.equal(existsSync(f.lifecycle), false, 'must never spawn, activate, or detach an Agentbox session');
    assert.equal(f.calls.some((m) => m.method === 'thread/start'), false);
    const revert = f.calls.find((m) => m.method === 'thread/revert').params;
    assert.deepEqual(revert, { threadId: 'old-thread', beforeTurnId: 'first-turn' });
    const resumed = f.calls.find((m) => m.method === 'thread/resume').params;
    assert.equal(resumed.model, 'keep-model');
    assert.doesNotMatch(JSON.stringify(f.calls), /SECRET_OLD_CONTEXT/);
    const selected = JSON.parse(readFileSync(join(f.state, 'target.json'), 'utf8'));
    assert.deepEqual(selected, { harness: 'codex', name: 'existing', session: 'old-thread' });
    const status = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'status'], { env, encoding: 'utf8' });
    assert.equal(JSON.parse(status.stdout).target.session, 'old-thread', 'thread identity stays unchanged');
    const saved = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    assert.ok(saved.messages.old.clearedAt); assert.equal(saved.resetPending, null); assert.equal(saved.acceptMediaUntil, 0);
    const late = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'reply', 'old', 'late'], { env, encoding: 'utf8' });
    assert.equal(late.status, 1); assert.match(late.stderr, /cleared conversation/);
  } finally { await stop(daemon); await f.cleanup(); }
});
}

test('/clear failure remains blocked across restart and never starts a replacement harness', async () => {
  const f = await resetFixture(); f.rejectStart(true);
  let daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: f.env });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('reset rejected'), 'failed reset');
    await new Promise((resolve) => setTimeout(resolve, 600));
    assert.equal(existsSync(f.argsFile), false); assert.equal(existsSync(f.lifecycle), false);
    await stop(daemon);
    daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: f.env });
    await new Promise((resolve) => setTimeout(resolve, 700));
    assert.equal(existsSync(f.argsFile), false); assert.equal(existsSync(f.lifecycle), false);
    assert.ok(JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8')).resetPending);
  } finally { await stop(daemon); await f.cleanup(); }
});

test('control replies are delivered while a failed /clear keeps the barrier pending', async () => {
  const f = await resetFixture(); f.rejectStart(true);
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...f.env, FAKE_FOLLOWUP_TEXT: '/sessions' } });
  const lines = () => (existsSync(f.fakeOut) ? readFileSync(f.fakeOut, 'utf8').trim().split('\n').filter(Boolean) : []);
  try {
    await waitUntil(() => lines().some((line) => line.includes('reset rejected')), 'failed reset');
    await waitUntil(() => lines().some((line) => !line.includes('reset rejected')), 'control reply past the barrier');
    assert.ok(JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8')).resetPending);
  } finally { await stop(daemon); await f.cleanup(); }
});

test('/clear reports unsupported Claude reset instead of spawning another harness', async () => {
  const f = await resetFixture('claude');
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: f.env });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('In-process clear is not supported'), 'capability error');
    assert.equal(f.calls.length, 0);
    assert.equal(existsSync(f.lifecycle), false);
    const selected = JSON.parse(readFileSync(join(f.state, 'target.json'), 'utf8'));
    assert.equal(selected.session, 'old-thread');
    const saved = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages.old.clearedAt, undefined);
    assert.equal(saved.resetPending, null);
  } finally { await stop(daemon); await f.cleanup(); }
});

test('an interrupted in-place reset safely retries an already empty thread after restart', async () => {
  const f = await resetFixture();
  const statePath = join(f.state, 'messages.json');
  const saved = JSON.parse(readFileSync(statePath, 'utf8'));
  saved.messages.clear = { id: 'clear', chat: '14155551234@s.whatsapp.net', text: '/clear', control: true, reply: null };
  saved.resetPending = 'clear';
  f.emptyHistory();
  writeFileSync(statePath, JSON.stringify(saved));
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...f.env, FAKE_INBOUND_TEXT: 'fresh question', FAKE_FOLLOWUP_TEXT: '' } });
  try {
    await waitUntil(() => existsSync(f.argsFile), 'recovered queue');
    assert.match(readFileSync(f.argsFile, 'utf8'), /old-thread/);
    assert.equal(f.calls.some((m) => m.method === 'thread/revert' || m.method === 'thread/start'), false);
    assert.equal(existsSync(f.lifecycle), false);
  } finally { await stop(daemon); await f.cleanup(); }
});

function routeFixture(script) {
  const fixture = setup();
  const route = join(fixture.dir, 'route');
  const requests = join(fixture.dir, 'requests.jsonl');
  const lifecycle = join(fixture.dir, 'lifecycle.txt');
  writeFileSync(route, `#!/bin/sh\nbody=$(cat)\nprintf '%s\\n' "$body" >> "$REQUESTS"\n${script}\n`);
  chmodSync(route, 0o700);
  // Any session-manager call other than listing would mean the bridge chose a
  // session itself instead of leaving it to the route command.
  writeFileSync(fixture.sessionBin, `#!/bin/sh\nprintf '%s\\n' "$2" >> "$LIFECYCLE"\ncase "$2" in candidates) printf '%s\\n' '[]' ;; *) printf '%s\\n' '{}' ;; esac\n`);
  chmodSync(fixture.sessionBin, 0o700);
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, LOCAL_WHATSAPP_ROUTE_CMD: route, REQUESTS: requests, LIFECYCLE: lifecycle };
  const read = (path) => existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean) : [];
  const saved = () => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
  return { fixture, env, requests: () => read(requests).map((line) => JSON.parse(line)), lifecycle: () => read(lifecycle), saved };
}

for (const debug of ['', '1']) {
test(`route command decides the session for each message (debug ${JSON.stringify(debug)})`, async () => {
  const r = routeFixture(`printf '%s\\n' '{"session":"wa-greece","action":"NEW"}'`);
  const env = { ...r.env, LOCAL_WHATSAPP_DEBUG: debug, FAKE_INBOUND_TEXT: `@${userInfo().username} what is the VAT rate in Greece` };
  const daemon = spawn(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const only = () => Object.values(r.saved().messages)[0];
  try {
    await waitUntil(() => existsSync(join(r.fixture.state, 'messages.json')) && only()?.deliveredTo, 'routed');
    const id = only().id;
    const [request] = r.requests();
    assert.equal(request.channel, 'whatsapp');
    assert.equal(request.message.id, id);
    assert.equal(request.message.text, 'what is the VAT rate in Greece');
    assert.ok(Number.isInteger(request.message.ts));
    assert.ok(request.reply.endsWith(`bridge.mjs reply ${id} <reply text>`));
    assert.ok(request.ack.endsWith(`bridge.mjs ack ${id}`));
    assert.deepEqual(request.recent, []);
    assert.equal(only().deliveredTo, 'route:wa-greece');
    assert.equal(only().routedTo, 'wa-greece');
    assert.ok(!existsSync(join(r.fixture.state, 'target.json')), 'routing never pins a target');
    assert.deepEqual(r.lifecycle().filter((call) => call !== 'candidates'), []);
    // The routed session answers through the same CLI as any session.
    assert.equal(spawnSync(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'ack', id], { env, encoding: 'utf8' }).status, 0);
    assert.equal(spawnSync(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'reply', id, '24%'], { env, encoding: 'utf8' }).status, 0);
    await waitUntil(() => existsSync(r.fixture.fakeOut) && readFileSync(r.fixture.fakeOut, 'utf8').includes('24%'), 'reply sent');
    const outbound = readFileSync(r.fixture.fakeOut, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(outbound.some((item) => item.payload.text === `Box: ${id} -> wa-greece (NEW)`), debug === '1');
    const status = JSON.parse(spawnSync(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'status'], { env, encoding: 'utf8' }).stdout);
    assert.equal(status.routing, true);
  } finally { await stop(daemon); rmSync(r.fixture.dir, { recursive: true, force: true }); }
});
}

test('a failed route keeps the message pending, keeps order, and never falls back to spawning', async () => {
  const r = routeFixture(`case "$body" in *'"id":"a"'*) echo 'router down' >&2; exit 3 ;; esac\nprintf '%s\\n' '{"session":"wa-x","action":"CONTINUE"}'`);
  writeFileSync(join(r.fixture.state, 'messages.json'), JSON.stringify({ messages: {
    a: { id: 'a', chat: '14155551234@s.whatsapp.net', text: 'first', receivedAt: '2026-11-15T10:00:00.000Z', deliveredTo: null, reply: null },
    b: { id: 'b', chat: '14155551234@s.whatsapp.net', text: 'second', receivedAt: '2026-11-15T10:00:05.000Z', deliveredTo: null, reply: null },
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'earlier', deliveredTo: 'route:wa-x', routedTo: 'wa-x',
      reply: { text: 'earlier answer', status: 'sent', sentAt: '2026-11-15T09:00:00.000Z' } },
  }, sentIds: {} }));
  const env = r.env;
  const daemon = spawn(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = '';
  daemon.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  try {
    await waitUntil(() => errors.includes('route failed for a: router down'), 'route failure logged');
    const requests = r.requests();
    assert.equal(requests.length, 1, 'b must not overtake a');
    assert.equal(requests[0].message.id, 'a');
    assert.equal(requests[0].message.ts, Date.parse('2026-11-15T10:00:00.000Z') / 1000);
    assert.deepEqual(requests[0].recent, [{ id: 'old', session: 'wa-x', reply: 'earlier answer' }]);
    assert.equal(r.saved().messages.a.deliveredTo, null);
    assert.equal(r.saved().messages.b.deliveredTo, null);
    assert.ok(!existsSync(join(r.fixture.state, 'target.json')));
    assert.deepEqual(r.lifecycle().filter((call) => call !== 'candidates'), []);
  } finally { await stop(daemon); rmSync(r.fixture.dir, { recursive: true, force: true }); }
});

test('an explicit /target pin wins over the route command', async () => {
  const r = routeFixture(`printf '%s\\n' '{"session":"wa-x"}'`);
  writeFileSync(join(r.fixture.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'thread-1', name: 'pinned' }));
  writeFileSync(r.fixture.sessionBin, `#!/bin/sh\ncase "$2" in candidates) printf '%s\\n' '[{"name":"pinned","harness":"codex","stopped":false,"selected":true}]' ;; *) printf '%s\\n' '{}' ;; esac\n`);
  const codex = join(r.fixture.dir, 'codex');
  const queued = join(r.fixture.dir, 'queued.txt');
  writeFileSync(codex, `#!/bin/sh\nprintf '%s ' "$@" >> "${queued}"\n`);
  chmodSync(codex, 0o700);
  const daemon = spawn(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'serve'], { env: { ...r.env, LOCAL_WHATSAPP_CODEX_BIN: codex }, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(queued), 'pinned delivery');
    assert.match(readFileSync(queued, 'utf8'), /--thread thread-1/);
    assert.deepEqual(r.requests(), []);
  } finally { await stop(daemon); rmSync(r.fixture.dir, { recursive: true, force: true }); }
});

test('a relative route command is refused', () => {
  const f = setup();
  const result = spawnSync(process.execPath, [join(f.dir, 'bridge.mjs'), 'status'], {
    env: { ...process.env, LOCAL_WHATSAPP_STATE_DIR: f.state, LOCAL_WHATSAPP_SESSION_BIN: f.sessionBin, LOCAL_WHATSAPP_ROUTE_CMD: 'route' }, encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must be an absolute path/);
  rmSync(f.dir, { recursive: true, force: true });
});

test('the chosen session can acknowledge before the route command returns', async () => {
  // The router delivers first and answers last: run the ack it was handed
  // while still running, the way a fast session would.
  const r = routeFixture(`ack=$(printf '%s' "$body" | sed -n 's/.*"ack":"\\([^"]*\\)".*/\\1/p')\n$ack > "$ACKED" 2>&1 || echo FAILED >> "$ACKED"\nprintf '%s\\n' '{"session":"wa-x","action":"NEW"}'`);
  const acked = join(r.fixture.dir, 'acked.txt');
  const env = { ...r.env, ACKED: acked };
  const daemon = spawn(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(join(r.fixture.state, 'messages.json')) && Object.values(r.saved().messages)[0]?.deliveredTo, 'routed');
    assert.match(readFileSync(acked, 'utf8'), /acknowledgment queued/);
    assert.doesNotMatch(readFileSync(acked, 'utf8'), /FAILED/);
    const entry = Object.values(r.saved().messages)[0];
    assert.equal(entry.routeInFlight, undefined);
    await waitUntil(() => existsSync(r.fixture.fakeOut) && readFileSync(r.fixture.fakeOut, 'utf8').includes('"react"'), 'reaction');
  } finally { await stop(daemon); rmSync(r.fixture.dir, { recursive: true, force: true }); }
});

test('a hung route command is stopped at the deadline and retried later', async () => {
  // Ignores SIGTERM and leaves a grandchild holding the pipes.
  const r = routeFixture(`trap '' TERM\n(sleep 60) &\nsleep 60`);
  const env = { ...r.env, LOCAL_WHATSAPP_ROUTE_TIMEOUT_MS: '400' };
  const daemon = spawn(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = '';
  daemon.stderr.on('data', (chunk) => { errors += chunk.toString(); });
  try {
    await waitUntil(() => errors.includes('route command timed out after 0.4s'), 'deadline');
    await waitUntil(() => Object.values(r.saved().messages)[0]?.routeRetryAt, 'retry time');
    const entry = Object.values(r.saved().messages)[0];
    assert.equal(entry.deliveredTo, null);
    assert.equal(entry.routeInFlight, undefined);
    assert.ok(entry.routeRetryAt >= Date.now() + 25000, 'retry waits 30 s after the failure');
    // The bridge still answers its control socket: nothing is wedged.
    const status = spawnSync(process.execPath, [join(r.fixture.dir, 'bridge.mjs'), 'status'], { env, encoding: 'utf8' });
    assert.equal(status.status, 0, status.stderr);
  } finally { await stop(daemon); rmSync(r.fixture.dir, { recursive: true, force: true }); }
});

test('/clear with automatic routing resets only the last routed Codex conversation', async () => {
  const f = await resetFixture();
  unlinkSync(join(f.state, 'target.json'));
  const route = join(f.dir, 'route.sh');
  writeFileSync(route, '#!/bin/sh\nexit 1\n'); chmodSync(route, 0o700);
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    other: { id: 'other', chat: '14155551234@s.whatsapp.net', text: 'other topic', reply: null, deliveredTo: 'route:elsewhere', routedTo: 'elsewhere' },
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'SECRET_OLD_CONTEXT', reply: null, deliveredTo: 'route:existing', routedTo: 'existing' },
  }, sentIds: {}, acceptMediaUntil: Date.now() + 600000 }));
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...f.env, LOCAL_WHATSAPP_ROUTE_CMD: route } });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('Context cleared'), 'reset confirmation');
    assert.deepEqual(f.calls.find((m) => m.method === 'thread/revert').params, { threadId: 'old-thread', beforeTurnId: 'first-turn' });
    assert.equal(existsSync(f.lifecycle), false);
    assert.equal(existsSync(join(f.state, 'target.json')), false, 'no explicit pin is created');
    const saved = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    assert.ok(saved.messages.old.clearedAt);
    assert.equal(saved.messages.other.clearedAt, undefined);
    assert.ok(saved.acceptMediaUntil > 0);
  } finally { await stop(daemon); await f.cleanup(); }
});

test('/clear under routing refuses a session whose Codex thread was replaced since routing', async () => {
  const f = await resetFixture();
  unlinkSync(join(f.state, 'target.json'));
  const route = join(f.dir, 'route.sh');
  writeFileSync(route, '#!/bin/sh\nexit 1\n'); chmodSync(route, 0o700);
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'SECRET_OLD_CONTEXT', reply: null, deliveredTo: 'route:existing', routedTo: 'existing', routedThread: 'earlier-thread' },
  }, sentIds: {}, acceptMediaUntil: Date.now() + 600000 }));
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...f.env, LOCAL_WHATSAPP_ROUTE_CMD: route } });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('was replaced'), 'replaced-thread refusal');
    assert.equal(f.calls.some((m) => m.method === 'thread/revert'), false);
    const saved = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages.old.clearedAt, undefined);
    assert.equal(saved.resetPending, null);
  } finally { await stop(daemon); await f.cleanup(); }
});

test('/clear under routing releases the barrier when the session listing fails before any reset', async () => {
  const f = await resetFixture();
  unlinkSync(join(f.state, 'target.json'));
  writeFileSync(f.sessionBin, '#!/bin/sh\nexit 1\n');
  const route = join(f.dir, 'route.sh');
  writeFileSync(route, '#!/bin/sh\nexit 1\n'); chmodSync(route, 0o700);
  writeFileSync(join(f.state, 'messages.json'), JSON.stringify({ messages: {
    old: { id: 'old', chat: '14155551234@s.whatsapp.net', text: 'x', reply: null, deliveredTo: 'route:existing', routedTo: 'existing' },
  }, sentIds: {} }));
  const daemon = spawn(process.execPath, [join(f.dir, 'bridge.mjs'), 'serve'], { env: { ...f.env, LOCAL_WHATSAPP_ROUTE_CMD: route } });
  try {
    await waitUntil(() => existsSync(f.fakeOut) && readFileSync(f.fakeOut, 'utf8').includes('Box:'), 'failure reply');
    await waitUntil(() => { const s = JSON.parse(readFileSync(join(f.state, 'messages.json'), 'utf8')); return s.resetPending === null; }, 'barrier released');
    assert.equal(f.calls.length, 0);
  } finally { await stop(daemon); await f.cleanup(); }
});
