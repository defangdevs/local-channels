import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

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
  copyFileSync(source, join(dir, 'bridge.mjs'));
  copyFileSync(stateSource, join(dir, 'state.mjs'));
  writeFileSync(sessionBin, `#!/bin/sh
case "$2" in
  candidates) printf '%s\\n' '[{"name":"claude","harness":"claude","stopped":false,"selected":true},{"name":"codex","harness":"codex","stopped":true,"selected":false}]' ;;
  select) printf '%s\\n' '{"name":"'"$3"'","harness":"codex","stopped":true}' ;;
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
    import { userInfo } from 'node:os';
    import { appendFileSync, existsSync } from 'node:fs';
    export const Browsers = { macOS: () => ['Chrome', 'macOS', '1'] };
    export const DisconnectReason = { loggedOut: 401 };
    export async function useMultiFileAuthState() {
      return { state: { creds: { me: process.env.FAKE_PAIR ? null : { id: '14155551234:1@s.whatsapp.net' } } }, saveCreds: async () => {} };
    }
    export default function makeWASocket() {
      const ev = new EventEmitter();
      setTimeout(() => {
        if (process.env.FAKE_PAIR) { ev.emit('connection.update', { qr: 'QR' }); return; }
        ev.emit('connection.update', { connection: 'open' });
        ev.emit('messages.upsert', { type: 'notify', messages: [{
          key: { id: process.env.FAKE_INBOUND_ID || 'IN1', fromMe: true, remoteJid: '14155551234@s.whatsapp.net' },
          message: { conversation: process.env.FAKE_INBOUND_TEXT || ('@' + userInfo().username + ' hello') },
        }] });
      }, 100);
      return { ev, end() { if (process.env.FAKE_PAIR) ev.emit('connection.update', { connection: 'close', lastDisconnect: { error: new Error('closed after pairing') } }); },
        async requestPairingCode() {
          setTimeout(() => ev.emit('connection.update', { connection: 'open' }), 20);
          return 'TEST1234';
        }, async sendMessage(jid, payload) {
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
    const code = await new Promise((resolve) => pair.once('exit', resolve));
    assert.equal(code, 0, errors);
    assert.match(output, /TEST1234/);
    assert.match(output, /device linked/);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

for (const debug of ['', '0', 'true', '1']) {
test(`bridge delivers and replies with debug receipts ${JSON.stringify(debug)}`, async () => {
  const fixture = setup();
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'claude', session: 'agent-claude', name: 'claude' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, LOCAL_WHATSAPP_DEBUG: debug };
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
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'whatsapp_reply', arguments: { id, text: 'answer' } } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 2), 'reply tool');
    await waitUntil(() => existsSync(fixture.fakeOut) && readFileSync(fixture.fakeOut, 'utf8').includes('answer'), 'WhatsApp send');
    const outbound = readFileSync(fixture.fakeOut, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.ok(outbound.every((item) => item.jid === '14155551234@s.whatsapp.net'));
    assert.ok(outbound.some((item) => item.payload.text === 'answer'));
    assert.equal(outbound.some((item) => item.payload.text.includes('Box: received')), debug === '1');
    await waitUntil(() => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8')).messages[id].reply?.status === 'sent', 'persisted reply');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages[id].reply.status, 'sent');
    assert.equal(saved.messages[id].ack?.status, debug === '1' ? 'sent' : undefined);
  } finally {
    if (peer) await stop(peer);
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

}

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
    assert.deepEqual(outbound.map((item) => item.payload.text), ['old answer']);
    await waitUntil(() => JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8')).messages.old.reply?.status === 'sent', 'persisted queued reply');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(saved.messages.old.ack.status, 'suppressed');
    assert.equal(saved.messages.old.reply.status, 'sent');
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('bridge routes to Codex queue without a Claude peer', async () => {
  const fixture = setup();
  const bin = join(fixture.dir, 'bin');
  const argsFile = join(fixture.dir, 'codex-args.txt');
  mkdirSync(bin);
  writeFileSync(join(bin, 'codex'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$CODEX_ARGS_FILE"\n');
  chmodSync(join(bin, 'codex'), 0o700);
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    CODEX_ARGS_FILE: argsFile, LOCAL_WHATSAPP_CODEX_BIN: join(bin, 'codex'),
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await waitUntil(() => existsSync(argsFile), 'Codex queue');
    const args = readFileSync(argsFile, 'utf8');
    assert.match(args, /queue\n--thread\ncodex\n--message\n/);
    assert.match(args, /WhatsApp Message Yourself/);
    assert.match(args, /reply right away with a one-line acknowledgement/);
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('disabled sessions receive no messages and cannot be selected', async () => {
  const fixture = setup();
  writeFileSync(fixture.sessionBin, "#!/bin/sh\ncase \"$2\" in candidates) printf '%s\\n' '[]' ;; spawn) exit 1 ;; esac\n");
  writeFileSync(join(fixture.state, 'target.json'), JSON.stringify({ harness: 'codex', session: 'codex', name: 'codex' }));
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state,
    LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin, FAKE_OUT: fixture.fakeOut };
  const daemon = spawn(process.execPath, [join(fixture.dir, 'bridge.mjs'), 'serve'], {
    env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await waitUntil(() => existsSync(join(fixture.state, 'messages.json')), 'saved message');
    const saved = JSON.parse(readFileSync(join(fixture.state, 'messages.json'), 'utf8'));
    assert.equal(Object.values(saved.messages)[0].deliveredTo, null);
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

test('self-chat can select a registered agent-box session without re-pairing', async () => {
  const fixture = setup();
  const bin = join(fixture.dir, 'bin');
  mkdirSync(bin);
  const env = { ...process.env, LOCAL_WHATSAPP_STATE_DIR: fixture.state, FAKE_OUT: fixture.fakeOut,
    FAKE_INBOUND_TEXT: `@${userInfo().username} /target codex`, LOCAL_WHATSAPP_SESSION_BIN: fixture.sessionBin };
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
    assert.equal(outbound.length, 1);
    assert.equal(outbound[0].jid, '14155551234@s.whatsapp.net');
    assert.equal(outbound[0].payload.caption, 'my picture');
    assert.equal(outbound[0].payload.mimetype, 'image/png');
    assert.deepEqual(Buffer.from(outbound[0].payload.image.data), png);
    await waitUntil(() => !existsSync(join(fixture.state, 'media-outbox', image)), 'media cleanup');
  } finally {
    await stop(daemon);
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});
