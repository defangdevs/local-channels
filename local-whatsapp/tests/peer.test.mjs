import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import test from 'node:test';

test('Claude peer registers, receives a channel message, and replies by id', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'local-whatsapp-peer-'));
  const socketPath = join(dir, 'bridge.sock');
  const requests = [];
  const server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      while (buffer.includes('\n')) {
        const index = buffer.indexOf('\n');
        const value = JSON.parse(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
        requests.push(value);
        if (value.op === 'subscribe') {
          socket.write(`${JSON.stringify({ op: 'message', message: {
            id: 'abc123', text: 'hello', receivedAt: '2026-10-02T00:00:00Z',
          } })}\n`);
        } else if (value.op === 'reply' || value.op === 'reply-image') {
          socket.write(`${JSON.stringify({ ok: true, status: 'queued' })}\n`);
        }
      }
    });
  });
  server.listen(socketPath);
  await once(server, 'listening');
  const peer = spawn(process.execPath, [new URL('../peer.mjs', import.meta.url).pathname], {
    env: { ...process.env, LOCAL_WHATSAPP_STATE_DIR: dir, LOCAL_WHATSAPP_SESSION: 'agent-claude' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const output = [];
  let buffer = '';
  peer.stdout.on('data', (chunk) => {
    buffer += chunk.toString();
    while (buffer.includes('\n')) {
      const index = buffer.indexOf('\n');
      output.push(JSON.parse(buffer.slice(0, index)));
      buffer = buffer.slice(index + 1);
    }
  });
  async function waitUntil(predicate) {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (predicate()) return;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error('timed out waiting for peer');
  }
  try {
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 1));
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    await waitUntil(() => output.some((item) => item.method === 'notifications/claude/channel'));
    assert.equal(output.find((item) => item.id === 1).result.capabilities.experimental['claude/channel'] instanceof Object, true);
    assert.equal(requests[0].session, 'agent-claude');
    assert.match(output.find((item) => item.method === 'notifications/claude/channel').params.content, /abc123.*hello/);
    assert.match(output.find((item) => item.method === 'notifications/claude/channel').params.content, /reply right away with a one-line acknowledgement/);
    assert.match(output.find((item) => item.id === 1).result.instructions, /progress update every few minutes/);
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {
      name: 'whatsapp_reply', arguments: { id: 'abc123', text: 'done' },
    } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 2));
    assert.deepEqual(requests.find((item) => item.op === 'reply'), { op: 'reply', id: 'abc123', text: 'done' });
    assert.equal(output.find((item) => item.id === 2).result.content[0].text, 'queued');
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' })}\n`);
    await waitUntil(() => output.some((item) => item.id === 3));
    assert.ok(output.find((item) => item.id === 3).result.tools.some((tool) => tool.name === 'whatsapp_reply_image'));
    peer.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {
      name: 'whatsapp_reply_image', arguments: { id: 'abc123', path: '/home/agent/picture.png', caption: 'picture' },
    } })}\n`);
    await waitUntil(() => output.some((item) => item.id === 4));
    assert.deepEqual(requests.find((item) => item.op === 'reply-image'), {
      op: 'reply-image', id: 'abc123', path: '/home/agent/picture.png', caption: 'picture',
    });
    assert.equal(output.find((item) => item.id === 4).result.content[0].text, 'queued');
  } finally {
    peer.kill();
    await once(peer, 'exit');
    server.close();
    await once(server, 'close');
    rmSync(dir, { recursive: true, force: true });
  }
});
