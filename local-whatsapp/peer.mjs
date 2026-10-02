import { createConnection } from 'node:net';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { publicMessage, stateDir } from './state.mjs';

const socketPath = join(stateDir(), 'bridge.sock');
const session = process.env.LOCAL_WHATSAPP_SESSION || process.env.LOCAL_WEBHOOK_SESSION;
let stopped = false;
let subscribed = false;

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function connectPeer() {
  if (!session || stopped) return;
  const socket = createConnection(socketPath);
  socket.on('connect', () => socket.write(`${JSON.stringify({ op: 'subscribe', session })}\n`));
  let buffer = '';
  socket.on('data', (chunk) => {
    buffer += chunk.toString();
    while (buffer.includes('\n')) {
      const index = buffer.indexOf('\n');
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        const event = JSON.parse(line);
        if (event.op !== 'message') continue;
        const message = publicMessage(event.message);
        output({
          jsonrpc: '2.0',
          method: 'notifications/claude/channel',
          params: {
            content: `WhatsApp Message Yourself (${message.id}): ${message.text}\nReply with whatsapp_reply using this message id.`,
            meta: { source: 'local-whatsapp', messageId: message.id, receivedAt: message.receivedAt },
          },
        });
      } catch (error) {
        process.stderr.write(`local-whatsapp peer: ${error.message}\n`);
      }
    }
  });
  socket.on('error', () => {});
  socket.on('close', () => {
    if (!stopped) setTimeout(connectPeer, 2000).unref();
  });
}

function requestReply(id, text) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let buffer = '';
    socket.setTimeout(10000);
    socket.on('connect', () => socket.write(`${JSON.stringify({ op: 'reply', id, text })}\n`));
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      if (!buffer.includes('\n')) return;
      socket.end();
      try {
        const answer = JSON.parse(buffer.split('\n')[0]);
        if (answer.ok) resolve(answer);
        else reject(new Error(answer.error || 'reply failed'));
      } catch (error) { reject(error); }
    });
    socket.on('timeout', () => socket.destroy(new Error('bridge timeout')));
    socket.on('error', reject);
  });
}

const reader = createInterface({ input: process.stdin });
reader.on('line', async (line) => {
  let message;
  try { message = JSON.parse(line); } catch { return; }
  if (message.method === 'notifications/initialized' && !subscribed) {
    subscribed = true;
    connectPeer();
    return;
  }
  if (!Object.hasOwn(message, 'id')) return;
  try {
    let result;
    if (message.method === 'initialize') {
      result = {
        protocolVersion: message.params?.protocolVersion || '2025-06-18',
        capabilities: { tools: {}, experimental: { 'claude/channel': {} } },
        serverInfo: { name: 'local-whatsapp', version: '0.1.0' },
        instructions: 'A linked WhatsApp self-chat can send messages to this session. Use whatsapp_reply with the message id to answer in WhatsApp. The host controls which session this peer registers as.',
      };
    } else if (message.method === 'tools/list') {
      result = { tools: [{
        name: 'whatsapp_reply',
        description: 'Reply to an incoming WhatsApp message in its original chat. Requires its message id.',
        inputSchema: { type: 'object', properties: {
          id: { type: 'string' }, text: { type: 'string' },
        }, required: ['id', 'text'], additionalProperties: false },
      }] };
    } else if (message.method === 'tools/call' && message.params?.name === 'whatsapp_reply') {
      const args = message.params.arguments || {};
      const reply = await requestReply(args.id, args.text);
      result = { content: [{ type: 'text', text: reply.status }] };
    } else {
      output({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'method not found' } });
      return;
    }
    output({ jsonrpc: '2.0', id: message.id, result });
  } catch (error) {
    output({ jsonrpc: '2.0', id: message.id, result: { isError: true, content: [{ type: 'text', text: error.message }] } });
  }
});
reader.on('close', () => { stopped = true; });
