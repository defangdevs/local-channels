"""A small mock of Slack for end-to-end testing local-slack: Web API over HTTP
and Socket Mode over a minimal WebSocket server. Everything local."""
import base64, hashlib, json, socket, struct, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

USERS = {
    'U1': {'id': 'U1', 'name': 'alice', 'team_id': 'T1', 'deleted': False, 'is_bot': False,
           'is_restricted': False, 'is_ultra_restricted': False, 'profile': {'display_name': 'alice'}},
    'UGUEST': {'id': 'UGUEST', 'name': 'gus', 'team_id': 'T1', 'deleted': False, 'is_bot': False,
               'is_restricted': True, 'is_ultra_restricted': False, 'profile': {'display_name': 'gus'}},
    'UBOT': {'id': 'UBOT', 'name': 'agentbox', 'team_id': 'T1', 'deleted': False, 'is_bot': True,
             'is_restricted': False, 'is_ultra_restricted': False, 'profile': {'display_name': 'Agent Box'}},
}
CHANNELS = {'C1': {'id': 'C1', 'name': 'dev', 'is_member': True, 'is_ext_shared': False},
            'C2': {'id': 'C2', 'name': 'random', 'is_member': True, 'is_ext_shared': False},
            'C3': {'id': 'C3', 'name': 'outside', 'is_member': False, 'is_ext_shared': False}}


class Mock:
    def __init__(self):
        self.calls = []          # (time, method, content_type, params, token_kind)
        self.messages = {}       # (channel, ts) -> message dict (incl. thread_ts)
        self.acks = []           # (time, envelope_id)
        self.sent = {}           # envelope_id -> time sent
        self.conns = []
        self.lock = threading.Lock()
        self.ts_counter = 1760600000
        self.ws_port = None

    # ---------------- Web API ----------------
    def next_ts(self):
        with self.lock:
            self.ts_counter += 1
            return '%d.000100' % self.ts_counter

    def api(self, method, ctype, params, token):
        kind = 'app' if token.startswith('xapp-') else 'bot' if token.startswith('xoxb-') else '?'
        self.calls.append((time.time(), method, ctype, params, kind))
        if method == 'auth.test':
            return {'ok': True, 'user_id': 'UBOT', 'bot_id': 'BBOT', 'team_id': 'T1', 'user': 'agentbox',
                    'url': 'https://acme.slack.com/'}
        if method == 'apps.connections.open':
            if kind != 'app':
                return {'ok': False, 'error': 'not_allowed_token_type'}
            return {'ok': True, 'url': 'ws://127.0.0.1:%d/link/?ticket=t' % self.ws_port}
        if method == 'conversations.info':
            c = CHANNELS.get(params.get('channel'))
            return {'ok': True, 'channel': c} if c else {'ok': False, 'error': 'channel_not_found'}
        if method == 'users.info':
            u = USERS.get(params.get('user'))
            return {'ok': True, 'user': u} if u else {'ok': False, 'error': 'user_not_found'}
        if method == 'users.list':
            return {'ok': True, 'members': list(USERS.values()), 'response_metadata': {'next_cursor': ''}}
        if method == 'conversations.list':
            return {'ok': True, 'channels': list(CHANNELS.values()), 'response_metadata': {'next_cursor': ''}}
        if method in ('conversations.replies', 'conversations.history'):
            ch, ts = params.get('channel'), params.get('ts') or params.get('latest')
            if not ch:
                return {'ok': False, 'error': 'channel_not_found'}   # what Slack says when args are missing
            m = self.messages.get((ch, ts))
            return {'ok': True, 'messages': [m] if m else []}
        if method == 'chat.postMessage':
            if not params.get('channel') or not params.get('text'):
                return {'ok': False, 'error': 'no_text'}
            ts = self.next_ts()
            m = {'ts': ts, 'user': 'UBOT', 'bot_id': 'BBOT', 'text': params['text']}
            if params.get('thread_ts'):
                m['thread_ts'] = params['thread_ts']
            self.messages[(params['channel'], ts)] = m
            return {'ok': True, 'ts': ts, 'channel': params['channel'], 'message': m}
        if method == 'chat.update':
            if len(params.get('text', '')) > 4000:
                return {'ok': False, 'error': 'msg_too_long'}
            return {'ok': True, 'ts': params.get('ts'), 'channel': params.get('channel')}
        if method in ('reactions.add', 'reactions.remove'):
            return {'ok': True}
        return {'ok': False, 'error': 'unknown_method'}

    def http_handler(self):
        mock = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, body):
                method = urllib.parse.urlsplit(self.path).path.rsplit('/', 1)[-1]
                ctype = (self.headers.get('Content-Type') or '').split(';')[0]
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
                params = dict(q)
                if body:
                    if ctype == 'application/json':
                        params.update(json.loads(body.decode() or '{}'))
                    else:
                        params.update(dict(urllib.parse.parse_qsl(body.decode())))
                token = (self.headers.get('Authorization') or '').replace('Bearer ', '')
                out = json.dumps(mock.api(method, ctype or ('query' if q else ''), params, token)).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):
                n = int(self.headers.get('Content-Length') or 0)
                self._go(self.rfile.read(n) if n else b'')

            def do_GET(self):
                self._go(b'')
        return H

    # ---------------- Socket Mode ----------------
    def ws_serve(self, srv):
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self.ws_conn, args=(conn,), daemon=True).start()

    def ws_conn(self, conn):
        buf = b''
        while b'\r\n\r\n' not in buf:
            buf += conn.recv(4096)
        key = [l.split(b':', 1)[1].strip() for l in buf.split(b'\r\n') if l.lower().startswith(b'sec-websocket-key')][0]
        acc = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest()).decode()
        conn.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                      'Sec-WebSocket-Accept: %s\r\n\r\n' % acc).encode())
        with self.lock:
            self.conns.append(conn)
        self.ws_send(conn, {'type': 'hello', 'num_connections': len(self.conns), 'connection_info': {'app_id': 'A1'}})
        try:
            while True:
                op, data = self.ws_read(conn)
                if op is None or op == 0x8:
                    break
                if op == 0x9:
                    self.ws_frame(conn, 0xA, data)
                    continue
                if op == 0x1:
                    msg = json.loads(data.decode())
                    if msg.get('envelope_id'):
                        self.acks.append((time.time(), msg['envelope_id']))
        finally:
            with self.lock:
                if conn in self.conns:
                    self.conns.remove(conn)

    def ws_read(self, conn):
        def rd(n):
            b = b''
            while len(b) < n:
                c = conn.recv(n - len(b))
                if not c:
                    raise EOFError
                b += c
            return b
        try:
            h = rd(2)
        except (EOFError, OSError):
            return None, None
        op, ln, masked = h[0] & 0x0F, h[1] & 0x7F, h[1] & 0x80
        if ln == 126:
            ln = struct.unpack('>H', rd(2))[0]
        elif ln == 127:
            ln = struct.unpack('>Q', rd(8))[0]
        mask = rd(4) if masked else b'\0\0\0\0'
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(rd(ln)))
        return op, data

    def ws_frame(self, conn, op, data):
        n = len(data)
        hdr = bytes([0x80 | op]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack('>H', n)
                                     if n < 65536 else bytes([127]) + struct.pack('>Q', n))
        conn.sendall(hdr + data)

    def ws_send(self, conn, obj):
        self.ws_frame(conn, 0x1, json.dumps(obj).encode())

    def wait_conn(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if self.conns:
                return True
            time.sleep(0.1)
        return False

    def event(self, eid, event, retry=0):
        """Deliver an events_api envelope on the first connection; also record
        posted messages so conversations.replies can resolve them."""
        if event.get('type') == 'message' and 'ts' in event and event.get('subtype') is None:
            self.messages[(event['channel'], event['ts'])] = dict(event)
        env_id = 'env-%s-%d' % (eid, retry)
        self.sent[env_id] = time.time()
        with self.lock:
            conn = self.conns[0]
        self.ws_send(conn, {'envelope_id': env_id, 'type': 'events_api', 'accepts_response_payload': False,
                            'retry_attempt': retry, 'retry_reason': 'timeout' if retry else '',
                            'payload': {'team_id': 'T1', 'api_app_id': 'A1', 'type': 'event_callback',
                                        'event_id': eid, 'event_time': int(time.time()), 'event': event}})
        return env_id


def start():
    m = Mock()
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0)); srv.listen(8)
    m.ws_port = srv.getsockname()[1]
    threading.Thread(target=m.ws_serve, args=(srv,), daemon=True).start()
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), m.http_handler())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return m, 'http://127.0.0.1:%d' % httpd.server_address[1]

