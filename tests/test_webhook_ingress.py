"""Bounded unauthenticated HTTP intake on disposable local listeners only."""
import contextlib
import hashlib
import hmac
import http.client
import io
import os
import socket
import threading
import time
from unittest.mock import patch

from test_webhook import EndToEndCase, StateDirCase


class TestIngressBounds(StateDirCase):
    def setUp(self):
        super().setUp()
        self.mod.HTTP_MAX_CONNECTIONS = 2
        self.mod.HTTP_READ_TIMEOUT_S = 0.6
        self.mod.SPOOL_ENABLED = False
        self.events = []
        self.mod.broadcast = self.events.append
        self.mod.dispatch_event = lambda event: None
        self.write_json('sources.json', {'sources': {'github': {'secret': 'fixture'}}})

    @contextlib.contextmanager
    def listener(self, transport='unix'):
        mod = self.mod
        started = []
        condition = threading.Condition()

        class ObservedHandler(mod.Handler):
            def setup(self):
                super().setup()
                with condition:
                    started.append(self)
                    condition.notify_all()

        unix = transport.endswith('unix')
        family = socket.AF_UNIX if unix else socket.AF_INET
        address = os.path.join(self.state, 'http.sock') if unix else ('127.0.0.1', 0)
        if transport.startswith('fd-'):
            inherited = socket.socket(family)
            inherited.bind(address)
            inherited.listen(16)
            address = inherited.getsockname()
            server = mod._FdServer(inherited.detach(), ObservedHandler)
        else:
            cls = mod._UnixServer if unix else mod._TcpServer
            server = cls(address, ObservedHandler)
            address = server.socket.getsockname()
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01},
                                  daemon=True)
        worker.start()
        sockets = []

        def connect(request=b''):
            client = socket.socket(family)
            sockets.append(client)
            client.settimeout(3)
            client.connect(address)
            if request:
                client.sendall(request)
            return client

        def admitted(count):
            with condition:
                self.assertTrue(condition.wait_for(lambda: len(started) >= count, timeout=2))

        try:
            yield connect, admitted, started
        finally:
            for client in sockets:
                client.close()
            server.shutdown()
            server.server_close()
            worker.join(2)
            if unix:
                os.unlink(address)

    def response(self, client):
        response = http.client.HTTPResponse(client)
        response.begin()
        response.read()
        return response.status

    def signed_request(self, chunked=False):
        body = b'{"repository":{"full_name":"o/r"},"action":"opened"}'
        signature = hmac.new(b'fixture', body, hashlib.sha256).hexdigest().encode()
        headers = (b'POST /github HTTP/1.1\r\nHost: local\r\n'
                   b'X-GitHub-Event: issues\r\nX-Hub-Signature-256: sha256=' + signature + b'\r\n')
        if chunked:
            # Tiny chunks also cover bounded accumulation and trailer parsing.
            wire = b''.join(b'1\r\n' + bytes([b]) + b'\r\n' for b in body)
            return headers + b'Transfer-Encoding: chunked\r\n\r\n' + wire + b'0\r\nX-Note: ok\r\n\r\n'
        return headers + b'Content-Length: %d\r\n\r\n' % len(body) + body

    def test_admission_and_recovery_on_all_listener_types(self):
        for transport in ('tcp', 'unix', 'fd-tcp', 'fd-unix'):
            with self.subTest(transport=transport), self.listener(transport) as (connect, admitted, started):
                # Two unsigned bodies withhold their last byte. Accepted
                # connections beyond those slots must never start a handler.
                held = [connect(b'POST /github HTTP/1.1\r\nContent-Length: 1\r\n\r\n')
                        for _ in range(2)]
                admitted(2)
                for _ in range(8):
                    self.assertEqual(self.response(connect()), 503)
                self.assertEqual(len(started), 2)
                for client in held:
                    self.assertEqual(self.response(client), 408)
                # The timeout response is flushed just before the worker
                # returns its slot; allow that return without racing it.
                deadline = time.monotonic() + 2
                while True:
                    status = self.response(connect(self.signed_request()))
                    if status != 503 or time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                self.assertEqual(status, 200)
                self.assertEqual(self.events[-1]['key'], 'o/r')

    def test_absolute_deadline_rejects_trickle_in_every_read_phase(self):
        requests = (
            b'',  # incomplete request line
            b'POST /github HTTP/1.1\r\nX-Slow: ',
            b'POST /github HTTP/1.1\r\nContent-Length: 100\r\n\r\n',
            b'POST /github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1;',
            b'POST /github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n',
            b'POST /github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Slow: ',
        )
        for request in requests:
            with self.subTest(request=request), self.listener() as (connect, admitted, _):
                client = connect(request)
                admitted(1)
                stop = threading.Event()

                def trickle():
                    while not stop.wait(0.03):
                        try:
                            client.sendall(b'a')
                        except OSError:
                            break

                writer = threading.Thread(target=trickle, daemon=True)
                writer.start()
                started_at = time.monotonic()
                try:
                    self.assertEqual(self.response(client), 408)
                    self.assertLess(time.monotonic() - started_at, 1.8)
                finally:
                    stop.set()
                    writer.join(2)
                self.assertEqual(self.events, [])

    def test_idle_header_and_body_deadlines(self):
        for request in (b'', b'POST /github HTTP/1.1\r\nX-Hold: ',
                        b'POST /github HTTP/1.1\r\nContent-Length: 1\r\n\r\n'):
            with self.subTest(request=request), self.listener() as (connect, _, _):
                self.assertEqual(self.response(connect(request)), 408)

    def test_aggregate_headers_and_trailers_are_bounded(self):
        headers = b''.join(b'X-Long: ' + b'a' * 1000 + b'\r\n' for _ in range(70))
        for request in (b'POST /github HTTP/1.1\r\n' + headers + b'\r\n',
                        b'POST /github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n'
                        + headers + b'\r\n'):
            with self.subTest(trailers=b'chunked' in request), self.listener() as (connect, _, _):
                self.assertEqual(self.response(connect(request)), 431)
        self.assertEqual(self.events, [])

    def test_chunked_signed_body_and_legacy_status_contracts(self):
        with self.listener() as (connect, _, _):
            self.assertEqual(self.response(connect(self.signed_request(chunked=True))), 200)
            self.assertEqual(self.response(connect(
                b'POST /github HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}')), 401)
            self.assertEqual(self.response(connect(
                b'POST /absent HTTP/1.1\r\nContent-Length: 0\r\n\r\n')), 404)
            self.assertEqual(self.response(connect(b'GET /github HTTP/1.1\r\n\r\n')), 405)
            self.mod.MAX_BODY_BYTES = 10
            self.assertEqual(self.response(connect(
                b'POST /github HTTP/1.1\r\nContent-Length: 11\r\n\r\n')), 413)
        self.assertEqual(len(self.events), 1)

    def test_incomplete_and_oversized_chunk_framing_never_deliver(self):
        prefix = b'POST /github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'
        for body in (b'1;' + b'a' * 8192 + b'\r\nx\r\n0\r\n\r\n',
                     b'3\r\nx', b'1\r\nx!!0\r\n\r\n', b'0\r\nX-Unfinished:'):
            with self.subTest(body=body[:20]), self.listener() as (connect, _, _):
                client = connect(prefix + body)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(self.response(client), 500)
        self.assertEqual(self.events, [])

    def test_delivery_processing_is_outside_read_deadline(self):
        self.mod.HTTP_READ_TIMEOUT_S = 0.1
        original = self.mod.deliver

        def slow_delivery(handler, body):
            time.sleep(0.2)
            return original(handler, body)

        self.mod.deliver = slow_delivery
        with self.listener() as (connect, _, _):
            self.assertEqual(self.response(connect(self.signed_request())), 200)

    def test_invalid_configuration_cannot_disable_bounds(self):
        for value in ('0', '-1', '', 'nan', '0.1'):
            with self.subTest(value=value), patch.dict(os.environ, {'INGRESS_TEST': value}), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.mod._positive_env('INGRESS_TEST', 8), 8)
        with patch.dict(os.environ, {'INGRESS_TEST': '3'}):
            self.assertEqual(self.mod._positive_env('INGRESS_TEST', 8), 3)

    def test_failed_thread_start_returns_admission_slot(self):
        server = self.mod._TcpServer(('127.0.0.1', 0), self.mod.Handler)
        self.addCleanup(server.server_close)
        with patch.object(threading.Thread, 'start', side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError):
                server.process_request(None, ('local', 0))
        self.assertTrue(server._request_slots.acquire(blocking=False))
        self.assertTrue(server._request_slots.acquire(blocking=False))
        self.assertFalse(server._request_slots.acquire(blocking=False))


class TestIngressRecoveryEndToEnd(EndToEndCase):
    def test_signed_delivery_reaches_real_peer_after_slow_request(self):
        self.start_daemon(LOCAL_WEBHOOK_HTTP_MAX_CONNECTIONS='1',
                          LOCAL_WEBHOOK_HTTP_READ_TIMEOUT_S='1')
        self.assertEqual(self.cli('subscribe', 'o/r', '--note', 'ingress recovery').returncode, 0)
        peer = self.start_peer('testsess')
        with socket.socket(socket.AF_UNIX) as slow:
            slow.settimeout(4)
            slow.connect(self.http_sock)
            slow.sendall(b'POST /github HTTP/1.1\r\nContent-Length: 1\r\n\r\n')
            with socket.socket(socket.AF_UNIX) as excess:
                excess.settimeout(4)
                excess.connect(self.http_sock)
                busy = http.client.HTTPResponse(excess)
                busy.begin()
                self.assertEqual(busy.status, 503)
                self.assertEqual(busy.getheader('Retry-After'), '1')
                busy.read()
            response = http.client.HTTPResponse(slow)
            response.begin()
            self.assertEqual(response.status, 408)
            response.read()
        deadline = time.monotonic() + 3
        while True:
            status, body = self.post(self.ISSUE)
            if status != 503 or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        self.assertEqual(status, 200, body)
        message = self.read_peer_line(peer)
        self.assertEqual(message['method'], 'notifications/claude/channel')
        self.assertIn('ingress recovery', message['params']['content'])
