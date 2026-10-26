"""Email uses ordinary signed ingress, routing and the durable inbox."""
import json
import os
import select
import stat
import threading
import time

from test_webhook import StateDirCase, EndToEndCase


class TestContent(StateDirCase):
    def env(self, ident='mail-1', text='complete body'):
        return {'source': 'email', 'format': 'generic', 'event': 'email.received',
                'delivery': ident, 'key': 'agent@box.example', 'sender': '',
                'payload': {'recipient': 'agent@box.example', 'text': text}}

    def test_content_outlives_queue_and_reload_but_expires(self):
        env = self.env()
        sid, at = self.mod.spool_accept(env, 'digest', retain=True)
        self.mod.spool_process(sid, env, at, live=False, enqueue=False, digest='digest')
        ident = env['contentRef']['id']
        self.assertEqual(self.load().read_content(ident)['payload']['text'], 'complete body')
        self.assertEqual(self.mod.spool_status()['content']['count'], 1)
        p = self.mod.spool_path(self.mod.CONTENT.new, ident)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.mod.spool_reap(now_s=time.time() + self.mod.CONTENT_TTL_S + 1)
        with self.assertRaisesRegex(ValueError, 'missing or expired'):
            self.mod.read_content(ident)
        with self.assertRaises(ValueError):
            self.mod.read_content('../../outside')

    def test_capacity_refuses_without_evicting_promised_content(self):
        mod = self.load(LOCAL_WEBHOOK_CONTENT_MAX='1')
        first = self.env()
        mod.spool_accept(first, 'a', retain=True)
        with self.assertRaisesRegex(OSError, 'capacity'):
            mod.spool_accept(self.env('mail-2'), 'b', retain=True)
        self.assertEqual(mod.read_content(first['contentRef']['id'])['payload']['text'], 'complete body')
        self.assertEqual(mod.spool_status()['inbox'], 1)

    def test_byte_limit_and_no_overwrite_for_reused_delivery_id(self):
        mod = self.load(LOCAL_WEBHOOK_CONTENT_MAX_BYTES='10')
        with self.assertRaisesRegex(OSError, 'capacity'):
            mod.spool_accept(self.env(), 'a', retain=True)
        first, second = self.env(), self.env(text='different body')
        self.mod.spool_accept(first, 'a', retain=True)
        self.mod.spool_accept(second, 'b', retain=True)
        self.assertNotEqual(first['contentRef']['id'], second['contentRef']['id'])
        self.assertEqual(self.mod.read_content(first['contentRef']['id'])['payload']['text'], 'complete body')

    def test_failed_inbox_write_rolls_back_only_new_content(self):
        env = self.env()
        real_publish = self.mod.SPOOL_INBOX.publish
        def broken(*args, **kwargs):
            raise OSError('inbox disk failure')
        self.mod.SPOOL_INBOX.publish = broken
        with self.assertRaises(OSError):
            self.mod.spool_accept(env, 'a', retain=True)
        self.assertEqual(self.mod.spool_status()['content']['count'], 0)
        self.mod.SPOOL_INBOX.publish = real_publish
        self.mod.spool_accept(env, 'a', retain=True)
        self.mod.SPOOL_INBOX.publish = broken
        # An already-promised reference must survive a failed duplicate path.
        with self.assertRaises(OSError):
            self.mod.spool_accept(self.env(), 'a', retain=True)
        self.assertEqual(self.mod.read_content(env['contentRef']['id'])['payload']['text'], 'complete body')

    def test_idless_acceptances_have_independent_retention(self):
        first, second = self.env(ident=''), self.env(ident='')
        self.mod.spool_accept(first, 'a', retain=True)
        self.mod.spool_accept(second, 'a', retain=True)
        self.assertNotEqual(first['contentRef']['id'], second['contentRef']['id'])

    def test_concurrent_admission_respects_count_cap(self):
        mod = self.load(LOCAL_WEBHOOK_CONTENT_MAX='1')
        results = []

        def store(n):
            try:
                mod.spool_accept(self.env('mail-%d' % n), str(n), retain=True)
                results.append('accepted')
            except OSError:
                results.append('full')

        threads = [threading.Thread(target=store, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ['accepted', 'full', 'full', 'full'])


class TestEmailEndToEnd(EndToEndCase):
    def setUp(self):
        super().setUp()
        self.add_source('email', format='generic', keyPath='recipient',
                        senderPath='envelopeSender', retainPayload=True)
        self.mail = {'recipient': 'agent@box.example', 'envelopeSender': 'claimed@example.org',
                     'title': 'Incoming task', 'summary': 'preview', 'text': 'x' * 5000,
                     'headers': {'messageId': '<same@untrusted.example>'},
                     'senderAuthenticated': False}

    def emit(self, ident):
        return self.cli('emit', 'email', '-', '--event', 'email.received',
                        '--delivery-id', ident, stdin=json.dumps(self.mail).encode())

    def test_signed_email_peer_retention_and_idempotent_retry(self):
        r = self.cli('subscribe', 'email:agent@box.example', session='mailreader')
        self.assertEqual(r.returncode, 0, r.stderr)
        daemon = self.start_daemon()
        peer = self.start_peer('mailreader')
        peer.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        peer.stdin.flush()
        r = self.emit('mta-queue-1')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(select.select([peer.stdout], [], [], 10)[0])
        msg = json.loads(peer.stdout.readline())['params']
        self.assertIn('UNTRUSTED', msg['content'])
        ident = msg['meta']['contentRef']['id']
        r = self.cli('read-content', ident)
        self.assertEqual(json.loads(r.stdout)['payload']['text'], 'x' * 5000)
        # Same handoff does not deliver twice, even after its queue copy drains.
        self.assertEqual(self.emit('mta-queue-1').returncode, 0)
        self.assertFalse(select.select([peer.stdout], [], [], 0.3)[0])
        # Independent SMTP transactions with the same header Message-ID survive.
        self.assertEqual(self.emit('mta-queue-2').returncode, 0)
        self.assertTrue(select.select([peer.stdout], [], [], 10)[0])
        peer.stdout.readline()
        daemon.kill()
        daemon.wait()
        self.assertEqual(self.cli('read-content', ident).returncode, 0)

    def test_standing_watch_has_the_same_content_reference(self):
        r = self.cli('subscribe', 'email:agent@box.example', '--deliver-to', 'subagent',
                     '--include', json.dumps({'path': 'event', 'in': ['email.received']}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.start_daemon()
        self.assertEqual(self.emit('mta-spawn-1').returncode, 0)
        self.assertTrue(self.wait_file(self.spawn_log, contains='read-content'))
        with open(self.spawn_log) as f:
            text = f.read()
        ident = text.split('read-content ')[1].split(';')[0]
        self.assertEqual(json.loads(self.cli('read-content', ident).stdout)['payload'], self.mail)
        self.mail['recipient'] = 'other@box.example'
        self.assertEqual(self.emit('mta-other-1').returncode, 0)
        time.sleep(0.2)
        with open(self.spawn_log) as f:
            self.assertEqual(f.read(), text)

    def test_failed_content_write_is_not_acknowledged(self):
        self.start_daemon(LOCAL_WEBHOOK_CONTENT_MAX_BYTES='10')
        self.assertEqual(self.emit('mta-full-1').returncode, 1)
        status = json.loads(self.cli('status').stdout)['spool']
        self.assertEqual(status['inbox'], 0)
        self.assertEqual(status['content']['count'], 0)

    def test_retention_cannot_silently_run_without_spool(self):
        self.start_daemon(LOCAL_WEBHOOK_SPOOL='off')
        self.assertEqual(self.emit('mta-off-1').returncode, 1)
        for ident in ('../escape', 'bad\nheader', '', '-switch'):
            self.assertEqual(self.emit(ident).returncode, 2)
