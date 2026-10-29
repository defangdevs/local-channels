"""Acceptance hook tests; no external reactions are sent."""
import io
import json
import os
import subprocess
import sys
from unittest.mock import patch

from test_webhook import ANY_EVENT, EndToEndCase, StateDirCase, PYTHON


def recorder(state):
    path = os.path.join(state, 'ack adapter')
    log = os.path.join(state, 'acks.jsonl')
    with open(path, 'w') as f:
        f.write('#!%s\nimport sys\nopen(%r, "a").write(sys.stdin.read()+"\\n")\n' % (PYTHON, log))
    os.chmod(path, 0o700)
    return path, log


class TestAcceptanceHook(StateDirCase):
    def setUp(self):
        super().setUp()
        self.cmd, self.log = recorder(self.state)
        self.mod = self.load(LOCAL_WEBHOOK_ACK_CMD=self.cmd)
        self.mod.out = lambda value: None
        self.env = {'source': 'github', 'format': 'github', 'key': 'o/r', 'event': 'issue_comment',
                    'sender': 'someone', 'payload': {'action': 'created', 'comment': {'id': 123}}}

    def records(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as f:
            return [json.loads(line) for line in f]

    def subscribe(self, claim=True):
        args = {'topic': 'o/r'}
        if claim:
            args['include'] = ANY_EVENT
        self.call('webhook_subscribe', **args)

    def test_claimed_claude_delivery_acknowledges_after_write(self):
        self.subscribe()
        def output(value):
            self.assertEqual(self.records(), [])
        self.mod.out = output
        self.assertEqual(self.mod.handle_event(self.env), 'delivered')
        self.assertEqual(self.records(), [{'envelope': self.env, 'target': 'testsess'}])

    def test_filtered_and_observer_deliveries_do_not_acknowledge(self):
        self.assertEqual(self.mod.handle_event(self.env), 'filtered')
        self.subscribe(claim=False)
        self.assertEqual(self.mod.handle_event(self.env), 'delivered')
        self.assertEqual(self.records(), [])

    def test_codex_failure_then_success(self):
        self.subscribe()
        self.mod.CODEX_PEER = True
        self.mod.codex_deliver = lambda *args: False
        self.assertEqual(self.mod.handle_event(self.env), 'failed')
        self.assertEqual(self.records(), [])
        self.mod.codex_deliver = lambda *args: True
        self.assertEqual(self.mod.handle_event(self.env), 'delivered')
        self.assertEqual(len(self.records()), 1)

    def test_spawn_success_acknowledges_every_batch_item_only(self):
        second = dict(self.env, delivery='second')
        items = [('one', {}, self.env, None), ('two', {}, second, None)]
        for code in (75, 1):
            d = self.mod.Dispatcher('exit %d' % code, 1, 0, 2)
            d.active = 1
            with patch.object(sys, 'stderr', io.StringIO()):
                d._run('o/r', items, {})
            self.assertEqual(self.records(), [])
        d = self.mod.Dispatcher('exit 0', 1, 0, 2)
        d.active = 1
        d._run('o/r', items, {})
        self.assertEqual([r['envelope'] for r in self.records()], [self.env, second])
        self.assertEqual([r['target'] for r in self.records()], ['dispatch', 'dispatch'])

    def test_generic_source_identity_is_preserved_for_future_adapters(self):
        generic = dict(self.env, source='slack', format='generic', key='T1/C1',
                       payload={'identifier': 'T1/C1/123.456', 'ts': '123.457', 'text': '\ud800'})
        self.mod.acknowledge_accepted(generic, 'dispatch')
        self.assertEqual(self.records(), [{'envelope': generic, 'target': 'dispatch'}])

    def test_hook_failure_and_timeout_do_not_retry_delivered_work(self):
        self.subscribe()
        for result in (OSError('missing'), subprocess.TimeoutExpired(self.cmd, 10)):
            with patch.object(self.mod.subprocess, 'run', side_effect=result), \
                    patch.object(sys, 'stderr', io.StringIO()) as err:
                self.assertEqual(self.mod.handle_event(self.env), 'delivered')
                self.assertIn('acknowledgment hook unavailable', err.getvalue())
        self.mod.ACK_CMD = ''
        self.assertEqual(self.mod.handle_event(self.env), 'delivered')
        self.assertEqual(self.records(), [])


class TestAcceptanceHookE2E(EndToEndCase):
    def test_signed_spawn_and_offline_owner_acknowledge_at_acceptance(self):
        cmd, log = recorder(self.state)
        # No owner or watch: receiving a signed event alone does not ack it.
        self.start_daemon(LOCAL_WEBHOOK_ACK_CMD=cmd)
        self.assertEqual(self.post(self.ISSUE), (200, 'ok'))
        self.assertFalse(os.path.exists(log))
        self.assertEqual(self.cli('subscribe', 'o/r', '--deliver-to', 'subagent',
                                 '--include', self.ANY_EVENT_JSON).returncode, 0)
        issue = dict(self.ISSUE, issue={'number': 6, 'title': 'spawn me'})
        self.assertEqual(self.post(issue), (200, 'ok'))
        self.assertTrue(self.wait_file(log, contains='dispatch'))
        with open(log) as f:
            self.assertEqual(len(f.readlines()), 1)
        # A subscribed but offline owner gets a durable inbox, not a reaction.
        self.cli('unsubscribe', 'o/r', '--deliver-to', 'subagent')
        self.cli('subscribe', 'o/r', '--include', self.ANY_EVENT_JSON, session='owner')
        issue = dict(self.ISSUE, issue={'number': 7, 'title': 'offline owner'})
        self.assertEqual(self.post(issue), (200, 'ok'))
        with open(log) as f:
            self.assertEqual(len(f.readlines()), 1)
        peer = self.start_peer('owner', LOCAL_WEBHOOK_ACK_CMD=cmd)
        peer.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n')
        peer.stdin.flush()
        self.read_peer_line(peer)
        peer.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        peer.stdin.flush()
        self.assertIn('offline owner', self.read_peer_line(peer)['params']['content'])
        self.assertTrue(self.wait_file(log, contains='"target":"owner"'))
