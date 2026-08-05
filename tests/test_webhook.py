# Tests for local-webhook/webhook.py — stdlib unittest only, mirroring the
# plugin's own constraint (stock python3 >= 3.9, no pip packages).
#
# Two layers:
#   - unit tests import webhook.py as a module (the __main__ guard added in
#     0.9.0 makes that safe) with LOCAL_WEBHOOK_* pointed at a throwaway state
#     dir, and exercise verification, topic matching, TTL/renewal, tool calls
#     and the dispatch batcher directly;
#   - end-to-end tests run webhook.py as real subprocesses (receiver daemon,
#     session peer, CLI) and drive the HTTP ingress with signed deliveries —
#     the same flow AGENTS.md prescribes for manual verification.
import http.client
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBHOOK_PY = os.path.join(REPO, 'local-webhook', 'webhook.py')
PYTHON = sys.executable or 'python3'

_module_seq = [0]


def load_webhook(env):
    """Import webhook.py under a controlled environment, as a unique module.

    RECEIVER_ONLY=1 keeps the import side-effect free (no IPC peer socket, no
    stdio loop — the main() guard means nothing serves either way).
    """
    _module_seq[0] += 1
    base = {
        'LOCAL_WEBHOOK_RECEIVER_ONLY': '1',
        'LOCAL_WEBHOOK_PORT': '0',
    }
    base.update(env)
    saved = {}
    for k in list(os.environ):
        if k.startswith('LOCAL_WEBHOOK_') or k in ('WEBHOOK_SECRET', 'WEBHOOK_PORT', 'LISTEN_FDS', 'LISTEN_PID'):
            saved[k] = os.environ.pop(k)
    os.environ.update(base)
    try:
        spec = importlib.util.spec_from_file_location('webhook_under_test_%d' % _module_seq[0], WEBHOOK_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k in base:
            os.environ.pop(k, None)
        os.environ.update(saved)


class StateDirCase(unittest.TestCase):
    """A fresh state dir + module instance per test."""

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix='webhook-test-')
        self.addCleanup(shutil.rmtree, self.state, True)
        self.mod = self.load()

    def load(self, **env):
        env.setdefault('LOCAL_WEBHOOK_STATE_DIR', self.state)
        env.setdefault('LOCAL_WEBHOOK_SESSION', 'testsess')
        return load_webhook(env)

    # -- helpers -------------------------------------------------------------
    def call(self, tool, **arguments):
        res = self.mod.call_tool({'name': tool, 'arguments': arguments})
        return '\n'.join(c['text'] for c in res['content'])

    def read_json(self, name):
        with open(os.path.join(self.state, name), encoding='utf-8') as f:
            return json.load(f)


class TestVerify(StateDirCase):
    BODY = b'{"a":1}'
    import hashlib as _h
    import hmac as _hm
    SIG = _hm.new(b'sekrit', BODY, _h.sha256).hexdigest()

    def test_valid_plain_and_prefixed(self):
        self.assertTrue(self.mod.verify('sekrit', self.SIG, self.BODY))
        self.assertTrue(self.mod.verify('sekrit', 'sha256=' + self.SIG, self.BODY))
        self.assertTrue(self.mod.verify('sekrit', 'SHA256=' + self.SIG, self.BODY))

    def test_rejects(self):
        self.assertFalse(self.mod.verify('sekrit', self.SIG, b'{"a":2}'))     # body tampered
        self.assertFalse(self.mod.verify('other', self.SIG, self.BODY))       # wrong secret
        self.assertFalse(self.mod.verify('sekrit', self.SIG[:-1] + 'X', self.BODY))  # not hex
        self.assertFalse(self.mod.verify('sekrit', self.SIG[:-2], self.BODY))  # wrong length
        self.assertFalse(self.mod.verify('sekrit', None, self.BODY))
        self.assertFalse(self.mod.verify('sekrit', '', self.BODY))


class TestMatchTopic(StateDirCase):
    def test_patterns(self):
        m = self.mod.match_topic
        self.assertTrue(m('github', 'o/r', '*'))
        self.assertTrue(m('github', 'o/r', 'github:*'))
        self.assertTrue(m('github', 'o/r', 'github:o/*'))
        self.assertTrue(m('github', 'o/r', 'github:o/r'))
        self.assertTrue(m('GitHub', 'O/R', 'github:o/r'))     # case-insensitive
        self.assertFalse(m('github', 'o/r', 'stripe:*'))
        self.assertFalse(m('github', 'other/r', 'github:o/*'))
        self.assertFalse(m('github', '', 'github:o/r'))       # keyless never exact-matches
        self.assertFalse(m('github', 'o/r', 'plainstring'))   # no colon → no match


class TestRouteEvent(StateDirCase):
    def entry(self, topic, **kw):
        e = {'topic': topic}
        e.update(kw)
        return e

    def write(self, topics, path=None, ttl=None):
        body = {'topics': topics}
        if ttl is not None:
            body['ttlHours'] = ttl
        with open(path or self.mod.FILTER_FILE, 'w', encoding='utf-8') as f:
            json.dump(body, f)

    def test_session_fails_open_dispatch_fails_closed(self):
        # No filter file at all.
        r = self.mod.route_event('github', 'o/r', 'x', 'issues')
        self.assertTrue(r['forward'])
        r = self.mod.route_event('github', 'o/r', 'x', 'issues',
                                 path=self.mod.DISPATCH_FILE, fail_open=False)
        self.assertFalse(r['forward'])
        # Corrupt file: same split.
        for p in (self.mod.FILTER_FILE, self.mod.DISPATCH_FILE):
            with open(p, 'w', encoding='utf-8') as f:
                f.write('{nope')
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues')['forward'])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                              path=self.mod.DISPATCH_FILE, fail_open=False)['forward'])

    def test_subscribed_topic_forwards_and_stamps(self):
        self.write([self.entry('github:o/*')])
        r = self.mod.route_event('github', 'o/r', 'x', 'issues')
        self.assertTrue(r['forward'])
        self.assertEqual(r['entry']['topic'], 'github:o/*')
        saved = self.read_json(os.path.basename(self.mod.FILTER_FILE))
        self.assertTrue(saved['topics'][0].get('lastActivityAt'))

    def test_unsubscribed_topic_filtered(self):
        self.write([self.entry('github:o/*')])
        self.assertFalse(self.mod.route_event('github', 'else/r', 'x', 'issues')['forward'])

    def test_disabled_mutes(self):
        with open(self.mod.FILTER_FILE, 'w', encoding='utf-8') as f:
            json.dump({'enabled': False, 'topics': ['*']}, f)
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues')['forward'])

    def test_expiry_prunes_but_pin_survives(self):
        old = self.mod.iso_at(self.mod.now_ms() - 3 * 3600e3)  # 3h ago, default ttl 1h
        self.write([self.entry('github:dead/*', subscribedAt=old),
                    self.entry('github:pinned/*', subscribedAt=old, ttlHours=0)])
        self.assertFalse(self.mod.route_event('github', 'dead/r', 'x', 'issues')['forward'])
        self.assertTrue(self.mod.route_event('github', 'pinned/r', 'x', 'issues')['forward'])
        left = [e['topic'] for e in self.read_json(os.path.basename(self.mod.FILTER_FILE))['topics']]
        self.assertEqual(left, ['github:pinned/*'])

    def test_warm_delivery_renews_cold_does_not(self):
        m = self.mod
        t0 = m.now_ms()
        warm = m.iso_at(t0 - 60e3)         # 1 min ago: inside the warm window
        cold = m.iso_at(t0 - 3600e3)       # 1h ago: cold
        sub = m.iso_at(t0 - 1800e3)        # subscribed 30 min ago
        self.write([self.entry('github:w/*', subscribedAt=sub, lastActivityAt=warm),
                    self.entry('github:c/*', subscribedAt=sub, lastActivityAt=cold)])
        m.route_event('github', 'w/r', 'x', 'issues')
        m.route_event('github', 'c/r', 'x', 'issues')
        saved = {e['topic']: e for e in self.read_json(os.path.basename(m.FILTER_FILE))['topics']}
        self.assertGreater(m.parse_ms(saved['github:w/*']['subscribedAt']), t0 - 1e3)  # renewed
        self.assertEqual(saved['github:c/*']['subscribedAt'], sub)                     # untouched

    def test_ignore_senders_with_ci_exemption(self):
        self.write([self.entry('github:o/*', ignoreSenders=['me'])])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'me', 'issues')['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'other', 'issues')['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'me', 'workflow_run')['forward'])

    def test_ci_exempt_false_applies_sender_ignore_to_ci_events(self):
        # The dispatch path passes ci_exempt=False for a non-failing CI event,
        # which is what stops a green build from spawning a session behind you.
        self.write([self.entry('github:o/*', ignoreSenders=['me'])])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'me', 'workflow_run',
                                              ci_exempt=False)['forward'])
        # ...while somebody else's green build is not an echo of anything.
        self.assertTrue(self.mod.route_event('github', 'o/r', 'other', 'workflow_run',
                                             ci_exempt=False)['forward'])


class TestCiOutcomeIsNews(StateDirCase):
    """Only a terminal, non-success CI outcome overrides ignoreSenders on the
    dispatch path — everything else is a lifecycle ping."""

    def news(self, event, payload):
        return self.mod.ci_outcome_is_news(event, payload)

    def run_payload(self, action, conclusion):
        p = {'action': action, 'workflow_run': {'name': 'CI', 'status': 'completed'}}
        if conclusion is not None:
            p['workflow_run']['conclusion'] = conclusion
        return p

    def test_failing_run_is_news(self):
        for concl in ('failure', 'timed_out', 'action_required', 'startup_failure', 'stale'):
            self.assertTrue(self.news('workflow_run', self.run_payload('completed', concl)), concl)

    def test_green_and_lifecycle_are_not(self):
        self.assertFalse(self.news('workflow_run', self.run_payload('completed', 'success')))
        self.assertFalse(self.news('workflow_run', self.run_payload('completed', 'skipped')))
        self.assertFalse(self.news('workflow_run', self.run_payload('completed', 'cancelled')))
        self.assertFalse(self.news('workflow_run', self.run_payload('requested', None)))
        self.assertFalse(self.news('workflow_run', self.run_payload('in_progress', None)))

    def test_check_run_and_suite(self):
        self.assertTrue(self.news('check_run', {'action': 'completed',
                                                'check_run': {'conclusion': 'failure'}}))
        self.assertFalse(self.news('check_run', {'action': 'created',
                                                 'check_run': {'conclusion': None}}))
        self.assertTrue(self.news('check_suite', {'action': 'completed',
                                                  'check_suite': {'conclusion': 'timed_out'}}))

    def test_status_and_deployment_status_use_state(self):
        self.assertTrue(self.news('status', {'state': 'failure'}))
        self.assertTrue(self.news('status', {'state': 'error'}))
        self.assertFalse(self.news('status', {'state': 'success'}))
        self.assertFalse(self.news('status', {'state': 'pending'}))
        self.assertTrue(self.news('deployment_status', {'deployment_status': {'state': 'failure'}}))
        self.assertFalse(self.news('deployment_status', {'deployment_status': {'state': 'success'}}))

    def test_unknown_shape_counts_as_news(self):
        # Never swallow a failure because GitHub moved a field.
        self.assertTrue(self.news('workflow_run', {'action': 'completed'}))
        self.assertTrue(self.news('workflow_run', {}))

    def test_non_ci_events_are_not_its_business(self):
        self.assertFalse(self.news('issues', {'action': 'opened'}))
        self.assertFalse(self.news('', {}))


class TestPeerScope(StateDirCase):
    """instances/<key>.<pid>.sock — the naming the ownership probe reads."""

    def test_own_socket_name_carries_the_filter_key(self):
        mod = self.load(LOCAL_WEBHOOK_SESSION='agent-main')
        self.assertEqual(os.path.basename(mod.IPC_SOCK), 'agent-main.%d.sock' % os.getpid())
        self.assertEqual(mod.peer_scope(os.path.basename(mod.IPC_SOCK)),
                         ('agent-main', os.getpid()))

    def test_parsing(self):
        p = self.mod.peer_scope
        self.assertEqual(p('agent-main.123.sock'), ('agent-main', 123))
        self.assertEqual(p('.123.sock'), ('', 123))          # unscoped -> filter.json
        self.assertEqual(p('lio.lunesu.5.sock'), ('lio.lunesu', 5))  # dots in the key
        self.assertIsNone(p('123.sock'))                     # pre-0.10.0 peer
        self.assertIsNone(p('agent-main.sock'))
        self.assertIsNone(p('agent-main.123'))

    def test_live_scopes_skip_dead_and_unscoped_peers(self):
        inst = os.path.join(self.state, 'instances')
        os.makedirs(inst, exist_ok=True)
        live = subprocess.Popen([PYTHON, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(lambda: (live.kill(), live.wait()))
        dead = subprocess.Popen([PYTHON, '-c', ''])
        dead.wait()
        for name in ('alive.%d.sock' % live.pid, 'gone.%d.sock' % dead.pid,
                     '%d.sock' % live.pid, 'junk'):
            open(os.path.join(inst, name), 'w').close()
        # A crashed peer's leftover socket must not claim ownership (it would
        # mute the watch); a legacy name carries no scope, so it claims nothing.
        self.assertEqual(self.mod.peer_scopes_live(), ['alive'])


class TestFilterClaims(StateDirCase):
    """The read-only probe: does some other session already own this event?"""

    def write(self, topics, name='filter.other.json', **body):
        body['topics'] = topics
        path = os.path.join(self.state, name)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(body, f)
        return path

    def test_matches_and_misses(self):
        path = self.write(['github:o/*'])
        self.assertTrue(self.mod.filter_claims(path, 'github', 'o/r', 'x', 'workflow_run'))
        self.assertFalse(self.mod.filter_claims(path, 'github', 'other/r', 'x', 'workflow_run'))

    def test_missing_or_disabled_claims_nothing(self):
        # Deliberately NOT fail-open: a yes here suppresses a spawn.
        self.assertFalse(self.mod.filter_claims(
            os.path.join(self.state, 'nope.json'), 'github', 'o/r', 'x', 'workflow_run'))
        path = self.write(['github:o/*'], enabled=False)
        self.assertFalse(self.mod.filter_claims(path, 'github', 'o/r', 'x', 'workflow_run'))

    def test_expired_entry_claims_nothing(self):
        old = self.mod.iso_at(self.mod.now_ms() - 5 * 3600e3)
        path = self.write([{'topic': 'github:o/r', 'subscribedAt': old}], ttlHours=1)
        self.assertFalse(self.mod.filter_claims(path, 'github', 'o/r', 'x', 'workflow_run'))

    def test_probe_writes_nothing(self):
        # Looking at a subscription must not renew it or prune its neighbours.
        old = self.mod.iso_at(self.mod.now_ms() - 5 * 3600e3)
        path = self.write([{'topic': 'github:o/r', 'ttlHours': 0, 'subscribedAt': old,
                            'lastActivityAt': old},
                           {'topic': 'github:dead/r', 'subscribedAt': old}], ttlHours=1)
        with open(path, encoding='utf-8') as f:
            before = f.read()
        self.assertTrue(self.mod.filter_claims(path, 'github', 'o/r', 'x', 'workflow_run'))
        with open(path, encoding='utf-8') as f:
            self.assertEqual(f.read(), before)


class TestCallTool(StateDirCase):
    def test_session_subscribe_defaults(self):
        out = self.call('webhook_subscribe', topic='o/r', note='why')
        self.assertIn('subscribed to github:o/r', out)
        saved = self.read_json('filter.testsess.json')
        self.assertEqual(saved['topics'][0]['topic'], 'github:o/r')
        self.assertNotIn('ttlHours', saved['topics'][0])  # inherits file default

    def test_dispatch_subscribe_defaults_to_pinned_shared_file(self):
        out = self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', note='watch')
        self.assertIn('dispatch', out)
        self.assertIn('pinned (never expires)', out)
        saved = self.read_json('filter.dispatch.json')
        self.assertEqual(saved['topics'][0]['ttlHours'], 0)
        # The session's own filter is untouched.
        self.assertFalse(os.path.exists(os.path.join(self.state, 'filter.testsess.json')))

    def test_dispatch_subscribe_explicit_ttl_wins(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', ttl_hours=8)
        self.assertEqual(self.read_json('filter.dispatch.json')['topics'][0]['ttlHours'], 8)

    def test_deliver_to_validation(self):
        out = self.call('webhook_subscribe', topic='o/r', deliver_to='nonsense')
        self.assertTrue(out.startswith('error: deliver_to'))

    def test_scopes_are_independent(self):
        self.call('webhook_subscribe', topic='o/r')
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        out = self.call('webhook_unsubscribe', topic='o/r', deliver_to='subagent')
        self.assertIn('unsubscribed from github:o/r [dispatch]', out)
        self.assertEqual(self.read_json('filter.dispatch.json')['topics'], [])
        self.assertEqual(self.read_json('filter.testsess.json')['topics'][0]['topic'], 'github:o/r')
        # ... and the session unsubscribe does not touch dispatch either.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.call('webhook_unsubscribe', topic='o/r')
        self.assertEqual(self.read_json('filter.dispatch.json')['topics'][0]['topic'], 'github:o/r')

    def test_subscriptions_lists_both_scopes(self):
        self.call('webhook_subscribe', topic='o/r', note='mine')
        self.call('webhook_subscribe', topic='p/q', deliver_to='subagent', note='watch')
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertEqual(body['topics'][0]['topic'], 'github:o/r')
        self.assertEqual(body['dispatch']['topics'][0]['topic'], 'github:p/q')
        self.assertEqual(body['dispatch']['topics'][0]['expiresIn'], 'never (pinned)')

    def test_subscriptions_warns_on_spawnless_receiver(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        with open(os.path.join(self.state, 'receiver.json'), 'w', encoding='utf-8') as f:
            json.dump({'pid': 1, 'version': '0.9.0', 'spawn': False}, f)
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertIn('inert', body['dispatch']['warning'])
        out = self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.assertIn('WARNING', out)

    def test_renew_keeps_scope_fields(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', note='first')
        out = self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.assertIn('renewed subscription', out)
        saved = self.read_json('filter.dispatch.json')
        self.assertEqual(saved['topics'][0]['note'], 'first')
        self.assertEqual(saved['topics'][0]['ttlHours'], 0)


class TestDispatchEvent(StateDirCase):
    """route → Dispatcher wiring, with the spawn command replaced by a recorder."""

    def env(self, **payload):
        p = {'repository': {'full_name': 'o/r'}, 'sender': {'login': 'x'}}
        p.update(payload)
        return {'source': 'github', 'format': 'github', 'event': 'issues',
                'key': 'o/r', 'sender': 'x', 'delivery': 'd1', 'payload': p}

    def test_no_dispatcher_is_inert(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.assertIsNone(self.mod.DISPATCHER)
        self.mod.dispatch_event(self.env())  # must not raise

    def test_match_reaches_spawn_command(self):
        out = os.path.join(self.state, 'spawned.txt')
        mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='cat > %s' % out,
                        LOCAL_WEBHOOK_STATE_DIR=self.state)
        self.mod = mod
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', note='ctx')
        mod.dispatch_event(self.env(action='opened', issue={'number': 7, 'title': 'boom'}))
        # Poll for CONTENT, not existence: the shell creates the redirect
        # target before `cat` has written anything.
        text = ''
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(out):
                with open(out, encoding='utf-8') as f:
                    text = f.read()
                if 'issue #7' in text:
                    break
            time.sleep(0.05)
        self.assertIn('[UNTRUSTED webhook:github', text)
        self.assertIn('issue #7 opened on o/r', text)
        self.assertIn('ctx', text)  # the note is echoed into the prompt

    def test_unmatched_event_spawns_nothing(self):
        out = os.path.join(self.state, 'spawned.txt')
        mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='cat > %s' % out,
                        LOCAL_WEBHOOK_STATE_DIR=self.state)
        self.mod = mod
        self.call('webhook_subscribe', topic='somewhere/else', deliver_to='subagent')
        env = self.env()
        mod.dispatch_event(env)
        time.sleep(0.3)
        self.assertFalse(os.path.exists(out))


class TestDispatchBrakes(StateDirCase):
    """A standing watch spawns for CI only on a failure (0.10.0, made
    sender-independent in 0.10.1), and never while a live session peer is
    already subscribed to the topic (0.10.0)."""

    def setUp(self):
        StateDirCase.setUp(self)
        self.out = os.path.join(self.state, 'spawned.txt')
        self.mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='cat > %s' % self.out)

    def env(self, event, payload, sender='me'):
        p = {'repository': {'full_name': 'o/r'}, 'sender': {'login': sender}}
        p.update(payload)
        return {'source': 'github', 'format': 'github', 'event': event,
                'key': 'o/r', 'sender': sender, 'delivery': 'd1', 'payload': p}

    def run_env(self, conclusion, action='completed', sender='me'):
        return self.env('workflow_run',
                        {'action': action,
                         'workflow_run': {'name': 'CI', 'status': action, 'conclusion': conclusion}},
                        sender=sender)

    def fake_live_peer(self, key, topics):
        """A running process with an instances/<key>.<pid>.sock and a filter."""
        inst = os.path.join(self.state, 'instances')
        os.makedirs(inst, exist_ok=True)
        p = subprocess.Popen([PYTHON, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(lambda: (p.kill(), p.wait()))
        open(os.path.join(inst, '%s.%d.sock' % (key, p.pid)), 'w').close()
        with open(os.path.join(self.state, 'filter.%s.json' % key), 'w', encoding='utf-8') as f:
            json.dump({'topics': topics}, f)

    def spawned(self, expect, needle=''):
        if not expect:
            # The redirect target appears the moment the spawn command runs, so
            # existence is the earliest and strictest negative signal — waiting
            # for CONTENT could pass while `cat` was merely slow to flush.
            time.sleep(1)
            self.assertFalse(os.path.exists(self.out), 'expected no spawn, got one')
            return
        deadline = time.time() + 10
        text = ''
        while time.time() < deadline:
            if os.path.exists(self.out):
                with open(self.out, encoding='utf-8') as f:
                    text = f.read()
                if needle in text and text:
                    break
            time.sleep(0.05)
        self.assertTrue(text, 'expected a spawn, got none')
        self.assertIn(needle, text)

    # -- brake 1: CI events spawn only on a failure --------------------------
    def test_failing_run_spawns(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  ignore_senders=['me'])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(True, 'workflow "CI"')

    def test_green_run_from_ignored_sender_does_not_spawn(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  ignore_senders=['me'])
        self.mod.dispatch_event(self.run_env('success'))
        self.spawned(False)

    def test_lifecycle_ping_from_ignored_sender_does_not_spawn(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  ignore_senders=['me'])
        self.mod.dispatch_event(self.run_env(None, action='requested'))
        self.spawned(False)

    def test_green_run_from_an_unignored_sender_does_not_spawn(self):
        # 0.10.1 reversal: through 0.10.0 the outcome only decided whether a CI
        # event could override ignoreSenders, so a green run from a sender the
        # watch did not name spawned a session — and a watch on a repo whose
        # humans push under their own logins names nobody. The sender was never
        # the question: no green build is worth an agent, whoever triggered it.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  ignore_senders=['me'])
        self.mod.dispatch_event(self.run_env('success', sender='someone'))
        self.spawned(False)

    def test_green_run_spawns_nothing_with_no_ignore_list_at_all(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.run_env('success', sender='someone'))
        self.spawned(False)

    def test_cancelled_and_lifecycle_from_an_unignored_sender_do_not_spawn(self):
        # One merge emits a supersede-cancelled run and several lifecycle pings;
        # a cancelled run is not a failure — its successor reports the verdict.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.run_env('cancelled', sender='someone'))
        self.spawned(False)
        self.mod.dispatch_event(self.run_env(None, action='in_progress', sender='someone'))
        self.spawned(False)

    def test_green_check_run_from_an_unignored_sender_does_not_spawn(self):
        # The exact shape that spawned a session on this box: a merge to master
        # fanned out check_run.completed/success per job.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.env('check_run', {
            'action': 'completed',
            'check_run': {'name': 'build', 'status': 'completed', 'conclusion': 'success'},
        }, sender='someone'))
        self.spawned(False)

    def test_failing_run_from_an_unignored_sender_spawns(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.run_env('failure', sender='someone'))
        self.spawned(True, 'workflow "CI"')

    # -- brake 2: a live session that owns the topic suppresses the spawn ----
    def test_ci_event_suppressed_while_a_live_session_is_subscribed(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', ['github:o/*'])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(False)

    def test_ci_event_spawns_when_the_subscribed_session_is_elsewhere(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', ['github:other/*'])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(True, 'workflow "CI"')

    def test_non_ci_event_spawns_even_when_a_session_owns_the_repo(self):
        # Ownership is object-granular, topics are repo-granular: a session
        # working one PR must not silence new work in the same repo.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', ['github:o/*'])
        self.mod.dispatch_event(self.env('issues', {'action': 'opened',
                                                    'issue': {'number': 9, 'title': 't'}}))
        self.spawned(True, 'issue #9 opened')

    def test_expired_session_subscription_does_not_suppress(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        old = self.mod.iso_at(self.mod.now_ms() - 5 * 3600e3)
        self.fake_live_peer('peer1', [{'topic': 'github:o/*', 'subscribedAt': old}])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(True, 'workflow "CI"')


class TestDispatcher(StateDirCase):
    """Fork-bomb control: immediate first spawn, coalescing, cap, failure."""

    def recorder(self, marker, sleep=0):
        # Each run appends one line: <marker> <count> then the batch lines.
        path = os.path.join(self.state, marker + '.log')
        cmd = ('{ echo "RUN count=$LOCAL_WEBHOOK_SPAWN_COUNT key=$LOCAL_WEBHOOK_SPAWN_KEY"; cat; } >> %s'
               % path)
        if sleep:
            cmd += '; sleep %s' % sleep
        return path, cmd

    def runs(self, path):
        if not os.path.exists(path):
            return []
        with open(path, encoding='utf-8') as f:
            return [ln for ln in f.read().splitlines() if ln.startswith('RUN ')]

    def wait_for(self, cond, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_first_event_spawns_immediately(self):
        path, cmd = self.recorder('imm')
        d = self.mod.Dispatcher(cmd, 2, 60, 30)
        d.add('k', 'hello', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        self.assertIn('count=1', self.runs(path)[0])

    def test_burst_coalesces_into_one_followup(self):
        path, cmd = self.recorder('burst', sleep=1)
        d = self.mod.Dispatcher(cmd, 2, 0, 30)  # window 0: follow-up gated only by the running spawn
        d.add('k', 'e1', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        for t in ('e2', 'e3', 'e4'):
            d.add('k', t, {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 2))
        time.sleep(1.5)  # no third spawn appears afterwards
        runs = self.runs(path)
        self.assertEqual(len(runs), 2)
        self.assertIn('count=3', runs[1])

    def test_window_defers_followup(self):
        path, cmd = self.recorder('win')
        d = self.mod.Dispatcher(cmd, 2, 2, 30)  # 2s rate window per key
        d.add('k', 'e1', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        d.add('k', 'e2', {'key': 'k'})
        time.sleep(0.5)
        self.assertEqual(len(self.runs(path)), 1)  # still inside the window
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 2, timeout=10))

    def test_concurrency_cap_across_keys(self):
        path_a, cmd_a = self.recorder('cap-a', sleep=1)
        d = self.mod.Dispatcher(cmd_a, 1, 0, 30)  # max 1 concurrent spawn
        d.add('a', 'e1', {'key': 'a'})
        d.add('b', 'e2', {'key': 'b'})
        # Both eventually run — through the same single slot.
        self.assertTrue(self.wait_for(lambda: len(self.runs(path_a)) == 2, timeout=15))
        keys = ' '.join(self.runs(path_a))
        self.assertIn('key=a', keys)
        self.assertIn('key=b', keys)

    def test_failing_spawn_drops_batch_but_recovers(self):
        path, ok_cmd = self.recorder('rec')
        d = self.mod.Dispatcher('exit 3', 2, 0, 30)
        d.add('k', 'lost', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: d.active == 0))
        d.cmd = ok_cmd  # spawner fixed; the next event must still dispatch
        d.add('k', 'found', {'key': 'k'})

        def batch_arrived():
            if not os.path.exists(path):
                return False
            with open(path, encoding='utf-8') as f:
                return 'found' in f.read()
        self.assertTrue(self.wait_for(batch_arrived))


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        http.client.HTTPConnection.__init__(self, 'local')
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(10)
        s.connect(self._path)
        self.sock = s


class TestEndToEnd(unittest.TestCase):
    """Real processes: receiver daemon + session peer + CLI, signed deliveries."""

    SECRET = 'shh'

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix='webhook-e2e-')
        self.addCleanup(shutil.rmtree, self.state, True)
        with open(os.path.join(self.state, 'github.secret'), 'w', encoding='utf-8') as f:
            f.write(self.SECRET)
        with open(os.path.join(self.state, 'sources.json'), 'w', encoding='utf-8') as f:
            json.dump({'defaultSource': 'github',
                       'sources': {'github': {'secretFile': 'github.secret'}}}, f)
        self.http_sock = os.path.join(self.state, 'in.sock')
        self.spawn_log = os.path.join(self.state, 'spawn.log')
        self.procs = []
        self.addCleanup(self.kill_all)

    def kill_all(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
            for f in (p.stdin, p.stdout, p.stderr):
                if f:
                    f.close()

    def base_env(self, **extra):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith('LOCAL_WEBHOOK_') and k not in ('WEBHOOK_SECRET', 'WEBHOOK_PORT',
                                                                   'LISTEN_FDS', 'LISTEN_PID')}
        env['LOCAL_WEBHOOK_STATE_DIR'] = self.state
        env.update(extra)
        return env

    def start_daemon(self, **extra):
        env = self.base_env(
            LOCAL_WEBHOOK_RECEIVER_ONLY='1',
            LOCAL_WEBHOOK_HTTP_SOCK=self.http_sock,
            LOCAL_WEBHOOK_SPAWN_CMD='cat >> %s' % self.spawn_log,
            **extra
        )
        p = subprocess.Popen([PYTHON, WEBHOOK_PY], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(p)
        deadline = time.time() + 15
        while not os.path.exists(self.http_sock) and time.time() < deadline:
            if p.poll() is not None:  # only read stderr once it is closed
                self.fail('daemon died: %s' % p.stderr.read().decode())
            time.sleep(0.05)
        self.assertTrue(os.path.exists(self.http_sock), 'daemon never bound its socket')
        return p

    def start_peer(self, session):
        env = self.base_env(LOCAL_WEBHOOK_SESSION=session, LOCAL_WEBHOOK_PORT='0')
        p = subprocess.Popen([PYTHON, WEBHOOK_PY], env=env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(p)
        inst = os.path.join(self.state, 'instances')
        deadline = time.time() + 15
        while time.time() < deadline:
            socks = [f for f in (os.listdir(inst) if os.path.isdir(inst) else [])
                     if f == '%s.%d.sock' % (session, p.pid)]
            if socks:
                return p
            time.sleep(0.05)
        self.fail('peer never registered its IPC socket')

    def cli(self, *args, session='testsess'):
        env = self.base_env(LOCAL_WEBHOOK_SESSION=session, LOCAL_WEBHOOK_PORT='0')
        return subprocess.run([PYTHON, WEBHOOK_PY] + list(args), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def post(self, body, event='issues', source='github', sig=None, method='POST'):
        import hashlib
        import hmac as hmac_mod
        raw = json.dumps(body).encode('utf-8') if isinstance(body, dict) else body
        if sig is None:
            sig = 'sha256=' + hmac_mod.new(self.SECRET.encode(), raw, hashlib.sha256).hexdigest()
        conn = UnixHTTPConnection(self.http_sock)
        headers = {'content-type': 'application/json', 'x-github-event': event,
                   'x-github-delivery': 'test-%f' % time.time()}
        if sig != '':
            headers['x-hub-signature-256'] = sig
        conn.request(method, '/' + source, raw, headers)
        resp = conn.getresponse()
        out = (resp.status, resp.read().decode())
        conn.close()
        return out

    ISSUE = {'repository': {'full_name': 'o/r'}, 'sender': {'login': 'someone'},
             'action': 'opened', 'issue': {'number': 5, 'title': 'title here',
                                           'html_url': 'https://x/5'}}

    def wait_file(self, path, timeout=15, contains=None):
        # With contains, wait for CONTENT: a shell redirect creates the file
        # before the command writes, so bare existence races the writer.
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(path):
                if contains is None:
                    return True
                with open(path, encoding='utf-8') as f:
                    if contains in f.read():
                        return True
            time.sleep(0.05)
        return False

    def test_http_status_codes(self):
        self.start_daemon()
        self.assertEqual(self.post(self.ISSUE)[0], 200)
        self.assertEqual(self.post(self.ISSUE, sig='sha256=' + '0' * 64)[0], 401)
        self.assertEqual(self.post(self.ISSUE, sig='')[0], 401)
        self.assertEqual(self.post(self.ISSUE, source='stripe')[0], 404)
        self.assertEqual(self.post(b'not json')[0], 400)
        self.assertEqual(self.post(self.ISSUE, method='GET')[0], 405)

    def test_receiver_advertisement(self):
        self.start_daemon()
        self.assertTrue(self.wait_file(os.path.join(self.state, 'receiver.json'), contains='}'))
        with open(os.path.join(self.state, 'receiver.json'), encoding='utf-8') as f:
            info = json.load(f)
        self.assertTrue(info['spawn'])
        self.assertTrue(info['version'])

    def test_dispatch_spawns_and_peer_fanout_and_isolation(self):
        # Standing watch via CLI (what a session's tool call writes).
        r = self.cli('subscribe', 'o/r', '--deliver-to', 'subagent', '--note', 'standing watch')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b'pinned', r.stdout)
        # A session peer subscribed to a DIFFERENT repo.
        r = self.cli('subscribe', 'peer/only', '--note', 'peer work', session='peersess')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.start_daemon()
        peer = self.start_peer('peersess')

        # Event on the watched repo: spawn fires, peer stays silent.
        self.assertEqual(self.post(self.ISSUE)[0], 200)
        self.assertTrue(self.wait_file(self.spawn_log, contains='issue #5'),
                        'spawn command never ran (or wrote nothing)')
        with open(self.spawn_log, encoding='utf-8') as f:
            text = f.read()
        self.assertIn('[UNTRUSTED webhook:github', text)
        self.assertIn('issue #5 opened on o/r', text)
        self.assertIn('standing watch', text)

        # Event on the peer's repo: channel notification, and no extra spawn.
        peer_evt = {'repository': {'full_name': 'peer/only'}, 'sender': {'login': 'x'},
                    'action': 'opened', 'issue': {'number': 1, 'title': 't'}}
        self.assertEqual(self.post(peer_evt)[0], 200)
        line = [None]

        def read_line():
            line[0] = peer.stdout.readline()
        t = threading.Thread(target=read_line)
        t.daemon = True
        t.start()
        t.join(15)
        self.assertTrue(line[0], 'peer never emitted a channel message')
        msg = json.loads(line[0].decode())
        self.assertEqual(msg['method'], 'notifications/claude/channel')
        self.assertIn('peer/only', msg['params']['content'])
        self.assertIn('peer work', msg['params']['content'])
        # The dispatch spawn stayed a single run (the peer event must not add one).
        time.sleep(1)
        with open(self.spawn_log, encoding='utf-8') as f:
            self.assertNotIn('peer/only', f.read())

    def run_payload(self, conclusion, sender='someone', action='completed'):
        return {'repository': {'full_name': 'o/r'}, 'sender': {'login': sender},
                'action': action,
                'workflow_run': {'name': 'CI', 'status': action, 'conclusion': conclusion,
                                 'head_branch': 'main', 'html_url': 'https://x/run/1'}}

    def test_dispatch_ci_brakes_end_to_end(self):
        """Real signed deliveries: a standing watch must not spawn for a green
        run — from an ignored sender or any other (0.10.1) — nor for a failure a
        live session is already subscribed to, but must spawn once it is gone."""
        r = self.cli('subscribe', 'o/r', '--deliver-to', 'subagent',
                     '--ignore-sender', 'someone', '--note', 'standing watch')
        self.assertEqual(r.returncode, 0, r.stderr)
        # The session that OWNS this repo's work right now.
        r = self.cli('subscribe', 'o/r', '--note', 'driving PR 1', session='ownersess')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.start_daemon()

        # Brake 1, the 0.10.1 half: a green run from a sender the watch does NOT
        # ignore. No peer is live yet, so the outcome is the only thing that can
        # be suppressing this spawn.
        self.assertEqual(self.post(self.run_payload('success', sender='outsider'),
                                   event='workflow_run')[0], 200)
        time.sleep(1)
        self.assertFalse(os.path.exists(self.spawn_log),
                         'green run from an unignored sender spawned a session')

        peer = self.start_peer('ownersess')

        # Brake 1: green run from the ignored sender — nothing to spawn for.
        self.assertEqual(self.post(self.run_payload('success'), event='workflow_run')[0], 200)
        time.sleep(1)
        self.assertFalse(os.path.exists(self.spawn_log), 'green run spawned a session')

        # Brake 2: a real FAILURE, but the owning session is live and subscribed,
        # so it is already getting this delivery — still no spawn.
        self.assertEqual(self.post(self.run_payload('failure'), event='workflow_run')[0], 200)
        time.sleep(1)
        self.assertFalse(os.path.exists(self.spawn_log),
                         'spawned while a live session owned the topic')
        # ...and it really did reach that session.
        line = [None]

        def read_line():
            line[0] = peer.stdout.readline()
        t = threading.Thread(target=read_line)
        t.daemon = True
        t.start()
        t.join(15)
        self.assertTrue(line[0], 'owning session never got the CI event')
        self.assertIn('workflow "CI"', json.loads(line[0].decode())['params']['content'])

        # Session gone: nobody owns the repo, so the watch takes over. The
        # stale socket is still on disk — liveness is the pid, not the file.
        peer.kill()
        peer.wait()
        self.assertEqual(self.post(self.run_payload('failure'), event='workflow_run')[0], 200)
        self.assertTrue(self.wait_file(self.spawn_log, contains='workflow "CI"'),
                        'no spawn once the owning session was gone')

    def test_dispatch_inert_without_spawn_cmd(self):
        self.cli('subscribe', 'o/r', '--deliver-to', 'subagent')
        env = self.base_env(LOCAL_WEBHOOK_RECEIVER_ONLY='1', LOCAL_WEBHOOK_HTTP_SOCK=self.http_sock)
        p = subprocess.Popen([PYTHON, WEBHOOK_PY], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(p)
        deadline = time.time() + 15
        while not os.path.exists(self.http_sock) and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.post(self.ISSUE)[0], 200)
        time.sleep(0.5)
        self.assertFalse(os.path.exists(self.spawn_log))
        with open(os.path.join(self.state, 'receiver.json'), encoding='utf-8') as f:
            self.assertFalse(json.load(f)['spawn'])

    def test_cli_exit_codes(self):
        self.assertEqual(self.cli('bogus-command').returncode, 2)
        self.assertEqual(self.cli('subscribe').returncode, 2)               # missing topic
        self.assertEqual(self.cli('subscribe', ':::').returncode, 1)        # in-band error
        self.assertEqual(self.cli('subscribe', 'o/r', '--deliver-to', 'nope').returncode, 2)
        self.assertEqual(self.cli('subscribe', 'o/r', '--ttl', '-1').returncode, 2)
        self.assertEqual(self.cli('ls').returncode, 0)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_cli_status_shape(self):
        self.cli('subscribe', 'o/r', '--deliver-to', 'subagent')
        r = self.cli('status')
        body = json.loads(r.stdout.decode())
        self.assertEqual(body['dispatchTopicCount'], 1)
        self.assertEqual(body['topicCount'], 0)
        self.assertTrue(body['sources']['github']['hasSecret'])


class TestVersionConsistency(unittest.TestCase):
    """The release invariants AGENTS.md states, enforced."""

    def read(self, *parts):
        with open(os.path.join(REPO, *parts), encoding='utf-8') as f:
            return f.read()

    def test_versions_and_descriptions_in_lockstep(self):
        version = re.search(r"^VERSION = '([^']+)'", self.read('local-webhook', 'webhook.py'),
                            re.M).group(1)
        plugin = json.loads(self.read('local-webhook', '.claude-plugin', 'plugin.json'))
        market = json.loads(self.read('.claude-plugin', 'marketplace.json'))
        self.assertEqual(plugin['version'], version)
        entry = [p for p in market['plugins'] if p['name'] == plugin['name']][0]
        self.assertEqual(entry['description'], plugin['description'])
        self.assertEqual(entry.get('keywords'), plugin.get('keywords'))
        # Both READMEs' version tables mention the current version.
        self.assertIn(version, self.read('README.md'))


if __name__ == '__main__':
    unittest.main()
