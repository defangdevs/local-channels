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
import io
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
        self.assertTrue(m('github', 'o/r', 'github:o/*'))
        self.assertTrue(m('github', 'o/r', 'github:o/r'))
        self.assertTrue(m('GitHub', 'O/R', 'github:o/r'))     # case-insensitive
        self.assertFalse(m('github', 'other/r', 'github:o/*'))
        self.assertFalse(m('github', '', 'github:o/r'))       # keyless never exact-matches
        self.assertFalse(m('github', 'o/r', 'plainstring'))   # no colon → no match

    def test_wildcards_removed(self):
        """0.13.0: "everything" is unexpressible. Both forms match nothing,
        wherever they came from — a hand-edited file or a 0.12.x filter that
        survived the upgrade."""
        m = self.mod.match_topic
        self.assertFalse(m('github', 'o/r', '*'))
        self.assertFalse(m('github', 'o/r', 'github:*'))
        self.assertFalse(m('stripe', 'ch_1', 'stripe:*'))
        # The prefix form is NOT a wildcard in this sense and stays legal: the
        # star is inside the key, so it still names one source and one owner.
        self.assertTrue(m('github', 'o/r', 'github:o/*'))

    def test_invalid_topics_are_reported_not_guessed(self):
        """Consumers must not re-derive the grammar to spot a dead row: the
        same string is legal on a 0.12.x daemon, so only the daemon serving it
        knows. (defangdevs/agent-box#227)"""
        why = self.mod.topic_invalid_reason
        self.assertEqual(why('github:o/r'), '')
        self.assertEqual(why('github:o/*'), '')
        self.assertIn('removed in 0.13.0', why('*'))
        self.assertIn('removed in 0.13.0', why('github:*'))
        self.assertIn('not a valid topic pattern', why('plainstring'))


class TestPredicates(StateDirCase):
    """The when/drop payload predicate language (0.11.0): any/all over
    {path, in/notIn} leaves plus {path, contains/notContains} substring leaves
    (0.14.0), evaluated with get_path."""

    P = {'action': 'opened', 'sender': {'login': 'bot'},
         'workflow_run': {'conclusion': 'failure'}, 'draft': False, 'number': 5,
         'comment': {'body': 'please @DefangDevs rebase this'}}

    def m(self, pred, payload=None):
        return self.mod.match_predicate(pred, self.P if payload is None else payload)

    def test_leaf_in_and_notin(self):
        self.assertTrue(self.m({'path': 'action', 'in': ['opened', 'reopened']}))
        self.assertFalse(self.m({'path': 'action', 'in': ['closed']}))
        self.assertFalse(self.m({'path': 'action', 'notIn': ['opened']}))
        self.assertTrue(self.m({'path': 'sender.login', 'notIn': ['human']}))

    def test_nested_path_and_absent_path(self):
        self.assertTrue(self.m({'path': 'workflow_run.conclusion', 'in': ['failure']}))
        # An absent path is None; null in the list matches it, nothing else does.
        self.assertFalse(self.m({'path': 'no.such.path', 'in': ['failure']}))
        self.assertTrue(self.m({'path': 'no.such.path', 'in': [None]}))
        # ...and notIn on an absent path matches (fails toward delivering).
        self.assertTrue(self.m({'path': 'no.such.path', 'notIn': ['x']}))

    def test_any_all_compose(self):
        self.assertTrue(self.m({'any': [{'path': 'action', 'in': ['closed']},
                                        {'path': 'workflow_run.conclusion', 'in': ['failure']}]}))
        self.assertFalse(self.m({'all': [{'path': 'action', 'in': ['opened']},
                                         {'path': 'sender.login', 'notIn': ['bot']}]}))
        self.assertTrue(self.m({'all': []}))   # vacuous
        self.assertFalse(self.m({'any': []}))

    def test_json_booleans_are_not_numbers(self):
        self.assertTrue(self.m({'path': 'draft', 'in': [False]}))
        self.assertFalse(self.m({'path': 'draft', 'in': [0]}))
        self.assertTrue(self.m({'path': 'number', 'in': [5]}))
        self.assertFalse(self.m({'path': 'number', 'in': [True]}))

    def test_leaf_contains_and_notcontains(self):
        # The case the operator exists for: a mention no whole-value list can
        # name, matched case-insensitively because GitHub logins are.
        self.assertTrue(self.m({'path': 'comment.body', 'contains': ['@defangdevs']}))
        self.assertTrue(self.m({'path': 'comment.body', 'contains': ['nope', 'rebase']}))
        self.assertFalse(self.m({'path': 'comment.body', 'contains': ['@someoneelse']}))
        self.assertFalse(self.m({'path': 'comment.body', 'notContains': ['@DEFANGDEVS']}))
        self.assertTrue(self.m({'path': 'comment.body', 'notContains': ['@someoneelse']}))

    def test_contains_needs_a_string_value(self):
        # A non-string contains nothing, so an absent path or a number fails
        # `contains` and passes `notContains` — the direction notIn takes too.
        self.assertFalse(self.m({'path': 'no.such.path', 'contains': ['x']}))
        self.assertTrue(self.m({'path': 'no.such.path', 'notContains': ['x']}))
        self.assertFalse(self.m({'path': 'number', 'contains': ['5']}))
        self.assertFalse(self.m({'path': 'draft', 'contains': ['false']}))

    def test_contains_composes_into_a_mention_rule(self):
        mention = {'all': [{'path': 'action', 'in': ['opened']},
                           {'path': 'sender.login', 'notIn': ['defangdevs']},
                           {'path': 'comment.body', 'contains': ['@defangdevs']}]}
        self.assertTrue(self.m(mention))
        # Same comment, posted by the box itself: the sender clause is what
        # stops a watch from answering its own echo forever.
        echo = dict(self.P, sender={'login': 'defangdevs'})
        self.assertFalse(self.m(mention, echo))

    def test_malformed_nodes_match_nothing(self):
        for bad in ('nope', {'path': 'action'}, {'path': 'action', 'in': 'opened'},
                    {'path': 'action', 'in': ['a'], 'notIn': ['b']}, {'any': 'x'}, {}, None,
                    # exactly one operator per leaf, and never an empty
                    # substring — that one is in every string.
                    {'path': 'action', 'in': ['a'], 'contains': ['b']},
                    {'path': 'comment.body', 'contains': 'rebase'}):
            self.assertFalse(self.m(bad), 'matched malformed node %r' % (bad,))
        # ...including nested inside a well-formed combinator.
        self.assertFalse(self.m({'any': [{'path': 'action'}]}))

    def test_predicate_error_mirrors_the_evaluator(self):
        ok = self.mod.predicate_error
        self.assertIsNone(ok({'path': 'a.b', 'in': ['x', 1, True, None]}))
        self.assertIsNone(ok({'any': [{'all': [{'path': 'a', 'notIn': []}]}]}))
        self.assertIsNone(ok({'path': 'comment.body', 'contains': ['@bot']}))
        self.assertIsNone(ok({'path': 'comment.body', 'notContains': ['@bot', 'wip']}))
        for bad in ('nope', {}, {'path': 'a'}, {'path': 'a', 'in': 'x'},
                    {'path': 'a', 'in': ['x'], 'notIn': ['y']}, {'any': 'x'},
                    {'any': [{'path': ''}]}, {'path': 'a', 'in': [{'nested': 1}]},
                    {'path': 'a', 'contains': 'x'}, {'path': 'a', 'contains': ['']},
                    {'path': 'a', 'contains': [1]}, {'path': 'a', 'contains': [None]},
                    {'path': 'a', 'in': ['x'], 'notContains': ['y']}):
            self.assertIsNotNone(ok(bad), 'accepted malformed predicate %r' % (bad,))


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

    def test_nothing_fails_open(self):
        """0.13.0: a session receives what it subscribed to and nothing else.
        Before it, a missing filter forwarded the whole bus -- and since most
        sessions never subscribe, most sessions got it."""
        # No filter file at all: the common case, a session that never subscribed.
        for path in (self.mod.FILTER_FILE, self.mod.DISPATCH_FILE):
            r = self.mod.route_event('github', 'o/r', 'x', 'issues', path=path)
            self.assertFalse(r['forward'])
        # Present but unparseable: a botched edit no longer buys the firehose.
        for p in (self.mod.FILTER_FILE, self.mod.DISPATCH_FILE):
            with open(p, 'w', encoding='utf-8') as f:
                f.write('{nope')
            self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues', path=p)['forward'])

    def test_absent_and_invalid_stay_distinguishable(self):
        """Both route nothing, but one is a starting state and the other an
        error. read_filter keeps them apart so subscriptions can say which."""
        self.assertEqual(self.mod.read_filter(self.mod.FILTER_FILE)['state'], 'absent')
        with open(self.mod.FILTER_FILE, 'w', encoding='utf-8') as f:
            f.write('{nope')
        self.assertEqual(self.mod.read_filter(self.mod.FILTER_FILE)['state'], 'invalid')
        self.write([])
        self.assertEqual(self.mod.read_filter(self.mod.FILTER_FILE)['state'], 'ok')

    def test_keyless_payloads_reach_nobody(self):
        """The third implicit "everything": a keyless payload used to reach
        anyone subscribed to anything from that source. For a source wired
        without a keyPath that promoted one subscription into all of them."""
        self.write([self.entry('github:o/r')])
        self.assertFalse(self.mod.route_event('github', '', 'x', 'ping')['forward'])
        # ...and no session can claim one for dispatch either, or a keyless
        # event would suppress its own spawn on behalf of a session that will
        # never see it.
        self.assertFalse(self.mod.filter_claims(self.mod.FILTER_FILE, 'github', '', 'x', 'ping'))

    def test_surviving_wildcard_entry_is_kept_and_inert(self):
        """An upgraded box keeps a 0.12.x wildcard as a visible dead row: it
        matches nothing, and the other topics in the file still work."""
        self.write([self.entry('github:*'), self.entry('github:o/r')])
        self.assertFalse(self.mod.route_event('github', 'other/repo', 'x', 'issues')['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues')['forward'])

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

    # -- when/drop payload predicates (0.11.0) -------------------------------
    def test_when_accepts_only_matching_payloads(self):
        self.write([self.entry('github:o/*', when={'path': 'action', 'in': ['opened']})])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                             {'action': 'opened'})['forward'])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                              {'action': 'closed'})['forward'])

    def test_drop_wins_over_when(self):
        self.write([self.entry('github:o/*',
                               when={'path': 'action', 'in': ['opened', 'closed']},
                               drop={'path': 'action', 'in': ['closed']})])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                             {'action': 'opened'})['forward'])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                              {'action': 'closed'})['forward'])

    def test_predicate_can_address_the_event_type(self):
        # Prerequisite for #294's default noise-exclude: most GitHub payloads
        # carry no field of their own named "event" (it's the X-GitHub-Event
        # header, passed separately), so entry_forwards must merge it in for
        # a predicate to see it at all.
        self.write([self.entry('github:o/*', exclude={'path': 'event', 'in': ['star', 'watch']})])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'star', {})['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues', {'action': 'opened'})['forward'])

    def test_event_setdefault_never_clobbers_a_real_payload_field(self):
        # workflow_run.event is a REAL, different field (what triggered the
        # run, e.g. "schedule") that already lived inside the payload before
        # #294; merging in the X-GitHub-Event name must not touch it.
        self.write([self.entry('github:o/*',
                               exclude={'path': 'workflow_run.event', 'in': ['schedule']})])
        payload = {'workflow_run': {'event': 'schedule'}}
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'workflow_run', payload)['forward'])

    def test_declarative_entry_loses_the_ci_sender_exemption(self):
        # The carve-out ("CI overrides a mute") is welded to ignoreSenders for
        # legacy entries; a predicate entry writes its own policy, so the mute
        # becomes a pure sender mute — even for a CI event.
        self.write([self.entry('github:o/*', ignoreSenders=['me'],
                               when={'path': 'action', 'in': ['completed']})])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'me', 'workflow_run',
                                              {'action': 'completed'})['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'other', 'workflow_run',
                                             {'action': 'completed'})['forward'])

    def test_sender_rules_expressed_positionally(self):
        # "Their opens, not their close buttons" — the trade ignoreSenders
        # could not express without muting the person outright.
        self.write([self.entry('github:o/*', when={'all': [
            {'path': 'action', 'in': ['opened']},
            {'path': 'sender.login', 'notIn': ['box']}]})])
        opened = {'action': 'opened', 'sender': {'login': 'human'}}
        echo = {'action': 'opened', 'sender': {'login': 'box'}}
        closed = {'action': 'closed', 'sender': {'login': 'human'}}
        self.assertTrue(self.mod.route_event('github', 'o/r', 'human', 'issues', opened)['forward'])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'box', 'issues', echo)['forward'])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'human', 'issues', closed)['forward'])

    def test_malformed_when_mutes_rather_than_floods(self):
        # A typo'd hand-edited predicate matches nothing: for `when` the entry
        # goes quiet (and stderr says so) instead of forwarding everything.
        self.write([self.entry('github:o/*', when={'oops': True})])
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                              {'action': 'opened'})['forward'])

    def test_most_permissive_entry_still_wins(self):
        # Predicates are per-entry; a sibling entry without them forwards as ever.
        self.write([self.entry('github:o/*', when={'path': 'action', 'in': ['opened']}),
                    self.entry('github:o/r')])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues',
                                             {'action': 'closed'})['forward'])

    def test_refused_distinguishes_declined_from_unsubscribed(self):
        # 'refused' is what lets dispatch log a deliberate drop (agent-box#170)
        # without narrating deliveries for repos nobody watches.
        self.write([self.entry('github:o/*', when={'path': 'action', 'in': ['opened']})])
        r = self.mod.route_event('github', 'o/r', 'x', 'issues', {'action': 'closed'})
        self.assertFalse(r['forward'])
        self.assertTrue(r['refused'])
        r = self.mod.route_event('github', 'else/r', 'x', 'issues', {'action': 'closed'})
        self.assertFalse(r['forward'])
        self.assertFalse(r['refused'])
        r = self.mod.route_event('github', 'o/r', 'x', 'issues', {'action': 'opened'})
        self.assertTrue(r['forward'])
        self.assertFalse(r['refused'])


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

    def test_subscriptions_reports_why_the_list_is_empty(self):
        # All three empty states now route the same (nothing), so the list is
        # no longer misleading on its own -- 0.12.1's failOpen field went with
        # the behaviour it warned about. What still differs is whether the
        # emptiness is an ordinary starting state or an error.
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertEqual(body['topics'], [])
        self.assertNotIn('failOpen', body)
        self.assertEqual(body['filterState'], 'absent')
        self.assertIn('receives nothing until it subscribes', body['warning'])
        # An explicit empty list means the same thing, and needs no warning.
        self.call('webhook_subscribe', topic='o/r')
        self.call('webhook_unsubscribe', topic='o/r')
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertEqual(body['topics'], [])
        self.assertEqual(body['filterState'], 'ok')
        self.assertNotIn('warning', body)
        # A botched edit is the one worth shouting about.
        with open(self.mod.FILTER_FILE, 'w', encoding='utf-8') as f:
            f.write('{nope')
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertEqual(body['filterState'], 'invalid')
        self.assertIn('unparseable', body['warning'])

    def test_subscriptions_marks_a_surviving_wildcard_entry(self):
        """A 0.12.x filter carried across the upgrade shows its dead rows as
        dead, so a consumer never re-derives the grammar to find them."""
        with open(self.mod.FILTER_FILE, 'w', encoding='utf-8') as f:
            json.dump({'topics': ['github:*', 'github:o/r']}, f)
        body = json.loads(self.call('webhook_subscriptions'))
        dead, live = body['topics'][0], body['topics'][1]
        self.assertEqual(dead['topic'], 'github:*')
        self.assertTrue(dead['invalid'])
        self.assertIn('removed in 0.13.0', dead['reason'])
        self.assertEqual(live['topic'], 'github:o/r')
        self.assertNotIn('invalid', live)

    def test_subscribe_refuses_both_wildcards(self):
        for topic in ('*', 'github:*'):
            out = self.call('webhook_subscribe', topic=topic)
            self.assertIn('not a valid pattern', out)
            self.assertIn('removed in 0.13.0', out)
        # The prefix form is still a valid pattern; for a session it now has
        # to be narrowed as well (see TestSessionSubscriptionLimits).
        self.assertNotIn('not a valid pattern',
                         self.call('webhook_subscribe', topic='github:defangdevs/*'))

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

    # -- include/exclude payload predicates (0.11.0; renamed in 0.15.0) -----
    def test_predicates_persist_and_roundtrip(self):
        include = {'path': 'action', 'in': ['opened']}
        exclude = {'path': 'action', 'in': ['closed']}
        out = self.call('webhook_subscribe', topic='o/r', include=include, exclude=exclude)
        self.assertIn('[include+exclude rules]', out)
        saved = self.read_json('filter.testsess.json')
        self.assertEqual(saved['topics'][0]['include'], include)
        self.assertEqual(saved['topics'][0]['exclude'], exclude)
        # ...surviving an unrelated write (write_filter round-trip).
        self.call('webhook_subscribe', topic='p/q', exclude={})
        saved = self.read_json('filter.testsess.json')
        self.assertEqual(saved['topics'][0]['include'], include)
        # ...and listed by webhook_subscriptions.
        body = json.loads(self.call('webhook_subscriptions'))
        self.assertEqual(body['topics'][0]['include'], include)

    def test_when_drop_still_work_as_argument_aliases(self):
        # Pre-#294 argument names read exactly like include/exclude, so a
        # caller that never updated keeps working. A fresh write normalizes
        # to the new names regardless of which ones came in.
        when = {'path': 'action', 'in': ['opened']}
        drop = {'path': 'action', 'in': ['closed']}
        out = self.call('webhook_subscribe', topic='o/r', when=when, drop=drop)
        self.assertIn('[include+exclude rules]', out)
        saved = self.read_json('filter.testsess.json')['topics'][0]
        self.assertEqual(saved['include'], when)
        self.assertEqual(saved['exclude'], drop)
        self.assertNotIn('when', saved)
        self.assertNotIn('drop', saved)

    def test_malformed_predicate_rejected_at_subscribe_time(self):
        for bad in ({'path': 'a'}, {'any': 'x'}, 'nope', {'path': 'a', 'in': 'x'}):
            out = self.call('webhook_subscribe', topic='o/r', include=bad)
            self.assertTrue(out.startswith('error:'), 'accepted %r: %s' % (bad, out))
        self.assertFalse(os.path.exists(os.path.join(self.state, 'filter.testsess.json')))

    def test_renew_keeps_or_clears_predicates(self):
        include = {'path': 'action', 'in': ['opened']}
        # exclude={} on the first call opts out of the default noise-exclude
        # (see test_new_session_subscribe_gets_default_noise_exclude), so this
        # test is only exercising include.
        self.call('webhook_subscribe', topic='o/r', include=include, exclude={})
        self.call('webhook_subscribe', topic='o/r')  # omitted → kept
        self.assertEqual(self.read_json('filter.testsess.json')['topics'][0]['include'], include)
        self.call('webhook_subscribe', topic='o/r', include={})  # {} → cleared
        self.assertNotIn('include', self.read_json('filter.testsess.json')['topics'][0])

    def test_new_session_subscribe_gets_default_noise_exclude(self):
        # A brand-new deliver_to:"session" entry that names no exclude is
        # seeded with the built-in noise list rather than None.
        self.call('webhook_subscribe', topic='o/r')
        saved = self.read_json('filter.testsess.json')['topics'][0]
        self.assertEqual(saved['exclude'], self.mod.DEFAULT_SESSION_EXCLUDE)
        # A dispatch (subagent) entry is unaffected -- it curates its own rules.
        self.call('webhook_subscribe', topic='p/q', deliver_to='subagent')
        self.assertNotIn('exclude', self.read_json('filter.dispatch.json')['topics'][0])

    def test_default_noise_exclude_actually_suppresses_a_star_event(self):
        self.call('webhook_subscribe', topic='o/r')
        self.assertFalse(self.mod.route_event('github', 'o/r', 'x', 'star')['forward'])
        self.assertTrue(self.mod.route_event('github', 'o/r', 'x', 'issues', {'action': 'opened'})['forward'])

    def test_renew_never_reapplies_the_default_exclude(self):
        # Broadening with exclude:{} must stick across a renew that omits it,
        # or "clear the noise filter" would be undone by the next re-subscribe.
        self.call('webhook_subscribe', topic='o/r')
        self.call('webhook_subscribe', topic='o/r', exclude={})
        self.assertNotIn('exclude', self.read_json('filter.testsess.json')['topics'][0])
        self.call('webhook_subscribe', topic='o/r', note='renew, no exclude passed')
        self.assertNotIn('exclude', self.read_json('filter.testsess.json')['topics'][0])


class TestSessionSubscriptionLimits(StateDirCase):
    """A session subscription interrupts a human, so it is bounded twice: it
    cannot outlive the work by much, and it cannot be an owner-wide firehose.
    Dispatch is exempt on both counts — it spawns instead of interrupting."""

    def test_session_ttl_is_capped(self):
        cap = self.mod.MAX_SESSION_TTL_HOURS
        out = self.call('webhook_subscribe', topic='o/r', ttl_hours=cap + 1)
        self.assertIn('too long for a session subscription', out)
        self.assertIn('deliver_to:"subagent"', out)
        self.assertEqual(self.mod.read_filter(
            os.path.join(self.state, 'filter.testsess.json'))['topics'], [])
        # The cap itself is allowed.
        self.assertIn('subscribed to', self.call('webhook_subscribe', topic='o/r', ttl_hours=cap))

    def test_session_may_not_pin(self):
        out = self.call('webhook_subscribe', topic='o/r', ttl_hours=0)
        self.assertIn('ttl_hours 0 (pinned) is not allowed for a session subscription', out)
        self.assertIn('deliver_to:"subagent"', out)

    def test_dispatch_ttl_is_unbounded(self):
        cap = self.mod.MAX_SESSION_TTL_HOURS
        for ttl in (0, cap * 100):
            out = self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', ttl_hours=ttl)
            self.assertNotIn('too long', out)

    def test_legacy_over_cap_entry_is_clamped_on_read(self):
        """Entries written before the cap must start expiring without anyone
        rewriting the file — that backlog is exactly what caused the noise."""
        path = os.path.join(self.state, 'filter.testsess.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'enabled': True, 'ttlHours': 999, 'topics': [
                {'topic': 'github:o/r', 'ttlHours': 720},
                {'topic': 'github:o/s', 'ttlHours': 0},
                {'topic': 'github:o/t', 'ttlHours': 2},
            ]}, f)
        got = self.mod.read_filter(path)
        cap = self.mod.MAX_SESSION_TTL_HOURS
        self.assertEqual(got['ttlHours'], cap)
        self.assertEqual([e['ttlHours'] for e in got['topics']], [cap, cap, 2])

    def test_dispatch_pinned_entry_survives_read(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        got = self.mod.read_filter(os.path.join(self.state, 'filter.dispatch.json'))
        self.assertEqual(got['topics'][0]['ttlHours'], 0)

    def test_session_prefix_topic_needs_an_include(self):
        out = self.call('webhook_subscribe', topic='github:o/*')
        self.assertIn('too broad for a session subscription', out)
        self.assertEqual(self.mod.read_filter(
            os.path.join(self.state, 'filter.testsess.json'))['topics'], [])

    def test_session_prefix_topic_is_fine_with_an_include(self):
        out = self.call('webhook_subscribe', topic='github:o/*',
                        include={'any': [{'path': 'action', 'in': ['opened']}]})
        self.assertIn('subscribed to', out)

    def test_renewing_a_narrowed_prefix_topic_need_not_repeat_the_include(self):
        self.call('webhook_subscribe', topic='github:o/*',
                  include={'any': [{'path': 'action', 'in': ['opened']}]})
        out = self.call('webhook_subscribe', topic='github:o/*', note='still working on it')
        self.assertIn('renewed subscription', out)

    def test_clearing_the_include_on_a_prefix_topic_is_refused(self):
        self.call('webhook_subscribe', topic='github:o/*',
                  include={'any': [{'path': 'action', 'in': ['opened']}]})
        out = self.call('webhook_subscribe', topic='github:o/*', include={})
        self.assertIn('too broad', out)

    def test_dispatch_prefix_topic_needs_no_include(self):
        out = self.call('webhook_subscribe', topic='github:o/*', deliver_to='subagent')
        self.assertNotIn('too broad', out)

    def test_exact_topic_needs_no_include(self):
        self.assertIn('subscribed to', self.call('webhook_subscribe', topic='github:o/r'))


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

    def test_match_exposes_object_identity_meta(self):
        out = os.path.join(self.state, 'spawned_meta.txt')
        mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='{ cat; echo "META=$LOCAL_WEBHOOK_SPAWN_META"; } > %s' % out,
                        LOCAL_WEBHOOK_STATE_DIR=self.state)
        self.mod = mod
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', note='ctx')
        mod.dispatch_event(self.env(action='opened', issue={'number': 7, 'title': 'boom'}))
        text = ''
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(out):
                with open(out, encoding='utf-8') as f:
                    text = f.read()
                if 'META=' in text:
                    break
            time.sleep(0.05)
        line = next((ln for ln in text.splitlines() if ln.startswith('META=')), '')
        self.assertTrue(line, 'expected a META= line, got: %r' % text)
        meta = json.loads(line[len('META='):])
        self.assertEqual(meta['number'], '7')
        self.assertEqual(meta['action'], 'opened')
        self.assertEqual(meta['event'], 'issues')
        self.assertEqual(meta['repo'], 'o/r')

    def test_issue_comment_meta_carries_the_raw_body(self):
        # agent-box#333: a spawn consumer that wants to resolve a
        # "@login+profile" mention suffix has nothing to parse but the
        # rendered prose line — unless the raw comment body rides along in
        # LOCAL_WEBHOOK_SPAWN_META, same as `number`/`action` already do.
        out = os.path.join(self.state, 'spawned_comment_meta.txt')
        mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='{ cat; echo "META=$LOCAL_WEBHOOK_SPAWN_META"; } > %s' % out,
                        LOCAL_WEBHOOK_STATE_DIR=self.state)
        self.mod = mod
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', note='ctx')
        env = {'source': 'github', 'format': 'github', 'event': 'issue_comment',
               'key': 'o/r', 'sender': 'x', 'delivery': 'd1',
               'payload': {'repository': {'full_name': 'o/r'}, 'sender': {'login': 'x'},
                           'action': 'created', 'issue': {'number': 286, 'title': 't'},
                           'comment': {'body': '@box+opus please rebase'}}}
        mod.dispatch_event(env)
        text = ''
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(out):
                with open(out, encoding='utf-8') as f:
                    text = f.read()
                if 'META=' in text:
                    break
            time.sleep(0.05)
        line = next((ln for ln in text.splitlines() if ln.startswith('META=')), '')
        self.assertTrue(line, 'expected a META= line, got: %r' % text)
        meta = json.loads(line[len('META='):])
        self.assertEqual(meta['comment_body'], '@box+opus please rebase')

    def test_no_payload_meta_is_empty_object_not_absent(self):
        # Non-github sources (or a Dispatcher.add caller with no per-line meta)
        # must still get a valid JSON object — a consumer does `.get()` on it.
        out = os.path.join(self.state, 'spawned_empty.txt')
        mod = self.load(LOCAL_WEBHOOK_SPAWN_CMD='{ cat; echo "META=$LOCAL_WEBHOOK_SPAWN_META"; } > %s' % out,
                        LOCAL_WEBHOOK_STATE_DIR=self.state)
        self.mod = mod
        mod.DISPATCHER.add('k', 'hello', {'key': 'k'})
        deadline = time.time() + 10
        text = ''
        while time.time() < deadline:
            if os.path.exists(out):
                with open(out, encoding='utf-8') as f:
                    text = f.read()
                if 'META=' in text:
                    break
            time.sleep(0.05)
        line = next((ln for ln in text.splitlines() if ln.startswith('META=')), '')
        self.assertEqual(line, 'META={}')

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


class DispatchCase(StateDirCase):
    """Shared harness for dispatch-policy tests: a recorder spawn command,
    envelope builders, and a fake live peer."""

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


class TestDispatchBrakes(DispatchCase):
    """A standing watch spawns for CI only on a failure (0.10.0, made
    sender-independent in 0.10.1), and never while a live session peer is
    already subscribed to the topic (0.10.0)."""

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

    def review_env(self, number=317, sender='human'):
        return self.env('pull_request_review',
                        {'action': 'submitted',
                         'review': {'state': 'approved'},
                         'pull_request': {'number': number, 'title': 't',
                                          'user': {'login': 'box'}}},
                        sender=sender)

    PR_RULE = {'include': {'path': 'pull_request.number', 'in': [317]}}

    def test_a_declared_peer_claims_a_non_ci_event(self):
        # agent-box#319: a review on a box-authored PR spawned a session while
        # the session that OPENED that PR was live — twice in one hour, and the
        # first duplicate pushed to the branch the live one owned. The CI brake
        # never looked, because a review is not a CI event.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', [dict(topic='github:o/*', **self.PR_RULE)])
        self.mod.dispatch_event(self.review_env())
        self.spawned(False)

    def test_a_declared_peer_claims_only_what_it_declared(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', [dict(topic='github:o/*', **self.PR_RULE)])
        self.mod.dispatch_event(self.review_env(number=999))
        self.spawned(True, 'review approved')

    def test_an_exclude_only_peer_does_not_claim(self):
        # The seeded default noise-exclude must never read as ownership, or
        # every session becomes an owner of its whole repo the moment it
        # subscribes — which is the same repo-wide silence #16 warns about.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', [{'topic': 'github:o/*',
                                       'exclude': {'path': 'action', 'in': ['closed']}}])
        self.mod.dispatch_event(self.review_env())
        self.spawned(True, 'review approved')

    def test_a_rule_less_peer_does_not_claim_a_non_ci_event(self):
        # The regression #16 warns about: honouring a repo-wide, rule-less
        # entry as a claim would let one hook session silence the watch for
        # every issue and PR in that repo until it exits.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', ['github:o/*'])
        self.mod.dispatch_event(self.review_env())
        self.spawned(True, 'review approved')

    def test_a_declared_claim_does_not_silence_other_work_in_the_repo(self):
        # Same property test_non_ci_event_spawns_even_when_a_session_owns_the_repo
        # pins, now with a peer that DID declare: new work still spawns.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', [dict(topic='github:o/*', **self.PR_RULE)])
        self.mod.dispatch_event(self.env('issues', {'action': 'opened',
                                                    'issue': {'number': 9, 'title': 't'}}))
        self.spawned(True, 'issue #9 opened')

    def test_a_declared_claim_under_another_topic_is_not_ownership(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.fake_live_peer('peer1', [dict(topic='github:other/*', **self.PR_RULE)])
        self.mod.dispatch_event(self.review_env())
        self.spawned(True, 'review approved')

    def test_an_expired_declared_claim_does_not_suppress(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        old = self.mod.iso_at(self.mod.now_ms() - 5 * 3600e3)
        self.fake_live_peer('peer1', [dict(topic='github:o/*', subscribedAt=old, **self.PR_RULE)])
        self.mod.dispatch_event(self.review_env())
        self.spawned(True, 'review approved')

    def test_expired_session_subscription_does_not_suppress(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        old = self.mod.iso_at(self.mod.now_ms() - 5 * 3600e3)
        self.fake_live_peer('peer1', [{'topic': 'github:o/*', 'subscribedAt': old}])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(True, 'workflow "CI"')


class TestDispatchDeclarative(DispatchCase):
    """A watch carrying when/drop predicates (0.11.0) owns its spawn policy:
    the failures-only CI brake steps aside for it, while the live-peer
    suppression — coordination, not policy — still applies."""

    RULES = {'when': {'any': [
        {'all': [{'path': 'action', 'in': ['opened', 'reopened']},
                 {'path': 'sender.login', 'notIn': ['box']}]},
        {'path': 'workflow_run.conclusion', 'in': ['failure', 'timed_out']}]},
        'drop': {'path': 'action', 'in': ['closed', 'merged']}}

    def watch(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent', **self.RULES)

    def test_opened_issue_spawns_closed_does_not(self):
        self.watch()
        self.mod.dispatch_event(self.env('issues', {'action': 'closed',
                                                    'issue': {'number': 3, 'title': 't'}}))
        self.spawned(False)
        self.mod.dispatch_event(self.env('issues', {'action': 'opened',
                                                    'issue': {'number': 9, 'title': 't'}}))
        self.spawned(True, 'issue #9 opened')

    def test_own_echo_dropped_by_positional_sender_rule(self):
        self.watch()
        self.mod.dispatch_event(self.env('issues', {'action': 'opened',
                                                    'issue': {'number': 3, 'title': 't'}},
                                         sender='box'))
        self.spawned(False)

    def test_declared_ci_failure_spawns_undeclared_green_does_not(self):
        self.watch()
        self.mod.dispatch_event(self.run_env('success', sender='box'))
        self.spawned(False)
        # A failure spawns whoever triggered it — via the rules, not the brake.
        self.mod.dispatch_event(self.run_env('failure', sender='box'))
        self.spawned(True, 'workflow "CI"')

    def test_rules_may_spawn_what_the_brake_would_drop(self):
        # The proof the predicate REPLACES the failures-only brake: a watch
        # that explicitly asks for green runs gets them.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  when={'path': 'workflow_run.conclusion', 'in': ['success']})
        self.mod.dispatch_event(self.run_env('success'))
        self.spawned(True, 'workflow "CI"')

    def test_live_peer_still_suppresses_a_declarative_ci_spawn(self):
        self.watch()
        self.fake_live_peer('peer1', ['github:o/*'])
        self.mod.dispatch_event(self.run_env('failure'))
        self.spawned(False)

    def comment_env(self, body, sender='me', action='created'):
        return self.env('issue_comment',
                        {'action': action, 'issue': {'number': 286, 'title': 't'},
                         'comment': {'body': body}}, sender=sender)

    def test_a_mention_in_free_text_spawns(self):
        # agent-box#296: an @mention is a work request, and no in/notIn list
        # can name it — it lives inside comment.body. Without `contains` the
        # watch declined it and the request reached nobody.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  when={'all': [{'path': 'action', 'in': ['created', 'edited']},
                                {'path': 'sender.login', 'notIn': ['box']},
                                {'path': 'comment.body', 'contains': ['@box']}]})
        self.mod.dispatch_event(self.comment_env('ship it'))
        self.spawned(False)
        self.mod.dispatch_event(self.comment_env('@BOX rebase'))
        self.spawned(True, 'comment created on #286')

    def test_the_boxs_own_mention_echo_does_not_spawn(self):
        # The sender clause earns its place here: the box quotes the request
        # back in its reply, so without it every answer would spawn again.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent',
                  when={'all': [{'path': 'sender.login', 'notIn': ['box']},
                                {'path': 'comment.body', 'contains': ['@box']}]})
        self.mod.dispatch_event(self.comment_env('done, @box out', sender='box'))
        self.spawned(False)


class TestDispatchFollowupOwnership(DispatchCase):
    """The duplicate one failing run always cost (#17), through the real path:
    GitHub emits check_run.completed and workflow_run.completed for the same
    run. The first spawns a session; the second arrives before that session's
    peer socket exists, so it is queued — and when its batch starts a window
    later, the session it is a duplicate of has been claiming the topic for
    most of that window."""

    def setUp(self):
        StateDirCase.setUp(self)
        self.log = os.path.join(self.state, 'spawns.log')
        self.mod = self.load(
            LOCAL_WEBHOOK_SPAWN_CMD='{ echo RUN; cat; } >> %s' % self.log,
            LOCAL_WEBHOOK_SPAWN_WINDOW='2')

    def spawns(self):
        if not os.path.exists(self.log):
            return 0
        with open(self.log, encoding='utf-8') as f:
            return f.read().count('RUN')

    def wait_for_spawns(self, n, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline and self.spawns() < n:
            time.sleep(0.05)
        self.assertEqual(self.spawns(), n)

    def check_run_failure(self):
        return self.env('check_run', {
            'action': 'completed',
            'check_run': {'name': 'deploy', 'status': 'completed', 'conclusion': 'failure'},
        })

    def test_one_failing_run_costs_one_session_not_two(self):
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.run_env('failure'))     # nobody owns it: spawn 1
        self.wait_for_spawns(1)
        self.mod.dispatch_event(self.check_run_failure())    # same run, peer not up yet
        self.fake_live_peer('peer1', ['github:o/*'])         # spawn 1's session claims it
        time.sleep(3.5)                                      # window opens; batch re-checked
        self.assertEqual(self.spawns(), 1)

    def test_a_queued_non_ci_event_still_spawns_its_own_session(self):
        # Ownership is object-granular and topics are repo-granular, so the
        # re-check must stay scoped to CI exactly like the arrival check: a new
        # issue arriving in the same burst is new work, not a duplicate.
        self.call('webhook_subscribe', topic='o/r', deliver_to='subagent')
        self.mod.dispatch_event(self.run_env('failure'))
        self.wait_for_spawns(1)
        self.mod.dispatch_event(self.env('issues', {'action': 'opened',
                                                    'issue': {'number': 9, 'title': 't'}}))
        self.fake_live_peer('peer1', ['github:o/*'])
        self.wait_for_spawns(2)
        with open(self.log, encoding='utf-8') as f:
            self.assertIn('issue #9 opened', f.read())


class TestDispatcher(StateDirCase):
    """Fork-bomb control: immediate first spawn, coalescing, cap, and the
    three-way exit contract (accepted / declined for now / broken)."""

    def recorder(self, marker, sleep=0):
        # Body first, header last: a waiter that polls for the header count
        # (runs()) never observes a RUN line before the batch text behind it
        # has been flushed.
        path = os.path.join(self.state, marker + '.log')
        cmd = ('{ cat; echo "RUN count=$LOCAL_WEBHOOK_SPAWN_COUNT key=$LOCAL_WEBHOOK_SPAWN_KEY"; } >> %s'
               % path)
        if sleep:
            cmd += '; sleep %s' % sleep
        return path, cmd

    def runs(self, path):
        if not os.path.exists(path):
            return []
        with open(path, encoding='utf-8') as f:
            return [ln for ln in f.read().splitlines() if ln.startswith('RUN ')]

    def pending(self, d, key):
        st = d.keys.get(key) or {}
        return [t for t, _, _ in st.get('pending', [])]

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

    def test_followup_batch_drops_lines_owned_by_then(self):
        # The bug of issue #17: ownership was decided when the line arrived and
        # never again, so the 60s wait — the one interval in which the answer
        # is guaranteed to change — ended in an unconditional spawn.
        path, cmd = self.recorder('owned')
        owned = {'now': False}
        d = self.mod.Dispatcher(cmd, 2, 1, 30,
                                owner_of=lambda env: 'peer1' if owned['now'] else None)
        d.add('k', 'e1', {'key': 'k'}, {'event': 'workflow_run'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        owned['now'] = True                       # session 1's peer socket appears
        d.add('k', 'e2', {'key': 'k'}, {'event': 'workflow_run'})
        time.sleep(2.5)                           # window opens, timer fires, nothing spawns
        self.assertEqual(len(self.runs(path)), 1)

    def test_followup_batch_keeps_the_lines_still_unowned(self):
        path, cmd = self.recorder('mixed')
        d = self.mod.Dispatcher(cmd, 2, 1, 30,
                                owner_of=lambda env: 'peer1' if env['event'] == 'ci' else None)
        d.add('k', 'e1', {'key': 'k'}, {'event': 'ci'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        d.add('k', 'owned-line', {'key': 'k'}, {'event': 'ci'})
        d.add('k', 'new-issue', {'key': 'k'}, {'event': 'issues'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 2, timeout=10))
        with open(path, encoding='utf-8') as f:
            text = f.read()
        self.assertIn('count=1', self.runs(path)[1])   # the batch shrank to what survived
        self.assertIn('new-issue', text)
        self.assertNotIn('owned-line', text)

    def test_first_event_on_an_idle_key_is_never_re_gated(self):
        # dispatch_event checked this line microseconds ago; asking a second
        # time here would let a stale claim keep an unowned key from starting.
        path, cmd = self.recorder('idle')
        d = self.mod.Dispatcher(cmd, 2, 1, 30, owner_of=lambda env: 'peer1')
        d.add('k', 'e1', {'key': 'k'}, {'event': 'workflow_run'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))

    def test_a_probe_that_raises_keeps_the_batch(self):
        def boom(env):
            raise RuntimeError('probe is broken')
        path, cmd = self.recorder('boom')
        d = self.mod.Dispatcher(cmd, 2, 1, 30, owner_of=boom)
        d.add('k', 'e1', {'key': 'k'}, {'event': 'workflow_run'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        d.add('k', 'e2', {'key': 'k'}, {'event': 'workflow_run'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 2, timeout=10))

    def test_failing_spawn_drops_batch_but_recovers(self):
        # Exit code branch 3 of 3: anything but 0 or 75 means a broken
        # spawner, and retrying one would loop.
        path, ok_cmd = self.recorder('rec')
        d = self.mod.Dispatcher('exit 3', 2, 0, 30)
        d.add('k', 'lost', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: d.active == 0))
        self.assertEqual(self.pending(d, 'k'), [])      # dropped, not deferred
        d.cmd = ok_cmd  # spawner fixed; the next event must still dispatch
        d.add('k', 'found', {'key': 'k'})

        def batch_arrived():
            if not os.path.exists(path):
                return False
            with open(path, encoding='utf-8') as f:
                return 'found' in f.read()
        self.assertTrue(self.wait_for(batch_arrived))

    # ---- the exit-code contract: 0 accepted, 75 declined for now, else
    # broken — plus the bounds that keep a permanent refusal finite (#28).

    def test_exit_zero_accepts_and_leaves_nothing_waiting(self):
        # Exit code branch 1 of 3, stated explicitly: an accepted batch leaves
        # no pending lines and no deferral streak behind.
        path, cmd = self.recorder('accepted')
        d = self.mod.Dispatcher(cmd, 2, 0, 30)
        d.add('k', 'e1', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))
        self.assertTrue(self.wait_for(lambda: d.active == 0))
        self.assertEqual(self.pending(d, 'k'), [])
        self.assertIsNone(d.keys['k']['defer_since'])

    def test_exit_75_keeps_the_batch_and_re_offers_it(self):
        # Exit code branch 2 of 3. Before 0.16.0 this batch was gone: the
        # consumer at its session ceiling exited non-zero, and nothing else
        # holds a standing watch's events.
        path, ok_cmd = self.recorder('defer')
        d = self.mod.Dispatcher('exit 75', 2, 1, 30)
        d.add('k', 'declined', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: self.pending(d, 'k') == ['declined']))
        d.add('k', 'arrived-while-waiting', {'key': 'k'})
        d.cmd = ok_cmd  # the consumer has room again
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) >= 1, timeout=10))

        def both_lines():
            with open(path, encoding='utf-8') as f:
                text = f.read()
            return 'declined' in text and 'arrived-while-waiting' in text
        self.assertTrue(self.wait_for(both_lines, timeout=10))
        with open(path, encoding='utf-8') as f:
            text = f.read()
        # Requeued at the HEAD: the declined line still precedes the one that
        # arrived while it waited.
        self.assertLess(text.index('declined'), text.index('arrived-while-waiting'))
        self.assertTrue(self.wait_for(lambda: d.active == 0))
        self.assertIsNone(d.keys['k']['defer_since'])   # streak closed on acceptance

    def test_a_deferred_batch_is_re_checked_for_ownership(self):
        # The whole point of waiting is that the answer changes while you
        # wait — the same re-check a coalesced follow-up batch gets (#17),
        # reached by the same path.
        path, ok_cmd = self.recorder('defer-owned')
        owned = {'now': False}
        d = self.mod.Dispatcher('exit 75', 2, 0.2, 30,
                                owner_of=lambda env: 'peer1' if owned['now'] else None)
        d.add('k', 'e1', {'key': 'k'}, {'event': 'workflow_run'})
        self.assertTrue(self.wait_for(lambda: self.pending(d, 'k') == ['e1']))
        owned['now'] = True   # a session claimed the topic while the batch waited
        d.cmd = ok_cmd        # and the consumer has room again
        self.assertTrue(self.wait_for(lambda: not self.pending(d, 'k') and d.active == 0))
        time.sleep(0.5)
        self.assertEqual(self.runs(path), [])           # no second session
        self.assertIsNone(d.keys['k']['defer_since'])   # streak closed with the batch

    def test_a_permanently_declined_batch_is_dropped_at_the_age_bound(self):
        err = io.StringIO()
        real_stderr = sys.stderr
        sys.stderr = err
        self.addCleanup(setattr, sys, 'stderr', real_stderr)
        path, ok_cmd = self.recorder('bound')
        # Sub-second bounds so the test does not sleep for minutes; the real
        # defaults are 60s window / 300s age.
        d = self.mod.Dispatcher('exit 75', 2, 0.05, 30, defer_max_s=0.3)
        d.add('k', 'stale', {'key': 'k'})
        self.assertTrue(self.wait_for(
            lambda: 'past LOCAL_WEBHOOK_SPAWN_DEFER_MAX_S' in err.getvalue()))
        self.assertTrue(self.wait_for(lambda: d.active == 0))
        self.assertEqual(self.pending(d, 'k'), [])
        self.assertIsNone(d.keys['k']['defer_since'])
        self.assertEqual(d.keys['k']['defer_n'], 0)
        log = err.getvalue()
        self.assertIn('declined', log)                  # each refusal said out loud
        self.assertRegex(log, r'declined them \d+ time\(s\) over \d+s')
        # The key is not poisoned: the next event still spawns.
        d.cmd = ok_cmd
        d.add('k', 'fresh', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: len(self.runs(path)) == 1))

    def test_pending_lines_are_capped_oldest_first(self):
        err = io.StringIO()
        real_stderr = sys.stderr
        sys.stderr = err
        self.addCleanup(setattr, sys, 'stderr', real_stderr)
        # Window 60s: nothing retries during the test, so the queue only grows.
        d = self.mod.Dispatcher('exit 75', 2, 60, 30, pending_max=3)
        d.add('k', 'e1', {'key': 'k'})
        self.assertTrue(self.wait_for(lambda: self.pending(d, 'k') == ['e1']))
        for t in ('e2', 'e3', 'e4', 'e5'):
            d.add('k', t, {'key': 'k'})
        self.assertEqual(self.pending(d, 'k'), ['e3', 'e4', 'e5'])
        self.assertIn('hit the 3-line cap', err.getvalue())


class TestResolveIngress(StateDirCase):
    """emit's ingress discovery: caller's env > receiver.json advertisement >
    the legacy loopback TCP port (whose owner writes no receiver.json)."""

    def setUp(self):
        super().setUp()
        # The runner's own environment must not leak into call-time resolution.
        self._sock = os.environ.pop('LOCAL_WEBHOOK_HTTP_SOCK', None)
        if self._sock is not None:
            self.addCleanup(os.environ.__setitem__, 'LOCAL_WEBHOOK_HTTP_SOCK', self._sock)

    def write_receiver(self, ingress):
        with open(os.path.join(self.state, 'receiver.json'), 'w', encoding='utf-8') as f:
            json.dump({'pid': 1, 'version': 'x', 'ingress': ingress}, f)

    def test_advertised_unix_and_tcp(self):
        self.write_receiver({'path': '/run/in.sock'})
        self.assertEqual(self.mod.resolve_ingress(), ('unix', '/run/in.sock'))
        self.write_receiver({'port': 8123})
        self.assertEqual(self.mod.resolve_ingress(), ('tcp', 8123))

    def test_env_sock_wins_over_advertisement(self):
        self.write_receiver({'path': '/run/other.sock'})
        os.environ['LOCAL_WEBHOOK_HTTP_SOCK'] = '/run/mine.sock'
        try:
            self.assertEqual(self.mod.resolve_ingress(), ('unix', '/run/mine.sock'))
        finally:
            del os.environ['LOCAL_WEBHOOK_HTTP_SOCK']

    def test_port_is_last_resort_and_zero_means_none(self):
        self.assertIsNone(self.mod.resolve_ingress())  # PORT=0, nothing else
        mod = self.load(LOCAL_WEBHOOK_PORT='8123')
        self.assertEqual(mod.resolve_ingress(), ('tcp', 8123))
        # A malformed advertisement falls through rather than erroring.
        self.write_receiver({'garbage': True})
        self.assertIsNone(self.mod.resolve_ingress())
        self.assertEqual(mod.resolve_ingress(), ('tcp', 8123))


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

    def start_daemon(self, spawn_cmd=None, **extra):
        env = self.base_env(
            LOCAL_WEBHOOK_RECEIVER_ONLY='1',
            LOCAL_WEBHOOK_HTTP_SOCK=self.http_sock,
            LOCAL_WEBHOOK_SPAWN_CMD=spawn_cmd or ('cat >> %s' % self.spawn_log),
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

    def cli(self, *args, session='testsess', stdin=None):
        env = self.base_env(LOCAL_WEBHOOK_SESSION=session, LOCAL_WEBHOOK_PORT='0')
        return subprocess.run([PYTHON, WEBHOOK_PY] + list(args), env=env, input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def add_source(self, name, **cfg):
        # Same shared secret; a distinct per-source file is what production uses.
        secret_file = '%s.secret' % name
        with open(os.path.join(self.state, secret_file), 'w', encoding='utf-8') as f:
            f.write(self.SECRET)
        path = os.path.join(self.state, 'sources.json')
        with open(path, encoding='utf-8') as f:
            sources = json.load(f)
        sources['sources'][name] = dict(cfg, secretFile=secret_file)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sources, f)

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
        # emit finds a socket-activated / unix ingress only through this field.
        self.assertEqual(info['ingress'], {'path': self.http_sock})

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

    def test_a_declined_spawn_is_retried_not_lost(self):
        """A real signed delivery whose spawn command declines it (exit 75) on
        the first attempt must still reach the second one — the whole of issue
        #28, end to end."""
        script = os.path.join(self.state, 'spawn.sh')
        declined = os.path.join(self.state, 'declined.once')
        with open(script, 'w', encoding='utf-8') as f:
            # First invocation: the consumer is at its ceiling — it reads the
            # batch, says why, and exits EX_TEMPFAIL. Afterwards it accepts.
            f.write('if [ ! -f %s ]; then cat > /dev/null; : > %s; '
                    'echo "at the hook-session cap"; exit 75; fi\n'
                    'cat >> %s\n' % (declined, declined, self.spawn_log))
        r = self.cli('subscribe', 'o/r', '--deliver-to', 'subagent', '--note', 'standing watch')
        self.assertEqual(r.returncode, 0, r.stderr)
        # Window 0: the retry rides the re-pump _run already does when a slot
        # frees, so the test needs no new timer either.
        self.start_daemon(spawn_cmd='sh %s' % script, LOCAL_WEBHOOK_SPAWN_WINDOW='0')

        # The dispatch verdict is asynchronous, so the delivery is still 200:
        # the HMAC verified and the peer fan-out happened either way.
        self.assertEqual(self.post(self.ISSUE), (200, 'ok'))
        self.assertTrue(self.wait_file(declined), 'the spawn command never ran')
        self.assertTrue(self.wait_file(self.spawn_log, contains='issue #5 opened on o/r'),
                        'the declined batch never reached the second attempt')
        with open(self.spawn_log, encoding='utf-8') as f:
            text = f.read()
        self.assertIn('[UNTRUSTED webhook:github', text)
        self.assertIn('standing watch', text)   # note echo survives the deferral

    def test_cli_exit_codes(self):
        self.assertEqual(self.cli('bogus-command').returncode, 2)
        self.assertEqual(self.cli('subscribe').returncode, 2)               # missing topic
        self.assertEqual(self.cli('subscribe', ':::').returncode, 1)        # in-band error
        self.assertEqual(self.cli('subscribe', 'o/r', '--deliver-to', 'nope').returncode, 2)
        self.assertEqual(self.cli('subscribe', 'o/r', '--ttl', '-1').returncode, 2)
        self.assertEqual(self.cli('subscribe', 'o/r', '--when', '{not json').returncode, 2)
        self.assertEqual(self.cli('subscribe', 'o/r', '--when', '{"path": "a"}').returncode, 1)
        self.assertEqual(self.cli('ls').returncode, 0)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_declarative_watch_end_to_end(self):
        """Real signed deliveries against an include/exclude watch (CLI: the
        old --when/--drop flag names, still accepted as aliases): an opened
        issue spawns, a close echo does not, and a session peer's own exclude
        predicate mutes without touching its other topics."""
        r = self.cli('subscribe', 'o/r', '--deliver-to', 'subagent', '--note', 'rules watch',
                     '--when', json.dumps({'any': [
                         {'path': 'action', 'in': ['opened', 'reopened']},
                         {'path': 'workflow_run.conclusion', 'in': ['failure']}]}),
                     '--drop', json.dumps({'path': 'action', 'in': ['closed']}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b'[include+exclude rules]', r.stdout)
        # A session peer that dropped close echoes on its repo.
        r = self.cli('subscribe', 'peer/only', '--exclude',
                     json.dumps({'path': 'action', 'in': ['closed']}), session='predsess')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.start_daemon()
        peer = self.start_peer('predsess')

        # Dispatch: the close echo is dropped, the green run is not declared,
        # the opened issue spawns. Ordering matters — the suppressed events go
        # first so the spawn log staying clean of them is meaningful.
        closed = dict(self.ISSUE, action='closed',
                      issue={'number': 6, 'title': 'bye', 'html_url': 'https://x/6'})
        self.assertEqual(self.post(closed)[0], 200)
        self.assertEqual(self.post(self.run_payload('success'), event='workflow_run')[0], 200)
        self.assertEqual(self.post(self.ISSUE)[0], 200)
        self.assertTrue(self.wait_file(self.spawn_log, contains='issue #5 opened'),
                        'declared opened issue never spawned')
        with open(self.spawn_log, encoding='utf-8') as f:
            text = f.read()
        self.assertNotIn('issue #6', text)
        self.assertNotIn('workflow', text)

        # Session path: closed on the peer repo is dropped, opened arrives.
        self.assertEqual(self.post(dict(closed, repository={'full_name': 'peer/only'}))[0], 200)
        self.assertEqual(self.post(dict(self.ISSUE, repository={'full_name': 'peer/only'}))[0], 200)
        line = [None]

        def read_line():
            line[0] = peer.stdout.readline()
        t = threading.Thread(target=read_line)
        t.daemon = True
        t.start()
        t.join(15)
        self.assertTrue(line[0], 'peer never got the opened issue')
        content = json.loads(line[0].decode())['params']['content']
        self.assertIn('issue #5 opened', content)
        self.assertNotIn('closed', content)

    def test_emit_reaches_sessions_and_standing_watches(self):
        """A box-local event enters through the ingress, so it gets the whole
        pipeline: fan-out to subscribed peers AND standing-watch dispatch —
        exactly like an external delivery (and a non-CI event spawns even while
        a live session is subscribed)."""
        # Keyed on the payload's own window, because 0.13.0 removed "budget:*"
        # along with every other way to subscribe to a whole source. A local
        # source therefore needs a real keyPath to be addressable at all —
        # see defangdevs/local-channels#19.
        self.add_source('budget', keyPath='window')
        r = self.cli('subscribe', 'budget:5h', '--note', 'usage-limit warnings', session='peersess')
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli('subscribe', 'budget:5h', '--deliver-to', 'subagent', '--note', 'budget watch')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.start_daemon()
        peer = self.start_peer('peersess')

        r = self.cli('emit', 'budget', '{"used_pct":92,"window":"5h"}', '--event', 'budget_warning')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b'delivered budget event', r.stdout)

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
        self.assertIn('[UNTRUSTED webhook:budget', msg['params']['content'])
        self.assertIn('used_pct=', msg['params']['content'])
        self.assertIn('usage-limit warnings', msg['params']['content'])
        self.assertEqual(msg['params']['meta']['event'], 'budget_warning')
        self.assertEqual(msg['params']['meta']['key'], '5h')
        self.assertTrue(msg['params']['meta']['delivery'].startswith('emit-'))

        self.assertTrue(self.wait_file(self.spawn_log, contains='budget_warning'),
                        'standing watch never spawned for the emitted event')
        with open(self.spawn_log, encoding='utf-8') as f:
            self.assertIn('budget watch', f.read())

    def test_emit_over_tcp_and_stdin(self):
        """The legacy/TCP shape: the daemon advertises its port, emit reads the
        payload from stdin and delivers as a plain HTTP client."""
        self.add_source('budget', keyPath='window')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        env = self.base_env(LOCAL_WEBHOOK_RECEIVER_ONLY='1', LOCAL_WEBHOOK_PORT=str(port))
        p = subprocess.Popen([PYTHON, WEBHOOK_PY], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(p)
        self.assertTrue(self.wait_file(os.path.join(self.state, 'receiver.json'), contains='"port"'))
        r = self.cli('emit', 'budget', '-', stdin=b'{"used_pct":95,"window":"weekly"}')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(('delivered budget event to 127.0.0.1:%d' % port).encode(), r.stdout)

    def test_emit_cli_contract(self):
        # Usage errors exit 2, operational failures exit 1 — same split as the
        # subscription commands, so `set -e` producers notice either way.
        self.add_source('budget', keyPath='window')
        r = self.cli('emit', 'nosuch', '{}')
        self.assertEqual(r.returncode, 1)
        self.assertIn(b'unknown source', r.stderr)
        r = self.cli('emit', 'budget', 'not json')
        self.assertEqual(r.returncode, 2)
        r = self.cli('emit')
        self.assertEqual(r.returncode, 2)
        r = self.cli('emit', 'budget', '{}')  # no daemon, no advertisement, PORT=0
        self.assertEqual(r.returncode, 1)
        self.assertIn(b'no ingress', r.stderr)
        # A stale advertisement (daemon crashed) is a prompt error, not a hang.
        with open(os.path.join(self.state, 'receiver.json'), 'w', encoding='utf-8') as f:
            json.dump({'ingress': {'path': os.path.join(self.state, 'gone.sock')}}, f)
        r = self.cli('emit', 'budget', '{}')
        self.assertEqual(r.returncode, 1)
        self.assertIn(b'could not reach', r.stderr)

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
