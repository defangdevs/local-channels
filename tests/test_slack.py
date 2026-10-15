# Tests for local-slack/slack.py — stdlib unittest only. The tracker and the
# composer are pure given an injected clock/resolver/emitter, so none of this
# touches the network; Socket Mode and the Web API are exercised only through
# their pure parts (the bucket, the frame codec is covered by the daemon e2e
# a follow-up adds).
import importlib.util
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('slack', os.path.join(REPO, 'local-slack', 'slack.py'))
slack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slack)

BOT = {'user_id': 'UBOT', 'bot_id': 'BBOT'}


def msg(ts, text='hi', user='U1', thread_ts=None, channel='C1', sub=None, eid=None, **kw):
    ev = {'type': 'message', 'channel': channel, 'ts': ts, 'text': text, 'user': user}
    if thread_ts:
        ev['thread_ts'] = thread_ts
    if sub:
        ev['subtype'] = sub
    ev.update(kw)
    return {'team_id': 'T1', 'event_id': eid or 'E' + ts + (sub or ''), 'event': ev}


def reaction(ts, emoji, user='U1', kind='reaction_added', channel='C1', eid=None):
    return {'team_id': 'T1', 'event_id': eid or 'R%s%s%s%s' % (ts, emoji, user, kind),
            'event': {'type': kind, 'user': user, 'reaction': emoji,
                      'item': {'type': 'message', 'channel': channel, 'ts': ts}}}


class Rig(unittest.TestCase):
    def setUp(self):
        self.t = [1000.0]
        self.events, self.reacts = [], []
        self.store = slack.Store(':memory:')
        self.cfg = slack._merge(slack.DEFAULT_CHANNEL, {'quiet_minutes': 10, 'max_wait_hours': 1})
        self.extra = {}
        self.defaults = {}
        self.tr = slack.Tracker(
            self.store, {'C1': self.cfg}, BOT, lambda a, p: self.events.append((a, p)),
            now=lambda: self.t[0], react=lambda c, ts, e: self.reacts.append((c, ts, e)),
            lookup=lambda c, ts: self.extra.get(ts), users=lambda uid: {'guest': False, 'external': False},
            defaults=self.defaults)

    def actions(self):
        return [a for a, _ in self.events]

    def advance(self, secs):
        self.t[0] += secs


class TestTracker(Rig):
    def test_quiet_settle(self):
        self.tr.handle(msg('1.1', 'Export button does nothing'))
        self.assertEqual(self.actions(), ['message.posted'])
        self.advance(599)
        self.assertEqual(self.tr.tick(), 0)
        self.advance(2)
        self.assertEqual(self.tr.tick(), 1)
        a, p = self.events[-1]
        self.assertEqual((a, p['reason']), ('thread.settled', 'quiet'))
        self.assertEqual(p['title'], 'Export button does nothing')
        self.assertEqual(p['identifier'], 'T1/C1/1.1')

    def test_activity_pushes_settle_out_and_bumps_version(self):
        self.tr.handle(msg('1.1'))
        self.advance(500)
        self.tr.handle(msg('1.2', thread_ts='1.1', user='U2'))
        self.advance(500)
        self.assertEqual(self.tr.tick(), 0)
        self.advance(200)
        self.assertEqual(self.tr.tick(), 1)
        self.assertEqual(self.events[-1][1]['version'], 2)

    def test_max_wait_caps_settle(self):
        self.tr.handle(msg('1.1'))
        for i in range(6):
            self.advance(550)
            self.tr.handle(msg('1.%d' % (i + 2), thread_ts='1.1'))
        self.advance(400)  # past first_seen + 1h
        self.tr.tick()
        self.assertEqual(self.events[-1][1]['reason'], 'max_wait')

    def test_dedup_event_id(self):
        self.tr.handle(msg('1.1', eid='X'))
        self.tr.handle(msg('1.1', eid='X'))
        self.assertEqual(self.actions(), ['message.posted'])

    def test_unconfigured_channel_ignored(self):
        self.tr.handle(msg('1.1', channel='C9'))
        self.assertEqual(self.events, [])

    def test_own_echo_and_nested_edit_echo_ignored(self):
        self.tr.handle(msg('1.1', user='UBOT'))
        self.tr.handle(msg('1.2', user=None, bot_id='BBOT', sub='bot_message'))
        self.assertEqual(self.events, [])

    def test_unchanged_message_changed_is_not_an_edit(self):
        self.tr.handle(msg('1.1', 'same'))
        n = len(self.events)
        self.tr.handle({'team_id': 'T1', 'event_id': 'e2', 'event': {
            'type': 'message', 'subtype': 'message_changed', 'channel': 'C1',
            'message': {'ts': '1.1', 'text': 'same', 'user': 'U1'},
            'previous_message': {'ts': '1.1', 'text': 'same', 'user': 'U1'}}})
        self.assertEqual(len(self.events), n)

    def test_real_edit_counts(self):
        self.tr.handle(msg('1.1', 'old'))
        self.tr.handle({'team_id': 'T1', 'event_id': 'e2', 'event': {
            'type': 'message', 'subtype': 'message_changed', 'channel': 'C1',
            'message': {'ts': '1.1', 'text': 'new', 'user': 'U1'},
            'previous_message': {'ts': '1.1', 'text': 'old', 'user': 'U1'}}})
        self.assertEqual(self.actions()[-1], 'message.edited')

    def test_edit_by_bot_ignored(self):
        self.tr.handle(msg('1.1', 'old'))
        n = len(self.events)
        self.tr.handle({'team_id': 'T1', 'event_id': 'e2', 'event': {
            'type': 'message', 'subtype': 'message_changed', 'channel': 'C1',
            'message': {'ts': '1.1', 'text': 'new', 'user': 'UBOT'},
            'previous_message': {'ts': '1.1', 'text': 'old', 'user': 'UBOT'}}})
        self.assertEqual(len(self.events), n)

    def test_thread_broadcast_never_starts_a_record(self):
        self.tr.handle(msg('2.2', thread_ts='2.1', sub='thread_broadcast'))
        self.assertEqual(self.events, [])

    def test_system_subtypes_ignored(self):
        self.tr.handle(msg('1.1', sub='channel_join'))
        self.assertEqual(self.events, [])

    def test_mention_settles_immediately_and_acks_only_when_configured(self):
        self.cfg['reactions']['ack'] = 'eyes'
        self.tr.handle(msg('1.1', 'help <@UBOT>'))
        self.assertEqual(self.actions(), ['message.posted', 'thread.settled'])
        self.assertEqual(self.events[-1][1]['reason'], 'mention')
        self.assertEqual(self.reacts, [('C1', '1.1', 'eyes')])

    def test_ready_reaction_on_a_reply_acts_on_the_thread(self):
        self.tr.handle(msg('1.1'))
        self.tr.handle(msg('1.2', thread_ts='1.1'))
        self.tr.handle(reaction('1.2', 'white_check_mark'))
        self.assertEqual(self.events[-1][1]['reason'], 'ready')

    def test_reaction_index_miss_uses_lookup(self):
        self.tr.handle(msg('1.1'))
        self.extra['1.9'] = '1.1'
        self.tr.handle(reaction('1.9', 'white_check_mark'))
        self.assertEqual(self.events[-1][0], 'thread.settled')

    def test_guest_cannot_control(self):
        self.tr.users = lambda uid: {'guest': True, 'external': False}
        self.tr.handle(msg('1.1'))
        self.tr.handle(reaction('1.1', 'white_check_mark', user='UG'))
        self.assertEqual(self.actions(), ['message.posted'])

    def test_hold_blocks_settle_until_removed(self):
        self.tr.handle(msg('1.1'))
        self.tr.handle(reaction('1.1', 'raised_hand'))
        self.advance(5000)
        self.assertEqual(self.tr.tick(), 0)
        self.tr.handle(reaction('1.1', 'raised_hand', kind='reaction_removed'))
        self.advance(601)
        self.assertEqual(self.tr.tick(), 1)

    def test_drop(self):
        self.tr.handle(msg('1.1'))
        self.tr.handle(reaction('1.1', 'x'))
        self.assertEqual(self.actions()[-1], 'thread.dropped')
        self.advance(5000)
        self.assertEqual(self.tr.tick(), 0)

    def test_resettle_reopens(self):
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()
        self.tr.handle(msg('1.2', thread_ts='1.1'))
        self.assertIn('thread.reopened', self.actions())
        self.advance(601)
        self.assertEqual(self.tr.tick(), 1)

    def test_compare_and_swap_loses_to_activity(self):
        self.tr.handle(msg('1.1'))
        row = self.store.q('SELECT * FROM threads')[0]
        self.tr.handle(msg('1.2', thread_ts='1.1'))   # version moves under the ticker
        self.assertFalse(self.tr._finish(row, 'quiet', self.cfg))

    def test_restart_recomputes_from_table(self):
        self.tr.handle(msg('1.1'))
        self.advance(601)
        tr2 = slack.Tracker(self.store, {'C1': self.cfg}, BOT, lambda a, p: self.events.append((a, p)),
                            now=lambda: self.t[0])
        self.assertEqual(tr2.tick(), 1)

    def test_ignore_users(self):
        self.cfg['ignore_users'] = ['U1']
        self.tr.handle(msg('1.1'))
        self.assertEqual(self.events, [])

    def test_mention_track_only_starts_on_mention(self):
        self.cfg['track'] = 'mention'
        self.tr.handle(msg('1.1', 'no mention'))
        self.assertEqual(self.events, [])
        self.tr.handle(msg('2.1', 'hey <@UBOT>'))
        self.assertEqual(self.actions(), ['message.posted', 'thread.settled'])

    def test_merge_window_attaches_same_author(self):
        self.cfg['merge_window_minutes'] = 10
        self.tr.handle(msg('1.1'))
        self.advance(60)
        self.tr.handle(msg('2.1'))
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM threads')[0]['c'], 1)
        self.assertEqual(self.store.q('SELECT extra_ts FROM threads')[0]['extra_ts'], '2.1')

    def test_feedback_on_bot_message(self):
        self.defaults['feedback_reactions'] = ['+1', '-1']
        self.tr.handle(msg('1.1'))
        self.store.x('INSERT INTO msgs VALUES (?,?,?,?,?,?,?)', 'T1', 'C1', '1.5', '1.1', 'UBOT', 0, 0)
        self.tr.handle(reaction('1.5', '+1'))
        self.assertEqual(self.actions()[-1], 'feedback')

    def test_channel_shared_flags_external(self):
        self.cfg['allow_external'] = True
        self.tr.handle({'team_id': 'T1', 'event_id': 'cs', 'event': {'type': 'channel_shared', 'channel': 'C1'}})
        self.tr.handle(msg('1.1'))
        self.assertTrue(self.events[0][1]['external'])

    def test_retention_prune_and_purge(self):
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()
        self.advance(31 * 86400)
        self.store.prune(self.t[0], 30)
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM threads')[0]['c'], 0)
        self.tr.handle(msg('3.1'))
        self.store.purge_channel('C1')
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM msgs')[0]['c'], 0)


class TestPayloadShape(Rig):
    def test_permalink_uses_the_workspace_host_and_summary_reads_well(self):
        self.tr.bot = dict(BOT, url='https://acme.slack.com/')
        self.tr.handle(msg('1.1'))
        p = self.events[0][1]
        self.assertEqual(p['url'], 'https://acme.slack.com/archives/C1/p11')
        self.assertEqual(p['summary'], 'v1 · 0 replies, 1 person')      # no reason on message.posted
        self.tr.handle(msg('1.2', thread_ts='1.1', user='U2'))
        self.assertEqual(self.events[-1][1]['summary'], 'v2 · 1 reply, 2 people')
        self.advance(601)
        self.tr.tick()
        self.assertTrue(self.events[-1][1]['summary'].endswith('· reason: quiet'))


class TestRetention(Rig):
    def test_unrecorded_index_rows_age_out(self):
        self.cfg['track'] = 'mention'
        self.tr.handle(msg('1.1', 'no mention'))     # indexed, never a record
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM msgs')[0]['c'], 1)
        self.advance(31 * 86400)
        self.store.prune(self.t[0], 30)
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM msgs')[0]['c'], 0)

    def test_open_record_rows_survive(self):
        self.tr.handle(msg('1.1'))
        self.store.prune(self.t[0] + 31 * 86400, 30)
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM msgs')[0]['c'], 1)

    def test_tick_uses_configured_retention(self):
        self.tr.retention_days = 1
        self.cfg['track'] = 'mention'
        self.tr.handle(msg('1.1'))
        self.advance(2 * 86400)
        self.tr.tick()
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM msgs')[0]['c'], 0)

    def test_purge_channel_clears_both_status_key_shapes(self):
        self.store.x("INSERT INTO status VALUES ('T1/C1/1.1','9.9'), ('C1/2.2','9.8'), ('T1/C2/3.3','9.7')")
        self.store.purge_channel('C1')
        self.assertEqual([r['thread_key'] for r in self.store.q('SELECT thread_key FROM status')], ['T1/C2/3.3'])


class TestEmitter(unittest.TestCase):
    def test_failures_are_logged_not_raised(self):
        old = os.environ.get('LOCAL_SLACK_EMIT')
        os.environ['LOCAL_SLACK_EMIT'] = '/nonexistent/emit-cmd'
        try:
            slack.make_emitter()('message.posted', {'team': 'T', 'channel': 'C'})  # FileNotFoundError
            os.environ['LOCAL_SLACK_EMIT'] = 'false'
            slack.make_emitter()('message.posted', {'team': 'T', 'channel': 'C'})  # exit 1
        finally:
            if old is None:
                del os.environ['LOCAL_SLACK_EMIT']
            else:
                os.environ['LOCAL_SLACK_EMIT'] = old


class TestClassifier(Rig):
    def test_topics_are_comma_wrapped(self):
        self.tr.classify = lambda cfg, key: ['feature-request']
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()
        self.assertEqual(self.events[-1][1]['topics'], ',feature-request,')

    def test_no_classifier_no_topics_key(self):
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()
        self.assertNotIn('topics', self.events[-1][1])

    def test_overlapping_labels_refused(self):
        self.assertTrue(slack.labels_overlap(['bug', 'debug']))
        self.assertFalse(slack.labels_overlap(['bug', 'question']))


class TestText(unittest.TestCase):
    CFG = slack._merge(slack.DEFAULT_CHANNEL, {})
    DEF = slack._merge(slack.DEFAULT_DEFAULTS, {'links': {'allowed_hosts': ['github.com']}})

    def res(self, sigil, name):
        return {'@alex': 'U9', '#dev': 'C9', '@eng': 'S7'}.get(sigil + name)

    def c(self, text, cfg=None):
        return slack.compose(text, self.res, cfg or self.CFG, self.DEF)

    def test_title_sanitised(self):
        self.assertEqual(slack.sanitize_title('hi <@U1> see <https://x.io|the doc> <!here> `x`\nline2'),
                         'hi U1 see the doc here x line2')
        self.assertEqual(len(slack.sanitize_title('a' * 500)), 200)

    def test_mentions_become_tokens(self):
        self.assertEqual(self.c('ping @alex in #dev'), 'ping <@U9> in <#C9>')

    def test_unknown_names_stay_literal_text(self):
        self.assertEqual(self.c('hi @nobody, see #general'), 'hi @nobody, see #general')
        self.assertEqual(self.c('PR #42, colour #fff, thanks @alice.'), 'PR #42, colour #fff, thanks @alice.')
        self.assertEqual(self.c('ping @alex.'), 'ping <@U9>.')

    def test_smuggled_token_is_refused_or_escaped(self):
        self.assertEqual(self.c('quoted &lt;!channel&gt;'), 'quoted &amp;lt;!channel&amp;gt;')
        self.assertEqual(self.c('<!channel> hello'), '&lt;!channel&gt; hello')   # inert text
        with self.assertRaises(slack.Refused):
            self.c('@channel hello')
        # a raw token the agent wrote is escaped, never live
        self.assertEqual(self.c('x <@U1> y'), 'x &lt;@U1&gt; y')

    def test_broadcast_needs_flag(self):
        cfg = slack._merge(self.CFG, {'write': {'broadcast': True}})
        with self.assertRaises(slack.Refused):
            self.c('@here hi')
        self.assertEqual(self.c('@here hi', cfg), '<!here> hi')

    def test_groups_need_flag(self):
        with self.assertRaises(slack.Refused):
            self.c('@eng look')
        cfg = slack._merge(self.CFG, {'write': {'groups': True}})
        self.assertEqual(self.c('@eng look', cfg), '<!subteam^S7> look')

    def test_mention_in_code_stays_literal(self):
        self.assertEqual(self.c('use `@alex` here'), 'use `@alex` here')

    def test_links(self):
        self.assertEqual(self.c('see https://github.com/o/r/pull/1'),
                         'see <https://github.com/o/r/pull/1|github.com>')
        with self.assertRaises(slack.Refused):
            self.c('see https://evil.example/x')
        with self.assertRaises(slack.Refused):
            self.c('https://github.com/x?q=' + 'a' * 300)
        with self.assertRaises(slack.Refused):
            self.c('https://github.com/x?t=ghp_%s' % ('A' * 36))
        with self.assertRaises(slack.Refused):
            self.c('https://github.com/x#%67hp_' + 'A' * 36)

    def test_image_markdown_refused(self):
        with self.assertRaises(slack.Refused):
            self.c('![x](https://github.com/a.png)')

    def test_secrets_refused_without_echo(self):
        try:
            self.c('key AKIAABCDEFGHIJKLMNOP')
        except slack.Refused as e:
            self.assertNotIn('AKIA', str(e))
        else:
            self.fail('not refused')

    def test_ampersand_escaped(self):
        self.assertEqual(self.c('a & b < c'), 'a &amp; b &lt; c')


class TestConfigAndBuckets(unittest.TestCase):
    def test_missing_or_corrupt_config_means_no_channels(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(slack.load_config(os.path.join(d, 'nope.json'))[0], {})
            p = os.path.join(d, 'bad.json')
            open(p, 'w').write('{not json')
            self.assertEqual(slack.load_config(p)[0], {})

    def test_roundtrip_applies_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'c.json')
            slack.save_config({'C1': {'quiet_minutes': 5}}, {'dm_allowlist': ['U1']}, p)
            ch, df = slack.load_config(p)
            self.assertEqual(ch['C1']['quiet_minutes'], 5)
            self.assertEqual(ch['C1']['write']['mode'], 'on_request')
            self.assertEqual(df['dm_allowlist'], ['U1'])
            self.assertIn('disclosure', df)

    def test_the_documented_example_loads_and_is_the_recommended_policy(self):
        ch, df = slack.load_config(os.path.join(REPO, 'local-slack', 'channels.example.json'))
        self.assertEqual(ch['C0123456789']['reactions']['ack'], 'eyes')
        self.assertEqual(df['feedback_reactions'], ['+1', '-1'])
        self.assertEqual(df['limits']['session_writes'], 20)
        # ...and a bare install carries none of it.
        self.assertIsNone(slack.DEFAULT_CHANNEL['reactions']['ack'])
        self.assertEqual((slack.DEFAULT_DEFAULTS['disclosure'], slack.DEFAULT_DEFAULTS['feedback_reactions'],
                          slack.DEFAULT_DEFAULTS['status_marks']), ('', [], {}))

    def test_reads_survive_a_write_burst(self):
        t = [0.0]
        b = slack.Bucket(45, now=lambda: t[0])
        wrote = sum(1 for _ in range(100) if b.take(True))
        self.assertLess(wrote, 45)            # 40% reserved
        self.assertTrue(b.take(False))        # a read still succeeds
        self.assertGreater(b.limited, 0)


TS = '1700000000.000100'


class TestWriter(unittest.TestCase):
    def setUp(self):
        self.calls = []

        class W:
            def call(s, method, params=None, **kw):
                self.calls.append((method, params))
                return {'ok': True, 'ts': '1700000009.000900', 'members': [], 'channels': []}
        self.store = slack.Store(':memory:')
        self.cfg = slack._merge(slack.DEFAULT_CHANNEL, {'write': {'allowed': True}})
        self.w = slack.Writer(W(), self.store, {'C1': self.cfg},
                              slack._merge(slack.DEFAULT_DEFAULTS, {}), BOT, session='s1')

    def ask(self, ts=TS):
        self.store.x("INSERT INTO threads VALUES ('k','T1','C1',?,'',0,0,0,1,'settled',NULL,1,'','0','',0,0,1)", ts)

    def test_on_request_blocks_reply_until_asked(self):
        with self.assertRaises(slack.Refused):
            self.w.reply('C1', TS, 'hello')
        self.ask()
        self.w.reply('C1', TS, 'hello')
        m, p = self.calls[-1]
        self.assertEqual((m, p['thread_ts'], p['unfurl_links'], p['unfurl_media']),
                         ('chat.postMessage', TS, False, False))
        self.assertNotIn('parse', p)

    def test_unconfigured_or_readonly_channel_refused(self):
        with self.assertRaises(slack.Refused):
            self.w.react('C9', TS, 'eyes')
        self.cfg['write']['allowed'] = False
        with self.assertRaises(slack.Refused):
            self.w.react('C1', TS, 'eyes')

    def test_top_level_needs_flag_and_is_rate_limited(self):
        with self.assertRaises(slack.Refused):
            self.w.post('C1', 'hi')
        self.cfg['write']['top_level'] = True
        for _ in range(5):
            self.w.post('C1', 'hi')
        with self.assertRaises(slack.Refused):
            self.w.post('C1', 'hi')

    def test_empty_or_bad_ts_cannot_become_a_top_level_post(self):
        self.cfg['write']['mode'] = 'always'
        for bad in ('', 'x', None, '1.1'):
            with self.assertRaises(slack.Refused):
                self.w.reply('C1', bad, 'hi')
            with self.assertRaises(slack.Refused):
                self.w.status('C1', bad, 'hi')
        self.assertEqual(self.calls, [])

    def test_reply_to_a_reply_is_posted_to_the_parent(self):
        self.ask()
        self.store.x('INSERT INTO msgs VALUES (?,?,?,?,?,?,?)', 'T1', 'C1', '1700000005.000500', TS, 'U2', 0, 0)
        self.w.reply('C1', '1700000005.000500', 'hello')
        self.assertEqual(self.calls[-1][1]['thread_ts'], TS)

    def test_status_is_gated_like_a_reply(self):
        with self.assertRaises(slack.Refused):      # on_request, nobody asked
            self.w.status('C1', TS, 'working')
        self.assertEqual(self.calls, [])
        self.ask()
        for i in range(20):
            self.w.audit('reply', 'C1', TS, '1.%d' % i, 'x')
        with self.assertRaises(slack.Refused):      # per-session cap
            self.w.status('C1', TS, 'working')

    def test_status_creates_then_edits_one_message_and_moves_the_reaction(self):
        self.w.defaults['status_marks'] = {'working': 'hourglass_flowing_sand', 'done': 'white_check_mark', 'failed': 'x'}
        self.cfg['reactions']['ack'] = 'eyes'
        self.ask()
        self.w.status('C1', TS, 'working')
        self.w.status('C1', TS, 'finished', 'done')
        methods = [m for m, _ in self.calls]
        self.assertEqual([m for m in methods if m.startswith('chat.')], ['chat.postMessage', 'chat.update'])
        self.assertNotIn('✅', [p for m, p in self.calls if m == 'chat.update'][0]['text'])
        adds = [p['name'] for m, p in self.calls if m == 'reactions.add']
        removes = [p['name'] for m, p in self.calls if m == 'reactions.remove']
        self.assertEqual(adds, ['hourglass_flowing_sand', 'white_check_mark'])
        self.assertIn('eyes', removes)   # the daemon's ack is replaced

    def test_status_makes_no_reactions_unless_marks_are_configured(self):
        self.cfg['reactions']['ack'] = 'eyes'
        self.ask()
        self.w.status('C1', TS, 'working')
        self.w.status('C1', TS, 'done', 'done')
        self.assertEqual([m for m, _ in self.calls if m.startswith('reactions.')], [])

    def test_limits_come_from_config_and_zero_turns_a_cap_off(self):
        self.ask()
        self.w.defaults['limits'] = {'session_writes': 2}
        self.w.reply('C1', TS, 'a')
        self.w.reply('C1', TS, 'b')
        with self.assertRaises(slack.Refused):
            self.w.reply('C1', TS, 'c')
        self.w.defaults['limits'] = {'session_writes': 0}
        self.w.reply('C1', TS, 'd')
        self.cfg['write']['top_level'] = True
        self.w.defaults['limits'] = {'session_writes': 0, 'top_level_per_hour': 1}
        self.w.post('C1', 'x')
        with self.assertRaises(slack.Refused):
            self.w.post('C1', 'y')

    def test_no_disclosure_line_unless_configured(self):
        self.ask()
        self.w.reply('C1', TS, 'hello')
        self.assertEqual(self.calls[-1][1]['text'], 'hello')
        self.w.defaults['disclosure'] = '_— bot_'
        self.w.reply('C1', TS, 'hello')
        self.assertTrue(self.calls[-1][1]['text'].endswith('_— bot_'))

    def test_status_edits_do_not_eat_the_session_cap(self):
        self.ask()
        self.w.status('C1', TS, 'working')
        for _ in range(30):
            self.w.status('C1', TS, 'still working')

    def test_secret_in_outgoing_text_refused_and_never_sent(self):
        self.ask()
        with self.assertRaises(slack.Refused):
            self.w.reply('C1', TS, 'token xoxb-1234567890-abcdefghij')
        self.assertEqual(self.calls, [])

    def test_send_result_lists_unresolved_names(self):
        self.ask()
        r = self.w.reply('C1', TS, 'thanks @alise')
        self.assertEqual(r['unresolved'], ['@alise'])
        self.assertEqual(self.w.status('C1', TS, 'hi @alise')['unresolved'], ['@alise'])

    def test_audit_row_written_with_the_session(self):
        self.ask()
        self.w.reply('C1', TS, 'hello')
        row = self.store.q('SELECT kind, session FROM audit')[0]
        self.assertEqual((row['kind'], row['session']), ('reply', 's1'))

    def test_react_is_audited_and_rate_limited(self):
        self.w.react('C1', TS, 'eyes')
        self.assertEqual(self.store.q("SELECT COUNT(*) c FROM audit WHERE kind='react'")[0]['c'], 1)
        for _ in range(25):
            try:
                self.w.react('C1', TS, 'eyes')
            except slack.Refused:
                break
        else:
            self.fail('never rate limited')

    def test_session_name_comes_from_agent_box_session_id(self):
        old = {k: os.environ.pop(k, None) for k in ('AGENT_BOX_SESSION', 'AGENT_BOX_SESSION_ID')}
        os.environ['AGENT_BOX_SESSION_ID'] = 'sid-1'
        try:
            w = slack.Writer(self.w.web, self.store, {}, {}, BOT)
            self.assertEqual(w.session, 'sid-1')
        finally:
            os.environ.pop('AGENT_BOX_SESSION_ID', None)
            for k, v in old.items():
                if v is not None:
                    os.environ[k] = v

    def test_own_posts_are_indexed_for_feedback(self):
        self.ask()
        self.w.reply('C1', TS, 'hello')
        r = self.store.q("SELECT user, thread_ts FROM msgs WHERE ts='1700000009.000900'")[0]
        self.assertEqual((r['user'], r['thread_ts']), ('UBOT', TS))

    def test_ambiguous_and_deactivated_names_are_not_resolved(self):
        members = [{'id': 'U1', 'name': 'sam'}, {'id': 'U2', 'name': 'sam'},
                   {'id': 'U3', 'name': 'gone', 'deleted': True}, {'id': 'U4', 'name': 'kim'}]
        self.w.web.call = lambda m, p=None, **kw: {'ok': True, 'members': members}
        self.assertIsNone(self.w.resolver('@', 'sam'))
        self.assertIsNone(self.w.resolver('@', 'gone'))
        self.assertEqual(self.w.resolver('@', 'kim'), 'U4')


class TestReviewRegressions(Rig):
    """Each of these reproduced by running the code in the PR #86 review."""

    DEF = slack._merge(slack.DEFAULT_DEFAULTS, {'links': {'allowed_hosts': ['slack.com', 'github.com']}})

    def c(self, text, write=None):
        cfg = slack._merge(slack.DEFAULT_CHANNEL, {'write': write or {}})
        return slack.compose(text, lambda *_: None, cfg, self.DEF)

    def test_broadcast_cannot_slip_past_a_backtick_or_unicode_boundary(self):
        for text in ('``@channel urgent', '`a`@here', '@here', 'x @everyone y'):
            with self.assertRaises(slack.Refused, msg=text):
                self.c(text)
        self.assertNotIn('<!', self.c('@channelé now'))
        self.assertEqual(self.c('@here hi', {'broadcast': True}), '<!here> hi')

    def test_link_allowlist_survives_backslash_and_userinfo(self):
        for url in ('https://evil.com\\@slack.com/x', 'https://evil.com\\.slack.com/x',
                    'https://user@slack.com/x', 'https://slack.com:99999999/x',
                    'https://\u0455lack.com/x', 'https://[::1]/x'):
            with self.assertRaises(slack.Refused, msg=url):
                self.c('see ' + url)

    def test_schemeless_links_are_checked(self):
        for text in ('see evil.com/?d=secret', 'see www.evil.org', 'mail mailto:a@evil.com'):
            with self.assertRaises(slack.Refused, msg=text):
                self.c(text)
        self.assertEqual(self.c('see github.com/o/r and README.md'), 'see github.com/o/r and README.md')

    def test_trailing_punctuation_stays_out_of_links(self):
        self.assertEqual(self.c('see https://github.com/x/y/pull/1.'),
                         'see <https://github.com/x/y/pull/1|github.com>.')
        self.assertEqual(self.c('(https://github.com/x), then https://github.com/y!'),
                         '(<https://github.com/x|github.com>), then <https://github.com/y|github.com>!')

    def test_bare_email_domain_is_checked(self):
        with self.assertRaises(slack.Refused):
            self.c('mail x@evil.com')
        self.assertEqual(self.c('mail x@github.com'), 'mail x@github.com')

    def test_unresolved_names_are_reported(self):
        cfg = slack._merge(slack.DEFAULT_CHANNEL, {})
        un = []
        out = slack.compose('hi @alise and #42 and @alise', lambda *_: None, cfg, self.DEF, un)
        self.assertEqual((out, un), ('hi @alise and #42 and @alise', ['@alise']))

    def test_kebab_case_is_not_a_secret(self):
        self.assertEqual(self.c('branch sk-feature-improve-the-login-flow-now'), 'branch sk-feature-improve-the-login-flow-now')
        with self.assertRaises(slack.Refused):
            self.c('key sk-' + 'a1' * 20)
        with self.assertRaises(slack.Refused):       # zero-width characters do not hide a token
            self.c('key AKIA\u200bABCDEFGHIJKLMNOP')

    def test_controllers_fail_closed_without_a_users_lookup(self):
        tr = slack.Tracker(self.store, {'C1': self.cfg}, BOT, lambda a, p: self.events.append((a, p)),
                           now=lambda: self.t[0])
        tr.handle(msg('1.1'))
        tr.handle(reaction('1.1', 'white_check_mark'))
        self.assertEqual(self.actions(), ['message.posted'])

    def test_users_lookup_fails_closed_on_error_and_reads_flags(self):
        class W:
            def call(s, m, p=None, **kw):
                if p['user'] == 'UERR':
                    raise slack.SlackError('boom')
                return {'user': {'is_restricted': p['user'] == 'UG', 'is_stranger': p['user'] == 'UX'}}
        look = slack.make_users_lookup(W())
        self.assertEqual(look('UERR'), {'guest': True, 'external': True})
        self.assertEqual(look('UG'), {'guest': True, 'external': False})
        self.assertEqual(look('UX'), {'guest': False, 'external': True})
        self.assertEqual(look('UM'), {'guest': False, 'external': False})

    def test_reads_are_form_encoded_and_writes_are_json(self):
        sent = []

        class R:
            def read(s):
                return b'{"ok": true}'

            def __enter__(s):
                return s

            def __exit__(s, *a):
                pass
        old = slack.urllib.request.urlopen
        slack.urllib.request.urlopen = lambda req, timeout=0: sent.append(req) or R()
        try:
            w = slack.Web('xoxb-test')
            w.call('conversations.replies', {'channel': 'C1', 'ts': '1.1', 'limit': 1})
            w.call('chat.postMessage', {'channel': 'C1', 'text': 'x'}, write=True)
        finally:
            slack.urllib.request.urlopen = old
        self.assertEqual(sent[0].get_header('Content-type'), 'application/x-www-form-urlencoded')
        self.assertIn(b'channel=C1', sent[0].data)
        self.assertTrue(sent[1].get_header('Content-type').startswith('application/json'))

    def test_a_failure_while_handling_does_not_burn_the_event_id(self):
        boom = [True]

        def emit(a, p):
            if boom[0]:
                raise RuntimeError('db')
            self.events.append((a, p))
        self.tr.emit = emit
        with self.assertRaises(RuntimeError):
            self.tr.handle(msg('1.1', eid='E1'))
        boom[0] = False
        self.tr.handle(msg('1.1', eid='E1'))      # Slack's redelivery is processed, not dropped
        self.assertEqual(self.actions(), ['message.posted'])

    def test_feedback_resolves_and_never_reopens_the_thread(self):
        self.defaults['feedback_reactions'] = ['+1']
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()                                   # settled
        self.tr.handle(msg('1.5', user='UBOT', thread_ts='1.1'))   # our own reply, indexed not counted
        self.assertEqual(self.actions().count('thread.settled'), 1)
        self.tr.handle(reaction('1.5', '+1'))
        self.assertEqual(self.actions()[-1], 'feedback')
        self.tr.handle(reaction('1.5', 'tada'))      # not a configured feedback reaction
        self.assertEqual(self.actions()[-1], 'reaction.added')
        self.assertTrue(self.events[-1][1]['on_bot_message'])
        self.assertNotIn('thread.reopened', self.actions())

    def test_merged_message_still_emits_and_a_mention_in_it_settles(self):
        self.cfg['merge_window_minutes'] = 10
        self.tr.handle(msg('1.1'))
        self.advance(60)
        self.tr.handle(msg('2.1', 'also <@UBOT> please'))
        self.assertEqual(self.actions(), ['message.posted', 'message.posted', 'thread.settled'])
        self.assertEqual(self.events[-1][1]['reason'], 'mention')

    def test_with_no_feedback_reactions_configured_a_thumb_is_a_plain_reaction(self):
        self.tr.handle(msg('1.1'))
        self.advance(601)
        self.tr.tick()
        self.tr.handle(msg('1.5', user='UBOT', thread_ts='1.1'))
        v = self.store.q('SELECT version FROM threads')[0]['version']
        self.tr.handle(reaction('1.5', '+1'))
        self.tr.handle(reaction('1.5', '+1', kind='reaction_removed'))
        self.assertEqual(self.actions()[-2:], ['reaction.added', 'reaction.removed'])
        self.assertTrue(all(p['on_bot_message'] for a, p in self.events[-2:]))
        self.assertNotIn('feedback', self.actions())
        self.assertEqual(self.store.q('SELECT version FROM threads')[0]['version'], v)   # never activity
        self.assertNotIn('thread.reopened', self.actions())

    def test_no_outward_action_without_config(self):
        self.tr.handle(msg('1.1', 'help <@UBOT>'))
        self.tr.handle(msg('2.1'))
        self.tr.handle(reaction('2.1', 'white_check_mark'))
        self.assertEqual(self.reacts, [])        # no ack: the daemon does not write by itself
        self.assertIn('thread.settled', self.actions())

    def test_activity_during_a_hold_moves_the_version(self):
        self.tr.handle(msg('1.1'))
        self.tr.handle(reaction('1.1', 'raised_hand'))
        v = self.store.q('SELECT version FROM threads')[0]['version']
        self.tr.handle(msg('1.2', thread_ts='1.1'))
        self.assertEqual(self.store.q('SELECT version FROM threads')[0]['version'], v + 1)

    def test_other_apps_bots_without_the_subtype_are_not_human_activity(self):
        self.tr.handle(msg('1.1', user=None, bot_id='BOTHER'))
        self.assertEqual(self.events, [])

    def test_external_channels_need_an_opt_in_and_survive_restart(self):
        self.tr.prime('C1', {'is_ext_shared': True, 'is_member': True})
        self.tr.handle(msg('1.1'))
        self.assertEqual(self.events, [])
        self.cfg['allow_external'] = True
        self.tr.handle(msg('1.2'))
        self.assertTrue(self.events[0][1]['external'])

    def test_bot_rejoining_a_channel_resumes_tracking(self):
        self.tr.handle({'team_id': 'T1', 'event_id': 'l1', 'event': {
            'type': 'member_left_channel', 'channel': 'C1', 'user': 'UBOT'}})
        self.tr.handle(msg('1.1'))
        self.assertEqual(self.events, [])
        self.tr.handle({'team_id': 'T1', 'event_id': 'j1', 'event': {
            'type': 'member_joined_channel', 'channel': 'C1', 'user': 'UBOT'}})
        self.tr.handle(msg('1.2'))
        self.assertEqual(self.actions(), ['message.posted'])

    def test_a_dead_bus_leaves_the_outbox_rows(self):
        self.store.outbox_put('thread.settled', {'team': 'T', 'channel': 'C', 'n': 1})
        self.store.outbox_put('thread.settled', {'team': 'T', 'channel': 'C', 'n': 2})
        self.assertEqual(slack.drain_outbox(self.store, lambda a, p: False), 0)
        self.assertEqual(self.store.q('SELECT COUNT(*) c FROM outbox')[0]['c'], 2)
        got = []
        self.assertEqual(slack.drain_outbox(self.store, lambda a, p: got.append(p['n']) or True), 2)
        self.assertEqual(got, [1, 2])        # in order, then gone
        self.assertIsNone(self.store.outbox_next())


class TestBusRouting(unittest.TestCase):
    """An emitted payload must be routable by a `slack:T/C` subscription once
    the source has keyPath `route` -- the thing that made nothing reach a
    session in the first cut."""

    def test_emitted_payload_matches_a_channel_subscription(self):
        wspec = importlib.util.spec_from_file_location('webhook_for_slack', os.path.join(REPO, 'local-webhook', 'webhook.py'))
        d = tempfile.mkdtemp()
        os.environ['LOCAL_WEBHOOK_STATE_DIR'] = d
        try:
            webhook = importlib.util.module_from_spec(wspec)
            wspec.loader.exec_module(webhook)
        finally:
            del os.environ['LOCAL_WEBHOOK_STATE_DIR']
        captured = []
        old = slack.subprocess.run
        slack.subprocess.run = lambda cmd, input=None, **kw: captured.append((cmd, input)) or type('R', (), {'returncode': 0})()
        os.environ['LOCAL_SLACK_EMIT'] = 'webhook.py emit'
        try:
            self.assertTrue(slack.make_emitter()('thread.settled', {'team': 'T0123', 'channel': 'C0456', 'thread': '1.1'}))
        finally:
            slack.subprocess.run = old
            del os.environ['LOCAL_SLACK_EMIT']
        cmd, body = captured[0]
        self.assertEqual(cmd, ['webhook.py', 'emit', 'slack', '-', '--event', 'thread.settled'])   # payload on stdin, not argv
        payload = json.loads(body)
        key = webhook.get_path(payload, 'route')           # the README's keyPath
        self.assertEqual(key, 'T0123/C0456')
        self.assertTrue(webhook.match_topic('slack', key, 'slack:T0123/C0456'))
        self.assertFalse(webhook.match_topic('slack', key, 'slack:T0123/C9999'))

    def test_cache_lookup_picks_the_newest_version_and_checkout_wins(self):
        with tempfile.TemporaryDirectory() as home:
            for v in ('0.9.0', '0.27.1', '0.10.0'):
                d = os.path.join(home, '.claude/plugins/cache/local-channels/local-webhook', v)
                os.makedirs(d)
                open(os.path.join(d, 'webhook.py'), 'w').close()
            old_home, old_file = os.environ.get('HOME'), slack.__file__
            os.environ['HOME'] = home
            slack.__file__ = os.path.join(home, 'elsewhere', 'slack.py')     # no sibling checkout
            try:
                self.assertIn('0.27.1', slack.find_webhook_py())            # not 0.9.0 or 0.10.0
            finally:
                slack.__file__ = old_file
                if old_home is None:
                    os.environ.pop('HOME', None)
                else:
                    os.environ['HOME'] = old_home
        self.assertTrue(slack.find_webhook_py().startswith(REPO))           # the checkout, no walk

    def test_emit_command_is_resolved_once(self):
        calls = []
        old_cmd, old_run = slack.emit_command, slack.subprocess.run
        slack.emit_command = lambda: calls.append(1) or ['x', 'emit']
        slack.subprocess.run = lambda cmd, **kw: type('R', (), {'returncode': 0})()
        try:
            e = slack.make_emitter()
            for _ in range(5):
                e('a', {'team': 'T', 'channel': 'C'})
        finally:
            slack.emit_command, slack.subprocess.run = old_cmd, old_run
        self.assertEqual(len(calls), 1)

    def test_default_emit_command_is_one_that_exists(self):
        os.environ.pop('LOCAL_SLACK_EMIT', None)
        cmd = slack.emit_command()
        self.assertEqual(cmd[1:], [os.path.normpath(os.path.join(REPO, 'local-webhook', 'webhook.py')), 'emit'])
        self.assertTrue(os.path.isfile(cmd[1]))


class TestCliSmoke(unittest.TestCase):
    def test_usage(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(slack.main(['--help']), 0)
        self.assertIn('slack.py daemon', buf.getvalue())

    def test_channel_edit_refuses_a_corrupt_file_and_keeps_hand_tuning(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'c.json')
            open(p, 'w').write('{"C1": {"controllers": ["U1"], "write": {"allowed": true, "mode": "always"}}, "C2": {}')
            with self.assertRaises(slack.Refused):
                slack.channel_add('C3', [], None, p)
            self.assertIn('"C2"', open(p).read())            # untouched
            open(p, 'w').write('{"C1": {"controllers": ["U1"], "write": {"allowed": true, "mode": "always"}}, "C2": {}}')
            slack.channel_add('C1', ['--quiet', '5'], None, p)
            raw = json.load(open(p))
            self.assertEqual(raw['C1']['controllers'], ['U1'])
            self.assertEqual(raw['C1']['write']['mode'], 'always')
            self.assertEqual(raw['C1']['quiet_minutes'], 5)
            self.assertIn('C2', raw)
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_channel_add_checks_membership_and_connect(self):
        class W:
            def __init__(s, info):
                s.info = info

            def call(s, m, p=None, **kw):
                return {'channel': s.info}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'c.json')
            with self.assertRaises(slack.Refused):
                slack.channel_add('C1', [], W({'is_member': False}), p)
            with self.assertRaises(slack.Refused):
                slack.channel_add('C1', [], W({'is_member': True, 'is_ext_shared': True}), p)
            slack.channel_add('C1', ['--allow-external'], W({'is_member': True, 'is_ext_shared': True}), p)
            self.assertTrue(json.load(open(p))['C1']['allow_external'])

    def test_channel_add_rm(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ['LOCAL_SLACK_CONFIG'] = os.path.join(d, 'c.json')
            os.environ['LOCAL_SLACK_STATE_DIR'] = d
            try:
                self.assertEqual(slack.main(['channel', 'add', 'C5', '--track', 'mention', '--quiet', '7', '--write']), 0)
                ch, _ = slack.load_config()
                self.assertEqual((ch['C5']['track'], ch['C5']['quiet_minutes'], ch['C5']['write']['allowed']),
                                 ('mention', 7, True))
                self.assertEqual(slack.main(['channel', 'rm', 'C5']), 0)
                self.assertEqual(slack.load_config()[0], {})
            finally:
                del os.environ['LOCAL_SLACK_CONFIG'], os.environ['LOCAL_SLACK_STATE_DIR']


if __name__ == '__main__':
    unittest.main()
