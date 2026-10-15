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
        self.tr = slack.Tracker(
            self.store, {'C1': self.cfg}, BOT, lambda a, p: self.events.append((a, p)),
            now=lambda: self.t[0], react=lambda c, ts, e: self.reacts.append((c, ts, e)),
            lookup=lambda c, ts: self.extra.get(ts))

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

    def test_mention_settles_immediately_and_acks(self):
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
        self.tr.handle(msg('1.1'))
        self.store.x('INSERT INTO msgs VALUES (?,?,?,?,?,?,?)', 'T1', 'C1', '1.5', '1.1', 'UBOT', 0, 0)
        self.tr.handle(reaction('1.5', '+1'))
        self.assertEqual(self.actions()[-1], 'feedback')

    def test_channel_shared_flags_external(self):
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

    def test_unknown_mention_is_an_error(self):
        with self.assertRaises(slack.Refused):
            self.c('hi @nobody')

    def test_smuggled_token_is_refused_or_escaped(self):
        self.assertEqual(self.c('quoted &lt;!channel&gt;'), 'quoted &amp;lt;!channel&amp;gt;')
        with self.assertRaises(slack.Refused):
            self.c('<!channel> hello')
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

    def test_reads_survive_a_write_burst(self):
        t = [0.0]
        b = slack.Bucket(45, now=lambda: t[0])
        wrote = sum(1 for _ in range(100) if b.take(True))
        self.assertLess(wrote, 45)            # 40% reserved
        self.assertTrue(b.take(False))        # a read still succeeds
        self.assertGreater(b.limited, 0)


class TestWriter(unittest.TestCase):
    def setUp(self):
        self.calls = []

        class W:
            def call(s, method, params=None, **kw):
                self.calls.append((method, params))
                return {'ok': True, 'ts': '9.9', 'members': [], 'channels': []}
        self.store = slack.Store(':memory:')
        self.cfg = slack._merge(slack.DEFAULT_CHANNEL, {'write': {'allowed': True}})
        self.w = slack.Writer(W(), self.store, {'C1': self.cfg},
                              slack._merge(slack.DEFAULT_DEFAULTS, {}), BOT, session='s1')

    def test_on_request_blocks_reply_until_asked(self):
        with self.assertRaises(slack.Refused):
            self.w.reply('C1', '1.1', 'hello')
        self.store.x("INSERT INTO threads VALUES ('k','T1','C1','1.1','',0,0,0,1,'settled',NULL,1,'','0','',0,0,1)")
        self.w.reply('C1', '1.1', 'hello')
        m, p = self.calls[-1]
        self.assertEqual((m, p['thread_ts'], p['unfurl_links'], p['unfurl_media']),
                         ('chat.postMessage', '1.1', False, False))
        self.assertTrue(p['text'].endswith(slack.DEFAULT_DEFAULTS['disclosure']))
        self.assertNotIn('parse', p)

    def test_unconfigured_or_readonly_channel_refused(self):
        with self.assertRaises(slack.Refused):
            self.w.react('C9', '1.1', 'eyes')
        self.cfg['write']['allowed'] = False
        with self.assertRaises(slack.Refused):
            self.w.react('C1', '1.1', 'eyes')

    def test_top_level_needs_flag_and_is_rate_limited(self):
        with self.assertRaises(slack.Refused):
            self.w.post('C1', 'hi')
        self.cfg['write']['top_level'] = True
        for _ in range(5):
            self.w.post('C1', 'hi')
        with self.assertRaises(slack.Refused):
            self.w.post('C1', 'hi')

    def test_status_creates_then_edits_one_message(self):
        self.w.status('C1', '1.1', 'working')
        self.w.status('C1', '1.1', 'finished', 'done')
        self.assertEqual([m for m, _ in self.calls], ['chat.postMessage', 'chat.update'])
        self.assertTrue(self.calls[-1][1]['text'].startswith('✅'))

    def test_secret_in_outgoing_text_refused_and_never_sent(self):
        self.store.x("INSERT INTO threads VALUES ('k','T1','C1','1.1','',0,0,0,1,'settled',NULL,1,'','0','',0,0,1)")
        with self.assertRaises(slack.Refused):
            self.w.reply('C1', '1.1', 'token xoxb-1234567890-abcdefghij')
        self.assertEqual(self.calls, [])

    def test_audit_row_written(self):
        self.store.x("INSERT INTO threads VALUES ('k','T1','C1','1.1','',0,0,0,1,'settled',NULL,1,'','0','',0,0,1)")
        self.w.reply('C1', '1.1', 'hello')
        self.assertEqual(self.store.q('SELECT kind, session FROM audit')[0]['kind'], 'reply')


class TestCliSmoke(unittest.TestCase):
    def test_usage(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(slack.main(['--help']), 0)
        self.assertIn('slack.py daemon', buf.getvalue())

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
