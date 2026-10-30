"""PR claims follow only their own authenticated merge commit (#62)."""
import copy
import json
import os
import threading

from test_webhook import EndToEndCase, StateDirCase, ANY_EVENT


SHA = 'a' * 40
OTHER_SHA = 'b' * 40
SCOPE = {'any': [{'path': 'pull_request.number', 'in': [42]},
                 {'path': 'issue.number', 'in': [42]}]}
POLICY = {'any': [{'path': 'action', 'in': ['closed']},
                  {'path': 'workflow_run.conclusion', 'in': ['failure']},
                  {'path': 'workflow_job.conclusion', 'in': ['failure']},
                  {'path': 'check_run.conclusion', 'in': ['failure']},
                  {'path': 'check_suite.conclusion', 'in': ['failure']},
                  {'path': 'deployment_status.state', 'in': ['failure']},
                  {'path': 'state', 'in': ['failure']}]}
CLAIM = {'all': [SCOPE, POLICY]}


def merged(at, sha=SHA, number=42):
    return {'repository': {'full_name': 'o/r'}, 'sender': {'login': 'owner'},
            'action': 'closed', 'pull_request': {
                'number': number, 'merged': True, 'merge_commit_sha': sha,
                'merged_at': at, 'title': 'merge', 'base': {'ref': 'main'}}}


def ci(event='workflow_run', sha=SHA, outcome='failure'):
    p = {'repository': {'full_name': 'o/r'}, 'sender': {'login': 'owner'},
         'action': 'completed'}
    if event == 'deployment_status':
        p.update(deployment={'sha': sha, 'ref': 'main'}, deployment_status={'state': outcome})
    elif event == 'status':
        p.update(sha=sha, state=outcome)
    else:
        p[event] = {'head_sha': sha, 'head_branch': 'main', 'conclusion': outcome,
                    'status': 'completed', 'name': event}
    return p


class TestMergeFollow(StateDirCase):
    def setUp(self):
        super().setUp()
        self.t = self.mod.now_ms()
        self.mod.now_ms = lambda: self.t
        self.stamp = self.mod.iso_at(self.t)

    def subscribe(self, include=CLAIM, **kwargs):
        text = self.call('webhook_subscribe', topic='o/r', include=include,
                         exclude={'path': 'event', 'in': ['pull_request']}, **kwargs)
        self.assertNotIn('error:', text)

    def env(self, event='pull_request', payload=None, delivery='merge'):
        return dict(source='github', format='github', key='o/r', sender='owner',
                    event=event, delivery=delivery,
                    payload=payload if payload is not None else merged(self.stamp))

    def learn(self, env=None):
        return self.mod.learn_merge(env or self.env(), self.t)

    def accepts(self, event='workflow_run', sha=SHA, outcome='failure', env=None):
        return self.mod.filter_accepts(self.mod.FILTER_FILE,
                                       env or self.env(event, ci(event, sha, outcome)))

    def test_all_six_shapes_preserve_policy_and_ownership(self):
        self.subscribe()
        self.assertFalse(self.accepts())
        self.assertTrue(self.learn())  # close delivery is excluded, scope maintenance is not
        raw = self.read_json('filter.testsess.json')['topics'][0]
        self.assertEqual(raw['include'], CLAIM)
        self.assertNotIn('main', json.dumps(raw['mergeCommits']))
        for event in self.mod.MERGE_SHA_PATHS:
            with self.subTest(event=event):
                p = ci(event)
                self.assertTrue(self.accepts(event))
                self.assertTrue(self.mod.filter_claims(self.mod.FILTER_FILE, 'github', 'o/r',
                                                       'owner', event, p))
                self.assertFalse(self.accepts(event, outcome='success'))
                self.assertFalse(self.accepts(event, sha=OTHER_SHA))
                other = self.env(event, p)
                other['key'] = 'o/other'
                self.assertFalse(self.accepts(env=other))
                other['key'], other['source'] = 'o/r', 'foreign'
                self.assertFalse(self.accepts(env=other))

    def test_issue_only_branch_negative_and_observer_never_invent_a_pr(self):
        for pred in ({'path': 'issue.number', 'in': [42]},
                     {'path': 'pull_request.head.ref', 'in': ['topic']},
                     {'path': 'pull_request.number', 'notIn': [43]}, ANY_EVENT):
            with self.subTest(pred=pred):
                self.subscribe(include=pred)
                self.assertFalse(self.learn())
                self.assertNotIn('mergeCommits', self.read_json('filter.testsess.json')['topics'][0])

    def test_explicit_pr_claim_and_bare_number_have_same_merge_authority(self):
        self.subscribe(include={'all': [{'path': 'pull_request.number', 'in': [42]}, POLICY]})
        self.assertTrue(self.learn())
        self.assertTrue(self.accepts())
        self.assertFalse(self.learn(self.env(payload=merged(self.stamp, number=43))))

    def test_invalid_or_nonmerge_payloads_do_not_change_scope(self):
        self.subscribe()
        base = self.env()
        variants = []
        for field, value in [('number', True), ('number', '42'), ('merged', 1),
                             ('merged', False), ('merge_commit_sha', 'main'),
                             ('merge_commit_sha', 'a' * 39), ('merge_commit_sha', None),
                             ('merged_at', 'bad'), ('merged_at', None)]:
            e = copy.deepcopy(base)
            e['payload']['pull_request'][field] = value
            variants.append(e)
        for field, value in [('format', 'generic'), ('event', 'issues'), ('key', '')]:
            variants.append(dict(base, **{field: value}))
        e = copy.deepcopy(base)
        e['payload']['action'] = 'opened'
        variants.append(e)
        for e in variants:
            with self.subTest(env=e):
                self.assertFalse(self.learn(e))
                self.assertFalse(self.accepts())

    def test_expiry_is_fixed_by_merge_time_replay_cannot_renew_it(self):
        self.subscribe(ttl_hours=8, renew_on_event=True)
        self.assertTrue(self.learn())
        self.t += self.mod.MERGE_TTL_MS - 1
        self.assertTrue(self.learn())
        self.assertTrue(self.accepts())
        self.t += 2
        self.assertFalse(self.accepts())
        self.assertFalse(self.learn())
        self.assertFalse(self.accepts())

    def test_sender_exclude_and_disabled_expired_filters_still_win(self):
        self.subscribe(ignore_senders=['owner'])
        self.assertTrue(self.learn())
        self.assertFalse(self.mod.filter_claims(self.mod.FILTER_FILE, 'github', 'o/r',
                                               'owner', 'workflow_run', ci()))
        self.assertFalse(self.mod.route_event('github', 'o/r', 'owner', 'workflow_run', ci())['forward'])
        raw = self.read_json('filter.testsess.json')
        raw['enabled'] = False
        self.write_json('filter.testsess.json', raw)
        self.assertFalse(self.accepts())
        self.assertFalse(self.learn())
        raw['enabled'] = True
        self.write_json('filter.testsess.json', raw)
        self.t += 3600 * 1000 + 1
        self.assertFalse(self.accepts())

    def test_restart_renew_and_scope_replacement(self):
        self.subscribe()
        self.learn()
        self.mod = self.load()
        self.assertTrue(self.accepts())
        self.call('webhook_subscribe', topic='o/r', note='renewed')
        self.assertTrue(self.accepts())
        # Replacing explicit PR scope removes its authority even if learned
        # metadata survives the write; no unconditional OR may resurrect it.
        self.call('webhook_subscribe', topic='o/r', include={'path': 'issue.number', 'in': [43]})
        self.assertFalse(self.accepts())
        self.call('webhook_unsubscribe', topic='o/r')
        self.subscribe()
        self.assertFalse(self.accepts())

    def test_prefix_claim_cannot_leak_learned_sha_to_another_repo(self):
        self.call('webhook_subscribe', topic='o/*', include=CLAIM, exclude={})
        self.assertTrue(self.learn())
        self.assertTrue(self.accepts())
        env = self.env('workflow_run', ci())
        env['key'] = 'o/second'
        self.assertFalse(self.accepts(env=env))

    def test_named_entries_and_concurrent_writers_keep_scope(self):
        self.subscribe(name='one')
        self.subscribe(name='two')
        gate = threading.Barrier(2)
        def renew():
            gate.wait()
            self.call('webhook_subscribe', topic='o/r', name='two', note='renewed')
        thread = threading.Thread(target=renew)
        thread.start()
        gate.wait()
        self.learn()
        thread.join(5)
        rows = self.read_json('filter.testsess.json')['topics']
        self.assertEqual([r['name'] for r in rows], ['one', 'two'])
        self.assertEqual(rows[1]['note'], 'renewed')
        self.assertTrue(all(len(r['mergeCommits']) == 1 for r in rows))

    def test_expired_scope_does_not_change_routing_of_previously_accepted_backlog(self):
        self.subscribe(ttl_hours=8)
        self.learn()
        accepted = self.t
        self.t += self.mod.MERGE_TTL_MS + 1
        self.assertFalse(self.accepts())
        for _ in range(2):
            self.assertTrue(self.mod.route_event('github', 'o/r', 'owner', 'status',
                                                ci('status'), at=accepted)['forward'])
        self.assertFalse(self.accepts())

    def test_corrupt_learned_state_is_ignored_and_state_is_bounded(self):
        self.subscribe()
        raw = self.read_json('filter.testsess.json')
        row = dict(source='github', key='o/r', number=42, sha=SHA, mergedAt=self.stamp)
        for invalid in (None, 'oops', {'number': 42}, [dict(row, sha='main')],
                        [dict(row, number=True)], [dict(row, mergedAt='bad')]):
            raw['topics'][0]['mergeCommits'] = invalid
            self.write_json('filter.testsess.json', raw)
            self.assertFalse(self.accepts())
        self.subscribe(include={'path': 'pull_request.number', 'in': list(range(1, 70))})
        for n in range(1, 70):
            self.learn(self.env(payload=merged(self.stamp, number=n)))
        self.assertEqual(len(self.read_json('filter.testsess.json')['topics'][0]['mergeCommits']),
                         self.mod.MERGE_MAX)

    def test_learning_write_failure_is_retried_from_the_durable_inbox(self):
        self.subscribe()
        env = self.env()
        sid, at = self.mod.spool_accept(env, 'merge')
        write = self.mod.write_filter
        def broken(*args):
            raise OSError('disk full')
        self.mod.write_filter = broken
        with self.assertRaises(OSError):
            self.mod.spool_process(sid, env, at, live=False, enqueue=False)
        self.assertTrue(os.path.exists(self.mod._inbox_path('new', sid)))
        self.mod.write_filter = write
        self.mod.spool_recover()
        self.assertTrue(self.accepts())
        self.assertFalse(os.path.exists(self.mod._inbox_path('new', sid)))

    def test_concurrent_independent_module_writers_do_not_clobber_merge_state(self):
        self.subscribe()
        peer = self.load()
        entered, release = threading.Event(), threading.Event()
        original = self.mod.write_filter
        errors = []
        def pause_write(*args):
            entered.set()
            release.wait(5)
            original(*args)
        self.mod.write_filter = pause_write
        def learn():
            try:
                self.learn()
            except Exception as e:
                errors.append(e)
        thread = threading.Thread(target=learn)
        thread.start()
        self.assertTrue(entered.wait(5))
        done = threading.Event()
        def renew():
            try:
                peer.call_tool({'name': 'webhook_subscribe', 'arguments': {'topic': 'o/r', 'note': 'new note'}})
            except Exception as e:
                errors.append(e)
            finally:
                done.set()
        writer = threading.Thread(target=renew)
        writer.start()
        try:
            self.assertFalse(done.wait(0.1), 'writer bypassed the cross-process lock')
        finally:
            release.set()
        thread.join(5)
        writer.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(writer.is_alive())
        self.assertEqual(errors, [])
        row = self.read_json('filter.testsess.json')['topics'][0]
        self.assertEqual(row['note'], 'new note')
        self.assertEqual(len(row['mergeCommits']), 1)

    def accept(self, env):
        sid, at = self.mod.spool_accept(env, env['delivery'])
        self.mod.spool_process(sid, env, at, live=False, enqueue=False)
        return sid

    def test_ci_before_merge_survives_restart_and_is_fanned_once(self):
        self.subscribe()
        env = self.env('status', ci('status'), delivery='early')
        sid = self.accept(env)
        self.assertTrue(os.path.exists(self.mod._inbox_path('new', sid)))
        self.assertEqual(self.mod.peer_queue('testsess').names(), [])
        self.mod = self.load()
        self.accept(self.env())
        self.assertEqual(self.mod.peer_queue('testsess').names(), [sid])
        self.assertIsNone(self.mod.spool_accept(env, 'early'))
        self.assertFalse(os.path.exists(self.mod._inbox_path('new', sid)))
        self.mod.peer_queue('testsess').drop(sid)
        self.mod.spool_recover()
        self.assertEqual(self.mod.peer_queue('testsess').names(), [])

    def test_grace_times_out_without_inventing_scope(self):
        self.subscribe()
        env = self.env('workflow_run', ci(), delivery='no-merge')
        sid = self.accept(env)
        self.t += self.mod.MERGE_CI_GRACE_MS + 1
        self.mod.resume_inbox('new', sid, enqueue=False)
        self.assertFalse(os.path.exists(self.mod._inbox_path('new', sid)))
        self.assertEqual(self.mod.peer_queue('testsess').names(), [])
        self.assertFalse(self.accepts())

    def test_unrelated_or_policy_filtered_ci_is_not_woken_by_merge(self):
        self.subscribe()
        sid = self.accept(self.env('status', ci('status', OTHER_SHA), delivery='other'))
        success = self.accept(self.env('status', ci('status', outcome='success'), delivery='success'))
        self.assertFalse(os.path.exists(self.mod._inbox_path('new', success)))
        self.accept(self.env())
        self.assertTrue(os.path.exists(self.mod._inbox_path('new', sid)))
        self.assertEqual(self.mod.peer_queue('testsess').names(), [])


class TestMergeFollowEndToEnd(EndToEndCase):
    INITIALIZED = b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'

    def subscribe(self):
        r = self.cli('subscribe', 'o/r', '--include', json.dumps(CLAIM),
                     '--exclude', json.dumps({'path': 'event', 'in': ['pull_request']}), session='owner')
        self.assertEqual(r.returncode, 0, r.stderr)

    def ready_peer(self):
        peer = self.start_peer('owner')
        peer.stdin.write(self.INITIALIZED)
        peer.stdin.flush()
        return peer

    def no_line(self, peer, seconds=0.4):
        import select
        return not select.select([peer.stdout], [], [], seconds)[0]

    def stamp(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def stop_daemon(self, d):
        d.kill()
        d.wait()
        os.unlink(self.http_sock)

    def test_signed_merge_and_all_six_ci_shapes_reach_real_peer(self):
        self.subscribe()
        self.start_daemon(LOCAL_WEBHOOK_SPAWN_WINDOW='0')
        peer = self.ready_peer()
        self.assertEqual(self.post(merged(self.stamp()), event='pull_request')[0], 200)
        self.assertTrue(self.no_line(peer))
        for event in ('workflow_run', 'workflow_job', 'check_run', 'check_suite', 'deployment_status', 'status'):
            with self.subTest(event=event):
                self.assertEqual(self.post(ci(event), event=event, delivery=event), (200, 'ok'))
                msg = self.read_peer_line(peer)
                self.assertEqual(msg['params']['meta']['event'], event)
                self.assertIn('[UNTRUSTED webhook:github', msg['params']['content'])
                self.assertEqual(self.post(ci(event), event=event, delivery=event), (200, 'ok (duplicate)'))
                self.assertTrue(self.no_line(peer))
        self.assertEqual(self.post(ci(outcome='success'), event='workflow_run')[0], 200)
        self.assertTrue(self.no_line(peer))
        self.assertEqual(self.post(ci(sha=OTHER_SHA), event='workflow_run')[0], 200)
        self.assertTrue(self.no_line(peer))

    def test_ci_first_merge_later_restart_and_dispatch_ownership(self):
        self.subscribe()
        r = self.cli('subscribe', 'o/r', '--deliver-to', 'subagent', '--include', json.dumps({'any': POLICY['any'][1:]}))
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.start_daemon(LOCAL_WEBHOOK_SPAWN_WINDOW='0')
        peer = self.ready_peer()
        self.assertEqual(self.post(ci('status'), event='status', delivery='early')[0], 200)
        self.assertTrue(self.no_line(peer))
        self.assertFalse(os.path.exists(self.spawn_log))
        self.stop_daemon(d)
        self.start_daemon(LOCAL_WEBHOOK_SPAWN_WINDOW='0')
        self.assertEqual(self.post(merged(self.stamp()), event='pull_request', delivery='merge')[0], 200)
        msg = self.read_peer_line(peer)
        self.assertEqual(msg['params']['meta']['event'], 'status')
        self.assertFalse(os.path.exists(self.spawn_log), 'post-merge CI started a duplicate worker')
        self.assertEqual(self.post(ci('status'), event='status', delivery='early'), (200, 'ok (duplicate)'))
        self.assertTrue(self.no_line(peer))
        # The next unrelated main commit remains unclaimed and can dispatch.
        self.assertEqual(self.post(ci('status', OTHER_SHA), event='status', delivery='next')[0], 200)
        # Skip the real one-minute wait by backdating only this accepted
        # test record; the normal reaper must finish it without a merge.
        inbox = os.path.join(self.state, 'spool', 'inbox', 'new', 'github~next')
        with open(inbox, encoding='utf-8') as f:
            rec = json.load(f)
        rec['acceptedMs'] -= 61000
        with open(inbox, 'w', encoding='utf-8') as f:
            json.dump(rec, f)
        self.stop_daemon(self.procs[-1])
        self.start_daemon(LOCAL_WEBHOOK_SPAWN_WINDOW='0')
        self.assertTrue(self.wait_file(self.spawn_log, contains='status'))
        self.assertTrue(self.no_line(peer))

    def test_bad_signature_cannot_establish_scope_and_offline_owner_learns(self):
        self.subscribe()
        d = self.start_daemon()
        self.assertEqual(self.post(merged(self.stamp()), event='pull_request', sig='wrong')[0], 401)
        with open(os.path.join(self.state, 'filter.owner.json'), encoding='utf-8') as f:
            self.assertNotIn('mergeCommits', json.load(f)['topics'][0])
        self.assertEqual(self.post(merged(self.stamp()), event='pull_request')[0], 200)
        self.stop_daemon(d)
        self.start_daemon()
        self.assertEqual(self.post(ci(), event='workflow_run')[0], 200)
        peer = self.ready_peer()
        self.assertEqual(self.read_peer_line(peer)['params']['meta']['event'], 'workflow_run')
        self.assertTrue(self.no_line(peer))

    def test_merge_first_works_without_durable_spool(self):
        self.subscribe()
        self.start_daemon(LOCAL_WEBHOOK_SPOOL='off')
        peer = self.ready_peer()
        self.assertEqual(self.post(merged(self.stamp()), event='pull_request')[0], 200)
        self.assertTrue(self.no_line(peer))
        self.assertEqual(self.post(ci('status'), event='status')[0], 200)
        self.assertEqual(self.read_peer_line(peer)['params']['meta']['event'], 'status')
        self.assertEqual(self.post(ci('status', OTHER_SHA), event='status')[0], 200)
        self.assertTrue(self.no_line(peer))
