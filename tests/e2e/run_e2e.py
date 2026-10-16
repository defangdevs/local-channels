"""End-to-end test of local-slack (PR #86) against a mock Slack and an isolated
local-webhook bus with a real MCP session peer. Nothing touches the network or
this box's live receiver: every path is under E2E_DIR."""
import atexit, json, os, queue, shutil, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get('REPO') or os.path.dirname(os.path.dirname(HERE))  # place under <repo>/tests/e2e/
WEBHOOK = os.path.join(REPO, 'local-webhook', 'webhook.py')
E2E = tempfile.mkdtemp(prefix='lse2e-', dir='/tmp')   # short: AF_UNIX paths are capped near 108 bytes
if not os.environ.get('LSE2E_KEEP'):   # set LSE2E_KEEP=1 to keep logs for debugging
    atexit.register(shutil.rmtree, E2E, True)
sys.path.insert(0, HERE)
import mock_slack  # noqa: E402
CHILDREN = []
atexit.register(lambda: [c.kill() for c in CHILDREN if c.poll() is None])

LW, LS = os.path.join(E2E, 'lw'), os.path.join(E2E, 'ls')
for d in (LW, LS):
    os.makedirs(d, mode=0o700, exist_ok=True)
SOCK = os.path.join(LW, 'ingress.sock')
SPAWN_LOG = os.path.join(E2E, 'spawned.log')
CFG = os.path.join(LS, 'channels.json')

results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))
    print(('PASS ' if ok else 'FAIL ') + name + (('  — ' + detail) if detail else ''), flush=True)


# ---------------------------------------------------------------- the bus
with open(os.path.join(LW, 'slack.secret'), 'w') as f:
    f.write('e2e-secret-0123456789abcdef')
with open(os.path.join(LW, 'sources.json'), 'w') as f:
    json.dump({'sources': {'slack': {'secretFile': 'slack.secret', 'format': 'generic', 'keyPath': 'route'}},
               'defaultSource': 'slack'}, f)

base_env = {k: v for k, v in os.environ.items() if not k.startswith(('LOCAL_WEBHOOK', 'SLACK_', 'LOCAL_SLACK'))}
lw_env = dict(base_env, LOCAL_WEBHOOK_STATE_DIR=LW)
recv = subprocess.Popen([sys.executable, WEBHOOK],
                        env=dict(lw_env, LOCAL_WEBHOOK_RECEIVER_ONLY='1', LOCAL_WEBHOOK_HTTP_SOCK=SOCK,
                                 LOCAL_WEBHOOK_SPAWN_CMD='cat >> %s; echo "=== END SPAWN" >> %s' % (SPAWN_LOG, SPAWN_LOG),
                                 LOCAL_WEBHOOK_SPAWN_WINDOW='0'),
                        stderr=open(os.path.join(E2E, 'receiver.err'), 'w'))
CHILDREN.append(recv)
for _ in range(50):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)
check('isolated local-webhook receiver is listening', os.path.exists(SOCK), SOCK)

# A simulated agent session: webhook.py as an MCP stdio peer.
peer = subprocess.Popen([sys.executable, WEBHOOK], env=dict(lw_env, LOCAL_WEBHOOK_SESSION='e2e', LOCAL_WEBHOOK_PORT='0'),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(os.path.join(E2E, 'peer.err'), 'w'),
                        text=True, bufsize=1)
CHILDREN.append(peer)
peer_out = queue.Queue()
threading.Thread(target=lambda: [peer_out.put(json.loads(l)) for l in peer.stdout if l.strip()], daemon=True).start()
notes, replies = [], {}


def pump(t=0.0):
    end = time.time() + t
    while True:
        try:
            m = peer_out.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            if time.time() >= end:
                return
            continue
        if m.get('method') == 'notifications/claude/channel':
            notes.append(m['params'])
        elif 'id' in m:
            replies[m['id']] = m


def rpc(i, method, params):
    peer.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params}) + '\n')
    peer.stdin.flush()
    end = time.time() + 10
    while i not in replies and time.time() < end:
        pump(0.2)
    return replies.get(i)


rpc(1, 'initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'e2e', 'version': '0'}})
peer.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n'); peer.stdin.flush()
r = rpc(2, 'tools/call', {'name': 'webhook_subscribe', 'arguments': {'topic': 'slack:T1/C1', 'note': 'e2e: #dev'}})
check('session peer subscribed to slack:T1/C1', r and 'error' not in json.dumps(r).lower()[:200], json.dumps(r)[:160])
r = rpc(3, 'tools/call', {'name': 'webhook_subscribe', 'arguments': {'topic': 'slack:T1/C2', 'note': 'e2e: #random (unconfigured)'}})
r = rpc(4, 'tools/call', {'name': 'webhook_subscribe', 'arguments': {
    'topic': 'slack:T1/C1', 'deliver_to': 'subagent', 'name': 'settled',
    'include': {'path': 'action', 'in': ['thread.settled']}, 'note': 'e2e watch: settled threads'}})
check('standing watch on thread.settled created', r and 'error' not in json.dumps(r).lower()[:200], json.dumps(r)[:160])

# ---------------------------------------------------------------- Slack + local-slack
mock, mock_url = mock_slack.start()
ls_env = dict(base_env, REPO=REPO, MOCK_SLACK=mock_url, LOCAL_SLACK_STATE_DIR=LS, LOCAL_SLACK_CONFIG=CFG,
              LOCAL_WEBHOOK_STATE_DIR=LW, LOCAL_WEBHOOK_HTTP_SOCK=SOCK,
              SLACK_BOT_TOKEN='xoxb-e2e-not-real', SLACK_APP_TOKEN='xapp-e2e-not-real', AGENT_BOX_SESSION_ID='e2e-sess',
              LOCAL_SLACK_TICK_S='2')   # the spec's 30 s tick would dominate the runtime


def cli(*args):
    p = subprocess.run([sys.executable, os.path.join(HERE, 'ls_patched.py')] + list(args), env=ls_env,
                       capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


rc, out = cli('channel', 'add', 'C1')
check('CLI: channel add C1 (bot is a member)', rc == 0, out[:120])
rc, out = cli('channel', 'add', 'C3')
check('CLI: channel add C3 refused (bot not a member)', rc != 0, out[:120])
cfg = json.load(open(CFG))
cfg['C1'].update({'quiet_minutes': 0.1, 'resettle': True})
cfg['C1'].setdefault('write', {})['allowed'] = True
cfg.setdefault('_defaults', {}).setdefault('links', {})['allowed_hosts'] = ['github.com']
json.dump(cfg, open(CFG, 'w'), indent=2)

daemon = subprocess.Popen([sys.executable, os.path.join(HERE, 'ls_patched.py'), 'daemon'], env=ls_env,
                          stdout=open(os.path.join(E2E, 'daemon.out'), 'w'), stderr=open(os.path.join(E2E, 'daemon.err'), 'w'))
CHILDREN.append(daemon)
check('daemon opened a Socket Mode connection', mock.wait_conn(), 'apps.connections.open via app token')


def wait_notes(pred, t=8):
    end = time.time() + t
    while time.time() < end:
        pump(0.2)
        hit = [n for n in notes if pred(n)]
        if hit:
            return hit
    return []


def act(n):
    return (n.get('meta') or {}).get('event', '')


A, B, C = '1760500001.000100', '1760500002.000100', '1760500003.000100'
# E1: top-level message
mock.event('Ev1', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': 'Export button does nothing on the reports page', 'ts': A})
got = wait_notes(lambda n: act(n) == 'message.posted')
check('E1 top-level message reaches the subscribed session as message.posted', got,
      got[0]['content'][:200] if got else 'nothing delivered')
if got:
    check('E1 delivery is framed untrusted and carries the subscription note',
          got[0]['content'].startswith('[UNTRUSTED webhook:slack') and 'e2e: #dev' in got[0]['content'])
n_before = len(notes)
# E2: Slack redelivers E1
mock.event('Ev1', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': 'Export button does nothing on the reports page', 'ts': A}, retry=1)
pump(2.5)
check('E2 redelivery of the same event_id is de-duplicated', len(notes) == n_before, '%d new' % (len(notes) - n_before))
# E3: reply
mock.event('Ev3', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': 'Happens in Firefox too', 'ts': B, 'thread_ts': A})
n_posted = len([n for n in notes if act(n) == 'message.posted'])
end = time.time() + 6
while time.time() < end and len([n for n in notes if act(n) == 'message.posted']) <= n_posted:
    pump(0.2)
new = [n for n in notes if act(n) == 'message.posted'][n_posted:]
check('E3 thread reply delivered as message.posted', new, new[0]['content'][:260] if new else 'no new message.posted')
n_before = len(notes)
# E4: unfurl-only message_changed, E5: the bot's own reply, E6: unconfigured channel
mock.event('Ev4', {'type': 'message', 'subtype': 'message_changed', 'channel': 'C1', 'ts': '1760500004.000100',
                   'message': {'user': 'U1', 'text': 'Export button does nothing on the reports page', 'ts': A, 'attachments': [{'title': 'x'}]},
                   'previous_message': {'user': 'U1', 'text': 'Export button does nothing on the reports page', 'ts': A}})
mock.event('Ev5', {'type': 'message', 'channel': 'C1', 'user': 'UBOT', 'bot_id': 'BBOT', 'text': 'bot echo', 'ts': '1760500005.000100', 'thread_ts': A})
mock.event('Ev6', {'type': 'message', 'channel': 'C2', 'user': 'U1', 'text': 'lunch?', 'ts': '1760500006.000100'})
pump(3)
check('E4/E5/E6 unfurl edit, bot echo and unconfigured channel produce nothing', len(notes) == n_before,
      '; '.join(act(n) for n in notes[n_before:]))
# E7: a guest adds the ready reaction on a reply
mock.event('Ev7', {'type': 'reaction_added', 'user': 'UGUEST', 'reaction': 'white_check_mark',
                   'item': {'type': 'message', 'channel': 'C1', 'ts': B}, 'event_ts': '1760500007.000100'})
pump(3)
check('E7 a guest cannot settle a thread with ✅', not [n for n in notes if act(n) == 'thread.settled'])
# E8: a member mentions the bot
mock.event('Ev8', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': '<@UBOT> can you look?', 'ts': C, 'thread_ts': A})
got = wait_notes(lambda n: act(n) == 'thread.settled')
check('E8 a mention settles the thread immediately', got, got[0]['content'][:220] if got else 'no thread.settled')
time.sleep(1.5)
wrote = [c for c in mock.calls if c[1] in ('reactions.add', 'chat.postMessage', 'chat.update')]
check('E8 with no ack configured the daemon writes nothing to Slack by itself', not wrote,
      json.dumps([c[1:2] + (c[3],) for c in wrote])[:200])
# Now a deployment opts in: an ack reaction and a disclosure line (hot-reloaded by the ticker).
cfg = json.load(open(CFG))
cfg['C1'].setdefault('reactions', {})['ack'] = 'eyes'
cfg['_defaults']['disclosure'] = '_— AI agent · can be wrong_'
json.dump(cfg, open(CFG, 'w'), indent=2)
time.sleep(5)
F = '1760500020.000100'
mock.event('Ev8b', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': '<@UBOT> and this one?', 'ts': F})
wait_notes(lambda n: act(n) == 'thread.settled' and F in json.dumps(n))
time.sleep(1.5)
eyes = [c for c in mock.calls if c[1] == 'reactions.add' and c[3].get('name') == 'eyes']
check('E8b once configured, the daemon acknowledges a mention with 👀', eyes, json.dumps(eyes[0][3]) if eyes else 'no reactions.add eyes')

# ---------------------------------------------------------------- writes through the CLI
rc, out = cli('reply', 'C1', A, 'Thanks @alice, tracked in https://github.com/defangdevs/agent-box/issues/863')
posts = [c for c in mock.calls if c[1] == 'chat.postMessage']
p = posts[-1][3] if posts else {}
check('W1 reply after a mention is sent (on_request allows it)', rc == 0 and posts, out[:160])
check('W1 reply is threaded, unfurls off, mention resolved, link tokenised, disclosure appended',
      p.get('thread_ts') == A and p.get('unfurl_links') is False and p.get('unfurl_media') is False
      and '<@U1>' in p.get('text', '') and '<https://github.com/defangdevs/agent-box/issues/863|github.com>' in p.get('text', '')
      and 'AI agent' in p.get('text', ''), json.dumps(p)[:300])
bot_ts = sorted([k[1] for k, m in mock.messages.items() if m.get('user') == 'UBOT' and k[0] == 'C1'])[-1] if posts else None
for name, args in [('W2 ``@channel refused', ('reply', 'C1', A, '``@channel urgent')),
                   ('W3 backslash link refused', ('reply', 'C1', A, 'see https://evil.com\\@github.com/x')),
                   ('W4 top-level post refused (write.top_level off)', ('post', 'C1', 'hello')),
                   ('W5 reply with empty ts refused', ('reply', 'C1', '', 'x')),
                   ('W6 reply in unconfigured C2 refused', ('reply', 'C2', '1760500006.000100', 'hi'))]:
    n = len([c for c in mock.calls if c[1] == 'chat.postMessage'])
    rc, out = cli(*args)
    sent = len([c for c in mock.calls if c[1] == 'chat.postMessage']) - n
    check(name, rc != 0 and sent == 0, out[:140])
rc, out = cli('status', 'C1', A, 'Looking into it')
rc2, out2 = cli('status', 'C1', A, 'Fixed in PR 12', '--done')
ups = [c for c in mock.calls if c[1] == 'chat.update']
check('W7 status creates then edits one message', rc == 0 and rc2 == 0 and ups, (out + ' | ' + out2)[:200])
reads = [(c[1], c[2]) for c in mock.calls if c[1] in ('conversations.replies', 'users.info', 'conversations.info', 'users.list')]
check('W8 read methods are form-encoded (not JSON)', reads and all(ct != 'application/json' for _, ct in reads), str(sorted(set(reads))))

# ---------------------------------------------------------------- feedback + quiet settle + watch
got = []   # reset: E8's result must not satisfy E10 if it cannot run
if bot_ts:
    mock.event('Ev9', {'type': 'message', 'channel': 'C1', 'user': 'UBOT', 'bot_id': 'BBOT', 'text': 'bot reply', 'ts': bot_ts, 'thread_ts': A})
    pump(1)
    mock.event('Ev10', {'type': 'reaction_added', 'user': 'U1', 'reaction': '+1',
                        'item': {'type': 'message', 'channel': 'C1', 'ts': bot_ts}, 'event_ts': '1760500010.000100'})
    got = wait_notes(lambda n: act(n) == 'reaction.added')
check('E10 with no feedback_reactions configured, 👍 on the bot\'s reply is a plain reaction.added',
      got and not [n for n in notes if act(n) == 'feedback'], got[0]['content'][:200] if got else 'no reaction.added')
D = '1760500011.000100'
mock.event('Ev11', {'type': 'message', 'channel': 'C1', 'user': 'U1', 'text': 'Can we add CSV export?', 'ts': D})
print('waiting for the quiet period (6 s) plus the ticker...', flush=True)
got = wait_notes(lambda n: act(n) == 'thread.settled' and D in json.dumps(n), t=30)
check('E11 a quiet thread settles with reason quiet', got and 'quiet' in got[0]['content'], got[0]['content'][:220] if got else 'none')
pump(3)
spawned = open(SPAWN_LOG).read() if os.path.exists(SPAWN_LOG) else ''
check('standing watch spawned for settled threads', spawned.count('=== END SPAWN') >= 1,
      '%d spawn(s); first: %s' % (spawned.count('=== END SPAWN'), spawned[:200].replace('\n', ' ')))
lat = [t - mock.sent[e] for t, e in mock.acks if e in mock.sent]
check('every envelope acked within 3 s', lat and max(lat) < 3 and len(set(e for _, e in mock.acks)) >= len(mock.sent) - 1,
      'acks %d/%d, max latency %.3fs' % (len(set(e for _, e in mock.acks)), len(mock.sent), max(lat) if lat else -1))

for p_ in (daemon, peer, recv):
    p_.terminate()
print('\n%d/%d checks passed' % (sum(ok for _, ok, _ in results), len(results)))
print('daemon stderr tail:\n' + open(os.path.join(E2E, 'daemon.err')).read()[-1500:])
sys.exit(0 if results and all(ok for _, ok, _ in results) else 1)

