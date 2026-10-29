#!/usr/bin/env python3
# local-slack — a Slack connection for agent-box (defangdevs/agent-box#863).
#
# One file, stdlib only, python >= 3.9, like local-webhook (see AGENTS.md).
# Slack threads become events on the local-webhook bus (source `slack`), a
# per-thread timer says when a conversation has settled, and a guarded CLI lets
# an agent write back. Everything below is split in layers that the tests reach
# one at a time:
#
#   1. text      — sanitising Slack text, composing outgoing text, secret scan
#   2. config    — channels.json (the allowlist) and the state dir
#   3. store     — SQLite: message index, threads, dedup, status ts, audit
#   4. tracker   — which Slack events count, the settle state machine
#   5. web       — Web API client with the per-tier token buckets
#   6. socket    — a minimal RFC 6455 client for Socket Mode
#   7. daemon    — wires 4 + 5 + 6 together and emits onto the bus
#   8. cli       — doctor / channels / thread / reply / post / status / react
#
# Two modes: PLAIN (tokens in the agent user's env) and socket-service (the
# daemon alone holds the tokens and serves writes on a Unix socket, callers
# checked by SO_PEERCRED). Grants, the
# HTTP Events API transport, the settings card and classifier
# isolation hardening are follow-ups; the spec's guardrails that do not depend
# on grants are all enforced here, in the code path every write passes.
import base64
import hashlib
import errno
import http.client
import json
import os
import re
import select
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = '0.1.0'

API_HOST = 'slack.com'

# How often the settle ticker runs. 30 s is the spec's; tests shorten it.
TICK_SECONDS = float(os.environ.get('LOCAL_SLACK_TICK_S') or 30)

# --------------------------------------------------------------------------
# 1. text
# --------------------------------------------------------------------------

# Slack wraps everything addressable in <...>: <@U1>, <#C1|name>, <!here>,
# <!subteam^S1>, <https://x|label>. A title that reaches the bus summary goes
# through sanitize_title so none of that survives as markup.
_TOKEN_RE = re.compile(r'<([^<>]*)>')


def sanitize_title(text, limit=200):
    """First line of a message, as plain text, safe for the bus summary."""
    def label(m):
        inner = m.group(1)
        if '|' in inner:
            return inner.split('|', 1)[1]
        if inner[:1] in '@#!':
            return inner[1:].split('^')[-1]
        return inner
    text = _TOKEN_RE.sub(label, text or '')
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[`*_~]', '', text).strip()
    return text[:limit]


# Token shapes worth refusing on the way out. This is a small built-in subset
# of the gitleaks rule set, chosen for the credentials an agent on this box can
# actually hold; a deployment extends it with channels.json _defaults.secret_patterns.
SECRET_PATTERNS = [
    re.compile(r'xox[abprs]-[A-Za-z0-9-]{10,}'),
    re.compile(r'xapp-\d-[A-Za-z0-9-]{10,}'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{40,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    # Needs a digit: a kebab-case branch name is not a key (`sk-` + 32 letters).
    re.compile(r'sk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}'),
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
]


class Refused(Exception):
    """A guardrail said no. The message is shown to the agent, so it names the
    rule but never echoes the matched secret."""


_ZERO_WIDTH_RE = re.compile('[\u200b-\u200f\u2060\ufeff]')


def scan_secrets(text, extra=()):
    # Look at the text as written AND with percent-escapes decoded, so a token
    # smuggled into a URL query is found (PromptArmor-style exfiltration).
    # Zero-width characters split a token for the scanner and not for a reader,
    # so scan the text with them removed too.
    seen = set()
    for t in (text, urllib.parse.unquote(text)):
        seen.add(t)
        seen.add(_ZERO_WIDTH_RE.sub('', t))
    for pat in list(SECRET_PATTERNS) + [re.compile(p) for p in extra]:
        for t in seen:
            if pat.search(t):
                raise Refused('text matches a secret pattern; refused (not logged)')


_URL_RE = re.compile(r'https?://[^\s<>|)\]]+', re.I)
_IMAGE_MD_RE = re.compile(r'!\[[^\]]*\]\([^)]*\)')
# A name is dot/dash/underscore-joined alphanumerics, so `thanks @alice.` names
# alice and not `alice.`; the lookahead keeps `@channelé` from resolving as
# `@channel` (the ASCII class and Unicode \w would otherwise disagree).
# `;` in the lookbehind: after escaping, a raw `<@U1>` the agent wrote reads
# `&lt;@U1&gt;`, and that `@U1` must stay inert text, not be resolved.
_MENTION_RE = re.compile(r'(?<![\w`<;])([@#])([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(?![\w@])')
_CODE_RE = re.compile(r'```.*?```|`[^`\n]*`', re.S)
BROADCASTS = ('channel', 'here', 'everyone')
# Text Slack may turn into a link without a scheme: www.x, a bare domain on a
# common TLD, and non-http schemes. All of them get the same host check as an
# explicit URL, because whether Slack linkifies them is not ours to decide.
_TLDS = ('com|net|org|io|dev|app|ai|co|us|uk|de|fr|eu|ru|cn|jp|in|br|au|ca|ch|nl|se|no|es|it|pl|info|biz|xyz|sh|me|tv|cc|to|ly|gg|cloud|tech|online|site|link|zip|mov')
_BARE_HOST_RE = re.compile(r'(?<![\w@./:-])(?:www\.|(?=[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:%s)\b))'
                           r'[a-z0-9-]+(?:\.[a-z0-9-]+)*(?:\.(?:%s))?(?::\d+)?(?:/[^\s<>|)\]]*)?' % (_TLDS, _TLDS), re.I)
_SCHEME_RE = re.compile(r'\b(?:mailto|ftp|ftps|file|javascript|data|tel|sms|slack):[^\s<>|)\]]+', re.I)
# RFC 3986 characters only: a backslash, a space or a control character is
# read one way by urlsplit and another by a browser (`evil.com\@slack.com`).
_URL_CHARS_RE = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")


def _host_allowed(host, allowed):
    host = (host or '').lower()
    return any(host == h or host.endswith('.' + h) for h in allowed)


def check_link(url, allowed_hosts):
    if not _URL_CHARS_RE.fullmatch(url):
        raise Refused('link has characters outside RFC 3986 (such as a backslash)')
    try:
        p = urllib.parse.urlsplit(url if '//' in url else '//' + url)
        host = (p.hostname or '').lower()
        p.port  # noqa: B018 — raises ValueError on a bad port
    except ValueError:
        raise Refused('link does not parse')
    if '@' in p.netloc:
        raise Refused('link with userinfo (user@host) is refused')
    if not re.fullmatch(r'[a-z0-9.-]+', host):
        raise Refused('link host "%s" is not plain ASCII' % host)
    if not _host_allowed(host, allowed_hosts):
        raise Refused('link host "%s" is not in links.allowed_hosts' % host)
    # A link can still carry data out in its tail; cap it and scan it decoded.
    for part in (p.path, p.query, p.fragment):
        dec = urllib.parse.unquote(part)
        if len(dec) > 256:
            raise Refused('link path/query/fragment over 256 characters')
        scan_secrets(dec)


_EMAIL_RE = re.compile(r'(?<![\w.+-])[\w.+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b')
_URL_TAIL = '.,;:!?\'"'


def compose(text, resolver, cfg, defaults, unresolved=None):
    """Build the text Slack receives. `resolver(kind, name)` returns an id for
    ('@', name) / ('#', name) / ('!', group) or None. Compose, don't filter:
    everything the agent wrote is escaped first, then only the tokens WE insert
    are live markup, and the result is re-checked for any token we did not
    insert (spec M2). Names that stay literal text because nothing resolved
    them are appended to `unresolved` when given, so the caller can say so."""
    write = cfg.get('write', {})
    if _IMAGE_MD_RE.search(text):
        raise Refused('image Markdown is refused; use upload')
    scan_secrets(text, defaults.get('secret_patterns', ()))

    allowed_hosts = list(defaults.get('links', {}).get('allowed_hosts', []))
    inserted = []

    # Work on code and non-code segments separately: mentions inside code stay
    # literal text.
    out, pos = [], 0
    segments = []
    for m in _CODE_RE.finditer(text):
        segments.append((False, text[pos:m.start()]))
        segments.append((True, m.group(0)))
        pos = m.end()
    segments.append((False, text[pos:]))

    def escape(s):
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    for is_code, seg in segments:
        if is_code:
            out.append(escape(seg))
            continue
        # Links first (on the raw text), so a mention-looking `@` in a URL is
        # not rewritten.
        pieces, p2 = [], 0
        for m in _URL_RE.finditer(seg):
            # Sentence punctuation after a link is not part of it.
            url = m.group(0).rstrip(_URL_TAIL)
            check_link(url, allowed_hosts)
            pieces.append(('t', seg[p2:m.start()]))
            pieces.append(('u', url))
            p2 = m.start() + len(url)
        pieces.append(('t', seg[p2:]))
        for kind, chunk in pieces:
            if kind != 't':
                continue
            for m in _SCHEME_RE.finditer(chunk):
                raise Refused('links other than http(s) are refused: %s:' % m.group(0).split(':')[0])
            for m in _BARE_HOST_RE.finditer(chunk):
                check_link(m.group(0), allowed_hosts)
            # Slack may turn a bare address into a mailto: link, so its domain
            # gets the same host check as any other link.
            for m in _EMAIL_RE.finditer(chunk):
                check_link(m.group(1), allowed_hosts)
        for kind, chunk in pieces:
            if kind == 'u':
                host = urllib.parse.urlsplit(chunk).hostname
                tok = '<%s|%s>' % (chunk, host)
                inserted.append(tok)
                out.append(tok)
                continue
            esc = escape(chunk)

            def mention(m):
                sigil, name = m.group(1), m.group(2)
                if sigil == '@' and name.lower() in BROADCASTS:
                    # The one place a broadcast token is made, so the flag is
                    # checked where the token is, whatever the text around it.
                    if not write.get('broadcast'):
                        raise Refused('@channel / @here / @everyone need write.broadcast')
                    tok = '<!%s>' % name.lower()
                    inserted.append(tok)
                    return tok
                if sigil == '#' and name.isdigit():
                    return sigil + name   # `PR #42` is text, not a channel
                rid = resolver(sigil, name)
                if not rid:
                    # Not a known person or channel: leave it as the literal
                    # text it is. Only what would become a live token is
                    # refused or resolved.
                    if unresolved is not None and sigil + name not in unresolved:
                        unresolved.append(sigil + name)
                    return sigil + name
                if rid.startswith('S'):  # user group
                    if not write.get('groups'):
                        raise Refused('@group mentions need write.groups')
                    tok = '<!subteam^%s>' % rid
                elif sigil == '#':
                    tok = '<#%s>' % rid
                else:
                    tok = '<@%s>' % rid
                inserted.append(tok)
                return tok
            out.append(_MENTION_RE.sub(mention, esc))
    final = ''.join(out)
    # Re-check: any Slack token that is not one we inserted is a smuggle.
    budget = list(inserted)
    for m in _TOKEN_RE.finditer(final):
        tok = m.group(0)
        if tok in budget:
            budget.remove(tok)
            continue
        raise Refused('text contains a Slack token the tool did not insert')
    return final


# --------------------------------------------------------------------------
# 2. config
# --------------------------------------------------------------------------

def state_dir():
    d = os.environ.get('LOCAL_SLACK_STATE_DIR') or os.path.join(
        os.environ.get('XDG_STATE_HOME') or os.path.expanduser('~/.local/state'), 'local-slack')
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def credential(name):
    """A token from the environment, else from a credentials file: systemd's
    $CREDENTIALS_DIRECTORY (LoadCredential=) or LOCAL_SLACK_CREDENTIALS_DIR. The
    file is named for the variable, lower- or upper-case. Socket-service mode
    needs only the file, so the daemon's environment holds no token."""
    v = os.environ.get(name)
    if v:
        return v
    for f in credential_files(name):
        try:
            with open(f) as fh:
                v = fh.read().strip()
        except OSError:
            continue
        if v:
            return v
    return None


def credential_files(name):
    d = os.environ.get('LOCAL_SLACK_CREDENTIALS_DIR') or os.environ.get('CREDENTIALS_DIRECTORY')
    return [os.path.join(d, n) for n in (name.lower(), name)] if d else []


def config_path():
    return os.environ.get('LOCAL_SLACK_CONFIG') or os.path.expanduser('~/.config/local-slack/channels.json')


# MECHANISM, NOT POLICY (this repo's rule, see the README). What follows are
# fresh defaults: plain starting values a deployment replaces by writing its own,
# and nothing else in the code depends on them. Anything that would make the
# daemon ACT in Slack by itself (an ack reaction, status reactions, a disclosure
# line) defaults to nothing; the recommended values live in agent-box's policy
# and are rendered into channels.json (see channels.example.json).
DEFAULT_CHANNEL = {
    'track': 'all',
    'quiet_minutes': 30, 'max_wait_hours': 24, 'merge_window_minutes': 0,
    'resettle': True, 'track_bots': False,
    'reactions': {'ready': 'white_check_mark', 'hold': 'raised_hand', 'drop': 'x', 'ack': None},
    'controllers': [], 'ignore_users': [],
    'write': {'allowed': False, 'mode': 'on_request', 'top_level': False,
              'broadcast': False, 'groups': False},
    'allow_external': False,
}
DEFAULT_DEFAULTS = {
    'dm_allowlist': [], 'links': {'allowed_hosts': []},
    # Appended to reply/post/dm when set. The wording is the deployment's.
    'disclosure': '',
    'retention_days': 30,
    # Write caps. A value of 0 (or null) turns that cap off.
    'limits': {'session_writes': 20, 'session_window_s': 600, 'top_level_per_hour': 5},
    # Reaction names that mean "feedback" on one of the bot's own messages. With
    # none configured such a reaction goes out as a plain reaction.added /
    # reaction.removed carrying on_bot_message: true, and consumers decide what
    # it means. Either way it is never thread activity.
    'feedback_reactions': [],
    # {'working': 'hourglass_flowing_sand', 'done': 'white_check_mark', 'failed': 'x'}:
    # progress reactions `status` keeps on the thread parent. None configured,
    # none made.
    'status_marks': {},
    # What `file` may download. Types are MIME types, and only those with a
    # signature in FILE_TYPES can ever be enabled, so SVG and HTML stay out
    # whatever the config says. PDF is opt-in: add 'application/pdf'.
    'files': {'types': ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
              'max_bytes': 20 * 1024 * 1024, 'total_bytes': 200 * 1024 * 1024},
}


def _merge(base, over):
    out = json.loads(json.dumps(base))
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path=None):
    """Returns (channels, defaults). A missing or corrupt file means NO
    channels: the config is the allowlist, so failure closes (AGENTS.md)."""
    try:
        with open(path or config_path()) as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError
    except (OSError, ValueError):
        return {}, json.loads(json.dumps(DEFAULT_DEFAULTS))
    defaults = _merge(DEFAULT_DEFAULTS, raw.get('_defaults'))
    channels = {k: _merge(DEFAULT_CHANNEL, v) for k, v in raw.items()
                if not k.startswith('_') and isinstance(v, dict)}
    return channels, defaults


def read_raw(path=None):
    """The file as written, for EDITING. load_config fails closed (a bad file
    means no channels), which is right for the daemon and wrong for `channel
    add`: saving over that view would wipe every other channel. So an edit
    refuses to touch a file that exists and does not parse."""
    path = path or config_path()
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise Refused('%s does not parse (%s); fix it by hand before editing' % (path, e))
    if not isinstance(raw, dict):
        raise Refused('%s is not a JSON object; fix it by hand before editing' % path)
    return raw


def write_raw(doc, path=None):
    path = path or config_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + '.tmp'
    # 0600: the file names channels and the people allowed to be DMed.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def save_config(channels, defaults, path=None):
    doc = dict(channels)
    doc['_defaults'] = defaults
    write_raw(doc, path)


def labels_overlap(labels):
    """`contains` on the bus is a substring match, so 'bug' would match
    'debug' (spec S7): refuse label sets where one contains another."""
    ls = [x.lower() for x in labels]
    return any(a != b and a in b for a in ls for b in ls)


# --------------------------------------------------------------------------
# 3. store
# --------------------------------------------------------------------------

SCHEMA = '''
CREATE TABLE IF NOT EXISTS seen   (event_id TEXT PRIMARY KEY, at REAL);
CREATE TABLE IF NOT EXISTS msgs   (team TEXT, channel TEXT, ts TEXT, thread_ts TEXT,
                                   user TEXT, is_bot INTEGER, at REAL,
                                   PRIMARY KEY (team, channel, ts));
CREATE TABLE IF NOT EXISTS threads(thread_key TEXT PRIMARY KEY, team TEXT, channel TEXT,
                                   thread_ts TEXT, title TEXT, first_seen_at REAL,
                                   last_activity_at REAL, settle_at REAL, version INTEGER,
                                   state TEXT, held_by TEXT, settled_version INTEGER,
                                   extra_ts TEXT, external INTEGER, participants TEXT,
                                   replies INTEGER, ended_at REAL, asked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL,
                                   action TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS status (thread_key TEXT PRIMARY KEY, ts TEXT);
CREATE TABLE IF NOT EXISTS audit  (at REAL, channel TEXT, thread TEXT, ts TEXT,
                                   session TEXT, kind TEXT, text TEXT);
'''


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript(SCHEMA)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def q(self, sql, *args):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql, *args):
        with self.lock:
            return self.db.execute(sql, args).rowcount

    def seen(self, event_id):
        if not event_id:
            return False
        return bool(self.q('SELECT 1 FROM seen WHERE event_id=?', event_id))

    def mark_seen(self, event_id, now):
        """Recorded AFTER an event is processed: marking first would let a
        failure inside handle() lose the event for good, because Slack's
        redelivery would then be dropped as a duplicate."""
        if event_id:
            self.x('INSERT OR IGNORE INTO seen VALUES (?,?)', event_id, now)

    # The outbox makes "persisted" mean "will reach the bus": the tracker
    # writes the event in the same pass that changes the thread, a worker
    # delivers it and deletes the row only on success. That also keeps the
    # emit subprocess out of the 3-second Socket Mode acknowledgement window.
    def outbox_put(self, action, payload):
        self.x('INSERT INTO outbox (at, action, payload) VALUES (?,?,?)',
               time.time(), action, json.dumps(payload))

    def outbox_next(self):
        r = self.q('SELECT * FROM outbox ORDER BY id LIMIT 1')
        return r[0] if r else None

    def outbox_done(self, row_id):
        self.x('DELETE FROM outbox WHERE id=?', row_id)

    def prune(self, now, retention_days=30, audit_days=90):
        self.x('DELETE FROM seen WHERE at < ?', now - 86400)
        self.x('DELETE FROM outbox WHERE at < ?', now - 7 * 86400)  # a bus down a week is not coming back
        cut = now - retention_days * 86400
        gone = self.q("SELECT team, channel, thread_ts FROM threads "
                      "WHERE state IN ('settled','dropped') AND ended_at < ?", cut)
        for r in gone:
            self.x('DELETE FROM msgs WHERE team=? AND channel=? AND thread_ts=?',
                   r['team'], r['channel'], r['thread_ts'])
        self.x("DELETE FROM threads WHERE state IN ('settled','dropped') AND ended_at < ?", cut)
        # Index rows that never got a record (a `mention` channel's unmentioned
        # messages, lookup results) hang off no thread, so age them out too;
        # rows of a still-open or held record stay.
        self.x('DELETE FROM msgs WHERE at < ? AND NOT EXISTS (SELECT 1 FROM threads t '
               "WHERE t.team=msgs.team AND t.channel=msgs.channel AND t.thread_ts=msgs.thread_ts "
               "AND t.state IN ('open','held'))", cut)
        self.x('DELETE FROM audit WHERE at < ?', now - audit_days * 86400)

    def purge_channel(self, channel):
        for t in ('msgs', 'threads', 'audit'):
            self.x('DELETE FROM %s WHERE channel=?' % t, channel)
        # Two key shapes: team/channel/ts, and channel/ts when Writer.status
        # found no record to take a key from.
        self.x('DELETE FROM status WHERE thread_key LIKE ? OR thread_key LIKE ?',
               '%/' + channel + '/%', channel + '/%')

    def purge_all(self):
        for t in ('seen', 'msgs', 'threads', 'status', 'audit', 'outbox'):
            self.x('DELETE FROM %s' % t)


# --------------------------------------------------------------------------
# 4. tracker
# --------------------------------------------------------------------------

CONTROL = ('ready', 'hold', 'drop')


class Tracker:
    """Turns raw Slack events into bus events and owns the settle state
    machine. `emit(action, payload)` is the only way out; `now` is injectable
    so tests control the clock. `bot` is {'user_id','bot_id'} from auth.test.
    `lookup(channel, ts)` resolves a message's thread via conversations.replies
    on an index miss. `users(user_id)` returns {'guest':bool,'external':bool}."""

    def __init__(self, store, channels, bot, emit, now=time.time, lookup=None, users=None,
                 react=None, classify=None, retention_days=30, defaults=None):
        self.store, self.channels, self.bot = store, channels, bot
        self.emit, self.now = emit, now
        self.retention_days = retention_days
        self.defaults = defaults if defaults is not None else {}
        self.lookup = lookup or (lambda channel, ts: None)
        # Fails CLOSED: with no way to ask Slack who a user is, nobody counts as a
        # full member, so nobody can ready, hold or drop a thread.
        self.users = users or (lambda uid: {'guest': True, 'external': True})
        self.lock = threading.RLock()
        self.react = react or (lambda channel, ts, emoji: None)
        self.classify = classify or (lambda cfg, key: None)
        self.external = {}   # channel -> bool, flipped by channel_shared events
        self.member = {}     # channel -> bool

    # -- helpers ----------------------------------------------------------
    def _is_bot_self(self, user=None, bot_id=None):
        return bool((user and user == self.bot.get('user_id')) or
                    (bot_id and bot_id == self.bot.get('bot_id')))

    def _key(self, team, channel, thread_ts):
        return '%s/%s/%s' % (team, channel, thread_ts)

    def _summary(self, row, extra):
        replies = row['replies'] or 0
        people = len([x for x in (row['participants'] or '').split(',') if x])
        out = 'v%d · %d %s, %d %s' % (row['version'], replies, 'reply' if replies == 1 else 'replies',
                                      people, 'person' if people == 1 else 'people')
        # `reason` means something only on thread.settled.
        if extra and extra.get('reason'):
            out += ' · reason: %s' % extra['reason']
        return out

    def _payload(self, row, action, ts=None, user=None, extra=None):
        p = {
            'identifier': row['thread_key'],
            'title': row['title'] or '',
            'summary': self._summary(row, extra),
            'action': action,
            'team': row['team'], 'channel': row['channel'], 'thread': row['thread_ts'],
            'ts': ts or row['thread_ts'], 'user': user or '', 'version': row['version'],
            'external': bool(row['external']),
            'url': '%sarchives/%s/p%s' % (self.bot.get('url') or 'https://slack.com/', row['channel'],
                                          row['thread_ts'].replace('.', '')),
        }
        if row['extra_ts']:
            p['also'] = row['extra_ts']
        if extra:
            p.update(extra)
        return p

    def _controller_ok(self, cfg, uid):
        if cfg['controllers']:
            return uid in cfg['controllers']
        u = self.users(uid)
        return not u.get('guest') and not u.get('external')

    # -- entry point --------------------------------------------------------
    def handle(self, envelope):
        """`envelope` is a Socket Mode events_api payload (or an HTTP event
        callback body): {'team_id','event_id','event':{...}}. One lock covers
        this and tick(): both read-modify-write `threads`, and an unlocked
        reply could be stranded in a thread the ticker just settled."""
        with self.lock:
            now = self.now()
            eid = envelope.get('event_id')
            if self.store.seen(eid):
                return
            team = envelope.get('team_id') or (envelope.get('event') or {}).get('team') or ''
            ev = envelope.get('event') or {}
            etype = ev.get('type')
            if etype == 'message':
                self._message(team, ev, now)
            elif etype in ('reaction_added', 'reaction_removed'):
                self._reaction(team, ev, etype, now)
            elif etype in ('channel_shared', 'channel_unshared'):
                self.external[ev.get('channel')] = (etype == 'channel_shared')
            elif etype in ('member_left_channel', 'member_joined_channel'):
                # Joining restores what leaving paused; without it a bot that is
                # removed and re-invited would drop every message, silently,
                # until the daemon restarted.
                if self._is_bot_self(user=ev.get('user')):
                    self.member[ev.get('channel')] = (etype == 'member_joined_channel')
            self.store.mark_seen(eid, now)

    def prime(self, channel, info):
        """Seed per-channel facts from conversations.info, so `external` and
        membership survive a restart (events only ever flip them)."""
        self.external[channel] = bool(info.get('is_ext_shared'))
        self.member[channel] = bool(info.get('is_member', True))

    # -- messages -----------------------------------------------------------
    def _message(self, team, ev, now):
        channel = ev.get('channel')
        cfg = self.channels.get(channel)
        if cfg is None or self.member.get(channel) is False:
            return  # the config is the allowlist
        if self.external.get(channel) and not cfg['allow_external']:
            return  # a Slack Connect channel nobody opted in to
        sub = ev.get('subtype')
        if sub in ('message_changed', 'message_deleted'):
            return self._edit_or_delete(team, ev, sub, cfg, now)
        if sub not in (None, 'file_share', 'me_message', 'thread_broadcast', 'bot_message'):
            return  # joins, topic changes and the rest of the system subtypes
        if self._is_bot_self(ev.get('user'), ev.get('bot_id')):
            # Our own echo is never activity, but it IS indexed: a 👍/👎 on it
            # has to resolve to its thread to become `feedback`.
            self.store.x('INSERT OR REPLACE INTO msgs VALUES (?,?,?,?,?,?,?)', team, channel,
                         ev.get('ts'), ev.get('thread_ts') or ev.get('ts'),
                         self.bot.get('user_id'), 1, now)
            return
        if (ev.get('bot_id') or sub == 'bot_message') and not cfg['track_bots']:
            # Other apps often post with a bot_id and no bot_message subtype.
            return
        user = ev.get('user') or ev.get('bot_id') or ''
        if user in cfg['ignore_users']:
            return
        ts = ev.get('ts')
        thread_ts = ev.get('thread_ts') or ts
        is_top = (thread_ts == ts) and sub != 'thread_broadcast'
        self.store.x('INSERT OR REPLACE INTO msgs VALUES (?,?,?,?,?,?,?)',
                     team, channel, ts, thread_ts, user, 1 if (sub == 'bot_message') else 0, now)
        mentioned = ('<@%s>' % self.bot.get('user_id')) in (ev.get('text') or '')
        key = self._key(team, channel, thread_ts)
        row = self._row(key)
        merged = False
        if row is None:
            if not is_top:
                # A reply in a thread we never started: only a mention can
                # start a record from the middle.
                if not (cfg['track'] == 'mention' and mentioned):
                    return
            elif cfg['track'] == 'mention':
                if not mentioned:
                    return
            elif cfg['track'].startswith('reaction:'):
                return  # started by the reaction, not the message
            row, merged = self._start(team, channel, thread_ts, ev, cfg, now, user)
            if merged:
                # Attached to an open record by the merge window: it is still a
                # message on that record, and a mention in it still counts.
                key = row['thread_key']
                row = self._row(key)
        else:
            self._bump(row, cfg, now, user, reply=not is_top)
            row = self._row(key)
        self.emit('message.posted', self._payload(
            row, 'message.posted', ts=ts, user=user, extra={'mentioned': mentioned}))
        if mentioned:
            self._settle_now(row, 'mention', cfg, ts)

    def _row(self, key):
        r = self.store.q('SELECT * FROM threads WHERE thread_key=?', key)
        return r[0] if r else None

    def _start(self, team, channel, thread_ts, ev, cfg, now, user):
        # Merge window: more top-level messages from the same author soon after
        # are attached to the open record instead of starting new ones.
        mw = cfg['merge_window_minutes']
        if mw:
            prior = self.store.q(
                "SELECT * FROM threads WHERE team=? AND channel=? AND state='open' "
                "AND first_seen_at > ? AND participants LIKE ? ORDER BY first_seen_at DESC",
                team, channel, now - mw * 60, user + '%')
            if prior:
                r = prior[0]
                extra = ','.join([x for x in (r['extra_ts'] or '').split(',') if x] + [ev.get('ts')])
                self.store.x('UPDATE threads SET extra_ts=? WHERE thread_key=?', extra, r['thread_key'])
                self._bump(r, cfg, now, user, reply=False)
                return r, True
        key = self._key(team, channel, thread_ts)
        quiet, maxw = cfg['quiet_minutes'] * 60, cfg['max_wait_hours'] * 3600
        ext = 1 if (self.external.get(channel)) else 0
        self.store.x('INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)',
                     key, team, channel, thread_ts, sanitize_title(ev.get('text')), now, now,
                     min(now + quiet, now + maxw), 1, 'open', None, 0, '', ext, user, 0, None)
        return self._row(key), False

    def _bump(self, row, cfg, now, user, reply):
        """Activity: bump version, push settle_at out (capped by max_wait)."""
        state = row['state']
        if state == 'dropped':
            return
        if state == 'held':
            # A hold stops the clock, not the count: activity still moves the
            # version, so the record does not re-settle at an unchanged one.
            parts = [x for x in (row['participants'] or '').split(',') if x]
            if user and user not in parts:
                parts.append(user)
            self.store.x('UPDATE threads SET version=version+1, last_activity_at=?, participants=?, '
                         'replies=replies+? WHERE thread_key=?', now, ','.join(parts),
                         1 if reply else 0, row['thread_key'])
            return
        quiet, maxw = cfg['quiet_minutes'] * 60, cfg['max_wait_hours'] * 3600
        if state == 'settled':
            if not cfg['resettle']:
                return
            self.store.x("UPDATE threads SET state='open', first_seen_at=?, ended_at=NULL WHERE thread_key=?",
                         now, row['thread_key'])
            row = self._row(row['thread_key'])
            self.emit('thread.reopened', self._payload(row, 'thread.reopened', user=user))
        parts = [x for x in (row['participants'] or '').split(',') if x]
        if user and user not in parts:
            parts.append(user)
        first = row['first_seen_at']
        self.store.x('UPDATE threads SET version=version+1, last_activity_at=?, settle_at=?, '
                     'participants=?, replies=replies+? WHERE thread_key=?',
                     now, min(now + quiet, first + maxw), ','.join(parts), 1 if reply else 0,
                     row['thread_key'])

    def _edit_or_delete(self, team, ev, sub, cfg, now):
        if sub == 'message_deleted':
            prev = ev.get('previous_message') or {}
            ts = prev.get('ts') or ev.get('deleted_ts')
            m = self.store.q('SELECT * FROM msgs WHERE team=? AND channel=? AND ts=?',
                             team, ev.get('channel'), ts)
            if not m:
                return
            key = self._key(team, ev.get('channel'), m[0]['thread_ts'])
            row = self._row(key)
            if row:
                self._bump(row, cfg, now, m[0]['user'], reply=False)
                self.emit('message.deleted', self._payload(self._row(key), 'message.deleted', ts=ts))
            return
        new, old = ev.get('message') or {}, ev.get('previous_message') or {}
        if self._is_bot_self(new.get('user'), new.get('bot_id')) or \
                self._is_bot_self(old.get('user'), old.get('bot_id')):
            return
        # Unfurls, attachment-only changes and language detection all arrive as
        # message_changed; only a real text/files change is an edit.
        if new.get('text') == old.get('text') and new.get('files') == old.get('files'):
            return
        m = self.store.q('SELECT * FROM msgs WHERE team=? AND channel=? AND ts=?',
                         team, ev.get('channel'), new.get('ts'))
        if not m:
            return
        key = self._key(team, ev.get('channel'), m[0]['thread_ts'])
        row = self._row(key)
        if row:
            self._bump(row, cfg, now, new.get('user') or '', reply=False)
            self.emit('message.edited', self._payload(self._row(key), 'message.edited',
                                                      ts=new.get('ts'), user=new.get('user')))

    # -- reactions ----------------------------------------------------------
    def _resolve_thread(self, team, channel, ts):
        m = self.store.q('SELECT thread_ts FROM msgs WHERE team=? AND channel=? AND ts=?',
                         team, channel, ts)
        if m:
            return m[0]['thread_ts']
        t = self.lookup(channel, ts)
        if t:
            self.store.x('INSERT OR REPLACE INTO msgs VALUES (?,?,?,?,?,?,?)',
                         team, channel, ts, t, '', 0, self.now())
        return t

    def _reaction(self, team, ev, etype, now):
        item = ev.get('item') or {}
        channel, ts = item.get('channel'), item.get('ts')
        cfg = self.channels.get(channel)
        if cfg is None or item.get('type') != 'message':
            return
        if self.external.get(channel) and not cfg['allow_external']:
            return
        user = ev.get('user') or ''
        emoji = ev.get('reaction') or ''
        if self._is_bot_self(user=user):
            return
        thread_ts = self._resolve_thread(team, channel, ts)
        if not thread_ts:
            return
        key = self._key(team, channel, thread_ts)
        row = self._row(key)
        ctrl = {v: k for k, v in cfg['reactions'].items() if k in CONTROL}
        if user in cfg['ignore_users']:
            return
        # reaction:<emoji> tracking starts a record from a reaction.
        if row is None:
            if cfg['track'] == 'reaction:' + emoji and etype == 'reaction_added':
                fake = {'text': '', 'ts': thread_ts}
                row, _ = self._start(team, channel, thread_ts, fake, cfg, now, user)
                if row:
                    self.emit('message.posted', self._payload(row, 'message.posted', user=user))
            return
        if emoji in ctrl:
            if not self._controller_ok(cfg, user):
                return
            which = ctrl[emoji]
            if etype == 'reaction_removed':
                if which == 'hold' and row['state'] == 'held' and row['held_by'] == user:
                    quiet = cfg['quiet_minutes'] * 60
                    self.store.x("UPDATE threads SET state='open', held_by=NULL, settle_at=? WHERE thread_key=?",
                                 now + quiet, key)
                return
            if which == 'ready':
                self._settle_now(row, 'ready', cfg, ts)
            elif which == 'hold' and row['state'] in ('open', 'settled'):
                self.store.x("UPDATE threads SET state='held', held_by=? WHERE thread_key=?", user, key)
            elif which == 'drop':
                self.store.x("UPDATE threads SET state='dropped', ended_at=? WHERE thread_key=?", now, key)
                self.emit('thread.dropped', self._payload(self._row(key), 'thread.dropped', user=user))
            return
        # 👍/👎 on one of the bot's own messages is feedback, not activity.
        m = self.store.q('SELECT user FROM msgs WHERE team=? AND channel=? AND ts=?', team, channel, ts)
        if m and m[0]['user'] == self.bot.get('user_id'):
            # A reaction on the bot's own message is never thread activity (that is
            # correctness: rating a reply must not re-settle the thread). What it
            # MEANS is the deployment's call: a configured feedback reaction goes
            # out as `feedback`, anything else as a plain reaction flagged
            # on_bot_message, for the consumer to interpret.
            if etype == 'reaction_added' and emoji in (self.defaults.get('feedback_reactions') or []):
                self.emit('feedback', self._payload(row, 'feedback', ts=ts, user=user,
                                                    extra={'rating': emoji, 'reason': 'feedback'}))
            else:
                act = 'reaction.added' if etype == 'reaction_added' else 'reaction.removed'
                self.emit(act, self._payload(row, act, ts=ts, user=user,
                                             extra={'reaction': emoji, 'on_bot_message': True}))
            return
        if etype == 'reaction_added':
            self._bump(row, cfg, now, user, reply=False)
            self.emit('reaction.added' if etype == 'reaction_added' else 'reaction.removed',
                      self._payload(self._row(key), 'reaction.added', ts=ts, user=user,
                                    extra={'reaction': emoji}))
        else:
            self.emit('reaction.removed', self._payload(row, 'reaction.removed', ts=ts, user=user,
                                                        extra={'reaction': emoji}))

    # -- settling -----------------------------------------------------------
    def _settle_now(self, row, reason, cfg, ts):
        if row['state'] not in ('open', 'settled') and reason not in ('ready', 'mention'):
            return
        if row['state'] == 'held' or row['state'] == 'dropped':
            return
        # Acknowledge before any agent exists (S1), but only if the deployment
        # configured an ack reaction: the daemon does not write to Slack by itself.
        ack = cfg['reactions'].get('ack')
        if ack:
            try:
                self.react(row['channel'], ts, ack)
            except Exception:
                pass
        # A human asked for the agent here: this is what unlocks replies in
        # write.mode on_request, and a plain quiet settle never does.
        self.store.x('UPDATE threads SET asked=1 WHERE thread_key=?', row['thread_key'])
        self._finish(row, reason, cfg)

    def _finish(self, row, reason, cfg):
        now = self.now()
        n = self.store.x("UPDATE threads SET state='settled', settled_version=version, ended_at=? "
                         "WHERE thread_key=? AND version=? AND state IN ('open','settled')",
                         now, row['thread_key'], row['version'])
        if not n:
            return False
        row = self._row(row['thread_key'])
        topics = self.classify(cfg, row['thread_key'])
        extra = {'reason': reason}
        if topics is not None:
            extra['topics'] = ',' + ','.join(topics) + ',' if topics else ','
        self.emit('thread.settled', self._payload(row, 'thread.settled', extra=extra))
        return True

    def tick(self):
        """The 30 s ticker: settle `open` records whose settle_at has passed,
        but only if version is unchanged since read (compare-and-swap in
        _finish). Restart-safe: everything is recomputed from the table."""
        with self.lock:
            return self._tick()

    def _tick(self):
        now = self.now()
        n = 0
        for row in self.store.q("SELECT * FROM threads WHERE state='open' AND settle_at <= ?", now):
            cfg = self.channels.get(row['channel'])
            if cfg is None:
                continue
            maxed = now >= row['first_seen_at'] + cfg['max_wait_hours'] * 3600
            if self._finish(row, 'max_wait' if maxed else 'quiet', cfg):
                n += 1
        self.store.prune(now, self.retention_days)
        return n


# --------------------------------------------------------------------------
# 5. web
# --------------------------------------------------------------------------

class Bucket:
    """Token bucket: `rate` tokens a minute, burst of `rate`. 40% of capacity
    is reserved for reads so a burst of writes cannot starve settle and
    classifier fetches (spec: Rate budgets)."""

    def __init__(self, per_min, now=time.monotonic):
        self.cap, self.now = float(per_min), now
        self.tokens, self.t = float(per_min), now()
        self.limited = 0
        self.lock = threading.Lock()   # socket handler threads, the ticker and the WS thread all take

    def take(self, write):
        with self.lock:
            t = self.now()
            self.tokens = min(self.cap, self.tokens + (t - self.t) * self.cap / 60.0)
            self.t = t
            floor = self.cap * 0.4 if write else 0.0
            if self.tokens - 1 < floor:
                self.limited += 1
                return False
            self.tokens -= 1
            return True


class SlackError(Exception):
    pass


FILE_HOSTS = ('files.slack.com',)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class Web:
    def __init__(self, bot_token, app_token=None):
        self.bot, self.app = bot_token, app_token
        self.t3, self.t2 = Bucket(45), Bucket(18)
        self.retry_after = 0.0

    def call(self, method, params=None, write=False, token=None, tier=3):
        if time.time() < self.retry_after:
            raise SlackError('rate_limited: retry in %ds' % (self.retry_after - time.time()))
        if not (self.t3 if tier == 3 else self.t2).take(write):
            raise SlackError('rate_limited: local %s budget exhausted' % ('write' if write else 'read'))
        # Slack documents JSON request bodies only for write methods; the read
        # methods (conversations.replies, users.list, ...) take form encoding and
        # may silently ignore a JSON body, so reads are form-encoded.
        headers = {'Authorization': 'Bearer ' + (token or self.bot)}
        if write:
            data = json.dumps(params or {}).encode()
            headers['Content-Type'] = 'application/json; charset=utf-8'
        else:
            data = urllib.parse.urlencode(
                {k: (('true' if v else 'false') if isinstance(v, bool) else v)
                 for k, v in (params or {}).items()}).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req = urllib.request.Request('https://%s/api/%s' % (API_HOST, method), data=data,
                                     method='POST', headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.retry_after = time.time() + int(e.headers.get('Retry-After', '5'))
                raise SlackError('rate_limited: Retry-After %s' % e.headers.get('Retry-After'))
            raise SlackError('http %d' % e.code)
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SlackError('network_error: %s' % type(e).__name__)
        if not out.get('ok'):
            raise SlackError(out.get('error', 'unknown_error'))
        return out

    def download(self, url, max_bytes):
        """Bytes of one Slack-hosted file, at most max_bytes. The bot token goes
        to an exact Slack file host over https and nowhere else: redirects are
        refused rather than followed, because urllib would copy the
        Authorization header to whatever host the redirect names."""
        u = urllib.parse.urlsplit(url or '')
        if u.scheme != 'https' or u.hostname not in FILE_HOSTS or u.port not in (None, 443):
            raise SlackError('file_host_refused')
        if not self.t3.take(False):
            raise SlackError('rate_limited: local read budget exhausted')
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + self.bot})
        try:
            with opener.open(req, timeout=30) as r:
                if r.status != 200:
                    raise SlackError('http %d' % r.status)
                buf = b''
                while len(buf) <= max_bytes:
                    chunk = r.read(65536)
                    if not chunk:
                        return buf
                    buf += chunk
        except urllib.error.HTTPError as e:
            raise SlackError('file_redirect_refused' if 300 <= e.code < 400 else 'http %d' % e.code)
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SlackError('network_error: %s' % type(e).__name__)
        raise SlackError('file_too_large')


# --------------------------------------------------------------------------
# 6. socket — Socket Mode over a minimal RFC 6455 client
# --------------------------------------------------------------------------

class WS:
    """Just enough WebSocket for Slack: client handshake, masked text frames,
    ping/pong, close. No extensions, no fragmentation on send."""

    def __init__(self, url, timeout=30):
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == 'wss' else 80)
        raw = socket.create_connection((u.hostname, port), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) \
            if u.scheme == 'wss' else raw
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path + ('?' + u.query if u.query else '')
        self.sock.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n'
                           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
                           'Sec-WebSocket-Version: 13\r\n\r\n' % (path, u.hostname, key)).encode())
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise SlackError('websocket handshake closed')
            buf += chunk
        head, _, self.buf = buf.partition(b'\r\n\r\n')
        # SHA-1 is what RFC 6455 section 4.2.2 mandates for Sec-WebSocket-Accept.
        # It proves the server read our handshake; it protects nothing.
        accept = base64.b64encode(hashlib.sha1(  # NOSONAR
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if b' 101 ' not in head.split(b'\r\n')[0] or accept.encode() not in head:
            raise SlackError('websocket handshake refused')

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise SlackError('websocket closed')
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, text, opcode=0x1):
        data = text.encode() if isinstance(text, str) else text
        mask = os.urandom(4)
        n = len(data)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack('>H', n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack('>Q', n)
        self.sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        """Next text message, or None when the peer closed."""
        msg = b''
        while True:
            b0, b1 = self._read(2)
            op, n = b0 & 0x0f, b1 & 0x7f
            if n == 126:
                n = struct.unpack('>H', self._read(2))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._read(8))[0]
            payload = self._read(n)
            if op == 0x9:
                self.send(payload, 0xA)
            elif op == 0x8:
                return None
            elif op in (0x0, 0x1):
                msg += payload
                if b0 & 0x80:
                    return msg.decode()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# 7. daemon
# --------------------------------------------------------------------------

def _version_key(path):
    return [int(n) for n in re.findall(r'\d+', path)]


def find_webhook_py():
    """The local-webhook CLI that has `emit`. agent-box's `agent-box-webhook`
    wrapper does not, so default to the plugin's own webhook.py: next to this
    plugin in a checkout, else the newest one in the Claude plugin cache. The
    checkout is tried first so the common case never walks the cache (which can
    hold node_modules-sized trees)."""
    here = os.path.dirname(os.path.abspath(__file__))
    local = os.path.normpath(os.path.join(here, '..', 'local-webhook', 'webhook.py'))
    if os.path.isfile(local):
        return local
    cache = os.path.expanduser('~/.claude/plugins/cache')
    cands = []
    for root, _dirs, files in os.walk(cache) if os.path.isdir(cache) else []:
        if 'webhook.py' in files and 'local-webhook' in root:
            cands.append(os.path.join(root, 'webhook.py'))
    # os.walk order is arbitrary, so pick the highest version rather than the
    # first found: a stale cached copy must not win.
    return max(cands, key=_version_key) if cands else None


def emit_command():
    env = os.environ.get('LOCAL_SLACK_EMIT')
    if env:
        return env.split()
    wp = find_webhook_py()
    return [sys.executable or 'python3', wp, 'emit'] if wp else None


def make_emitter(source='slack'):
    """Deliver one event to the bus through `webhook.py emit`, which signs it
    with the source's own secret and posts it to the ingress, so it gets
    subscriptions AND standing-watch dispatch like any other delivery. Returns
    True on success: the outbox keeps a row until this does. The payload goes
    on stdin, not argv, where another local user could read it in /proc."""
    resolved = []   # resolved once; retried only while nothing was found

    def emit(action, payload):
        if not resolved or resolved[0] is None:
            resolved[:] = [emit_command()]
        cmd = resolved[0]
        if not cmd:
            print('local-slack: no emit command (set LOCAL_SLACK_EMIT, or install local-webhook)',
                  file=sys.stderr)
            return False
        body = dict(payload)
        # What the bus routes on. The source's keyPath must be `route` (see the
        # README): match_topic compares `slack:<route>` with `T/C`, so a field
        # holding `slack:T/C` would match nothing.
        body['route'] = '%s/%s' % (payload['team'], payload['channel'])
        try:
            r = subprocess.run(cmd + [source, '-', '--event', action], input=json.dumps(body).encode(),
                               check=False, timeout=15, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)
        except (OSError, subprocess.SubprocessError) as e:
            print('local-slack: emit %s failed: %s' % (action, e), file=sys.stderr)
            return False
        if r.returncode:
            err = (r.stderr or b'').decode('utf-8', 'replace').strip()
            print('local-slack: emit %s exited %d%s' % (action, r.returncode, ': ' + err if err else ''),
                  file=sys.stderr)
            if 'no ingress' in err and not os.environ.get('LOCAL_WEBHOOK_HTTP_SOCK'):
                # A socket-activated receiver (agent-box) writes its discovery
                # file only once something has connected, so under a clean
                # systemd environment `emit` cannot find it by itself.
                print('local-slack: hint: set LOCAL_WEBHOOK_HTTP_SOCK to the receiver socket in this '
                      "daemon's environment (see the README, Setup step 4)", file=sys.stderr)
            return False
        return True
    return emit


def drain_outbox(store, emitter, limit=1000):
    """Deliver queued events oldest first; stop at the first failure so order
    is kept. Returns how many went out."""
    n = 0
    while n < limit:
        row = store.outbox_next()
        if row is None or not emitter(row['action'], json.loads(row['payload'])):
            break
        store.outbox_done(row['id'])
        n += 1
    return n


def make_users_lookup(web, ttl=3600):
    """users.info as {'guest','external'}, cached. Fails CLOSED: on any error
    the user counts as both, so a control reaction from someone Slack could not
    vouch for is ignored."""
    cache = {}

    def users(uid):
        hit = cache.get(uid)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        try:
            u = web.call('users.info', {'user': uid})['user']
            out = {'guest': bool(u.get('is_restricted') or u.get('is_ultra_restricted')
                                 or u.get('is_bot') or u.get('deleted')),
                   'external': bool(u.get('is_stranger'))}
        except (SlackError, KeyError):
            return {'guest': True, 'external': True}   # not cached: ask again next time
        cache[uid] = (time.time(), out)
        return out
    return users


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True
    except (OSError, TypeError, ValueError):
        return False


def write_connection_status(state, **info):
    """One small file `doctor` reads, since a daemon that logs only errors
    cannot otherwise be asked whether it is connected."""
    doc = dict(info, state=state, at=int(time.time()), pid=os.getpid())
    path = os.path.join(state_dir(), 'connection.json')
    try:
        with open(path + '.tmp', 'w') as f:
            json.dump(doc, f)
        os.replace(path + '.tmp', path)
    except OSError as e:
        print('local-slack: cannot write %s: %s' % (path, e), file=sys.stderr)


def run_daemon():
    bot_token, app_token = credential('SLACK_BOT_TOKEN'), credential('SLACK_APP_TOKEN')
    if not bot_token or not app_token:
        sys.exit('local-slack: SLACK_BOT_TOKEN and SLACK_APP_TOKEN must both be set '
                 '(environment or a credentials file)')
    sock_path = os.environ.get('LOCAL_SLACK_SOCKET')
    try:
        allowed = parse_uids(os.environ.get('LOCAL_SLACK_ALLOWED_UIDS', '')) if sock_path else None
    except ValueError as e:
        sys.exit('local-slack: %s' % e)
    if sock_path and not allowed:
        sys.exit('local-slack: LOCAL_SLACK_SOCKET is set but LOCAL_SLACK_ALLOWED_UIDS names no user')
    web = Web(bot_token, app_token)
    me = web.call('auth.test')
    # auth.test's `url` is this workspace's own host, which permalinks should use.
    wurl = me.get('url') or ''
    bot = {'user_id': me['user_id'], 'bot_id': me.get('bot_id'), 'team': me.get('team_id') or '',
           'url': wurl if wurl.endswith('/') else wurl + '/' if wurl else ''}
    store = Store(os.path.join(state_dir(), 'slack.db'))
    channels, defaults = load_config()

    def lookup(channel, ts):
        try:
            r = web.call('conversations.replies', {'channel': channel, 'ts': ts, 'limit': 1})
            m = (r.get('messages') or [{}])[0]
            return m.get('thread_ts') or m.get('ts')
        except SlackError:
            return None

    def react(channel, ts, emoji):
        # Best effort and off the receive thread: the ack reaction must not
        # hold the Socket Mode acknowledgement.
        def go():
            try:
                web.call('reactions.add', {'channel': channel, 'timestamp': ts, 'name': emoji}, write=True)
            except SlackError:
                pass
        threading.Thread(target=go, daemon=True).start()

    tracker = Tracker(store, channels, bot, store.outbox_put, lookup=lookup, react=react,
                      users=make_users_lookup(web), retention_days=defaults['retention_days'],
                      defaults=defaults)

    def prime_channels():
        for cid in list(tracker.channels):
            if cid not in tracker.external:
                try:
                    tracker.prime(cid, web.call('conversations.info', {'channel': cid})['channel'])
                except (SlackError, KeyError):
                    pass   # unknown stays unknown; a channel_shared event still flips it
    prime_channels()

    emitter = make_emitter()
    wake = threading.Event()

    def outbox_worker():
        delay = 1
        while True:
            try:
                if drain_outbox(store, emitter):
                    delay = 1
                elif store.outbox_next() is not None:
                    delay = min(delay * 2, 60)   # the bus is down: back off, keep the rows
                else:
                    delay = 1
            except Exception as e:
                print('local-slack: outbox failed: %s' % e, file=sys.stderr)
            wake.wait(delay if store.outbox_next() is not None else 5)
            wake.clear()
    threading.Thread(target=outbox_worker, daemon=True).start()

    def ticker():
        while True:
            time.sleep(TICK_SECONDS)
            # One bad tick must not end the thread: a dead ticker means no
            # thread ever settles again, with the daemon still looking healthy.
            try:
                tracker.channels, d = load_config()   # hot-reload the allowlist
                tracker.retention_days = d['retention_days']
                tracker.defaults = d
                prime_channels()
                tracker.tick()
                wake.set()
            except Exception as e:
                print('local-slack: tick failed: %s' % e, file=sys.stderr)
    threading.Thread(target=ticker, daemon=True).start()

    if sock_path:
        ctx = Ctx(web, store, lambda: tracker.channels, lambda: tracker.defaults, bot)
        serve_socket(sock_path, allowed, ctx)

    backoff = 1
    while True:
        ws, t0 = None, time.time()
        try:
            url = web.call('apps.connections.open', token=app_token)['url']
            ws = WS(url)
            info = {'team': me.get('team_id'), 'bot_user': me['user_id'], 'channels': len(tracker.channels)}
            print('local-slack: connected to Socket Mode (team %s, bot %s, %d configured channels)' % (
                info['team'], info['bot_user'], info['channels']), file=sys.stderr, flush=True)
            write_connection_status('connected', **info)
            while True:
                raw = ws.recv()
                if raw is None:
                    break
                env = json.loads(raw)
                if env.get('type') == 'disconnect':
                    break
                if env.get('type') == 'events_api':
                    # Persist (the thread rows and the outbox) BEFORE
                    # acknowledging, so a crash between the two is covered by
                    # Slack's redelivery. A failure here leaves the envelope
                    # unacknowledged AND unmarked as seen, so the redelivery is
                    # processed rather than dropped as a duplicate.
                    try:
                        tracker.handle(env['payload'])
                    except Exception as e:
                        print('local-slack: handling an event failed: %s' % e, file=sys.stderr)
                        continue
                    ws.send(json.dumps({'envelope_id': env['envelope_id']}))
                    wake.set()
        except Exception as e:
            print('local-slack: %s; reconnecting in %ds' % (e, backoff), file=sys.stderr)
        finally:
            # Every exit from the inner loop (disconnect, EOF, error) leaves the
            # old socket behind otherwise; close it before dialling again.
            if ws is not None:
                ws.close()
            write_connection_status('disconnected')
        # Only a connection that lasted counts as healthy: a server that
        # disconnects at once (link_disabled) must not be redialled every second.
        backoff = 1 if time.time() - t0 > 30 else min(backoff * 2, 60)
        time.sleep(backoff)


# --------------------------------------------------------------------------
# 8. cli
# --------------------------------------------------------------------------

USAGE = '''local-slack %s

  slack.py daemon                         run the Socket Mode daemon
  slack.py doctor
  slack.py channels
  slack.py channel add CHANNEL_ID [--track all|mention|reaction:EMOJI] [--quiet MIN]
                       [--write] [--allow-external]
  slack.py channel rm CHANNEL_ID
  slack.py thread CHANNEL TS               messages, with each one's files listed
  slack.py file CHANNEL TS FILE_ID         save one allowed file; prints its local path
  slack.py reply CHANNEL TS TEXT
  slack.py post CHANNEL TEXT
  slack.py status CHANNEL TS TEXT [--done|--failed]
  slack.py react CHANNEL TS EMOJI
  slack.py purge

Tokens come from SLACK_BOT_TOKEN / SLACK_APP_TOKEN, or a credentials file
($CREDENTIALS_DIRECTORY). With LOCAL_SLACK_SOCKET set, the commands go through
the daemon's Unix socket instead and this process holds no token. Writes go
through the guardrails in compose() and the per-channel write settings.''' % VERSION


_TS_RE = re.compile(r'\d{9,}\.\d{1,9}')


class Writer:
    """Every outgoing message passes here: allowlist, mode, compose, disclosure,
    send, audit. The agent never gets to bypass any step."""

    def __init__(self, web, store, channels, defaults, bot, session=None):
        self.web, self.store, self.channels = web, store, channels
        self.defaults, self.bot = defaults, bot
        # agent-box exports AGENT_BOX_SESSION_ID; with neither set every session
        # shares one empty name and the per-session cap becomes box-wide.
        self.session = session or os.environ.get('AGENT_BOX_SESSION_ID') or os.environ.get('AGENT_BOX_SESSION', '')
        self._names = {}

    def resolver(self, sigil, name):
        key = sigil + name
        if key in self._names:
            return self._names[key]
        found = set()
        try:
            if sigil == '@':
                cur = None
                while True:
                    r = self.web.call('users.list', {'limit': 200, **({'cursor': cur} if cur else {})})
                    for m in r.get('members', []):
                        if m.get('deleted'):
                            continue   # a deactivated user is not who anyone means
                        if name in (m.get('name'), (m.get('profile') or {}).get('display_name')):
                            found.add(m['id'])
                    cur = (r.get('response_metadata') or {}).get('next_cursor')
                    if not cur:
                        break
            elif sigil == '#':
                r = self.web.call('conversations.list', {'limit': 1000, 'types': 'public_channel,private_channel'})
                for c in r.get('channels', []):
                    if c.get('name') == name and c['id'] in self.channels:
                        found.add(c['id'])
        except SlackError:
            found = set()
        # Two people called `sam` is not a mention of either: leave it as text.
        rid = found.pop() if len(found) == 1 else None
        self._names[key] = rid
        return rid

    def _ts(self, ts):
        if not isinstance(ts, str) or not _TS_RE.fullmatch(ts):
            raise Refused('bad message ts %r' % (ts,))
        return ts

    def _parent(self, channel, ts):
        """A reply's ts normalised to its thread's parent, so the on_request
        lookup and thread_ts both see the thread, not the reply."""
        r = self.store.q('SELECT thread_ts FROM msgs WHERE channel=? AND ts=?', channel, ts)
        return r[0]['thread_ts'] if r else ts

    def _check(self, channel, thread_ts, top_level):
        cfg = self.channels.get(channel)
        if cfg is None:
            raise Refused('channel %s is not configured' % channel)
        w = cfg['write']
        if not w['allowed']:
            raise Refused('writing is not allowed in %s (write.allowed)' % channel)
        if top_level and not w['top_level']:
            raise Refused('top-level posts need write.top_level')
        if not top_level and w['mode'] == 'on_request':
            # Reply only after a human mentioned the bot there or added ready.
            rows = self.store.q("SELECT 1 FROM threads WHERE channel=? AND thread_ts=? AND "
                                "asked=1", channel, thread_ts)
            if not rows:
                raise Refused('write.mode is on_request: reply only after a mention or the ready reaction')
        return cfg

    def _rate(self, channel, top_level):
        lim = dict(DEFAULT_DEFAULTS['limits'], **(self.defaults.get('limits') or {}))
        now = time.time()
        cap, window = lim.get('session_writes'), lim.get('session_window_s') or 600
        if cap:
            n = self.store.q("SELECT COUNT(*) c FROM audit WHERE session=? AND at>? AND kind != 'status_edit'",
                             self.session, now - window)[0]['c']
            if n >= cap:
                raise Refused('at most %d writes per session per %d seconds' % (cap, window))
        cap = lim.get('top_level_per_hour')
        if top_level and cap:
            c = self.store.q("SELECT COUNT(*) c FROM audit WHERE channel=? AND kind='post' AND at>?",
                             channel, now - 3600)[0]['c']
            if c >= cap:
                raise Refused('at most %d top-level posts per channel per hour' % cap)

    def _index(self, channel, ts, thread_ts):
        """Index our own post, so a 👍/👎 on it resolves to its thread."""
        if ts:
            self.store.x('INSERT OR REPLACE INTO msgs VALUES (?,?,?,?,?,?,?)', self.team or '', channel,
                         ts, thread_ts or ts, self.bot.get('user_id'), 1, time.time())

    team = ''

    def _send(self, kind, channel, thread_ts, text, top_level=False):
        if thread_ts is not None:
            thread_ts = self._parent(channel, self._ts(thread_ts))
        cfg = self._check(channel, thread_ts, top_level)
        self._rate(channel, top_level)
        unresolved = []
        body = compose(text, self.resolver, cfg, self.defaults, unresolved)
        if self.defaults.get('disclosure'):
            body += '\n\n' + self.defaults['disclosure']
        if len(body) > 4000:
            raise Refused('message over 4,000 characters; upload a file instead')
        params = {'channel': channel, 'text': body, 'unfurl_links': False, 'unfurl_media': False}
        if thread_ts:
            params['thread_ts'] = thread_ts
        r = self.web.call('chat.postMessage', params, write=True)
        self._index(channel, r.get('ts'), thread_ts)
        self.audit(kind, channel, thread_ts, r.get('ts'), body)
        # A name nothing resolved went out as plain text and pinged nobody:
        # say so, or a typo'd @name fails silently and the agent never knows.
        return dict(r, unresolved=unresolved)

    def audit(self, kind, channel, thread, ts, text):
        self.store.x('INSERT INTO audit VALUES (?,?,?,?,?,?,?)', time.time(), channel, thread, ts,
                     self.session, kind, text)

    def reply(self, channel, ts, text):
        # _send treats thread_ts=None as a top-level post, so a reply must prove
        # it has a ts here rather than rely on it.
        return self._send('reply', channel, self._ts(ts), text)

    def post(self, channel, text):
        return self._send('post', channel, None, text, top_level=True)

    def _mark(self, channel, ts, emoji, remove=()):
        """Move the thread's progress reaction: drop the earlier ones, add this."""
        for old in remove:
            try:
                self.web.call('reactions.remove', {'channel': channel, 'timestamp': ts, 'name': old}, write=True)
            except SlackError:
                pass   # not there is fine
        try:
            self.web.call('reactions.add', {'channel': channel, 'timestamp': ts, 'name': emoji}, write=True)
        except SlackError as e:
            if str(e) != 'already_reacted':
                raise

    def status(self, channel, ts, text, mark=None):
        """One status message per thread, created then edited. It passes the
        same gates as a reply (on_request, rate, length) -- a status is a write
        into the thread -- and only its EDITS are exempt from the per-session
        count. Progress shows as a reaction on the parent: the daemon's 👀 ack
        becomes ⏳, then ✅ or ❌."""
        ts = self._parent(channel, self._ts(ts))
        cfg = self._check(channel, ts, False)
        k = '%s/%s' % (channel, ts)
        rows = self.store.q('SELECT thread_key FROM threads WHERE channel=? AND thread_ts=?', channel, ts)
        if rows:
            k = rows[0]['thread_key']
        have = self.store.q('SELECT ts FROM status WHERE thread_key=?', k)
        if not have:
            self._rate(channel, False)
        unresolved = []
        body = compose(text, self.resolver, cfg, self.defaults, unresolved)
        if len(body) > 4000:
            raise Refused('message over 4,000 characters; upload a file instead')
        if have:
            r = self.web.call('chat.update', {'channel': channel, 'ts': have[0]['ts'], 'text': body}, write=True)
            self.audit('status_edit', channel, ts, have[0]['ts'], body)
        else:
            r = self.web.call('chat.postMessage', {'channel': channel, 'thread_ts': ts, 'text': body,
                                                    'unfurl_links': False, 'unfurl_media': False}, write=True)
            self.store.x('INSERT OR REPLACE INTO status VALUES (?,?)', k, r['ts'])
            self._index(channel, r.get('ts'), ts)
            self.audit('status', channel, ts, r.get('ts'), body)
        marks = self.defaults.get('status_marks') or {}
        state = mark or 'working'
        if marks.get(state):
            # Progress reactions only when the deployment named them: the 👀 ack
            # (if any) and the other states' marks give way to this one.
            self._mark(channel, ts, marks[state],
                       remove=[e for e in [cfg['reactions'].get('ack')] +
                               [m for st, m in marks.items() if st != state] if e])
        return dict(r, unresolved=unresolved)

    def react(self, channel, ts, emoji):
        ts = self._ts(ts)
        cfg = self.channels.get(channel)
        if cfg is None or not cfg['write']['allowed']:
            raise Refused('writing is not allowed in %s' % channel)
        if not re.fullmatch(r'[a-z0-9_+-]{1,64}', emoji):
            raise Refused('bad emoji name')
        self._rate(channel, False)
        try:
            self.web.call('reactions.add', {'channel': channel, 'timestamp': ts, 'name': emoji}, write=True)
        except SlackError as e:
            if str(e) != 'already_reacted':   # de-duplicated per (ts, emoji)
                raise
        self.audit('react', channel, ts, ts, ':%s:' % emoji)


# --------------------------------------------------------------------------
# 7b. socket-service mode: the daemon alone holds the tokens
# --------------------------------------------------------------------------
#
# MECHANISM, NOT POLICY: the daemon listens on LOCAL_SLACK_SOCKET and serves the
# write commands through the same Writer as the CLI. WHO may connect is a uid
# allowlist (LOCAL_SLACK_ALLOWED_UIDS, numbers or user names) checked against
# SO_PEERCRED, which the kernel fills in and the client cannot forge. Which
# user runs the daemon, where the socket lives and who gets its group are the
# deployment's choice. The session name in a request is the caller's own claim:
# it is audited, and rate-limited, next to the verified uid.



# Protective bounds. Constants here; read when used, so they can be tuned.
MAX_REQUEST = 64 * 1024
MAX_CONNECTIONS = 32
SERVER_TIMEOUT_S = 10    # a connected peer must send its request within this
LOCK_WAIT_S = 10         # a write waits this long for the one write lock
CLIENT_TIMEOUT_S = 90    # must exceed LOCK_WAIT_S plus a Slack round trip
SOCKET_COMMANDS = ('reply', 'post', 'status', 'react', 'thread', 'file')


def parse_uids(spec):
    import pwd
    uids = set()
    for item in re.split(r'[,\s]+', spec or ''):
        if not item:
            continue
        try:
            uids.add(int(item))
        except ValueError:
            try:
                uids.add(pwd.getpwnam(item).pw_uid)
            except KeyError:
                # The list was written deliberately: a typo must not start the
                # daemon with a shorter one.
                raise ValueError('unknown user %r in LOCAL_SLACK_ALLOWED_UIDS' % item)
    return uids


class Ctx:
    """What a request handler needs; channels and defaults are callables because
    the ticker hot-reloads them."""

    def __init__(self, web, store, channels, defaults, bot):
        self.web, self.store, self.channels, self.defaults, self.bot = web, store, channels, defaults, bot
        # Writer._rate counts audit rows that Writer.audit adds only after the
        # Slack round trip, so concurrent writes would all pass the caps.
        self.write_lock = threading.Lock()


def execute(w, cmd, rest):
    """One write or read command against a Writer; shared by the CLI (plain
    mode) and the socket, so a guardrail cannot differ between them."""
    if cmd == 'reply' and len(rest) == 3:
        r = w.reply(*rest)
    elif cmd == 'post' and len(rest) == 2:
        r = w.post(*rest)
    elif cmd == 'status' and len(rest) >= 3:
        args = rest[3:]
        r = w.status(rest[0], rest[1], rest[2], 'done' if '--done' in args else 'failed' if '--failed' in args else None)
    elif cmd == 'react' and len(rest) == 3:
        w.react(*rest)
        r = {}
    elif cmd == 'file' and len(rest) == 3:
        fid, ext, data = fetch_file(w.web, w.channels, w.defaults, *rest)
        return {'id': fid, 'ext': ext, 'data': base64.b64encode(data).decode()}
    else:
        raise Refused('usage: %s' % cmd)
    out = {'ts': r.get('ts')}
    if r.get('unresolved'):
        out['unresolved'] = r['unresolved']
    return out


# MIME type -> (extension, signature check). The saved extension comes from
# here, never from the sender's file name.
FILE_TYPES = {
    'image/png': ('png', lambda b: b.startswith(b'\x89PNG\r\n\x1a\n')),
    'image/jpeg': ('jpg', lambda b: b.startswith(b'\xff\xd8\xff')),
    'image/gif': ('gif', lambda b: b[:6] in (b'GIF87a', b'GIF89a')),
    'image/webp': ('webp', lambda b: b[:4] == b'RIFF' and b[8:12] == b'WEBP'),
    'application/pdf': ('pdf', lambda b: b.startswith(b'%PDF-')),
}
_CTRL = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')


def _transcript(f):
    """Slack's own transcript of an audio or video clip, when it made one. The
    field shape is undocumented: this reads transcription.preview.content, a
    transcription string and a preview string, and must be checked against a
    real clip. Slack only makes one after a person asks for it."""
    t = f.get('transcription')
    cand = None
    if isinstance(t, dict):
        p = t.get('preview')
        cand = (p.get('content') if isinstance(p, dict) else p) or t.get('content')
    elif isinstance(t, str):
        cand = t
    return cand if isinstance(cand, str) and cand.strip() else None


def file_meta(f):
    m = {'id': f.get('id'), 'name': _CTRL.sub('', str(f.get('name') or f.get('title') or ''))[:200],
         'mimetype': f.get('mimetype'), 'size': f.get('size'), 'subtype': f.get('subtype')}
    if str(f.get('mimetype') or '').split('/')[0] in ('audio', 'video') or f.get('subtype') == 'slack_audio':
        t = _transcript(f)
        m['transcript'] = t[:8000] if t else None
        if not t:
            m['transcript_note'] = 'Slack has no transcript for this clip'
    return m


def read_thread(web, channel, ts):
    r = web.call('conversations.replies', {'channel': channel, 'ts': ts, 'limit': 200})
    out = []
    for m in r.get('messages', []):
        row = {'ts': m.get('ts'), 'user': m.get('user'), 'text': m.get('text')}
        if m.get('files'):
            row['files'] = [file_meta(f) for f in m['files'] if isinstance(f, dict)]
        out.append(row)
    return out


def fetch_file(web, channels, defaults, channel, ts, file_id):
    """One file from one allowlisted thread message, checked; returns
    (file id, extension, bytes). Shared by plain mode and the daemon, so the
    guards cannot differ between them."""
    if channel not in channels:
        raise Refused('channel %s is not configured' % channel)
    cfg = defaults.get('files') or {}
    allowed = [t for t in cfg.get('types', []) if t in FILE_TYPES]
    cap = int(cfg.get('max_bytes') or 0)
    if cap <= 0:
        raise Refused('file downloads are turned off (_defaults.files.max_bytes)')
    f, cursor = None, None
    # Slack pages this method and may return fewer than `limit`, so follow the
    # cursor (bounded) instead of trusting the first response to hold the message.
    for _page in range(10):
        r = web.call('conversations.replies', dict({'channel': channel, 'ts': ts, 'limit': 200},
                                                   **({'cursor': cursor} if cursor else {})))
        f = next((f for m in r.get('messages', []) if m.get('ts') == ts
                  for f in m.get('files') or [] if isinstance(f, dict) and f.get('id') == file_id), None)
        cursor = (r.get('response_metadata') or {}).get('next_cursor')
        if f is not None or not cursor:
            break
    if f is None:
        raise Refused('file %s is not on message %s' % (file_id, ts))
    if f.get('mode') in ('external', 'file_access') or f.get('is_external') or f.get('filetype') == 'remote':
        raise Refused('file %s is external or remote; not downloaded' % file_id)
    mime = f.get('mimetype')
    if mime not in allowed:
        raise Refused('file type %s is not allowed (allowed: %s)' % (mime, ', '.join(allowed) or 'none'))
    size = f.get('size')
    if not isinstance(size, int) or size > cap:
        raise Refused('file %s is larger than %d bytes' % (file_id, cap))
    if not re.fullmatch(r'[A-Za-z0-9]{1,32}', str(file_id)):
        raise Refused('bad file id')
    try:
        data = web.download(f.get('url_private'), cap)
    except SlackError as e:
        raise Refused('download failed: %s' % e)
    ext, sig = FILE_TYPES[mime]
    if not sig(data):
        raise Refused('file %s is not a real %s (first bytes do not match)' % (file_id, mime))
    return file_id, ext, data


def save_file(file_id, ext, data, total_cap=0, directory=None):
    """Write the bytes under this user's state dir as <file id>.<ext>, mode
    0600, .part then rename; prune the oldest files past total_cap."""
    if total_cap and len(data) > total_cap:
        raise Refused('file is larger than the total file cache (%d bytes)' % total_cap)
    d = directory or os.path.join(state_dir(), 'files')
    os.makedirs(d, mode=0o700, exist_ok=True)
    final = os.path.join(d, '%s.%s' % (file_id, ext))
    part = '%s.%d.part' % (final, os.getpid())
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        os.rename(part, final)
    except BaseException:
        try:
            os.unlink(part)
        except OSError:
            pass
        raise
    if total_cap:
        files = sorted(((os.stat(p).st_mtime, p) for p in (os.path.join(d, n) for n in os.listdir(d))
                        if os.path.isfile(p) and p != final), reverse=True)
        used = len(data)
        for _mt, p in files:
            used += os.path.getsize(p)
            if used > total_cap:
                try:
                    os.unlink(p)
                except OSError:
                    pass
    return final


def client_gone(conn):
    """True when the peer has hung up (a peek returns EOF). A request nobody is
    waiting for must not reach Slack, or the agent retries it and it posts twice."""
    if conn is None:
        return False
    try:
        # select first: a socket with a timeout would otherwise wait it out.
        if not select.select([conn], [], [], 0)[0]:
            return False
        return conn.recv(1, socket.MSG_PEEK) == b''
    except OSError:
        return True


def handle_request(ctx, uid, req, conn=None):
    """A decoded request from a peer whose uid was already checked. Returns the
    response dict; every failure becomes ok=false, never a crash and never
    silence."""
    try:
        cmd, args = req.get('cmd'), req.get('args')
        if cmd not in SOCKET_COMMANDS:
            raise Refused('unknown command %r' % (cmd,))
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise Refused('args must be a list of strings')
        name = req.get('session')
        session = 'uid%d/%s' % (uid, name[:64] if isinstance(name, str) else '')
        channels = ctx.channels()
        if cmd == 'thread':
            if len(args) != 2:
                raise Refused('usage: thread CHANNEL TS')
            if args[0] not in channels:
                raise Refused('channel %s is not configured' % args[0])
            return {'ok': True, 'messages': read_thread(ctx.web, *args)}
        if cmd == 'file':
            if len(args) != 3:
                raise Refused('usage: file CHANNEL TS FILE_ID')
            return dict(execute(Writer(ctx.web, ctx.store, channels, ctx.defaults(), ctx.bot,
                                       session=session), cmd, args), ok=True)
        w = Writer(ctx.web, ctx.store, channels, ctx.defaults(), ctx.bot, session=session)
        w.team = ctx.bot.get('team') or ''
        if not ctx.write_lock.acquire(timeout=LOCK_WAIT_S):
            raise Refused('daemon is busy with another write; try again')
        try:
            if client_gone(conn):
                return {'ok': False, 'error': 'client went away before the write started'}
            return dict(execute(w, cmd, args), ok=True)
        finally:
            ctx.write_lock.release()
    except (Refused, SlackError) as e:
        return {'ok': False, 'error': str(e)}
    except Exception as e:
        print('local-slack: request failed: %r' % e, file=sys.stderr)
        return {'ok': False, 'error': 'internal error; see the daemon log'}


def peer_uid(conn):
    pid, uid, gid = struct.unpack('iII', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                       struct.calcsize('iII')))
    return uid


def _read_line(conn):
    buf = b''
    while b'\n' not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_REQUEST:
            raise Refused('request too large')
    return buf.split(b'\n', 1)[0]


def serve_connection(conn, allowed, ctx):
    with conn:
        conn.settimeout(SERVER_TIMEOUT_S)
        try:
            uid = peer_uid(conn)
            if uid not in allowed:
                print('local-slack: refused a connection from uid %d (not in the allowlist)' % uid,
                      file=sys.stderr)
                resp = {'ok': False, 'error': 'uid %d is not allowed' % uid}
            else:
                try:
                    req = json.loads(_read_line(conn).decode())
                    if not isinstance(req, dict):
                        raise ValueError
                except (ValueError, UnicodeDecodeError):
                    resp = {'ok': False, 'error': 'bad request'}
                else:
                    resp = handle_request(ctx, uid, req, conn)
            conn.sendall(json.dumps(resp).encode() + b'\n')
        except Refused as e:
            conn.sendall(json.dumps({'ok': False, 'error': str(e)}).encode() + b'\n')
        except Exception as e:   # one bad peer must not stop the listener
            print('local-slack: socket request failed: %s' % e, file=sys.stderr)


def bind_socket(path):
    """Bind PATH, replacing a stale socket but never a live one or another kind
    of file. The socket is bound under a temporary name in the same directory,
    given its final mode, then renamed into place: no window exists in which it
    is more open than asked, and a failure never leaves a mode-0 socket at PATH.
    The directory must be writable only by the daemon's user, because this logic
    unlinks and renames by path."""
    import stat
    mode = os.environ.get('LOCAL_SLACK_SOCKET_MODE') or '660'
    try:
        mode_bits = int(mode, 8)
    except ValueError:
        raise OSError('LOCAL_SLACK_SOCKET_MODE %r is not an octal mode' % mode)
    try:
        st = os.lstat(path)
        if not stat.S_ISSOCK(st.st_mode):
            raise OSError('%s exists and is not a socket' % path)
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(path)
        except ConnectionRefusedError:
            os.unlink(path)   # nobody listens: stale
        except PermissionError:
            if st.st_uid != os.getuid():
                raise OSError('cannot judge the socket at %s (not ours)' % path)
            os.unlink(path)   # ours, and closed to us: a leftover
        except OSError:
            pass   # not ours to judge; bind below reports it
        else:
            raise OSError('a daemon is already serving %s' % path)
        finally:
            probe.close()
    except FileNotFoundError:
        pass
    tmp = '%s.%d.tmp' % (path, os.getpid())
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o777)
    try:
        srv.bind(tmp)
    except BaseException:
        srv.close()
        raise
    finally:
        os.umask(old)
    try:
        os.chmod(tmp, mode_bits)
        os.rename(tmp, path)
    except BaseException:
        srv.close()
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    srv.listen(16)
    return srv


def serve_socket(path, allowed, ctx):
    srv = bind_socket(path)
    print('local-slack: serving writes on %s for uid(s) %s' % (path, ','.join(map(str, sorted(allowed)))),
          file=sys.stderr, flush=True)

    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def handle(conn):
        try:
            serve_connection(conn, allowed, ctx)
        finally:
            slots.release()

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError as e:
                # EMFILE and friends are transient; a closed listener is not.
                print('local-slack: accept failed: %s' % e, file=sys.stderr)
                if e.errno in (errno.EBADF, errno.ENOTSOCK, errno.EINVAL):
                    return
                time.sleep(0.5)
                continue
            if not slots.acquire(blocking=False):
                try:
                    conn.settimeout(1)
                    conn.sendall(json.dumps({'ok': False, 'error': 'busy'}).encode() + b'\n')
                except OSError:
                    pass
                conn.close()   # shed load rather than grow without bound
                continue
            try:
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except RuntimeError:
                slots.release()
                conn.close()
    threading.Thread(target=loop, daemon=True).start()


def socket_call(path, cmd, args, session=None):
    """The CLI side: one request, one answer. Holds no token."""
    session = session or os.environ.get('AGENT_BOX_SESSION_ID') or os.environ.get('AGENT_BOX_SESSION', '')
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(CLIENT_TIMEOUT_S)
    try:
        c.connect(path)
        sent = None
        try:
            c.sendall(json.dumps({'cmd': cmd, 'args': args, 'session': session}).encode() + b'\n')
        except (BrokenPipeError, ConnectionResetError) as e:
            # A daemon that sheds us answers and closes before we write; the
            # answer is still readable, so read it rather than hide it.
            sent = e
        buf = b''
        while not buf.endswith(b'\n'):
            try:
                chunk = c.recv(65536)
            except OSError:
                if sent is None:
                    raise
                chunk = b''
            if not chunk:
                break
            buf += chunk
        if sent is not None and not buf:
            raise sent
    except OSError as e:
        raise Refused('no answer from the local-slack daemon at %s: %s (the request may still have '
                      'been sent; check the thread before retrying)' % (path, e))
    finally:
        c.close()
    try:
        resp = json.loads(buf.decode())
    except ValueError:
        raise Refused('bad answer from the local-slack daemon')
    if not resp.get('ok'):
        raise Refused(resp.get('error') or 'refused')
    return resp


def _opt(args, name, default=None, flag=False):
    if name in args:
        i = args.index(name)
        if flag:
            args.pop(i)
            return True
        if i + 1 >= len(args):
            raise Refused('%s needs a value' % name)
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return False if flag else default


def channel_add(cid, args, web=None, path=None):
    """Create or UPDATE a channel entry. Only the flags given change; an
    existing entry keeps its controllers, write settings and everything else
    hand-tuned in the file."""
    raw = read_raw(path)
    # A new entry starts from the file's `_channel_defaults` template (its
    # contents are the deployment's policy; copying it is the mechanism). An
    # existing entry is never re-templated, and explicit flags below still win.
    tmpl = raw.get('_channel_defaults')
    entry = dict(raw[cid]) if isinstance(raw.get(cid), dict) else (
        json.loads(json.dumps(tmpl)) if isinstance(tmpl, dict) else {})
    track = _opt(args, '--track')
    quiet = _opt(args, '--quiet')
    write = _opt(args, '--write', flag=True)
    ext = _opt(args, '--allow-external', flag=True)
    if args:
        raise Refused('unknown arguments: %s' % ' '.join(args))
    if track is not None:
        if not re.fullmatch(r'reaction:[a-z0-9_+-]+|all|mention', track):
            raise Refused('bad --track')
        entry['track'] = track
    if quiet is not None:
        entry['quiet_minutes'] = int(quiet)
    if write:
        entry['write'] = dict(entry.get('write') or {}, allowed=True)
    if ext:
        entry['allow_external'] = True
    if web is not None:
        # The bot must already be in the channel (a person invites it: that is
        # the consent step), and a Slack Connect channel needs an explicit opt-in.
        try:
            info = web.call('conversations.info', {'channel': cid})['channel']
        except (SlackError, KeyError) as e:
            raise Refused('cannot look up %s (%s); is the bot invited?' % (cid, e))
        if not info.get('is_member'):
            raise Refused('the bot is not a member of %s; ask someone to /invite it first' % cid)
        if info.get('is_ext_shared') and not entry.get('allow_external'):
            raise Refused('%s is a Slack Connect channel; pass --allow-external to opt in' % cid)
    raw[cid] = entry
    write_raw(raw, path)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == 'daemon':
        run_daemon()
        return 0
    try:
        return _main(cmd, rest)
    except (Refused, SlackError) as e:
        print('local-slack: refused: %s' % e, file=sys.stderr)
        return 1


LOCAL_ONLY = ('channels', 'channel', 'purge')


def _main(cmd, rest):
    if os.environ.get('LOCAL_SLACK_SOCKET') and cmd in LOCAL_ONLY:
        # These read and write THIS user's channels.json and slack.db, which a
        # daemon running as another user never reads, and `channel add` would
        # skip its membership and Slack Connect checks without a token.
        raise Refused('`%s` is not available through the socket: run it as the daemon\'s user with '
                      'LOCAL_SLACK_SOCKET unset' % cmd)
    channels, defaults = load_config()
    if cmd == 'channels':
        for cid, c in sorted(channels.items()):
            print('%s track=%s quiet=%dm write=%s/%s external_ok=%s' % (
                cid, c['track'], c['quiet_minutes'], c['write']['allowed'], c['write']['mode'],
                c['allow_external']))
        return 0
    if cmd == 'channel' and rest[:1] == ['add'] and len(rest) >= 2:
        token = None if os.environ.get('LOCAL_SLACK_SOCKET') else credential('SLACK_BOT_TOKEN')
        channel_add(rest[1], rest[2:], Web(token) if token else None)
        print('saved %s' % rest[1])
        return 0
    if cmd == 'channel' and rest[:1] == ['rm'] and len(rest) == 2:
        raw = read_raw()
        raw.pop(rest[1], None)
        write_raw(raw)
        Store(os.path.join(state_dir(), 'slack.db')).purge_channel(rest[1])
        print('removed %s and purged its rows' % rest[1])
        return 0
    if cmd == 'purge':
        Store(os.path.join(state_dir(), 'slack.db')).purge_all()
        print('purged')
        return 0
    sock = os.environ.get('LOCAL_SLACK_SOCKET')
    if sock:
        return _socket_main(sock, cmd, rest)
    bot_token = credential('SLACK_BOT_TOKEN')
    if not bot_token:
        sys.exit('local-slack: SLACK_BOT_TOKEN is not set')
    web = Web(bot_token)
    if cmd == 'doctor':
        me = web.call('auth.test')
        print('team %s user %s bot %s token …%s' % (me.get('team_id'), me.get('user_id'),
                                                  me.get('bot_id'), bot_token[-4:]))
        print('app token: %s' % ('set …' + os.environ['SLACK_APP_TOKEN'][-4:]
                                 if os.environ.get('SLACK_APP_TOKEN') else 'MISSING'))
        print('channels configured: %d (config %s)' % (len(channels), config_path()))
        try:
            with open(os.path.join(state_dir(), 'connection.json')) as f:
                c = json.load(f)
            print('daemon: %s since %s (pid %s%s)' % (
                c.get('state'), time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(c.get('at', 0))),
                c.get('pid'), '' if _pid_alive(c.get('pid')) else ', NOT RUNNING - status is stale'))
        except (OSError, ValueError):
            print('daemon: no status file (never started)')
        return 0
    if cmd == 'thread' and len(rest) == 2:
        if rest[0] not in channels:
            raise Refused('channel %s is not configured' % rest[0])
        for m in read_thread(web, *rest):
            print(json.dumps(m))
        return 0
    if cmd == 'file' and len(rest) == 3:
        fid, ext, data = fetch_file(web, channels, defaults, *rest)
        print(save_file(fid, ext, data, defaults['files'].get('total_bytes') or 0))
        return 0
    if cmd not in SOCKET_COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    me = web.call('auth.test')
    store = Store(os.path.join(state_dir(), 'slack.db'))
    w = Writer(web, store, channels, defaults, {'user_id': me['user_id']})
    w.team = me.get('team_id') or ''
    try:
        out = execute(w, cmd, rest)
    except Refused as e:
        if str(e).startswith('usage: '):
            print(USAGE, file=sys.stderr)
            return 2
        raise
    print(json.dumps(out))
    return 0


def _socket_main(sock, cmd, rest):
    """Socket-service mode: the daemon holds the tokens and runs the guardrails;
    this process neither reads a token nor calls Slack."""
    if cmd == 'doctor':
        for name in ('SLACK_BOT_TOKEN', 'SLACK_APP_TOKEN'):
            if os.environ.get(name):
                print('WARNING: %s is in this process\'s environment; in socket mode only the daemon '
                      'should hold it' % name)
            for f in credential_files(name):
                if os.access(f, os.R_OK):
                    print('WARNING: credential file %s is readable by this user' % f)
        try:
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(5)
            c.connect(sock)
            c.close()
            print('socket: %s reachable' % sock)
        except OSError as e:
            print('socket: %s NOT reachable: %s' % (sock, e))
            return 1
        return 0
    if cmd == 'thread' and len(rest) == 2:
        for m in socket_call(sock, 'thread', rest)['messages']:
            print(json.dumps(m))
        return 0
    if cmd not in SOCKET_COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    if cmd == 'file' and len(rest) == 3:
        r = socket_call(sock, cmd, rest)
        print(save_file(r['id'], r['ext'], base64.b64decode(r['data']),
                        load_config()[1]['files'].get('total_bytes') or 0))
        return 0
    r = socket_call(sock, cmd, rest)
    print(json.dumps({k: v for k, v in r.items() if k != 'ok'}))
    return 0

if __name__ == '__main__':
    sys.exit(main())
