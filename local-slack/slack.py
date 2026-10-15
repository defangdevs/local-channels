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
# Scope of this first cut: PLAIN mode only (tokens in the agent user's env).
# Socket-service mode (own Linux user, Unix socket, SO_PEERCRED grants), the
# HTTP Events API transport, files, the settings card and classifier
# isolation hardening are follow-ups; the spec's guardrails that do not depend
# on grants are all enforced here, in the code path every write passes.
import base64
import hashlib
import http.client
import json
import os
import re
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
    re.compile(r'sk-[A-Za-z0-9_-]{20,}'),
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
]


class Refused(Exception):
    """A guardrail said no. The message is shown to the agent, so it names the
    rule but never echoes the matched secret."""


def scan_secrets(text, extra=()):
    # Look at the text as written AND with percent-escapes decoded, so a token
    # smuggled into a URL query is found (PromptArmor-style exfiltration).
    seen = {text, urllib.parse.unquote(text)}
    for pat in list(SECRET_PATTERNS) + [re.compile(p) for p in extra]:
        for t in seen:
            if pat.search(t):
                raise Refused('text matches a secret pattern; refused (not logged)')


_URL_RE = re.compile(r'https?://[^\s<>|)\]]+', re.I)
_IMAGE_MD_RE = re.compile(r'!\[[^\]]*\]\([^)]*\)')
# `;` in the lookbehind: after escaping, a raw `<@U1>` the agent wrote reads
# `&lt;@U1&gt;`, and that `@U1` must stay inert text, not be resolved.
_MENTION_RE = re.compile(r'(?<![\w`<;])([@#])([A-Za-z0-9._-]+)')
_CODE_RE = re.compile(r'```.*?```|`[^`\n]*`', re.S)
_BROADCAST_RE = re.compile(r'<!(channel|here|everyone)\b[^>]*>|(?<![\w`])@(channel|here|everyone)\b', re.I)


def _host_allowed(host, allowed):
    host = (host or '').lower()
    return any(host == h or host.endswith('.' + h) for h in allowed)


def check_link(url, allowed_hosts):
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or '').lower()
    if not _host_allowed(host, allowed_hosts):
        raise Refused('link host "%s" is not in links.allowed_hosts' % host)
    # A link can still carry data out in its tail; cap it and scan it decoded.
    for part in (p.query, p.fragment):
        dec = urllib.parse.unquote(part)
        if len(dec) > 256:
            raise Refused('link query/fragment over 256 characters')
        scan_secrets(dec)


def compose(text, resolver, cfg, defaults):
    """Build the text Slack receives. `resolver(kind, name)` returns an id for
    ('@', name) / ('#', name) / ('!', group) or None. Compose, don't filter:
    everything the agent wrote is escaped first, then only the tokens WE insert
    are live markup, and the result is re-checked for any token we did not
    insert (spec M2)."""
    write = cfg.get('write', {})
    if _IMAGE_MD_RE.search(text):
        raise Refused('image Markdown is refused; use upload')
    if _BROADCAST_RE.search(text) and not write.get('broadcast'):
        raise Refused('@channel / @here / @everyone need write.broadcast')
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
            check_link(m.group(0), allowed_hosts)
            pieces.append(('t', seg[p2:m.start()]))
            pieces.append(('u', m.group(0)))
            p2 = m.end()
        pieces.append(('t', seg[p2:]))
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
                if sigil == '@' and name.lower() in ('channel', 'here', 'everyone'):
                    # Only reachable with write.broadcast (refused above otherwise).
                    tok = '<!%s>' % name.lower()
                    inserted.append(tok)
                    return tok
                rid = resolver(sigil, name)
                if not rid:
                    raise Refused('unknown %s%s' % (sigil, name))
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


def config_path():
    return os.environ.get('LOCAL_SLACK_CONFIG') or os.path.expanduser('~/.config/local-slack/channels.json')


DEFAULT_CHANNEL = {
    'track': 'all',
    'quiet_minutes': 30, 'max_wait_hours': 24, 'merge_window_minutes': 0,
    'resettle': True, 'track_bots': False,
    'reactions': {'ready': 'white_check_mark', 'hold': 'raised_hand', 'drop': 'x', 'ack': 'eyes'},
    'controllers': [], 'ignore_users': [],
    'write': {'allowed': False, 'mode': 'on_request', 'top_level': False,
              'broadcast': False, 'groups': False},
    'allow_external': False,
}
DEFAULT_DEFAULTS = {
    'dm_allowlist': [], 'links': {'allowed_hosts': []},
    'disclosure': '_— AI agent · can be wrong · 👍/👎 to rate_',
    'retention_days': 30,
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


def save_config(channels, defaults, path=None):
    path = path or config_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    doc = dict(channels)
    doc['_defaults'] = defaults
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


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

    def first_time(self, event_id, now):
        """True the first time an event_id is seen (24 h memory)."""
        if not event_id:
            return True
        with self.lock:
            try:
                self.db.execute('INSERT INTO seen VALUES (?,?)', (event_id, now))
                return True
            except sqlite3.IntegrityError:
                return False

    def prune(self, now, retention_days=30, audit_days=90):
        self.x('DELETE FROM seen WHERE at < ?', now - 86400)
        cut = now - retention_days * 86400
        gone = self.q("SELECT team, channel, thread_ts FROM threads "
                      "WHERE state IN ('settled','dropped') AND ended_at < ?", cut)
        for r in gone:
            self.x('DELETE FROM msgs WHERE team=? AND channel=? AND thread_ts=?',
                   r['team'], r['channel'], r['thread_ts'])
        self.x("DELETE FROM threads WHERE state IN ('settled','dropped') AND ended_at < ?", cut)
        self.x('DELETE FROM audit WHERE at < ?', now - audit_days * 86400)

    def purge_channel(self, channel):
        for t in ('msgs', 'threads', 'audit'):
            self.x('DELETE FROM %s WHERE channel=?' % t, channel)
        self.x('DELETE FROM status WHERE thread_key LIKE ?', '%/' + channel + '/%')

    def purge_all(self):
        for t in ('seen', 'msgs', 'threads', 'status', 'audit'):
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
                 react=None, classify=None):
        self.store, self.channels, self.bot = store, channels, bot
        self.emit, self.now = emit, now
        self.lookup = lookup or (lambda channel, ts: None)
        self.users = users or (lambda uid: {'guest': False, 'external': False})
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

    def _payload(self, row, action, ts=None, user=None, extra=None):
        p = {
            'identifier': row['thread_key'],
            'title': row['title'] or '',
            'summary': 'v%d · %d replies, %d people · reason: %s' % (
                row['version'], row['replies'] or 0,
                len([x for x in (row['participants'] or '').split(',') if x]),
                (extra or {}).get('reason', action)),
            'action': action,
            'team': row['team'], 'channel': row['channel'], 'thread': row['thread_ts'],
            'ts': ts or row['thread_ts'], 'user': user or '', 'version': row['version'],
            'external': bool(row['external']),
            'url': 'https://slack.com/archives/%s/p%s' % (row['channel'], row['thread_ts'].replace('.', '')),
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
        callback body): {'team_id','event_id','event':{...}}."""
        now = self.now()
        if not self.store.first_time(envelope.get('event_id'), now):
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
        elif etype == 'member_left_channel':
            if self._is_bot_self(user=ev.get('user')):
                self.member[ev.get('channel')] = False

    # -- messages -----------------------------------------------------------
    def _message(self, team, ev, now):
        channel = ev.get('channel')
        cfg = self.channels.get(channel)
        if cfg is None or self.member.get(channel) is False:
            return  # the config is the allowlist
        sub = ev.get('subtype')
        if sub in ('message_changed', 'message_deleted'):
            return self._edit_or_delete(team, ev, sub, cfg, now)
        if sub == 'bot_message':
            if not cfg['track_bots'] or self._is_bot_self(bot_id=ev.get('bot_id')):
                return
        elif sub not in (None, 'file_share', 'me_message', 'thread_broadcast'):
            return  # joins, topic changes and the rest of the system subtypes
        if self._is_bot_self(ev.get('user'), ev.get('bot_id')):
            return  # our own echo is never activity
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
            row = self._start(team, channel, thread_ts, ev, cfg, now, user)
            if row is None:
                return  # attached to a merge window instead
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
                return None
        key = self._key(team, channel, thread_ts)
        quiet, maxw = cfg['quiet_minutes'] * 60, cfg['max_wait_hours'] * 3600
        ext = 1 if (self.external.get(channel)) else 0
        self.store.x('INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)',
                     key, team, channel, thread_ts, sanitize_title(ev.get('text')), now, now,
                     min(now + quiet, now + maxw), 1, 'open', None, 0, '', ext, user, 0, None)
        return self._row(key)

    def _bump(self, row, cfg, now, user, reply):
        """Activity: bump version, push settle_at out (capped by max_wait)."""
        state = row['state']
        if state in ('dropped', 'held'):
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
                row = self._start(team, channel, thread_ts, fake, cfg, now, user)
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
        if m and m[0]['user'] == self.bot.get('user_id') and emoji in ('+1', '-1', 'thumbsup', 'thumbsdown'):
            self.emit('feedback', self._payload(row, 'feedback', ts=ts, user=user,
                                                extra={'rating': emoji, 'reason': 'feedback'}))
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
        # Acknowledge before any agent exists (S1).
        try:
            self.react(row['channel'], ts, cfg['reactions']['ack'])
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
        now = self.now()
        n = 0
        for row in self.store.q("SELECT * FROM threads WHERE state='open' AND settle_at <= ?", now):
            cfg = self.channels.get(row['channel'])
            if cfg is None:
                continue
            maxed = now >= row['first_seen_at'] + cfg['max_wait_hours'] * 3600
            if self._finish(row, 'max_wait' if maxed else 'quiet', cfg):
                n += 1
        self.store.prune(now, 30)
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

    def take(self, write):
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


class Web:
    def __init__(self, bot_token, app_token=None):
        self.bot, self.app = bot_token, app_token
        self.t3, self.t2 = Bucket(45), Bucket(18)
        self.retry_after = 0.0

    def call(self, method, params=None, write=False, token=None, tier=3, json_body=True):
        if time.time() < self.retry_after:
            raise SlackError('rate_limited: retry in %ds' % (self.retry_after - time.time()))
        if not (self.t3 if tier == 3 else self.t2).take(write):
            raise SlackError('rate_limited: local %s budget exhausted' % ('write' if write else 'read'))
        data = json.dumps(params or {}).encode()
        req = urllib.request.Request(
            'https://%s/api/%s' % (API_HOST, method), data=data, method='POST',
            headers={'Authorization': 'Bearer ' + (token or self.bot),
                     'Content-Type': 'application/json; charset=utf-8'})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.retry_after = time.time() + int(e.headers.get('Retry-After', '5'))
                raise SlackError('rate_limited: Retry-After %s' % e.headers.get('Retry-After'))
            raise SlackError('http %d' % e.code)
        if not out.get('ok'):
            raise SlackError(out.get('error', 'unknown_error'))
        return out


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

def make_emitter(source='slack'):
    """Put an event on the bus through `webhook.py emit`, which signs it with
    the source's own secret and delivers through the ingress, so it gets
    subscriptions AND standing-watch dispatch like any other delivery. The
    command is overridable (LOCAL_SLACK_EMIT) for agent-box's wrapper."""
    cmd = os.environ.get('LOCAL_SLACK_EMIT', 'agent-box-webhook emit').split()

    def emit(action, payload):
        topic_payload = dict(payload)
        # The bus keys routing on the payload; `topic` is team/channel.
        topic_payload['topic'] = 'slack:%s/%s' % (payload['team'], payload['channel'])
        subprocess.run(cmd + [source, json.dumps(topic_payload), '--event', action],
                       check=False, timeout=15, stdout=subprocess.DEVNULL)
    return emit


def run_daemon():
    bot_token, app_token = os.environ.get('SLACK_BOT_TOKEN'), os.environ.get('SLACK_APP_TOKEN')
    if not bot_token or not app_token:
        sys.exit('local-slack: SLACK_BOT_TOKEN and SLACK_APP_TOKEN must both be set')
    web = Web(bot_token, app_token)
    me = web.call('auth.test')
    bot = {'user_id': me['user_id'], 'bot_id': me.get('bot_id')}
    store = Store(os.path.join(state_dir(), 'slack.db'))
    channels, _ = load_config()

    def lookup(channel, ts):
        try:
            r = web.call('conversations.replies', {'channel': channel, 'ts': ts, 'limit': 1})
            m = (r.get('messages') or [{}])[0]
            return m.get('thread_ts') or m.get('ts')
        except SlackError:
            return None

    tracker = Tracker(store, channels, bot, make_emitter(), lookup=lookup,
                      react=lambda c, ts, e: web.call('reactions.add', {'channel': c, 'timestamp': ts, 'name': e}, write=True))

    def ticker():
        while True:
            time.sleep(30)
            tracker.channels, _ = load_config()   # hot-reload the allowlist
            tracker.tick()
    threading.Thread(target=ticker, daemon=True).start()

    backoff = 1
    while True:
        try:
            url = web.call('apps.connections.open', token=app_token)['url']
            ws = WS(url)
            backoff = 1
            while True:
                raw = ws.recv()
                if raw is None:
                    break
                env = json.loads(raw)
                if env.get('type') == 'disconnect':
                    break
                if env.get('type') == 'events_api':
                    # Persist (dedup row + record) BEFORE acknowledging, so a
                    # crash between the two is covered by Slack's redelivery.
                    tracker.handle(env['payload'])
                    ws.send(json.dumps({'envelope_id': env['envelope_id']}))
        except (SlackError, OSError, ValueError) as e:
            print('local-slack: %s; reconnecting in %ds' % (e, backoff), file=sys.stderr)
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)


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
  slack.py thread CHANNEL TS
  slack.py reply CHANNEL TS TEXT
  slack.py post CHANNEL TEXT
  slack.py status CHANNEL TS TEXT [--done|--failed]
  slack.py react CHANNEL TS EMOJI
  slack.py purge

Tokens come from SLACK_BOT_TOKEN / SLACK_APP_TOKEN. Writes go through the
guardrails in compose() and the per-channel write settings.''' % VERSION


class Writer:
    """Every outgoing message passes here: allowlist, mode, compose, disclosure,
    send, audit. The agent never gets to bypass any step."""

    def __init__(self, web, store, channels, defaults, bot, session=None):
        self.web, self.store, self.channels = web, store, channels
        self.defaults, self.bot, self.session = defaults, bot, session or os.environ.get('AGENT_BOX_SESSION', '')
        self._names = {}

    def resolver(self, sigil, name):
        key = sigil + name
        if key in self._names:
            return self._names[key]
        rid = None
        try:
            if sigil == '@':
                cur = None
                while True:
                    r = self.web.call('users.list', {'limit': 200, **({'cursor': cur} if cur else {})})
                    for m in r.get('members', []):
                        if name in (m.get('name'), (m.get('profile') or {}).get('display_name')):
                            rid = m['id']
                    cur = (r.get('response_metadata') or {}).get('next_cursor')
                    if rid or not cur:
                        break
            elif sigil == '#':
                r = self.web.call('conversations.list', {'limit': 1000, 'types': 'public_channel,private_channel'})
                for c in r.get('channels', []):
                    if c.get('name') == name and c['id'] in self.channels:
                        rid = c['id']
        except SlackError:
            rid = None
        self._names[key] = rid
        return rid

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
        now = time.time()
        n = self.store.q('SELECT COUNT(*) c FROM audit WHERE session=? AND at>?', self.session, now - 600)[0]['c']
        if n >= 20:
            raise Refused('at most 20 writes per session per 10 minutes')
        if top_level:
            c = self.store.q("SELECT COUNT(*) c FROM audit WHERE channel=? AND kind='post' AND at>?",
                             channel, now - 3600)[0]['c']
            if c >= 5:
                raise Refused('at most 5 top-level posts per channel per hour')

    def _send(self, kind, channel, thread_ts, text, top_level=False, disclose=True):
        cfg = self._check(channel, thread_ts, top_level)
        self._rate(channel, top_level)
        body = compose(text, self.resolver, cfg, self.defaults)
        if disclose and self.defaults.get('disclosure'):
            body += '\n\n' + self.defaults['disclosure']
        if len(body) > 4000:
            raise Refused('message over 4,000 characters; upload a file instead')
        params = {'channel': channel, 'text': body, 'unfurl_links': False, 'unfurl_media': False}
        if thread_ts:
            params['thread_ts'] = thread_ts
        r = self.web.call('chat.postMessage', params, write=True)
        self.audit(kind, channel, thread_ts, r.get('ts'), body)
        return r

    def audit(self, kind, channel, thread, ts, text):
        self.store.x('INSERT INTO audit VALUES (?,?,?,?,?,?,?)', time.time(), channel, thread, ts,
                     self.session, kind, text)

    def reply(self, channel, ts, text):
        return self._send('reply', channel, ts, text)

    def post(self, channel, text):
        return self._send('post', channel, None, text, top_level=True)

    def status(self, channel, ts, text, mark=None):
        """One status message per thread: create it, then edit it. Emoji marks
        are appended by the tool, not chosen by the agent."""
        cfg = self.channels.get(channel)
        if cfg is None or not cfg['write']['allowed']:
            raise Refused('writing is not allowed in %s' % channel)
        body = compose(text, self.resolver, cfg, self.defaults)
        body = {'done': '✅ ', 'failed': '❌ '}.get(mark, '⏳ ') + body
        key = [r for r in self.store.q("SELECT thread_key FROM threads WHERE channel=? AND thread_ts=?", channel, ts)]
        k = key[0]['thread_key'] if key else '%s/%s' % (channel, ts)
        have = self.store.q('SELECT ts FROM status WHERE thread_key=?', k)
        if have:
            r = self.web.call('chat.update', {'channel': channel, 'ts': have[0]['ts'], 'text': body}, write=True)
        else:
            r = self.web.call('chat.postMessage', {'channel': channel, 'thread_ts': ts, 'text': body,
                                                    'unfurl_links': False, 'unfurl_media': False}, write=True)
            self.store.x('INSERT OR REPLACE INTO status VALUES (?,?)', k, r['ts'])
        self.audit('status', channel, ts, r.get('ts'), body)
        return r

    def react(self, channel, ts, emoji):
        cfg = self.channels.get(channel)
        if cfg is None or not cfg['write']['allowed']:
            raise Refused('writing is not allowed in %s' % channel)
        if not re.fullmatch(r'[a-z0-9_+-]{1,64}', emoji):
            raise Refused('bad emoji name')
        try:
            self.web.call('reactions.add', {'channel': channel, 'timestamp': ts, 'name': emoji}, write=True)
        except SlackError as e:
            if str(e) != 'already_reacted':   # de-duplicated per (ts, emoji)
                raise


def _opt(args, name, default=None, flag=False):
    if name in args:
        i = args.index(name)
        if flag:
            args.pop(i)
            return True
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return False if flag else default


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == 'daemon':
        run_daemon()
        return 0
    channels, defaults = load_config()
    if cmd == 'channels':
        for cid, c in sorted(channels.items()):
            print('%s track=%s quiet=%dm write=%s/%s external_ok=%s' % (
                cid, c['track'], c['quiet_minutes'], c['write']['allowed'], c['write']['mode'],
                c['allow_external']))
        return 0
    if cmd == 'channel' and rest[:1] == ['add'] and len(rest) >= 2:
        args = rest[2:]
        cid = rest[1]
        c = json.loads(json.dumps(DEFAULT_CHANNEL))
        c['track'] = _opt(args, '--track', 'all')
        c['quiet_minutes'] = int(_opt(args, '--quiet', 30))
        c['write']['allowed'] = _opt(args, '--write', flag=True)
        c['allow_external'] = _opt(args, '--allow-external', flag=True)
        if not re.fullmatch(r'reaction:[a-z0-9_+-]+|all|mention', c['track']):
            sys.exit('local-slack: bad --track')
        channels[cid] = _merge(DEFAULT_CHANNEL, c)
        save_config(channels, defaults)
        print('added %s' % cid)
        return 0
    if cmd == 'channel' and rest[:1] == ['rm'] and len(rest) == 2:
        channels.pop(rest[1], None)
        save_config(channels, defaults)
        Store(os.path.join(state_dir(), 'slack.db')).purge_channel(rest[1])
        print('removed %s and purged its rows' % rest[1])
        return 0
    if cmd == 'purge':
        Store(os.path.join(state_dir(), 'slack.db')).purge_all()
        print('purged')
        return 0
    bot_token = os.environ.get('SLACK_BOT_TOKEN')
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
        return 0
    if cmd == 'thread' and len(rest) == 2:
        r = web.call('conversations.replies', {'channel': rest[0], 'ts': rest[1], 'limit': 200})
        for m in r.get('messages', []):
            print(json.dumps({'ts': m.get('ts'), 'user': m.get('user'), 'text': m.get('text')}))
        return 0
    me = web.call('auth.test')
    store = Store(os.path.join(state_dir(), 'slack.db'))
    w = Writer(web, store, channels, defaults, {'user_id': me['user_id']})
    try:
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
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except (Refused, SlackError) as e:
        print('local-slack: refused: %s' % e, file=sys.stderr)
        return 1
    print(json.dumps({'ts': r.get('ts')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
