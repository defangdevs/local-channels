# local-webhook

One-way MCP **channel** plugin: receives HMAC-signed webhook deliveries over
HTTP (GitHub or any other sender that signs the raw body with HMAC-SHA256) and
pushes a concise, untrusted-marked summary of each event into the Claude Code
session that spawned it. Ships MCP tools (`webhook_subscribe`,
`webhook_unsubscribe`, `webhook_subscriptions`) so the agent can route which
topics reach it — hot-reloaded per delivery, no session restart needed — plus an
equivalent [CLI](#cli) for callers with no MCP client.

Single dependency-free file (`webhook.py`); runs under the stock `python3`
(≥3.9) that RHEL 9 and Ubuntu server images already ship. No pip packages, no
build step. (Until 0.8.0 this was `webhook.mjs` under node/bun — the Python
port removed the only runtime dependency the plugin had.)

## How it fits together

```
GitHub / Stripe / anything ──HTTPS──> reverse proxy (Caddy, TLS)
                                        │ plain HTTP (unix socket or 127.0.0.1:8788)
                                        ▼
                              webhook.py   (ingress owner: verifies HMAC once)
                                        │ unix-socket fan-out
                    ┌───────────────────┼───────────────────┐
                    ▼                    ▼                    ▼
     <state>/instances/<pid>.sock   …/<pid>.sock         …/<pid>.sock
       webhook.py (session A)     webhook.py (B)      webhook.py (C)
         ──stdio/MCP──> claude       ──> claude          ──> claude
                                        │
                          ~/.local/state/local-webhook/
                            sources.json           (who may deliver, secrets)
                            filter.json            (default subscriptions)
                            filter.<session>.json  (per-session subscriptions)
                            filter.dispatch.json   (shared standing watches →
                                                    spawn a fresh session, 0.9.0)
                            receiver.json          (daemon advertisement)
```

- The **ingress owner** verifies the HMAC once and re-broadcasts each event to
  every live session over per-PID unix sockets, so **all** concurrent sessions
  receive deliveries, each applying its **own** filter. Two deployment shapes:
  - **Legacy / single-file:** each session spawns its own copy and races for the
    loopback port; the winner is the ingress owner (and also delivers to itself).
  - **Daemon (agent-box):** one `LOCAL_WEBHOOK_RECEIVER_ONLY=1` process owns the
    ingress (a systemd-socket-activated unix socket) and has no session of its
    own; every session runs with `LOCAL_WEBHOOK_PORT=0` as a pure IPC peer. This
    keeps the box's one webhook endpoint up regardless of which sessions exist.
- Subscriptions are **per session**: set `LOCAL_WEBHOOK_SESSION=<id>` and each
  session gets its own `filter.<session>.json`, so a `webhook_subscribe` in one
  session never leaks into a sibling that happens to act as the same identity.
- Auth fails **closed** (unknown source / missing secret / bad signature →
  reject). The topic filter fails **open** (missing or corrupt `filter.json`
  → forward everything) so a botched edit degrades to noise, not silence.
- All payload free-text is truncated and wrapped in `⟪UNTRUSTED:…⟫` markers,
  and every channel message is prefixed `[UNTRUSTED webhook:<source>]`.

## State directory

Default `~/.local/state/local-webhook` (override: `LOCAL_WEBHOOK_STATE_DIR`).
Secrets and config live here — **outside** the plugin install dir, which is a
managed cache that may be wiped on update, and outside the marketplace repo.

### sources.json

```json
{
  "defaultSource": "github",
  "sources": {
    "github": { "secretFile": "github.secret" },
    "stripe": { "secretFile": "stripe.secret", "keyPath": "data.object.id" }
  }
}
```

The URL path picks the source: `POST /github`, `POST /stripe`; a bare `POST /`
maps to `defaultSource` (back-compat with hook URLs that predate multi-source).
Per-source keys (all optional except one of `secret`/`secretFile`):

| key | default | meaning |
|---|---|---|
| `secret` / `secretFile` | — | HMAC-SHA256 secret (file paths resolve in the state dir) |
| `format` | `github` iff source is named github, else `generic` | payload summarizer |
| `signatureHeader` | `x-hub-signature-256` | hex HMAC of raw body, optional `sha256=` prefix |
| `eventHeader` | `x-github-event` / `x-webhook-event` | falls back to payload `event`/`type` |
| `deliveryHeader` | `x-github-delivery` / `x-webhook-delivery` | delivery id for meta |
| `keyPath` | `repository.full_name` (github) / none | dot-path to the routing key |
| `senderPath` | `sender.login` (github) / none | dot-path to the acting user, matched against `ignoreSenders` |

### filter.json

Managed by the MCP tools; safe to hand-edit. Topics are `source:key` patterns:
`github:owner/repo` (exact), `github:owner/*` (prefix), `github:*`, or `*`.
An entry may also be an object with `ignoreSenders`: events on that topic whose
sender matches are dropped as echoes of the session's own actions (pass
`ignore_senders` to `webhook_subscribe`, or hand-edit). `"@self"` resolves to
`LOCAL_WEBHOOK_SELF`. **CI-outcome events** (`workflow_run`, `workflow_job`,
`check_run`, `check_suite`, `status`, `deployment_status`) are exempt from
sender-ignore: their sender is merely who triggered the run, and muting your
own login must not mute CI results for your own pushes. A
`deliver_to:"subagent"` watch is stricter still: there a CI event spawns only on
a *failing* outcome, sender irrelevant (0.10.1) — see
[Dispatch](#dispatch-delivery-into-a-fresh-session-090).

```json
{ "enabled": true, "ttlHours": 1, "topics": [
    "github:defangdevs/*",
    { "topic": "github:me/my-config-repo", "ttlHours": 72,
      "note": "tracking the config migration all week", "subscribedAt": "2026-07-16T00:00:00Z" },
    { "topic": "github:defangdevs/claude-box", "ignoreSenders": ["@self"],
      "note": "waiting on CI for PR 42", "subscribedAt": "2026-07-16T00:00:00Z" } ] }
```

### `when` / `drop` payload predicates (0.11.0)

Topic and sender are sometimes the wrong granularity: "their new issues, not
their close buttons" is not expressible with `ignoreSenders`, which can only
mute the whole person. An entry may therefore carry two predicates over the
**payload**, using the same dot-path convention as `keyPath`/`senderPath` — an
event-agnostic mechanism, so a stripe source gates on `data.object.status`
exactly like github gates on `action`:

- `drop` — events matching it are refused by this entry. Evaluated first, wins.
- `when` — if present, the entry accepts **only** matching events.

The predicate language is deliberately tiny: `{"any": [...]}` / `{"all": [...]}`
over leaves `{"path": "a.b.c", "in": [values]}` or
`{"path": "a.b.c", "notIn": [values]}`. Values are JSON scalars; `null` in an
`in` list matches an *absent* path. JSON booleans only match booleans (`true`
never matches `1`).

```json
{ "topic": "github:defangdevs/*",
  "when": { "any": [
      { "all": [ { "path": "action", "in": ["opened", "reopened"] },
                 { "path": "sender.login", "notIn": ["defangdevs"] } ] },
      { "path": "workflow_run.conclusion", "in": ["failure", "timed_out", "startup_failure"] } ] },
  "drop": { "path": "action", "in": ["closed", "merged"] } }
```

An entry carrying `when`/`drop` is **declarative**: its rules were written by
whoever configured it, so the built-in CI carve-outs step aside for that entry —
the sender-ignore exemption here, and on the dispatch path the failures-only
brake (the live-session suppression is coordination, not policy, and still
applies). Express sender muting *inside* the predicate (as above) rather than
combining with `ignoreSenders`, which on a declarative entry is a pure mute
that would silence even that sender's CI failures.

`webhook_subscribe` takes the predicates as `when` / `drop` (CLI: `--when` /
`--drop` with a JSON argument) and rejects a malformed one at subscribe time.
A malformed node that reaches delivery anyway (hand-edited file) matches
**nothing** and logs to stderr — for `when` that mutes the entry, for `drop` it
forwards, and either way the misconfiguration is distinguishable from a watch
that quietly stopped working. Omit both on re-subscribe to keep them; pass
`{}` to clear.

### Subscription expiry and notes (0.5.x)

Agent sessions come and go — context gets cleared, and a webhook landing
later in a fresh session is noise without the work that motivated it. Worse, a
late delivery lands after the session's KV cache has aged out, so re-reading
the whole conversation to handle one stale event burns a large pile of tokens.
So subscriptions **expire**, `ttlHours` after their clock was last reset
(top-level default **1** — chosen to track how long the KV cache stays warm, so
a straggler event can't trigger an expensive cold re-read; per-entry `ttlHours`
overrides it; `0` = pinned, never expires — but see the warning below). Expired
topics are pruned at delivery time and on every tool call.

Two things reset the clock:

1. **Re-subscribing** — expressing fresh interest.
2. A **warm delivery** — an event arriving within ~10 min (`WARM_WINDOW_MS`,
   ~2× the prompt-cache TTL) of the previous one, i.e. while the cache from
   handling that previous event is still hot. Warm deliveries are cheap, so
   extending the window costs nothing and keeps a subscription alive through a
   genuinely active streak. A **cold** straggler (gap beyond the window — the
   kind that forces the expensive re-read) is delivered but does *not* renew, so
   a repo with sparse bot traffic (dependabot, sporadic CI) still expires with
   no one working on it. Renewal follows cache warmth, never raw event count.

For a stream you intend to react to **indefinitely**, pass
`renew_on_event: true`: every delivery then resets the clock regardless of gap,
so the subscription lives as long as events keep arriving within `ttl_hours`.
`webhook_subscribe` also takes `ttl_hours` to set the per-topic override —
larger for a genuinely multi-hour or multi-day wait.

> **Don't pin session-delivered topics.** `ttl_hours: 0` never expires, and
> `renew_on_event: true` keeps a busy topic alive forever in practice. A
> session delivery lands in whichever session is *active at the time*, so
> either one interrupts unrelated work indefinitely — no session "owns" a
> standing watch on a repo. Scope the TTL to the work in flight and let it
> lapse. For a genuine standing watch, use
> [dispatch](#dispatch-delivery-into-a-fresh-session-090) instead: with
> `deliver_to: "subagent"` a matching event spawns a **fresh** session with no
> warm cache to lose and nobody to interrupt, so `ttl_hours: 0` is safe there —
> and is the default
> ([#1](https://github.com/defangdevs/local-channels/issues/1)).

Hand-written
entries without timestamps never expire until some write stamps them
(`subscribedAt` is filled in on the next file write).

`webhook_subscribe` also takes a `note` — a one-liner saying *why* the
subscription exists ("waiting on Lio to wire the hook, issue 15"). It is echoed
under every delivery on that topic:

```
[UNTRUSTED webhook:github — …] issue #15 closed on …
[subscribed to github:owner/repo 26h ago: waiting on Lio to wire the hook, issue 15]
```

so a session that has since lost its context still knows what the event relates
to. Omitting `note` (or `ttl_hours`) on re-subscribe keeps the existing values;
pass `""` to clear the note.

### Dispatch: delivery into a fresh session (0.9.0)

Session delivery answers "tell *me* when CI for *my* PR finishes." A **standing
watch** — "handle any new issue on this repo," with no session that owns the
work — has no correct live session to interrupt; the right response is to
*start* one. Pass `deliver_to: "subagent"` to `webhook_subscribe` (CLI:
`--deliver-to subagent`) and matching events are written to the **shared**
`filter.dispatch.json` instead of the session's own filter. The ingress owner
routes every verified delivery against that file after the peer fan-out; a
match makes it run `LOCAL_WEBHOOK_SPAWN_CMD` — a shell command expected to
start a new agent session (under agent-box, a wrapper over
`agent-box-session add --prompt`). The formatted event text (same
`[UNTRUSTED …]` framing and note echo as a channel message) arrives on the
command's **stdin**; routing context rides in `LOCAL_WEBHOOK_SPAWN_SOURCE`,
`_KEY`, `_EVENT`, `_TOPIC`, `_NOTE` and `_COUNT` env vars (payload-derived —
quote them).

Differences from session routing, all deliberate:

- **Fails closed.** No spawn command, no dispatch file, or a corrupt one all
  mean *spawn nothing*. Failing open here would be a session per delivery — a
  fork bomb, not noise. (`webhook_subscribe` warns when the receiver daemon
  advertises no spawn command in `receiver.json`.)
- **Shared, not per-session.** The watch outlives the session that created it;
  every session sees the dispatch list under `dispatch` in
  `webhook_subscriptions`.
- **Pinned by default.** New dispatch entries get `ttlHours: 0` unless a
  `ttl_hours` is passed — a spawned session has no warm cache to lose, which is
  the entire cost the session-filter TTL exists to bound.
- **Bursts coalesce.** The first event on an idle key spawns immediately;
  events arriving while that spawn runs, or within `LOCAL_WEBHOOK_SPAWN_WINDOW`
  (60 s) of its start, batch into one follow-up spawn — a 10-PR dependabot
  burst costs two sessions, not ten. At most `LOCAL_WEBHOOK_SPAWN_MAX` (2)
  spawn commands run concurrently across all keys. A failing spawn command is
  logged and its batch dropped; the same events already reached session peers.
- **CI events only spawn on a failure (0.10.0, sender-independent since
  0.10.1).** A run reports itself queued, in progress, cancelled and
  finished-fine, and none of those justify a whole session — so on this path a CI
  event spawns only for a terminal non-success outcome (`failure`, `timed_out`,
  `action_required`, `startup_failure`, `stale`, and `error`/`failure` for
  `status` / `deployment_status`), whoever triggered the run. A failure
  additionally overrides `ignoreSenders`, because your own build breaking is
  news. 0.10.0 had only that override, which made the rule accidentally
  sender-dependent: a watch on repos whose humans push under their own logins
  ignores nobody relevant, so every green `check_run.completed` and
  `workflow_run` success on a merge still took a session slot to conclude
  "nothing to do". Session delivery keeps the unconditional exemption — "merge on
  green" wants exactly that green run. An outcome the payload does not state
  counts as a failure: a swallowed break is the one error worth avoiding twice
  over. A watch carrying [`when`/`drop` predicates](#when--drop-payload-predicates-0110)
  replaces this brake with its own rules (0.11.0): the consumer owns the whole
  spawn decision, including whether a green run is news to it.
- **A live owner suppresses the spawn (0.10.0).** A standing watch is for events
  nobody owns, so before spawning for a CI event the ingress owner asks whether
  a live session peer's own filter already covers it — if so, that session is
  getting this delivery and a second agent on the same PR (sharing one working
  tree) is not help. Liveness comes from the peer's `instances/<key>.<pid>.sock`
  entry, pid-checked, so a crashed session cannot mute a watch; the probe is
  read-only, so it never renews the subscription it consults. Suppression is
  logged. **Scoped to CI events on purpose:** topics are repo-granular while
  ownership is object-granular, so a session working one PR must not silence the
  watch for every unrelated new issue in that repo — `issues.opened` and other
  people's PRs spawn regardless of who is subscribed.

### Per-identity filters

Set `LOCAL_WEBHOOK_SELF=<name>` in a session's environment and its instance
reads/writes `filter.<name>.json` instead of the shared `filter.json`. Two
concurrent sessions acting as different GitHub users can then subscribe to the
same repo with different ignore lists — each mutes only its own echoes, while
fan-out delivers the event to both.

## CLI

The MCP tools only exist inside a Claude Code session that loaded the plugin. A
Codex session, a plain shell, or a script can manage the same subscriptions by
running `webhook.py` with a command — a thin shim over the very same code, so
the two paths can't drift on TTL/renew semantics:

    python3 webhook.py subscribe owner/repo --note "waiting on PR 146 CI" --ttl 8
    python3 webhook.py subscribe 'github:defangdevs/*' --ignore-sender @self
    python3 webhook.py subscribe 'github:defangdevs/*' --deliver-to subagent \
        --note "standing watch: new issues/PRs spawn a fresh session"
    python3 webhook.py ls
    python3 webhook.py unsubscribe owner/repo
    python3 webhook.py status        # state dir, session, sources (no secrets)

`--note`, `--ttl`, `--deliver-to`, `--renew-on-event`, `--ignore-sender`
(repeatable, or one comma-separated list), `--when` and `--drop` (JSON
predicate objects) mirror the tool arguments;
`webhook.py --help` prints the details. Subscriptions are per session, so export the same
`LOCAL_WEBHOOK_SESSION` (and `LOCAL_WEBHOOK_STATE_DIR`) the session runs with —
under agent-box both are already in every session's environment.

A CLI invocation binds nothing: it is not a session peer and never touches the
ingress, so it is safe to run alongside the daemon and any number of sessions.

## Wiring a GitHub repo

1. Put the shared secret in `<state-dir>/github.secret` (mode 0600).
2. Repo → Settings → Webhooks → Add: URL `https://<your-host>/github` (or `/`),
   content type `application/json`, the same secret, pick events.
3. In a session: call `webhook_subscribe` with `owner/repo` (shorthand for
   `github:owner/repo`).

## Wiring anything else

Any sender that can POST JSON and sign the raw body with HMAC-SHA256 works.
Add a source to `sources.json`, point the sender at `POST /<source>`, and put
the hex digest in the signature header. For senders with fixed non-GitHub
header names (e.g. `x-signature`), set `signatureHeader`.

## Env

| var | default | |
|---|---|---|
| `LOCAL_WEBHOOK_PORT` (or legacy `WEBHOOK_PORT`) | `8788` | loopback TCP ingress port; `0` = no TCP ingress (pure IPC peer) |
| `LOCAL_WEBHOOK_HTTP_SOCK` | — | listen for the HTTP ingress on this unix socket path instead of TCP (stale socket reclaimed on start) |
| `LOCAL_WEBHOOK_RECEIVER_ONLY` | — | `1`/`true` = daemon mode: own the ingress and fan out to peers, but no session of its own (no MCP stdio, no self-delivery) |
| `LOCAL_WEBHOOK_SESSION` | — | per-session subscription scope; selects `filter.<session>.json` (falls back to `SELF`, then default) |
| `LOCAL_WEBHOOK_STATE_DIR` | `~/.local/state/local-webhook` | secrets + filters (must be shared across a box's daemon + sessions for fan-out) |
| `LOCAL_WEBHOOK_SELF` | — | identity this session acts as; resolves `"@self"` in ignore lists (no longer the filter-file key) |
| `LOCAL_WEBHOOK_SPAWN_CMD` | — | ingress owner only: shell command run per dispatched event batch (prompt text on stdin, `LOCAL_WEBHOOK_SPAWN_*` env). Unset = dispatch subscriptions are inert |
| `LOCAL_WEBHOOK_SPAWN_MAX` | `2` | max concurrent spawn commands across all keys |
| `LOCAL_WEBHOOK_SPAWN_WINDOW` | `60` | seconds after a spawn starts during which further events on the same key coalesce into one follow-up batch |
| `LOCAL_WEBHOOK_SPAWN_TIMEOUT` | `600` | seconds before a running spawn command is killed (and its batch dropped) |
| `WEBHOOK_SECRET` | — | legacy: implies a single `github` source if `sources.json` is absent |

When systemd socket activation is in effect (`LISTEN_FDS` set), the ingress
adopts the passed fd (fd 3) and both `LOCAL_WEBHOOK_HTTP_SOCK` and
`LOCAL_WEBHOOK_PORT` are ignored — the `.socket` unit owns the path and perms.
