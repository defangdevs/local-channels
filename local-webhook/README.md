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
  reject), and since 0.13.0 so does the topic filter: a missing `filter.json`,
  a corrupt one and an explicit empty `topics` list all forward **nothing**.
  Through 0.12.x the first two forwarded everything, so any session that had
  never subscribed received the whole bus. All three states list no topics, so
  `webhook_subscriptions` reports `filterState` (`absent` / `invalid` / `ok`)
  to say which, and warns on the two that are not an ordinary empty list.
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
`github:owner/repo` (exact) or `github:owner/*` (prefix). Since 0.13.0 there is
no wildcard for a whole source (`github:*`) or for everything (`*`); an entry
holding one is **kept and never matches**, and `webhook_subscriptions` marks it
`invalid` with a reason, so an upgraded filter shows a visible dead row its
owner can re-point rather than silently losing a subscription.

On the **session** path a prefix topic must also carry an `include` predicate —
`webhook_subscribe` refuses `github:owner/*` on its own, because owner-wide
traffic interrupting a working session is a firehose rather than a watch. Name
one repo, narrow it with `include`, or use `deliver_to:"subagent"`, which is
exempt: it spawns a session per event batch instead of interrupting one, and an
org-wide standing watch is its intended shape.

An entry may also be an object with `ignoreSenders`: events on that topic whose
sender matches are dropped as echoes of the session's own actions (pass
`ignore_senders` to `webhook_subscribe`, or hand-edit). `"@self"` resolves to
`LOCAL_WEBHOOK_SELF`. Since 0.23.0 this is a **pure sender mute**, with no
exemption for any event. Through 0.22.x a hardcoded set of GitHub CI-outcome
events (`workflow_run`, `check_run`, …) overrode it — their sender is merely
who triggered the run, so muting your own login also muted your own build
results — and the dispatch path carried the mirror image: a CI event spawned a
session only on a *failing* outcome. Both were this plugin holding one
consumer's policy, and both are retired (#16). Say it in the rules *instead of*
in `ignoreSenders`, which is evaluated after them and wins: an entry that wants
its own failing runs but not its own comment echoes drops the mute and writes
one `include` — `{"any": [{"path": "workflow_run.conclusion", "in":
["failure"]}, {"path": "sender.login", "notIn": ["me"]}]}` — which says what
the carve-out meant and more, since the carve-out took that sender's green runs
too. See [Dispatch](#dispatch-delivery-into-a-fresh-session-090).

```json
{ "enabled": true, "ttlHours": 1, "topics": [
    { "topic": "github:defangdevs/*", "include": { "any": [ { "path": "action", "in": ["opened"] } ] },
      "note": "a prefix topic needs an include on the session path", "subscribedAt": "2026-07-16T00:00:00Z" },
    { "topic": "github:me/my-config-repo", "ttlHours": 8,
      "note": "tracking the config migration today", "subscribedAt": "2026-07-16T00:00:00Z" },
    { "topic": "github:defangdevs/claude-box", "ignoreSenders": ["@self"],
      "note": "waiting on CI for PR 42", "subscribedAt": "2026-07-16T00:00:00Z" } ] }
```

### `include` / `exclude` payload predicates (0.11.0)

Topic and sender are sometimes the wrong granularity: "their new issues, not
their close buttons" is not expressible with `ignoreSenders`, which can only
mute the whole person. An entry may therefore carry two predicates over the
**payload**, using the same dot-path convention as `keyPath`/`senderPath` — an
event-agnostic mechanism, so a stripe source gates on `data.object.status`
exactly like github gates on `action`:

- `exclude` — events matching it are refused by this entry. Evaluated first, wins.
- `include` — if present, the entry accepts **only** matching events.

`when` and `drop` are still accepted everywhere `include`/`exclude` are — in a
filter file, as `webhook_subscribe` arguments, and as CLI flags — because
downstream writers still emit them: agent-box's
`services.agent-box.webhook.watchPolicy` writes `when` today. A fresh write
always uses the new names, so a file converts itself the next time anything
touches it.

The predicate language is deliberately tiny: `{"any": [...]}` / `{"all": [...]}`
over leaves `{"path": "a.b.c", "in": [values]}` or
`{"path": "a.b.c", "notIn": [values]}`. Values are JSON scalars; `null` in an
`in` list matches an *absent* path. JSON booleans only match booleans (`true`
never matches `1`). Since 0.15.0, `path` may also address `event` — the
`X-GitHub-Event` name (`issues`, `workflow_run`, `star`, ...) — which
`entry_forwards` merges into the payload it evaluates against via
`setdefault` (a real payload field of the same name, if one ever exists,
always wins). Since 0.22.0, an all-digits segment indexes into a list instead
of ending the walk at `None` — `workflow_run.pull_requests.0.number` reaches
the first linked PR's number, the shape a spawned session needs to scope a
`when` to its own run (agent-box#251). Anything else against a list —
non-digits, a negative sign, an out-of-range index — misses the same way a
missing dict key does.

A leaf may instead carry `contains` / `notContains`, which test a **string**
value for any of the listed substrings, case-insensitively (0.14.0):

```json
{ "all": [ { "path": "action", "in": ["created", "edited"] },
           { "path": "comment.body", "contains": ["@mybot"] } ] }
```

Reach for these only where no list of whole values can do the job — free text.
A GitHub @mention is the case they exist for: it lives inside `comment.body`
with no structured field beside it, so `in` can never name it. Substrings must
be non-empty (an empty one is in every string, which would smuggle back the
"subscribe to everything" this file refuses to express), a non-string value
contains nothing, and a leaf carries exactly **one** of the four operators.
There is no regex: payload text is hostile, and a pathological pattern in
somebody else's comment body would stall the daemon.

```json
{ "topic": "github:defangdevs/*",
  "include": { "any": [
      { "all": [ { "path": "action", "in": ["opened", "reopened"] },
                 { "path": "sender.login", "notIn": ["defangdevs"] } ] },
      { "path": "workflow_run.conclusion", "in": ["failure", "timed_out", "startup_failure"] } ] },
  "exclude": { "path": "action", "in": ["closed", "merged"] } }
```

These rules are the **whole policy**: since 0.23.0 nothing built in adds to
them or steps aside for them, and a `deliver_to:"subagent"` watch cannot be
created without them (the live-session suppression on the dispatch path is
coordination, not policy, and still applies). Express sender muting *inside*
the predicate (as above) rather than combining with `ignoreSenders`, which is a
blunt mute that also silences that sender's CI failures.

`webhook_subscribe` takes the predicates as `include` / `exclude` (CLI:
`--include` / `--exclude` with a JSON argument; `when`/`drop` still work as
aliases) and rejects a malformed one at subscribe time. A malformed node that
reaches delivery anyway (hand-edited file) matches **nothing** and logs to
stderr — for `include` that mutes the entry, for `exclude` it forwards, and
either way the misconfiguration is distinguishable from a watch that quietly
stopped working. Omit both on re-subscribe to keep them; pass `{}` to clear.

#### Default noise-exclude for a brand-new session subscription (0.15.0)

A brand-new `deliver_to:"session"` subscription (never a renew, and never a
`deliver_to:"subagent"` entry, which already narrows via its own curated
rules) that names no `exclude` of its own is seeded with a built-in
noise-exclude instead of `None` — most agents never think to filter out a
repo's social-graph/lifecycle pings (`star`, `watch`, `fork`, `gollum`,
`member`, `membership`, `team`, `team_add`, `public`, `sponsorship`,
`delete`, `page_build`, `project`, `project_card`, `project_column`), plus a
`workflow_run` fired by a cron `schedule` rather than a human action.
Deliberately left alone: `label`, `milestone`, `commit_comment` — those carry
actual human intent, not pure plumbing. Pass `exclude: {}` explicitly to opt
out, or your own predicate to replace it; a re-subscribe never reapplies the
default, so once you've broadened with `exclude: {}` it stays broadened.

### Subscription expiry and notes (0.5.x)

Agent sessions come and go — context gets cleared, and a webhook landing
later in a fresh session is noise without the work that motivated it. Worse, a
late delivery lands after the session's KV cache has aged out, so re-reading
the whole conversation to handle one stale event burns a large pile of tokens.
So subscriptions **expire**, `ttlHours` after their clock was last reset
(top-level default **1** — chosen to track how long the KV cache stays warm, so
a straggler event can't trigger an expensive cold re-read; per-entry `ttlHours`
overrides it; `0` = pinned, never expires). Expired topics are pruned at
delivery time and on every tool call.

A **session** subscription is capped at **8 hours** (`MAX_SESSION_TTL_HOURS`)
and may not be pinned: `webhook_subscribe` refuses a longer `ttl_hours`, and
entries written before the cap are clamped when the file is read. The reason is
the renewal rule below — routine CI fires several events inside the warm
window, so each burst renews the very subscription it is polluting, and a
long-lived session topic sustains itself indefinitely. One observed case: a 12h
subscription on a busy repo lived through the night on CI bursts and delivered
a nightly build into unrelated work. A watch meant to last longer belongs on
`deliver_to:"subagent"`, which has no cap because it spawns a session rather
than interrupting one.

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
quote them). Those six name the batch's *routing*, never the object it is
about, so a consumer wanting "which PR/issue/run" had no way to get it short
of regexing the rendered prose. `LOCAL_WEBHOOK_SPAWN_META` (0.17.0) closes
that gap: one JSON object, the same per-event meta a channel notification's
`meta` field already carries (`event`, `repo`, `sender`, and whatever the
event type adds — `number`, `action`, `conclusion`, `ref`, ...), taken from
the newest surviving line in a coalesced batch. It promises only that
whatever the source's summarizer produced is visible, not that a given key
exists for every event type; an event with nothing to add still gets `{}`,
never a missing variable.

Differences from session routing, all deliberate:

- **Fails closed for a bigger reason.** No spawn command, no dispatch file, or
  a corrupt one all mean *spawn nothing*. Session routing fails closed too since
  0.13.0; what differs is the cost of the opposite mistake — failing open here
  would be a session per delivery, a fork bomb, not noise. (`webhook_subscribe`
  warns when the receiver daemon advertises no spawn command in
  `receiver.json`.)
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
  spawn commands run concurrently across all keys.
- **The spawn command can say "not now" (0.16.0).** Its exit code is a
  three-way answer: `0` accepted the batch; **`75`** (`EX_TEMPFAIL`) means the
  command understood the request and declines it *for now*; any other non-zero
  means a broken spawner, whose batch is logged and dropped (the same events
  already reached session peers). A declined batch is **kept** — put back at
  the head of its key's pending queue, re-checked against live ownership like
  any other waiting batch, and re-offered when the rate window opens or a
  concurrency slot frees. This is how a consumer at a session ceiling stops
  losing events: exit `1` there was indistinguishable from "command not
  found", and for a standing watch — events *nobody* owns — no session peer
  holds a copy to fall back on. Two bounds keep a permanent refusal finite: a
  key declined for more than `LOCAL_WEBHOOK_SPAWN_DEFER_MAX_S` (300 s) drops
  its batch with a log line naming how long it waited, and at most
  `LOCAL_WEBHOOK_SPAWN_PENDING_MAX` (200) lines wait per key, oldest dropped
  first. The HTTP response is unaffected: `deliver()` still answers `200 ok`,
  because the dispatch verdict is asynchronous and the HMAC and the peer
  fan-out really did succeed.
- **A waiting batch is re-checked before it spawns (0.11.1).** Every line in a
  follow-up batch is put to the live-peer question again the moment the batch
  starts, and dropped if a session now claims it. One failing run emits both
  `check_run.completed` and `workflow_run.completed`; the second arrives while
  the first spawn's session is still booting, so the arrival-time answer is
  "nobody owns this" and the window then defers it for a full 60 s — long after
  that session opened its peer socket and declared the topic. Without the
  re-check every failing run cost exactly two sessions, ~60 s apart. Only a
  follow-up batch is re-examined: the first event on an idle key still spawns
  immediately.
- **A watch with no rules spawns nothing (0.23.0).** Every event a watch
  matches costs a whole agent session, so the watch has to say which events are
  worth one: a dispatch entry carrying neither `include` nor `exclude` matches
  nothing, `webhook_subscribe` refuses to create one, and each declined event
  is logged to stderr naming the reason. Through 0.22.x such an entry inherited
  a built-in brake instead — a GitHub CI-outcome event spawned only for a
  terminal non-success (`failure`, `timed_out`, `action_required`,
  `startup_failure`, `stale`, plus `error` for `status`/`deployment_status`),
  and an unstated outcome counted as a failure. That default was useful and
  wrong in the same way: useful because it stopped a session per green build,
  wrong because a source-agnostic bus was deciding, for one source, which
  events matter, and a consumer that disagreed could not override it without
  writing rules that made the default moot anyway. Write the same policy as a
  predicate and it is visible, per-watch and yours (#16):

  ```json
  { "any": [ { "path": "action", "in": ["opened", "reopened"] },
             { "path": "workflow_run.conclusion",
               "in": ["failure", "timed_out", "startup_failure", "stale"] } ] }
  ```

  On agent-box that policy lives in `services.agent-box.webhook.watchPolicy`,
  which re-applies it to the box's own watches whenever the receiver daemon
  starts.
- **A live owner suppresses the spawn (0.10.0).** A standing watch is for events
  nobody owns, so before spawning the ingress owner asks whether a live session
  peer's own filter already claims this event — if so, that session is getting
  this delivery and a second agent on the same PR (sharing one working tree) is
  not help. Liveness comes from the peer's `instances/<key>.<pid>.sock`
  entry, pid-checked, so a crashed session cannot mute a watch; the probe is
  read-only, so it never renews the subscription it consults. Suppression is
  logged. **A claim must be declared (0.19.0, unified in 0.23.0).** An event is
  claimed only by a live peer whose entry carries an `include` predicate that
  matches it: a session that declared what it is working on has said something
  precise enough to act on, while a bare repo-wide entry has not. An `exclude`
  never claims — a new session subscription is seeded with the default
  noise-exclude, so counting those would make every session an owner. That is
  the difference between "a session is watching this repo" and "a session is
  working this PR", and it is why `issues.opened` still spawns while a session
  holds one PR (#16 — honouring a rule-less entry for every event would silence
  the watch for the whole repo until that session exits). Until 0.22.x a
  CI-outcome event took a coarser route (any live peer on the topic claimed
  it), because a session had no way to claim its own run; 0.23.0 dropped that
  along with the rest of the CI vocabulary, so a session claims its build by
  naming its branch — `{"path": "workflow_run.head_branch", "in": ["fix/…"]}` —
  and agent-box seeds exactly such a claim into every session it spawns
  (agent-box#251).

  So a session that wants to stop the watch from starting a second agent onto
  its work says what its work is:

  ```
  webhook_subscribe(topic="defangdevs/agent-box",
                    include={"any": [{"path": "pull_request.number", "in": [317]},
                                     {"path": "workflow_run.head_branch",
                                      "in": ["fix/317-thing"]}]},
                    note="PR #317: waiting on CI + review")
  ```

  This also narrows what that session receives, which is usually what it wanted
  anyway. Before 0.18.0 the probe was gated on `event in CI_EVENTS`, so a review
  or a comment on work a live session held spawned a duplicate session
  regardless (agent-box#319); since 0.23.0 the same predicate is what claims
  that PR's CI too, which is why the example names the branch as well.

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
        --include '{"any":[{"path":"action","in":["opened","reopened"]},
                           {"path":"workflow_run.conclusion","in":["failure"]}]}' \
        --note "standing watch: new issues/PRs and failing CI spawn a fresh session"
    python3 webhook.py ls
    python3 webhook.py unsubscribe owner/repo
    python3 webhook.py status        # state dir, session, sources (no secrets)
    python3 webhook.py emit budget '{"used_pct":92,"window":"5h"}' \
        --event budget_warning       # put a box-local event on the bus

`--note`, `--ttl`, `--deliver-to`, `--renew-on-event`, `--ignore-sender`
(repeatable, or one comma-separated list), `--include` and `--exclude` (JSON
predicate objects; `--when`/`--drop` still work as aliases) mirror the tool arguments;
`webhook.py --help` prints the details. Subscriptions are per session, so export the same
`LOCAL_WEBHOOK_SESSION` (and `LOCAL_WEBHOOK_STATE_DIR`) the session runs with —
under agent-box both are already in every session's environment.

A CLI invocation binds nothing: it is not a session peer and never owns the
ingress (`emit` connects to it as a client), so it is safe to run alongside the
daemon and any number of sessions.

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

## Wiring box-local sources (`emit`, 0.12.0)

The box's own signals — an imminent token-budget limit, a filling disk, an OOM
kill — are exactly as invisible to a session as a GitHub PR, and `webhook.py
emit SOURCE [JSON] [--event NAME]` puts them on the same bus. The payload (an
argument, or stdin when omitted or `-`) is signed with the source's secret from
`sources.json` and POSTed to the local ingress, entering through the front door
so verification, normalization, fan-out **and** standing-watch dispatch all
apply. Everything downstream works unchanged: `budget:5h` or `disk:/var` are
ordinary topics, `include`/`exclude` predicates gate on `used_pct` like any other
payload field, and a `deliver_to:"subagent"` watch can spawn a fresh session
for a signal nobody is live to see.

```sh
printf '%s' "$(openssl rand -hex 32)" > <state-dir>/budget.secret
# in sources.json:  "budget": { "secretFile": "budget.secret", "keyPath": "window" }
python3 webhook.py emit budget '{"used_pct":92,"window":"5h","resets_at":"..."}' \
    --event budget_warning
```

`emit` finds the ingress via `LOCAL_WEBHOOK_HTTP_SOCK`, then the daemon's
`receiver.json` advertisement (the only place a systemd-socket-activated path
is knowable — sessions run with `LOCAL_WEBHOOK_PORT=0` and no socket env), then
loopback `LOCAL_WEBHOOK_PORT`. Signing a same-box loop is plumbing reuse, not
security — the trust boundary is state-dir file permissions either way — but it
means the ingress needs no second, unauthenticated entry path. Producers should
fire on threshold *crossings* with hysteresis, never per poll: every event
lands in every subscribed session. The sensor set itself (budget / disk / OOM
timers calling `emit`) is
[#19](https://github.com/defangdevs/local-channels/issues/19).

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
| `LOCAL_WEBHOOK_SPAWN_DEFER_MAX_S` | `300` | how long a batch the spawn command keeps declining (exit `75`) is kept before it is dropped; `0` disables deferral |
| `LOCAL_WEBHOOK_SPAWN_PENDING_MAX` | `200` | max event lines waiting per key; past it the oldest are dropped |
| `WEBHOOK_SECRET` | — | legacy: implies a single `github` source if `sources.json` is absent |

When systemd socket activation is in effect (`LISTEN_FDS` set), the ingress
adopts the passed fd (fd 3) and both `LOCAL_WEBHOOK_HTTP_SOCK` and
`LOCAL_WEBHOOK_PORT` are ignored — the `.socket` unit owns the path and perms.
