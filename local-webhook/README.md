# local-webhook

One-way MCP **channel** plugin: receives HMAC-signed webhook deliveries over
HTTP (GitHub or any other sender that signs the raw body with HMAC-SHA256) and
pushes a concise, untrusted-marked summary of each event into the Claude Code
session that spawned it. Ships MCP tools (`webhook_subscribe`,
`webhook_unsubscribe`, `webhook_subscriptions`) so the agent can route which
topics reach it — hot-reloaded per delivery, no session restart needed.

Single dependency-free file (`webhook.mjs`); runs under stock `node` (≥18) or
`bun`. No `node_modules`, no build step.

## How it fits together

```
GitHub / Stripe / anything ──HTTPS──> reverse proxy (Caddy, TLS)
                                        │ plain HTTP
                                        ▼
                              127.0.0.1:8788  webhook.mjs ──stdio/MCP──> claude session A
                                        │ unix-socket fan-out
                                        ▼
                    <state>/instances/<pid>.sock  webhook.mjs ──stdio/MCP──> claude session B
                                        │
                          ~/.local/state/local-webhook/
                            sources.json          (who may deliver, secrets)
                            filter.json           (topic subscriptions)
                            filter.<self>.json    (per-identity subscriptions)
```

- Each claude session spawns its own copy (it's an MCP server). Only one wins
  the HTTP port; it verifies the HMAC once and re-broadcasts the event to every
  other live instance over per-PID unix sockets, so **all** concurrent sessions
  receive deliveries, each applying its **own** filter.
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
own login must not mute CI results for your own pushes.

```json
{ "enabled": true, "ttlHours": 1, "topics": [
    "github:defangdevs/*",
    { "topic": "github:me/my-config-repo", "ttlHours": 0,
      "note": "this box's own repo — pinned", "subscribedAt": "2026-07-16T00:00:00Z" },
    { "topic": "github:defangdevs/claude-box", "ignoreSenders": ["@self"],
      "note": "waiting on CI for PR 42", "subscribedAt": "2026-07-16T00:00:00Z" } ] }
```

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
so the subscription lives as long as events keep arriving within `ttl_hours`
(pair with `ttl_hours: 0` to also survive total silence). `webhook_subscribe`
also takes `ttl_hours` to set the per-topic override — larger for a genuinely
multi-hour or multi-day wait, `0` to pin the box's own repos. Hand-written
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

### Per-identity filters

Set `LOCAL_WEBHOOK_SELF=<name>` in a session's environment and its instance
reads/writes `filter.<name>.json` instead of the shared `filter.json`. Two
concurrent sessions acting as different GitHub users can then subscribe to the
same repo with different ignore lists — each mutes only its own echoes, while
fan-out delivers the event to both.

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
| `LOCAL_WEBHOOK_PORT` (or legacy `WEBHOOK_PORT`) | `8788` | HTTP listen port, 127.0.0.1 only |
| `LOCAL_WEBHOOK_STATE_DIR` | `~/.local/state/local-webhook` | secrets + filter |
| `LOCAL_WEBHOOK_SELF` | — | identity this session acts as; selects `filter.<self>.json` and resolves `"@self"` in ignore lists |
| `WEBHOOK_SECRET` | — | legacy: implies a single `github` source if `sources.json` is absent |
