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
                              127.0.0.1:8788  webhook.mjs ──stdio/MCP──> claude session
                                        │
                          ~/.local/state/local-webhook/
                            sources.json   (who may deliver, secrets)
                            filter.json    (topic subscriptions)
```

- Each claude session spawns its own copy (it's an MCP server). Only one wins
  the HTTP port; the others log a warning and keep serving the MCP tools.
  Deliveries land in the session that owns the port.
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

### filter.json

Managed by the MCP tools; safe to hand-edit. Topics are `source:key` patterns:
`github:owner/repo` (exact), `github:owner/*` (prefix), `github:*`, or `*`.

```json
{ "enabled": true, "topics": ["github:defangdevs/claude-box", "github:defangdevs/*"] }
```

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
| `WEBHOOK_SECRET` | — | legacy: implies a single `github` source if `sources.json` is absent |
