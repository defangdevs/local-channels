# AGENTS.md

Guidance for AI agents working **on this repo**. For what the plugins do and how
to use them, read [README.md](README.md) — don't repeat it here.

## Layout

```
.claude-plugin/marketplace.json   marketplace manifest: name, owner, plugin list
local-webhook/
  .claude-plugin/plugin.json      plugin manifest: name, description, version
  .mcp.json                       launches `python3 ${CLAUDE_PLUGIN_ROOT}/webhook.py`
  webhook.py                      the entire plugin: MCP stdio server, HTTP ingress,
                                  IPC fan-out, filter/TTL logic, CLI — one file
  README.md                       per-plugin reference docs
```

There is no build system, no lockfile, no generated file, no CI workflow and no
test suite. A new plugin is a new top-level directory with its own
`.claude-plugin/plugin.json`, `.mcp.json`, `README.md` and a marketplace entry.

## Constraints that are not negotiable

- **Single file, stdlib only.** `webhook.py` must run straight out of a plugin
  cache directory under the stock `python3` **≥ 3.9** (the RHEL 9 / Ubuntu
  floor). No pip packages, no MCP SDK, no 3.10+ syntax (`match`, `X | Y`
  annotations). Dropping the last runtime dependency was the entire point of
  0.8.0 — don't add one back.
- **Wire and state contracts are load-bearing.** `sources.json`,
  `filter.*.json`, the IPC envelope on `instances/*.sock` and the HTTP status
  codes (agent-box's fail2ban keys on the `401`) are consumed outside this repo.
  Changing any of them is a breaking change that needs a companion change
  downstream, not a silent edit.
- **Auth fails closed, routing fails open.** Unknown source / missing secret /
  bad signature must reject; a missing or corrupt filter file must forward
  everything. Keep new code on the right side of that split.
- **Payload text is hostile.** Anything from a delivery that reaches the session
  goes through `s()`/`u()` (truncate + `⟪UNTRUSTED:…⟫`) and the
  `[UNTRUSTED webhook:<source>]` prefix.
- **Secrets never enter the repo.** All mutable state lives in the state dir.

## Conventions

- **Comments carry the *why*.** `webhook.py` is heavily commented with the
  reasoning behind each design choice (why TTL tracks cache warmth, why the CLI
  binds nothing, why CI events are sender-ignore exempt). Match that register
  when you touch it; a change that invalidates a comment must update it.
- **Terminology is fixed:** channel, delivery, ingress owner, session peer,
  topic (`source:key`), subscription, warm/cold delivery, echo muting. Reuse the
  existing words rather than inventing synonyms.
- **Tool descriptions and `INSTRUCTIONS` are docs too.** They are what a session
  actually reads, so behaviour changes must be reflected there, in
  `FILTER_COMMENT`, in `CLI_USAGE`, and in `local-webhook/README.md` — in the
  same commit.

## Versioning and release

Every behaviour change to a plugin is a version bump in the same commit:

1. `VERSION` in `local-webhook/webhook.py` and `version` in
   `local-webhook/.claude-plugin/plugin.json` must stay identical.
2. The plugin's `description` and `keywords` in `.claude-plugin/plugin.json` and
   its entry in `.claude-plugin/marketplace.json` are kept byte-identical.
3. Minor bump (`0.7.0` → `0.8.0`) for new capability or a reshaped internal
   model; patch bump for a fix or a tuned default (`0.5.3` retuned the TTL).
4. Update `local-webhook/README.md` and the root `README.md` version table.

Consumers pin this repo by revision — agent-box carries the pin in its
`modules/agent-box.nix` (a generated file there; edit its `.in` source) — so a
bump usually needs a companion PR in that repo. Mention it in the PR body.

## Commits and PRs

- Branch `feat/<short-topic>`; never commit to `main`.
- Commit subject: `local-webhook <version>: <what changed>`, imperative and
  concrete. Body explains the **problem first, then the change**, in prose
  paragraphs and bullets, and ends with the verification evidence. Keep the
  `Co-authored-by:` / `Claude-Session:` trailers.
- PR title mirrors the commit subject; PR body restates the rationale, the
  contracts deliberately left unchanged, and a `## Verification` section with
  what was actually run. Reference the issue it closes.
- Open the PR and stop — a human merges. Recent PRs are squash-merged, which is
  why the subject on `main` ends in `(#4)`.

## Testing

Verification is manual and end-to-end; the bar set by history is a real
signed delivery reaching a real session peer. Run it in a throwaway state dir so
you never touch the box's live subscriptions:

```sh
export LOCAL_WEBHOOK_STATE_DIR=$(mktemp -d) LOCAL_WEBHOOK_SESSION=test LOCAL_WEBHOOK_PORT=0
printf 'shh' > "$LOCAL_WEBHOOK_STATE_DIR/github.secret"
echo '{"defaultSource":"github","sources":{"github":{"secretFile":"github.secret"}}}' \
  > "$LOCAL_WEBHOOK_STATE_DIR/sources.json"

python3 local-webhook/webhook.py subscribe owner/repo --note "e2e"      # CLI path
LOCAL_WEBHOOK_RECEIVER_ONLY=1 LOCAL_WEBHOOK_HTTP_SOCK=$LOCAL_WEBHOOK_STATE_DIR/in.sock \
  python3 local-webhook/webhook.py &                                    # daemon
python3 local-webhook/webhook.py > peer.out &                           # session peer

BODY='{"repository":{"full_name":"owner/repo"},"sender":{"login":"someone"},"action":"opened","issue":{"number":1,"title":"t"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac shh -r | cut -d' ' -f1)
curl -sS --unix-socket "$LOCAL_WEBHOOK_STATE_DIR/in.sock" -X POST http://local/github \
  -H "x-hub-signature-256: sha256=$SIG" -H 'x-github-event: issues' -d "$BODY"   # -> ok
# peer.out must contain a notifications/claude/channel line with the note echoed
```

Also cover, as appropriate to the change: bad signature → `401`, unknown source
→ `404`, non-POST → `405`, the MCP stdio path (`initialize` reports the new
version, `tools/list`, `tools/call`), CLI exit codes (2 for usage, 1 for in-band
errors), per-session filter isolation, and that no stale `instances/*.sock` is
left behind. State the results in the commit body and PR.
