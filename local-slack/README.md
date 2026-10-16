# local-slack

A Slack connection for agent-box ([defangdevs/agent-box#863](https://github.com/defangdevs/agent-box/issues/863)).
Single file (`slack.py`), stdlib only, python ≥ 3.9. Design: the spec in that issue.

**0.1.0 is the core.** It covers event shaping, the settle timer, the send
guardrails, a Socket Mode client and a small CLI, in *plain mode* (tokens in the
agent user's env). Not yet built: socket-service mode (own Linux user, Unix
socket, `SO_PEERCRED` grants), MCP tools, the classifier command runner, `dm`
and `upload`, the HTTP Events API transport, the settings card and the agent-box
supervisor unit. Until socket-service mode exists, an agent that can read the
bot token can bypass the guardrails — use it only where the agent user is the
only author of its input.

## Setup

1. Create an internal Slack app in your own workspace with Socket Mode on, an
   app-level token with the `connections:write` scope, bot scopes
   `channels:history groups:history channels:read groups:read chat:write
   reactions:read reactions:write users:read`, and bot events
   `message.channels message.groups reaction_added reaction_removed
   channel_shared channel_unshared member_left_channel member_joined_channel`. Do **not** add
   `app_mentions:read` (mentions are read from `message` events; subscribing to
   both delivers each twice).
2. Set `SLACK_APP_TOKEN` (`xapp-…`) and `SLACK_BOT_TOKEN` (`xoxb-…`).
3. Declare the `slack` source on the bus. Run `agent-box-webhook setup slack`
   (it mints the secret and writes the source), then make sure its entry in
   local-webhook's `sources.json` carries the routing field this daemon sets:

   ```json
   "slack": { "secretFile": "slack.secret", "format": "generic", "keyPath": "route" }
   ```

   `route` is `<team>/<channel>`, so a subscription `slack:T0123/C0456` matches.
   Without `keyPath` every event is delivered to nobody.
4. Events reach the bus through local-webhook's own `webhook.py emit` (found
   next to this plugin, or in the Claude plugin cache); `LOCAL_SLACK_EMIT`
   overrides the command. Events are written to an outbox table in the same
   transaction pass that updates the thread and delivered by a worker that
   keeps the row until the emit succeeds, so a bus that is down delays events
   and does not lose them.
5. Invite the bot to a channel (`/invite`), then `slack.py channel add C0123`.
   It refuses a channel the bot is not in, and a Slack Connect channel unless
   `--allow-external`. `channel add` on an existing channel changes only the
   flags you pass and refuses to touch a `channels.json` that does not parse.
   **A channel missing from `channels.json` is never processed, even if the bot
   is in it.**
6. `slack.py daemon`.

## Events (topic `slack:<team>/<channel>`)

`message.posted`, `message.edited`, `message.deleted`, `reaction.added`,
`reaction.removed`, `thread.settled` (`reason`: `quiet`, `max_wait`, `ready`,
`mention`), `thread.reopened`, `thread.dropped`, `feedback`. Message text is
never inlined; `title` is sanitised and capped at 200 characters.

## Writing

Every write passes `Writer`: the channel must be configured with
`write.allowed`; in `write.mode: on_request` (default) replies and `status` need
a prior mention or `ready`; the ts must be a real message ts and is normalised
to its thread's parent. Text is *composed*: everything is escaped, then only the
`<@U…>` / `<#C…>` tokens the tool resolved are live. `@channel`/`@here`/
`@everyone` are refused unless `write.broadcast` (checked where the token is
made). A name that is not a known person or channel (`#42`, `@nobody`) stays
literal text, so an unknown name does not ping anyone and does not fail the
message either. Links: http(s) only, host on `links.allowed_hosts`, RFC 3986
characters only (no backslash, no `user@`), path/query/fragment capped and
scanned decoded, never unfurled; a scheme-less `evil.com` or `www.` link and
`mailto:` are held to the same check. Image Markdown and secret patterns
(zero-width characters ignored) are refused; a disclosure line is appended to
`reply` and `post` when `_defaults.disclosure` is set; write caps from
`_defaults.limits` (fresh defaults 20 per session per 10 minutes, `status` edits
excepted, and 5 top-level posts per channel per hour); `reply`, `post`, `status` and `react` are audited in SQLite. Slack
calls go through per-tier token buckets with 40% reserved for reads; read
methods are form-encoded, writes JSON.

`status` keeps one message per thread. If `_defaults.status_marks` names them it
also moves a progress reaction on the parent (the ack, if configured, gives way
to `working`, then `done` or `failed`); with none configured it makes no
reactions.

The session name is `AGENT_BOX_SESSION_ID` (else `AGENT_BOX_SESSION`); with
neither set the per-session cap is shared by everyone on the box.

Controllers (who may `ready`/`hold`/`drop`) default to full workspace members,
looked up with `users.info`; a failed lookup counts as not a member.

## Mechanism, not policy

This repo carries mechanism only (Lio's rule from closing #13); the recommended
*policy* belongs to agent-box, which renders it into `channels.json`.
[`channels.example.json`](channels.example.json) is that recommendation, written
out as the file agent-box would render.

**Mechanism, and not configurable because it is correctness or a Slack fact:**
de-duplication, persist-then-ack and the outbox; the settle state machine and its
compare-and-swap; the message index; compose-don't-filter and the token-smuggle
check; *enforcing* the broadcast flag, the link allowlist and the write gate; the
classifier as an opaque command; `SECRET_PATTERNS` as a safety floor; the
4,000-character limit; and that a reaction on the bot's own message is never
thread activity.

**Fail-closed, on purpose:** a channel not in `channels.json` is ignored, writing
is off, a failed user lookup counts as a guest, and a Slack Connect channel is
refused unless allowed.

**The daemon does not act in Slack by itself.** With an empty `_defaults` it
makes no reaction, appends no disclosure line, and keeps no status reactions.
These are all opt-in: `reactions.ack` (per channel), `_defaults.disclosure`,
`_defaults.status_marks`.

**What a reaction on the bot's own message means is configurable.**
`_defaults.feedback_reactions` names the reactions that go out as `feedback`;
with none configured it goes out as a plain `reaction.added` / `reaction.removed`
carrying `on_bot_message: true`, and the consumer decides.

**Fresh defaults.** These are starting values only. An explicit value always
wins, and nothing else in the code depends on them: `quiet_minutes` 30,
`max_wait_hours` 24, the ✅/✋/❌ control reactions, `write.mode: on_request`,
`retention_days` 30, and the write caps `_defaults.limits`
(`session_writes` 20 per `session_window_s` 600, `top_level_per_hour` 5; 0 turns a
cap off).

Not done yet, deliberately: emitting the bot's own messages and reactions with
`self: true` so a consumer can seed an exclude (the way local-webhook seeds its
GitHub echo exclude). The settle timer already ignores them. When grants land
(socket-service mode) they take the scope as given, with no built-in rule that a
watch-started session is limited to its thread: deciding that is agent-box's
spawn path.

## Not yet verified against Slack

Nothing here has talked to a real workspace. First live run, in order: events
reach a subscribed session; `conversations.replies`/`users.list` return data;
whether `markdown_text` accepts mention syntax (this sends mrkdwn `text`);
whether Slack linkifies a bare domain in API `text`.

Tests: `python -m unittest discover -s tests` for the unit layer, and
`python tests/e2e/run_e2e.py` for an end-to-end run (about 25 s): a mock Slack
(Web API plus a Socket Mode WebSocket server), this repo's real local-webhook
receiver with the documented `slack` source, a simulated agent session and a
standing watch, and the real `slack.py daemon` and CLI. It proves the pieces
work together and with the bus; it does not prove Slack agrees with our reading
of its docs. `LOCAL_SLACK_TICK_S` shortens the settle ticker for it.
