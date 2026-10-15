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
   channel_shared channel_unshared member_left_channel`. Do **not** add
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
`reply` and `post`; at most 20 writes per session per 10 minutes (`status`
edits and the first-message count excepted) and 5 top-level posts per channel
per hour; `reply`, `post`, `status` and `react` are audited in SQLite. Slack
calls go through per-tier token buckets with 40% reserved for reads; read
methods are form-encoded, writes JSON.

`status` keeps one message per thread and moves a reaction on the parent: the
daemon's 👀 ack becomes ⏳, then ✅ (`--done`) or ❌ (`--failed`).

The session name is `AGENT_BOX_SESSION_ID` (else `AGENT_BOX_SESSION`); with
neither set the per-session cap is shared by everyone on the box.

Controllers (who may `ready`/`hold`/`drop`) default to full workspace members,
looked up with `users.info`; a failed lookup counts as not a member.

## Not yet verified against Slack

Nothing here has talked to a real workspace. First live run, in order: events
reach a subscribed session; `conversations.replies`/`users.list` return data;
whether `markdown_text` accepts mention syntax (this sends mrkdwn `text`);
whether Slack linkifies a bare domain in API `text`.

Tests: `python -m unittest discover -s tests`.
