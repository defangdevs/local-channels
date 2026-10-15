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

1. Create an internal Slack app in your own workspace with Socket Mode on, bot
   scopes `channels:history groups:history channels:read groups:read chat:write
   reactions:read reactions:write users:read`, and bot events
   `message.channels message.groups reaction_added reaction_removed
   channel_shared channel_unshared member_left_channel`. Do **not** add
   `app_mentions:read` (mentions are read from `message` events; subscribing to
   both delivers each twice).
2. Set `SLACK_APP_TOKEN` (`xapp-…`) and `SLACK_BOT_TOKEN` (`xoxb-…`).
3. Register the `slack` source on the bus (`webhook.py setup slack`) and set
   `LOCAL_SLACK_EMIT` if `agent-box-webhook emit` is not the command to use.
4. Invite the bot to a channel (`/invite`), then `slack.py channel add C0123`.
   **A channel missing from `channels.json` is never processed, even if the bot
   is in it.**
5. `slack.py daemon`.

## Events (topic `slack:<team>/<channel>`)

`message.posted`, `message.edited`, `message.deleted`, `reaction.added`,
`reaction.removed`, `thread.settled` (`reason`: `quiet`, `max_wait`, `ready`,
`mention`), `thread.reopened`, `thread.dropped`, `feedback`. Message text is
never inlined; `title` is sanitised and capped at 200 characters.

## Writing

Every write passes `Writer`: the channel must be configured with
`write.allowed`; in `write.mode: on_request` (default) replies need a prior
mention or `ready`; text is *composed* (escape everything, then insert only the
`<@U…>` / `<#C…>` tokens the tool resolved, then refuse any token it did not
insert); links only to `links.allowed_hosts`, never unfurled; image Markdown
and secret patterns refused; a disclosure line is appended; 20 writes per
session per 10 minutes and 5 top-level posts per channel per hour; every write
is audited in SQLite. Slack calls go through per-tier token buckets with 40%
reserved for reads.

Tests: `python -m unittest discover -s tests`.
