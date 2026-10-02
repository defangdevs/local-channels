# local-whatsapp

Optional personal WhatsApp linked-device bridge. The device link belongs to one
per-user bridge process, not to a Claude or Codex session. The bridge accepts
only commands in the linked account's Message Yourself chat beginning with
`@box `; it never forwards other WhatsApp conversations. A message is routed to
one configured session. Claude receives a channel notification and can answer
with `whatsapp_reply`; Codex receives `codex queue` and can answer with the
`reply` CLI. The agent-box user controls session selection.

This is an unofficial WhatsApp Web client based on
[`@whiskeysockets/baileys`](https://github.com/WhiskeySockets/Baileys). Pairing
grants the bridge device access to the WhatsApp account, including chats the
bridge does not forward. The plugin does not use the WhatsApp Business API.

## Install and pair

Install the plugin with `claude plugin install local-whatsapp@local-channels`.
The peer itself needs only Node.js. The persistent bridge needs Node.js >=20
and the pinned npm dependencies. Copy `bridge.mjs`, `state.mjs`, `package.json`
and `package-lock.json` from the plugin's installed directory into a stable
per-user directory such as `~/.local/share/local-whatsapp`, then run
`npm ci --ignore-scripts` there. The plugin install path appears in
`~/.claude/plugins/installed_plugins.json`. When updating the bridge, replace
those four files and repeat `npm ci`. Run `npm audit` after updates.

All `node bridge.mjs` commands below run from that stable directory. Set a
private `LOCAL_WHATSAPP_STATE_DIR` to override the default
`~/.local/state/local-whatsapp`. Set `LOCAL_WHATSAPP_PHONE` to the number in
international digits-only format and run `node bridge.mjs pair`. The bridge
prints a short-lived pairing code. In WhatsApp on the primary phone, choose
**Linked devices > Link a device > Link with phone number instead** and enter
it. `pair` exits after the linked device connects. The phone number can also
be supplied on stdin. The number is needed only for pairing, not for later
service starts.

Run `node bridge.mjs target claude USER-SESSION` or
`node bridge.mjs target codex SESSION` to select the recipient. For Claude,
`USER-SESSION` is the value of `LOCAL_WEBHOOK_SESSION` (agent-box sets this to
`<login>-<session-name>`). Start the Claude session with
`--channels plugin:local-whatsapp@local-channels` in addition to its other
channels. For Codex, `SESSION` is the exact name accepted by `codex queue`.
Run `node bridge.mjs serve` as a supervised user service, then
`node bridge.mjs status` to check it. The bridge needs only outbound WhatsApp
network access; it opens a private Unix socket under the state directory for
Claude peers and local reply commands.

On an agent-box without a user systemd manager, a dedicated shell session can
supervise the bridge across host restarts:

```sh
agent-box-session add whatsapp-bridge --harness shell \
  --cwd "$HOME/.local/share/local-whatsapp" \
  -- -lc 'exec node bridge.mjs serve'
```

This shell session hosts the transport; it is not a WhatsApp command target.
It uses one agent-box session slot. Restart it with
`agent-box-session restart whatsapp-bridge` after updating the bridge files.

Send `@box hello` in Message Yourself. Replies are text-only. The bridge
answers with a receipt. Send `@box /sessions` to list agent-box sessions and
`@box /target NAME` to select one, even if it is currently stopped. These
commands use `agent-box-session ls` on the bridge host. A selected session can
restart without re-pairing the device. If it has been removed, select another
session; unanswered messages will then be routed to that session.
The bridge uses `/usr/local/bin/agent-box-session` and
`~/.nix-profile/bin/codex` by default; set `LOCAL_WHATSAPP_SESSION_BIN` or
`LOCAL_WHATSAPP_CODEX_BIN` to an absolute executable path if your installation
differs.

The bridge
retains incoming messages until they receive a reply, and queues a reply while
WhatsApp is disconnected. A Claude peer that reconnects may receive an
unanswered message again; its message ID stays the same so it can recognize
the retry. A Codex `queue` success records that it was queued to that target.
`sent` means WhatsApp accepted an outbound send, not that the phone displayed
it. A crash between WhatsApp accepting a send and recording it can cause a
duplicate reply.

The bridge stores linked-device keys and message text beneath its private
state directory. Sessions under the same Linux user can access this state;
agent-box sessions are not security boundaries. WhatsApp's Linked devices
screen can revoke the bridge at any time. A revoked device must be paired
again.

## Commands

| Command | Purpose |
| --- | --- |
| `node bridge.mjs pair` | Link by phone-number code |
| `node bridge.mjs serve` | Run the persistent bridge |
| `node bridge.mjs target claude USER-SESSION` | Route to a Claude peer |
| `node bridge.mjs target codex SESSION` | Route to a Codex session |
| `node bridge.mjs reply ID TEXT` | Queue a reply to the original WhatsApp chat |
| `node bridge.mjs status` | Show connection, target, and pending count |

The bridge has no shell-session adapter. The message transport and the target
selector are separate so one can be added without changing WhatsApp pairing.
