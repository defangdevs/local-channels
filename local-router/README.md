# local-router

Decide which session an incoming message belongs to.

Chat channels such as WhatsApp, an email address, a Slack DM or a web prompt box
give one flat stream of messages. An agent works best with separate sessions,
one per task. Without a router, the user must choose the session for each
message, or everything goes into one long session. For each message,
`local-router` answers one of:

| action | meaning |
|---|---|
| `CONTINUE` | append it to an existing session (the current one or an older one) |
| `NEW` | start a clean session |
| `NEW_LINKS` | start a clean session that points at older sessions holding useful facts |

This is **mechanism only**. The caller decides what a decision does: resume a
session, start one whose kickoff names the linked transcripts, show the route to
the user, or let an explicit command override the router. The caller also
chooses which model backend to prefer.

It is one file, `router.py`, with the standard library only and Python 3.9 or
later, like the rest of this repo. It is not a Claude Code plugin and has no
marketplace entry.

## How it decides

1. **Reply hint.** If the channel knows what the message replies to (a WhatsApp
   quote, an email `In-Reply-To` header, a Slack `thread_ts`), pass it as
   `reply_to`. The router then continues that session without a model call.
2. **Optional short-reply rule.** If enabled, a short message soon after the
   last one continues the current session without a model call.
3. **A small LLM.** The prompt shows at most 9 candidate sessions: the 6 most
   recently active, plus up to 3 that your `similar` hook proposes (for example
   from an embedding search). Each candidate shows its age, the topic labels of
   its recent messages and its last two exchanges. Session ids are replaced by
   letters. The prompt stays under about 4k tokens, whatever the length of the
   chat.
4. **Fallback.** If the backend fails or gives an unusable answer, the message
   continues the current session (or starts a new one when there is none). The
   router never drops a message. A wrong merge only adds context; a wrong split
   loses context. So when the router cannot decide, it merges.

Each decision also returns a short `topic` label for the message. Store it with
the message and pass it back later: later prompts describe each session by these
labels.

## Why this design

The design comes from a benchmark (the scripts are not in this repo yet). The
data: 4,251 messages from 120 per-user WildChat streams, labelled by an LLM judge
with hindsight, plus hand-labelled personal WhatsApp and Grok chats.

- **An LLM, not rules or embeddings.** One decision at a time, with the correct
  history, Haiku was right for 90% of WildChat messages and 93–100% of the
  personal chats. The best time-gap rule got 78–82%. Embeddings alone did not
  beat the rules.
- **Haiku and gpt-6-luna tied** (90% vs 90% on WildChat). Claude calls are much
  smaller, so `auto_backend()` tries Claude first.
- **Recent topic labels, plus "not a catch-all".** In live routing, the
  router's own decisions build the history. Describing a session by its first
  message made a session that had drifted across topics look like "general
  work", and every new topic joined it: one session took 94 of 112 messages. The
  current prompt cut that to 23, with no loss of follow-up context on real
  traffic.
- **Cost.** With the lean `claude -p` flags used here, a Haiku call costs about
  $0.0005 and takes about 2 s. Without the flags, the call loads the user's whole
  Claude Code context and costs about 300 times more.

## Use

```python
import router   # local-router/router.py

sessions = [
    {"id": "s1", "messages": [
        {"role": "user", "text": "fix the leaking kitchen tap", "ts": 1731400000, "topic": "kitchen tap repair"},
        {"role": "assistant", "text": "Turn off the valve under the sink...", "ts": 1731400010}]},
    {"id": "s2", "messages": [
        {"role": "user", "text": "translate 'good morning' to Spanish", "ts": 1731500000, "topic": "Spanish translation"},
        {"role": "assistant", "text": "Buenos días.", "ts": 1731500005}]},
]
backend = router.auto_backend()          # first of claude, codex that answers a probe call
d = router.route({"text": "and in French?", "ts": 1731500300}, sessions, current="s2", backend=backend)
# {"action": "CONTINUE", "session": "s2", "links": [], "topic": "French translation", "reason": "llm"}
```

Pass only the tail of each session (the last few messages are enough); the
router reads no more than that.

`reason` tells you how the decision was made: `reply-hint`, `no-sessions`,
`rule-short`, `llm`, or `fallback`. A `fallback` decision also has an `error`
field when the backend failed.

### CLI

```sh
python3 router.py route [--backend auto|claude|codex|anthropic|openai|none] [--model M] \
                        [--short-rule 25,21600] < request.json
python3 router.py prompt < request.json      # show the prompt, no model call
python3 router.py probe --backend claude      # exit 0 when the backend answers
```

`request.json` is `{"message": {...}, "sessions": [...], "current": "id or null"}`.

## Backends

| name | class | auth | notes |
|---|---|---|---|
| `claude` | `ClaudeCLI(model="haiku")` | the signed-in `claude` CLI | runs with `--tools "" --setting-sources project --disable-slash-commands --system-prompt` in an empty directory |
| `codex` | `CodexCLI(model="gpt-6-luna", codex_home=None)` | the signed-in `codex` CLI | read-only sandbox and an ephemeral session. Pass `codex_home` (a directory that holds only `auth.json`) to keep the user's global `AGENTS.md` out of each call |
| `anthropic` | `AnthropicAPI(model="claude-haiku-5-5")` | `ANTHROPIC_API_KEY` | Messages API, low effort |
| `openai` | `OpenAICompatible(model, base_url)` | `OPENAI_API_KEY` (optional) | any `/v1/chat/completions` endpoint: hosted providers, vLLM, llama.cpp, Ollama |
| | `CommandBackend(argv)` | — | any command that reads the prompt on stdin |

`probe(backend)` sends one tiny real call. Local status commands do not prove
that auth works: `claude auth status` reports "logged in" for any key value.
`auto_backend(order=("claude", "codex"))` returns the first backend that passes.

## Safety

Message text is untrusted. The prompt puts all user and assistant text between
`<<<` and `>>>` and tells the model to route it, not to follow it. The router
replaces those two markers in the text, so the text cannot close them. The
worst result of a prompt injection is one misrouted message: the answer must be
one of three actions plus letters that map to known sessions. Anything else
becomes a fallback.

The routing call gets no tools. `claude -p` runs with `--tools ""`. `codex exec`
runs with `--ignore-user-config` (no MCP servers or plugins from the user's
config) and with its shell, unified-exec, code-mode, apps, browser, computer-use
and web-search tools turned off, because its read-only sandbox blocks writes but
not reads. On codex-cli 0.165.0 every tool call goes through the code-mode host, so with
`features.code_mode_host=false` each call fails closed before it runs. Canaries
outside the working directory confirmed it for a text file (exec), an image
(`view_image`) and a real MCP server, whose tool never ran even with the user
config loaded. Any Codex run that still
shows a tool item, or a blocked tool attempt, is rejected, so its answer never
reaches the caller. Codex adds tool families over time: re-check the flags when
the CLI is upgraded. Where inbound text is hostile, run the router as a user that
holds no secrets beyond the harness login.
