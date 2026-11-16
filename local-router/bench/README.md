# local-router benchmark

This folder holds the benchmark that the `local-router` design comes from: the
script and a labelled test set made from public data. Use it to compare
backends, to check a prompt change before you ship it, or to measure the router
on your own labelled chats.

```sh
cd local-router
python3 bench/bench.py --router gap:2                        # baseline, no model calls
python3 bench/bench.py --backend claude --model haiku        # teacher-forced, 2,006 calls
python3 bench/bench.py --backend claude --mode live --mix 0.5 --streams 20
python3 bench/bench.py --data ~/my_labelled_chat.jsonl --backend codex
```

`bench.py` uses `router.route()` exactly as a caller does: the same prompt, the
same parsing and the same fallback. It has the same constraints as `router.py`:
one file, the standard library only, Python 3.9 or later. Model answers are
cached by prompt in `bench/.cache.jsonl` (not committed), so a second run with
the same router and data makes no model calls (`--no-cache` turns it off). Use `--json` for a machine-readable
result.

## Two modes

| mode | what the router sees | score |
|---|---|---|
| `teacher` (default) | the **correct** sessions, built from the gold labels of the earlier messages | accuracy per gold class |
| `live` | the sessions that **its own earlier decisions** built, as in production | what the agent actually gets (below) |

Teacher-forced accuracy measures single decisions: one early error does not
change the later prompts. Live routing is what users get. One wrong merge puts
unrelated messages into a session, and later prompts show that session with a
mixed history. The live score asks, for each message:

- **context kept**: the message continues a topic, and the session it joined
  holds the previous message of that topic. The rest are **splits**: the agent
  lost the context.
- **clean start**: the message starts a topic, and the router started a new
  session. The rest are **merges**: the agent gets unrelated context.
- **foreign share**: the share of messages from other topics in the session the
  message joined.
- **largest session**: the "snowball" check. A router that lets one session take
  every new topic gets a large number here.

A strict score that maps each predicted session to one gold thread is not
stable: one early merge marks every later message of the merged topic wrong.

### Topic mixing (`--mix P`)

Many users do not say "new topic". They switch between open tasks in one chat.
`--mix P` re-orders each stream so that the user switches to another open topic
with probability P for each message. Each topic keeps its own order, and topics
still start in their original order, so the gold labels stay correct. The
original timestamps are used again in order, so a time gap no longer shows a
topic switch. Mixing is deterministic (the seed is the stream's position).

## Results

Router 0.1.0, no `similar` hook, no short-reply rule. Haiku is `claude -p
--model haiku` with the lean flags of `ClaudeCLI`.

Teacher-forced, `wildchat_test` (61 streams, 2,006 messages):

| router | all | continue current | continue older | new | new + links |
|---|---|---|---|---|---|
| always-current | 72% | 100% | 0% | 13% | 0% |
| `gap:2` (new after 2 h of silence) | 80% | 95% | 0% | 53% | 34% |
| `gap:6` | 79% | 97% | 0% | 47% | 25% |
| Haiku | **90%** | 92% | 63% | 93% | 66% |

Live, first 20 streams of `wildchat_test` (196 gold topics):

| data | router | context kept | clean start | foreign share | sessions | largest session |
|---|---|---|---|---|---|---|
| as sent | always-current | 100% | 10% | 65% | 20 | 57 |
| as sent | `gap:2` | 95% | 42% | 39% | 107 | 50 |
| as sent | Haiku | 88% | 83% | 12% | 216 | 34 |
| `--mix 0.5` | always-current | 100% | 10% | 71% | 20 | 57 |
| `--mix 0.5` | `gap:2` | 81% | 24% | 56% | 107 | 50 |
| `--mix 0.5` | Haiku | 78% | 83% | 23% | 235 | 48 |

The three Haiku runs made about 3,000 model calls (the live runs re-use cached
answers for identical prompts) and cost about $1.50. One teacher-forced decision
was a fallback (an unusable answer). Live numbers move by a few points between
runs, because one different early decision changes the later prompts.

In the research behind the router, the same comparison on hand-labelled
personal WhatsApp and Grok chats gave the same order. Those chats are private
and are not in this repo. Other results from that research:

- gpt-6-luna (Codex) tied with Haiku on teacher-forced accuracy.
- Embeddings (bge-small) alone did not beat the time-gap rules. As a `similar`
  hook, their only gain was to find returns to sessions that had left the
  recent window.
- An embedding-first cascade sent 56–65% of messages to the LLM and lost about
  1 accuracy point. The short-reply rule `(25, 21600)` gives a similar trade
  with no embedding model.

## Data

`data/wildchat_test.jsonl.gz` (61 streams, 2,006 messages) and
`data/wildchat_dev.jsonl.gz` (59 streams, 2,245 messages). Use `dev` to tune a
prompt or a threshold, and report results on `test`.

**Source.** [WildChat-1M](https://huggingface.co/datasets/allenai/WildChat-1M)
(Allen Institute for AI), released under the
[ODC-BY 1.0](https://opendatacommons.org/licenses/by/1-0/) license. These files
are derived from it and are distributed under the same license. Cite:
Zhao, Ren, Hessel, Cardie, Choi and Deng, *WildChat: 1M ChatGPT Interaction
Logs in the Wild*, ICLR 2024.

The text is real user prompts and ChatGPT replies, unfiltered except for the
PII removal that WildChat did. Some of it is offensive.

**How the streams were made.**

- A stream is all the user turns of one WildChat user (same hashed IP address
  and user agent), in time order, across all of that user's conversations. This
  makes one flat chat with no threads, like WhatsApp. The `stream` id is a short
  hash of that key.
- Selection: users with 20–60 messages, a median message length under 400
  characters and under 30% templated first messages. Half of the streams return
  to an older conversation at least once.
- `ts` is the timestamp of the assistant reply (WildChat has no user-turn
  timestamp), at one-minute resolution.
- To keep the files small, `msg` is cut at 4,000 characters (71 messages) and
  `reply` at 2,000 characters (1,349 replies). The router reads at most 1,500
  and 300 characters of them.
- The split is by a hash of the stream id.

**How the labels were made.** WildChat's own conversation boundaries are not
usable as labels: a user who starts a new chat for a retry of the same task
needs CONTINUE, and a user who types a new topic into an old chat needs NEW.
About half of WildChat's "new chat" messages were not new topics. So each
stream was labelled by an LLM judge (Claude Sonnet) that saw the whole stream,
past and future, with the question "what SHOULD a router do with this message":

- `CONTINUE` thread: the message needs that thread's history.
- `NEW`: no earlier history helps.
- `NEW_LINKS` links: a new topic, but specific earlier threads hold useful facts.

On a pilot, Sonnet and Opus agreed on the action for 76 of 81 messages, and on
all 61 that Opus labelled with high confidence. The labels were not checked by
hand. Messages that a router could not decide at arrival (for example a bare
"Translate" whose text comes in the next message) have `"flags": ["amb"]`.

Totals: 2,914 CONTINUE, 1,124 NEW, 213 NEW_LINKS.

## Your own data

Any JSON Lines file (optionally gzipped) with one user message per line works
with `--data PATH`:

```json
{"stream": "me", "seq": 7, "ts": 1731500000, "msg": "and in French?", "reply": "En français : ...",
 "gold": {"action": "CONTINUE", "thread": "T3", "links": [], "also_ok": []}}
```

- `gold.action` is `CONTINUE`, `NEW` or `NEW_LINKS`. `thread` names the topic
  (for NEW and NEW_LINKS, the new topic's id). `links` lists useful older topics.
- `also_ok` lists other answers that you accept, for example `["NEW"]` or
  `["CONTINUE T2"]`.
- Two more actions are for chats where the assistant also writes on its own:
  `CONTROL` (an explicit command that ends the current session; not routed) and
  `EVENT` (a message the assistant started, which joins the topics in
  `gold.threads`).

Hand labels on a few hundred of your own messages tell you more about your
traffic than any public set. Keep private chats out of this repo.
