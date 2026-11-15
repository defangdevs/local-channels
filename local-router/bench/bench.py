#!/usr/bin/env python3
"""Benchmark for local-router: run router.route() over labelled message streams.

Two modes, because they answer different questions:

  teacher  For message i the router sees the GOLD sessions built from messages < i.
           One early error cannot spoil the rest, so this measures single
           decisions. Score: accuracy per gold class.
  live     The router's own answers build the sessions, as in production. One
           wrong merge or split changes every later prompt. Score: what the agent
           actually gets (see live_rows).

--mix P re-orders each stream so the user switches between open topics with
probability P per message (a "lazy" user who never says "new topic"). Each topic
keeps its internal order and topics still start in their original order, so the
gold labels stay valid. The original timestamps are re-used in order, so a time
gap no longer marks a switch.

Same constraints as router.py: single file, stdlib only, python >= 3.9.

  python3 bench/bench.py --mode teacher --backend claude --model haiku
  python3 bench/bench.py --mode live --mix 0.5 --streams 20 --backend claude
  python3 bench/bench.py --router gap:2            # a baseline, no model calls
  python3 bench/bench.py --data my_streams.jsonl   # your own labelled data

Model answers are cached by prompt in bench/.cache.jsonl, so a re-run with the same router
and data costs nothing. Delete the cache after changing the backend's model.
"""
import argparse
import collections
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import random
import statistics
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import router as R  # noqa: E402

DATA = os.path.join(HERE, "data")
CACHE = os.path.join(HERE, ".cache.jsonl")   # fixed path: the bench writes nowhere else
SKIP = ("CONTROL", "EVENT")   # gold actions that are not routing decisions


# ---------------------------------------------------------------- data
#
# One user message per JSON line:
#   {"stream": id, "seq": int, "ts": epoch s, "msg": text, "reply": assistant text,
#    "gold": {"action": CONTINUE|NEW|NEW_LINKS|CONTROL|EVENT, "thread": id,
#             "links": [thread ids], "also_ok": ["CONTINUE T3", "NEW", ...]}}
# CONTROL is an explicit command that clears the current session (it is not
# routed); EVENT is a message the assistant started, which joins gold["threads"].

def load(name_or_path):
    path = name_or_path
    if not os.path.exists(path):
        path = os.path.join(DATA, name_or_path + ".jsonl.gz")
    opener = gzip.open if path.endswith(".gz") else open
    by = collections.OrderedDict()
    with opener(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                by.setdefault(r["stream"], []).append(r)
    return [sorted(v, key=lambda r: r["seq"]) for _, v in sorted(by.items())]


def mix(stream, p, seed):
    """Topic-mixed copy of a stream (see the module docstring)."""
    recs = [r for r in stream if r["gold"]["action"] not in SKIP]
    by = collections.OrderedDict()
    for r in recs:
        by.setdefault(r["gold"]["thread"], []).append(r)
    order = list(by)
    rng = random.Random(seed)
    pos = dict((t, 0) for t in order)
    started, cur, out = 0, None, []
    while len(out) < len(recs):
        open_ = [t for t in order[:started] if pos[t] < len(by[t])]
        cands = open_ + ([order[started]] if started < len(order) else [])
        if cur in open_ and (rng.random() >= p or len(cands) == 1):
            t = cur
        else:
            t = rng.choice([x for x in cands if x != cur] or cands)
        if started < len(order) and t == order[started]:
            started += 1
        out.append(by[t][pos[t]]); pos[t] += 1; cur = t
    stamps = sorted(r["ts"] for r in recs)
    seen, res = set(), []
    for i, (r, ts) in enumerate(zip(out, stamps)):
        g = dict(r["gold"])
        if g["thread"] in seen and g["action"] != "CONTINUE":
            # A retry that the original labelled NEW now follows its own topic.
            g["action"], g["links"] = "CONTINUE", []
        seen.add(g["thread"])
        q = dict(r); q.update(stream=r["stream"] + "~mix", seq=i, orig_seq=r["seq"], ts=ts, gold=g)
        res.append(q)
    return res


def as_sessions(stream, members, topics):
    """router.py session dicts. members: {session id: [stream indices]}, topics:
    {stream index: label the router returned for that message}."""
    out = []
    for sid, idx in members.items():
        msgs = []
        for j in idx:
            r = stream[j]
            if r["gold"]["action"] == "EVENT":
                msgs.append({"role": "assistant", "text": r["msg"], "ts": r["ts"]})
                continue
            msgs.append({"role": "user", "text": r["msg"], "ts": r["ts"], "topic": topics.get(j, "")})
            if r.get("reply"):
                msgs.append({"role": "assistant", "text": r["reply"], "ts": r["ts"]})
        out.append({"id": sid, "messages": msgs})
    return out


# ---------------------------------------------------------------- routers
#
# A router is fn(message, sessions, current) -> router.py decision dict.

class Cached(object):
    """Backend wrapper: answers cached on disk by prompt, plus a call counter.
    A failed call is not cached, so a re-run retries it."""
    def __init__(self, backend, path, tag):
        self.backend, self.path, self.tag = backend, path, tag
        self.lock = threading.Lock()
        self.memo, self.calls, self.hits = {}, 0, 0
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    d = json.loads(line)
                    self.memo[d["k"]] = d["text"]

    def complete(self, system, prompt):
        k = hashlib.sha256(("%s\0%s\0%s" % (self.tag, system, prompt)).encode()).hexdigest()
        with self.lock:
            if k in self.memo:
                self.hits += 1
                return self.memo[k]
        if self.backend is None:
            raise RuntimeError("no backend and no cached answer")
        text = self.backend.complete(system, prompt)
        with self.lock:
            self.memo[k] = text; self.calls += 1
            if self.path:
                with open(self.path, "a") as f:
                    f.write(json.dumps({"k": k, "text": text}) + "\n")
        return text


def llm_router(backend, short_rule=None):
    def f(message, sessions, current):
        return R.route(message, sessions, current, backend=backend, short_rule=short_rule)
    return f


def baseline(spec):
    """always-current, or gap:H (NEW after more than H hours of silence)."""
    hours = float(spec.split(":", 1)[1]) if spec.startswith("gap:") else None

    def f(message, sessions, current):
        last = max([m["ts"] for s in sessions for m in s["messages"] if m.get("ts") is not None] or [None],
                   key=lambda x: -1 if x is None else x)
        stale = hours is not None and last is not None and message["ts"] - last > hours * 3600
        if current is None or stale:
            return {"action": "NEW", "session": None, "links": [], "topic": "", "reason": "baseline"}
        return {"action": "CONTINUE", "session": current, "links": [], "topic": "", "reason": "baseline"}
    return f


# ---------------------------------------------------------------- teacher-forced

def gold_class(g, current):
    if g["action"] in SKIP:
        return None
    if g["action"] == "CONTINUE":
        return "cont-current" if g["thread"] == current else "cont-older"
    return g["action"].lower().replace("_", "-")


def correct(g, d, current):
    """CONTINUE needs the right session; NEW and NEW_LINKS count as one class
    (both start clean; the links are scored separately, if at all)."""
    new = d["action"] in ("NEW", "NEW_LINKS")
    if g["action"] == "CONTINUE":
        if d["action"] == "CONTINUE" and d["session"] == g["thread"]:
            return True
    elif new:
        return True
    for alt in g.get("also_ok") or []:
        a, _, t = alt.partition(" ")
        if a in ("NEW", "NEW_LINKS") and new:
            return True
        if a == "CONTINUE" and d["action"] == "CONTINUE":
            if t and d["session"] == t:
                return True
            if not t and (d["session"] in (g.get("links") or []) or d["session"] == current):
                return True
    return False


def teacher(stream, route):
    members, topics = collections.OrderedDict(), {}
    current, rows = None, []
    for i, r in enumerate(stream):
        g = r["gold"]
        c = gold_class(g, current)
        if c is not None:
            d = route({"text": r["msg"], "ts": r["ts"]}, as_sessions(stream, members, topics), current)
            if d.get("topic"):
                topics[i] = d["topic"]
            rows.append((c, correct(g, d, current), d["reason"]))
        if g["action"] == "CONTROL":
            current = None
        elif g["action"] == "EVENT":
            for t in g["threads"]:
                members.setdefault(t, []).append(i); members.move_to_end(t)
            current = g["threads"][-1]
        else:
            members.setdefault(g["thread"], []).append(i); members.move_to_end(g["thread"])
            current = g["thread"]
    return rows


def teacher_summary(rows):
    tot, ok = collections.Counter(), collections.Counter()
    for c, hit, _ in rows:
        for k in ("ALL", c):
            tot[k] += 1; ok[k] += hit
    order = ["ALL", "cont-current", "cont-older", "new", "new-links"]
    return dict((k, {"accuracy": round(ok[k] / tot[k], 4), "n": tot[k]}) for k in order if tot[k])


# ---------------------------------------------------------------- live

def live(stream, route):
    """Rows of (kind, ok, foreign share, session). The strict score (map each
    predicted session to one gold thread) is unstable: one early merge marks every
    later message of the merged topic wrong. These ask what the agent gets:
      cont: gold CONTINUE; ok when the chosen session holds the previous message
            of that topic (context kept), else a split (context lost)
      new:  gold NEW/NEW_LINKS (or a topic's first message); ok when the router
            started a session, else a merge (extra, unrelated context)
      foreign share: share of OTHER topics' messages in the session joined."""
    members, topics = collections.OrderedDict(), {}
    current, n, rows = None, 0, []
    for i, r in enumerate(stream):
        g = r["gold"]
        if g["action"] == "CONTROL":
            current = None; continue
        if g["action"] == "EVENT":
            if current:
                members[current].append(i)
            continue
        d = route({"text": r["msg"], "ts": r["ts"]}, as_sessions(stream, members, topics), current)
        if d.get("topic"):
            topics[i] = d["topic"]
        sid = d["session"]
        new = d["action"] != "CONTINUE" or sid not in members
        if new:
            n += 1; sid = "p%d" % n; members[sid] = []
        prev = [j for j in range(i) if stream[j]["gold"]["action"] not in SKIP
                and stream[j]["gold"]["thread"] == g["thread"]]
        mates = [j for j in members[sid] if stream[j]["gold"]["action"] not in SKIP]
        foreign = sum(stream[j]["gold"]["thread"] != g["thread"] for j in mates) / len(mates) if mates else 0.0
        if g["action"] == "CONTINUE" and prev:
            rows.append(("cont", prev[-1] in members[sid], foreign, sid, d["reason"]))
        else:
            rows.append(("new", new, foreign, sid, d["reason"]))
        members[sid].append(i); members.move_to_end(sid); current = sid
    return rows, n


def live_summary(parts, ngold):
    rows = [x for rr, _ in parts for x in rr]
    cont = [ok for k, ok, *_ in rows if k == "cont"]
    new = [ok for k, ok, *_ in rows if k == "new"]
    joined = [f for k, ok, f, *_ in rows if not (k == "new" and ok)]
    biggest = max([collections.Counter(x[3] for x in rr).most_common(1)[0][1] for rr, _ in parts if rr] or [0])
    ratio = lambda xs: round(sum(xs) / len(xs), 4) if xs else None  # noqa: E731
    return {"useful": ratio(cont + new), "context_kept": ratio(cont), "clean_start": ratio(new),
            "foreign_share": round(statistics.mean(joined), 4) if joined else 0.0,
            "sessions": sum(n for _, n in parts), "gold_threads": ngold, "largest_session": biggest,
            "n": len(rows)}


# ---------------------------------------------------------------- CLI

def pct(x):
    return "-" if x is None else "%.0f%%" % (100 * x)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bench.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", default="wildchat_test",
                    help="wildchat_test, wildchat_dev, or a .jsonl/.jsonl.gz path (default wildchat_test)")
    ap.add_argument("--mode", choices=["teacher", "live"], default="teacher")
    ap.add_argument("--mix", type=float, help="topic switch probability per message (live or teacher)")
    ap.add_argument("--streams", type=int, help="only the first N streams (sorted by id)")
    ap.add_argument("--router", default="llm", help="llm (default), always-current, gap:HOURS")
    ap.add_argument("--backend", default="auto", choices=["auto"] + sorted(R.BACKENDS))
    ap.add_argument("--model")
    ap.add_argument("--short-rule", help="CHARS,SECONDS (see router.route)")
    ap.add_argument("--no-cache", action="store_true",
                    help="do not read or write the answer cache (bench/.cache.jsonl)")
    ap.add_argument("--workers", type=int, default=2, help="streams routed in parallel")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    streams = load(args.data)[:args.streams]
    if args.mix is not None:
        streams = [mix(s, args.mix, k) for k, s in enumerate(streams)]
    cached = None
    if args.router == "llm":
        if args.backend == "auto":
            if args.model:
                raise SystemExit("--model needs an explicit --backend")
            backend = R.auto_backend()
            if backend is None:
                raise SystemExit("no backend answered a probe call; pass --backend")
        else:
            kw = {"model": args.model} if args.model else {}
            backend = R.BACKENDS[args.backend](**kw)
        tag = "%s/%s" % (getattr(backend, "name", args.backend), getattr(backend, "model", args.model or ""))
        cached = Cached(backend, None if args.no_cache else CACHE, tag)
        short = None
        if args.short_rule:
            c, s = args.short_rule.split(",")
            short = (int(c), float(s))
        route = llm_router(cached, short)
        label = tag
    elif args.router == "always-current" or args.router.startswith("gap:"):
        route, label = baseline(args.router), args.router
    else:
        raise SystemExit("unknown --router %r" % args.router)

    fn = teacher if args.mode == "teacher" else live
    with cf.ThreadPoolExecutor(max(1, args.workers)) as ex:
        parts = list(ex.map(lambda s: fn(s, route), streams))
    reasons = collections.Counter(x[-1] for p in parts for x in (p if args.mode == "teacher" else p[0]))
    name = os.path.basename(args.data).split(".")[0] + ("~mix%g" % args.mix if args.mix is not None else "")
    if args.mode == "teacher":
        score = teacher_summary([x for p in parts for x in p])
    else:
        ngold = sum(len(set(r["gold"]["thread"] for r in s if r["gold"]["action"] not in SKIP)) for s in streams)
        score = live_summary(parts, ngold)
    result = {"data": name, "streams": len(streams), "mode": args.mode, "router": label,
              "score": score, "reasons": dict(reasons),
              "model_calls": cached.calls if cached else 0, "cache_hits": cached.hits if cached else 0,
              "router_version": R.VERSION}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if args.mode == "teacher":
            line = "  ".join("%s %s (%d)" % (k, pct(v["accuracy"]), v["n"]) for k, v in score.items())
        else:
            line = ("useful %s  context kept %s  clean start %s  foreign share %s  sessions %d/%d gold  "
                    "largest session %d msgs" % (pct(score["useful"]), pct(score["context_kept"]),
                                                 pct(score["clean_start"]), pct(score["foreign_share"]),
                                                 score["sessions"], score["gold_threads"],
                                                 score["largest_session"]))
        print("[%s, %d streams] %s %s: %s" % (name, len(streams), args.mode, label, line))
        print("decisions by reason: %s; model calls %d, cache hits %d" % (
            dict(reasons), result["model_calls"], result["cache_hits"]))
    if reasons.get("fallback"):
        print("warning: %d fallback decisions (backend errors or unusable answers)" % reasons["fallback"],
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
