"""local-router benchmark: data files, mixing and scoring, with fake routers (no model calls)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "local-router" / "bench" / "bench.py"
SPEC = importlib.util.spec_from_file_location("bench", BENCH)
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def rec(stream, seq, ts, msg, action, thread, reply="ok"):
    return {"stream": stream, "seq": seq, "ts": ts, "msg": msg, "reply": reply,
            "gold": {"action": action, "thread": thread, "links": [], "also_ok": [], "flags": []}}


# Two topics, interleaved once: T1 T1 T2 T1(return) T2
STREAM = [rec("s", 0, 0, "write a poem about cats", "NEW", "T1"),
          rec("s", 1, 60, "shorter", "CONTINUE", "T1"),
          rec("s", 2, 120, "what is the VAT rate in Cyprus", "NEW", "T2"),
          rec("s", 3, 180, "make the cat poem rhyme", "CONTINUE", "T1"),
          rec("s", 4, 240, "and in Greece?", "CONTINUE", "T2")]


def oracle(stream):
    """A router that knows the gold labels: it maps each gold thread to the
    session that the bench created for it."""
    by_text = dict((r["msg"], r["gold"]) for r in stream)
    owner = {}

    def f(message, sessions, current):
        g = by_text[message["text"]]
        if g["action"] == "CONTINUE":
            for s in sessions:
                if s["id"] == g["thread"] or owner.get(g["thread"]) == s["id"] or any(
                        m.get("text") == message["text"] for m in s["messages"]):
                    return {"action": "CONTINUE", "session": s["id"], "links": [], "topic": "", "reason": "o"}
            sid = owner.get(g["thread"])
            if sid:
                return {"action": "CONTINUE", "session": sid, "links": [], "topic": "", "reason": "o"}
        # NEW: remember which session id the bench will give it (p1, p2 ... in live mode)
        owner[g["thread"]] = "p%d" % (len(owner) + 1)
        return {"action": "NEW", "session": None, "links": [], "topic": "t", "reason": "o"}
    return f


class Data(unittest.TestCase):
    def test_published_sets_load(self):
        for name, n in (("wildchat_test", 2006), ("wildchat_dev", 2245)):
            streams = bench.load(name)
            recs = [r for s in streams for r in s]
            self.assertEqual(len(recs), n)
            for r in recs:
                self.assertIn(r["gold"]["action"], ("CONTINUE", "NEW", "NEW_LINKS"))
                self.assertTrue(r["gold"]["thread"])
            for s in streams:
                self.assertEqual([r["seq"] for r in s], sorted(r["seq"] for r in s))

    def test_plain_jsonl_path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("".join(json.dumps(r) + "\n" for r in reversed(STREAM)))
        self.assertEqual([r["seq"] for r in bench.load(f.name)[0]], [0, 1, 2, 3, 4])


class Mix(unittest.TestCase):
    def test_keeps_topic_order_and_valid_labels(self):
        for seed in range(20):
            m = bench.mix(STREAM, 0.9, seed)
            self.assertEqual(sorted(r["orig_seq"] for r in m), [0, 1, 2, 3, 4])
            self.assertEqual([r["ts"] for r in m], [0, 60, 120, 180, 240])
            for t in ("T1", "T2"):
                seqs = [r["orig_seq"] for r in m if r["gold"]["thread"] == t]
                self.assertEqual(seqs, sorted(seqs))
                first = next(r for r in m if r["gold"]["thread"] == t)
                self.assertEqual(first["gold"]["action"], "NEW")
            self.assertEqual(m[0]["orig_seq"], 0)    # topics still start in order

    def test_deterministic(self):
        self.assertEqual(bench.mix(STREAM, 0.5, 3), bench.mix(STREAM, 0.5, 3))


class Scoring(unittest.TestCase):
    def test_teacher_baseline(self):
        rows = bench.teacher(STREAM, bench.baseline("always-current"))
        s = bench.teacher_summary(rows)
        # first message NEW (right), "shorter" (right), VAT NEW (wrong), cat return (wrong), Greece (wrong)
        self.assertEqual(s["ALL"], {"accuracy": 0.4, "n": 5})
        self.assertEqual(s["cont-older"]["n"], 2)

    def test_teacher_sees_gold_sessions(self):
        seen = []

        def spy(message, sessions, current):
            seen.append((current, [s["id"] for s in sessions]))
            return {"action": "NEW", "session": None, "links": [], "topic": "", "reason": "spy"}
        bench.teacher(STREAM, spy)
        self.assertEqual(seen[3], ("T2", ["T1", "T2"]))
        self.assertEqual(seen[4], ("T1", ["T2", "T1"]))

    def test_live_oracle_is_perfect(self):
        rows, n = bench.live(STREAM, oracle(STREAM))
        s = bench.live_summary([(rows, n)], 2)
        self.assertEqual((s["useful"], s["context_kept"], s["clean_start"], s["foreign_share"]), (1, 1, 1, 0))
        self.assertEqual((s["sessions"], s["largest_session"]), (2, 3))

    def test_live_always_current_merges(self):
        rows, n = bench.live(STREAM, bench.baseline("always-current"))
        s = bench.live_summary([(rows, n)], 2)
        self.assertEqual(s["sessions"], 1)
        self.assertEqual(s["context_kept"], 1)
        self.assertEqual(s["clean_start"], 0.5)   # first message starts one; the VAT topic merges

    def test_gap_baseline(self):
        f = bench.baseline("gap:1")
        sess = [{"id": "a", "messages": [{"role": "user", "text": "x", "ts": 0}]}]
        self.assertEqual(f({"text": "y", "ts": 3000}, sess, "a")["action"], "CONTINUE")
        self.assertEqual(f({"text": "y", "ts": 4000}, sess, "a")["action"], "NEW")


class Cache(unittest.TestCase):
    def test_answers_are_cached_and_failures_are_not(self):
        class B(object):
            calls = 0
            fail = True

            def complete(self, system, prompt):
                B.calls += 1
                if B.fail:
                    raise RuntimeError("down")
                return '{"action": "NEW"}'
        path = Path(tempfile.mkdtemp()) / "c.jsonl"
        c = bench.Cached(B(), str(path), "t")
        with self.assertRaises(RuntimeError):
            c.complete("s", "p")
        B.fail = False
        self.assertEqual(c.complete("s", "p"), '{"action": "NEW"}')
        c2 = bench.Cached(None, str(path), "t")
        self.assertEqual(c2.complete("s", "p"), '{"action": "NEW"}')
        self.assertEqual((B.calls, c2.hits), (2, 1))
        with self.assertRaises(RuntimeError):
            bench.Cached(None, str(path), "other-model").complete("s", "p")


class CLI(unittest.TestCase):
    def test_baseline_run_json(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bench.main(["--router", "gap:2", "--streams", "3", "--json", "--mode", "live", "--mix", "0.5"])
        d = json.loads(out.getvalue())
        self.assertEqual((d["streams"], d["mode"], d["model_calls"]), (3, "live", 0))
        self.assertIn("context_kept", d["score"])


if __name__ == "__main__":
    unittest.main()
