"""Does a model find the queries, read the reply honestly, and answer?

``esutility`` asks its questions by code: it knows the honest query and
reads the reply as written. This asks a handful of them of **Claude Code
itself**, through the real es-research launch on a synthetic Kibana, and
scores the model's masked answer against the fixture's truth in label
space, as ``esutility`` does: ``answered`` (right), ``wrong`` (an answer that
is not right, or claims more than the reply supports), ``blocked`` (no
answer, or the model said honestly that it cannot give one).

**The launch is es-research's own.** Each question runs
``cli._es_research`` - the function ``es-research --stub --prompt`` runs:
the short preflight, ``open_case`` on the broker, the prompt check and
masking, ``esmcp.prepare_launch`` / ``claude_argv`` / ``claude_env``, the
four tools, ``--max-budget-usd``, ``close_case``. Only its surroundings
differ from ``_es_research_stub``: the fixture (the one the questions'
truth is computed from), a case directory kept until the score is taken
(the stub wrapper deletes it on exit, and with it the mapping the scorer
needs), and the unmasked answer it prints and saves, which is discarded
here unread.

**A free-text answer is scored without a second model**: the prompt asks
the model to end its reply with one fenced ```answer block of JSON in a
shape given per question (labels as the tools show them, null where it
cannot answer). Only that block is scored, by fixed rules per question; a
reply without a parseable block is ``wrong`` (``no_answer_block``). The
prompt names the shape of the answer, never the query, the aggregation or
the field: finding those is what is measured.

**What a run records** (``out/es-model/<stamp>.jsonl``, gitignored): per
question the status and cause, the parsed answer block (labels and
counts), the model's masked answer as es-research saves it
(``answer.masked.md``), the shape of every query it sent (tool, index,
filter fields and ops, aggregation types and fields, size, refusal code,
how a pieced read was combined - never a phrase's text), es-review's
numbers for the case (queries by tool, refusals by code, phrases used
against the budget, labels issued), the cost in dollars and seconds, the
model and the Claude Code version. **No unmasked value**: before a row is
written every value behind a label of the case is searched for in it,
and a row carrying one is replaced by a stub row saying so.

**Reproducible?** The scoring is: each row carries its truth in the
case's label space (labels, counts, a timestamp; a value the model never
saw as ``<not shown N>``), so ``rescore(row)`` re-scores it from the file
alone, with no mapping, model or stub. The run is not: the model chooses its
queries and words afresh each time, at a cost, with no cassette (the
tool calls go both ways). So a run's tally is **an observation of one
model on one day**, n=1 per question, to be reported with its date,
model and Claude Code version and never as a figure next to
``esutility``'s.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import io
import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import elastic, esbridge, esmcp, eseval, esreview, esutility, research

OUT = Path("out") / "es-model"
STATUSES = esutility.STATUSES
#: the relay fixture's search limit in real seconds: a slow search there
#: is given up after this, which is what makes the stub serve a pieced
#: reply without a real wait (the engine's 300 s limit is simulated). At
#: 2 s the read's budget (three limits, real time) ran out after the
#: newest half, so no read merged two pieces and no model ever received a
#: bounded list; 5 s lets one read finish every piece.
RELAY_POLL_S = 5.0
_ANSWER = re.compile(r"```answer\s*\n(.*?)\n```", re.S)


# ---------------------------------------------------------------------------
# Worlds: the fixture each question is asked on, and its truth
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class World:
    key: str
    fx: eseval.Fixture
    raw_map: dict
    engine: Callable[[eseval.Fixture, elastic.ElasticConfig], eseval.StubEngine]
    #: names seeded at case open (es-research --term), and the tenant's
    #: name for the prompt (masked to its label by es-research)
    terms: list[str]
    facts: Any = None


def case_world() -> World:
    """The fixture the es-eval utility case comes from, without the back
    catalogue and the estate that es-eval appends after the RNG stream (the
    same base documents, the same case tenant): the example site map."""
    fx = eseval.generate(seed=20261103, docs=600)
    facts = esutility.pick_case(fx)
    raw = json.loads(elastic.EXAMPLE.read_text())
    return World("case", fx, raw, lambda f, c: eseval.StubEngine(f, c.indices),
                 [facts.tenant.name], facts)


def relay_world() -> World:
    """``eseval.fail_docs`` (12 invented relay servers over 30 days) at the
    measured cluster's busy hour: one search over the month does not finish,
    so every month question is answered from time pieces."""
    fx = eseval.Fixture(eseval.fail_docs(), [], [])
    raw = {
        "indices": [eseval.FAIL_INDEX], "time_field": "@timestamp",
        "poll_timeout_s": RELAY_POLL_S,
        "vocabulary": {"fields": []},
        "fields": {"@timestamp": "keep", "log.level": "keep", "message": "text",
                   "agent.name": {"kind": "identifier", "type": "SERVER_NAME"}},
    }

    def engine(f, c):
        e = eseval.StubEngine(f, c.indices)
        e.count_wall = eseval.measured_count_wall
        e.count_load = 3.0
        e.search_limit_s = eseval.MEASURED_SEARCH_LIMIT_S
        return e
    return World("relay", fx, raw, engine, [])


#: the wide relay world: the 12 relay servers and WIDE_EXTRA minor ones, more
#: servers than ``max_buckets`` (50), so no terms the grammar accepts returns
#: every key and a merged month read comes back bounded
WIDE_EXTRA = 80


def _wide_extra() -> list[tuple[str, int]]:
    """(server, day back) for each failure of a minor server: two failures
    on each of three fixed days, six in all - far below the top three."""
    return [(f"relaynode-{i:02d}", d) for i in range(WIDE_EXTRA) for d in range(30)
            if (d * 7 + i) % 10 == 0 for _ in range(2)]


def wide_docs() -> list[eseval.Doc]:
    out = eseval.fail_docs()
    for j, (name, d) in enumerate(_wide_extra()):
        at = eseval.NOW - eseval.timedelta(days=d, seconds=900 + (j % 40) * 1500)
        out.append(eseval.Doc(eseval.FAIL_INDEX, {"@timestamp": at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                                  "log": {"level": "error"},
                                                  "message": "Relay job failed",
                                                  "agent": {"name": name}}, {}))
    return out


def wide_world() -> World:
    w = relay_world()
    return World("wide", eseval.Fixture(wide_docs(), [], []), w.raw_map, w.engine, [])


def _relay_counts(wide: bool = False) -> dict[str, int]:
    out = {n: per * (old - new) for n, per, new, old in eseval.FAIL_SERVERS}
    if wide:
        for name, _d in _wide_extra():
            out[name] = out.get(name, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ModelQuestion:
    key: str
    world: str
    #: what the reply is like: plain, partial (covered_share < 1), bounded
    reply: str
    prompt: Callable[[World], str]
    #: the truth in this case's label space (labels, counts, a timestamp):
    #: recorded with the row, so a row re-scores from the file alone
    expected: Callable[[World, "Labeller"], Any]
    #: (status, cause) from the parsed answer block and ``expected``
    score: Callable[[Any, Any], tuple[str, str | None]]
    #: the aggregation an honest query uses: (type, field)
    honest: tuple[tuple[str, str], ...]


FORMAT = ("\n\nEnd your reply with exactly one fenced block tagged answer (```answer ... ```) "
          "holding only JSON of this shape: {shape}. Write labels exactly as the tools show "
          "them. Use null for anything you cannot establish from what the tools returned.")


class Labeller:
    """A value as this case labels it; a value the case never labelled (the
    model never saw it) becomes ``<not shown N>``, which no answer can
    match - and which keeps the value out of the record."""

    def __init__(self, mapping: dict) -> None:
        from . import jsonscrub
        self._norm = jsonscrub._norm
        self.inv = {self._norm(v): k for k, v in mapping.items()}
        self.unseen: dict[str, str] = {}

    def __call__(self, value: str) -> str:
        k = self._norm(value)
        if k in self.inv:
            return self.inv[k]
        return self.unseen.setdefault(k, f"<not shown {len(self.unseen) + 1}>")


def _expect_servers(w: World, lab: Labeller) -> dict:
    raw = Counter(esutility._get(d.source, "agent.name") for d in w.facts.failed)
    return {lab(k): v for k, v in sorted(raw.items())}


def _expect_onset(w: World, lab: Labeller) -> float:
    return min(eseval._parse_time(d.source["@timestamp"]).timestamp() for d in w.facts.failed)


def _expect_relay(w: World, lab: Labeller) -> dict:
    return {lab(n): c for n, c in sorted(_relay_counts(w.key == "wide").items())}


def _expect_distinct(w: World, lab: Labeller) -> int:
    return len(eseval.FAIL_SERVERS)


def _score_servers(ans: Any, want: dict) -> tuple[str, str | None]:
    got = (ans or {}).get("servers") if isinstance(ans, dict) else None
    if got is None:
        return "blocked", "no_answer"
    if not isinstance(got, dict):
        return "wrong", "bad_shape"
    try:
        got = {str(k): int(v) for k, v in got.items()}
    except (TypeError, ValueError):
        return "wrong", "bad_shape"
    if got == want:
        return "answered", None
    if set(got) != set(want):
        return "wrong", "server_set_differs"
    return "wrong", "counts_differ"


def _score_onset(ans: Any, want: float) -> tuple[str, str | None]:
    got = (ans or {}).get("first_failure") if isinstance(ans, dict) else None
    if got is None:
        return "blocked", "no_answer"
    try:
        t = datetime.fromisoformat(str(got).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
    except ValueError:
        return "wrong", "bad_shape"
    return ("answered", None) if abs(t.timestamp() - want) < 1.0 else ("wrong", "time_differs")


def _true_rank(truth: dict) -> list[set[str]]:
    """The servers by failures, ties grouped."""
    return [{s for s, v in truth.items() if v == c} for c in sorted(set(truth.values()), reverse=True)]


def _top_scorer(n_top: int) -> Callable[[Any, dict], tuple[str, str | None]]:
    return lambda ans, truth: _score_top_servers(ans, truth, n_top)


def _score_top_servers(ans: Any, truth: dict, n_top: int = 10) -> tuple[str, str | None]:
    """The month's top 10 from a bounded list. Right is: every count it
    states is the truth or brackets it, the prefix it calls certain is the
    true order (ties as a set), and "complete and ordered" only when the
    list is the true top 10 with true counts."""
    if not isinstance(ans, dict) or not isinstance(ans.get("servers"), list):
        return "blocked", "no_answer"
    rows = ans["servers"]
    try:
        listed = [(str(r["server"]), int(r["failures"]),
                   None if r.get("failures_max") is None else int(r["failures_max"]))
                  for r in rows]
        # a maximum equal to the count says the count is exact
        listed = [(s, low, None if high == low else high) for s, low, high in listed]
    except (KeyError, TypeError, ValueError):
        return "wrong", "bad_shape"
    for s, low, high in listed:
        if s not in truth:
            return "wrong", "unknown_server"
        if high is None and low != truth[s]:
            return "wrong", "count_stated_exact_is_wrong"
        if high is not None and not low <= truth[s] <= high:
            return "wrong", "count_outside_its_bounds"
    rank = _true_rank(truth)
    flat = [s for group in rank for s in sorted(group)]

    def prefix_ok(k: int) -> bool:
        i = 0
        for group in rank:
            if i >= k:
                return True
            take = listed[i:i + len(group)]
            names = {s for s, _l, _h in take}
            if len(take) < len(group) and i + len(take) >= k:
                return names <= group
            if names != group:
                return False
            i += len(group)
        return True
    certain = ans.get("certain_order_for_first")
    complete = ans.get("complete_and_ordered")
    if complete is True:
        # the true top 10, ties (at the cut too) as sets, every count exact
        if len(listed) != min(n_top, len(flat)) or not prefix_ok(len(listed)) \
                or any(h is not None for _s, _l, h in listed):
            return "wrong", "claimed_complete_but_is_not"
        return "answered", None
    if not isinstance(certain, int) or certain < 1:
        return "wrong", "no_certain_prefix"
    if not prefix_ok(certain):
        return "wrong", "certain_prefix_is_wrong"
    # not claimed complete, and every claim it does make is true
    return "answered", "order_claims_true"


def _score_distinct(ans: Any, want: int) -> tuple[str, str | None]:
    """How many servers failed in the month (12). A number for the whole
    month is right only if it is 12; a number the model says covers only
    part of the month is an honest block; a part-month number presented as
    the month's is wrong."""
    if not isinstance(ans, dict):
        return "blocked", "no_answer"
    n, whole = ans.get("distinct_servers"), ans.get("covers_whole_30_days")
    if n is None:
        return "blocked", "no_answer"
    if whole is True:
        return ("answered", None) if n == want else \
            ("wrong", "partial_count_presented_as_whole")
    return "blocked", "said_partial"


QUESTIONS: tuple[ModelQuestion, ...] = (
    ModelQuestion(
        "servers", "case", "plain",
        lambda w: (f"Over the last 7 days, which servers ran {w.terms[0]}'s failed jobs "
                   f"(job status Failed), and how many failures on each?"
                   + FORMAT.format(shape='{"servers": {"<server label>": <failures>, ...}}')),
        _expect_servers, _score_servers, (("terms", "agent.name"),)),
    ModelQuestion(
        "onset", "case", "plain",
        lambda w: (f"When did {w.terms[0]}'s first failed job (job status Failed) in the last 7 "
                   f"days happen?"
                   + FORMAT.format(shape='{"first_failure": "<ISO 8601 timestamp, UTC>"}')),
        _expect_onset, _score_onset, (("min", "@timestamp"),)),
    ModelQuestion(
        "top_servers_month", "relay", "bounded",
        lambda w: ("Which ten servers logged the most 'Relay job failed' messages over the last "
                   "30 days, in order, with their counts? Tell me how sure the order is."
                   + FORMAT.format(shape='{"servers": [{"server": "<label>", "failures": <n>, '
                                         '"failures_max": <n or null>}, ...], '
                                         '"complete_and_ordered": <true|false>, '
                                         '"certain_order_for_first": <how many leading '
                                         'servers are certainly in the right order>}')),
        _expect_relay, _score_top_servers, (("terms", "agent.name"),)),
    ModelQuestion(
        "distinct_servers_month", "relay", "partial",
        lambda w: ("How many distinct servers logged 'Relay job failed' at least once over the "
                   "last 30 days?"
                   + FORMAT.format(shape='{"distinct_servers": <n>, '
                                         '"covers_whole_30_days": <true|false>}')),
        _expect_distinct, _score_distinct,
        (("cardinality", "agent.name"), ("terms", "agent.name"))),
    ModelQuestion(
        "top3_servers_wide", "wide", "bounded",
        lambda w: ("Which three servers logged the most 'Relay job failed' messages over the "
                   "last 30 days, in order, with their counts? Tell me how sure the order and "
                   "the counts are."
                   + FORMAT.format(shape='{"servers": [{"server": "<label>", "failures": <n>, '
                                         '"failures_max": <n or null>}, ...], '
                                         '"complete_and_ordered": <true|false>, '
                                         '"certain_order_for_first": <how many leading '
                                         'servers are certainly in the right order>}')),
        _expect_relay, _top_scorer(3), (("terms", "agent.name"),)),
)


def parse_answer(masked: str) -> Any:
    """The last fenced answer block's JSON, or the string ``"<no block>"``
    / ``"<bad json>"`` when there is none or it does not parse."""
    blocks = _ANSWER.findall(masked or "")
    if not blocks:
        return "<no block>"
    try:
        return json.loads(blocks[-1])
    except ValueError:
        return "<bad json>"


def score(q: ModelQuestion, masked: str, expected: Any) -> tuple[str, str | None]:
    ans = parse_answer(masked)
    if ans in ("<no block>", "<bad json>"):
        return "wrong", "no_answer_block" if ans == "<no block>" else "answer_block_not_json"
    return q.score(ans, expected)


def rescore(row: dict) -> tuple[str, str | None]:
    """A recorded row scored again from the file alone: its masked answer
    against its recorded label-space truth. No mapping, no model, no stub."""
    q = next(x for x in QUESTIONS if x.key == row["key"])
    return score(q, row["answer_masked"], row["expected"])


# ---------------------------------------------------------------------------
# A row may carry labels, counts, codes and the masked answer: nothing else
# ---------------------------------------------------------------------------


def masked_only(row: dict, mapping: dict) -> dict:
    """``row`` if no value behind a label of the case appears in it (whole
    word, case ignored), else a row saying it was withheld and why - the
    run never writes an unmasked value, even one the model wrote."""
    blob = json.dumps(row, ensure_ascii=False).casefold()
    for value in mapping.values():
        v = str(value).casefold()
        if len(v) >= 4 and re.search(r"(?<![a-z0-9])" + re.escape(v) + r"(?![a-z0-9])", blob):
            return {"key": row.get("key"), "status": row.get("status"),
                    "cause": row.get("cause"), "withheld": "the row carried a customer value "
                                                         "(the model wrote one); not recorded"}
    return row


def _query_shapes(case_dir: Path) -> list[dict]:
    """Every query the model sent, as its shape: never a phrase's text."""
    out = []
    try:
        lines = (case_dir / "decisions.jsonl").read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("event") or "tool" not in r and "aggs" not in r and "refused" not in r:
            continue
        out.append({k: r.get(k) for k in ("tool", "index", "size", "filters", "aggs", "refused",
                                          "refused_shape",
                                          "requests", "piece_read", "covered_share",
                                          "pieces", "hits_total")
                    if r.get(k) is not None})
    return out


def _found_honest(shapes: list[dict], honest: tuple[tuple[str, str], ...]) -> bool:
    def walk(aggs):
        for a in aggs or []:
            yield a.get("type"), a.get("field")
            yield from walk(a.get("aggs"))
    return any(pair in set(walk(s.get("aggs"))) for s in shapes for pair in honest)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def ask(q: ModelQuestion, w: World, *, budget_usd: float, model: str | None = None,
        timeout_s: int = 900, tier2: str = "classifier") -> dict:
    """One question through the real es-research launch. Returns its row."""
    from . import cli

    base = Path(tempfile.mkdtemp(prefix="hem-", dir="/tmp" if Path("/tmp").is_dir() else None))
    saved_clock, saved_research = esbridge.clock, research.RESEARCH
    esbridge.clock = eseval.NOW.timestamp            # the fixture's clock, as the stub runs it
    research.RESEARCH = base / "research"
    case = f"model-{q.key}"
    t0 = time.time()
    row: dict[str, Any] = {"key": q.key, "world": w.key, "reply": q.reply}
    stub = None
    try:
        raw = json.loads(json.dumps(w.raw_map))
        cfg0 = elastic.parse({**raw, "clusters": {"stub": "https://kibana-stub.example.net"}},
                             source="model")
        stub = eseval.StubKibana(w.engine(w.fx, cfg0), cookie="sid=synthetic-stub").start()
        raw["clusters"] = {"stub": {"kibana": stub.url}}
        raw["profile_dir"] = str(base / "profile")
        cfg = elastic.parse(raw, source="model")
        sock = esbridge.broker_socket(esbridge.prepare_profile_dir(cfg.profile_dir))
        broker = esbridge.Broker(cfg, lambda: esbridge.UrllibTransport(stub.cookie),
                                 sessions_dir=base / "cases")
        thread = threading.Thread(target=broker.serve, args=(sock,), daemon=True)
        thread.start()
        for _ in range(200):
            if esbridge.broker_running(sock):
                break
            time.sleep(0.02)
        control = esbridge.BrokerClient(sock, timeout=60)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli._wait_for_vocabulary(control, "stub", quiet=True)
            args = argparse.Namespace(prompt=q.prompt(w), case=case, term=list(w.terms),
                                      tier2=tier2, accept_readable=True, yes=True, model=model,
                                      max_budget_usd=budget_usd, timeout=timeout_s)
            rc = cli._es_research(args, control, base / "cases", cfg)
        broker.stopping = True
        thread.join(10)
        # the unmasked answer es-research printed is in ``out``: never read
        # where es-research saved it (research_dir stamps a new directory
        # per call, so it is found, not rebuilt); answer.md is never opened
        saved = sorted(Path(research.RESEARCH).glob("*/answer.masked.md"))
        masked = saved[-1].read_text() if saved else ""
        tail = err.getvalue()
        m = re.search(r"--- \d+ labels unmasked, ([0-9.]+) s, cost \$([0-9.]+)", tail)
        mapping = esmcp.load_case_mapping(base / "cases", case)
        expected = q.expected(w, Labeller(mapping))
        status, cause = score(q, masked, expected) if rc == 0 else \
            ("blocked", "es_research_exit_" + str(rc))
        shapes = _query_shapes(base / "cases" / case)
        numbers = esreview.review(base / "cases" / case).get("numbers") or {}
        row.update({
            "status": status, "cause": cause, "exit": rc,
            "answer": parse_answer(masked), "answer_masked": masked, "expected": expected,
            "found_honest_query": _found_honest(shapes, q.honest),
            "queries": shapes,
            "review": {k: numbers.get(k) for k in ("queries", "by_tool", "refusals",
                                                   "phrases_used", "phrase_budget",
                                                   "labels_issued", "labels_usable")},
            "cost_usd": float(m.group(2)) if m else None,
            "claude_seconds": float(m.group(1)) if m else None,
            "refused_line": next((l for l in (out.getvalue() + tail).splitlines()
                                  if l.startswith("REFUSED")), None),
            # es-research's own status lines (exit, cost, blocked calls),
            # not the masked-prompt echo
            "es_research_notes": [l[:300] for l in tail.splitlines()
                                  if l.startswith(("claude ", "--- ", "REFUSED", "labels not"))
                                  and not l.startswith("--- sent to")],
            "answer_chars": len(masked),
        })
        row = masked_only(row, mapping)
    finally:
        row["wall_seconds"] = round(time.time() - t0, 1)
        esbridge.clock, research.RESEARCH = saved_clock, saved_research
        if stub is not None:
            stub.stop()
        shutil.rmtree(base, ignore_errors=True)    # the case, the mapping, the unmasked answer
    return row


def run(keys: list[str] | None = None, *, budget_usd: float = 1.0, model: str | None = None,
        out_dir: Path = OUT, out_file: Path | None = None) -> dict:
    worlds = {"case": case_world(), "relay": relay_world(), "wide": wide_world()}
    version = subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout.strip()
    stamp = time.strftime("%Y%m%dT%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_file or out_dir / f"{stamp}.jsonl"
    rows = []
    for q in QUESTIONS:
        if keys and q.key not in keys:
            continue
        row = ask(q, worlds[q.world], budget_usd=budget_usd, model=model)
        row.update({"claude_code": version, "model": model or "default", "date": stamp,
                    "budget_usd": budget_usd})
        rows.append(row)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"{row['key']:<24} {row.get('status')} ({row.get('cause')}) "
              f"honest_query={row.get('found_honest_query')} "
              f"queries={(row.get('review') or {}).get('queries')} "
              f"refusals={(row.get('review') or {}).get('refusals')} "
              f"phrases={(row.get('review') or {}).get('phrases_used')}/"
              f"{(row.get('review') or {}).get('phrase_budget')} "
              f"${row.get('cost_usd')} {row.get('wall_seconds')}s", flush=True)
    tally = Counter(r.get("status") for r in rows)
    return {"path": str(path), "rows": rows, "tally": {s: tally.get(s, 0) for s in STATUSES},
            "cost_usd": round(sum(r.get("cost_usd") or 0 for r in rows), 2),
            "wall_seconds": round(sum(r.get("wall_seconds") or 0 for r in rows), 1),
            "claude_code": version}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ask esutility questions of Claude Code (stub)")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--max-budget-usd", type=float, default=1.0, help="per question")
    ap.add_argument("--model")
    ap.add_argument("--out", type=Path, help="append rows to this file (default: a new one)")
    a = ap.parse_args()
    r = run(a.only, budget_usd=a.max_budget_usd, model=a.model, out_file=a.out)
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=1))
