"""Can an operator still get real answers through the Elasticsearch bridge?

Everything else ``es-eval`` measures is what the bridge hides or refuses.
This measures the other side, with no model involved: a set of scripted
investigations, each the questions a support engineer actually asks about
one tenant whose jobs started failing, run through the real
:class:`esbridge.Bridge` path (compile, vocabulary, gate again, send, scrub)
over the stub engine. Every question is a **fresh case seeded with the
tenant's name and nothing else**, and its expected answer is computed from
the fixture's raw documents, never written by hand.

The case is picked from the fixture, not invented for it: the first tenant
that has a failing job (``job.status`` ``Failed``) whose name contains
"Nightly". No document is added, so nothing else the eval reports moves.

Scoring. An answer counts only if it can be read from what the bridge
returned. A label counts as the value it stands for (the human can unmask a
finished answer locally); a value that came back only as a label does not
count when the question needs the value itself.

* **answered** - the answer read from the bridge equals the fixture's
  answer **in label space**: every customer value replaced by the label this
  case's mapping gives it, and nothing else changed.
* **wrong** - the bridge returned an answer and it differs. ``redaction``
  when unmasking every label in it would give the right answer - redaction
  changed what the operator reads (a word that is not a customer value
  labelled, a value hidden only in part, one value under two labels) - and
  ``differs`` when it would not. Redaction that changes the answer is
  scored wrong, not answered, because the operator reads the redacted
  answer, not the unmasked one.
* **blocked** - no answer: the honest query was refused (its refusal code
  is kept), or the answer came back only behind a label. Each blocked
  question names what is missing (:data:`GAPS`). A question whose honest
  form does not fit the grammar is sent in that form and left blocked; it
  is never rewritten into something the grammar accepts.

The report carries counts and codes only - question keys, statuses, causes,
refusal codes, numbers of queries, requests and answer items - never a
value. It is not a gate.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from . import elastic, eseval, jsonscrub

INDEX = "logs-app-*"
#: every question asks over the last week, which holds every failure the
#: fixture has (they sit in the six hours before ``eseval.NOW``)
CASE_RANGE = {"gte": "now-7d", "lte": "now"}
FAILED = "Failed"
NIGHTLY = "Nightly"
STATUSES = ("answered", "wrong", "blocked")

#: What is missing when a question is blocked, by cause code. The report
#: prints the code; this is what it means.
GAPS = {
    "name_not_seeded": "the engineer knows the job by its name from the ticket; an identifier "
                       "field takes only a label the case has been shown, and only the human "
                       "can seed a name (there is deliberately no value-to-label tool): "
                       "es-seed adds it to the open case, which is the human step the "
                       "named_job question shows",
    "text_aggregation": "group failures by their message text; text fields cannot be "
                        "aggregated by terms (text_groups groups them after redaction)",
    "negation": "exclude what matches a filter (everything except the known error); the "
                "grammar has no not/must_not",
    "or_across_fields": "match any one of several conditions on different fields; filters "
                        "are AND only and in is OR within one field",
    "label_only": "the answer is a value the site map declares an identifier (tenant size), "
                  "so only its label comes back, and range/min/max/avg on it are refused",
    "no_readable_phrase": "redaction left no run of two plain words in the error to search by",
    "text_names_not_enumerable": "which tenants an error hits, when some are named only in "
                                 "text: a terms aggregation buckets the tenant field, so a "
                                 "document without it is in no bucket, and a group's text "
                                 "shows <*> where a name stood (a group makes no label "
                                 "usable), so names in text cannot be listed; each candidate "
                                 "must be asked for by its own label, one wider scope at a "
                                 "time",
}

_LABELISH = re.compile(r"<[^<>\s]+>")
_DIGITS = re.compile(r"\S*\d\S*")
_WORD = re.compile(r"[A-Za-z]+")


# ---------------------------------------------------------------------------
# The case, and what the fixture says about it
# ---------------------------------------------------------------------------


@dataclass
class CaseFacts:
    """The fixture's side of the case. Raw values: never reported."""

    tenant: eseval.Tenant
    job: str
    #: every application document of the case's tenant in the window
    docs: list[eseval.Doc]
    #: its failures, newest first (the default sort of a page)
    failed: list[eseval.Doc]
    #: every tenant's failures in the window
    all_failed: list[eseval.Doc]
    templates: list[re.Pattern]

    def template(self, text: str) -> int | None:
        for i, rx in enumerate(self.templates):
            if rx.fullmatch(text):
                return i
        return None


def _get(src: dict, path: str) -> Any:
    for k in path.split("."):
        src = src.get(k) if isinstance(src, dict) else None
    return src


def _in_window(doc: eseval.Doc) -> bool:
    t = eseval._parse_time(doc.source.get("@timestamp"))
    lo = eseval._parse_time(CASE_RANGE["gte"])
    hi = eseval._parse_time(CASE_RANGE["lte"], round_up=True)
    return t is not None and lo <= t <= hi


def _templates() -> list[re.Pattern]:
    """Every template a status message is drawn from: the index's messages
    and the clean ones (a clean document's status message is clean too)."""
    tpl = eseval._load()
    out = []
    for t in tpl["messages"][INDEX] + tpl["clean_messages"]:
        parts = re.split(r"\{[A-Z_]+\}", t)
        out.append(re.compile("(.+?)".join(map(re.escape, parts))))
    return out


def _newest_first(docs: list[eseval.Doc]) -> list[eseval.Doc]:
    return sorted(docs, key=lambda d: eseval._parse_time(d.source["@timestamp"]), reverse=True)


def pick_case(fx: eseval.Fixture) -> CaseFacts | None:
    """The first tenant with a failing job whose name says Nightly."""
    app = [d for d in fx.docs if d.index == INDEX and _in_window(d)]
    failed = [d for d in app if _get(d.source, "job.status") == FAILED]
    for t in fx.tenants:
        mine = [d for d in app if _get(d.source, "labels.tenant_name") == t.name]
        for job in dict.fromkeys(j[0] for j in t.jobs):
            if NIGHTLY in job and any(_get(d.source, "job.name") == job
                                      and _get(d.source, "job.status") == FAILED for d in mine):
                return CaseFacts(t, job, mine,
                                 _newest_first([d for d in mine if d in failed]),
                                 _newest_first(failed), _templates())
    return None


# ---------------------------------------------------------------------------
# The operator: a fresh case, its seed, and what it can read
# ---------------------------------------------------------------------------


class Blocked(Exception):
    def __init__(self, cause: str, code: str | None = None) -> None:
        super().__init__(cause)
        self.cause, self.code = cause, code


class Operator:
    """One fresh case on the real bridge, seeded with the tenant only."""

    def __init__(self, cfg: elastic.ElasticConfig, engine: eseval.StubEngine,
                 vocab: elastic.ClusterVocabulary, seed: str, *, tier2: str) -> None:
        self.case = eseval.BridgeCase(cfg, engine, vocab, tier2=tier2)
        self.scrubber = self.case.scrubber
        self.engine = engine
        self.tenant = self.scrubber.seed(seed)
        self.queries = 0
        #: the human's steps, as the report shows them: what the engineer
        #: did by hand between queries (never a value)
        self.human_steps: list[str] = []
        self._requests0 = len(engine.requests)

    @property
    def requests(self) -> int:
        return len(self.engine.requests) - self._requests0

    def ask(self, query: dict, *, gap: str | None = None, gap_codes: tuple[str, ...] = ()) -> dict:
        """Run one query; a refusal blocks the question. ``gap`` names what
        is missing when the refusal is the one the honest query was
        expected to meet."""
        self.queries += 1
        out, refused, _dt, _c = self.case.call(query)
        if refused is not None:
            raise Blocked(gap if gap and refused.code in gap_codes else refused.code,
                          refused.code)
        return out

    def human_seed(self, term: str, what: str) -> str:
        """The engineer adds a name to the open case (es-seed): the same
        bridge step the CLI reaches through the broker, a decision-log row
        with the label and never the value. Returns the label the engineer
        hands to Claude. ``what`` says where the name came from."""
        r = self.case.bridge.seed(term)
        self.human_steps.append(f"es-seed {r['type']} {what}")
        return r["label"]

    def close(self) -> None:
        shutil.rmtree(self.case.directory, ignore_errors=True)

    # -- reading what came back, as the operator reads it ------------------

    def is_label(self, s: Any) -> bool:
        return isinstance(s, str) and s in self.scrubber.mapping

    # -- the grader's side: the case's own mapping -------------------------

    def label_of(self, value: str) -> str:
        """The label this case gives a value, or the value itself when the
        case never labelled it (then the operator should read it as written)."""
        return self.scrubber.known.get(jsonscrub._norm(value), value)

    def project(self, text: str, planted: dict[str, str]) -> str:
        """``text`` as it should read: each customer value planted in it
        replaced by its label, nothing else changed."""
        values = sorted((v for v, t in planted.items() if t != "TENANT_SIZE" and v in text),
                        key=len, reverse=True)
        if not values:
            return text
        rx = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(map(re.escape, values))
                        + r")(?![A-Za-z0-9])")
        return rx.sub(lambda m: self.label_of(m.group(0)), text)

    def unmask(self, node: Any) -> Any:
        """Every label in an answer replaced by the value behind it."""
        if isinstance(node, str):
            if node in self.scrubber.mapping:
                return self.scrubber.mapping[node]
            present = sorted((lb for lb in self.scrubber.mapping if lb in node),
                             key=len, reverse=True)
            for lb in present:
                node = node.replace(lb, self.scrubber.mapping[lb])
            return node
        if isinstance(node, Counter):
            return Counter({self.unmask(k): v for k, v in node.items()})
        if isinstance(node, dict):
            return {self.unmask(k): self.unmask(v) for k, v in node.items()}
        if isinstance(node, list):
            return sorted(self.unmask(x) for x in node)
        return node


def shape(text: str) -> str:
    """A message with its labels and anything carrying a digit masked: what
    an engineer reads as "the same error" across a page."""
    return _DIGITS.sub("#", _LABELISH.sub("<>", text))


def search_phrase(text: str) -> str | None:
    """The longest run of plain words in a redacted message (two or more),
    which is what an engineer would paste into a search."""
    best: list[str] = []
    for seg in re.split(r"<>|#", shape(text)):
        words = _WORD.findall(seg)
        if len(words) > len(best):
            best = words
    return " ".join(best) if len(best) >= 2 else None


def commonest(texts: list[str], key: Callable[[str], Any]) -> Any:
    """The commonest key among ``texts`` (given newest first); a tie goes to
    the newest."""
    counts = Counter(key(t) for t in texts)
    top = max(counts.values())
    return next(key(t) for t in texts if counts[key(t)] == top)


# ---------------------------------------------------------------------------
# The investigations
# ---------------------------------------------------------------------------


def _q(*filters: dict, size: int = 0, aggs: dict | None = None) -> dict:
    q: dict[str, Any] = {"index": INDEX, "time_range": CASE_RANGE, "size": size,
                         "filters": list(filters)}
    if aggs:
        q["aggs"] = aggs
    return q


def _eq(f: str, v: Any) -> dict:
    return {"field": f, "op": "eq", "value": v}


def _messages(out: dict, path: str = "job.status_message") -> list[str]:
    return [str(_get(h.get("_source") or {}, path)) for h in out["hits"]["hits"]
            if _get(h.get("_source") or {}, path) is not None]


@dataclass
class Graded:
    expected_raw: Any
    expected_read: Any
    got: Any
    #: the answer needs the value itself, so a label does not count
    needs_value: bool = False
    #: figures for the report line, counts only (how far the reply said to
    #: trust itself, and whether it was right to)
    figures: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class Question:
    key: str
    kind: str
    #: the real work it stands for
    work: str
    run: Callable[[Operator, CaseFacts], Graded]
    #: what is missing if the honest query does not fit, and the refusal
    #: codes that mean it did not
    gap: str | None = None
    gap_codes: tuple[str, ...] = ()
    #: the honest query, in words
    honest: str = ""
    #: the question runs on invented documents of its own, in their own
    #: index pattern and map (see :func:`eseval.burst_world`), because the
    #: fixture's case cannot show what it measures; None: the fixture's case
    own_data: Callable[..., tuple] | None = None
    #: the tenant the fresh case is seeded with on its own data
    own_seed: str = ""


def _onset(op: Operator, cs: CaseFacts) -> Graded:
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.status", FAILED),
                    aggs={"first": {"type": "min", "field": "@timestamp"}}))
    want = min(eseval._parse_time(d.source["@timestamp"]).timestamp() * 1000 for d in cs.failed)
    got = out["aggregations"]["first"]["value"]
    return Graded(round(want), round(want), None if got is None else round(got))


def _terms_answer(op: Operator, cs: CaseFacts, path: str) -> Graded:
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.status", FAILED),
                    aggs={"by": {"type": "terms", "field": path, "size": 50}}))
    raw = Counter(_get(d.source, path) for d in cs.failed)
    return Graded(raw, Counter({op.label_of(k): v for k, v in raw.items()}),
                  Counter({b["key"]: b["doc_count"] for b in out["aggregations"]["by"]["buckets"]}))


def _servers(op: Operator, cs: CaseFacts) -> Graded:
    return _terms_answer(op, cs, "agent.name")


def _which_jobs(op: Operator, cs: CaseFacts) -> Graded:
    return _terms_answer(op, cs, "job.name")


def _failure_page(op: Operator) -> dict:
    return op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.status", FAILED), size=100))


def _error_text(op: Operator, cs: CaseFacts) -> Graded:
    out = _failure_page(op)
    raw = Counter(_get(d.source, "job.status_message") for d in cs.failed)
    read = Counter(op.project(_get(d.source, "job.status_message"), d.seeded) for d in cs.failed)
    return Graded(raw, read, Counter(_messages(out)))


def _top_template(cs: CaseFacts) -> int | None:
    return commonest([_get(d.source, "job.status_message") for d in cs.failed], cs.template)


def _top_phrase(op: Operator) -> str:
    """Read the tenant's failures and pick the error to chase: the
    commonest message shape, and the longest plain-word run in it."""
    msgs = _messages(_failure_page(op))
    if not msgs:
        raise Blocked("no_readable_phrase")
    top = commonest(msgs, shape)
    phrase = search_phrase(next(m for m in msgs if shape(m) == top))
    if phrase is None:
        raise Blocked("no_readable_phrase")
    return phrase


def _other_tenants(op: Operator, cs: CaseFacts) -> Graded:
    phrase = _top_phrase(op)
    out = op.ask(_q(_eq("job.status", FAILED),
                    {"field": "job.status_message", "op": "phrase", "value": phrase},
                    aggs={"tenants": {"type": "terms", "field": "labels.tenant_name",
                                      "size": 50}}))
    top = _top_template(cs)
    raw = sorted({_get(d.source, "labels.tenant_name") for d in cs.all_failed
                  if cs.template(_get(d.source, "job.status_message")) == top}
                 - {cs.tenant.name})
    got = sorted(b["key"] for b in out["aggregations"]["tenants"]["buckets"]
                 if b["key"] != op.tenant)
    return Graded(raw, sorted(op.label_of(n) for n in raw), got)


def _per_day(op: Operator, cs: CaseFacts) -> Graded:
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.status", FAILED),
                    aggs={"days": {"type": "date_histogram", "field": "@timestamp",
                                   "interval": "1d"}}))
    raw = Counter(d.source["@timestamp"][:10] for d in cs.failed)
    got = Counter({str(b.get("key_as_string", ""))[:10]: b["doc_count"]
                   for b in out["aggregations"]["days"]["buckets"] if b["doc_count"]})
    return Graded(raw, raw, got)


def _named_job(op: Operator, cs: CaseFacts) -> Graded:
    """The engineer knows the job by its name from the ticket. The case
    knows labels only, so the honest flow has a human step in it: the
    engineer seeds the name (es-seed, no session ended), reads the label
    back, and Claude asks with the label. The step is counted and shown as
    the engineer's, not hidden in the query."""
    label = op.human_seed(f"JOB_NAME={cs.job}", "from the ticket")
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.name", label),
                    _eq("job.status", FAILED),
                    aggs={"first": {"type": "min", "field": "@timestamp"}}),
                 gap="name_not_seeded", gap_codes=("literal_identifier", "known_value"))
    want = min(eseval._parse_time(d.source["@timestamp"]).timestamp() * 1000
               for d in cs.failed if _get(d.source, "job.name") == cs.job)
    got = out["aggregations"]["first"]["value"]
    return Graded(round(want), round(want), None if got is None else round(got))


def _error_census(op: Operator, cs: CaseFacts) -> Graded:
    out = op.ask(_q(_eq("job.status", FAILED),
                    aggs={"errors": {"type": "text_groups", "field": "job.status_message",
                                     "size": 10}}),
                 gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"))
    # The fixture's answer, by template: one group per template the
    # failures were drawn from, counted, keyed by one instance with its
    # planted values swapped for this case's labels and then masked. If two
    # messages of one template came back as two groups (a hidden value
    # splitting them), the counts would not match.
    # (and, since codes stay readable, by template and the codes in it: HTTP
    # 429 and 500 are two groups of one template)
    by_template: dict[tuple, list[eseval.Doc]] = {}
    for d in cs.all_failed:
        msg = _get(d.source, "job.status_message")
        by_template.setdefault((cs.template(msg), elastic.text_group_codes(msg)), []).append(d)
    expected: dict[str, int] = {}
    for docs in by_template.values():
        d = docs[0]
        key = elastic.text_group_key(op.project(_get(d.source, "job.status_message"), d.seeded))
        expected[key] = expected.get(key, 0) + len(docs)
    top = Counter(dict(sorted(expected.items(), key=lambda kv: (-kv[1], kv[0]))[:10]))
    return Graded(top, top, Counter({b["key"]: b["doc_count"]
                                     for b in out["aggregations"]["errors"]["buckets"]}))


def _wider(op: Operator, text_field: str = "job.status_message") -> dict:
    """The tenant's **wider scope**: the tenant field, or the name unmarked
    in the text - one any_of of the field eq the label and a phrase made
    only of the label on the text field. The phrase resolves in the bridge
    (the name never leaves it), costs nothing from the per-case budget (a
    label-only phrase is free) and one of the query's ``max_phrases``; a
    document matching both branches is one hit, never two."""
    return {"any_of": [_eq("labels.tenant_name", op.tenant),
                       {"field": text_field, "op": "phrase", "value": op.tenant}]}


def _split_q(op: Operator, *filters: dict, aggs: dict | None = None, size: int = 0,
             tr: dict | None = None) -> dict:
    q: dict[str, Any] = {"index": eseval.SPLIT_INDEX,
                         "time_range": tr or eseval.SPLIT_RANGE, "size": size,
                         "filters": [*filters, _eq("job.status", FAILED)]}
    if aggs:
        q["aggs"] = aggs
    return q


def _split_both(op: Operator, read: Callable[[dict], Any], expected: Callable[[], Any],
                aggs: dict | None = None) -> Graded:
    """Ask the question **today's way first** (tenant field alone), grade
    that against the full truth into the figures, then ask the wider scope
    and grade it: the row shows what the field scope missed beside the
    honest answer. ``expected`` is computed after the queries, when the
    labels the answer is read in exist."""
    narrow = read(op.ask(_split_q(op, _eq("labels.tenant_name", op.tenant), aggs=aggs)))
    wide = read(op.ask(_split_q(op, _wider(op), aggs=aggs)))
    raw, want = expected()
    fig = {"field_scope_against_full_truth": "answered" if narrow == want else "wrong",
           "field_scope_items": _items(narrow), "full_truth_items": _items(want)}
    return Graded(raw, want, wide, figures=fig)


def _text_onset(op: Operator, cs: Any) -> Graded:
    want = round(min(eseval._parse_time(d.source["@timestamp"]).timestamp() * 1000
                     for d in eseval.split_truth()))
    read = lambda out: (None if out["aggregations"]["first"]["value"] is None
                        else round(out["aggregations"]["first"]["value"]))
    return _split_both(op, read, lambda: (want, want),
                       aggs={"first": {"type": "min", "field": "@timestamp"}})


def _text_servers(op: Operator, cs: Any) -> Graded:
    read = lambda out: Counter({b["key"]: b["doc_count"]
                                for b in out["aggregations"]["by"]["buckets"]})
    raw = Counter(d.source["agent"]["name"] for d in eseval.split_truth())
    return _split_both(op, read,
                       lambda: (raw, Counter({op.label_of(k): v for k, v in raw.items()})),
                       aggs={"by": {"type": "terms", "field": "agent.name", "size": 50}})


def _text_per_day(op: Operator, cs: Any) -> Graded:
    want = Counter(d.source["@timestamp"][:10] for d in eseval.split_truth())
    read = lambda out: Counter({str(b.get("key_as_string", ""))[:10]: b["doc_count"]
                                for b in out["aggregations"]["d"]["buckets"] if b["doc_count"]})
    return _split_both(op, read, lambda: (want, want),
                       aggs={"d": {"type": "date_histogram", "field": "@timestamp",
                                   "interval": "1d"}})


def _text_error_census(op: Operator, cs: Any) -> Graded:
    def expected():
        want: Counter = Counter()
        for d in eseval.split_truth():
            want[elastic.text_group_key(op.project(
                d.source["job"]["status_message"], {eseval.SPLIT_TENANT: "ORG_NAME"}))] += 1
        return want, want
    read = lambda out: Counter({b["key"]: b["doc_count"]
                                for b in out["aggregations"]["g"]["buckets"]})
    return _split_both(op, read, expected,
                       aggs={"g": {"type": "text_groups", "field": "job.status_message",
                                   "size": 10}})


def _text_lookalike(op: Operator, cs: Any) -> Graded:
    """The declared miss of the wider scope, measured: a week's count pulls
    in one failure whose text uses the name's words in another sense (a
    route named after the same place). Scored wrong on purpose - nothing
    mechanical can tell the senses apart - with the overcount in the
    figures. A one-word tenant is this miss at its worst: its label
    resolves to a word every message may use in English."""
    out = op.ask(_split_q(op, _wider(op), tr=eseval.SPLIT_WIDE_RANGE))
    want = len(eseval.split_truth())
    got = out["hits"]["total"]["value"]
    return Graded(want, want, got,
                  figures={"counted": got, "about_the_tenant": want,
                           "same_words_another_sense": got - want})


def _text_two_fields(op: Operator, cs: Any) -> Graded:
    """A tenant known under two fields: the short name the case was seeded
    with, and a full name another component writes to a second field, in
    another spelling. The second spelling is its own value and its own
    label - the engineer seeds it (es-seed, a human step) and the wider
    scope carries each field with its own label. Asked with the first
    label alone first: the zero is explained by the bridge, not left bare."""
    plain = _split_q(op, _wider(op), tr=eseval.SPLIT_TWO_FIELD_RANGE)
    first = op.ask(plain)
    narrow = first["hits"]["total"]["value"]
    explained = first.get("empty") or {}
    full = op.human_seed(f"ORG_NAME={eseval.SPLIT_FULL_NAME}", "the full name from the ticket")
    both = {"any_of": [_eq("labels.tenant_name", op.tenant), _eq("labels.tenant_full_name", full),
                       {"field": "job.status_message", "op": "phrase", "value": op.tenant},
                       {"field": "job.status_message", "op": "phrase", "value": full}]}
    out = op.ask(_split_q(op, both, tr=eseval.SPLIT_TWO_FIELD_RANGE))
    want = sum(1 for d in eseval.split_docs()
               if d.source["job"]["status"] == FAILED
               and d.source.get("labels", {}).get("tenant_full_name") == eseval.SPLIT_FULL_NAME)
    return Graded(want, want, out["hits"]["total"]["value"],
                  figures={"one_field_scope": narrow, "both_fields": out["hits"]["total"]["value"],
                           "zero_explained": {f: x["status"] for f, x in
                                              (explained.get("fields") or {}).items()},
                           "check_requests": explained.get("requests")})


def _text_which_tenants(op: Operator, cs: Any) -> Graded:
    """Which tenants does the text-only error hit: the honest query runs
    and cannot answer - the terms aggregation buckets the tenant field,
    and the documents naming their tenant only in text are in no bucket."""
    out = op.ask(_split_q(op, {"field": "job.status_message", "op": "phrase",
                               "value": eseval.SPLIT_TEXT_PHRASE},
                          aggs={"t": {"type": "terms", "field": "labels.tenant_name",
                                      "size": 50}}))
    hits = out["hits"]["total"]["value"]
    buckets = out["aggregations"]["t"]["buckets"]
    if hits and len(buckets) < hits:
        raise Blocked("text_names_not_enumerable")
    return Graded(None, None, [b["key"] for b in buckets])


def _census(op: Operator, query: dict, spec: tuple[tuple[str, int], ...],
            tenant: str, agg_name: str = "errors") -> Graded:
    """A text_groups question graded on the order of the groups - what an
    engineer reads off to decide what to fix first - with the counts
    reported beside it: how far the reply said to trust itself, and whether
    it was right to. ``spec`` is (message template, true count) per group."""
    s0 = op.engine.simulated_seconds
    out = op.ask(query, gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"))
    truth: dict[str, int] = {}
    for template, n in spec:
        # one instance of the template with a tenant in it, as a page would
        # show it, then the group key
        key = elastic.text_group_key(op.project(
            template.replace("{TENANT}", tenant).replace("{N}", "7"), {tenant: "ORG_NAME"}))
        truth[key] = n
    expected = [k for k, _n in sorted(truth.items(), key=lambda kv: (-kv[1], kv[0]))]
    agg = out["aggregations"][agg_name]
    got = [b["key"] for b in agg["buckets"]]
    # how the reply said to trust itself, against the truth: counts only
    fig: dict[str, Any] = {"total": out["hits"]["total"]["value"], "sampled": agg.get("sampled"),
                           "exact": agg.get("exact"), "requests": op.requests,
                           "order_settled": agg.get("order_settled"),
                           "scan_seconds": round(op.engine.simulated_seconds - s0, 2)}
    for k in ("covered_share", "timeouts", "passes"):
        if agg.get(k) is not None:
            fig[k] = agg[k]
    errors, within = [], 0
    for b in agg["buckets"]:
        true = truth.get(b["key"], 0)
        errors.append(abs(b["doc_count"] - true) / true if true else 1.0)
        if abs(b["doc_count"] - true) <= b.get("margin", 0):
            within += 1
    fig.update(within_margin=within, groups=len(agg["buckets"]),
               max_error_pct=round(100 * max(errors), 1) if errors else None,
               missing=len(set(truth) - set(got)))
    return Graded(expected, expected, got, figures=fig)


def _week_census(op: Operator, cs: Any) -> Graded:
    """Which errors are commonest **this week**, over a scope wider than the
    group sample, whose commonest error is not among the newest documents
    (:func:`eseval.burst_docs`)."""
    return _census(op, {"index": eseval.BURST_INDEX, "time_range": eseval.BURST_RANGE, "size": 0,
                        "filters": [_eq("job.status", FAILED)],
                        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message",
                                            "size": 10}}},
                   ((eseval.BURST_STEADY_MESSAGE, eseval.BURST_STEADY),
                    (eseval.BURST_NOISY_MESSAGE, eseval.BURST_NOISY),
                    (eseval.BURST_RARE_MESSAGE, eseval.BURST_RARE)),
                   eseval.BURST_TENANTS[0])


def _slow_week_census(op: Operator, cs: Any) -> Graded:
    """The same week question on the measured cluster's wall-time shape
    (:func:`eseval.slow_world`): one sampling pass over the week cannot
    finish within the site's 300 s search limit, so the window is read in
    newest-first pieces, the timed-out widths remembered, and the reply
    says what part of the window its groups describe."""
    return _census(op, {"index": eseval.BURST_INDEX, "time_range": eseval.BURST_RANGE, "size": 0,
                        "filters": [_eq("job.status", FAILED)],
                        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message",
                                            "size": 10}}},
                   ((eseval.BURST_STEADY_MESSAGE, eseval.BURST_STEADY),
                    (eseval.BURST_NOISY_MESSAGE, eseval.BURST_NOISY),
                    (eseval.BURST_RARE_MESSAGE, eseval.BURST_RARE)),
                   eseval.BURST_TENANTS[0])


def _tenant_day_census(op: Operator, cs: Any) -> Graded:
    """Which errors hit the tenant **today**, when the whole day's failures
    sit in one half hour (:func:`eseval.dense_docs`): the scope is several
    times the group sample and lands in one slice of the day window, so a
    sample spread evenly over the window reads one slice's share of it."""
    return _census(op, {"index": eseval.DENSE_INDEX, "time_range": eseval.DENSE_RANGE, "size": 0,
                        "filters": [_eq("labels.tenant_name", op.tenant),
                                    _eq("job.status", FAILED)],
                        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message",
                                            "size": 10}}},
                   ((eseval.DENSE_STEADY_MESSAGE, eseval.DENSE_STEADY),
                    (eseval.DENSE_TAIL_MESSAGE, eseval.DENSE_TAIL),
                    (eseval.DENSE_RARE_MESSAGE, eseval.DENSE_RARE)),
                   eseval.DENSE_TENANT)


def _except_top_error(op: Operator, cs: CaseFacts) -> Graded:
    phrase = _top_phrase(op)
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), _eq("job.status", FAILED),
                    {"not": {"field": "job.status_message", "op": "phrase", "value": phrase}},
                    size=100),
                 gap="negation", gap_codes=("raw_dsl", "bad_filter"))
    top = _top_template(cs)
    rest = [d for d in cs.failed if cs.template(_get(d.source, "job.status_message")) != top]
    return Graded(Counter(_get(d.source, "job.status_message") for d in rest),
                  Counter(op.project(_get(d.source, "job.status_message"), d.seeded)
                          for d in rest),
                  Counter(_messages(out)))


def _any_failure_signal(op: Operator, cs: CaseFacts) -> Graded:
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant),
                    {"any_of": [_eq("job.status", FAILED), _eq("event.outcome", "failure"),
                                _eq("log.level", "error")]}),
                 gap="or_across_fields", gap_codes=("raw_dsl", "bad_filter"))
    want = sum(1 for d in cs.docs
               if _get(d.source, "job.status") == FAILED
               or _get(d.source, "event.outcome") == "failure"
               or _get(d.source, "log.level") == "error")
    return Graded(want, want, out["hits"]["total"]["value"])


def _tenant_size(op: Operator, cs: CaseFacts) -> Graded:
    out = op.ask(_q(_eq("labels.tenant_name", op.tenant), size=1))
    hits = out["hits"]["hits"]
    got = _get(hits[0]["_source"], "tenant.users_in_tenant") if hits else None
    return Graded(str(cs.tenant.users), str(cs.tenant.users),
                  None if got is None else str(got), needs_value=True)


QUESTIONS: tuple[Question, ...] = (
    Question("onset", "time point",
             "when did the failures start: lines the incident up against changes and the "
             "customer's report", _onset,
             honest="min @timestamp over the tenant's failed job runs"),
    Question("servers", "identifier set",
             "which servers ran the failing jobs: one bad worker, or everywhere", _servers,
             honest="terms agent.name over the tenant's failed runs"),
    Question("which_jobs", "identifier set",
             "which of the tenant's jobs fail: one job or the whole schedule", _which_jobs,
             honest="terms job.name over the tenant's failed runs"),
    Question("error_text", "free text",
             "what the error says: the thing every next step depends on", _error_text,
             honest="a page of the tenant's failed runs, job.status_message read off each"),
    Question("other_tenants", "cross-tenant",
             "do other tenants have the same error: a platform incident or one customer",
             _other_tenants,
             honest="read the tenant's failures, take the commonest error's longest plain "
                    "phrase, terms labels.tenant_name over every failed run carrying it"),
    Question("per_day", "time series",
             "how often per day: trend, and whether it is getting worse", _per_day,
             honest="date_histogram @timestamp 1d over the tenant's failed runs, last 7 days"),
    Question("named_job", "external name",
             "is it the job the customer named in the ticket, and since when", _named_job,
             gap="name_not_seeded", gap_codes=("literal_identifier", "known_value"),
             honest="the engineer seeds the job name from the ticket (es-seed), then job.name "
                    "eq its label, min @timestamp"),
    Question("error_census", "text grouping",
             "which errors are commonest across all failing jobs: what to fix first",
             _error_census, gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"),
             honest="text_groups on job.status_message over every failed run (it was terms "
                    "on the text field, which has no way to group by message)"),
    Question("text_onset", "time point",
             "when did the failures start, counting the ones named only in the text: the "
             "component that names the tenant in its message does not fill the tenant field",
             _text_onset, own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="min @timestamp over any_of(tenant field eq its label, text phrase of the "
                    "label) and status Failed - the wider scope"),
    Question("text_servers", "identifier set",
             "which servers ran the failing jobs, counting the text-only ones: the worst "
             "server fills no tenant field at all", _text_servers,
             own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="terms agent.name over the wider scope"),
    Question("text_per_day", "time series",
             "how often per day, counting the text-only failures", _text_per_day,
             own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="date_histogram 1d over the wider scope"),
    Question("text_error_census", "text grouping",
             "which errors hit the tenant, when the commonest is named only in the text",
             _text_error_census, own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="text_groups on job.status_message over the wider scope"),
    Question("text_lookalike", "magnitude",
             "how many of the tenant's runs failed this week, when another document uses the "
             "name's words in another sense: the declared miss of the wider scope, scored "
             "wrong on purpose", _text_lookalike,
             own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="count over the wider scope, a week back"),
    Question("text_two_fields", "magnitude",
             "how many of the tenant's runs failed, when another component writes the tenant "
             "under a second field in another spelling", _text_two_fields,
             own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="the engineer seeds the full name (es-seed), then any_of over each field "
                    "with its own label and a phrase of each"),
    Question("text_which_tenants", "cross-tenant",
             "which tenants does the text-only error hit, when they are named only in text",
             _text_which_tenants, gap="text_names_not_enumerable",
             own_data=eseval.split_world, own_seed=eseval.SPLIT_TENANT,
             honest="terms labels.tenant_name over the error's phrase: runs, and the "
                    "documents naming their tenant only in text are in no bucket"),
    Question("week_census", "text grouping",
             "which errors are commonest this week, over far more documents than one group "
             "read samples, when the last minute was noisy", _week_census,
             gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"),
             honest="text_groups on job.status_message over every failed run of the week",
             own_data=eseval.burst_world, own_seed=eseval.BURST_TENANTS[0]),
    Question("slow_week_census", "text grouping",
             "the same week question on the measured slow cluster, where one sampling pass "
             "over the week cannot finish within the site's 300 s search limit: the window "
             "is read in newest-first pieces and the reply says what it covers",
             _slow_week_census,
             gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"),
             honest="text_groups over the week, the window read in pieces when a sampling "
                    "pass hits the search limit",
             own_data=eseval.slow_world, own_seed=eseval.BURST_TENANTS[0]),
    Question("tenant_day_census", "text grouping",
             "which errors hit the tenant today, when the whole day's failures sit in one "
             "half hour: a sample spread evenly over the asked-about day lands one slice's "
             "share on them", _tenant_day_census,
             gap="text_aggregation", gap_codes=("field_not_queryable", "bad_agg"),
             honest="text_groups on job.status_message over the tenant's failed runs, last "
                    "24 hours",
             own_data=eseval.dense_world, own_seed=eseval.DENSE_TENANT),
    Question("except_top_error", "exclusion",
             "apart from the known error, what else is failing for the tenant",
             _except_top_error, gap="negation", gap_codes=("raw_dsl", "bad_filter"),
             honest="the tenant's failed runs NOT matching the commonest error's phrase"),
    Question("any_failure_signal", "union",
             "how many of the tenant's runs show any failure signal (status Failed, outcome "
             "failure or level error)", _any_failure_signal,
             gap="or_across_fields", gap_codes=("raw_dsl", "bad_filter"),
             honest="count of the tenant's runs with status Failed OR outcome failure OR "
                    "level error"),
    Question("tenant_size", "magnitude",
             "how many users the tenant has: throttling scales with tenant size", _tenant_size,
             gap="label_only",
             honest="read tenant.users_in_tenant off one of the tenant's documents"),
)


# ---------------------------------------------------------------------------
# Scoring and the run
# ---------------------------------------------------------------------------


def _items(x: Any) -> int | None:
    """How many distinct entries an answer has (servers, days, messages)."""
    if isinstance(x, (dict, list)):
        return len(x)
    return None if x is None else 1


def grade(op: Operator, g: Graded) -> tuple[str, str | None]:
    """(status, cause) for an answer the bridge returned."""
    if g.needs_value and op.is_label(g.got):
        return "blocked", "label_only"
    if g.got == g.expected_read:
        return "answered", None
    if op.unmask(g.got) == g.expected_raw:
        return "wrong", "redaction"
    return "wrong", "differs"


def run_utility_eval(cfg: elastic.ElasticConfig, fx: eseval.Fixture,
                     vocab: elastic.ClusterVocabulary, *, tier2: str = "none") -> dict:
    """Every question in :data:`QUESTIONS` as a fresh case on the real bridge.

    Its own stub engine (no simulated page cost), so the requests it makes
    move no other figure. Counts and codes only in what it returns.
    """
    facts = pick_case(fx)
    if facts is None:
        return {"case": False, "questions": []}
    cfg = dataclasses.replace(
        cfg, clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))
    engine = eseval.StubEngine(fx, cfg.indices)
    worlds: dict[Any, tuple] = {}
    rows = []
    for q in QUESTIONS:
        if q.own_data is not None:
            if q.own_data not in worlds:
                worlds[q.own_data] = q.own_data(tier2=tier2)
            own_cfg, _own_fx, own_engine, own_vocab = worlds[q.own_data]
            op = Operator(own_cfg, own_engine, own_vocab, q.own_seed, tier2=tier2)
        else:
            op = Operator(cfg, engine, vocab, facts.tenant.name, tier2=tier2)
        row: dict[str, Any] = {"key": q.key, "kind": q.kind, "refused": None, "cause": None,
                               "expected_items": None, "got_items": None, "figures": {}}
        try:
            g = q.run(op, facts)
            row["status"], row["cause"] = grade(op, g)
            row["expected_items"], row["got_items"] = _items(g.expected_raw), _items(g.got)
            row["figures"] = g.figures
        except Blocked as b:
            row["status"], row["cause"], row["refused"] = "blocked", b.cause, b.code
        finally:
            row["queries"], row["requests"] = op.queries, op.requests
            row["human_steps"] = list(op.human_steps)
            op.close()
        rows.append(row)
    by = Counter(r["status"] for r in rows)
    return {
        "case": True,
        "questions": rows,
        "counts": {s: by.get(s, 0) for s in STATUSES},
        "blocked_by": dict(Counter(r["cause"] for r in rows if r["status"] == "blocked")),
        "wrong_by": dict(Counter(r["cause"] for r in rows if r["status"] == "wrong")),
        "queries": sum(r["queries"] for r in rows),
        "requests": sum(r["requests"] for r in rows),
        "human_steps": sum(len(r["human_steps"]) for r in rows),
        "tier2": tier2,
    }


def _figures(f: dict[str, Any]) -> str:
    """The reply's own account of itself against the truth, counts only."""
    parts = []
    if "sampled" in f:
        parts.append(f"{f.get('sampled')} of {f.get('total')} docs read in {f.get('requests')} "
                     f"request{'s' if f.get('requests') != 1 else ''}, "
                     f"{'exact' if f.get('exact') else 'estimated'}"
                     + (f", {f['scan_seconds']}s simulated scan"
                        if f.get("scan_seconds") is not None else "")
                     + (f", covered {round(100 * f['covered_share'], 1)}% of the window in "
                        f"{f.get('passes')} passes, {f.get('timeouts')} of them hit the "
                        f"search limit"
                        if f.get("timeouts") else ""))
    if "groups" in f:
        parts.append(f"{f['groups']} groups, {f.get('missing')} of the true groups missing, "
                     f"{f.get('within_margin')} of {f['groups']} counts within the reply's margin, "
                     f"worst count off by {f.get('max_error_pct')}%, order settled for "
                     f"{f.get('order_settled')}")
    if "field_scope_against_full_truth" in f:
        parts.append(f"asked today's way (tenant field alone) first: "
                     f"{f['field_scope_against_full_truth']} against the full truth, "
                     f"{f.get('field_scope_items')} of {f.get('full_truth_items')} items")
    if "one_field_scope" in f:
        parts.append(f"asked with the first label alone: {f['one_field_scope']} hits, the zero "
                     f"explained by the bridge as {f.get('zero_explained')} in "
                     f"{f.get('check_requests')} check request(s); with both fields' labels "
                     f"{f['both_fields']}")
    if "same_words_another_sense" in f:
        parts.append(f"counted {f.get('counted')}, about the tenant {f.get('about_the_tenant')}, "
                     f"the name's words in another sense {f['same_words_another_sense']} "
                     "(the wider scope cannot tell the senses apart; declared)")
    return "; ".join(parts)


def format_lines(u: dict | None) -> list[str]:
    """The es-eval section: keys, statuses, causes, codes and counts."""
    if not u:
        return []
    head = "-- operator utility (scripted investigations, not a gate) --"
    if not u.get("case"):
        return [head, "utility           no case: the fixture has no tenant with a failing "
                      "Nightly job"]
    c = u["counts"]
    lines = [
        head,
        f"utility           {c['answered']}/{len(u['questions'])} answered, {c['wrong']} wrong, "
        f"{c['blocked']} blocked; each a fresh case seeded with one tenant only; "
        f"{u['queries']} queries, {u['requests']} reached Kibana, {u.get('human_steps', 0)} human "
        f"step(s) (tier2={u['tier2']})",
    ]
    for r in u["questions"]:
        detail = r["cause"] or ""
        if r["refused"] and r["refused"] != r["cause"]:
            detail = f"{r['cause']} (refused {r['refused']})"
        elif r["refused"]:
            detail = f"refused {r['refused']}"
        if r["got_items"] is not None:
            detail = (detail + "; " if detail else "") + \
                f"{r['got_items']} of {r['expected_items']} items"
        if r.get("human_steps"):
            detail = (detail + "; " if detail else "") + \
                f"{len(r['human_steps'])} human step: {', '.join(r['human_steps'])}"
        lines.append(f"  {r['key']:<19}{r['status']:<9}{r['kind']:<15}{detail}")
        if r.get("figures"):
            lines.append("  " + " " * 19 + _figures(r["figures"]))
    if u["blocked_by"]:
        lines.append("  blocked by      " + ", ".join(f"{k} {v}" for k, v in
                                                     sorted(u["blocked_by"].items())))
    if u["wrong_by"]:
        lines.append("  wrong by        " + ", ".join(f"{k} {v}" for k, v in
                                                     sorted(u["wrong_by"].items())))
    return lines
