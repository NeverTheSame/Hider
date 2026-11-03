"""The closed query grammar and its compiler to a Kibana async-search body.

Claude never writes Query DSL. It fills a small structured request, and this
module either compiles it to the ``{"params": {"index", "body"}}`` document
that ``POST /internal/search/ese`` takes, or raises :class:`elastic.Refused`
with a stable code. Everything that is not in the grammar is refused,
including any key the grammar does not name, which is what keeps raw DSL
out.

Why a closed grammar rather than a filtered DSL: hit counts leak values
without a value ever crossing. A wildcard on a tenant field recovers the
name a letter at a time, a range on an identifier does a binary search, a
sort by identifier reveals alphabetical order between labels, and a terms
aggregation with an ``include`` regex does all of that for a whole index.
Each of those is an :data:`ORACLE_CASES` entry, and each must be refused.

On the way out, two substitutions and one gate:

* An identifier field is filtered by *label*: ``<Org-01>`` is resolved to
  the real value from the session, and only if the label's type fits the
  field. A literal on an identifier field is refused whatever it is.
* A phrase on a text field may contain labels of any type; they are
  resolved so Claude can search ``message`` for the tenant it knows only as
  a label. The rest of the phrase is then checked: a known value, or
  anything tier 1 or the site shapes recognise, is refused. Every text
  query is counted and logged (the phrase as Claude wrote it, with labels,
  never the resolved one): confirming a guessed plain word by its hit count
  is an accepted and declared channel.
* Literals on ``keep`` fields pass the same gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import elastic, jsonscrub, pipeline

MAX_PHRASE_CHARS = 256
MAX_LITERAL_CHARS = 128
MAX_IN_VALUES = 50
MAX_FROM = 1000
MAX_AGG_DEPTH = 3
MAX_TOP_HITS = 10

_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: ISO-8601 timestamps (date or date-time, optional fraction and zone) or
#: Elasticsearch date math anchored on ``now``. Nothing else is a time.
_TIME = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"|now(?:[+-]\d{1,4}[smhdwMy])?(?:/[smhdwMy])?)$"
)
_INTERVAL = re.compile(r"^(?:\d{1,4}(?:ms|s|m|h|d)|1[wMqy]|minute|hour|day|week|month|quarter|year)$")
_FILTER_OPS = {"eq", "in", "exists", "range", "phrase"}
_RANGE_KEYS = {"gte", "gt", "lte", "lt"}
_METRICS = {"min", "max", "avg", "sum", "value_count", "percentiles"}
_AGG_TYPES = _METRICS | {"terms", "date_histogram", "cardinality", "top_hits", "filters"}
_QUERY_KEYS = {"index", "time_range", "filters", "size", "from", "sort", "aggs"}
_LABEL_WORD = re.compile(r"<[A-Za-z][A-Za-z_]*-\d+>")

_GUID_FAMILY = {"GUID", "SESSION_GUID", "TENANT_ID", "OBJECT_GUID", "DOC_ID"}


@dataclass
class Compiled:
    """The request to send and what the scrubber needs to read the answer."""

    body: dict
    plan: elastic.Plan
    #: text phrases as Claude wrote them (labels, not values), for the log
    text_queries: list[str] = field(default_factory=list)
    labels_used: list[str] = field(default_factory=list)


class _Compiler:
    def __init__(self, config: elastic.ElasticConfig, session: elastic.EsScrubber) -> None:
        self.cfg = config
        self.session = session
        self.text_queries: list[str] = []
        self.labels_used: list[str] = []
        self._tier1 = pipeline.RegexTier()
        self._label_rx = None

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def refuse(code: str, message: str) -> elastic.Refused:
        return elastic.Refused(code, message)

    def rule(self, name: Any, *, what: str) -> elastic.FieldRule:
        if not isinstance(name, str) or not elastic._FIELD_RE.match(name) or "*" in name:
            raise self.refuse("unknown_field", f"{what}: field name is not usable")
        r = self.cfg.rule(name)
        if r is None:
            raise self.refuse("unknown_field", f"{what}: field is not in the site map")
        return r

    def _labels_in(self, text: str) -> list[str]:
        """Every label the session knows that appears in ``text``, longest first."""
        if self._label_rx is None:
            labels = sorted(self.session.mapping, key=len, reverse=True)
            if not labels:
                return []
            self._label_rx = re.compile(
                r"(?<![A-Za-z0-9])(?:" + "|".join(map(re.escape, labels)) + r")(?![A-Za-z0-9])")
        return [m.group(0) for m in self._label_rx.finditer(text)]

    def _resolve_text(self, text: str) -> str:
        """Labels -> values inside a phrase; the remainder must be clean."""
        out, pos = [], 0
        rx = None
        labels = self._labels_in(text)
        if labels:
            rx = self._label_rx
        remainder = []
        for m in (rx.finditer(text) if rx else ()):
            out.append(text[pos:m.start()])
            remainder.append(text[pos:m.start()])
            val = self.session.resolve_label(m.group(0))
            assert val is not None
            out.append(val[0])
            self.labels_used.append(m.group(0))
            pos = m.end()
        out.append(text[pos:])
        remainder.append(text[pos:])
        rest = " ".join(remainder)
        if _LABEL_WORD.search(rest):
            raise self.refuse("unknown_label", "a label in the phrase is not one this case "
                                               "has issued")
        self._gate_literal(rest, what="phrase")
        return "".join(out)

    def _gate_literal(self, text: str, *, what: str) -> None:
        """Refuse a literal Claude should not possess: a mapped value or a
        value shaped like an identifier."""
        if not text.strip():
            return
        if self.session._find_known(text):
            raise self.refuse("known_value", f"{what}: contains a value this case has "
                                             "already pseudonymised; use its label")
        for rule, rx in self.session._shape_rx:
            if rx.search(text):
                raise self.refuse("shaped_literal", f"{what}: contains a {rule.type} value; "
                                                    "use its label")
        spans = self._tier1.detect(text, [(0, len(text))])
        if spans:
            raise self.refuse("shaped_literal", f"{what}: contains a {spans[0].entity_type} "
                                                "value; use its label")

    def _scalar(self, v: Any, *, what: str) -> Any:
        if isinstance(v, bool) or v is None:
            raise self.refuse("bad_value", f"{what}: value must be a string or a number")
        if isinstance(v, (int, float)):
            return v
        if not isinstance(v, str) or not v.strip():
            raise self.refuse("bad_value", f"{what}: value must be a non-empty string or a number")
        if len(v) > MAX_LITERAL_CHARS:
            raise self.refuse("bad_value", f"{what}: value is too long")
        return v

    def _label_value(self, rule: elastic.FieldRule, v: Any, *, what: str) -> Any:
        """A filter value on an identifier field: a label of a fitting type."""
        if not isinstance(v, str):
            raise self.refuse("literal_identifier", f"{what}: identifier fields take labels, "
                                                    "not literals")
        hit = self.session.resolve_label(v.strip())
        if hit is None:
            if _LABEL_WORD.fullmatch(v.strip()) or self._looks_like_label(v.strip()):
                raise self.refuse("unknown_label", f"{what}: that label was not issued in this case")
            raise self.refuse("literal_identifier", f"{what}: identifier fields take labels, "
                                                    "not literals")
        value, vtype = hit
        if not _types_compatible(rule.type, vtype):
            raise self.refuse("label_type_mismatch", f"{what}: that label is a {vtype}, the "
                                                     f"field holds {rule.type}")
        self.labels_used.append(v.strip())
        return value

    @staticmethod
    def _looks_like_label(v: str) -> bool:
        return bool(jsonscrub._LABEL_RE.fullmatch(v)) or bool(re.fullmatch(r"[\w.-]*-s\d+", v))

    # -- filters -----------------------------------------------------------

    def filters(self, raw: Any, *, what: str) -> list[dict]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise self.refuse("bad_filter", f"{what}: filters must be a list")
        return [self.one_filter(f, what=f"{what}[{i}]") for i, f in enumerate(raw)]

    def one_filter(self, f: Any, *, what: str) -> dict:
        if not isinstance(f, dict):
            raise self.refuse("bad_filter", f"{what}: a filter is an object")
        unknown = set(f) - {"field", "op", "value"}
        if unknown:
            raise self.refuse("raw_dsl", f"{what}: unknown filter keys {sorted(unknown)}")
        op = f.get("op")
        if op not in _FILTER_OPS:
            raise self.refuse("bad_filter", f"{what}: op must be one of {sorted(_FILTER_OPS)}")
        rule = self.rule(f.get("field"), what=what)
        name = f["field"]
        if op == "exists":
            if "value" in f:
                raise self.refuse("bad_filter", f"{what}: exists takes no value")
            return {"exists": {"field": name}}
        if op == "phrase":
            if rule.kind != "text":
                raise self.refuse("field_not_queryable", f"{what}: phrase applies to text fields")
            v = f.get("value")
            if not isinstance(v, str) or not v.strip():
                raise self.refuse("bad_value", f"{what}: phrase must be a non-empty string")
            if len(v) > MAX_PHRASE_CHARS:
                raise self.refuse("bad_value", f"{what}: phrase is too long")
            if any(c in v for c in "*?"):
                raise self.refuse("pattern_query", f"{what}: wildcards are not allowed")
            resolved = self._resolve_text(v)
            self.text_queries.append(v)
            return {"match_phrase": {name: resolved}}
        if rule.kind == "text":
            raise self.refuse("field_not_queryable", f"{what}: text fields take phrase only")
        if op == "range":
            if rule.kind == "identifier":
                raise self.refuse("range_identifier", f"{what}: range on an identifier field")
            v = f.get("value")
            if not isinstance(v, dict) or not v or set(v) - _RANGE_KEYS:
                raise self.refuse("bad_filter", f"{what}: range takes gte/gt/lte/lt")
            bounds = {}
            for k, b in v.items():
                b = self._scalar(b, what=what)
                if isinstance(b, str):
                    if name == self.cfg.time_field or _TIME.match(b):
                        if not _TIME.match(b):
                            raise self.refuse("bad_value", f"{what}: not a timestamp")
                    else:
                        self._gate_literal(b, what=what)
                bounds[k] = b
            return {"range": {name: bounds}}
        values = f.get("value") if op == "in" else [f.get("value")]
        if op == "in" and (not isinstance(values, list) or not values):
            raise self.refuse("bad_filter", f"{what}: in takes a non-empty list")
        if len(values) > MAX_IN_VALUES:
            raise self.refuse("bad_filter", f"{what}: too many values")
        out = []
        for v in values:
            if rule.kind == "identifier":
                out.append(self._label_value(rule, v, what=what))
            else:
                v = self._scalar(v, what=what)
                if isinstance(v, str):
                    if any(c in v for c in "*?"):
                        raise self.refuse("pattern_query", f"{what}: wildcards are not allowed")
                    self._gate_literal(v, what=what)
                out.append(v)
        if op == "eq":
            return {"term": {name: out[0]}}
        return {"terms": {name: out}}

    def time_range(self, raw: Any) -> dict | None:
        if raw is None:
            return None
        if not isinstance(raw, dict) or not raw or set(raw) - _RANGE_KEYS:
            raise self.refuse("bad_filter", "time_range takes gte/gt/lte/lt")
        bounds = {}
        for k, v in raw.items():
            if not isinstance(v, str) or not _TIME.match(v):
                raise self.refuse("bad_value", f"time_range.{k}: not a timestamp or date math")
            bounds[k] = v
        return {"range": {self.cfg.time_field: bounds}}

    # -- sort, aggs --------------------------------------------------------

    def sort(self, raw: Any) -> list[dict]:
        if raw is None:
            return [{self.cfg.time_field: {"order": "desc"}}]
        if not isinstance(raw, list) or not raw:
            raise self.refuse("bad_sort", "sort must be a non-empty list")
        out = []
        for s in raw:
            if not isinstance(s, dict) or set(s) - {"field", "order"}:
                raise self.refuse("bad_sort", "a sort entry is {field, order}")
            rule = self.rule(s.get("field"), what="sort")
            if rule.kind != "keep":
                raise self.refuse("sort_identifier" if rule.kind == "identifier" else "bad_sort",
                                  "sort is allowed on keep fields only")
            order = s.get("order", "desc")
            if order not in ("asc", "desc"):
                raise self.refuse("bad_sort", "order is asc or desc")
            out.append({s["field"]: {"order": order}})
        return out

    def aggs(self, raw: Any, depth: int = 0, *, what: str = "aggs") -> tuple[dict, dict[str, elastic.AggPlan]]:
        if raw is None:
            return {}, {}
        if not isinstance(raw, dict):
            raise self.refuse("bad_agg", f"{what}: aggs is an object of name -> agg")
        if depth >= MAX_AGG_DEPTH:
            raise self.refuse("bad_agg", f"{what}: aggregations nest too deep")
        body, plans = {}, {}
        for name, spec in raw.items():
            if not isinstance(name, str) or not _NAME.match(name):
                raise self.refuse("bad_agg", f"{what}: aggregation names are short lowercase words")
            body[name], plans[name] = self.one_agg(spec, depth, what=f"{what}.{name}")
        return body, plans

    def one_agg(self, spec: Any, depth: int, *, what: str) -> tuple[dict, elastic.AggPlan]:
        if not isinstance(spec, dict):
            raise self.refuse("bad_agg", f"{what}: an aggregation is an object")
        atype = spec.get("type")
        if atype not in _AGG_TYPES:
            raise self.refuse("bad_agg", f"{what}: type must be one of {sorted(_AGG_TYPES)}")
        allowed = {"type", "aggs"}
        allowed |= {
            "terms": {"field", "size"}, "date_histogram": {"field", "interval"},
            "cardinality": {"field"}, "top_hits": {"size", "sort"}, "filters": {"filters"},
        }.get(atype, {"field", "percents"} if atype == "percentiles" else {"field"})
        unknown = set(spec) - allowed
        if unknown:
            raise self.refuse("raw_dsl", f"{what}: unknown keys {sorted(unknown)}")
        sub_body, sub_plans = self.aggs(spec.get("aggs"), depth + 1, what=what)
        body: dict[str, Any]
        if atype == "top_hits":
            size = spec.get("size", 1)
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_TOP_HITS:
                raise self.refuse("size_cap", f"{what}: top_hits size is 1..{MAX_TOP_HITS}")
            body = {"top_hits": {"size": size, "sort": self.sort(spec.get("sort")),
                                 "_source": {"includes": self.cfg.source_includes()}}}
            if sub_body:
                raise self.refuse("bad_agg", f"{what}: top_hits takes no sub-aggregations")
            return body, elastic.AggPlan("top_hits")
        if atype == "filters":
            named = spec.get("filters")
            if not isinstance(named, dict) or not named or len(named) > self.cfg.max_buckets:
                raise self.refuse("bad_agg", f"{what}: filters is an object of name -> filter list")
            compiled = {}
            for fname, flist in named.items():
                if not isinstance(fname, str) or not _NAME.match(fname):
                    raise self.refuse("bad_agg", f"{what}: filter names are short lowercase words")
                fs = self.filters(flist, what=f"{what}.{fname}")
                if not fs:
                    raise self.refuse("bad_agg", f"{what}.{fname}: a filter list is non-empty")
                compiled[fname] = {"bool": {"filter": fs}}
            body = {"filters": {"filters": compiled}}
            if sub_body:
                body["aggs"] = sub_body
            return body, elastic.AggPlan("filters", subs=sub_plans, names=tuple(compiled))
        rule = self.rule(spec.get("field"), what=what)
        fname = spec["field"]
        if rule.kind == "text":
            raise self.refuse("field_not_queryable", f"{what}: text fields cannot be aggregated")
        if atype == "terms":
            if rule.kind == "identifier" and rule.type in {"DOC_ID"}:
                raise self.refuse("bad_agg", f"{what}: that field cannot be aggregated")
            size = spec.get("size", 10)
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= self.cfg.max_buckets:
                raise self.refuse("size_cap", f"{what}: terms size is 1..{self.cfg.max_buckets}")
            # order is fixed to doc count: ordering by key would expose the
            # alphabetical order of real values behind the labels
            body = {"terms": {"field": fname, "size": size, "order": {"_count": "desc"}}}
        elif atype == "date_histogram":
            if rule.kind != "keep":
                raise self.refuse("range_identifier", f"{what}: histogram on an identifier field")
            interval = spec.get("interval", "1h")
            if not isinstance(interval, str) or not _INTERVAL.match(interval):
                raise self.refuse("bad_agg", f"{what}: interval like 5m, 1h, 1d, week")
            key = "calendar_interval" if interval in {"1w", "1M", "1q", "1y", "minute", "hour",
                                                        "day", "week", "month", "quarter",
                                                        "year"} else "fixed_interval"
            body = {"date_histogram": {"field": fname, key: interval, "min_doc_count": 0}}
        elif atype == "cardinality":
            body = {"cardinality": {"field": fname}}
            sub_body = {}
        else:  # min, max, avg, sum, value_count, percentiles
            if rule.kind != "keep":
                raise self.refuse("range_identifier", f"{what}: {atype} on an identifier field "
                                                      "exposes its value")
            body = {atype: {"field": fname}}
            if atype == "percentiles":
                pct = spec.get("percents", [50, 95, 99])
                if not isinstance(pct, list) or not pct or not all(
                        isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 100
                        for p in pct):
                    raise self.refuse("bad_agg", f"{what}: percents is a list of 0..100")
                body["percentiles"]["percents"] = pct
            sub_body = {}
        if sub_body:
            if atype not in {"terms", "date_histogram"}:
                raise self.refuse("bad_agg", f"{what}: only bucket aggregations nest")
            body["aggs"] = sub_body
        return body, elastic.AggPlan(atype, fname, rule, sub_plans if sub_body else {})

    # -- the whole request -------------------------------------------------

    def compile(self, q: Any) -> Compiled:
        if not isinstance(q, dict):
            raise self.refuse("bad_query", "a query is an object")
        unknown = set(q) - _QUERY_KEYS
        if unknown:
            raise self.refuse("raw_dsl", f"unknown query keys {sorted(unknown)}; the grammar is "
                                         f"{sorted(_QUERY_KEYS)}")
        index = q.get("index")
        if not isinstance(index, str) or index not in self.cfg.indices:
            raise self.refuse("bad_index", "index must be one of the configured patterns")
        size = q.get("size", 10)
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= self.cfg.max_hits:
            raise self.refuse("size_cap", f"size is 0..{self.cfg.max_hits}")
        frm = q.get("from", 0)
        if isinstance(frm, bool) or not isinstance(frm, int) or not 0 <= frm <= MAX_FROM:
            raise self.refuse("size_cap", f"from is 0..{MAX_FROM}")
        filters = self.filters(q.get("filters"), what="filters")
        tr = self.time_range(q.get("time_range"))
        if tr:
            filters.insert(0, tr)
        sort = self.sort(q.get("sort")) if size else []
        agg_body, agg_plans = self.aggs(q.get("aggs"))
        body: dict[str, Any] = {
            "size": size,
            "track_total_hits": True,
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "_source": {"includes": self.cfg.source_includes()},
        }
        if frm:
            body["from"] = frm
        if sort:
            body["sort"] = sort
        if agg_body:
            body["aggs"] = agg_body
        plan = elastic.Plan(index, agg_plans, size)
        return Compiled({"params": {"index": index, "body": body}}, plan,
                        list(self.text_queries), list(self.labels_used))


def _types_compatible(field_type: str, label_type: str) -> bool:
    if field_type == label_type:
        return True
    return field_type in _GUID_FAMILY and label_type in _GUID_FAMILY


def compile_query(q: Any, config: elastic.ElasticConfig, session: elastic.EsScrubber) -> Compiled:
    """Grammar in, async-search body out, or :class:`elastic.Refused`."""
    return _Compiler(config, session).compile(q)


# ---------------------------------------------------------------------------
# Adversarial query cases: each is a shape that must be refused
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OracleCase:
    name: str
    why: str
    query: dict
    #: the refusal code expected; the case fails if the query compiles or a
    #: different rule catches it (a different rule is still a refusal, but a
    #: changed reason is a changed design and should be looked at)
    code: str


_IDX = "logs-app-*"
_SERVER = "agent.name"
_TENANT = "labels.tenant_name"
_TENANT_ID = "labels.tenant_id"

#: Written against ``templates/elastic.example.json``. A test compiles every
#: one with a session that has issued ``<Org-01>`` (ORG_NAME),
#: ``ctr-amer-s01`` (SERVER_NAME) and ``<Tenant-01>`` (TENANT_ID).
ORACLE_CASES: tuple[OracleCase, ...] = (
    OracleCase("raw-dsl-query", "a raw query clause bypasses every rule below",
               {"index": _IDX, "query": {"wildcard": {_TENANT: "c*"}}}, "raw_dsl"),
    OracleCase("raw-dsl-in-filter", "DSL smuggled through a filter object",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "<Org-01>",
                                            "boost": 2}]}, "raw_dsl"),
    OracleCase("script-fields", "scripts concatenate and transform values past the scrubber",
               {"index": _IDX, "script_fields": {"x": {"script": "doc['labels.tenant_name']"}}},
               "raw_dsl"),
    OracleCase("runtime-mappings", "a runtime field is a script by another name",
               {"index": _IDX, "runtime_mappings": {"x": {"type": "keyword"}}}, "raw_dsl"),
    OracleCase("highlight", "highlight fragments split values across the label boundary",
               {"index": _IDX, "highlight": {"fields": {"message": {}}}}, "raw_dsl"),
    OracleCase("source-override", "widening _source past the allowlist",
               {"index": _IDX, "_source": True}, "raw_dsl"),
    OracleCase("wildcard-literal-in-eq", "a wildcard on a keep field is still a pattern probe",
               {"index": _IDX, "filters": [{"field": "data_stream.dataset", "op": "eq",
                                            "value": "app.*"}]}, "pattern_query"),
    OracleCase("wildcard-in-phrase", "a wildcard inside a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "tenant con*"}]}, "pattern_query"),
    OracleCase("literal-on-identifier", "a real-looking literal on an identifier field: Claude "
               "should only hold labels",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "Contoso"}]},
               "literal_identifier"),
    OracleCase("prefix-probe-via-literal", "the letter-by-letter oracle, first step",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "C"}]},
               "literal_identifier"),
    OracleCase("range-on-identifier", "a range on an identifier is a binary search over its value",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "range",
                                            "value": {"gte": "A", "lt": "M"}}]},
               "range_identifier"),
    OracleCase("range-on-numeric-identifier", "the same, over a numeric identifier",
               {"index": _IDX, "filters": [{"field": "tenant.users_in_tenant", "op": "range",
                                            "value": {"gte": 1000}}]}, "range_identifier"),
    OracleCase("sort-by-identifier", "sorting by an identifier reveals the order of real values",
               {"index": _IDX, "sort": [{"field": _TENANT, "order": "asc"}]}, "sort_identifier"),
    OracleCase("unknown-label", "a label this case never issued: a guess, not a reference",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "<Org-77>"}]},
               "unknown_label"),
    OracleCase("label-of-wrong-type", "a tenant GUID label used to filter the tenant name",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "<Tenant-01>"}]},
               "label_type_mismatch"),
    OracleCase("server-label-on-tenant-field", "a server label used on an organisation field",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq", "value": "ctr-amer-s01"}]},
               "label_type_mismatch"),
    OracleCase("known-value-in-phrase", "the real value behind an issued label, typed into a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "Contoso Holdings failed"}]}, "known_value"),
    OracleCase("shaped-literal-in-phrase", "a GUID typed into a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "job 9b1e4d7a-2c3f-4a5b-8e6d-0f1a2b3c4d5e"}]},
               "shaped_literal"),
    OracleCase("server-literal-in-phrase", "a real server name typed into a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "restarting ctr-emea-017"}]}, "shaped_literal"),
    OracleCase("email-literal-on-keep", "an email typed as a literal on a keep field",
               {"index": _IDX, "filters": [{"field": "data_stream.dataset", "op": "eq",
                                            "value": "anna.novak@litware.com"}]}, "shaped_literal"),
    OracleCase("unlisted-field", "a field the site map does not list",
               {"index": _IDX, "filters": [{"field": "user.password", "op": "exists"}]},
               "unknown_field"),
    OracleCase("field-glob", "a glob in a field name",
               {"index": _IDX, "filters": [{"field": "labels.*", "op": "exists"}]}, "unknown_field"),
    OracleCase("unlisted-index", "an index outside the allowlist",
               {"index": ".kibana_security_session*", "size": 1}, "bad_index"),
    OracleCase("terms-on-text", "aggregating a text field returns its words as bucket keys",
               {"index": _IDX, "size": 0, "aggs": {"m": {"type": "terms", "field": "message"}}},
               "field_not_queryable"),
    OracleCase("terms-include-regex", "a terms include regex is the oracle over a whole index",
               {"index": _IDX, "size": 0, "aggs": {"t": {"type": "terms", "field": _TENANT,
                                                         "include": "c.*"}}}, "raw_dsl"),
    OracleCase("terms-order-by-key", "ordering buckets by key reveals the order of real values",
               {"index": _IDX, "size": 0, "aggs": {"t": {"type": "terms", "field": _TENANT,
                                                         "order": {"_key": "asc"}}}}, "raw_dsl"),
    OracleCase("min-on-identifier", "min of an identifier field is its smallest real value",
               {"index": _IDX, "size": 0, "aggs": {"m": {"type": "min",
                                                         "field": "tenant.users_in_tenant"}}},
               "range_identifier"),
    OracleCase("histogram-on-identifier", "a histogram over a numeric identifier is a range probe",
               {"index": _IDX, "size": 0, "aggs": {"h": {"type": "date_histogram",
                                                         "field": "tenant.users_in_tenant"}}},
               "range_identifier"),
    OracleCase("terms-on-doc-id", "document ids as bucket keys enumerate the index",
               {"index": _IDX, "size": 0, "aggs": {"d": {"type": "terms", "field": "_id"}}},
               "unknown_field"),
    OracleCase("scripted-metric", "a scripted metric runs arbitrary code over the values",
               {"index": _IDX, "size": 0, "aggs": {"s": {"type": "scripted_metric",
                                                         "map_script": "x"}}}, "bad_agg"),
    OracleCase("top-hits-wide", "a top_hits larger than the cap",
               {"index": _IDX, "size": 0, "aggs": {"t": {"type": "terms", "field": _SERVER,
                                                         "aggs": {"l": {"type": "top_hits",
                                                                        "size": 500}}}}},
               "size_cap"),
    OracleCase("size-over-cap", "a page larger than the cap",
               {"index": _IDX, "size": 10000}, "size_cap"),
    OracleCase("filters-agg-with-literal", "a filters aggregation smuggling an identifier literal",
               {"index": _IDX, "size": 0, "aggs": {"f": {"type": "filters", "filters": {
                   "a": [{"field": _TENANT, "op": "eq", "value": "Fabrikam"}]}}}},
               "literal_identifier"),
    OracleCase("time-range-not-a-time", "a time bound that is not a timestamp (injection vector)",
               {"index": _IDX, "time_range": {"gte": "Contoso"}}, "bad_value"),
    OracleCase("tenant-id-literal", "a GUID literal on the tenant id field",
               {"index": _IDX, "filters": [{"field": _TENANT_ID, "op": "in",
                                            "value": ["3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10"]}]},
               "literal_identifier"),
)
