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

Two compound filters, in a query's ``filters`` only: ``{"not": filter}``
(compiled to ``must_not``) and ``{"any_of": [filter, ...]}`` (``should``,
``minimum_should_match`` 1). Each holds plain filters, one level deep, and
each inner filter goes through :meth:`_Compiler.one_filter` with the outer
position's name, so every rule above applies inside them and a refusal
inside is the refusal outside, word for word. Their phrases count toward
the per-query cap and the per-case budget like any other.

One aggregation that is not Elasticsearch's: ``text_groups`` on a text
field, the commonest redacted messages in scope with their counts. It
compiles to a read of a page's worth of documents spread over the scope's
time span, grouped by the scrubber after redaction (see
:class:`GroupRead` and :meth:`_Compiler.text_groups`).
"""

from __future__ import annotations

import calendar
import math
import re
import time
import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

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
_AGG_TYPES = _METRICS | {"terms", "date_histogram", "cardinality", "top_hits", "filters",
                         "text_groups"}
#: what a text_groups key puts where a value was: never a label, so typed
#: into a phrase it is refused rather than searched for as a word
_GROUP_PLACEHOLDER = re.compile(r"<\*>|<[A-Za-z_]+>")
_QUERY_KEYS = {"index", "time_range", "filters", "size", "from", "sort", "aggs"}
_LABEL_WORD = re.compile(r"<[A-Za-z][A-Za-z_]*-\d+>")

_GUID_FAMILY = {"GUID", "SESSION_GUID", "TENANT_ID", "OBJECT_GUID", "DOC_ID"}

# -- the histogram pre-flight ------------------------------------------------
#
# A date_histogram's bucket count follows from the window and the interval,
# both known before the query is sent, so a histogram that would overrun
# ``max_buckets`` is refused here instead of being run and then withheld by
# the scrubber (which keeps its own cap as the backstop). Both bounds are
# resolved the way Elasticsearch resolves them and the buckets between them
# counted exactly. That count is the most the reply can hold: Elasticsearch
# fills empty buckets only between the first and last matching document, so
# sparse data gives fewer. Everything is UTC because the compiled range sets
# no time_zone, and fixed intervals are aligned to the epoch.
#
# ``now`` is Kibana's clock, which this machine can only approximate:
#
# * no bound on ``now``: exact, no clock involved;
# * one side on ``now`` and the other an ISO date: that side is resolved at
#   this clock plus or minus CLOCK_SKEW_S, whichever widens the window, so
#   the count is a true upper bound;
# * both sides on ``now``: one clock reading for both, as Kibana uses one.
#   The anchor cancels (now-7d..now at 1h is 169 buckets at any hour); a
#   window that is not whole intervals can gain one bucket if Kibana's clock
#   sits across a bucket edge from this one, and the scrubber catches that.

#: Widening applied to the ``now`` side of a mixed ISO/``now`` window.
CLOCK_SKEW_S = 300.0
_DAY = 86400
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MATH = re.compile(r"^now(?:([+-])(\d{1,4})([smhdwMy]))?(?:/([smhdwMy]))?$")
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?"
                  r"(Z|[+-]\d{2}:?\d{2})?)?$")
_FIXED_UNIT_S = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": _DAY}
_CALENDAR_S = {"minute": 60, "hour": 3600, "day": _DAY, "1w": 7 * _DAY, "week": 7 * _DAY,
               "1M": 28 * _DAY, "month": 28 * _DAY, "1q": 90 * _DAY, "quarter": 90 * _DAY,
               "1y": 365 * _DAY, "year": 365 * _DAY}
#: what a refusal suggests instead, smallest first; every one is grammar-valid
_SUGGESTED_INTERVALS = ("1m", "5m", "10m", "15m", "30m", "1h", "2h", "3h", "4h", "6h", "12h",
                        "1d", "1w", "month", "quarter", "year")


def _utc(t: float) -> datetime:
    return _EPOCH + timedelta(seconds=t)


def _secs(d: datetime) -> float:
    return (d - _EPOCH).total_seconds()


def _shift(d: datetime, n: int, unit: str) -> datetime:
    """Date-math ``+n unit``; months and years clamp the day like Java's plusMonths."""
    if unit in "smhdw":
        return d + timedelta(seconds=n * {"s": 1, "m": 60, "h": 3600, "d": _DAY, "w": 7 * _DAY}[unit])
    months = d.year * 12 + d.month - 1 + (n * 12 if unit == "y" else n)
    y, m = divmod(months, 12)
    return d.replace(year=y, month=m + 1, day=min(d.day, calendar.monthrange(y, m + 1)[1]))


def _floor(d: datetime, unit: str) -> datetime:
    d = d.replace(microsecond=0)
    if unit == "s":
        return d
    d = d.replace(second=0)
    if unit == "m":
        return d
    d = d.replace(minute=0)
    if unit == "h":
        return d
    d = d.replace(hour=0)
    if unit == "w":
        return d - timedelta(days=d.weekday())  # weeks start on Monday
    if unit == "M":
        return d.replace(day=1)
    if unit == "y":
        return d.replace(month=1, day=1)
    return d


def _resolve(v: str, *, round_up: bool, now: float) -> float:
    """The instant Elasticsearch reads a range bound as, in epoch seconds.

    ``gt`` and ``lte`` round up (``now/d`` is the last millisecond of today,
    a bare date the last millisecond of that day), ``gte`` and ``lt`` round
    down. Raises ValueError or OverflowError for a date that cannot exist.
    """
    m = _MATH.match(v)
    if m:
        d = _utc(now)
        if m.group(1):
            d = _shift(d, int(m.group(2)) * (1 if m.group(1) == "+" else -1), m.group(3))
        if not m.group(4):
            return _secs(d)
        lo = _floor(d, m.group(4))
        return _secs(_shift(lo, 1, m.group(4))) - 0.001 if round_up else _secs(lo)
    m = _ISO.match(v)
    if m is None:
        raise ValueError(v)
    y, mo, d, hh, mi, ss, frac, zone = m.groups()
    t = _secs(datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0),
                       tzinfo=timezone.utc))
    t += float("0." + frac) if frac else 0.0
    if zone and zone != "Z":
        offset = int(zone[1:3]) * 3600 + int(zone[-2:]) * 60
        t -= offset if zone[0] == "+" else -offset
    unit = _DAY if hh is None else 60 if ss is None else 1 if frac is None else 0
    return t + unit - 0.001 if round_up and unit else t


def _interval_seconds(interval: str) -> float:
    """The shortest bucket an interval makes."""
    if interval in _CALENDAR_S:
        return float(_CALENDAR_S[interval])
    m = re.fullmatch(r"(\d+)(ms|s|m|h|d)", interval)
    return int(m.group(1)) * _FIXED_UNIT_S[m.group(2)]


def _bucket_index(t: float, interval: str) -> int:
    d = _utc(t)
    if interval in ("1M", "month"):
        return d.year * 12 + d.month - 1
    if interval in ("1q", "quarter"):
        return d.year * 4 + (d.month - 1) // 3
    if interval in ("1y", "year"):
        return d.year
    if interval in ("1w", "week"):
        return math.floor((t - 4 * _DAY) / (7 * _DAY))  # 1970-01-05 was a Monday
    return math.floor(t / _interval_seconds(interval))


def _bucket_count(start: float, end: float, interval: str) -> int:
    return 0 if end < start else _bucket_index(end, interval) - _bucket_index(start, interval) + 1


def _fmt_span(seconds: float) -> str:
    s = int(round(seconds / 60.0)) * 60
    if s <= 0:
        return f"{max(seconds, 0):g}s"
    parts = []
    for unit, size in (("d", _DAY), ("h", 3600), ("m", 60)):
        if s >= size:
            parts.append(f"{s // size}{unit}")
            s %= size
    return " ".join(parts[:2])


@dataclass
class Compiled:
    """The request to send and what the scrubber needs to read the answer."""

    body: dict
    plan: elastic.Plan
    #: text phrases as Claude wrote them (labels, not values), for the log
    text_queries: list[str] = field(default_factory=list)
    labels_used: list[str] = field(default_factory=list)
    #: plain-word (field, phrase key) pairs this query would add to the
    #: case's spent set; the caller spends them just before sending
    new_phrases: frozenset = frozenset()
    #: set for a text_groups query: the read is several requests, and
    #: ``body``/``plan`` are its first (see :func:`read_text_groups`)
    group_read: "GroupRead | None" = None


@dataclass(frozen=True)
class GroupRead:
    """How a ``text_groups`` query is read: two to four requests, each a
    page's worth of documents at most, built here and run by
    :func:`read_text_groups`.

    1. **count** (closed time range) or **bounds** (no closed range): how
       many documents the scope holds, counted up to
       :data:`elastic.TEXT_GROUP_SLOW_DOCS` - early-terminated, so it is
       cheap either way - and, for bounds, the scope's first and last
       timestamp (``min``/``max``, no documents). A scope at or past the
       bound is refused ``slow_read`` here, before the sampling pass that
       would mostly die at the session's completion ceiling anyway.
    2. **exact** - the whole scope as one page of
       :data:`elastic.TEXT_GROUP_SAMPLE` hits, when the count says it fits.
    3. **strata** - otherwise: the scope's span cut into at most ``strata``
       equal slices, the newest ``per_stratum`` documents of each, in one
       request: the sample is spread over the time the engineer asked
       about instead of being the newest moment of it.
    4. **respread** - only when the strata pass landed materially less than
       the sample (documents concentrated in a few slices): the same sample
       re-spread over where the first pass counted the documents, one
       ``filter`` range per slice sized to the slice's share, a slice owed
       more than ``per_cap`` cut into equal sub-ranges of at most
       ``per_cap`` each. The asked sizes sum to at most the sample.
    """

    index: str
    query: dict
    includes: list[str]
    time_field: str
    groups: elastic.GroupPlan
    #: the query's closed time range, epoch seconds, or None
    window: tuple[float, float] | None
    strata: int
    per_stratum: int
    #: most documents one time range may carry: Elasticsearch's default
    #: inner result window, and never more than the site's page
    per_cap: int = elastic.TEXT_GROUP_MAX_PER_STRATUM

    def _request(self, body: dict) -> dict:
        return {"params": {"index": self.index, "body": body}}

    def count(self) -> tuple[dict, elastic.Plan]:
        """How many documents the scope holds, counted up to the slow
        bound: Elasticsearch stops collecting at the cap, so a scope wide
        enough to refuse answers without paying for a full count."""
        body = {"size": 0, "track_total_hits": elastic.TEXT_GROUP_SLOW_DOCS,
                "query": self.query}
        return self._request(body), elastic.Plan(self.index, {}, 0)

    def bounds(self) -> tuple[dict, elastic.Plan]:
        tf = self.time_field
        body = {"size": 0, "track_total_hits": elastic.TEXT_GROUP_SLOW_DOCS, "query": self.query,
                "aggs": {"first": {"min": {"field": tf}}, "last": {"max": {"field": tf}}}}
        plan = elastic.Plan(self.index, {"first": elastic.AggPlan("min", tf),
                                         "last": elastic.AggPlan("max", tf)}, 0)
        return self._request(body), plan

    def interval_s(self, lo: float, hi: float) -> int:
        """Seconds per slice: the span over ``strata - 2``, so the slices,
        aligned to the epoch as Elasticsearch aligns them, number at most
        ``strata`` even when the range sits across a boundary."""
        return max(1, math.ceil(max(hi - lo, 0.0) / max(self.strata - 2, 1)))

    def strata_read(self, lo: float, hi: float) -> tuple[dict, elastic.Plan]:
        tf = self.time_field
        body = {
            "size": 0, "track_total_hits": True, "query": self.query,
            "aggs": {elastic.STRATA_AGG: {
                "date_histogram": {"field": tf, "fixed_interval": f"{self.interval_s(lo, hi)}s",
                                   "min_doc_count": 1},
                "aggs": {elastic.STRATA_HITS_AGG: {"top_hits": {
                    "size": self.per_stratum, "sort": [{tf: {"order": "desc"}}],
                    "_source": {"includes": self.includes}}}}}},
        }
        plan = elastic.Plan(
            self.index,
            {elastic.STRATA_AGG: elastic.AggPlan(
                "date_histogram", tf, None, {elastic.STRATA_HITS_AGG: elastic.AggPlan("top_hits")})},
            0, dataclasses.replace(self.groups, phase="strata", strata=self.strata,
                                   per_stratum=self.per_stratum))
        return self._request(body), plan

    def respread(self, slices: list[tuple[int, int]],
                 interval_ms: int) -> tuple[dict, elastic.Plan]:
        """The second sampling pass: one sibling ``filter`` aggregation per
        time range, each with its own newest-first ``top_hits``, the sizes
        the allocation over the first pass's per-slice document counts
        (``slices``: one ``(slice start in epoch ms, documents to read)``
        per non-empty slice). A slice owed more than ``per_cap`` is cut
        into equal sub-ranges of at most ``per_cap`` each; the asked sizes
        sum to at most the sample, so this request never carries more than
        one page's worth. Each range's own ``doc_count`` comes back with
        it, which is what keeps the estimate honest for sub-ranges the
        documents do not fill evenly."""
        tf = self.time_field
        aggs: dict[str, Any] = {}
        plans: dict[str, elastic.AggPlan] = {}
        ranges: list[tuple[str, int]] = []
        for key, owed in slices:
            parts = max(1, math.ceil(owed / self.per_cap))
            bounds = [key + round(j * interval_ms / parts) for j in range(parts)]
            bounds.append(key + interval_ms)
            for j in range(parts):
                name = f"s{len(ranges):02d}"
                size = owed // parts + (1 if j < owed % parts else 0)
                ranges.append((name, size))
                aggs[name] = {
                    "filter": {"range": {tf: {"gte": bounds[j], "lt": bounds[j + 1]}}},
                    "aggs": {elastic.STRATA_HITS_AGG: {"top_hits": {
                        "size": size, "sort": [{tf: {"order": "desc"}}],
                        "_source": {"includes": self.includes}}}}}
                plans[name] = elastic.AggPlan(
                    "filter", tf, None, {elastic.STRATA_HITS_AGG: elastic.AggPlan("top_hits")})
        body = {"size": 0, "track_total_hits": True, "query": self.query, "aggs": aggs}
        plan = elastic.Plan(self.index, plans, 0,
                            dataclasses.replace(self.groups, phase="respread",
                                                ranges=tuple(ranges)))
        return self._request(body), plan

    def exact(self) -> tuple[dict, elastic.Plan]:
        body = {"size": elastic.TEXT_GROUP_SAMPLE, "track_total_hits": True, "query": self.query,
                "_source": {"includes": self.includes},
                "sort": [{self.time_field: {"order": "desc"}}]}
        plan = elastic.Plan(self.index, {}, elastic.TEXT_GROUP_SAMPLE,
                            dataclasses.replace(self.groups, phase="exact"))
        return self._request(body), plan

    def first(self) -> tuple[dict, elastic.Plan]:
        """The read's first request: a capped count when the span is known,
        else bounds (which carry the same capped count)."""
        if self.window is not None:
            return self.count()
        return self.bounds()


def _allocate(counts: list[int], sample: int) -> list[int]:
    """How many documents to read from each slice: every slice up to a fair
    share - the largest ``fair`` with ``sum(min(count, fair)) <= sample`` -
    so a slice smaller than the share is read whole and the budget it does
    not need goes to the slices that do; the remainder goes one each to the
    widest slices, oldest first on a tie. Deterministic, and built only
    from the first pass's document counts: nothing typed in a query reaches
    it."""
    lo, hi = 0, sample
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if sum(min(n, mid) for n in counts) <= sample:
            lo = mid
        else:
            hi = mid - 1
    alloc = [min(n, lo) for n in counts]
    left = sample - sum(alloc)
    for i in sorted(range(len(counts)), key=lambda i: (-counts[i], i)):
        if left <= 0:
            break
        if counts[i] > alloc[i]:
            alloc[i] += 1
            left -= 1
    return alloc


def _group_total(out: dict) -> tuple[Any, str]:
    total = (out.get("hits") or {}).get("total") or {}
    return total.get("value"), total.get("relation", "eq")


def _refuse_slow() -> elastic.Refused:
    about = int(elastic.TEXT_GROUP_SLOW_DOCS / 1_000_000 * elastic.TEXT_GROUP_SCAN_S_PER_MDOC)
    return elastic.Refused(
        "slow_read",
        f"text_groups: the scope holds at least {elastic.TEXT_GROUP_SLOW_DOCS:,} documents, "
        f"and spreading the sample over it makes Elasticsearch bucket every one - about "
        f"{about}s or more, past what the session waits for one search. Narrow the time "
        f"range or add filters; a terms or date_histogram aggregation over the same scope "
        f"is cheap and shows where the documents are.")


def read_text_groups(search: Callable[[dict], Any], scrubber: elastic.EsScrubber,
                     read: GroupRead) -> tuple[elastic.Scrubbed, int]:
    """Run a ``text_groups`` read: ``search`` takes a request document and
    returns the raw envelope; every reply goes through the scrubber with
    the plan of its own request. Returns the groups and how many requests
    were made; the groups carry the count too.

    The order (see :class:`GroupRead`): the capped count (or bounds), then
    - a scope past :data:`elastic.TEXT_GROUP_SLOW_DOCS` refused
    ``slow_read`` - the whole scope as one exact page when it fits the
    sample, else the strata pass, and a second pass re-spreading the sample
    over where the documents are when the first left more than a quarter of
    it unused (:data:`elastic.TEXT_GROUP_RESPREAD_MIN`)."""
    n = 0
    lo_hi = read.window

    def empty(out: dict) -> tuple[elastic.Scrubbed, int]:
        # nothing in scope: no groups, the total as the reply gave it
        agg = elastic.group_estimate([], read.groups.size, _group_total(out)[0])
        agg["sample_cap"] = elastic.TEXT_GROUP_SAMPLE
        agg["requests"] = n
        return elastic.Scrubbed({"hits": {"total": out["hits"]["total"], "hits": []},
                                 "aggregations": {read.groups.name: agg}}, {"hits": 0}), n

    if lo_hi is None:
        body, plan = read.bounds()
        n += 1
        out = scrubber.scrub_response(search(body), plan).output
        total, relation = _group_total(out)
        if relation != "eq" or (isinstance(total, int) and total >= elastic.TEXT_GROUP_SLOW_DOCS):
            raise _refuse_slow()
        first = (out.get("aggregations") or {}).get("first", {}).get("value")
        last = (out.get("aggregations") or {}).get("last", {}).get("value")
        if not isinstance(first, (int, float)) or not isinstance(last, (int, float)):
            return empty(out)
        lo_hi = (float(first) / 1000.0, float(last) / 1000.0)
    else:
        body, plan = read.count()
        n += 1
        out = scrubber.scrub_response(search(body), plan).output
        total, relation = _group_total(out)
        if relation != "eq" or (isinstance(total, int) and total >= elastic.TEXT_GROUP_SLOW_DOCS):
            raise _refuse_slow()
        if total == 0:
            return empty(out)
    if isinstance(total, int) and total <= elastic.TEXT_GROUP_SAMPLE:
        # the scope fits one page: read it whole rather than estimate what
        # is all there
        body, plan = read.exact()
        n += 1
        scrubbed = scrubber.scrub_response(search(body), plan)
        agg = scrubbed.output["aggregations"][read.groups.name]
        agg["requests"] = n
        return scrubbed, n
    body, plan = read.strata_read(*lo_hi)
    n += 1
    scrubbed = scrubber.scrub_response(search(body), plan)
    agg = scrubbed.output["aggregations"][read.groups.name]
    slices = agg.pop("_slices", [])
    if not agg["exact"] and slices and all(isinstance(k, int) for k, _c in slices):
        # re-spread: the same sample sized to where the first pass counted
        # the documents, only when it reads materially more than the first
        # landed (elastic.TEXT_GROUP_RESPREAD_MIN)
        alloc = _allocate([c for _k, c in slices], elastic.TEXT_GROUP_SAMPLE)
        if sum(alloc) > agg["sampled"] * elastic.TEXT_GROUP_RESPREAD_MIN:
            body, plan = read.respread(
                [(k, a) for (k, _c), a in zip(slices, alloc) if a > 0],
                read.interval_s(*lo_hi) * 1000)
            n += 1
            scrubbed = scrubber.scrub_response(search(body), plan)
            agg = scrubbed.output["aggregations"][read.groups.name]
    agg.pop("_slices", None)
    agg["requests"] = n
    return scrubbed, n


class _Compiler:
    def __init__(self, config: elastic.ElasticConfig, session: elastic.EsScrubber, *,
                 now: float | None = None) -> None:
        self.cfg = config
        self.session = session
        self.now = time.time() if now is None else now
        #: (widest window in seconds, whether our clock was needed), or None
        #: when time_range lacks a start or an end
        self.window: tuple[float, bool] | None = None
        self.text_queries: list[str] = []
        #: distinct (field, phrase) pairs, for the per-query phrase cap
        self.phrases: set[tuple[str, str]] = set()
        #: the subset that carry plain words (not only labels): what the
        #: per-case budget charges
        self.plain_phrases: set[tuple[str, str]] = set()
        self.labels_used: list[str] = []
        self._tier1 = pipeline.RegexTier()
        self._label_rx = None

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def refuse(code: str, message: str, *, label: str | None = None) -> elastic.Refused:
        return elastic.Refused(code, message, label=label)

    def rule(self, name: Any, *, what: str) -> elastic.FieldRule:
        if not isinstance(name, str) or not elastic._FIELD_RE.match(name) or "*" in name:
            raise self.refuse("unknown_field", f"{what}: field name is not usable"
                              + self._closest(name))
        r = self.cfg.rule(name)
        if r is None:
            raise self.refuse("unknown_field", f"{what}: field is not in the site map"
                              + self._closest(name))
        return r

    def _closest(self, name: Any) -> str:
        hit = self.cfg.closest_field(name[:128]) if isinstance(name, str) else None
        return f"; closest site-map field: {hit}" if hit else "; see the site map's field list"

    def _labels_in(self, text: str) -> list[str]:
        """Every label the case has been **shown** that appears in ``text``,
        longest first.

        Shown, not merely issued: a guessed label inside a phrase has to
        fall through to the remainder, where it is refused like any other
        label the case does not have.
        """
        if self._label_rx is None:
            labels = sorted(self.session.shown, key=len, reverse=True)
            if not labels:
                return []
            # Cached on the session, not on this compiler: a cluster
            # vocabulary makes this alternation tens of thousands of
            # branches, and compiling it once per query cost more than
            # everything else a query does (measured on the realistic
            # estate: 0.6s a query at 42,000 labels). The cache is keyed by
            # how many labels the session has issued, so a label issued
            # since the last compile rebuilds it.
            cached = getattr(self.session, "_shown_alternation", None)
            if cached is not None and cached[0] == len(labels):
                self._label_rx = cached[1]
            else:
                self._label_rx = re.compile(
                    r"(?<![A-Za-z0-9])(?:" + "|".join(map(re.escape, labels))
                    + r")(?![A-Za-z0-9])")
                try:
                    self.session._shown_alternation = (len(labels), self._label_rx)
                except AttributeError:
                    pass
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
            val = self.session.shown_label(m.group(0))
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

    def _gate_literal(self, text: str, *, what: str, keep: bool = False) -> None:
        """Refuse a literal Claude should not possess: a mapped value or a
        value shaped like an identifier.

        ``keep`` marks an ``eq``/``in`` literal on a keep field. A keep value
        is shown as written even when a learnt name sits inside it (an index
        named after a job), so such a literal is accepted **only when this
        case has been shown that exact keep value** on a page
        (:meth:`elastic.EsScrubber.keep_literal_shown`). Everything else is
        refused with the same code and the same words - a refusal must not
        tell a guess from a value never shown.
        """
        if not text.strip():
            return
        if self.session._find_known(text) and not (
                keep and self.session.keep_literal_shown(text)):
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
        # shown_label, not resolve_label: a label the case has not been
        # shown is treated exactly as one that was never issued, so the
        # refusal below cannot tell a live guess from a dead one
        hit = self.session.shown_label(v.strip())
        if hit is None:
            if _LABEL_WORD.fullmatch(v.strip()) or self._looks_like_label(v.strip()):
                raise self.refuse("unknown_label", f"{what}: that label was not issued in this case",
                                  label=v.strip())
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

    def filters(self, raw: Any, *, what: str, compound: bool = False) -> list[dict]:
        """``compound``: the query's own filters, where ``not`` and
        ``any_of`` are allowed; everywhere else (a filters aggregation's
        buckets) they are refused."""
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise self.refuse("bad_filter", f"{what}: filters must be a list")
        return [self.one_filter(f, what=f"{what}[{i}]", compound=compound)
                for i, f in enumerate(raw)]

    def compound_filter(self, f: dict, *, what: str, allowed: bool) -> dict:
        """``{"not": filter}`` or ``{"any_of": [filter, ...]}``.

        Every filter inside is compiled by :meth:`one_filter` **with the
        outer position's ``what``**, so a refusal inside one is the refusal
        the same filter gets on its own at that position, word for word,
        and every rule - labels, shown labels, keep literals, the phrase cap
        and the per-case budget (both count through ``self.phrases``) - is
        the same code path. One level deep and in the query's filters only:
        nothing nests, and a filters aggregation's bucket takes plain
        filters.
        """
        key = "not" if "not" in f else "any_of"
        unknown = set(f) - {key}
        if unknown:
            raise self.refuse("raw_dsl", f"{what}: unknown filter keys {sorted(unknown)}")
        if not allowed:
            raise self.refuse("bad_filter", f"{what}: not and any_of hold plain filters and "
                                            "apply to the query's filters only (not nested, not "
                                            "inside an aggregation)")
        inner = f[key]
        if key == "not":
            if not isinstance(inner, dict):
                raise self.refuse("bad_filter", f"{what}: not takes one filter")
            return {"bool": {"must_not": [self.one_filter(inner, what=what)]}}
        if not isinstance(inner, list) or not inner:
            raise self.refuse("bad_filter", f"{what}: any_of takes a non-empty list of filters")
        if len(inner) > MAX_IN_VALUES:
            raise self.refuse("bad_filter", f"{what}: too many filters in any_of")
        return {"bool": {"should": [self.one_filter(x, what=what) for x in inner],
                         "minimum_should_match": 1}}

    def one_filter(self, f: Any, *, what: str, compound: bool = False) -> dict:
        if not isinstance(f, dict):
            raise self.refuse("bad_filter", f"{what}: a filter is an object")
        if "not" in f or "any_of" in f:
            return self.compound_filter(f, what=what, allowed=compound)
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
            if _GROUP_PLACEHOLDER.search(v):
                raise self.refuse("bad_value", f"{what}: <*> (and <Org>, <n> and the like) "
                                               "is a group placeholder standing for any value; "
                                               "search the words around it")
            if any(c in v for c in "*?"):
                raise self.refuse("pattern_query", f"{what}: wildcards are not allowed")
            resolved = self._resolve_text(v)
            self.text_queries.append(v)
            self.phrases.add((name, _phrase_key(v)))
            if _LABEL_SHAPES.sub(" ", v).strip():
                self.plain_phrases.add((name, _phrase_key(v)))
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
                    self._gate_literal(v, what=what, keep=rule.kind == "keep")
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
        on_now = {k: v.startswith("now") for k, v in bounds.items()}
        mixed = len(set(on_now.values())) > 1
        starts, ends = [], []
        for k, v in bounds.items():
            is_start = k in ("gte", "gt")
            at = self.now + (0.0 if not (mixed and on_now[k]) else
                             -CLOCK_SKEW_S if is_start else CLOCK_SKEW_S)
            try:
                t = _resolve(v, round_up=k in ("gt", "lte"), now=at)
            except (ValueError, OverflowError):
                raise self.refuse("bad_value", f"time_range.{k}: not a calendar date") from None
            (starts if is_start else ends).append(t)
        if starts and ends:
            # every bound applies, so the window is the tightest pair
            self.window = (max(starts), min(ends), mixed)
        return {"range": {self.cfg.time_field: bounds}}

    def check_phrases(self) -> None:
        """At most ``max_phrases`` distinct phrases per query, counting the
        filters and every aggregation at any depth (all of them come through
        ``one_filter``). Distinct per field: a phrase repeated across buckets
        is one guess however many counts it appears in, and that is also
        what keeps the zero-hit check, which reuses a query's own filters,
        inside the cap of the query it checks. The message has the numbers,
        never the phrases."""
        n, cap = len(self.phrases), self.cfg.max_phrases
        if n > cap:
            uses = len(self.text_queries)
            raise self.refuse("size_cap", (
                f"the query has {n} distinct phrases"
                + (f" ({uses} uses)" if uses != n else "")
                + f" across its filters and aggregations; the cap is {cap} per query"))

    def check_budget(self) -> frozenset:
        """The per-case ``phrase_budget``: distinct plain-word phrases over
        all the case's queries. Run last, so a query refused for any other
        reason spends nothing. Depends only on how many phrases are new to
        the case and how many it has spent - never on what a phrase would
        match - and the message carries the numbers, never a phrase."""
        spent = self.session.phrases_spent
        new = frozenset(self.plain_phrases - spent)
        budget = self.cfg.phrase_budget
        if budget and new and len(spent) + len(new) > budget:
            raise self.refuse("phrase_budget", (
                f"this case has used {len(spent)} of its {budget} distinct text phrases and "
                f"the query adds {len(new)} new ones; phrases already used, and phrases "
                f"made only of labels, cost nothing"))
        return new

    def check_histogram(self, fname: str, interval: str, *, what: str) -> None:
        """Refuse a histogram whose bucket count can overrun the cap, before
        it is sent. One that cannot be bounded is refused too: it is exactly
        the query that would run on the cluster and then be withheld."""
        step = _interval_seconds(interval)
        if step <= 0:
            raise self.refuse("bad_agg", f"{what}: interval must be longer than zero")
        tf = self.cfg.time_field
        if fname != tf:
            raise self.refuse("unbounded_histogram", f"{what}: time_range bounds {tf} only, so "
                                                     f"a histogram on {fname} has no bucket limit; "
                                                     f"histogram {tf} instead")
        if self.window is None:
            raise self.refuse("unbounded_histogram", f"{what}: a histogram needs time_range with a "
                                                     "start (gte/gt) and an end (lte/lt); without "
                                                     "both its bucket count cannot be checked "
                                                     "before the query runs")
        start, end, clock = self.window
        cap = self.cfg.max_buckets
        n = _bucket_count(start, end, interval)
        if n <= cap:
            return
        fits = next(((iv, k) for iv in _SUGGESTED_INTERVALS
                     for k in [_bucket_count(start, end, iv)] if k <= cap), None)
        hint = (f"{fits[0]} fits ({fits[1]} buckets)" if fits
                else "no interval in the grammar fits")
        # a window of (cap - 1) intervals fits at any alignment
        raise self.refuse("size_cap", (
            f"{what}: {interval} over a window of {_fmt_span(end - start)} gives {n} buckets, "
            f"the cap is {cap}; {hint}, or keep {interval} with a window of at most "
            f"{_fmt_span((cap - 1) * step)}"
            + (" (window measured against this machine's clock)" if clock else "")))

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
        if atype == "text_groups":
            # the query-level path (text_groups) handles it; reaching here
            # means it is nested or beside another aggregation
            raise self.refuse("bad_agg", f"{what}: text_groups is a query's only aggregation, "
                                         "at the top level")
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
            self.check_histogram(fname, interval, what=what)
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

    def text_groups(self, raw: dict, q: dict) -> elastic.GroupPlan:
        """``{"type": "text_groups", "field": <text field>, "size": n}``.

        The commonest redacted texts of a text field in the query's scope,
        each with its count. Not an Elasticsearch aggregation: the read
        (:class:`GroupRead`) samples at most :data:`elastic.TEXT_GROUP_SAMPLE`
        documents per request, spread over the scope's time span, the
        scrubber redacts them as one page and groups the result
        (:meth:`elastic.EsScrubber._text_groups`). So it is the only
        aggregation in its query, at the top level, with no hits, offset or
        order of its own, and no sub-aggregations; and nothing in the spec
        shapes the read - no sample size, slice count or width, no "exact"
        and no "newest" - because the per-request read is the cap that
        keeps a group read no wider than paging.
        """
        if len(raw) != 1:
            raise self.refuse("bad_agg", "aggs: text_groups is a query's only aggregation, at "
                                         "the top level")
        (name, spec), = raw.items()
        what = f"aggs.{name}"
        if not isinstance(name, str) or not _NAME.match(name):
            raise self.refuse("bad_agg", "aggs: aggregation names are short lowercase words")
        if q.get("size", 10) != 0:
            raise self.refuse("bad_agg", f"{what}: text_groups returns groups, not hits; size 0")
        if q.get("from") or "sort" in q:
            raise self.refuse("bad_agg", f"{what}: text_groups samples the documents in scope "
                                         "over its time span; no from or sort")
        unknown = set(spec) - {"type", "field", "size", "aggs"}
        if unknown:
            raise self.refuse("raw_dsl", f"{what}: unknown keys {sorted(unknown)}")
        if "aggs" in spec:
            raise self.refuse("bad_agg", f"{what}: text_groups takes no sub-aggregations")
        rule = self.rule(spec.get("field"), what=what)
        if rule.kind != "text":
            raise self.refuse("field_not_queryable", f"{what}: text_groups applies to text "
                                                     "fields")
        n = spec.get("size", 10)
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= self.cfg.max_buckets:
            raise self.refuse("size_cap", f"{what}: text_groups size is 1..{self.cfg.max_buckets}")
        return elastic.GroupPlan(name, spec["field"], n)

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
        filters = self.filters(q.get("filters"), what="filters", compound=True)
        tr = self.time_range(q.get("time_range"))
        if tr:
            filters.insert(0, tr)
        raw_aggs = q.get("aggs")
        groups = None
        if isinstance(raw_aggs, dict) and any(isinstance(v, dict) and v.get("type") == "text_groups"
                                              for v in raw_aggs.values()):
            groups = self.text_groups(raw_aggs, q)
            self.check_phrases()
            new_phrases = self.check_budget()
            # the read: a page's worth of documents per request, spread over
            # the scope's time span, each scrubbed exactly as it would be on
            # a page (see GroupRead)
            strata = min(elastic.TEXT_GROUP_STRATA, self.cfg.max_buckets)
            per_stratum = min(elastic.TEXT_GROUP_SAMPLE // strata, elastic.TEXT_GROUP_MAX_PER_STRATUM,
                              self.cfg.max_hits)
            read = GroupRead(index, {"bool": {"filter": filters}} if filters else {"match_all": {}},
                             self.cfg.source_includes(), self.cfg.time_field, groups,
                             (self.window[0], self.window[1]) if self.window else None,
                             strata, per_stratum,
                             min(elastic.TEXT_GROUP_MAX_PER_STRATUM, self.cfg.max_hits))
            body, plan = read.first()
            return Compiled(body, plan, list(self.text_queries), list(self.labels_used),
                            new_phrases, read)
        sort = self.sort(q.get("sort")) if size else []
        agg_body, agg_plans = self.aggs(raw_aggs)
        self.check_phrases()
        new_phrases = self.check_budget()
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
        plan = elastic.Plan(index, agg_plans, size, groups)
        return Compiled({"params": {"index": index, "body": body}}, plan,
                        list(self.text_queries), list(self.labels_used), new_phrases)


_LABEL_SHAPES = elastic.EsScrubber._LABEL_SHAPES


def _phrase_key(v: str) -> str:
    """Spellings that differ only in case or spacing are one phrase: the text
    analyzer reads them alike, so the second confirms nothing new. Other
    variants count separately, which errs toward the cap."""
    return " ".join(v.casefold().split())


def _types_compatible(field_type: str, label_type: str) -> bool:
    if field_type == label_type:
        return True
    return field_type in _GUID_FAMILY and label_type in _GUID_FAMILY


def compile_query(q: Any, config: elastic.ElasticConfig, session: elastic.EsScrubber, *,
                  now: float | None = None) -> Compiled:
    """Grammar in, async-search body out, or :class:`elastic.Refused`.

    ``now`` (epoch seconds, default this machine's clock) is used only to
    bound a histogram window that mixes an ISO date with ``now``.
    """
    return _Compiler(config, session, now=now).compile(q)


# ---------------------------------------------------------------------------
# Adversarial query cases: each is a shape that must be refused
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShownKeepCase:
    """A keep literal that is refused until the case has been shown the
    keep value it carries, and accepted after. ``shown`` is the page value
    (field path and value) that has to come back first; ``code`` is the
    refusal before it does."""

    name: str
    why: str
    query: dict
    shown: tuple[str, str]
    code: str


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

#: A one-word name the oracle session has **learnt** - from a page or the
#: vocabulary, not seeded, and never shown inside a keep value. It is the
#: first of ``eseval.DEFAULT_MAP_ONE_WORD``, which the es-eval vocabulary
#: reads from ``labels.tenant_name``, so the eval's sessions know it too
#: (pinned by a test in ``test_eseval.py``).
ORACLE_LEARNT = "Thornbury"

#: Written against ``templates/elastic.example.json``. A test compiles every
#: one with a session that has issued ``<Org-01>`` (ORG_NAME),
#: ``ctr-amer-s01`` (SERVER_NAME) and ``<Tenant-01>`` (TENANT_ID), and has
#: learnt :data:`ORACLE_LEARNT` (ORG_NAME) without being shown it in a
#: keep value.
#: The other half of the keep-literal rule: the same literal, accepted once
#: the case has been shown the value. Each is refused like its oracle case
#: until the page in ``shown`` has come back.
SHOWN_KEEP_CASES: tuple[ShownKeepCase, ...] = (
    ShownKeepCase("learnt-name-in-keep-literal-shown",
                  "the dataset of a stream named after a learnt name, after a page showed it",
                  {"index": _IDX, "filters": [{"field": "data_stream.dataset", "op": "eq",
                                               "value": f"agent.{ORACLE_LEARNT.lower()}_events"}]},
                  ("data_stream.dataset", f"agent.{ORACLE_LEARNT.lower()}_events"),
                  "known_value"),
)

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
    # A label number no case issues, so this one is a guess at a label that
    # does not exist...
    OracleCase("unknown-label", "a label this case never issued: a guess, not a reference",
               {"index": _IDX, "filters": [{"field": _TENANT, "op": "eq",
                                            "value": "<Org-999977>"}]},
               "unknown_label"),
    # ...and this one is a guess at a label that **does** exist. Applying a
    # cluster vocabulary mints a label for every name on the estate, so
    # every low Org number is live before the case has asked anything.
    # Resolving it would let a case reach and count a customer it was never
    # shown - nobody unmasked, but the whole cluster reachable. A label is
    # usable only once the case has been shown it (seeded, or carried in a
    # page or an aggregation), and the refusal is the one above, word for
    # word: a refusal must not tell a live guess from a dead one.
    OracleCase("vocabulary-label-never-shown",
               "a label the vocabulary minted but this case was never shown",
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
    # A keep value containing a learnt name is shown as written (an index
    # named after a job), and a literal on a keep field may carry it - but
    # only once this case has been shown that exact value on a page. Typed
    # before that it is a guess at a name confirmed by a hit count, and the
    # refusal is the one a never-shown value gets, word for word.
    OracleCase("learnt-name-in-keep-literal-never-shown",
               "a keep literal containing a learnt name this case was never shown",
               {"index": _IDX, "filters": [{"field": "data_stream.dataset", "op": "eq",
                                            "value": f"agent.{ORACLE_LEARNT.lower()}_events"}]},
               "known_value"),
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
    OracleCase("histogram-over-cap", "a histogram wider than the bucket cap would run on the "
               "cluster and only then be withheld; refused before it is sent",
               {"index": _IDX, "size": 0, "time_range": {"gte": "now-7d", "lte": "now"},
                "aggs": {"h": {"type": "date_histogram", "field": "@timestamp", "interval": "1h"}}},
               "size_cap"),
    OracleCase("histogram-without-window", "a histogram with no end to its window has no bucket "
               "limit that can be checked before it runs",
               {"index": _IDX, "size": 0, "time_range": {"gte": "now-7d"},
                "aggs": {"h": {"type": "date_histogram", "field": "@timestamp", "interval": "1d"}}},
               "unbounded_histogram"),
    OracleCase("phrase-flooded-filters-agg", "one filters aggregation with a phrase per bucket "
               "returns a separate count for each, confirming a whole word list in one query",
               {"index": _IDX, "size": 0, "aggs": {"guess": {"type": "filters", "filters": {
                   f"w{i:02d}": [{"field": "message", "op": "phrase", "value": word}]
                   for i, word in enumerate(("harbor", "violet", "granite", "meadow", "copper",
                                             "lantern", "orchid", "summit", "willow", "ember",
                                             "falcon", "juniper"))}}}},
               "size_cap"),
    OracleCase("time-range-not-a-time", "a time bound that is not a timestamp (injection vector)",
               {"index": _IDX, "time_range": {"gte": "Contoso"}}, "bad_value"),
    OracleCase("tenant-id-literal", "a GUID literal on the tenant id field",
               {"index": _IDX, "filters": [{"field": _TENANT_ID, "op": "in",
                                            "value": ["3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10"]}]},
               "literal_identifier"),
)


# -- not and any_of: every filter rule, inside them -------------------------
#
# A filter inside ``not`` or ``any_of`` is compiled by the same code as a
# filter outside, so every rule above must refuse it with the same code and
# the same words. The cases below are generated, not copied: every oracle
# case that is one plain filter is wrapped once in ``not`` and once in
# ``any_of`` (after a filter that is fine on its own, so the refusal cannot
# come from the any_of being short). Two plain cases are added first because
# the rule exists and had no case of its own: a never-shown label inside a
# phrase, and an exact match on a text field.

ORACLE_CASES += (
    OracleCase("vocabulary-label-in-phrase-never-shown",
               "a live label this case was never shown, inside a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "failed for <Org-77>"}]}, "unknown_label"),
    OracleCase("eq-on-text", "an exact match on a text field is a whole-message oracle",
               {"index": _IDX, "filters": [{"field": "message", "op": "eq",
                                            "value": "Backup job failed"}]},
               "field_not_queryable"),
)

#: a filter every session accepts, put first in each wrapped any_of
COMPOUND_GOOD = {"field": "message", "op": "phrase", "value": "completed with"}


def _one_filter_case(c: OracleCase) -> bool:
    q = c.query
    return set(q) == {"index", "filters"} and len(q["filters"]) == 1 \
        and isinstance(q["filters"][0], dict) and not ({"not", "any_of"} & set(q["filters"][0]))


#: (plain case, wrapped case) pairs: a test compiles both and requires the
#: same refusal - code, message and label
def _wrapped(c: OracleCase) -> tuple[tuple[OracleCase, OracleCase], ...]:
    inner = c.query["filters"][0]
    return ((c, OracleCase(f"not-{c.name}", f"inside not: {c.why}",
                           {"index": _IDX, "filters": [{"not": inner}]}, c.code)),
            (c, OracleCase(f"any-of-{c.name}", f"inside any_of: {c.why}",
                           {"index": _IDX, "filters": [{"any_of": [COMPOUND_GOOD, inner]}]},
                           c.code)))


COMPOUND_TWINS: tuple[tuple[OracleCase, OracleCase], ...] = tuple(
    pair for c in ORACLE_CASES if _one_filter_case(c) for pair in _wrapped(c))

_FLOOD = ("harbor", "violet", "granite", "meadow", "copper", "lantern", "orchid", "summit",
          "willow", "ember", "falcon", "juniper")


def _phrase(word: str) -> dict:
    return {"field": "message", "op": "phrase", "value": word}


#: Shapes only these forms have. One level deep, in the query's filters
#: only: nesting and use inside a filters aggregation are refused, so the
#: phrase accounting and the zero-hit rule have exactly two new places to
#: look, not a tree.
COMPOUND_CASES: tuple[OracleCase, ...] = tuple(w for _p, w in COMPOUND_TWINS) + (
    OracleCase("not-of-not", "negation nested in negation",
               {"index": _IDX, "filters": [{"not": {"not": _phrase("completed with")}}]},
               "bad_filter"),
    OracleCase("not-of-any-of", "a none-of: an any_of nested in a not",
               {"index": _IDX, "filters": [{"not": {"any_of": [_phrase("harbor"),
                                                               _phrase("violet")]}}]},
               "bad_filter"),
    OracleCase("any-of-of-any-of", "an any_of nested in an any_of",
               {"index": _IDX, "filters": [{"any_of": [COMPOUND_GOOD, {"any_of": [
                   _phrase("harbor"), _phrase("violet")]}]}]}, "bad_filter"),
    OracleCase("any-of-of-not", "a not nested in an any_of",
               {"index": _IDX, "filters": [{"any_of": [COMPOUND_GOOD,
                                                       {"not": _phrase("harbor")}]}]},
               "bad_filter"),
    OracleCase("not-with-extra-key", "DSL smuggled beside a not",
               {"index": _IDX, "filters": [{"not": _phrase("completed with"), "boost": 2}]},
               "raw_dsl"),
    OracleCase("any-of-with-extra-key", "DSL smuggled beside an any_of",
               {"index": _IDX, "filters": [{"any_of": [COMPOUND_GOOD],
                                            "minimum_should_match": 0}]}, "raw_dsl"),
    OracleCase("not-and-any-of-together", "both forms in one object",
               {"index": _IDX, "filters": [{"not": COMPOUND_GOOD, "any_of": [COMPOUND_GOOD]}]},
               "raw_dsl"),
    OracleCase("not-of-a-list", "not takes one filter, not a list",
               {"index": _IDX, "filters": [{"not": [COMPOUND_GOOD]}]}, "bad_filter"),
    OracleCase("any-of-empty", "an empty any_of matches nothing in Elasticsearch's reading and "
               "everything in another's", {"index": _IDX, "filters": [{"any_of": []}]},
               "bad_filter"),
    OracleCase("any-of-over-cap", "more alternatives than an in takes values",
               {"index": _IDX, "filters": [{"any_of": [
                   {"field": "job.status", "op": "eq", "value": f"s{i}"} for i in range(51)]}]},
               "bad_filter"),
    OracleCase("not-inside-filters-agg", "a not inside a filters aggregation bucket",
               {"index": _IDX, "size": 0, "aggs": {"f": {"type": "filters", "filters": {
                   "a": [{"not": _phrase("harbor")}]}}}}, "bad_filter"),
    OracleCase("any-of-inside-filters-agg", "an any_of inside a filters aggregation bucket",
               {"index": _IDX, "size": 0, "aggs": {"f": {"type": "filters", "filters": {
                   "a": [{"any_of": [_phrase("harbor"), _phrase("violet")]}]}}}}, "bad_filter"),
    OracleCase("phrase-flooded-any-of", "one any_of of a whole word list: more distinct phrases "
               "than the per-query cap", {"index": _IDX, "size": 0, "filters": [
                   {"any_of": [_phrase(w) for w in _FLOOD]}]}, "size_cap"),
    OracleCase("phrase-flooded-nots", "a none-of spelled as many nots",
               {"index": _IDX, "size": 0, "filters": [{"not": _phrase(w)} for w in _FLOOD]},
               "size_cap"),
    OracleCase("phrase-flood-split-across-forms", "the word list split across an any_of, nots "
               "and plain phrases, so no one part is over the cap",
               {"index": _IDX, "size": 0, "filters": [
                   {"any_of": [_phrase(w) for w in _FLOOD[:4]]},
                   *[{"not": _phrase(w)} for w in _FLOOD[4:8]],
                   *[_phrase(w) for w in _FLOOD[8:]]]}, "size_cap"),
)

ORACLE_CASES += COMPOUND_CASES


# -- text_groups: the commonest messages in a scope -------------------------
#
# Grouping is done by the bridge after redaction: a sample of the documents
# in scope, spread over its time span, is scrubbed as a page is, and grouped by their redacted text with
# every label and every token carrying a digit masked, so two messages that
# differ only by a hidden value are one group. Everything that would group
# before redaction, unmask, nest, widen the read or smuggle DSL is refused.

def _groups(**over: Any) -> dict:
    spec = {"type": "text_groups", "field": "message", "size": 10}
    spec.update(over)
    return {k: v for k, v in spec.items() if v is not None}


TEXT_GROUP_CASES: tuple[OracleCase, ...] = (
    OracleCase("text-groups-on-keep-field", "grouping a keep field is a terms aggregation's job",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(field="log.level")}},
               "field_not_queryable"),
    OracleCase("text-groups-on-identifier", "grouping an identifier field by its text",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(field=_TENANT)}},
               "field_not_queryable"),
    OracleCase("text-groups-on-time-field", "grouping the time field",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(field="@timestamp")}},
               "field_not_queryable"),
    OracleCase("text-groups-unlisted-field", "grouping a field the site map does not list",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(field="process.command_line")}},
               "unknown_field"),
    OracleCase("text-groups-field-glob", "a glob in the grouped field",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(field="job.*")}},
               "unknown_field"),
    OracleCase("text-groups-unmasked", "asking for groups by the unmasked text",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(mask=False)}}, "raw_dsl"),
    OracleCase("text-groups-include-regex", "an include pattern over the grouped text",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(include="Contoso.*")}},
               "raw_dsl"),
    OracleCase("text-groups-min-doc-count", "a minimum count filters groups by how rare they are",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(min_doc_count=1)}}, "raw_dsl"),
    OracleCase("text-groups-size-over-cap", "more groups than the bucket cap",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(size=51)}}, "size_cap"),
    OracleCase("text-groups-nested-under-terms", "groups per tenant label: one group read per "
               "bucket, nested", {"index": _IDX, "size": 0, "aggs": {"t": {
                   "type": "terms", "field": _TENANT, "aggs": {"g": _groups()}}}}, "bad_agg"),
    OracleCase("text-groups-under-filters-agg", "groups per filters bucket, nested",
               {"index": _IDX, "size": 0, "aggs": {"f": {"type": "filters", "filters": {
                   "a": [{"field": "message", "op": "phrase", "value": "completed with"}]},
                   "aggs": {"g": _groups()}}}}, "bad_agg"),
    OracleCase("text-groups-with-sub-aggs", "a sub-aggregation under each group",
               {"index": _IDX, "size": 0, "aggs": {"g": {**_groups(), "aggs": {
                   "t": {"type": "terms", "field": _TENANT}}}}}, "bad_agg"),
    OracleCase("text-groups-beside-another-agg", "groups and another aggregation in one query",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(),
                                                   "t": {"type": "terms", "field": _SERVER}}},
               "bad_agg"),
    OracleCase("text-groups-with-hits", "groups and a page of hits in one query",
               {"index": _IDX, "size": 20, "aggs": {"g": _groups()}}, "bad_agg"),
    OracleCase("text-groups-with-from", "groups read from an offset: a wider read than the newest "
               "documents", {"index": _IDX, "size": 0, "from": 500, "aggs": {"g": _groups()}},
               "bad_agg"),
    OracleCase("text-groups-with-sort", "groups over documents chosen by another order",
               {"index": _IDX, "size": 0, "sort": [{"field": "job.status", "order": "asc"}],
                "aggs": {"g": _groups()}}, "bad_agg"),
    OracleCase("text-groups-scoped-by-literal", "the scope is gated like any filter: a literal "
               "on an identifier", {"index": _IDX, "size": 0, "filters": [
                   {"field": _TENANT, "op": "eq", "value": "Contoso"}], "aggs": {"g": _groups()}},
               "literal_identifier"),
    OracleCase("text-groups-scoped-by-unshown-label", "the scope is gated like any filter: a "
               "label never shown", {"index": _IDX, "size": 0, "filters": [
                   {"field": _TENANT, "op": "eq", "value": "<Org-77>"}], "aggs": {"g": _groups()}},
               "unknown_label"),
    OracleCase("text-groups-scope-phrase-flood", "the scope's phrases count toward the cap",
               {"index": _IDX, "size": 0, "filters": [{"any_of": [_phrase(w) for w in _FLOOD]}],
                "aggs": {"g": _groups()}}, "size_cap"),
    # the read is the bridge's to shape: a query cannot widen the sample,
    # choose the time slices it is spread over, or ask for the whole scope
    OracleCase("text-groups-wider-sample", "a sample wider than the cap: more documents in one "
               "request than paging allows", {"index": _IDX, "size": 0,
                                               "aggs": {"g": _groups(sample=10_000)}}, "raw_dsl"),
    OracleCase("text-groups-own-strata", "choosing how many time slices the sample is spread "
               "over", {"index": _IDX, "size": 0, "aggs": {"g": _groups(strata=500)}}, "raw_dsl"),
    OracleCase("text-groups-own-interval", "choosing the width of a time slice",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(interval="1m")}}, "raw_dsl"),
    OracleCase("text-groups-exact-asked", "asking for every document in scope to be read",
               {"index": _IDX, "size": 0, "aggs": {"g": _groups(exact=True)}}, "raw_dsl"),
    OracleCase("text-groups-newest-asked", "asking for the newest documents only, the read "
               "this replaced", {"index": _IDX, "size": 0, "aggs": {"g": _groups(newest=True)}},
               "raw_dsl"),
    OracleCase("group-placeholder-in-phrase", "a group's placeholder stands for any value; typed "
               "into a phrase it would search for the placeholder's letters",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "Throttled by SharePoint for <Org>"}]},
               "bad_value"),
    OracleCase("group-wildcard-placeholder-in-phrase", "the <*> a group puts where a hidden value "
               "or a number was, typed back into a phrase",
               {"index": _IDX, "filters": [{"field": "message", "op": "phrase",
                                            "value": "Rate limit for <*> reached"}]},
               "bad_value"),
)

ORACLE_CASES += TEXT_GROUP_CASES
# a one-filter case added here is wrapped in not and any_of like the others
_LATE_TWINS = tuple(pair for c in TEXT_GROUP_CASES if _one_filter_case(c)
                    for pair in _wrapped(c))
COMPOUND_TWINS += _LATE_TWINS
ORACLE_CASES += tuple(w for _p, w in _LATE_TWINS)
