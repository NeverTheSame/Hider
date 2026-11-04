"""The closed query grammar: what compiles, what is refused, what is logged."""

from __future__ import annotations

import json

import pytest

from hider import elastic, esquery

CFG = elastic.load(elastic.EXAMPLE)


def _session() -> elastic.EsScrubber:
    """The session the oracle cases are written against: one org, one
    server, one tenant GUID issued."""
    s = elastic.EsScrubber(CFG, tier2="none")
    assert s.seed("Contoso Holdings") == "<Org-01>"
    assert s.seed("ctr-amer-042", "SERVER_NAME") == "ctr-amer-s01"
    assert s.label_for(CFG.rule("labels.tenant_id"), "3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10") == "<Tenant-01>"
    return s


def _compile(q: dict, s: elastic.EsScrubber | None = None) -> esquery.Compiled:
    return esquery.compile_query(q, CFG, s or _session())


# -- the adversarial cases, first ----------------------------------------------


@pytest.mark.parametrize("case", esquery.ORACLE_CASES, ids=[c.name for c in esquery.ORACLE_CASES])
def test_every_oracle_case_is_refused_with_its_declared_code(case):
    with pytest.raises(elastic.Refused) as e:
        _compile(case.query)
    assert e.value.code == case.code, (case.why, e.value.message)
    # the refusal names the rule, never a value
    for v in ("Contoso", "ctr-amer-042", "3f2a9c4e"):
        assert v not in e.value.message


def test_oracle_cases_cover_every_refusal_code_the_compiler_has():
    import re
    from pathlib import Path
    src = Path(esquery.__file__).read_text()
    codes = set(re.findall(r'refuse\("([a-z_]+)"', src))
    declared = {c.code for c in esquery.ORACLE_CASES}
    # codes that only a malformed (not adversarial) request can reach
    structural = {"bad_query", "bad_filter", "bad_sort", "bad_value", "field_not_queryable",
                  "unknown_field", "bad_agg", "size_cap", "raw_dsl", "bad_index", "pattern_query"}
    assert codes - declared - structural == set(), "a refusal rule without an adversarial case"
    assert codes >= declared


# -- what a good query compiles to ---------------------------------------------


def test_labels_resolve_to_real_values_on_the_way_out_and_the_log_keeps_labels():
    s = _session()
    c = _compile({
        "index": "logs-app-*",
        "time_range": {"gte": "now-6h", "lte": "now"},
        "filters": [
            {"field": "labels.tenant_name", "op": "eq", "value": "<Org-01>"},
            {"field": "agent.name", "op": "in", "value": ["ctr-amer-s01"]},
            {"field": "labels.tenant_id", "op": "eq", "value": "<Tenant-01>"},
            {"field": "message", "op": "phrase", "value": "Throttled for <Org-01> on ctr-amer-s01"},
            {"field": "log.level", "op": "eq", "value": "error"},
            {"field": "job.counters.errors", "op": "range", "value": {"gte": 1}},
            {"field": "job.name", "op": "exists"},
        ],
        "size": 20, "from": 20,
        "sort": [{"field": "@timestamp", "order": "asc"}],
    }, s)
    body = c.body["params"]["body"]
    assert c.body["params"]["index"] == "logs-app-*"
    filters = body["query"]["bool"]["filter"]
    assert filters[0] == {"range": {"@timestamp": {"gte": "now-6h", "lte": "now"}}}
    assert {"term": {"labels.tenant_name": "Contoso Holdings"}} in filters
    assert {"terms": {"agent.name": ["ctr-amer-042"]}} in filters
    assert {"term": {"labels.tenant_id": "3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10"}} in filters
    assert {"match_phrase": {"message": "Throttled for Contoso Holdings on ctr-amer-042"}} in filters
    assert {"exists": {"field": "job.name"}} in filters
    assert body["sort"] == [{"@timestamp": {"order": "asc"}}]
    assert body["size"] == 20 and body["from"] == 20 and body["track_total_hits"] is True
    assert body["_source"]["includes"] == CFG.source_includes()
    # the decision log gets the phrase as written, with labels
    assert c.text_queries == ["Throttled for <Org-01> on ctr-amer-s01"]
    assert "Contoso" not in json.dumps(c.text_queries)
    assert set(c.labels_used) == {"<Org-01>", "ctr-amer-s01", "<Tenant-01>"}


def test_defaults_are_a_recent_first_page_with_no_raw_dsl():
    c = _compile({"index": "logs-worker-*"})
    body = c.body["params"]["body"]
    assert body["query"] == {"match_all": {}}
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert body["size"] == 10
    assert set(body) == {"size", "track_total_hits", "query", "_source", "sort"}


def test_aggregations_compile_with_fixed_count_order_and_a_plan():
    c = _compile({
        "index": "logs-app-*", "size": 0, "time_range": {"gte": "now-1d", "lte": "now"},
        "aggs": {
            "by_srv": {"type": "terms", "field": "agent.name", "size": 5,
                       "aggs": {"last": {"type": "top_hits", "size": 1}}},
            "over_time": {"type": "date_histogram", "field": "@timestamp", "interval": "30m",
                          "aggs": {"ds": {"type": "terms", "field": "data_stream.dataset"}}},
            "daily": {"type": "date_histogram", "field": "@timestamp", "interval": "day"},
            "tenants": {"type": "cardinality", "field": "labels.tenant_id"},
            "first": {"type": "min", "field": "@timestamp"},
            "slow": {"type": "percentiles", "field": "transaction.duration.us", "percents": [50, 99]},
            "levels": {"type": "filters", "filters": {
                "errors": [{"field": "log.level", "op": "eq", "value": "error"}]}},
        },
    })
    aggs = c.body["params"]["body"]["aggs"]
    assert aggs["by_srv"]["terms"] == {"field": "agent.name", "size": 5, "order": {"_count": "desc"}}
    assert aggs["by_srv"]["aggs"]["last"]["top_hits"]["_source"] == {"includes": CFG.source_includes()}
    assert aggs["over_time"]["date_histogram"]["fixed_interval"] == "30m"
    assert aggs["daily"]["date_histogram"]["calendar_interval"] == "day"
    assert aggs["tenants"] == {"cardinality": {"field": "labels.tenant_id"}}
    assert aggs["slow"]["percentiles"]["percents"] == [50, 99]
    assert aggs["levels"]["filters"]["filters"]["errors"] == {"bool": {"filter": [{"term": {"log.level": "error"}}]}}
    assert "sort" not in c.body["params"]["body"]
    plan = c.plan
    assert plan.aggs["by_srv"].rule.kind == "identifier"
    assert plan.aggs["by_srv"].subs["last"].type == "top_hits"
    assert plan.aggs["over_time"].subs["ds"].rule.kind == "keep"
    assert plan.aggs["levels"].names == ("errors",)


def test_guid_family_labels_are_interchangeable_across_guid_fields():
    s = _session()
    c = _compile({"index": "logs-app-*",
                  "filters": [{"field": "job.id", "op": "eq", "value": "<Tenant-01>"}]}, s)
    assert {"term": {"job.id": "3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10"}} in \
        c.body["params"]["body"]["query"]["bool"]["filter"]


def test_phrase_with_only_a_label_and_phrase_with_unknown_label():
    s = _session()
    c = _compile({"index": "logs-app-*",
                  "filters": [{"field": "message", "op": "phrase", "value": "<Org-01>"}]}, s)
    assert {"match_phrase": {"message": "Contoso Holdings"}} in c.body["params"]["body"]["query"]["bool"]["filter"]
    with pytest.raises(elastic.Refused) as e:
        _compile({"index": "logs-app-*",
                  "filters": [{"field": "message", "op": "phrase", "value": "job <Session-09> failed"}]}, s)
    assert e.value.code == "unknown_label"


@pytest.mark.parametrize("q,code", [
    ({"index": "logs-app-*", "filters": [{"field": "message", "op": "eq", "value": "x"}]},
     "field_not_queryable"),
    ({"index": "logs-app-*", "filters": [{"field": "log.level", "op": "phrase", "value": "x"}]},
     "field_not_queryable"),
    ({"index": "logs-app-*", "filters": [{"field": "log.level", "op": "like", "value": "x"}]},
     "bad_filter"),
    ({"index": "logs-app-*", "filters": [{"field": "log.level", "op": "eq", "value": True}]},
     "bad_value"),
    ({"index": "logs-app-*", "filters": [{"field": "log.level", "op": "eq", "value": "x" * 200}]},
     "bad_value"),
    ({"index": "logs-app-*", "filters": [{"field": "message", "op": "phrase", "value": "x" * 300}]},
     "bad_value"),
    ({"index": "logs-app-*", "filters": [{"field": "log.level", "op": "in", "value": ["a"] * 60}]},
     "bad_filter"),
    ({"index": "logs-app-*", "from": 5000}, "size_cap"),
    ({"index": "logs-app-*", "sort": [{"field": "@timestamp", "order": "sideways"}]}, "bad_sort"),
    ({"index": "logs-app-*", "time_range": {"since": "now-1h"}}, "bad_filter"),
    ({"index": "logs-app-*", "size": 0, "aggs": {"Bad Name": {"type": "cardinality",
                                                                "field": "labels.tenant_id"}}}, "bad_agg"),
    ({"index": "logs-app-*", "size": 0, "aggs": {"a": {"type": "terms", "field": "agent.name",
                                                        "aggs": {"b": {"type": "terms", "field": "agent.name",
                                                                       "aggs": {"c": {"type": "terms", "field": "agent.name",
                                                                                      "aggs": {"d": {"type": "cardinality", "field": "agent.name"}}}}}}}}},
     "bad_agg"),
    ({"index": "logs-app-*", "size": 0, "aggs": {"a": {"type": "date_histogram", "field": "@timestamp",
                                                        "interval": "3 weeks"}}}, "bad_agg"),
    ("not an object", "bad_query"),
])
def test_structural_refusals(q, code):
    with pytest.raises(elastic.Refused) as e:
        _compile(q)
    assert e.value.code == code


def test_a_tier1_shape_in_a_keep_literal_is_refused_but_plain_words_pass():
    _compile({"index": "logs-app-*",
              "filters": [{"field": "data_stream.dataset", "op": "eq", "value": "app.engine"}]})
    _compile({"index": "logs-app-*",
              "filters": [{"field": "message", "op": "phrase", "value": "Retry-After 30s, HTTP 429"}]})
    with pytest.raises(elastic.Refused) as e:
        _compile({"index": "logs-app-*",
                  "filters": [{"field": "message", "op": "phrase", "value": "host 10.44.2.17 down"}]})
    assert e.value.code == "shaped_literal"


# -- the histogram pre-flight: the bucket cap, before the query is sent --------

_NOW = 1_787_227_200.0  # Thursday 2026-08-20T12:00:00Z, the stub's clock


def _hist(time_range, interval="1h", field="@timestamp", nested=False):
    h = {"type": "date_histogram", "field": field, "interval": interval}
    aggs = {"by_srv": {"type": "terms", "field": "agent.name", "aggs": {"t": h}}} if nested else {"t": h}
    q = {"index": "logs-app-*", "size": 0, "aggs": aggs}
    if time_range is not None:
        q["time_range"] = time_range
    return q


def _refusal(q, now=_NOW):
    with pytest.raises(elastic.Refused) as e:
        esquery.compile_query(q, CFG, _session(), now=now)
    return e.value


def _buckets(tr, interval, now=_NOW):
    c = esquery._Compiler(CFG, _session(), now=now)
    c.time_range(tr)
    start, end, _ = c.window
    return esquery._bucket_count(start, end, interval)


@pytest.mark.parametrize("tr,interval,expected", [
    # relative on both ends
    ({"gte": "now-49h", "lte": "now"}, "1h", 50),          # the cap exactly
    ({"gte": "now-50h", "lte": "now"}, "1h", 51),
    ({"gte": "now-7d", "lte": "now"}, "1d", 8),
    ({"gte": "now-7d", "lte": "now"}, "1h", 169),
    ({"gte": "now-7d", "lte": "now-5d"}, "1h", 49),
    # rounding: gte rounds down, lte rounds up to the unit's last millisecond
    ({"gte": "now-1d/d", "lte": "now"}, "1h", 37),         # yesterday 00:00 .. 12:00
    ({"gte": "now-2d/d", "lte": "now"}, "1h", 61),
    ({"gte": "now-1d", "lte": "now/d"}, "1h", 36),         # .. end of today
    ({"gte": "now-1d/d", "lte": "now/d"}, "1h", 48),       # Kibana's "yesterday and today"
    ({"gte": "now-6w/w", "lte": "now"}, "1w", 7),          # weeks start on Monday
    # gt rounds up, lt down
    ({"gt": "now-49h", "lt": "now"}, "1h", 50),
    ({"gt": "now-2d/d", "lt": "now"}, "1h", 38),           # after the end of 18 Aug
    # calendar months: now-1M is 20 July
    ({"gte": "now-1M", "lte": "now"}, "1d", 32),
    ({"gte": "now-2M", "lte": "now"}, "1d", 62),
    ({"gte": "now-49d", "lte": "now"}, "day", 50),
    ({"gte": "now-3y", "lte": "now"}, "month", 37),
    ({"gte": "now-5y", "lte": "now"}, "month", 61),
    ({"gte": "2014-04-01", "lte": "now"}, "quarter", 50),
    ({"gte": "2014-01-01", "lte": "now"}, "quarter", 51),
    # ISO on both ends: no clock. A bare date on lte is its last millisecond,
    # seconds without a fraction are rounded up to .999
    ({"gte": "2026-08-18T11:00:00Z", "lte": "2026-08-20T12:00:00Z"}, "1h", 50),
    ({"gte": "2026-08-18T10:00:00Z", "lte": "2026-08-20T12:00:00Z"}, "1h", 51),
    ({"gte": "2026-08-01", "lte": "2026-08-20"}, "1d", 20),
    ({"gte": "2026-08-19", "lte": "2026-08-20"}, "1h", 48),
    ({"gte": "2026-08-18", "lte": "2026-08-20"}, "1h", 72),
    ({"gte": "2026-08-18 11:00", "lte": "2026-08-20 12:00"}, "1h", 50),
    # offsets move the instant
    ({"gte": "2026-08-18T13:00:00+02:00", "lte": "2026-08-20T12:00:00Z"}, "1h", 50),
    ({"gte": "2026-08-18T13:00-0200", "lte": "2026-08-20T16:00:00Z"}, "1h", 50),
    # mixed ISO and now: the now side is pushed out by the skew margin
    ({"gte": "2026-08-18T12:00:00Z", "lte": "now"}, "1h", 49),
    ({"gte": "2026-08-18T10:00:00Z", "lte": "now"}, "1h", 51),
    ({"gte": "now-7d", "lte": "2026-08-20T12:00:00Z"}, "4h", 44),
])
def test_histogram_bucket_count_matches_elasticsearch_and_the_cap_is_applied_before_sending(
        tr, interval, expected):
    assert _buckets(tr, interval) == expected
    for nested in (False, True):
        q = _hist(tr, interval, nested=nested)
        if expected <= CFG.max_buckets:
            esquery.compile_query(q, CFG, _session(), now=_NOW)
        else:
            assert _refusal(q).code == "size_cap", (tr, interval)


def test_a_relative_window_counts_the_same_at_any_hour():
    for dt in (0, 1, 1799, 3599, 3600 * 11 + 59):
        assert _buckets({"gte": "now-7d", "lte": "now"}, "1h", _NOW + dt) == 169
        assert _buckets({"gte": "now-49h", "lte": "now"}, "1h", _NOW + dt) == 50
        assert _buckets({"gte": "now-1d/d", "lte": "now/d"}, "1h", _NOW + dt) == 48


def test_a_mixed_window_widens_toward_the_now_side_by_the_clock_skew_margin():
    # three minutes before the hour: by this clock 50 buckets, but Kibana's
    # clock may already be past 12:00, which makes 51
    early = _NOW - 180
    tr = {"gte": "2026-08-18T10:00:00Z", "lte": "now"}
    assert _buckets(tr, "1h", early) == 51
    e = _refusal(_hist(tr), now=early)
    assert e.code == "size_cap" and "this machine's clock" in e.message
    # the same on the start side: by this clock 18 Aug 11:03, possibly 10:58
    tr = {"gte": "now-49h", "lte": "2026-08-20T12:30:00Z"}
    assert _buckets(tr, "1h", _NOW + 180) == 51
    # no margin when both sides are on now: one clock reading for both
    assert _buckets({"gte": "now-49h", "lte": "now"}, "1h", early) == 50


def test_histogram_over_cap_refusal_says_how_many_buckets_and_what_fits():
    e = _refusal(_hist({"gte": "now-7d", "lte": "now"}, nested=True))
    assert e.code == "size_cap"
    assert "aggs.by_srv.t" in e.message and "window of 7d gives 169 buckets" in e.message
    assert "the cap is 50" in e.message and "4h fits (43 buckets)" in e.message
    assert "window of at most 2d 1h" in e.message and "clock" not in e.message
    e = _refusal(_hist({"gte": "2026-05-01", "lte": "now"}, "1d"))
    assert "1w fits (17 buckets)" in e.message and "this machine's clock" in e.message
    e = _refusal(_hist({"gte": "1900-01-01", "lte": "2026-01-01"}, "1d"))
    assert "no interval in the grammar fits" in e.message


@pytest.mark.parametrize("tr", [None, {"gte": "now-7d"}, {"gt": "now-7d"}, {"lte": "now"}])
def test_histogram_without_a_closed_window_is_refused_not_guessed(tr):
    e = _refusal(_hist(tr, "1d"))
    assert e.code == "unbounded_histogram" and "start (gte/gt) and an end (lte/lt)" in e.message
    # the same window is fine for a query without a histogram
    q = {"index": "logs-app-*", "size": 1}
    if tr is not None:
        q["time_range"] = tr
    esquery.compile_query(q, CFG, _session(), now=_NOW)


def test_histogram_on_a_field_time_range_does_not_bound_is_refused():
    e = _refusal(_hist({"gte": "now-1d", "lte": "now"}, "1h", field="event.created"))
    assert e.code == "unbounded_histogram" and "@timestamp" in e.message


@pytest.mark.parametrize("q,code", [
    (_hist({"gte": "now-1d", "lte": "now"}, "0h"), "bad_agg"),
    (_hist({"gte": "2026-02-30", "lte": "now"}), "bad_value"),
    (_hist({"gte": "2026-08-20T25:00:00Z", "lte": "now"}), "bad_value"),
    (_hist({"gte": "now-9999y", "lte": "now"}), "bad_value"),
    ({"index": "logs-app-*", "time_range": {"gte": "2026-13-01", "lte": "now"}}, "bad_value"),
])
def test_impossible_intervals_and_dates_are_refused(q, code):
    assert _refusal(q).code == code


def test_compile_uses_the_real_clock_when_none_is_given():
    import time
    # from a fixed date to now grows with the clock: ten days back is under the
    # cap at 1d whatever today is, and 2000-01-01 never is
    recent = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 10 * 86400))
    esquery.compile_query(_hist({"gte": recent, "lte": "now"}, "1d"), CFG, _session())
    with pytest.raises(elastic.Refused):
        esquery.compile_query(_hist({"gte": "2000-01-01", "lte": "now"}, "1d"), CFG, _session())
