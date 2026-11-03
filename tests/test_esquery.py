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
            {"field": "job_name", "op": "exists"},
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
    assert {"exists": {"field": "job_name"}} in filters
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
        "index": "logs-app-*", "size": 0,
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
