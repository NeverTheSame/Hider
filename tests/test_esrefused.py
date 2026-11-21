"""A refused query's shape in the decision log: what the model tried, in
closed vocabularies only - never a value, a phrase, a label or a name the
model chose."""

import json

import pytest

from hider import elastic, esbridge, eseval, esreview

CFG = elastic.load(elastic.EXAMPLE)
CFG = elastic.parse({**json.loads(elastic.EXAMPLE.read_text()),
                     "clusters": {"stub": "https://kibana-stub.example.net"}}, source="t")


@pytest.fixture(scope="module")
def engine():
    return eseval.StubEngine(eseval.generate(docs=120), CFG.indices)


def _bridge(engine, tmp_path):
    return esbridge.Bridge(CFG, elastic.EsScrubber(CFG, tier2="none"),
                           eseval.EngineSession(engine), log_path=tmp_path / "decisions.jsonl")


def _rows(tmp_path):
    return [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]


def test_an_elasticsearch_style_aggregation_is_logged_as_its_shape(engine, tmp_path):
    """The shape the model sent first in every case of the model run:
    Elasticsearch's own {"terms": {"field": ...}} instead of the grammar's
    {"type": "terms", "field": ...}. The log says so - type missing, the DSL
    word and its keys, the field - and holds none of the free choices."""
    b = _bridge(engine, tmp_path)
    q = {"index": "logs-app-*", "time_range": {"gte": "now-7d", "lte": "now"}, "size": 0,
         "filters": [{"field": "message", "op": "phrase", "value": "Harbourline Tickets"}],
         "aggs": {"contoso_servers": {"terms": {"field": "agent.name", "size": 20,
                                                "zebra_secret": 1}}}}
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", q, probe=False)
    assert e.value.code == "bad_agg"
    row = _rows(tmp_path)[-1]
    shape = row["refused_shape"]
    (agg,) = shape["aggs"]
    assert agg["type"] == "<missing>" and agg["keys"] == ["terms"] and agg["other_keys"] == 0
    assert agg["dsl"] == {"terms": {"keys": ["field", "size"], "other_keys": 1,
                                    "field": "agent.name"}}
    assert [f.get("field") for f in shape["filters"]] == ["message"]
    assert [f.get("op") for f in shape["filters"]] == ["phrase"]
    blob = json.dumps(row)
    for free in ("contoso_servers", "Harbourline", "zebra_secret"):
        assert free not in blob


def test_unlisted_fields_and_invented_types_are_never_written(engine, tmp_path):
    b = _bridge(engine, tmp_path)
    q = {"index": "logs-secret-tenant-*", "size": 0,
         "aggs": {"a": {"type": "tenant_zebra", "field": "customer.secret_name"}}}
    with pytest.raises(elastic.Refused):
        b.run("stub", q, probe=False)
    row = _rows(tmp_path)[-1]
    assert row["refused_shape"]["index"] == "<unlisted>"
    assert row["refused_shape"]["aggs"][0]["type"] == "<other>"
    assert row["refused_shape"]["aggs"][0]["field"] == "<unlisted>"
    assert "zebra" not in json.dumps(row) and "secret" not in json.dumps(row)


def test_a_query_the_grammar_accepts_logs_no_refused_shape(engine, tmp_path):
    b = _bridge(engine, tmp_path)
    b.run("stub", {"index": "logs-app-*", "time_range": {"gte": "now-7d", "lte": "now"},
                   "size": 0, "aggs": {"srv": {"type": "terms", "field": "agent.name"}}},
          probe=False)
    assert "refused_shape" not in _rows(tmp_path)[-1]


def test_es_review_shows_what_was_refused(engine, tmp_path):
    b = _bridge(engine, tmp_path)
    with pytest.raises(elastic.Refused):
        b.run("stub", {"index": "logs-app-*", "size": 0,
                       "aggs": {"by": {"terms": {"field": "agent.name"}}}}, probe=False)
    r = esreview.review(tmp_path)
    assert r["numbers"]["refused_shapes"][0]["code"] == "bad_agg"
    lines = esreview.format_review(r)
    assert any(l.startswith("REFUSED  bad_agg: ") and '"<missing>"' in l for l in lines)
