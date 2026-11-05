"""Synthetic Elasticsearch fixtures, the stub Kibana, and the offline eval."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from hider import elastic, esquery, eseval

CFG = elastic.load(elastic.EXAMPLE)


@pytest.fixture(scope="module")
def fixture():
    return eseval.generate(docs=200)


@pytest.fixture(scope="module")
def engine(fixture):
    return eseval.StubEngine(fixture, CFG.indices)


# -- fixtures ------------------------------------------------------------------


def test_fixture_is_deterministic_and_carries_ground_truth(fixture):
    again = eseval.generate(docs=200)
    assert [d.source for d in again.docs] == [d.source for d in fixture.docs]
    assert {d.index for d in fixture.docs} == set(CFG.indices)
    truth = fixture.truth
    assert len(truth) > 100
    # every planted value really is in its document
    for d in fixture.docs:
        blob = json.dumps(d.source).lower()
        for v in d.seeded:
            assert v.lower() in blob, v
    # the unlisted fields are planted with a customer value, by design
    app = next(d for d in fixture.docs if d.index == "logs-app-*")
    assert app.source["process"]["command_line"].split("--tenant ")[1] in truth
    assert any(d.clean for d in fixture.docs) and any(not d.clean for d in fixture.docs)


def test_servers_follow_the_example_shape(fixture):
    shape = CFG.rule("agent.name").shape
    for s in fixture.servers:
        assert shape.fullmatch(s.name), s.name


# -- the stub engine -------------------------------------------------------------


def test_engine_answers_the_grammar(engine, fixture):
    s = elastic.EsScrubber(CFG, tier2="none")
    lab = s.seed(fixture.tenants[0].name)
    c = esquery.compile_query({
        "index": "logs-app-*", "size": 5, "time_range": {"gte": "now-6h", "lte": "now"},
        "filters": [{"field": "labels.tenant_name", "op": "eq", "value": lab}],
        "aggs": {"by_srv": {"type": "terms", "field": "agent.name", "size": 3,
                            "aggs": {"last": {"type": "top_hits", "size": 1}}},
                 "over_time": {"type": "date_histogram", "field": "@timestamp", "interval": "1h"},
                 "n": {"type": "cardinality", "field": "labels.tenant_id"},
                 "levels": {"type": "filters", "filters": {
                     "errors": [{"field": "log.level", "op": "eq", "value": "error"}]}},
                 "first": {"type": "min", "field": "@timestamp"}},
    }, CFG, s)
    raw = engine.search("logs-app-*", c.body["params"]["body"])
    expected = [d for d in fixture.docs if d.index == "logs-app-*"
                and d.source["labels"]["tenant_name"] == fixture.tenants[0].name]
    assert raw["hits"]["total"]["value"] == len(expected)
    assert len(raw["hits"]["hits"]) == min(5, len(expected))
    # projection: the unlisted field is gone before the scrubber sees it
    assert "process" not in raw["hits"]["hits"][0]["_source"]
    # newest first
    stamps = [h["_source"]["@timestamp"] for h in raw["hits"]["hits"]]
    assert stamps == sorted(stamps, reverse=True)
    a = raw["aggregations"]
    assert a["n"]["value"] == 1
    assert sum(b["doc_count"] for b in a["by_srv"]["buckets"]) + a["by_srv"]["sum_other_doc_count"] == len(expected)
    assert len(a["by_srv"]["buckets"][0]["last"]["hits"]["hits"]) == 1
    assert sum(b["doc_count"] for b in a["over_time"]["buckets"]) == len(expected)
    assert a["levels"]["buckets"]["errors"]["doc_count"] == sum(
        1 for d in expected if d.source["log"]["level"] == "error")
    assert a["first"]["value_as_string"].endswith("Z")


def test_engine_phrase_matching_is_token_sequence(engine):
    body = {"size": 3, "query": {"match_phrase": {"message": "throttled by sharepoint"}}}
    raw = engine.search("logs-app-*", body)
    assert raw["hits"]["total"]["value"] > 0
    for h in raw["hits"]["hits"]:
        assert "throttled by sharepoint" in h["_source"]["message"].lower()
    assert engine.search("logs-app-*", {"size": 1, "query": {"match_phrase": {"message": "sharepoint by throttled"}}})["hits"]["total"]["value"] == 0


# -- the Kibana protocol ----------------------------------------------------------


def _post(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


KBN = {"kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana"}


def test_stub_kibana_speaks_the_async_search_protocol(engine):
    kb = eseval.StubKibana(engine, cookie="sid=synthetic").start()
    try:
        s = elastic.EsScrubber(CFG, tier2="none")
        c = esquery.compile_query({"index": "logs-worker-*", "size": 3}, CFG, s)
        url = kb.url + "/internal/search/ese"
        # no session: behind SSO that is the login page with a 200, never a 401
        req = urllib.request.Request(url, data=json.dumps(c.body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **KBN})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200 and "/login" in r.geturl()
            assert r.headers["Content-Type"].startswith("text/html")
        # headers are required, as on the real endpoint
        assert _post(url, c.body, {"Cookie": "sid=synthetic"})[0] == 400
        assert _post(url, c.body, {"Cookie": "sid=synthetic", "kbn-xsrf": "true"})[0] == 400
        hdr = {"Cookie": "sid=synthetic", **KBN}
        status, first = _post(url, c.body, hdr)
        assert status == 200 and first["isRunning"] is True and first["id"]
        # the partial envelope is a refusal for the scrubber, never a page
        with pytest.raises(elastic.Refused) as e:
            s.scrub_response(first, c.plan)
        assert e.value.code == "incomplete"
        status, done = _post(f"{url}/{first['id']}", c.body, hdr)
        assert status == 200 and done["isRunning"] is False and done["isPartial"] is False
        out = s.scrub_response(done, c.plan).output
        assert len(out["hits"]["hits"]) == 3
        # an index outside the allowlist: Kibana echoes it, the scrubber does not
        status, err = _post(url, {"params": {"index": ".kibana_task_manager", "body": {}}}, hdr)
        assert status == 404 and ".kibana_task_manager" in err["message"]
        with pytest.raises(elastic.Refused) as e:
            s.scrub_response(err, c.plan)
        assert e.value.code == "upstream_error"
        assert "kibana_task_manager" not in e.value.message
        assert "not_found:index_not_found_exception" in e.value.message
    finally:
        kb.stop()


# -- the eval -----------------------------------------------------------------------


def test_eval_passes_its_gates_on_the_example_map():
    r = eseval.run_eval(docs=300, queries=40, tier2="none")
    assert r["passed"], r["gates"]
    assert r["response_leaks"] == 0
    assert r["oracle"]["refused"] == len(esquery.ORACLE_CASES)
    assert r["label_round_trip"]["tried"] > 0
    assert r["text_queries"] > 0
    assert r["unlisted_fields_seen"] == ["process.command_line", "user.full_name"]
    assert r["field_coverage"]["unlisted"] == 2
    text = eseval.format_report(r)
    assert "PASSED" in text
    # the report carries counts and field names, never a planted value
    truth = eseval.generate(docs=300).truth
    blob = json.dumps(r).lower()
    assert not any(v.lower() in blob for v in truth if len(v) > 5)
