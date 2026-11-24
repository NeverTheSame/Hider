"""An empty result: what a zero means, for the person and for the model.

The first three tests are the measurement **before** the bridge explained
zeros: the model's bare zero, what es-smoke's old check cost on a wide
window, and the skip for a query that uses any_of or not. They stay as the
"before" figures; ``esbridge.field_probe`` is kept for them."""

from __future__ import annotations

import dataclasses
import json
import tempfile
from pathlib import Path

import pytest

from hider import elastic, esbridge, eseval, esmcp

CFG = dataclasses.replace(elastic.load(elastic.EXAMPLE),
                          clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))
#: a listed field the app index never fills (it belongs to the traces index)
NEVER_FILLED = "transaction.result"
WEEK = {"gte": "now-7d", "lte": "now"}
DAY = {"gte": "now-1d", "lte": "now"}


@pytest.fixture(scope="module")
def world():
    fx = eseval.generate(docs=300)
    engine = eseval.StubEngine(fx, CFG.indices)
    vocab, _b = eseval.build_vocabulary(CFG, engine)
    return fx, engine, vocab


def _case(world, *, exists_seconds=0.0):
    fx, engine, vocab = world
    engine.exists_seconds_per_day = exists_seconds
    engine.simulated_seconds = 0.0
    engine.exists_scans = engine.exists_early = 0
    case = eseval.BridgeCase(CFG, engine, vocab, tier2="none")
    return engine, case


def _mcp_case(world):
    fx, engine, vocab = world
    index = elastic.VocabularyIndex(None)
    index.put("stub", vocab)
    book = esmcp.CaseBook(CFG, Path(tempfile.mkdtemp()))
    _token, case, _r = book.open("c1", [fx.tenants[0].name], "none",
                                 eseval.EngineSession(engine), index)
    return case


# -- before -------------------------------------------------------------------------


def test_before_the_model_got_a_bare_zero(world):
    """The model's reply to a zero on a field this index never fills: a
    count of 0 and nothing else - indistinguishable from "nothing matches"."""
    esbridge.clock = lambda: eseval.NOW.timestamp()
    case = _mcp_case(world)
    reply = esmcp.call_tool(CFG, case, "es_count", {
        "index": "logs-app-*", "time_range": DAY,
        "filters": [{"field": NEVER_FILLED, "op": "eq", "value": "ok"}]})
    payload = json.loads(reply["content"][0]["text"])
    assert payload["hits_total"]["value"] == 0
    # what the model learns about why: nothing beyond the three keys
    assert set(payload) - {"cluster", "hits_total", "seconds", "empty"} == set()


def test_before_the_old_check_counted_every_document_in_the_window(world):
    """es-smoke's check: one filters aggregation with exists buckets, each
    a full count over the window. The stub charges EXISTS_SCAN_SECONDS_PER_DAY
    per bucket per window-day (sized from 30-39s measured on one day)."""
    engine, case = _case(world, exists_seconds=eseval.EXISTS_SCAN_SECONDS_PER_DAY)
    for window, days in ((DAY, 1), (WEEK, 7)):
        q = {"index": "logs-app-*", "time_range": window, "size": 0, "filters": [
            {"field": "message", "op": "phrase", "value": "zebra quokka"},
            {"field": NEVER_FILLED, "op": "eq", "value": "ok"}]}
        probes, fields = esbridge.field_probe(q, max_buckets=CFG.max_buckets)
        before_r, before_s = len(engine.requests), engine.simulated_seconds
        for p in probes:
            out, refused, _dt, _c = case.call(p)
            assert refused is None
        requests = len(engine.requests) - before_r
        seconds = engine.simulated_seconds - before_s
        # two fields: s, w, f buckets each; the four exists buckets are the
        # full scans - 48 simulated seconds on a day, 336 on a week
        assert requests == 1 and fields == ["message", NEVER_FILLED]
        assert seconds == pytest.approx(4 * eseval.EXISTS_SCAN_SECONDS_PER_DAY * days)
    # and those seconds were not in the query's own reported time: the
    # check ran as separate runs in es-smoke, each logged as a query row
    rows = [json.loads(x) for x in (case.directory / "decisions.jsonl").read_text().splitlines()
            if "vocabulary" not in x]
    assert len(rows) == 2 and all(r["aggs"][0]["type"] == "filters" for r in rows)


def test_before_the_check_was_skipped_for_a_wide_scope_query(world):
    """The honest tenant ask (any_of of the field and a text phrase of the
    label) got no check at all: a zero stayed bare."""
    engine, case = _case(world)
    label = case.scrubber.seed(world[0].tenants[0].name)
    q = {"index": "logs-app-*", "time_range": DAY, "size": 0, "filters": [
        {"any_of": [{"field": "labels.tenant_name", "op": "eq", "value": label},
                    {"field": "message", "op": "phrase", "value": label}]},
        {"field": NEVER_FILLED, "op": "eq", "value": "ok"}]}
    assert esbridge.field_probe(q) is None
    report = esbridge.run_smoke(lambda query: esbridge.run_case(case.bridge, "stub", query), q,
                                max_buckets=CFG.max_buckets)
    assert report["hits_total"] == 0 and "field_probe" not in report


# -- after --------------------------------------------------------------------------


def test_the_model_is_told_what_a_zero_means_and_never_the_value(world):
    esbridge.clock = lambda: eseval.NOW.timestamp()
    case = _mcp_case(world)
    reply = esmcp.call_tool(CFG, case, "es_count", {
        "index": "logs-app-*", "time_range": DAY,
        "filters": [{"field": NEVER_FILLED, "op": "eq", "value": "ok"},
                    {"field": "message", "op": "phrase", "value": "zebra quokka"}]})
    payload = json.loads(reply["content"][0]["text"])
    assert payload["hits_total"]["value"] == 0
    e = payload["empty"]
    assert e["fields"][NEVER_FILLED]["status"] == "absent_in_window"
    assert e["fields"]["message"]["status"] == "present_in_window"
    assert f"{NEVER_FILLED} is not filled on any document in this index and window" in e["meaning"]
    assert "not checked further" in e["meaning"]
    # the typed value is nowhere in the explanation
    blob = json.dumps(e)
    assert "zebra" not in blob and '"ok"' not in blob
    # and the check's time is in the reported seconds, and reported apart
    assert payload["seconds"] >= e["seconds"] and e["requests"] == 3
    # a real zero: the field is filled where the filters look
    reply = esmcp.call_tool(CFG, case, "es_count", {
        "index": "logs-app-*", "time_range": DAY,
        "filters": [{"field": "message", "op": "phrase", "value": "zebra quokka"}]})
    e = json.loads(reply["content"][0]["text"])["empty"]
    assert e["fields"]["message"]["status"] == "present" and "a real zero" in e["meaning"]
    # a page in between: fields seen on it are remembered, the window check
    # is skipped for them, and only the window total is asked (1 request)
    assert e["requests"] <= 2


def test_after_the_check_costs_a_few_capped_counts_not_a_scan_of_the_window(world):
    """The same two-filter zero as the before-test, on a day and on a week:
    a handful of requests, each answered early (a present field stops at
    the cap, an absent one has no postings), against one request of four
    full scans - 48 and 336 simulated seconds - before."""
    engine, case = _case(world, exists_seconds=eseval.EXISTS_SCAN_SECONDS_PER_DAY)
    for window in (DAY, WEEK):
        case = eseval.BridgeCase(CFG, engine, world[2], tier2="none")   # fresh: no memory yet
        before_r, before_s = len(engine.requests), engine.simulated_seconds
        q = {"index": "logs-app-*", "time_range": window, "size": 0, "filters": [
            {"field": "message", "op": "phrase", "value": "zebra quokka"},
            {"field": NEVER_FILLED, "op": "eq", "value": "ok"}]}
        out, refused, _dt, _c = case.call(q)
        assert refused is None and out["hits"]["total"]["value"] == 0
        e = out["empty"]
        requests = len(engine.requests) - before_r - 1      # the query itself
        seconds = engine.simulated_seconds - before_s
        assert requests == e["requests"] == 3
        assert seconds <= 3 * eseval.EXISTS_EARLY_SECONDS + 1e-9
        assert engine.exists_scans == 0                      # no full scan
        # the check's requests are not query rows in the log; the row
        # carries statuses and counts only
        rows = [json.loads(x) for x in (case.directory / "decisions.jsonl").read_text().splitlines()
                if "vocabulary" not in x]
        assert len(rows) == 1
        assert rows[0]["empty_check"] == {
            "requests": 3, "seconds": e["seconds"],
            "fields": {"message": "present_in_window", NEVER_FILLED: "absent_in_window"},
            "window_documents": f">={esbridge.EMPTY_CHECK_CAP}"}


def test_after_a_wide_scope_zero_is_explained_and_memory_saves_requests(world):
    engine, case = _case(world)
    label = case.scrubber.seed(world[0].tenants[0].name)
    q = {"index": "logs-app-*", "time_range": DAY, "size": 0, "filters": [
        {"any_of": [{"field": "labels.tenant_name", "op": "eq", "value": label},
                    {"field": "message", "op": "phrase", "value": label}]},
        {"field": NEVER_FILLED, "op": "eq", "value": "ok"}]}
    out, refused, _dt, _c = case.call(q)
    assert refused is None
    e = out["empty"]
    assert set(e["fields"]) == {"labels.tenant_name", "message", NEVER_FILLED}
    assert e["fields"][NEVER_FILLED]["status"] == "absent_in_window"
    assert e["requests"] == 4           # three window checks, one window total
    # a page shows fields; a later zero on them needs no window request
    page, refused, _dt, _c = case.call({"index": "logs-app-*", "time_range": DAY, "size": 5})
    assert refused is None and page["hits"]["hits"]
    out, refused, _dt, _c = case.call({"index": "logs-app-*", "time_range": DAY, "size": 0,
                                       "filters": [{"field": "message", "op": "phrase",
                                                    "value": "zebra quokka"}]})
    e = out["empty"]
    assert e["fields"]["message"]["status"] == "present" and e["requests"] == 1
    # an empty window is still called empty, memory or not
    out, refused, _dt, _c = case.call({"index": "logs-app-*",
                                       "time_range": {"gte": "now-1m", "lte": "now-1m"}, "size": 0,
                                       "filters": [{"field": "message", "op": "phrase",
                                                    "value": "zebra"}]})
    e = out["empty"]
    assert e["window_documents"] == 0 and "no document in this index and window" in e["meaning"]
    assert e["requests"] == 1
    # a filter emptied by another one is not blamed on its field
    out, refused, _dt, _c = case.call({"index": "logs-app-*", "time_range": DAY, "size": 0,
                                       "filters": [
                                           {"field": "job.status", "op": "eq", "value": "Nope"},
                                           {"field": "message", "op": "phrase", "value": "job"}]})
    e = out["empty"]
    assert e["fields"]["job.status"]["status"] == "present"
    assert e["fields"]["message"]["status"] == "others_empty"
    assert "job.status is filled" in e["meaning"] and "a real zero" in e["meaning"]
    assert "Nope" not in json.dumps(e)


def test_an_explained_zero_moves_no_review_signal(world):
    from hider import esreview

    engine, case = _case(world)
    for _ in range(2):
        case.call({"index": "logs-app-*", "time_range": DAY, "size": 0, "filters": [
            {"field": NEVER_FILLED, "op": "eq", "value": "ok"},
            {"field": "message", "op": "phrase", "value": "zebra quokka"}]})
    case.save()
    r = esreview.review(case.directory)
    n = r["numbers"]
    # the check's requests are not queries; the typed phrase is still a
    # zero-hit phrase (the zero is explained, not excused: declared)
    assert n["queries"] == 2 and n["text_phrases_distinct"] == 1 and n["text_phrases_zero_hit"] == 1
    assert r["verdict"] == "nothing flagged"


# -- a pattern with no index behind it -----------------------------------------------


NO_INDEX = "traces-apm-*"


@pytest.fixture
def no_index(world):
    _fx, engine, _vocab = world
    engine.no_backing = {NO_INDEX}
    yield
    engine.no_backing = set()


def test_an_aggregation_on_a_pattern_with_no_index_is_a_zero_for_the_model(world, no_index):
    """Elasticsearch leaves the aggregations block out when a pattern matches
    no index. The model was told ``malformed``; it gets a count of 0 and an
    empty aggregations object."""
    esbridge.clock = lambda: eseval.NOW.timestamp()
    case = _mcp_case(world)
    reply = esmcp.call_tool(CFG, case, "es_aggregate", {
        "index": NO_INDEX, "time_range": DAY,
        "aggs": {"t": {"type": "terms", "field": "labels.tenant_id", "size": 5}}})
    assert not reply.get("isError")
    payload = json.loads(reply["content"][0]["text"])
    assert payload["hits_total"] == {"value": 0, "relation": "eq"}
    assert payload["aggregations"] == {}
    reply = esmcp.call_tool(CFG, case, "es_count", {"index": NO_INDEX, "time_range": DAY})
    assert json.loads(reply["content"][0]["text"])["hits_total"]["value"] == 0


def test_es_smoke_prints_a_pattern_with_no_index_as_a_zero(world, no_index, capsys):
    _engine, case = _case(world)
    q = {"index": NO_INDEX, "time_range": WEEK, "size": 0,
         "aggs": {"t": {"type": "terms", "field": "labels.tenant_id", "size": 5},
                  "d": {"type": "date_histogram", "field": "@timestamp", "interval": "1d"}}}
    esbridge.clock = lambda: eseval.NOW.timestamp()
    rc = esbridge.smoke(case.bridge, "stub", q)
    out = capsys.readouterr().out
    assert rc in (0, 3) and "hits_total=0" in out and "REFUSED" not in out


def test_a_group_read_on_a_pattern_with_no_index_was_already_a_zero(world, no_index):
    """A group read counts first, with no aggregation, so it never met the
    missing block: no groups, and the zero explained as an empty window."""
    _engine, case = _case(world)
    out, refused, _dt, _c = case.call({
        "index": NO_INDEX, "time_range": DAY, "size": 0,
        "aggs": {"g": {"type": "text_groups", "field": "message", "size": 5}}})
    assert refused is None
    assert out["aggregations"]["g"]["buckets"] == [] and out["aggregations"]["g"]["total"] == 0
    assert out["empty"]["window_documents"] == 0


def test_a_count_and_a_terms_on_a_pattern_with_no_index_say_the_window_is_empty(world, no_index):
    _engine, case = _case(world)
    out, refused, _dt, _c = case.call({
        "index": NO_INDEX, "time_range": DAY, "size": 0,
        "aggs": {"t": {"type": "terms", "field": "labels.tenant_id", "size": 5}}})
    assert refused is None and "aggregations" not in out
    assert out["hits"]["total"] == {"value": 0, "relation": "eq"}
    assert out["empty"]["window_documents"] == 0
    rows = [json.loads(x) for x in (case.directory / "decisions.jsonl").read_text().splitlines()]
    assert rows[-1]["hits_total"] == 0 and "refused" not in rows[-1]
