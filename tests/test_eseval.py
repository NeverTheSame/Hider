"""Synthetic Elasticsearch fixtures, the stub Kibana, and the offline eval."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import timedelta

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


# -- the back catalogue: more job names than one aggregation can carry ----------
#
# A real cluster holds tens of thousands of distinct job names over its
# retention period. The vocabulary used to be one terms aggregation over the
# last vocabulary.days days, capped: on an estate this size the cap was
# always hit, so every case was refused and no page was ever shown. These
# tests pin both halves of the fix - the catalogue is genuinely past the old
# cap, and an hour-wide case now reads one page and still hides the name.


@pytest.fixture(scope="module")
def bulk():
    fx = eseval.generate(docs=200, bulk_jobs=eseval.BULK_JOBS)
    return fx, eseval.StubEngine(fx, CFG.indices)


def test_the_back_catalogue_is_past_what_one_capped_aggregation_returns(bulk):
    fx, engine = bulk
    names = {eseval.flatten(d.source).get("job.name") for d in fx.docs}
    names.discard(None)
    assert len(names) > 10_000  # the cap the single-request read shipped with
    # what the old read asked for, against this fixture: a full bucket list,
    # which is exactly the condition that refused the case
    body = {"size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-30d"}}}]}},
            "aggs": {"v": {"terms": {"field": "job.name", "size": 10_000}}}}
    raw = engine.search(",".join(CFG.indices), body, ignore_unavailable=True)
    assert len(raw["aggregations"]["v"]["buckets"]) == 10_000


def test_the_sign_in_build_covers_a_one_hour_case_at_no_cost_to_it(bulk):
    """The case reads nothing: the build happened once, for the cluster,
    and it covered thirty days, so the job's record is in it even though it
    sits outside the case's hour."""
    fx, engine = bulk
    s = elastic.EsScrubber(CFG, tier2="none")
    n = len(engine.requests)
    vocab, build = eseval.build_vocabulary(CFG, engine)
    assert len(engine.requests) - n == build.requests
    n = len(engine.requests)
    s.apply_vocabulary("stub", vocab)
    assert len(engine.requests) == n          # applying costs no request
    out = s._scrub_text(eseval.WINDOW_CASE_MESSAGE)
    assert eseval.WINDOW_CASE_JOB not in out
    assert out == eseval.WINDOW_CASE_MESSAGE.replace(
        eseval.WINDOW_CASE_JOB, s.known[eseval.WINDOW_CASE_JOB.casefold()])
    assert not eseval.name_part_leaks([out], eseval.WINDOW_CASE_PHRASE, eseval.WINDOW_CASE_JOB)


def test_the_build_pages_through_the_whole_catalogue_one_field_at_a_time(bulk):
    fx, engine = bulk
    vocab, build = eseval.build_vocabulary(CFG, engine)
    counts = vocab.counts
    assert counts["job.name"] > 12_000
    # One page per thousand names of the widest field, plus one page for
    # each of the other four - but now per slice, and the catalogue is
    # spread over several days, so the floor is the whole-catalogue count
    # and the ceiling allows a page per field per slice.
    pages = -(-counts["job.name"] // elastic.VOCABULARY_PAGE)
    slices = CFG.vocabulary_days
    assert pages + 4 <= build.requests <= pages + len(CFG.vocabulary_rules) * slices
    s = elastic.EsScrubber(CFG, tier2="none")
    s.apply_vocabulary("stub", vocab)
    assert eseval.bulk_job_name(0).casefold() in s.known


def test_the_stub_charges_what_a_page_really_costs(bulk):
    """Without a simulated cost an in-memory build looks free, and the whole
    reason this is built once per bridge disappears from the measurement.

    The budget is now per **slice**, not per cover: the cover over thirty
    days is far past it, and that is the measured fact that made slicing
    necessary rather than a failure.
    """
    fx, engine = bulk
    engine.page_seconds = eseval.PAGE_SECONDS
    engine.wide_page_seconds = eseval.WIDE_PAGE_SECONDS
    engine.simulated_seconds = 0.0
    before = engine.simulated_seconds
    _vocab, cover = eseval.build_cover(CFG, engine)
    spent = engine.simulated_seconds - before
    assert spent > 300                           # minutes, not milliseconds
    assert cover["max_slice_s"] <= CFG.vocabulary_budget_s   # each slice is inside it
    assert not cover["wide_pages"]               # no page asked for a wide range
    assert min(eseval.PAGE_SECONDS) >= 8 and max(eseval.PAGE_SECONDS) <= 35
    # a top-up reads only what is new, so it costs a page per field
    before = engine.simulated_seconds
    _new, topup = eseval.build_vocabulary(
        CFG, engine, _vocab.covered_until,
        _vocab.covered_until + elastic.VOCABULARY_REFRESH_S)
    assert topup.requests == len(CFG.vocabulary_rules)
    assert engine.simulated_seconds - before < spent
    engine.page_seconds = engine.wide_page_seconds = ()


def test_a_wide_range_page_costs_what_the_cluster_measured(bulk):
    """The measurement that made slicing necessary: the same page is 8-35s
    over a day and 31-297s over the whole retention period. A build that
    still asked for the whole range would be charged the second number."""
    fx, engine = bulk
    engine.page_seconds = eseval.PAGE_SECONDS
    engine.wide_page_seconds = eseval.WIDE_PAGE_SECONDS
    engine.simulated_seconds = 0.0
    until = eseval.NOW.timestamp()
    eseval.build_slice(CFG, engine, until - 86400.0, until)
    narrow = engine.simulated_seconds
    assert engine.wide_pages == 0
    engine.simulated_seconds = 0.0
    # and a build that still asked for the whole range at once is charged
    # so much that it fails its own budget - which is what happened on the
    # real cluster, and why the range is sliced before it is paged
    with pytest.raises(elastic.Refused) as e:
        eseval.build_slice(CFG, engine, until - 30 * 86400.0, until)
    assert e.value.code == "vocabulary" and "budget_s" in e.value.message
    assert engine.wide_pages > 0
    assert engine.simulated_seconds > narrow
    assert min(eseval.WIDE_PAGE_SECONDS) >= 31 and max(eseval.WIDE_PAGE_SECONDS) <= 297
    engine.page_seconds = engine.wide_page_seconds = ()
    engine.wide_pages = 0


def test_a_case_runs_off_the_recent_slices_while_the_older_ones_build(bulk):
    """The shape of the whole change: the recent days are enough to show a
    page, the rest keeps reading behind it, and the broker answers between
    steps instead of disappearing for the length of a page."""
    fx, engine = bulk
    engine.page_seconds = eseval.PAGE_SECONDS
    engine.wide_page_seconds = eseval.WIDE_PAGE_SECONDS
    try:
        out = eseval.run_slice_eval(CFG, fx, engine, tier2="none")
    finally:
        engine.page_seconds = engine.wide_page_seconds = ()
    assert out["refused_before_cover"] == "vocabulary_building"
    assert out["case_shown"] and not out["case_leaks"] and not out["case_part_leak"]
    assert out["still_building_older"]           # the cover is not complete
    assert out["covered_days_at_first_case"] <= elastic.VOCABULARY_SERVE_DAYS
    assert out["pings"] == out["pings_answered"] > 0
    assert out["max_step_s"] <= out["poll_interval_s"]
    assert out["steps"] > out["slices_at_first_case"]   # many steps per slice


# -- a site map with no vocabulary section -------------------------------------


def test_the_fixture_names_tenants_and_resources_on_other_documents(fixture):
    """The default-map shape: the message names them, its own document holds
    another tenant, and the names sit in their own fields elsewhere."""
    for tenant, resource, message in eseval.default_map_cases():
        holders = [d for d in fixture.docs if d.source.get("message") == message]
        assert len(holders) == 1
        flat = eseval.flatten(holders[0].source)
        assert tenant not in flat.values() and resource not in flat.values()
        assert any(eseval.flatten(d.source).get("labels.tenant_name") == tenant
                   for d in fixture.docs)
        assert any(eseval.flatten(d.source).get("labels.resource_name") == resource
                   for d in fixture.docs)


def test_the_one_hour_window_covers_the_messages_but_not_the_name_records(fixture):
    """The records are outside the case's hour and inside the margin: what
    makes this a vocabulary read rather than a harvest."""
    lo = eseval.NOW - timedelta(hours=4)
    hi = eseval.NOW - timedelta(hours=3)
    for tenant, _resource, message in eseval.default_map_cases():
        msg = next(d for d in fixture.docs if d.source.get("message") == message)
        assert lo <= eseval._parse_time(msg.source["@timestamp"]) <= hi
        rec = next(d for d in fixture.docs
                   if eseval.flatten(d.source).get("labels.tenant_name") == tenant
                   and d.source.get("message") == "Inventory refreshed")
        at = eseval._parse_time(rec.source["@timestamp"])
        assert at < lo and at > lo - timedelta(days=1)  # outside the hour, inside the margin


def test_the_skip_rules_leave_some_one_word_tenant_names_readable():
    """Named, not assumed: many real tenants are one word, and a one-word
    name that is an ordinary word or shorter than four characters is never
    made vocabulary, so it stays readable in message text."""
    dropped = {n: elastic.EsScrubber.vocabulary_skip(n)
               for n in eseval.DEFAULT_MAP_ONE_WORD}
    assert {n: w for n, w in dropped.items() if w} == {
        "Archive": "ordinary_word", "Vault": "ordinary_word", "Ops": "short"}
    assert sum(1 for w in dropped.values() if not w) == 5


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
    # the MCP section: real HTTP to a broker on the same fixture
    m = r["mcp"]
    assert m["protocol_ok"] and m["tool_calls"] > 20 and m["leaks"] == 0
    assert m["oracle"]["refused"] == m["oracle"]["cases"] == len(esquery.ORACLE_CASES)
    assert m["oracle"]["by_tool_layer"] == 5 and not m["oracle"]["wrong_code"]
    rj = m["rejected_requests"]
    assert rj["tried"] == rj["rejected"] >= 13 and rj["reached_kibana"] == 0
    assert m["label_round_trip"]["passed"] == m["label_round_trip"]["tried"] > 0
    assert all(m["launch"].values()) and m["log_leaks"] == 0
    assert {g for g in r["gates"] if g.startswith("mcp_")} == set(eseval.mcp_gates(m))
    text = eseval.format_report(r)
    assert "PASSED" in text and "mcp rejected" in text
    # the report carries counts and field names, never a planted value
    truth = eseval.generate(docs=300).truth
    blob = json.dumps(r).lower()
    assert not any(v.lower() in blob for v in truth if len(v) > 5)
