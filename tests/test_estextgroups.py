"""text_groups: the commonest messages in a scope, grouped after redaction."""

from __future__ import annotations

import json

import pytest

from hider import elastic, eseval, esquery

CFG = elastic.load(elastic.EXAMPLE)
GROUPS = {"g": {"type": "text_groups", "field": "message", "size": 10}}


def _session() -> elastic.EsScrubber:
    s = elastic.EsScrubber(CFG, tier2="none")
    s.seed("Contoso Holdings")
    return s


def _raw(messages: list[tuple[str, str]], index: str = "logs-app-*") -> dict:
    """A raw reply with one hit per (tenant, message)."""
    hits = [{"_index": eseval.backing_index(index), "_id": f"h{i}",
             "_source": {"@timestamp": f"2026-08-20T10:{i:02d}:00.000Z", "message": m,
                         "labels": {"tenant_name": t}}}
            for i, (t, m) in enumerate(messages)]
    return {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits}}}


def _exact_plan(s: elastic.EsScrubber) -> elastic.Plan:
    """The plan of the read's exact request: the whole scope as one page."""
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS}, CFG, s)
    return c.group_read.exact()[1]


def _grouped(s: elastic.EsScrubber, raw: dict) -> dict:
    return s.scrub_response(raw, _exact_plan(s)).output


def _stub_search(engine: eseval.StubEngine):
    return lambda body: {"id": "x", "isPartial": False, "isRunning": False,
                         "rawResponse": engine.search(body["params"]["index"],
                                                      body["params"]["body"])}


FAILED = {"field": "job.status", "op": "eq", "value": "Failed"}
BURST_Q = {"index": eseval.BURST_INDEX, "time_range": eseval.BURST_RANGE, "size": 0,
           "filters": [FAILED],
           "aggs": {"errors": {"type": "text_groups", "field": "job.status_message", "size": 10}}}


# -- the key ---------------------------------------------------------------------


def test_the_key_masks_every_hidden_value_and_number_as_one_placeholder():
    k = elastic.text_group_key
    assert k("Throttled by SharePoint for <Org-01>: Retry-After 12s, object <Guid-03>") == \
        "Throttled by SharePoint for <*>: Retry-After <*>, object <*>"
    assert k("Worker ctr-amer-s01 picked up user-02@tenant-01.example at 203.0.113.7.") == \
        "Worker <*> picked up <*> at <*>."
    assert k("token <REDACTED:API_KEY> rejected") == "token <*> rejected"
    assert k("build 8.4.1;  Scheduler tick") == "build <*>; Scheduler tick"


@pytest.mark.parametrize("text,key", [
    ("returned HTTP 429 after 3 retries", "returned HTTP 429 after <*> retries"),
    ("HTTP/1.1 503 Service Unavailable", "HTTP/1.1 503 Service Unavailable"),
    ("last status 503", "last status 503"),
    ("request failed, status=404", "request failed, status=404"),
    ("StatusCode: 500", "StatusCode: 500"),
    ("error code: 0x80070005.", "error code: 0x80070005."),
    ("upload failed with 0x80070005 after 2 tries", "upload failed with 0x80070005 after <*> tries"),
    ("sign-in refused, code=AADSTS50076", "sign-in refused, code=AADSTS50076"),
    ("process exit code 1.", "process exit code 1."),
    ("SQL error 1205 deadlock", "SQL error 1205 deadlock"),
])
def test_a_code_stays_readable(text, key):
    assert elastic.text_group_key(text) == key


@pytest.mark.parametrize("text,key", [
    # not a code: no code word, too long, a duration, a plural
    ("GET /api/sites 429 in 333 ms", "GET /api/sites <*> in <*> ms"),
    ("error 12345678 at offset 9", "error <*> at offset <*>"),
    ("status 200ms", "status <*>"),
    ("errors 5", "errors <*>"),
    # a hidden value right after a code word is hidden, never a code
    ("status <Org-01>", "status <*>"),
    ("code user-01@tenant-01.example", "code <*>"),
])
def test_what_is_not_a_code_is_masked(text, key):
    assert elastic.text_group_key(text) == key


# -- what it compiles to ------------------------------------------------------------


def test_the_read_spreads_a_pages_worth_of_documents_over_the_scopes_time_span():
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS,
                               "time_range": {"gte": "now-7d", "lte": "now"},
                               "filters": [FAILED]}, CFG, _session())
    body = c.body["params"]["body"]
    # the read's first request: a count capped at the slow bound, no
    # documents, no aggregations - cheap whatever the scope holds
    assert body["size"] == 0 and "aggs" not in body and "sort" not in body
    assert body["track_total_hits"] == elastic.TEXT_GROUP_SLOW_DOCS
    assert c.plan.groups is None
    # the sampling pass: a histogram over the span with the newest
    # documents of each slice, a page's source for each
    strata_body, strata_plan = c.group_read.strata_read(*c.group_read.window)
    sb = strata_body["params"]["body"]
    assert sb["size"] == 0 and "sort" not in sb and "from" not in sb
    strata = sb["aggs"][elastic.STRATA_AGG]
    assert strata["date_histogram"] == {"field": "@timestamp", "fixed_interval": "12600s",
                                        "min_doc_count": 1}
    sample = strata["aggs"][elastic.STRATA_HITS_AGG]["top_hits"]
    assert sample == {"size": 20, "sort": [{"@timestamp": {"order": "desc"}}],
                      "_source": {"includes": CFG.source_includes()}}
    # 7 days in 12600s slices is 48 aligned slices, 49 across a boundary:
    # at most 50 x 20 = the sample, never more per request than a page
    # of the whole scope would read
    assert c.group_read.strata * c.group_read.per_stratum == elastic.TEXT_GROUP_SAMPLE
    assert c.group_read.per_cap == min(elastic.TEXT_GROUP_MAX_PER_STRATUM, CFG.max_hits)
    assert strata_plan.groups == elastic.GroupPlan("g", "message", 10, "strata", 50, 20)
    assert strata_plan.aggs[elastic.STRATA_AGG].subs[elastic.STRATA_HITS_AGG].type == "top_hits"
    # the exact request is the whole scope as one page, the read this replaced
    exact_body, exact_plan = c.group_read.exact()
    eb = exact_body["params"]["body"]
    assert eb["size"] == elastic.TEXT_GROUP_SAMPLE and "aggs" not in eb
    assert eb["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert eb["_source"] == {"includes": CFG.source_includes()}
    assert exact_plan.groups == elastic.GroupPlan("g", "message", 10, "exact")


def test_without_a_closed_time_range_the_span_comes_from_a_bounds_request_first():
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS}, CFG, _session())
    body = c.body["params"]["body"]
    assert c.group_read.window is None and body["size"] == 0
    assert body["aggs"] == {"first": {"min": {"field": "@timestamp"}},
                            "last": {"max": {"field": "@timestamp"}}}
    assert c.plan.groups is None
    # one end only is not a closed range either
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS,
                               "time_range": {"gte": "now-7d"}}, CFG, _session())
    assert c.group_read.window is None


def test_a_sites_lower_caps_shrink_the_slices_and_what_each_carries():
    import dataclasses
    small = dataclasses.replace(CFG, max_buckets=10, max_hits=30)
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS}, small,
                              elastic.EsScrubber(small, tier2="none"))
    # 10 slices of 30: a slice never carries more than a page, and never more
    # than Elasticsearch's inner result window allows
    assert (c.group_read.strata, c.group_read.per_stratum) == (10, 30)


def test_the_respread_allocation_is_fair_deterministic_and_never_more_than_the_sample():
    alloc = esquery._allocate
    # one heavy slice takes the whole sample; a slice smaller than its
    # share is read whole and its surplus goes where the documents are
    assert alloc([11000], 1000) == [1000]
    assert alloc([5, 3000, 7], 1000) == [5, 988, 7]
    assert alloc([10, 10, 2000, 3000], 1000) == [10, 10, 490, 490]
    # a uniform scope stays uniform; the remainder goes to the widest
    # slices, oldest first on a tie
    assert alloc([40] * 50, 1000) == [20] * 50
    assert alloc([700, 500], 1000) == [500, 500]
    assert alloc([999, 998, 997], 1000) == [334, 333, 333]
    # a scope smaller than the sample is read whole
    assert alloc([600, 300], 1000) == [600, 300]
    for counts in ([11000], [5, 3000, 7], [40] * 50, [999, 998, 997]):
        assert sum(alloc(counts, 1000)) <= 1000


def test_a_scope_past_the_slow_bound_is_refused_before_the_sampling_pass():
    s = _session()
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS,
                               "time_range": {"gte": "now-7d", "lte": "now"},
                               "filters": [FAILED]}, CFG, s)
    sent = []

    def search(body):
        sent.append(body)
        return {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
            "hits": {"total": {"value": elastic.TEXT_GROUP_SLOW_DOCS, "relation": "gte"},
                     "hits": []}}}

    with pytest.raises(elastic.Refused) as e:
        esquery.read_text_groups(search, s, c.group_read)
    # one early-terminated count reached the engine and nothing else; the
    # refusal carries counts and what to do, never a value
    assert e.value.code == "slow_read" and len(sent) == 1
    assert "aggs" not in sent[0]["params"]["body"]
    assert f"{elastic.TEXT_GROUP_SLOW_DOCS:,}" in e.value.message
    assert "narrow" in e.value.message.lower()
    # the windowless path refuses off its bounds request the same way
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS}, CFG, _session())
    sent.clear()

    def bounds_search(body):
        sent.append(body)
        return {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
            "hits": {"total": {"value": elastic.TEXT_GROUP_SLOW_DOCS, "relation": "gte"},
                     "hits": []},
            "aggregations": {"first": {"value": 0.0}, "last": {"value": 1000.0}}}}

    with pytest.raises(elastic.Refused) as e:
        esquery.read_text_groups(bounds_search, _session(), c.group_read)
    assert e.value.code == "slow_read" and len(sent) == 1


def test_a_respread_reply_wider_than_asked_is_withheld_before_a_document_is_read():
    s = _session()
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS,
                               "time_range": {"gte": "now-7d", "lte": "now"}}, CFG, s)
    body, plan = c.group_read.respread([(0, 150)], 12_600_000)
    # 150 documents owed over the 100-per-range cap: two equal sub-ranges
    aggs = body["params"]["body"]["aggs"]
    assert [a["aggs"][elastic.STRATA_HITS_AGG]["top_hits"]["size"] for a in aggs.values()] == [75, 75]
    assert plan.groups.phase == "respread" and plan.groups.ranges == (("s00", 75), ("s01", 75))

    def reply(hits_per_range: dict[str, int], drop: str | None = None) -> dict:
        aggs_node = {}
        for name, size in plan.groups.ranges:
            if name == drop:
                continue
            rows = [{"_index": eseval.backing_index("logs-app-*"), "_id": f"{name}-{j}",
                     "_source": {"@timestamp": "2026-08-20T10:00:00.000Z",
                                 "message": "Scheduler tick"}}
                    for j in range(hits_per_range.get(name, 0))]
            aggs_node[name] = {"doc_count": 200, elastic.STRATA_HITS_AGG: {
                "hits": {"total": {"value": 200, "relation": "eq"}, "hits": rows}}}
        return {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
            "hits": {"total": {"value": 400, "relation": "eq"}, "hits": []},
            "aggregations": aggs_node}}

    harvested = []
    s._harvest_hit = lambda h: harvested.append(h)
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(reply({"s00": 76, "s01": 0}), plan)
    assert e.value.code == "size_cap" and harvested == []
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(reply({"s00": 75}, drop="s01"), plan)
    assert e.value.code == "malformed" and harvested == []
    # what fits is read, each range scaled by its own documents
    s._harvest_hit = elastic.EsScrubber._harvest_hit.__get__(s)
    g = s.scrub_response(reply({"s00": 75, "s01": 75}), plan).output["aggregations"]["g"]
    assert g["sampled"] == 150 and g["strata"] == 2 and not g["exact"]
    assert g["buckets"][0]["doc_count"] == 400


def test_a_group_placeholder_in_a_phrase_is_refused_and_a_label_is_not():
    s = _session()
    with pytest.raises(elastic.Refused) as e:
        esquery.compile_query({"index": "logs-app-*", "filters": [
            {"field": "message", "op": "phrase", "value": "failed: access denied for <n>"}]}, CFG, s)
    assert e.value.code == "bad_value" and "placeholder" in e.value.message
    with pytest.raises(elastic.Refused) as e:
        esquery.compile_query({"index": "logs-app-*", "filters": [
            {"field": "message", "op": "phrase", "value": "rate limit for <*> reached"}]}, CFG, s)
    assert e.value.code == "bad_value" and "placeholder" in e.value.message
    esquery.compile_query({"index": "logs-app-*", "filters": [
        {"field": "message", "op": "phrase", "value": "throttled for <Org-01>"}]}, CFG, s)


# -- what comes back ------------------------------------------------------------------


def test_messages_differing_only_by_a_hidden_name_are_one_group():
    msgs = [("Contoso Holdings", "Rate limit for Contoso Holdings reached, backing off 30s"),
            ("Fabrikam Partners", "Rate limit for Fabrikam Partners reached, backing off 12s"),
            ("Fabrikam Partners", "Scheduler tick")]
    s = _session()
    s.label_for(CFG.rule("labels.tenant_name"), "Fabrikam Partners")
    out = _grouped(s, _raw(msgs))
    g = out["aggregations"]["g"]
    assert g["buckets"] == [{"key": "Rate limit for <*> reached, backing off <*>", "doc_count": 2,
                             "sampled_count": 2},
                            {"key": "Scheduler tick", "doc_count": 1, "sampled_count": 1}]
    assert g["sampled"] == 3 and g["groups"] == 2 and out["hits"]["hits"] == []
    # every document in scope was read: exact counts, no margin, the order settled
    assert g["exact"] and g["coverage"] == 1.0 and g["order_settled"] == 2
    assert not any("margin" in b for b in g["buckets"])
    # the same documents as a page show the two names as two labels
    page = s.scrub_response(_raw(msgs), elastic.Plan("logs-app-*", size=3)).output
    texts = {h["_source"]["message"] for h in page["hits"]["hits"]}
    assert len({t for t in texts if t.startswith("Rate limit")}) == 2
    blob = json.dumps(out)
    assert "Contoso" not in blob and "Fabrikam" not in blob


def test_a_group_response_makes_no_label_usable_and_a_page_does():
    msgs = [("Fabrikam Partners", "Rate limit for Fabrikam Partners reached")]
    s = _session()
    before = set(s.shown)
    _grouped(s, _raw(msgs))
    assert s.shown == before
    s.scrub_response(_raw(msgs), elastic.Plan("logs-app-*", size=1))
    assert len(s.shown) > len(before)


def test_a_leak_in_any_sampled_document_withholds_the_groups_as_it_withholds_a_page():
    msgs = [("Contoso Holdings", "Rate limit for Contoso Holdings reached")]
    for plan_of in ("groups", "page"):
        s = _session()
        # redaction that let a value through: no rewrite and no sweep, so
        # only the leak check stands between the value and the reply
        s._rewrite_hit = lambda h: h
        s._sweep = lambda out: out
        with pytest.raises(elastic.Refused) as e:
            if plan_of == "groups":
                _grouped(s, _raw(msgs))
            else:
                s.scrub_response(_raw(msgs), elastic.Plan("logs-app-*", size=1))
        assert e.value.code == "leak"


def test_a_reply_wider_than_the_sample_is_withheld():
    s = _session()
    msgs = [("Contoso Holdings", "Scheduler tick")] * (elastic.TEXT_GROUP_SAMPLE + 1)
    with pytest.raises(elastic.Refused) as e:
        _grouped(s, _raw(msgs))
    assert e.value.code == "size_cap"


# -- through the bridge, against the guessing run and the pages ----------------------


def test_through_the_bridge_a_count_then_an_exact_read_and_the_log_has_the_shape_only():
    fx = eseval.Fixture(eseval.stream_name_docs(), [], [])
    cfg = eseval.stream_name_map()
    engine = eseval.StubEngine(fx, (eseval.STREAM_INDEX,))
    vocab, _ = eseval.build_vocabulary(cfg, engine)
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    n = len(engine.requests)
    out, refused, _dt, _c = case.call({"index": eseval.STREAM_INDEX, "time_range": eseval.STREAM_RANGE,
                                       "size": 0, "aggs": GROUPS})
    # the capped count said the scope fits one page, so it was read whole
    assert refused is None and len(engine.requests) == n + 2
    assert engine.requests[n]["body"]["track_total_hits"] == elastic.TEXT_GROUP_SLOW_DOCS
    assert sum(b["doc_count"] for b in out["aggregations"]["g"]["buckets"]) == 3
    assert out["aggregations"]["g"]["exact"] and out["aggregations"]["g"]["requests"] == 2
    rows = [json.loads(x) for x in (case.directory / "decisions.jsonl").read_text().splitlines()]
    row = [r for r in rows if "vocabulary" not in r][-1]
    assert row["aggs"] == [{"name": "g", "type": "text_groups", "field": "message", "aggs": []}]
    assert row["hits_shown"] == 0 and row["new_labels"] == 0
    # the read's account of itself, counts only
    assert (row["requests"], row["sampled"], row["exact"], row["strata"]) == (2, 3, True, 1)
    assert eseval.STREAM_JOB not in json.dumps(out)


def test_the_guessing_run_confirms_no_more_and_none_cheaper_with_groups():
    fx = eseval.Fixture(eseval.stream_name_docs(), [], [])
    g = eseval.run_compound_guess_eval(fx)
    assert eseval.text_groups_guess_holds(g) and eseval.compound_guess_holds(g)
    a = g["attackers"]
    assert a["groups_any_of"]["requests_per_guess"] >= a["filters_agg"]["requests_per_guess"]
    assert a["groups_single"]["confirmed"] <= g["budget"]


def test_groups_equal_the_pages_of_the_same_documents_grouped():
    fx = eseval.generate(docs=200)
    engine = eseval.StubEngine(fx, CFG.indices)
    vocab, _ = eseval.build_vocabulary(CFG, engine)
    t = eseval.run_text_groups_eval(CFG, fx, vocab, tier2="none")
    assert eseval.text_groups_page_equivalent(t), t
    for r in t["scopes"]:
        if r.get("estimated"):
            continue
        assert r["groups"] < r["distinct_texts_on_pages"]       # what the engineer gives up
        # the read costs at most one request more than paging the scope:
        # the capped count in front of the exact page
        assert r["labels_made_usable"] == 0 and r["page_requests"] + 1 >= r["group_requests"]
        assert r["group_requests"] <= 2 and r["exact"]


# -- a scope wider than the sample ------------------------------------------------


def _burst_case():
    cfg, _fx, engine, vocab = eseval.burst_world()
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    case.scrubber.seed(eseval.BURST_TENANTS[0])
    return case, engine


def _truth_keys(case) -> dict[str, int]:
    out = {}
    for template, n in ((eseval.BURST_STEADY_MESSAGE, eseval.BURST_STEADY),
                        (eseval.BURST_NOISY_MESSAGE, eseval.BURST_NOISY),
                        (eseval.BURST_RARE_MESSAGE, eseval.BURST_RARE)):
        msg = template.replace("{TENANT}", eseval.BURST_TENANTS[0]).replace("{N}", "7")
        label = case.scrubber.known[eseval.jsonscrub_norm(eseval.BURST_TENANTS[0])]
        out[elastic.text_group_key(msg.replace(eseval.BURST_TENANTS[0], label))] = n
    return out


def test_a_wide_scope_is_sampled_over_its_span_and_the_reply_says_how_far_to_trust_it():
    case, engine = _burst_case()
    truth = _truth_keys(case)
    n = len(engine.requests)
    out, refused, _dt, _c = case.call(BURST_Q)
    assert refused is None
    g = out["aggregations"]["errors"]
    # the capped count, then one sampling pass of a page's worth of
    # documents from across the week; the sample already landed nearly
    # whole, so no re-spread runs
    assert len(engine.requests) == n + 2 and g["requests"] == 2
    assert g["sampled"] <= elastic.TEXT_GROUP_SAMPLE and g["strata"] == 49
    assert g["total"] == 2700 and not g["exact"] and 0.3 < g["coverage"] < 0.4
    # the week's order, with the steady error first although the newest
    # thousand documents are all the noisy one
    assert [b["key"] for b in g["buckets"]] == sorted(truth, key=lambda k: -truth[k])
    for b in g["buckets"]:
        assert abs(b["doc_count"] - truth[b["key"]]) <= b["margin"], b
        assert b["margin"] < truth[b["key"]] / 2
    assert g["order_settled"] == 3
    # the read it replaced: the newest documents in scope, as one page
    _b, exact_plan = _c.group_read.exact() if _c else (None, None)
    c = esquery.compile_query(BURST_Q, case.bridge.config, case.scrubber)
    body, plan = c.group_read.exact()
    old = case.scrubber.scrub_response(_stub_search(engine)(body), plan).output["aggregations"]["errors"]
    assert [b["key"] for b in old["buckets"]] == [max(truth, key=lambda k: k.startswith("Connection"))]
    assert old["sampled"] == 1000 and not old["exact"]
    # no label became usable either way, and no value is in either reply
    assert case.scrubber.shown == {case.scrubber.known[eseval.jsonscrub_norm(eseval.BURST_TENANTS[0])]}
    blob = json.dumps(out) + json.dumps(old)
    assert not any(t in blob for t in eseval.BURST_TENANTS + eseval.BURST_JOBS)


def test_without_a_time_range_the_bounds_come_from_one_more_request():
    case, engine = _burst_case()
    truth = _truth_keys(case)
    n = len(engine.requests)
    q = {k: v for k, v in BURST_Q.items() if k != "time_range"}
    out, refused, _dt, _c = case.call(q)
    assert refused is None
    g = out["aggregations"]["errors"]
    assert len(engine.requests) == n + 2 and g["requests"] == 2
    first = engine.requests[n]["body"]
    assert first["size"] == 0 and set(first["aggs"]) == {"first", "last"}
    assert [b["key"] for b in g["buckets"]] == sorted(truth, key=lambda k: -truth[k])
    assert g["strata"] >= 48 and not g["exact"]


def test_documents_in_one_slice_of_the_window_get_the_sample_respread_over_them():
    # one tenant's day: 3,000 failures inside one half hour of a day-wide
    # window. The uniform pass lands one slice's share (20 documents); the
    # re-spread reads the whole sample from inside the half hour, cut into
    # ranges of at most per_cap, each scaled by its own document count.
    cfg, _fx, engine, vocab = eseval.dense_world()
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    tenant = case.scrubber.seed(eseval.DENSE_TENANT)
    n = len(engine.requests)
    out, refused, _dt, _c = case.call({
        "index": eseval.DENSE_INDEX, "time_range": eseval.DENSE_RANGE, "size": 0,
        "filters": [{"field": "labels.tenant_name", "op": "eq", "value": tenant},
                    {"field": "job.status", "op": "eq", "value": "Failed"}],
        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message", "size": 10}}})
    assert refused is None
    g = out["aggregations"]["errors"]
    # three requests: the capped count, the uniform pass, the re-spread
    assert len(engine.requests) == n + 3 and g["requests"] == 3
    assert g["sampled"] == elastic.TEXT_GROUP_SAMPLE and g["total"] == 3000 and not g["exact"]
    # the re-spread request asked for the sample and nothing more, in
    # ranges of at most per_cap documents each
    respread = engine.requests[-1]["body"]["aggs"]
    sizes = [a["aggs"][elastic.STRATA_HITS_AGG]["top_hits"]["size"] for a in respread.values()]
    assert sum(sizes) == elastic.TEXT_GROUP_SAMPLE
    assert max(sizes) <= min(elastic.TEXT_GROUP_MAX_PER_STRATUM, cfg.max_hits)
    # all three groups, in the true order, where the uniform pass alone saw
    # only the half hour's newest minute
    assert [b["key"].split(" for ")[0] for b in g["buckets"]] == [
        "Replica sync deadlocked", "Connection pool exhausted", "License revalidation failed"]
    assert g["order_settled"] == 3
    # no label made usable and no value in the reply
    assert case.scrubber.shown == {tenant}
    blob = json.dumps(out)
    assert eseval.DENSE_TENANT not in blob and eseval.DENSE_JOB not in blob
    assert "_slices" not in g
    # asking again returns the same reply: the allocation reads counts, not
    # anything typed, and the ranges are deterministic
    again, refused, _dt, _c = case.call({
        "index": eseval.DENSE_INDEX, "time_range": eseval.DENSE_RANGE, "size": 0,
        "filters": [{"field": "labels.tenant_name", "op": "eq", "value": tenant},
                    {"field": "job.status", "op": "eq", "value": "Failed"}],
        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message", "size": 10}}})
    assert refused is None and again["aggregations"]["errors"] == g


def test_declared_miss_a_burst_at_the_end_of_one_range_is_still_counted_as_that_range():
    # the re-spread shrinks the newest-first bias from the whole sample to
    # one range's share, and the margin's assumption (what was read in a
    # range stands for the range) still does not cover a burst at a range's
    # very end: the tail error is overcounted by the steady documents that
    # share its range, and the steady one undercounted by the same amount
    cfg, _fx, engine, vocab = eseval.dense_world()
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    tenant = case.scrubber.seed(eseval.DENSE_TENANT)
    out, _refused, _dt, _c = case.call({
        "index": eseval.DENSE_INDEX, "time_range": eseval.DENSE_RANGE, "size": 0,
        "filters": [{"field": "labels.tenant_name", "op": "eq", "value": tenant},
                    {"field": "job.status", "op": "eq", "value": "Failed"}],
        "aggs": {"errors": {"type": "text_groups", "field": "job.status_message", "size": 10}}})
    by = {b["key"].split(" for ")[0]: b for b in out["aggregations"]["errors"]["buckets"]}
    tail = by["Connection pool exhausted"]
    assert tail["doc_count"] > eseval.DENSE_TAIL
    assert tail["doc_count"] - tail["margin"] > eseval.DENSE_TAIL
    # the bias is one range's share now; before the re-spread the same read
    # put the whole scope's count on this group (3,000 against 480)
    assert tail["doc_count"] - eseval.DENSE_TAIL < 200


def test_a_scope_that_fits_the_sample_but_not_its_slices_is_read_whole_in_a_second_request():
    # three hundred failures in one minute, asked about over a week: the
    # slice they fall in holds more than its share, the scope fits a page
    docs = [d for d in eseval.burst_docs() if d.source["job"]["status"] == "Failed"][-300:]
    cfg = eseval.burst_map()
    fx = eseval.Fixture(docs, [], [])
    engine = eseval.StubEngine(fx, (eseval.BURST_INDEX,))
    vocab, _b = eseval.build_vocabulary(cfg, engine)
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    n = len(engine.requests)
    out, refused, _dt, _c = case.call(BURST_Q)
    assert refused is None
    g = out["aggregations"]["errors"]
    assert g["requests"] == 2 and len(engine.requests) == n + 2
    assert g["exact"] and g["sampled"] == g["total"] == 300 and g["strata"] == 1
    assert [b["doc_count"] for b in g["buckets"]] == [300]
    assert engine.requests[-1]["body"]["size"] == elastic.TEXT_GROUP_SAMPLE


def test_a_strata_reply_wider_than_asked_is_withheld_before_a_document_is_read():
    s = _session()
    c = esquery.compile_query({"index": "logs-app-*", "size": 0, "aggs": GROUPS,
                               "time_range": {"gte": "now-7d", "lte": "now"}}, CFG, s)
    plan = c.group_read.strata_read(*c.group_read.window)[1]

    def reply(buckets: list[tuple[int, int]]) -> dict:
        bs = []
        for i, (docs, hits) in enumerate(buckets):
            rows = [{"_index": eseval.backing_index("logs-app-*"), "_id": f"h{i}-{j}",
                     "_source": {"@timestamp": "2026-08-20T10:00:00.000Z",
                                 "message": "Scheduler tick"}} for j in range(hits)]
            bs.append({"key": 1_000_000 * i, "doc_count": docs, elastic.STRATA_HITS_AGG: {
                "hits": {"total": {"value": docs, "relation": "eq"}, "hits": rows}}})
        return {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
            "hits": {"total": {"value": sum(d for d, _h in buckets), "relation": "eq"}, "hits": []},
            "aggregations": {elastic.STRATA_AGG: {"buckets": bs}}}}

    harvested = []
    s._harvest_hit = lambda h: harvested.append(h)
    for bad in ([(30, 21)], [(5, 5)] * 51, [(20, 20)] * 50 + [(1, 1)]):
        with pytest.raises(elastic.Refused) as e:
            s.scrub_response(reply(bad), plan)
        assert e.value.code == "size_cap" and harvested == []
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response({"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}}, plan)
    assert e.value.code == "malformed"
    # what fits is read
    s._harvest_hit = elastic.EsScrubber._harvest_hit.__get__(s)
    g = s.scrub_response(reply([(20, 20)] * 50), plan).output["aggregations"]["g"]
    assert g["exact"] and g["sampled"] == 1000 and g["buckets"][0]["doc_count"] == 1000


# -- the estimate ------------------------------------------------------------------


def test_a_slice_read_whole_counts_exactly_and_a_partial_one_is_scaled():
    agg = elastic.group_estimate([(10, ["a"] * 6 + ["b"] * 4), (100, ["a"] * 5 + ["b"] * 5)],
                                 10, 110)
    by = {b["key"]: b for b in agg["buckets"]}
    assert not agg["exact"] and agg["strata_read_whole"] == 1 and agg["sampled"] == 20
    assert by["a"]["doc_count"] == 6 + 50 and by["b"]["doc_count"] == 4 + 50
    assert by["a"]["sampled_count"] == 11 and "margin" in by["a"]
    # the whole slice adds no uncertainty; the partial one does, for both
    assert by["a"]["margin"] == by["b"]["margin"] > 0
    assert agg["order_settled"] == 0 and agg["coverage"] == round(20 / 110, 4)


def test_exactness_margins_and_the_settled_order():
    agg = elastic.group_estimate([(3, ["a", "a", "b"]), (2, ["c", "c"])], 10, 5)
    assert agg["exact"] and agg["coverage"] == 1.0 and agg["strata_read_whole"] == 2
    assert [(b["key"], b["doc_count"]) for b in agg["buckets"]] == [("a", 2), ("c", 2), ("b", 1)]
    # a tie is not a settled order even when exact
    assert agg["order_settled"] == 0 and not any("margin" in b for b in agg["buckets"])
    agg = elastic.group_estimate([(3, ["a", "a", "b"])], 10, 3)
    assert agg["order_settled"] == 2
    # a group seen in every sampled document of a slice still has a margin
    agg = elastic.group_estimate([(1000, ["b"] * 20)], 10, 1000)
    b = agg["buckets"][0]
    assert b["doc_count"] == 1000 and b["margin"] > 0 and agg["order_settled"] == 1
    # documents without a text are read but in no group; documents in no
    # slice (no time field) are reported
    agg = elastic.group_estimate([(4, ["a", None, "a", None])], 10, 6)
    assert agg["with_field"] == 2 and agg["unbucketed"] == 2 and agg["sampled"] == 4
    # only size groups leave; the rest are counted together
    agg = elastic.group_estimate([(4, ["a", "a", "b", "c"])], 1, 4)
    assert [b["key"] for b in agg["buckets"]] == ["a"] and agg["sum_other_doc_count"] == 2
    assert agg["groups"] == 3


def test_declared_miss_a_burst_at_the_end_of_one_slice_is_counted_as_the_whole_slice():
    # a slice of 1,000 documents: 980 steady, then 20 noisy ones at its very
    # end. The newest twenty are read, so the noisy message is estimated at
    # the slice's full 1,000 and the steady one at none, and the margin does
    # not cover it: within a slice the read is still newest-first
    agg = elastic.group_estimate([(1000, ["noisy"] * 20)], 10, 1000)
    b = agg["buckets"][0]
    assert b["key"] == "noisy" and b["doc_count"] == 1000 and 1000 - b["margin"] > 20
    assert agg["groups"] == 1


# -- a hidden value's type must not split a group --------------------------------


def _doc(i: int, message: str, **fields) -> dict:
    src = {"@timestamp": f"2026-08-20T10:{i:02d}:00.000Z", "message": message}
    for path, v in fields.items():
        node = src
        *head, last = path.split("__")
        for k in head:
            node = node.setdefault(k, {})
        node[last] = v
    return {"_index": eseval.backing_index("logs-app-*"), "_id": f"t{i}", "_source": src}


def _groups_of(docs: list[dict], tier2: str = "none") -> list[dict]:
    s = elastic.EsScrubber(CFG, tier2=tier2)
    raw = {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": {
        "hits": {"total": {"value": len(docs), "relation": "eq"}, "hits": docs}}}
    return s.scrub_response(raw, _exact_plan(s)).output["aggregations"]["g"]["buckets"]


G1 = "5b0f7c2e-8a41-4d6b-9c3e-1f2a3b4c5d6e"
G2 = "c7d8e9f0-1a2b-4c3d-8e4f-5a6b7c8d9e0f"


def test_an_id_labelled_by_its_field_and_one_labelled_in_text_are_one_group():
    docs = [_doc(1, f"Job {G1} scheduled, 3 sites enqueued", job__id=G1),
            _doc(2, f"Job {G2} scheduled, 3 sites enqueued")]
    assert [b["doc_count"] for b in _groups_of(docs)] == [2], _groups_of(docs)


def test_one_id_seen_in_two_fields_keeps_one_label_and_one_group():
    docs = [_doc(1, f"Job {G1} scheduled", job__id=G1),
            _doc(2, f"Job {G1} scheduled", job__session_id=G1)]
    assert [b["doc_count"] for b in _groups_of(docs)] == [2], _groups_of(docs)


def test_a_name_known_from_its_field_and_one_found_in_text_are_one_group():
    docs = [_doc(1, "Rate limit for Contoso Holdings reached", labels__tenant_name="Contoso Holdings"),
            _doc(2, "Rate limit for Brindlewood Partners reached")]
    assert [b["doc_count"] for b in _groups_of(docs, tier2="classifier")] == [2], \
        _groups_of(docs, tier2="classifier")


def test_codes_split_groups_and_numbers_that_are_not_codes_do_not():
    docs = [_doc(1, "Site returned HTTP 429 after 3 retries"),
            _doc(2, "Site returned HTTP 429 after 7 retries"),
            _doc(3, "Site returned HTTP 500 after 2 retries"),
            _doc(4, "Upload took 912 ms, 3 items"), _doc(5, "Upload took 87 ms, 41 items")]
    assert {b["key"]: b["doc_count"] for b in _groups_of(docs)} == {
        "Site returned HTTP 429 after <*> retries": 2,
        "Site returned HTTP 500 after <*> retries": 1,
        "Upload took <*> ms, <*> items": 2}
