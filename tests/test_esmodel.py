"""The model-utility harness without a model: what the stub serves, how an
answer block is parsed and scored, and what a row may carry."""

import json

import pytest

from hider import elastic, esbridge, eseval, esmodel


@pytest.fixture(autouse=True)
def _clock():
    saved = esbridge.clock
    esbridge.clock = lambda: eseval.NOW.timestamp()
    yield
    esbridge.clock = saved


def _q(key):
    return next(q for q in esmodel.QUESTIONS if q.key == key)


def test_the_stub_serves_a_pieced_reply_over_http_as_kibana_would():
    """A search whose engine wall time is past its limit stays running on
    the stub until the session's own deadline deletes it, as on Kibana -
    so the bridge's piece read, and a bounded terms, can be served to a
    model through the real HTTP path (before, the stub dropped the
    connection and the bridge saw a transport error)."""
    w = esmodel.relay_world()
    cfg0 = elastic.parse({**w.raw_map, "clusters": {"stub": "https://x.example.net"}}, source="t")
    kb = eseval.StubKibana(w.engine(w.fx, cfg0), cookie="sid=synthetic").start()
    try:
        cfg = elastic.parse({**w.raw_map, "clusters": {"stub": kb.url}}, source="t")
        session = esbridge.KibanaSession(esbridge.UrllibTransport(kb.cookie), poll_interval=0.05,
                                         poll_timeout=cfg.poll_timeout_s)
        b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), session)
        q = {"index": eseval.FAIL_INDEX, "time_range": {"gte": "now-30d", "lte": "now"},
             "size": 0, "aggs": {"srv": {"type": "terms", "field": "agent.name", "size": 10}}}
        out = b.run("stub", q, probe=False).output
        assert out["pieces"]["read"] == "bounded" and out["pieces"]["covered_share"] == 1.0
        assert out["aggregations"]["srv"]["order_settled"] == 3
        assert kb.deleted                        # the timed-out searches were released
    finally:
        kb.stop()


def test_an_answer_block_is_the_last_fenced_answer_json():
    assert esmodel.parse_answer("text\n```answer\n{\"a\": 1}\n```\nmore\n```answer\n"
                                "{\"a\": 2}\n```") == {"a": 2}
    assert esmodel.parse_answer("no block") == "<no block>"
    assert esmodel.parse_answer("```answer\nnot json\n```") == "<bad json>"
    q = _q("servers")
    assert esmodel.score(q, "I think s1", {"s1": 2}) == ("wrong", "no_answer_block")


def test_servers_and_onset_score_exactly_in_label_space():
    want = {"srv-a": 3, "srv-b": 1}
    s = _q("servers").score
    assert s({"servers": {"srv-a": 3, "srv-b": 1}}, want) == ("answered", None)
    assert s({"servers": {"srv-a": 3}}, want) == ("wrong", "server_set_differs")
    assert s({"servers": {"srv-a": 2, "srv-b": 1}}, want) == ("wrong", "counts_differ")
    assert s({"servers": None}, want) == ("blocked", "no_answer")
    o = _q("onset").score
    t = eseval.NOW.timestamp()
    iso = eseval.NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert o({"first_failure": iso}, t) == ("answered", None)
    assert o({"first_failure": "2026-01-01T00:00:00Z"}, t) == ("wrong", "time_differs")
    assert o({"first_failure": None}, t) == ("blocked", "no_answer")


TRUTH = {f"s{i:02d}": c for i, c in
         ((1, 600), (2, 450), (3, 300), (5, 160), (6, 160), (7, 160), (8, 160), (4, 150),
          (9, 120), (10, 120), (11, 120), (12, 120))}


def _row(s, low, high=None):
    return {"server": s, "failures": low, "failures_max": high}


def test_a_bounded_list_is_answered_only_when_every_claim_it_makes_is_true():
    s = _q("top_servers_month").score
    honest = {"servers": [_row("s01", 600), _row("s02", 450), _row("s03", 300),
                          _row("s05", 160), _row("s06", 160), _row("s07", 160),
                          _row("s08", 145, 160), _row("s09", 120), _row("s10", 120),
                          _row("s11", 120)],
              "complete_and_ordered": False, "certain_order_for_first": 3}
    assert s(honest, TRUTH) == ("answered", "order_claims_true")
    # the same list claimed complete: it is not (s04 is missing)
    assert s({**honest, "complete_and_ordered": True}, TRUTH) == \
        ("wrong", "claimed_complete_but_is_not")
    # a lower bound stated as an exact count
    lied = dict(honest, servers=[*honest["servers"][:6], _row("s08", 145),
                                 *honest["servers"][7:]])
    assert s(lied, TRUTH) == ("wrong", "count_stated_exact_is_wrong")
    # claiming more of the order than is true
    assert s({**honest, "certain_order_for_first": 10}, TRUTH) == \
        ("wrong", "certain_prefix_is_wrong")
    # the exact top ten (ties as a set), claimed complete: answered
    exact = {"servers": [_row(k, TRUTH[k]) for k in
                         ("s01", "s02", "s03", "s08", "s07", "s06", "s05", "s04", "s09", "s12")],
             "complete_and_ordered": True, "certain_order_for_first": 10}
    assert s(exact, TRUTH) == ("answered", None)
    assert s({"servers": None}, TRUTH) == ("blocked", "no_answer")
    # a maximum equal to its count is an exact count (the model run wrote it so)
    top3 = esmodel._top_scorer(3)
    same = {"servers": [_row("s01", 600, 600), _row("s02", 450, 450), _row("s03", 300, 300)],
            "complete_and_ordered": True, "certain_order_for_first": 3}
    assert top3(same, TRUTH) == ("answered", None)


def test_a_partial_count_is_honest_only_when_called_partial():
    s = _q("distinct_servers_month").score
    assert s({"distinct_servers": 12, "covers_whole_30_days": True}, 12) == ("answered", None)
    assert s({"distinct_servers": 8, "covers_whole_30_days": True}, 12) == \
        ("wrong", "partial_count_presented_as_whole")
    assert s({"distinct_servers": 8, "covers_whole_30_days": False}, 12) == \
        ("blocked", "said_partial")


def test_a_row_never_carries_a_value_and_rescores_from_the_file_alone():
    mapping = {"srv-a": "relaybox-01", "<Org-01>": "Contoso Harbour"}
    lab = esmodel.Labeller(mapping)
    assert lab("relaybox-01") == "srv-a" and lab("relaybox-99") == "<not shown 1>"
    row = {"key": "servers", "status": "answered", "cause": None,
           "answer_masked": "```answer\n{\"servers\": {\"srv-a\": 3}}\n```",
           "expected": {"srv-a": 3}}
    assert esmodel.masked_only(row, mapping) is row
    assert esmodel.rescore(json.loads(json.dumps(row))) == ("answered", None)
    leaked = dict(row, answer_masked="the tenant Contoso Harbour failed")
    out = esmodel.masked_only(leaked, mapping)
    assert "withheld" in out and "Contoso" not in json.dumps(out)


def test_the_prompts_name_the_answer_shape_never_the_query():
    w = {"case": esmodel.case_world(), "relay": esmodel.relay_world(), "wide": esmodel.wide_world()}
    for q in esmodel.QUESTIONS:
        p = q.prompt(w[q.world])
        for word in ("terms", "cardinality", "aggregation", "es_aggregate", "agent.name",
                     "date_histogram", "size"):
            assert word not in p, (q.key, word)
