"""A terms aggregation over a window too slow for one search.

"Which servers failed this month" on the measured cluster's busy hour
(``eseval.measured_count_wall`` times 3, a 300 s limit) through the real
``Bridge``, on ``eseval.fail_docs``: 12 invented relay servers, four
failing every day, four only 10-30 days back, four only 20-30 days back.
The "before" half is the ``split_terms`` measurement switch (terms answered
from the newest piece only), set by nothing in the live path. Answers are
compared in value space (each case labels in its own order).
"""

import dataclasses

import pytest

from hider import elastic, esbridge, eseval, esmcp

LIMIT = eseval.MEASURED_SEARCH_LIMIT_S
BUSY = 3.0
EVERY_DAY = {"relaybox-01", "relaybox-02", "relaybox-03", "relaybox-04"}
WEEKS_AGO = {"relaybox-09", "relaybox-10", "relaybox-11", "relaybox-12"}


@pytest.fixture(autouse=True)
def _clock():
    saved = esbridge.clock
    esbridge.clock = lambda: eseval.NOW.timestamp()
    yield
    esbridge.clock = saved


@pytest.fixture(scope="module")
def docs():
    return eseval.fail_docs()


def _bridge(docs, *, load=BUSY, wall=eseval.measured_count_wall):
    cfg = dataclasses.replace(eseval.fail_map(), poll_timeout_s=LIMIT)
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.FAIL_INDEX,))
    engine.count_wall = wall
    engine.count_load = load
    engine.search_limit_s = LIMIT if wall is not None else None
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                        eseval.EngineSession(engine))
    b.read_clock = lambda: engine.simulated_seconds
    return b, engine


def _q(aggs, days=30):
    return {"index": eseval.FAIL_INDEX, "time_range": {"gte": f"now-{days}d", "lte": "now"},
            "size": 0, "filters": [{"field": "message", "op": "phrase", "value": "Relay job failed"}],
            "aggs": aggs}


def _servers(size):
    return {"srv": {"type": "terms", "field": "agent.name", "size": size}}


def _values(b, node):
    """(server, doc_count, doc_count_max) per bucket, labels unmasked."""
    return [(b.scrubber.mapping.get(x["key"], x["key"]), x["doc_count"], x.get("doc_count_max"))
            for x in node["buckets"]]


def _truth(docs, q, name="srv"):
    b, _e = _bridge(docs, wall=None)
    out = b.run("stub", q).output
    return b, out


def test_before_which_servers_failed_this_month_answers_for_the_newest_half(docs):
    """Today: the newest piece only. 8 of 12 servers, every count half the
    truth, and the four that failed three weeks ago are not there at all;
    the reply says newest_only and covered 50%, but nothing says which
    servers it missed."""
    b, engine = _bridge(docs)
    b.split_terms = False
    out = b.run("stub", _q(_servers(12))).output
    got = {s: c for s, c, _m in _values(b, out["aggregations"]["srv"])}
    assert out["pieces"]["read"] == "newest_only" and out["pieces"]["covered_share"] == 0.5
    assert set(got) == EVERY_DAY | {"relaybox-05", "relaybox-06", "relaybox-07", "relaybox-08"}
    assert not (WEEKS_AGO & set(got))
    tb, tout = _truth(docs, _q(_servers(12)))
    truth = {s: c for s, c, _m in _values(tb, tout["aggregations"]["srv"])}
    assert all(got[s] * 2 == truth[s] for s in EVERY_DAY)       # half of every count
    assert len(engine.requests) == 2


def test_after_a_list_that_holds_every_key_is_exact_for_the_whole_month(docs):
    tb, tout = _truth(docs, _q(_servers(12)))
    b, engine = _bridge(docs)
    out = b.run("stub", _q(_servers(12))).output
    node = out["aggregations"]["srv"]
    assert out["pieces"]["read"] == "summed" and node["pieced"] == "exact"
    assert out["pieces"]["covered_share"] == 1.0
    assert _values(b, node) == _values(tb, tout["aggregations"]["srv"])
    assert node["sum_other_doc_count"] == tout["aggregations"]["srv"]["sum_other_doc_count"]
    assert len(engine.requests) == 4 and engine.simulated_seconds <= 4 * LIMIT


def test_after_a_cut_list_is_bounded_and_says_how_far_it_can_be_trusted(docs):
    """size 10 of 12 servers: one piece dropped servers into its tail, so
    their sums are lower bounds. The reply says bounded, gives each such
    key's maximum, how many leading keys are settled, and how much a key
    not shown could have; every true count lies inside its bounds and no
    unshown server's true count exceeds what the reply allows."""
    tb, tout = _truth(docs, _q(_servers(12)))
    truth = {s: c for s, c, _m in _values(tb, tout["aggregations"]["srv"])}
    b, _e = _bridge(docs)
    out = b.run("stub", _q(_servers(10))).output
    node = out["aggregations"]["srv"]
    assert out["pieces"]["read"] == "bounded" and out["pieces"]["bounded"] == ["srv"]
    assert node["pieced"] == "bounded" and len(node["buckets"]) == 10   # never more than size
    rows = _values(b, node)
    for s, low, high in rows:
        assert low <= truth[s] <= (high if high is not None else low)
    settled = node["order_settled"]
    assert settled == 3
    true_order = sorted(truth, key=lambda s: -truth[s])
    assert [s for s, _l, _h in rows[:settled]] == true_order[:settled]
    shown = {s for s, _l, _h in rows}
    last_low = rows[-1][1]
    outranks = [s for s in set(truth) - shown if truth[s] > last_low]
    # here one does (relaybox-04, 150 against a last shown 120): the reply
    # must not claim the order that far, and it does not
    assert outranks == ["relaybox-04"] and settled < len(rows)
    assert "lower bound" in out["pieces"]["note"]


def test_only_the_keys_the_reply_shows_are_made_usable(docs):
    """Every piece is scrubbed and leak-checked as a reply, but its keys
    are marked shown only if they make the merged answer: a server label
    cut from the top 3 cannot be filtered by afterwards."""
    b, _e = _bridge(docs)
    out = b.run("stub", _q(_servers(3))).output
    shown_keys = {x["key"] for x in out["aggregations"]["srv"]["buckets"]}
    assert len(shown_keys) == 3
    server_labels = {lab for lab in b.scrubber.shown if b.scrubber.mapping.get(lab, "").startswith("relaybox-")}
    assert server_labels == shown_keys
    cut = next(lab for lab, v in b.scrubber.mapping.items()
               if v.startswith("relaybox-") and lab not in shown_keys)
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {**_q(_servers(3), days=1),
                       "filters": [{"field": "agent.name", "op": "eq", "value": cut}]})
    assert e.value.code == "unknown_label"


def test_terms_under_a_daily_histogram_is_exact_with_aligned_pieces(docs):
    """Pieces on the histogram's own day boundaries: every day, and the
    servers under it, comes whole from one piece - exactly one search's
    answer for that day."""
    aggs = {"per_day": {"type": "date_histogram", "field": "@timestamp", "interval": "1d",
                        "aggs": {"srv": {"type": "terms", "field": "agent.name", "size": 5}}}}
    tb, tout = _truth(docs, _q(aggs))
    b, _e = _bridge(docs)
    out = b.run("stub", _q(aggs)).output
    assert out["pieces"]["read"] == "summed" and out["pieces"]["covered_share"] == 1.0

    def days(br, o):
        return [(x["key"], x["doc_count"], _values(br, x["srv"]))
                for x in o["aggregations"]["per_day"]["buckets"]]
    assert days(b, out) == days(tb, tout)


def test_terms_with_a_sub_aggregation_and_cardinality_stay_newest_only(docs):
    b, _e = _bridge(docs)
    nested = {"srv": {"type": "terms", "field": "agent.name", "size": 12,
                      "aggs": {"lvl": {"type": "terms", "field": "log.level", "size": 3}}}}
    out = b.run("stub", _q(nested)).output
    assert out["pieces"]["read"] == "newest_only" and out["pieces"]["not_split"] == ["srv"]
    b2, _e2 = _bridge(docs)
    out = b2.run("stub", _q({"n": {"type": "cardinality", "field": "agent.name"}})).output
    assert out["pieces"]["read"] == "newest_only" and out["pieces"]["not_split"] == ["n"]


def test_a_terms_read_that_fits_one_search_is_unchanged(docs):
    b, engine = _bridge(docs, load=1.0)
    out = b.run("stub", _q(_servers(10))).output
    assert "pieces" not in out and len(engine.requests) == 1


def test_es_smoke_prints_a_counts_only_line_for_a_pieced_read(docs, capsys):
    b, _e = _bridge(docs)
    report = esbridge.run_case(b, "stub", _q(_servers(10)))
    esbridge.print_smoke("stub", _q(_servers(10)), report)
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if l.startswith("PIECES "))
    assert ("PIECES   read=bounded pieces=3 requests=4 timeouts=1 covered=100.0% "
            "bounded=srv") in line
    assert "relaybox" not in out and "<Server" not in line
    b2, _e2 = _bridge(docs)
    report = esbridge.run_case(b2, "stub", _q(_servers(12)))
    esbridge.print_smoke("stub", _q(_servers(12)), report)
    assert "PIECES   read=summed pieces=3 requests=4 timeouts=1 covered=100.0% (every figure " \
           "exact" in capsys.readouterr().out
    # and the MCP payload carries the same facts
    assert esmcp._payload("es_aggregate", b2.outcomes[-1])["pieces"]["read"] == "summed"
