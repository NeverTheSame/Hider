"""A count or histogram over a window too slow for one search.

Measured on one real cluster: a daily histogram of one error phrase took
33 s over 7 days, 85 s over 14 and 200 s over 30, against a 300 s search
limit, and the same read varies about three times with the time of day.
The stub charges that shape (``eseval.measured_count_wall``, times
``count_load``) and these tests drive the real ``Bridge`` with its piece
sizing and waiting measured on the stub's simulated seconds. The "before"
half is the ``split_reads`` measurement switch, set by nothing in the live
path.
"""

import dataclasses

import pytest

from hider import elastic, esbridge, eseval, esmcp

LIMIT = eseval.MEASURED_SEARCH_LIMIT_S
BUSY = 3.0          # the measured time-of-day swing
PHRASE = "Run finished"


@pytest.fixture(autouse=True)
def _clock():
    saved = esbridge.clock
    esbridge.clock = lambda: eseval.NOW.timestamp()
    yield
    esbridge.clock = saved


@pytest.fixture(scope="module")
def docs():
    return eseval.aged_docs()


def _bridge(docs, *, load=BUSY, wall=eseval.measured_count_wall, spans=None):
    cfg = dataclasses.replace(eseval.aged_map(), poll_timeout_s=LIMIT)
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.AGED_INDEX,))
    engine.count_wall = wall
    engine.count_load = load
    engine.search_limit_s = LIMIT if wall is not None else None
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                        eseval.EngineSession(engine), group_spans=spans)
    b.read_clock = lambda: engine.simulated_seconds
    return b, engine


def _q(days=30, aggs=None, size=0):
    q = {"index": eseval.AGED_INDEX, "time_range": {"gte": f"now-{days}d", "lte": "now"},
         "size": size, "filters": [{"field": "message", "op": "phrase", "value": PHRASE}]}
    if aggs is not None:
        q["aggs"] = aggs
    return q


HIST = {"per_day": {"type": "date_histogram", "field": "@timestamp", "interval": "1d"}}


def _truth(docs, q):
    """The answer one search gives with no time limit at all."""
    b, _e = _bridge(docs, wall=None)
    return b.run("stub", q).output


def _buckets(out, name="per_day"):
    return [(x["key"], x["doc_count"]) for x in out["aggregations"][name]["buckets"]]


def test_before_a_30_day_histogram_in_the_busy_hour_returns_nothing(docs):
    """Today: one search, the full limit spent, refused incomplete; what the
    model reads is the refusal text, and its only move is to guess a
    narrower window - paying a full limit for each wrong guess."""
    b, engine = _bridge(docs)
    b.split_reads = False
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", _q(aggs=HIST))
    assert e.value.code == "incomplete" and engine.simulated_seconds == LIMIT
    seen = esmcp._refusal(e.value.code, e.value.message)["content"][0]["text"]
    assert seen.startswith("refused (incomplete): response withheld: search did not finish "
                           "in 300s")
    print("MODEL SEES:", seen)
    # the guesses: 21 days (still over: ~453 s busy) pays a whole limit again
    b2, e2 = _bridge(docs)
    b2.split_reads = False
    with pytest.raises(elastic.Refused):
        b2.run("stub", _q(days=21, aggs=HIST))
    assert e2.simulated_seconds == LIMIT


def test_after_the_busy_30_day_histogram_answers_exactly_by_pieces(docs):
    truth = _truth(docs, _q(aggs=HIST))
    b, engine = _bridge(docs)
    out = b.run("stub", _q(aggs=HIST)).output
    p = out["pieces"]
    print("AFTER", p, "simulated", engine.simulated_seconds)
    assert p["read"] == "summed" and p["covered_share"] == 1.0
    assert out["hits"]["total"] == truth["hits"]["total"]
    assert _buckets(out) == _buckets(truth)                 # every day, exactly
    # bounded: the budget of three limits plus the one in flight
    assert engine.simulated_seconds <= 4 * LIMIT
    assert p["timeouts"] == 1 and p["requests"] == 1 + p["pieces"]
    # the model is told how the answer was made
    payload = esmcp._payload("es_aggregate", b.outcomes[-1])
    assert payload["pieces"]["read"] == "summed" and "exact" in payload["pieces"]["note"]


def test_a_window_that_finishes_is_read_exactly_as_before(docs):
    """The quiet hour: 200 s, under the limit - one request, no new key."""
    b, engine = _bridge(docs, load=1.0)
    out = b.run("stub", _q(aggs=HIST)).output
    assert "pieces" not in out and len(engine.requests) == 1
    assert engine.simulated_seconds == pytest.approx(200.0, abs=1)
    assert _buckets(out) == _buckets(_truth(docs, _q(aggs=HIST)))


def test_a_plain_count_answers_by_pieces(docs):
    truth = _truth(docs, _q())
    b, _e = _bridge(docs)
    out = b.run("stub", _q()).output
    assert out["pieces"]["read"] == "summed"
    assert out["hits"]["total"] == truth["hits"]["total"]


def test_an_aggregation_that_does_not_add_up_gets_the_newest_piece_and_says_so(docs):
    """A distinct count does not add over pieces: it is answered over the
    newest piece that finishes, the reply naming the aggregation and the
    covered part, the total a lower bound."""
    q = _q(aggs={"n": {"type": "cardinality", "field": "job.name"}})
    b, engine = _bridge(docs)
    out = b.run("stub", q).output
    p = out["pieces"]
    assert p["read"] == "newest_only" and p["not_split"] == ["n"]
    assert 0 < p["covered_share"] < 1 and out["hits"]["total"]["relation"] == "gte"
    assert "do not add up" in p["note"] and "NOT read" in p["note"]
    assert engine.simulated_seconds <= 4 * LIMIT


def test_asking_again_skips_the_width_that_timed_out(docs):
    spans: dict = {}
    b, e1 = _bridge(docs, spans=spans)
    b.run("stub", _q(aggs=HIST))
    first_s, first_n = e1.simulated_seconds, len(e1.requests)
    b2, e2 = _bridge(docs, spans=spans)
    out = b2.run("stub", _q(aggs=HIST)).output
    assert out["pieces"]["timeouts"] == 0                   # the whole window is not tried
    assert e2.simulated_seconds <= first_s - LIMIT + 1 and len(e2.requests) < first_n
    assert "count:" + eseval.AGED_INDEX in spans


def test_a_cluster_slow_at_every_width_is_refused_within_four_limits(docs):
    b, engine = _bridge(docs, load=1000.0)
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", _q(aggs=HIST))
    assert e.value.code == "slow_read" and "newest-first pieces" in e.value.message
    assert engine.simulated_seconds <= 4 * LIMIT
