"""Older days on slower storage: a vocabulary extension slice that cannot
fit ``vocabulary.budget_s``.

Measured on one real cluster: a one-day slice took about 42 seconds for a
recent day and 600-730 for a day 10 to 20 days old; the slowest took 1,028
of 1,200 seconds and two failed. The stub charges that shape
(``eseval.AGED_REQUEST_SECONDS``) and these tests drive the real ``Broker``
with its budget measured on the stub's simulated seconds. The "before"
half is the ``extend_shrinks`` measurement switch, set by nothing in the
live path.
"""

import pytest

from hider import elastic, esbridge, eseval

CL = elastic.Cluster("stub", "https://kibana-stub.example.net")
DAY = 86400.0


@pytest.fixture(autouse=True)
def _restore_clock():
    saved = esbridge.clock
    yield
    esbridge.clock = saved


@pytest.fixture(scope="module")
def docs():
    return eseval.aged_docs()


class _OldDaysFail(eseval.SteppedSearchTransport):
    """Every vocabulary request whose range ends ``older`` days or more
    before NOW is an upstream error: storage that cannot answer even an
    hour of those days within its limits."""

    older = 25.9

    def _dispatch(self, method, path, body):
        if method != "DELETE" and path == esbridge.SEARCH_PATH:
            b = (body or {}).get("params", {}).get("body", {})
            end = eseval._query_range_end(b)
            if end is not None and (eseval.NOW - end).total_seconds() >= self.older * DAY:
                return eseval.kibana_error(500, "upstream")
        return super()._dispatch(method, path, body)


def _run(tmp_path, docs, *, hours, shrinks=True, aged=eseval.aged_request_seconds,
         transport=eseval.SteppedSearchTransport, until=None):
    """Sign in and let the broker work for ``hours`` of simulated time.
    Time moves with the engine's charged seconds, plus a minute whenever the
    broker has nothing to do. Returns the figures and the broker."""
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.AGED_INDEX,))
    engine.aged_seconds = aged
    tr = transport(engine)
    base = eseval.NOW.timestamp()
    idle = [0.0]
    esbridge.clock = lambda: base + engine.simulated_seconds + idle[0]
    cfg = eseval.aged_map()
    br = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    br.build_clock = lambda: engine.simulated_seconds
    br.extend_shrinks = shrinks
    br.open()
    br.start_vocabulary(CL)
    states, stale_while_serving = set(), 0
    while esbridge.clock() - base < hours * 3600.0 and not (until and until(br)):
        if not br.pump_vocabulary():
            idle[0] += 60.0
        rep = br.vocabulary.report("stub", cfg, now=esbridge.clock())
        states.add(rep["state"])
        if rep["state"] == "stale" and rep["serving"]:
            stale_while_serving += 1
    log = br._build_log
    fails = [r for r in log if r["vocabulary"] in ("failed", "extend_failed")]
    held = br.vocabulary.get("stub")
    c = held.cover("job.name")
    return {
        "failures": len(fails),
        "failed_ranges": [tuple(r["range"]) for r in fails],
        "cluster_failed": sum(1 for r in log if r["vocabulary"] == "failed"),
        "slices": sum(1 for r in log if r["vocabulary"] == "slice"),
        "cover_days": round((esbridge.clock() - c[0]) / DAY, 2),
        # how far back from the moment of sign-in: what the failing edge is
        "reach_from_start_days": round((base - c[0]) / DAY, 2),
        "cover_end_lag_s": esbridge.clock() - c[1],
        "states": states, "stale_while_serving": stale_while_serving,
        "requests": len([x for x in tr.calls if x[1] == esbridge.SEARCH_PATH]),
        "report": br.vocabulary_progress("stub"), "log": log,
    }, br


def test_before_an_old_day_that_cannot_fit_is_retried_whole_for_ever(tmp_path, docs):
    """Today's behaviour, pinned in numbers: the first day that does not fit
    the budget (26 days back) fails, is retried 60 seconds later over the
    **same range**, fails again, and so on; the cluster is reported
    ``stale`` while its recent cover serves; and the cover never gets past
    that day."""
    got, _ = _run(tmp_path, docs, hours=12, shrinks=False)
    assert got["cluster_failed"] == got["failures"] >= 20
    assert len(set(got["failed_ranges"])) == 1          # the same range every time
    assert got["reach_from_start_days"] < 26.1          # never reaches vocabulary.days (30)
    assert got["stale_while_serving"] > 0               # healthy recent cover shown broken
    assert "stale" in got["states"]
    # what the attempts cost the cluster: every one ran to past the budget
    print("BEFORE", {k: v for k, v in got.items() if k not in ("log", "report", "failed_ranges")})


def test_after_a_failing_old_day_covers_less_each_time_and_the_cover_reaches_the_window(
        tmp_path, docs):
    got, br = _run(tmp_path, docs, hours=12)
    ext = [r for r in got["log"] if r["vocabulary"] == "extend_failed"]
    assert got["cluster_failed"] == 0                   # never charged to the cluster
    assert got["stale_while_serving"] == 0 and "stale" not in got["states"]
    assert len(ext) >= 1
    widths = [r["next_width_s"] for r in ext]
    assert widths == sorted(widths, reverse=True) and widths[0] < DAY
    assert len(set(got["failed_ranges"])) == len(got["failed_ranges"])  # never the same range twice
    assert got["cover_days"] >= eseval.AGED_DAYS - 0.01  # reaches vocabulary.days
    assert got["cover_end_lag_s"] <= elastic.VOCABULARY_REFRESH_S + 1500.0  # top-ups kept up
    rep = got["report"]
    assert rep["reach"]["complete"] is True
    line = esbridge.vocabulary_line(rep)
    assert "COVER REACHES" not in line                  # complete: nothing to say
    # the narrowed width is saved: a restart does not pay the failure again
    again = elastic.VocabularyIndex(br.vocabulary.directory)
    assert again.extend["stub"]["width"] == widths[-1]
    print("AFTER", {k: v for k, v in got.items() if k not in ("log", "report", "failed_ranges")}, got["failed_ranges"])


def test_while_shrinking_the_vocab_line_says_how_far_and_why(tmp_path, docs):
    """Stopped just after the first extension failure: cases are served,
    nothing is stale, and the line names how far the cover reaches, the
    code, and the narrower width the next try reads."""
    first_fail = lambda br: any(r["vocabulary"] == "extend_failed" for r in br._build_log)
    got, br = _run(tmp_path, docs, hours=12, until=first_fail)
    rep = got["report"]
    assert rep["serving"] and rep["state"] != "stale"
    r = rep["reach"]
    assert r["attempts"] == 1 and r["width_h"] == 12 and not r["stopped"]
    line = esbridge.vocabulary_line(rep)
    assert "COVER REACHES" in line and "older days are slower to read" in line
    assert "(vocabulary)" in line and "at 12h" in line
    print("LINE", line)


def test_a_day_that_cannot_fit_even_an_hour_stops_the_cover_and_says_so(tmp_path, docs):
    """Storage that cannot answer past 26 days, even the one-hour floor: the
    width halves to the floor, then the delay doubles (attempts thin out to
    one an hour), the cover stops at that edge, cases are served, nothing
    is stale, the edge never moves (no partial read is learnt), and the
    VOCAB line says where the cover stops and why."""
    got, br = _run(tmp_path, docs, hours=14, transport=_OldDaysFail)
    ext = [r for r in got["log"] if r["vocabulary"] == "extend_failed"]
    widths = [r["next_width_s"] for r in ext]
    assert widths[:5] == [43200.0, 21600.0, 10800.0, 5400.0, 3600.0]
    assert set(widths[5:]) <= {3600.0}
    assert got["cluster_failed"] == 0 and "stale" not in got["states"]
    assert 25.9 <= got["reach_from_start_days"] < 26.1
    # doubling delay at the floor: the gaps between floor attempts grow
    rec = br.vocabulary.extend["stub"]
    assert rec["at_floor"] >= 3
    rep = got["report"]
    assert rep["reach"]["stopped"] is True
    line = esbridge.vocabulary_line(rep)
    assert "STOPS THERE" in line and "vocabulary.budget_s" in line
    assert "Quarrytide" not in line and "Quarrytide" not in repr(got["log"])
    # top-ups kept their priority throughout
    assert got["cover_end_lag_s"] <= elastic.VOCABULARY_REFRESH_S + 1500.0


def test_a_fast_cluster_gets_the_same_slices_and_requests(tmp_path, docs):
    """No extension failure: the switch changes nothing - same slices, same
    requests, same cover."""
    fast = lambda age: 14.0
    a, _ = _run(tmp_path / "a", docs, hours=3, aged=fast)
    b, _ = _run(tmp_path / "b", docs, hours=3, aged=fast, shrinks=False)
    assert a["failures"] == b["failures"] == 0
    assert (a["slices"], a["requests"], a["cover_days"]) == (b["slices"], b["requests"],
                                                            b["cover_days"])
    assert a["slices"] >= eseval.AGED_DAYS
