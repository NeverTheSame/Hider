"""A long break on a slow cluster: the catch-up after the bridge was down.

The cover was read through to 14 days ago and the bridge was then down for
14 days. The catch-up reads forward from the cover's end, one day at a
time, through the slow older days (``eseval.AGED_REQUEST_SECONDS``), and
the gap rule refuses every case until it lands. These tests drive the real
``Broker`` on the stub with the slice budget measured on simulated
seconds. The "before" half is the ``catch_up_jumps`` measurement switch,
set by nothing in the live path.
"""

import pytest

from hider import elastic, esbridge, eseval

CL = elastic.Cluster("stub", "https://kibana-stub.example.net")
DAY = 86400.0
BREAK_DAYS = 14


@pytest.fixture(autouse=True)
def _restore_clock():
    saved = esbridge.clock
    yield
    esbridge.clock = saved


@pytest.fixture(scope="module")
def docs():
    return eseval.aged_docs()


class _DaysFail(eseval.SteppedSearchTransport):
    """Every vocabulary request whose range ends between ``band`` days
    before NOW is an upstream error: one catch-up day that cannot fit."""

    band = (9.5, 10.5)

    def _dispatch(self, method, path, body):
        if method != "DELETE" and path == esbridge.SEARCH_PATH:
            b = (body or {}).get("params", {}).get("body", {})
            end = eseval._query_range_end(b)
            if end is not None:
                age = (eseval.NOW - end).total_seconds() / DAY
                if self.band[0] <= age < self.band[1]:
                    return eseval.kibana_error(500, "upstream")
        return super()._dispatch(method, path, body)


def _saved_cover(tmp_path, docs):
    """A cover of job.name from 30 to 14 days back, saved as a bridge that
    stopped 14 days ago left it. Names from the fixture's documents in
    that range."""
    now = eseval.NOW.timestamp()
    lo, hi = now - 30 * DAY, now - BREAK_DAYS * DAY
    names = sorted({d.source["job"]["name"] for d in docs
                    if lo <= eseval._parse_time(d.source["@timestamp"]).timestamp() <= hi})
    idx = elastic.VocabularyIndex(tmp_path)
    idx.put("stub", elastic.ClusterVocabulary(lo, hi, hi, {"job.name": names}))
    return names


def _run(tmp_path, docs, *, hours, jumps=True, transport=eseval.SteppedSearchTransport,
         aged=eseval.aged_request_seconds):
    """Restart after the break and let the broker work for ``hours`` of
    simulated time; time moves with the engine's charged seconds, plus a
    minute whenever the broker has nothing to do."""
    _saved_cover(tmp_path, docs)
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.AGED_INDEX,))
    engine.aged_seconds = aged
    tr = transport(engine)
    base = eseval.NOW.timestamp()
    idle = [0.0]
    esbridge.clock = lambda: base + engine.simulated_seconds + idle[0]
    cfg = eseval.aged_map()
    br = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    br.build_clock = lambda: engine.simulated_seconds
    br.catch_up_jumps = jumps
    br.open()
    br.start_vocabulary(CL)
    out = {"first_served_s": None, "refused_readings": 0, "states": set(),
           "stale_while_serving": 0, "gap_closed_s": None}
    while esbridge.clock() - base < hours * 3600.0:
        if not br.pump_vocabulary():
            idle[0] += 60.0
        t = esbridge.clock()
        rep = br.vocabulary.report("stub", cfg, now=t)
        out["states"].add(rep["state"])
        if rep["serving"]:
            if out["first_served_s"] is None:
                out["first_served_s"] = round(t - base)
            if rep["state"] == "stale":
                out["stale_while_serving"] += 1
        else:
            out["refused_readings"] += 1
        held = br.vocabulary.get("stub")
        if out["first_served_s"] is not None and out["gap_closed_s"] is None \
                and held is not None and not getattr(held, "held_over", None) \
                and held.cover("job.name") and held.cover("job.name")[0] <= base - 29.5 * DAY:
            out["gap_closed_s"] = round(t - base)
    log = br._build_log
    out.update({
        "cluster_failed": sum(1 for r in log if r["vocabulary"] == "failed"),
        "failed_ranges": [tuple(r["range"]) for r in log if r["vocabulary"] == "failed"],
        "jumped": sum(1 for r in log if r["vocabulary"] == "catch_up_jumped"),
        "slices": sum(1 for r in log if r["vocabulary"] == "slice"),
        "requests": len([x for x in tr.calls if x[1] == esbridge.SEARCH_PATH]),
        "report": br.vocabulary_progress("stub"), "log": log,
    })
    return out, br


def _show(tag, got):
    print(tag, {k: v for k, v in got.items() if k not in ("log", "report", "failed_ranges")})


def test_before_a_two_week_break_refuses_every_case_through_the_slow_days(tmp_path, docs):
    """Today's behaviour, in numbers: forward from the cover's end, one
    slow day at a time; every case refused until the last day lands."""
    got, _ = _run(tmp_path, docs, hours=4, jumps=False)
    _show("BEFORE", got)
    assert got["first_served_s"] is not None and got["first_served_s"] > 3600   # 4,852s on this stub
    assert got["jumped"] == 0


def test_before_one_catch_up_day_that_cannot_fit_refuses_every_case_for_ever(tmp_path, docs):
    got, _ = _run(tmp_path, docs, hours=6, jumps=False, transport=_DaysFail)
    _show("BEFORE-FAIL", got)
    assert got["first_served_s"] is None                # never served in six hours
    assert got["cluster_failed"] >= 10
    assert len(set(got["failed_ranges"])) == 1          # the same day every time


def _first_build_s(tmp_path, docs, aged=eseval.aged_request_seconds):
    """Time to the first served case of a first build on the same stub:
    the yardstick the catch-up after a break is held to."""
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.AGED_INDEX,))
    engine.aged_seconds = aged
    tr = eseval.SteppedSearchTransport(engine)
    base = eseval.NOW.timestamp()
    esbridge.clock = lambda: base + engine.simulated_seconds
    cfg = eseval.aged_map()
    br = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    br.build_clock = lambda: engine.simulated_seconds
    br.open()
    br.start_vocabulary(CL)
    while not br.vocabulary.serves("stub", cfg, esbridge.clock()):
        assert br.pump_vocabulary()
    return round(esbridge.clock() - base)


def test_after_a_two_week_break_the_first_case_comes_about_as_soon_as_a_first_build(
        tmp_path, docs):
    fb = _first_build_s(tmp_path / "fb", docs)
    got, br = _run(tmp_path / "run", docs, hours=4)
    _show("AFTER", got)
    print("FIRST BUILD", fb)
    assert got["jumped"] == 1 and got["cluster_failed"] == 0
    # a first build plus the quarter-budget the slow catch-up slice was
    # given before it was abandoned (and the page in flight when it was)
    budget = eseval.aged_map().vocabulary_budget_s
    assert got["first_served_s"] <= fb + elastic.VOCABULARY_CATCH_UP_SLOW_SHARE * budget + 300
    assert got["stale_while_serving"] == 0
    # the gap is read behind the new cover and joins the old one: one
    # range, no hole, nothing set aside
    assert got["gap_closed_s"] is not None
    held = br.vocabulary.get("stub")
    assert held.held_over == {} and held.cover("job.name")[0] <= eseval.NOW.timestamp() - 29.5 * DAY


def test_at_the_first_served_case_it_is_at_least_as_safe_as_a_first_build(tmp_path, docs):
    """When the first case is served the field has what a first build has
    (the newest two days) **plus** every name read before the break, still
    applied; only the gap's days are unread - names logged only then are
    readable until the backward read reaches them, which a first build
    also leaves unread."""
    names = _saved_cover(tmp_path, docs)
    served = lambda br: br.vocabulary.serves("stub", eseval.aged_map(), esbridge.clock())
    got = None
    engine = eseval.StubEngine(eseval.Fixture(docs, [], []), (eseval.AGED_INDEX,))
    engine.aged_seconds = eseval.aged_request_seconds
    tr = eseval.SteppedSearchTransport(engine)
    base = eseval.NOW.timestamp()
    esbridge.clock = lambda: base + engine.simulated_seconds
    cfg = eseval.aged_map()
    br = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    br.build_clock = lambda: engine.simulated_seconds
    br.open()
    br.start_vocabulary(CL)
    while not served(br):
        assert br.pump_vocabulary()
    held = br.vocabulary.get("stub")
    c = held.cover("job.name")
    assert c[1] >= esbridge.clock() - elastic.VOCABULARY_REFRESH_S   # the newest day
    assert c[1] - c[0] >= elastic.VOCABULARY_SERVE_DAYS * DAY - 1   # two days, as a first build
    have = set(held.fields["job.name"])
    assert set(names) <= have                                       # pre-break names kept
    assert held.held_over["job.name"][1] == base - BREAK_DAYS * DAY
    rep = br.vocabulary_progress("stub")
    line = esbridge.vocabulary_line(rep)
    assert "CATCH-UP JUMPED, GAP NOT READ YET" in line and "job.name" in line
    assert rep["held_over"]["job.name"]["gap_days"] == pytest.approx(BREAK_DAYS - 2, abs=0.1)
    assert "Quarrytide" not in line and "Quarrytide" not in repr(br._build_log)
    # saved and restored as it is: names, the new cover and the set-aside range
    again = elastic.VocabularyIndex(tmp_path).get("stub")
    assert again.held_over == held.held_over and again.cover("job.name") == c
    assert set(again.fields["job.name"]) == have
    print("LINE", line)


def test_after_one_catch_up_day_that_cannot_fit_cases_are_served_and_it_says_where(
        tmp_path, docs):
    got, br = _run(tmp_path, docs, hours=6, transport=_DaysFail)
    _show("AFTER-FAIL", got)
    assert got["first_served_s"] is not None and got["first_served_s"] < 1800
    assert got["cluster_failed"] == 0 and got["stale_while_serving"] == 0
    assert "stale" not in got["states"]
    held = br.vocabulary.get("stub")
    c = held.cover("job.name")
    # read back to the day that cannot be read, and no further: no hole
    assert c[0] >= eseval.NOW.timestamp() - 10.5 * DAY
    assert held.held_over                                   # the old names still applied
    line = esbridge.vocabulary_line(got["report"])
    assert "CATCH-UP JUMPED, GAP NOT READ YET" in line and "COVER REACHES" in line
    print("LINE", line)


def test_a_fast_catch_up_is_read_forward_exactly_as_before(tmp_path, docs):
    fast = lambda age: 14.0
    a, _ = _run(tmp_path / "a", docs, hours=3, aged=fast)
    b, _ = _run(tmp_path / "b", docs, hours=3, aged=fast, jumps=False)
    assert a["jumped"] == 0
    assert (a["slices"], a["requests"], a["first_served_s"]) == \
        (b["slices"], b["requests"], b["first_served_s"])
