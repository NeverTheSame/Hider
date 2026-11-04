"""The live session layer, against the stub Kibana. No cluster, invented values.

The browser transport tests run only when Playwright and Chrome are both
present; everything else uses the plain-HTTP transport the stub accepts.
"""

from __future__ import annotations

import json
import re
import shutil
import threading

import pytest

from hider import elastic, esbridge, eseval

CFG0 = elastic.load(elastic.EXAMPLE)


def _config(url: str, tmp_path) -> elastic.ElasticConfig:
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": url}, "other": {"kibana": "https://kibana-other.example.net"}}
    raw["profile_dir"] = str(tmp_path / "profile")
    return elastic.parse(raw, source="test")


@pytest.fixture(scope="module")
def fixture():
    return eseval.generate(docs=150)


@pytest.fixture
def stub(fixture):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), cookie="sid=synthetic").start()
    yield kb
    kb.stop()


def _bridge(stub, tmp_path, **kw):
    cfg = _config(stub.url, tmp_path)
    scrubber = elastic.EsScrubber(cfg, tier2="none")
    session = esbridge.KibanaSession(esbridge.UrllibTransport("sid=synthetic"), sleep=lambda s: None,
                                     **kw)
    return esbridge.Bridge(cfg, scrubber, session, log_path=tmp_path / "decisions.jsonl")


# -- configuration -------------------------------------------------------------


@pytest.mark.parametrize("clusters,needle", [
    ({"Bad Name": {"kibana": "https://x.example.net"}}, "short lowercase"),
    ({"a": {"kibana": "https://x.example.net/app/kibana"}}, "no path"),
    ({"a": {"kibana": "http://kibana.example.net"}}, "loopback"),
    ({"a": {"kibana": "https://x.example.net", "cookie": "sid=1"}}, "exactly"),
    ({}, "object of name"),
])
def test_cluster_config_errors(clusters, needle):
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = clusters
    with pytest.raises(elastic.ConfigError, match=needle):
        elastic.parse(raw)


def test_cluster_config_accepts_loopback_http_and_string_form():
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"local": "http://127.0.0.1:5601/"}
    cfg = elastic.parse(raw)
    assert cfg.cluster("local").kibana == "http://127.0.0.1:5601"
    assert cfg.cluster("local").host == "127.0.0.1:5601"
    assert cfg.summary()["clusters"] == ["local"]


def test_profile_dir_is_dedicated(tmp_path, monkeypatch):
    p = esbridge.prepare_profile_dir(tmp_path / "fresh")
    assert (p / esbridge.PROFILE_MARKER).exists()
    assert esbridge.prepare_profile_dir(p) == p  # reusable once marked
    busy = tmp_path / "everyday"
    busy.mkdir()
    (busy / "Default").mkdir()
    with pytest.raises(elastic.ConfigError, match="not created by the bridge"):
        esbridge.prepare_profile_dir(busy)
    with pytest.raises(elastic.ConfigError, match="required"):
        esbridge.prepare_profile_dir("")
    # a stock Chrome profile root is refused even if it carried the marker
    stock = tmp_path / "Library" / "Application Support" / "Google" / "Chrome"
    stock.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(elastic.ConfigError, match="stock Chrome profile"):
        esbridge.prepare_profile_dir(stock / "Default")


# -- reply validation ----------------------------------------------------------------

CL = elastic.Cluster("stub", "https://kibana-stub.example.net")


@pytest.mark.parametrize("reply,code", [
    (esbridge.Reply(200, "https://login.microsoftonline.example/oauth2/authorize", "text/html",
                    "<html>", True), "session_expired"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/login?next=%2F", "text/html",
                    eseval.LOGIN_PAGE, True), "session_expired"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "text/html",
                    eseval.LOGIN_PAGE), "session_expired"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "text/html",
                    "<html><body>Service unavailable</body></html>"), "malformed"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "application/json",
                    "<html>"), "malformed"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "text/plain",
                    "ok"), "malformed"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "application/json",
                    "not json"), "malformed"),
    (esbridge.Reply(200, "https://kibana-stub.example.net/internal/search/ese", "application/json",
                    "[1,2]"), "malformed"),
    (esbridge.Reply(401, "https://kibana-stub.example.net/internal/search/ese", "application/json",
                    json.dumps(eseval.kibana_error(401, "Unauthorized"))), "session_expired"),
    (esbridge.Reply(200, "https://kibana-stub.example.net:443/internal/search/ese",
                    "application/json", "{}"), "session_expired"),  # host must match exactly
])
def test_parse_reply_refuses_everything_that_is_not_kibana_json(reply, code):
    with pytest.raises(elastic.Refused) as e:
        esbridge.KibanaSession.parse_reply(CL, reply)
    assert e.value.code == code
    assert "Welcome" not in e.value.message and "microsoftonline" not in e.value.message


def test_parse_reply_accepts_a_json_object_and_passes_es_errors_through():
    ok = esbridge.KibanaSession.parse_reply(
        CL, esbridge.Reply(200, CL.kibana + "/internal/search/ese", "application/json; charset=utf-8",
                           '{"id": "x", "isRunning": false, "rawResponse": {}}'))
    assert ok["id"] == "x"
    err = esbridge.KibanaSession.parse_reply(
        CL, esbridge.Reply(404, CL.kibana + "/internal/search/ese", "application/json",
                           json.dumps(eseval.kibana_error(404, "[index_not_found_exception] x"))))
    assert elastic.error_class(err) == "not_found:index_not_found_exception"


# -- the protocol against the stub -----------------------------------------------------


def test_search_submits_polls_and_releases(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    o = b.run("stub", {"index": "logs-app-*", "size": 2})
    assert o.refused is None and o.hits_shown == 2 and o.hits_total > 2
    methods = [(m, p.split("/")[-1] == p.split("/")[-1]) for m, p, _ in stub.calls]
    seq = [m for m, _, _ in stub.calls]
    assert seq[:2] == ["GET", "POST"]            # probe, submit
    assert "DELETE" in seq and seq[-1] == "DELETE"  # released after the poll
    assert len(stub.deleted) == 1
    assert "_source" in o.output["hits"]["hits"][0]


def test_expired_session_is_a_refusal_before_anything_is_submitted(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    stub.expire()
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {"index": "logs-app-*", "size": 1})
    assert e.value.code == "session_expired"
    assert [m for m, _, _ in stub.calls] == ["GET", "GET"]   # probe, then the /login redirect
    assert not any(p.startswith("/internal/search") for _, p, _ in stub.calls)
    # signing back in makes the same bridge work again, no restart
    stub.sign_in()
    assert b.run("stub", {"index": "logs-app-*", "size": 1}).refused is None


def test_session_expiring_between_probe_and_poll_is_refused(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    cfg = b.config
    cl = cfg.cluster("stub")
    real = b.session.transport.request

    def flaky(cluster, method, path, body=None):
        r = real(cluster, method, path, body)
        if method == "POST" and path == esbridge.SEARCH_PATH:
            stub.expire()   # the SSO session dies right after the submit
        return r

    b.session.transport.request = flaky
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {"index": "logs-app-*", "size": 1})
    assert e.value.code == "session_expired"
    stub.sign_in()


def test_poll_timeout_is_incomplete_and_the_search_is_deleted(fixture, tmp_path):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), cookie="sid=synthetic",
                           slow=True).start()
    try:
        b = _bridge(kb, tmp_path, poll_timeout=0.0)
        with pytest.raises(elastic.Refused) as e:
            b.run("stub", {"index": "logs-app-*", "size": 1})
        assert e.value.code == "incomplete"
        assert len(kb.deleted) == 1
    finally:
        kb.stop()


def test_upstream_errors_reach_claude_as_a_class_only(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    cfg = b.config
    # an index the config allows but the stub engine does not have
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": stub.url}}
    raw["indices"] = ["logs-app-*", "logs-missing-*"]
    b.config = elastic.parse(raw, source="test")
    b.scrubber.config = b.config
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {"index": "logs-missing-*", "size": 1})
    assert e.value.code == "upstream_error"
    assert "index_not_found_exception" in e.value.message
    assert "logs-missing" not in e.value.message


def test_unknown_cluster_and_grammar_refusals_never_touch_kibana(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    with pytest.raises(elastic.Refused) as e:
        b.run("prod", {"index": "logs-app-*"})
    assert e.value.code == "bad_cluster"
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {"index": "logs-app-*", "query": {"match_all": {}}})
    assert e.value.code == "raw_dsl"
    assert stub.calls == []


def test_labels_round_trip_through_the_live_path_and_the_log_holds_no_values(stub, tmp_path, fixture):
    b = _bridge(stub, tmp_path)
    tenant = fixture.tenants[0]
    lab = b.scrubber.seed(tenant.name)
    o = b.run("stub", {"index": "logs-app-*", "size": 5,
                       "filters": [{"field": "labels.tenant_name", "op": "eq", "value": lab},
                                   {"field": "message", "op": "phrase", "value": lab}]})
    assert o.hits_total > 0
    # the stub saw the real value; Claude's page shows the label
    submitted = next(body for m, p, body in stub.calls if m == "POST" and p == esbridge.SEARCH_PATH)
    assert tenant.name in json.dumps(submitted)
    page = json.dumps(o.output)
    assert tenant.name not in page and lab in page
    assert all(h["_source"]["labels"]["tenant_name"] == lab for h in o.output["hits"]["hits"])
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert row["cluster"] == "stub" and row["labels_used"] == [lab]
    assert row["text_queries"] == [lab]
    assert row["filters"] == [{"field": "labels.tenant_name", "op": "eq"},
                              {"field": "message", "op": "phrase"}]
    blob = json.dumps(rows)
    for v in fixture.truth:
        if len(v) > 4:
            assert v not in blob, v


def test_refusals_are_logged_with_their_code(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    stub.expire()
    with pytest.raises(elastic.Refused):
        b.run("stub", {"index": "logs-app-*"})
    stub.sign_in()
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    assert rows[-1]["refused"] == "session_expired" and rows[-1]["index"] == "logs-app-*"


def test_concurrent_calls_are_serialised_and_all_clean(stub, tmp_path, fixture):
    b = _bridge(stub, tmp_path)
    errors: list[BaseException] = []
    outs: list[esbridge.Outcome] = []

    def go(i: int):
        try:
            outs.append(b.run("stub", {"index": ["logs-app-*", "logs-worker-*", "traces-apm-*"][i % 3],
                                       "size": 5}))
        except BaseException as e:  # pragma: no cover - a failure, reported below
            errors.append(e)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors and len(outs) == 6
    for o in outs:
        assert eseval._leaks(o.output, fixture.truth) == []


def test_smoke_prints_decisions_only(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, phrase="Throttled by SharePoint")
    assert esbridge.smoke(b, "stub", q) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK ") and "hits_total=" in out
    for v in fixture.truth:
        if len(v) > 4:
            assert v not in out
    stub.expire()
    assert esbridge.smoke(b, "stub", q) == 2
    assert "REFUSED" in capsys.readouterr().out
    stub.sign_in()


def test_smoke_query_time_window_defaults_to_the_last_hour_and_is_overridable():
    assert esbridge.smoke_query(CFG0)["time_range"] == {"gte": "now-1h", "lte": "now"}
    q = esbridge.smoke_query(CFG0, since="now-7d/d", until="now-1d")
    assert q["time_range"] == {"gte": "now-7d/d", "lte": "now-1d"} and "aggs" not in q


_SERVER_LABEL = re.compile(r"^[a-z]{2,5}-(?:amer|emea|apj|aus)-s\d{2}$")


def test_smoke_count_by_server_per_interval_prints_counts_not_keys(stub, tmp_path, capsys, fixture):
    """Matching lines per server per hour: keys are region-keeping labels,
    the summary line carries counts only, and keys appear only with show."""
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, size=0, since="now-6h", count_by="agent.name",
                             interval="1h", buckets=5)
    assert esbridge.smoke(b, "stub", q) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and "since=now-6h until=now" in out
    m = re.search(r"buckets=5 bucket_docs=\[([\d, ]+)\] other_docs=(\d+) time_buckets=(\d+)", out)
    assert m, out
    counts = [int(c) for c in m.group(1).split(",")]
    o = b.outcomes[-1]
    assert sum(counts) + int(m.group(2)) == o.hits_total
    # no key of any kind on the summary line: no label, no real name, no time
    assert not re.search(r"-s\d{2}\b|<[A-Z]", out)
    assert "2026-" not in out
    for v in fixture.truth:
        if len(v) > 4:
            assert v not in out
    rows = o.output["aggregations"][esbridge.COUNT_AGG]["buckets"]
    assert len(rows) == 5 and all(_SERVER_LABEL.match(r["key"]) for r in rows)
    assert sum(len(r[esbridge.TIME_AGG]["buckets"]) for r in rows) == int(m.group(3))
    for r in rows:
        assert sum(t["doc_count"] for t in r[esbridge.TIME_AGG]["buckets"]) == r["doc_count"]
    assert eseval._leaks(o.output, fixture.truth) == []
    # the decision log has the shape, not the keys
    row = json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    assert row["aggs"][0]["field"] == "agent.name"
    assert row["aggs"][0]["aggs"][0]["type"] == "date_histogram"
    assert not any(r["key"] in json.dumps(row) for r in rows)

    assert esbridge.smoke(b, "stub", q, show=True) == 0
    shown = capsys.readouterr().out
    assert all(r["key"] in shown for r in rows)


def test_smoke_count_by_identifier_keys_come_back_as_labels(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, size=0, since="now-6h", count_by="labels.tenant_name")
    assert esbridge.smoke(b, "stub", q, show=True) == 0
    rows = b.outcomes[-1].output["aggregations"][esbridge.COUNT_AGG]["buckets"]
    assert rows and all(re.fullmatch(r"<Org-\d+>", r["key"]) for r in rows)
    out = capsys.readouterr().out
    for v in fixture.truth:
        if len(v) > 4:
            assert v not in out


def test_smoke_interval_alone_is_a_histogram_of_matching_lines(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, size=0, since="now-6h", interval="1h")
    assert esbridge.smoke(b, "stub", q) == 0
    out = capsys.readouterr().out
    m = re.search(r"time_buckets=(\d+) bucket_docs=\[([\d, ]+)\]", out)
    assert m and "buckets=" not in out.replace("time_buckets=", "")
    assert sum(int(c) for c in m.group(2).split(",")) == b.outcomes[-1].hits_total


@pytest.mark.parametrize("kw,code", [
    ({"count_by": "user.password"}, "unknown_field"),
    ({"count_by": "labels.*"}, "unknown_field"),
    ({"count_by": "message"}, "field_not_queryable"),
    ({"count_by": "agent.name", "interval": "2w"}, "bad_agg"),
    ({"count_by": "agent.name", "interval": "1h; drop"}, "bad_agg"),
    ({"interval": "fortnight"}, "bad_agg"),
    ({"count_by": "agent.name", "buckets": 500}, "size_cap"),
    ({"since": "yesterday"}, "bad_value"),
    ({"until": "Contoso"}, "bad_value"),
    # the bucket cap, known before sending: these never reach Kibana
    ({"since": "now-7d", "count_by": "agent.name", "interval": "1h"}, "size_cap"),
    ({"since": "now-50h", "interval": "1h"}, "size_cap"),
    ({"since": "now-1d/d", "until": "now/d", "interval": "10m"}, "size_cap"),
    ({"since": "2026-08-18", "until": "2026-08-20", "interval": "1h"}, "size_cap"),
    ({"since": "2026-08-01", "interval": "1h"}, "size_cap"),
    ({"since": "2026-02-30", "interval": "1d"}, "bad_value"),
    ({"interval": "0h"}, "bad_agg"),
])
def test_smoke_bad_aggregation_or_time_is_a_refusal(stub, tmp_path, capsys, kw, code):
    b = _bridge(stub, tmp_path)
    n = len(stub.engine.requests)
    q = esbridge.smoke_query(b.config, size=0, **kw)
    assert esbridge.smoke(b, "stub", q) == 2
    out = capsys.readouterr().out
    assert out.startswith("REFUSED ") and f"code={code}" in out
    assert len(stub.engine.requests) == n  # refused before anything left
    row = json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    assert row["refused"] == code


@pytest.mark.parametrize("kw,most", [
    ({"since": "now-49h", "interval": "1h"}, 50),                          # the cap exactly
    ({"since": "now-49h", "count_by": "agent.name", "interval": "1h"}, 50),
    ({"since": "now-1d/d", "until": "now/d", "interval": "1h"}, 48),
    ({"since": "2026-08-19", "until": "2026-08-20", "interval": "1h"}, 48),
    ({"since": "2026-08-13T12:00:00Z", "until": "2026-08-20T12:00:00Z", "interval": "4h"}, 43),
])
def test_smoke_histogram_within_the_cap_reaches_kibana(stub, tmp_path, capsys, kw, most):
    b = _bridge(stub, tmp_path)
    n = len(stub.engine.requests)
    q = esbridge.smoke_query(b.config, size=0, **kw)
    assert esbridge.smoke(b, "stub", q) == 0, capsys.readouterr().out
    assert len(stub.engine.requests) == n + 1
    aggs = b.outcomes[-1].output["aggregations"]
    lists = ([r[esbridge.TIME_AGG]["buckets"] for r in aggs[esbridge.COUNT_AGG]["buckets"]]
             if esbridge.COUNT_AGG in aggs else [aggs[esbridge.TIME_AGG]["buckets"]])
    assert all(len(rows) <= most for rows in lists)


def test_smoke_refused_histogram_says_how_many_buckets_and_what_fits(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    n = len(stub.engine.requests)
    q = esbridge.smoke_query(b.config, size=0, since="now-7d", count_by="agent.name",
                             interval="1h")
    assert esbridge.smoke(b, "stub", q) == 2
    out = capsys.readouterr().out
    assert "code=size_cap" in out and "gives 169 buckets, the cap is 50" in out
    assert "4h fits (43 buckets)" in out and "window of at most 2d 1h" in out
    assert len(stub.engine.requests) == n and b.session.transport is not None


def test_es_smoke_cli_wires_the_new_flags(capsys):
    from hider import cli

    rc = cli.main(["es-smoke", "--stub", "--no-browser", "--tier2", "none", "--since", "now-6h",
                   "--count-by", "agent.name", "--interval", "1d"])
    captured = capsys.readouterr()
    assert rc == 0 and '"size": 0' in captured.err
    assert re.search(r"shown=0 .* buckets=\d+ bucket_docs=", captured.out)
    rc = cli.main(["es-smoke", "--stub", "--no-browser", "--tier2", "none",
                   "--count-by", "not.in.map"])
    assert rc == 2 and "code=unknown_field" in capsys.readouterr().out


# -- the browser transport, when it can run --------------------------------------------


def _browser_available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    import os
    return os.path.exists("/Applications/Google Chrome.app") or bool(
        shutil.which("google-chrome") or shutil.which("google-chrome-stable"))


@pytest.mark.skipif(not _browser_available(), reason="playwright and Chrome are needed")
def test_browser_transport_runs_the_whole_path_and_sees_the_login_page(fixture, tmp_path):
    # no cookie requirement: the browser's jar is empty and that is the point;
    # the stub decides signed-in state server side
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices)).start()
    transport = esbridge.BrowserTransport(tmp_path / "profile")
    try:
        cfg = _config(kb.url, tmp_path)
        scrubber = elastic.EsScrubber(cfg, tier2="none")
        b = esbridge.Bridge(cfg, scrubber, esbridge.KibanaSession(transport, poll_interval=0.1))
        o = b.run("stub", {"index": "logs-worker-*", "size": 3})
        assert o.refused is None and o.hits_shown == 3
        assert eseval._leaks(o.output, fixture.truth) == []
        # the request came from the Kibana tab with the required headers
        posts = [(p, h) for m, p, h in kb.calls if m == "POST"]
        assert posts and posts[0][0] == esbridge.SEARCH_PATH
        assert (tmp_path / "profile" / esbridge.PROFILE_MARKER).exists()
        kb.expire()
        with pytest.raises(elastic.Refused) as e:
            b.run("stub", {"index": "logs-worker-*", "size": 1})
        assert e.value.code == "session_expired"
        kb.sign_in()
        assert b.run("stub", {"index": "logs-worker-*", "size": 1}).refused is None
    finally:
        transport.close()
        kb.stop()
