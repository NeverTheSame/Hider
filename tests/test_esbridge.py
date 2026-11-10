"""The live session layer, against the stub Kibana. No cluster, invented values.

The browser transport tests run only when Playwright and Chrome are both
present; everything else uses the plain-HTTP transport the stub accepts.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
import time
from pathlib import Path

import pytest

from hider import elastic, esbridge, eseval

CFG0 = elastic.load(elastic.EXAMPLE)


@pytest.fixture(autouse=True)
def _fixture_clock():
    """The stub's documents sit at ``eseval.NOW``, so the vocabulary build
    has to read the range around that instant rather than around today.
    Against a real cluster ``esbridge.clock`` is the wall clock."""
    esbridge.clock = eseval.NOW.timestamp
    yield
    esbridge.clock = time.time


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


def _bridge(stub, tmp_path, *, vocabulary=True, **kw):
    """A bridge on a signed-in cluster whose vocabulary is already built,
    which is what every case sees in practice: es-login builds it once."""
    cfg = _config(stub.url, tmp_path)
    scrubber = elastic.EsScrubber(cfg, tier2="none")
    session = esbridge.KibanaSession(esbridge.UrllibTransport("sid=synthetic"), sleep=lambda s: None,
                                     **kw)
    index = elastic.VocabularyIndex(None)
    if vocabulary:
        built, _ = eseval.build_vocabulary(cfg, stub.engine)
        index.put("stub", built)
    return esbridge.Bridge(cfg, scrubber, session, log_path=tmp_path / "decisions.jsonl",
                           index=index)


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
    # one search, released: the vocabulary was built at sign-in, so the case
    # submits only its own page
    assert len(stub.deleted) == 1
    assert "_source" in o.output["hits"]["hits"][0]
    b.run("stub", {"index": "logs-app-*", "size": 2})
    assert len(stub.deleted) == 2                # one search per page, and nothing else


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
        assert "did not finish in 0s" in e.value.message
        assert "shorter time window" in e.value.message and "index pattern" in e.value.message
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
    submitted = [body for m, p, body in stub.calls if m == "POST" and p == esbridge.SEARCH_PATH]
    # the case submits one search, its own: the vocabulary was built at
    # sign-in, before this case existed
    assert len(submitted) == 1 and tenant.name in json.dumps(submitted[0])
    page = json.dumps(o.output)
    assert tenant.name not in page and lab in page
    assert all(h["_source"]["labels"]["tenant_name"] == lab for h in o.output["hits"]["hits"])
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    vocab, row = rows
    assert vocab["vocabulary"] == "applied" and vocab["fields"]["job.name"] > 0 \
        and vocab["max"] == elastic.DEFAULT_VOCABULARY_MAX and "refused" not in vocab
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
    assert out.count("\n") == 2 and "since=now-6h until=now" in out
    # the second line: each vocabulary field against its cap, counts only
    cap = CFG0.vocabulary_max
    assert re.search(rf"^VOCAB    job\.name=\d+/{cap} labels\.tenant_name=\d+/{cap} ", out, re.M)
    m = re.search(r"buckets=5 bucket_docs=\[([\d, ]+)\] other_docs=(\d+) count_error_bound=0 "
                  r"docs_with_field=\d+ time_buckets=(\d+)", out)
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
    # one request: the query. The vocabulary was built once, at sign-in.
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


# -- phrases, exact filters, the zero-hit check, approximate terms -----------------------


def _expected(fixture, index, pred):
    """Ground truth from the fixture: the stub's window is its whole 6h spread."""
    return sum(1 for d in fixture.docs if d.index == index and pred(eseval.flatten(d.source)))


def _words(text):
    return eseval._TOKEN.findall(text.lower())


def _has_phrase(text, phrase):
    have, want = _words(text or ""), _words(phrase)
    return any(have[i:i + len(want)] == want for i in range(len(have) - len(want) + 1))


def _smoke(b, capsys, **kw):
    q = esbridge.smoke_query(b.config, since="now-6h", **kw)
    report = esbridge.run_smoke(lambda query: esbridge.run_case(b, "stub", query), q,
                                max_buckets=b.config.max_buckets)
    rc = esbridge.print_smoke("stub", q, report)
    return rc, capsys.readouterr().out, report


def test_smoke_query_builds_anded_filters_on_the_named_phrase_field():
    q = esbridge.smoke_query(CFG0, phrase=["returned HTTP", "429"], phrase_field="job.status_message",
                             eq=[("data_stream.dataset", "app.engine"), ("agent.name", "ctr-amer-s01")])
    assert q["filters"] == [
        {"field": "data_stream.dataset", "op": "eq", "value": "app.engine"},
        {"field": "agent.name", "op": "eq", "value": "ctr-amer-s01"},
        {"field": "job.status_message", "op": "phrase", "value": "returned HTTP"},
        {"field": "job.status_message", "op": "phrase", "value": "429"},
    ]
    # the default is still the first text rule, and now it is said out loud
    assert esbridge.default_phrase_field(CFG0) == "message"
    assert esbridge.smoke_query(CFG0, phrase="x")["filters"][0]["field"] == "message"
    # a site map with no text rule: the phrase is refused, not dropped
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["fields"] = {k: v for k, v in raw["fields"].items() if v != "text"}
    no_text = elastic.parse(raw)
    q = esbridge.smoke_query(no_text, phrase="x")
    with pytest.raises(elastic.Refused) as e:
        from hider import esquery
        esquery.compile_query(q, no_text, elastic.EsScrubber(no_text, tier2="none"))
    assert e.value.code == "unknown_field"


def test_repeated_phrases_are_anded_and_the_summary_names_the_field(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    one = _expected(fixture, "logs-app-*", lambda f: _has_phrase(f.get("message"), "returned HTTP"))
    both = _expected(fixture, "logs-app-*", lambda f: _has_phrase(f.get("message"), "returned HTTP")
                     and _has_phrase(f.get("message"), "429"))
    assert 0 < both < one  # the pair is a real narrowing in the fixture
    rc, out, report = _smoke(b, capsys, phrase="returned HTTP")
    assert rc == 0 and report["hits_total"] == one and "phrase_field=message phrases=1" in out
    rc, out, report = _smoke(b, capsys, phrase=["returned HTTP", "429"])
    assert rc == 0 and report["hits_total"] == both and "phrase_field=message phrases=2" in out
    # the phrases themselves never reach the summary, and each is logged as written
    assert "returned HTTP" not in out and "429" not in out.replace("phrases=2", "")
    row = json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    assert row["text_queries"] == ["returned HTTP", "429"]


def test_a_phrase_on_a_field_with_no_documents_is_empty_not_zero(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    window = _expected(fixture, "logs-app-*", lambda f: True)
    rc, out, report = _smoke(b, capsys, phrase="returned HTTP", phrase_field="transaction.name")
    assert rc == 3 and out.startswith("EMPTY ")
    assert "phrase_field=transaction.name" in out and "phrase_field_docs=0/" in out
    assert f"transaction.name holds no documents among the {window}" in out
    assert "pick another --phrase-field" in out
    # the check is a second query, logged like any other
    rows = (tmp_path / "decisions.jsonl").read_text().splitlines()
    assert json.loads(rows[-1])["aggs"][0]["type"] == "filters"


def test_a_phrase_that_matches_nothing_on_a_live_field_is_a_real_zero(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    window = _expected(fixture, "logs-app-*", lambda f: "message" in f)
    rc, out, _ = _smoke(b, capsys, phrase="zebra quokka nebula")
    assert rc == 0 and out.startswith("OK ") and "hits_total=0" in out
    assert f"phrase_field_docs={window}/{window}" in out


def test_an_empty_window_is_empty_not_zero(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, phrase="returned HTTP", since="now-1m", until="now-1m")
    report = esbridge.run_smoke(lambda query: esbridge.run_case(b, "stub", query), q)
    assert esbridge.print_smoke("stub", q, report) == 3
    assert "no document in this index and window at all" in capsys.readouterr().out


def test_eq_on_a_keep_field_narrows_and_on_a_missing_field_is_empty(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    dataset = next(eseval.flatten(d.source)["data_stream.dataset"] for d in fixture.docs
                   if d.index == "logs-app-*")
    want = _expected(fixture, "logs-app-*", lambda f: f.get("data_stream.dataset") == dataset)
    rc, out, report = _smoke(b, capsys, eq=[("data_stream.dataset", dataset)])
    assert rc == 0 and report["hits_total"] == want and dataset not in out
    # a value nobody has: a real zero, the field is there
    rc, out, _ = _smoke(b, capsys, eq=[("data_stream.dataset", "nope.nope")])
    assert rc == 0 and out.startswith("OK ") and "fields_checked=1" in out
    # a listed field this index never fills (a label named differently here)
    rc, out, _ = _smoke(b, capsys, eq=[("job.status", "Failed"), ("transaction.result", "ok")])
    assert rc == 3 and "transaction.result holds no documents among" in out
    # two values nobody has, one of them on an empty field: still found
    rc, out, _ = _smoke(b, capsys, eq=[("data_stream.dataset", "nope"), ("transaction.result", "ok")])
    assert rc == 3 and "transaction.result holds no documents in this index and window" in out
    assert "data_stream.dataset holds" not in out


def test_eq_on_an_identifier_takes_a_label_this_run_issued(stub, tmp_path, capsys, fixture):
    server = next(eseval.flatten(d.source)["agent.name"] for d in fixture.docs
                  if d.index == "logs-app-*")
    want = _expected(fixture, "logs-app-*", lambda f: f.get("agent.name") == server)
    b = _bridge(stub, tmp_path)
    # the literal is refused, whoever typed it
    rc, out, _ = _smoke(b, capsys, eq=[("agent.name", server)])
    assert rc == 2 and "code=literal_identifier" in out and server not in out
    # a typed seed gives the label, the same one every run
    labels = esbridge.seed_terms(b.config, b.scrubber, [f"SERVER_NAME={server}"])
    again = esbridge.seed_terms(b.config, elastic.EsScrubber(b.config, tier2="none"),
                                [f"SERVER_NAME={server}"])
    assert labels == again and re.fullmatch(r"[a-z]{2,5}-(amer|emea|apj|aus)-s\d{2}", labels[0])
    rc, out, report = _smoke(b, capsys, eq=[("agent.name", labels[0])])
    assert rc == 0 and report["hits_total"] == want and server not in out
    # a label of the wrong type, and one never issued
    org = b.scrubber.seed("Contoso Holdings")
    rc, out, _ = _smoke(b, capsys, eq=[("agent.name", org)])
    assert rc == 2 and "code=label_type_mismatch" in out
    rc, out, _ = _smoke(b, capsys, eq=[("agent.name", "ctr-amer-s77")])
    assert rc == 2 and "code=unknown_label" in out


def test_a_typed_seed_needs_a_site_map_type(tmp_path):
    cfg = _config("https://kibana-stub.example.net", tmp_path)
    with pytest.raises(elastic.Refused) as e:
        esbridge.seed_terms(cfg, elastic.EsScrubber(cfg, tier2="none"), ["PASSWORD=hunter2"])
    assert e.value.code == "bad_request" and "hunter2" not in e.value.message


@pytest.fixture
def knob_stub(fixture, request):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices, **request.param),
                           cookie="sid=synthetic").start()
    yield kb
    kb.stop()


@pytest.mark.parametrize("knob_stub", [{}], indirect=True)
def test_terms_counts_that_add_up_print_the_error_bound_and_no_note(knob_stub, tmp_path, capsys):
    b = _bridge(knob_stub, tmp_path)
    rc, out, report = _smoke(b, capsys, size=0, count_by="agent.name", buckets=3)
    assert rc == 0 and "count_error_bound=0" in out
    assert f"docs_with_field={report['hits_total']}" in out and "NOTE" not in out


@pytest.mark.parametrize("knob_stub", [{"missing": {"agent.name": 4}}], indirect=True)
def test_terms_counts_short_of_hits_total_say_why(knob_stub, tmp_path, capsys):
    b = _bridge(knob_stub, tmp_path)
    rc, out, report = _smoke(b, capsys, size=0, count_by="agent.name", buckets=3)
    total = report["hits_total"]
    present = re.search(r"docs_with_field=(\d+)", out)
    assert rc == 0 and present and int(present.group(1)) < total
    assert f"NOTE     {total - int(present.group(1))} of {total} matching documents have no " \
           "agent.name and are in no bucket" in out


@pytest.mark.parametrize("knob_stub", [{"terms_error": 3}], indirect=True)
def test_terms_counts_from_many_shards_print_the_bound(knob_stub, tmp_path, capsys):
    b = _bridge(knob_stub, tmp_path)
    rc, out, report = _smoke(b, capsys, size=0, count_by="agent.name", buckets=3)
    assert rc == 0 and "count_error_bound=3" in out
    assert "NOTE     each bucket count may be low by up to 3" in out
    # the total still reconciles, as in Elasticsearch: no "does not add up" note
    assert "does not add up" not in out


@pytest.mark.parametrize("aggs,hits_total,needle", [
    # a multi-valued field: more bucket entries than documents
    ({"count_by": {"buckets": [{"key": "a", "doc_count": 6}, {"key": "b", "doc_count": 6}],
                   "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0},
      "count_by_field": {"buckets": {"present": {"doc_count": 10}}}}, 10,
     "buckets + other_docs = 12, more than the 10 documents with agent.name"),
    # neither the total nor the documents with the field
    ({"count_by": {"buckets": [{"key": "a", "doc_count": 4}], "sum_other_doc_count": 1,
                   "doc_count_error_upper_bound": 2},
      "count_by_field": {"buckets": {"present": {"doc_count": 9}}}}, 10,
     "buckets + other_docs = 5 does not add up to hits_total=10 or to the 9 documents"),
    ({"count_by": {"buckets": [{"key": "a", "doc_count": 4}], "sum_other_doc_count": 0,
                   "doc_count_error_upper_bound": -1},
      "count_by_field": {"buckets": {"present": {"doc_count": 4}}}}, 4,
     "could not bound the bucket count error"),
])
def test_terms_reconciliation_notes(capsys, aggs, hits_total, needle):
    q = esbridge.smoke_query(CFG0, size=0, count_by="agent.name")
    report = {"refused": None, "output": {"hits": {}, "aggregations": aggs},
              "hits_total": hits_total, "hits_shown": 0, "seconds": 0.1, "labels_issued": 0,
              "dropped": []}
    assert esbridge.print_smoke("stub", q, report) == 0
    out = capsys.readouterr().out
    assert "NOTE" in out and needle in out and "key" not in out


_CAP_WORDS = ("harbor", "violet", "granite", "meadow", "copper", "lantern", "orchid", "summit",
              "willow")


def _event_fields(n):
    return [(f"event.f{i:02d}", "x") for i in range(n)]


@pytest.mark.parametrize("max_buckets,eq,phrase_field", [
    (50, [("data_stream.dataset", "app.engine")], "message"),
    (50, [("data_stream.dataset", "app.engine"), ("log.level", "error")], "transaction.name"),
    (50, _event_fields(20), "message"),        # 3 buckets a field: past max_buckets, split
    (2, _event_fields(3), "message"),          # a cap smaller than one field's buckets
    (1, [("log.level", "error")], "message"),
])
def test_the_zero_hit_check_is_never_refused_for_a_query_that_was_allowed(
        tmp_path, max_buckets, eq, phrase_field):
    from hider import esquery

    cfg = elastic.parse({**json.loads(elastic.EXAMPLE.read_text()), "max_buckets": max_buckets})
    for n in range(cfg.max_phrases + 2):
        q = esbridge.smoke_query(cfg, phrase=list(_CAP_WORDS[:n]), phrase_field=phrase_field,
                                 eq=eq, since="now-6h")
        s = elastic.EsScrubber(cfg, tier2="none")
        try:
            esquery.compile_query(q, cfg, s)
        except elastic.Refused as e:
            assert n > cfg.max_phrases and e.code == "size_cap"
            continue
        probes, fields = esbridge.field_probe(q, max_buckets=cfg.max_buckets)
        for probe in probes:
            esquery.compile_query(probe, cfg, s)  # raises if the check would be refused
        names = [k for p in probes for k in p["aggs"][esbridge.PHRASE_FIELD_AGG]["filters"]]
        assert len(names) == len(set(names)) and all(
            len(p["aggs"][esbridge.PHRASE_FIELD_AGG]["filters"]) <= max_buckets for p in probes)


def test_a_query_at_the_phrase_cap_gets_its_zero_hit_check(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    dataset = next(eseval.flatten(d.source)["data_stream.dataset"] for d in fixture.docs
                   if d.index == "logs-app-*")
    rc, out, report = _smoke(b, capsys, phrase=list(_CAP_WORDS[:8]), phrase_field="transaction.name",
                             eq=[("data_stream.dataset", dataset), ("log.level", "error")])
    assert "refused" not in report["field_probe"], report["field_probe"]
    assert rc == 3 and "transaction.name holds no documents" in out
    # many filtered fields: the check is split, and still not refused
    rc, out, report = _smoke(b, capsys, phrase=list(_CAP_WORDS[:8]),
                             eq=[("data_stream.dataset", dataset)] + _event_fields(17))
    assert "refused" not in report["field_probe"] and report["field_probe"]["queries"] == 2
    assert rc == 3 and "event.f00 holds no documents" in out


def test_one_phrase_over_the_cap_is_refused_before_kibana(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    n = len(stub.engine.requests)
    rc, out, _ = _smoke(b, capsys, phrase=list(_CAP_WORDS[:9]))
    assert rc == 2 and "code=size_cap" in out
    assert "the query has 9 distinct phrases" in out and "the cap is 8 per query" in out
    assert not any(w in out for w in _CAP_WORDS)
    assert len(stub.engine.requests) == n
    row = json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    assert row["refused"] == "size_cap" and "text_queries" not in row


@pytest.mark.parametrize("no_browser", [True, False])
def test_es_smoke_stub_expired_is_refused_with_and_without_a_browser(monkeypatch, capsys, no_browser):
    """--expired exits 2 in the browser too. The browser here is SimBrowser
    parking its tab the way BrowserTransport does (a navigation through
    /login first), which is what signed the expired run back in before."""
    from hider import cli

    monkeypatch.setattr(esbridge, "BrowserTransport",
                        lambda profile_dir: eseval.SimBrowser([], headless=True, parks=True))
    argv = ["es-smoke", "--stub", "--tier2", "none", "--expired"]
    if no_browser:
        argv.append("--no-browser")
    assert cli.main(argv) == 2
    out = capsys.readouterr().out
    assert out.startswith("REFUSED ") and "code=session_expired" in out


def test_a_parked_headless_browser_is_signed_in_only_while_the_stub_idp_is_open(fixture):
    cluster_of = lambda kb: elastic.Cluster("stub", kb.url)
    for sso, expect in ((True, None), (False, "session_expired")):
        kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), signed_in=False,
                               sso_headless=True, sso=sso).start()
        try:
            browser = eseval.SimBrowser([], headless=True, parks=True)
            try:
                esbridge.KibanaSession(browser).probe(cluster_of(kb))
                got = None
            except elastic.Refused as e:
                got = e.code
            assert got == expect and kb.logins == (1 if sso else 0)
        finally:
            kb.stop()


def test_es_smoke_cli_repeated_phrases_eq_and_the_empty_exit_code(capsys):
    from hider import cli

    base = ["es-smoke", "--stub", "--no-browser", "--tier2", "none", "--since", "now-6h"]
    assert cli.main(base + ["--phrase", "returned HTTP", "--phrase", "429",
                            "--eq", "log.level=error"]) in (0, 3)
    captured = capsys.readouterr()
    q = json.loads(captured.err.split("query     ", 1)[1].splitlines()[0])
    assert [f["op"] for f in q["filters"]] == ["eq", "phrase", "phrase"]
    assert cli.main(base + ["--phrase", "x", "--phrase-field", "transaction.name"]) == 3
    assert "EMPTY" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="FIELD=VALUE"):
        cli.main(base + ["--eq", "log.level"])
    with pytest.raises(SystemExit, match="give a --phrase"):
        cli.main(base + ["--phrase-field", "message"])


# -- the session lifecycle: one login, many runs ----------------------------------------
#
# Kibana's session cookie has no expiry, so it lives exactly as long as the
# browser that holds it. The stub issues it that way and its IdP completes
# only for a headed top-level navigation; SimBrowser keeps Chrome's cookie
# rules. Before the broker, es-login signed in and closed its browser, and
# every es-smoke started a new one: the replay below shows the stub now
# refuses that, as the real cluster did.


@pytest.fixture
def sso(fixture):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices)).start()
    yield kb
    kb.stop()


@pytest.fixture
def short_dir():
    """A socket path must fit in 104 bytes; pytest's tmp_path on macOS does not."""
    import tempfile
    d = tempfile.mkdtemp(prefix="hb-", dir="/tmp")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def _sso_config(url: str, profile: Path, *, vocabulary=False, **extra) -> elastic.ElasticConfig:
    """A broker config for the transport tests. The name vocabulary is off
    unless a test is about it: signing in starts a build, and a build on a
    stub that never answers (slow=True) would refuse every page under test
    for a reason that has nothing to do with the transport."""
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": url}}
    raw["profile_dir"] = str(profile)
    if not vocabulary:
        raw["vocabulary"] = {"fields": []}
    raw.update(extra)
    return elastic.parse(raw, source="test")


def _probe(browser, cluster) -> None:
    esbridge.KibanaSession(browser).probe(cluster)


def test_stub_session_cookie_dies_with_the_browser(sso):
    cluster = elastic.Cluster("stub", sso.url)
    profile: list = []
    first = eseval.SimBrowser(profile)
    assert first.login(cluster) and sso.logins == 1
    _probe(first, cluster)
    assert [c.name for c in first.cookies if c.discard] == ["sid"]  # a session cookie
    first.close()
    assert profile == []  # nothing about the session reached the profile
    second = eseval.SimBrowser(profile)
    with pytest.raises(elastic.Refused) as e:
        _probe(second, cluster)
    assert e.value.code == "session_expired"


def test_headless_sso_never_completes_and_a_fetch_never_signs_in(sso):
    cluster = elastic.Cluster("stub", sso.url)
    assert eseval.SimBrowser([], headless=True).login(cluster, timeout=0.3) is False
    with pytest.raises(elastic.Refused) as e:
        _probe(eseval.SimBrowser([]), cluster)  # headed, but a fetch is not a navigation
    assert e.value.code == "session_expired"
    assert sso.logins == 0


def test_the_lifecycle_before_the_broker_fails_against_the_stub(sso, tmp_path):
    """es-login in one browser, es-smoke in the next: refused every time."""
    cfg = _sso_config(sso.url, tmp_path / "p")
    profile: list = []
    login = eseval.SimBrowser(profile)
    assert login.login(cfg.cluster("stub"))
    login.close()  # what es-login's finally did
    for _ in range(2):
        b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                            esbridge.KibanaSession(eseval.SimBrowser(profile), sleep=lambda s: None))
        with pytest.raises(elastic.Refused) as e:
            b.run("stub", {"index": "logs-app-*", "size": 1})
        assert e.value.code == "session_expired"


class _ServedBroker:
    def __init__(self, cfg, sock, factory):
        self.broker = esbridge.Broker(cfg, factory, poll_interval=0.01)
        self.sock = sock
        self.thread = threading.Thread(target=self.broker.serve, args=(sock,), daemon=True)
        self.thread.start()
        for _ in range(200):
            if esbridge.broker_running(sock):
                break
            threading.Event().wait(0.02)

    def client(self, timeout=30.0):
        return esbridge.BrokerClient(self.sock, timeout=timeout)

    def stop(self):
        if self.thread.is_alive():
            try:
                self.client().call("stop")
            except elastic.Refused:
                pass
            self.thread.join(10)


@pytest.fixture
def served(sso, short_dir):
    cfg = _sso_config(sso.url, short_dir / "profile")
    esbridge.prepare_profile_dir(cfg.profile_dir)
    profile: list = []
    browsers: list = []

    def factory():
        browsers.append(eseval.SimBrowser(profile))  # headed, as es-broker launches it
        return browsers[-1]

    sb = _ServedBroker(cfg, esbridge.broker_socket(cfg.profile_dir), factory)
    sb.cfg, sb.profile, sb.browsers, sb.sso = cfg, profile, browsers, sso
    yield sb
    sb.stop()


def test_one_login_lasts_across_many_smoke_runs(served, fixture):
    c = served.client()
    assert c.call("login", cluster="stub", timeout=5)["signed_in"] is True
    for i in range(3):  # three es-smoke processes, one client each
        report = served.client().call("run", cluster="stub", tier2="none",
                                      query={"index": "logs-app-*", "size": 2})["report"]
        assert report["refused"] is None and report["hits_shown"] == 2
        assert eseval._leaks(report["output"], fixture.truth) == []
        # data-stream backing indices are admitted, as on the real cluster
        assert all(h["_index"].startswith(".ds-logs-app-") for h in report["output"]["hits"]["hits"])
    assert served.sso.logins == 1 and len(served.browsers) == 1
    # Kibana ends the session: refused, not retried; es-login signs in again
    served.sso.expire()
    report = c.call("run", cluster="stub", tier2="none", query={"index": "logs-app-*", "size": 1})["report"]
    assert report["refused"]["code"] == "session_expired"
    assert c.call("login", cluster="stub", timeout=5)["signed_in"] is True
    assert c.call("run", cluster="stub", tier2="none",
                  query={"index": "logs-app-*", "size": 1})["report"]["refused"] is None
    # stopping the bridge closes its browser, and the session goes with it
    served.stop()
    assert not served.sock.exists() and served.profile == []
    with pytest.raises(elastic.Refused) as e:
        served.client().call("run", cluster="stub", query={"index": "logs-app-*"})
    assert e.value.code == "session_expired" and "es-login" in e.value.message


def test_a_new_bridge_starts_signed_out(served):
    assert served.client().call("login", cluster="stub", timeout=5)["signed_in"]
    served.stop()
    again = _ServedBroker(served.cfg, served.sock, lambda: eseval.SimBrowser(served.profile))
    try:
        report = again.client().call("run", cluster="stub", tier2="none",
                                     query={"index": "logs-app-*", "size": 1})["report"]
        assert report["refused"]["code"] == "session_expired"
    finally:
        again.stop()


def test_a_headless_bridge_cannot_sign_in(sso, short_dir):
    cfg = _sso_config(sso.url, short_dir / "profile")
    esbridge.prepare_profile_dir(cfg.profile_dir)
    sb = _ServedBroker(cfg, esbridge.broker_socket(cfg.profile_dir),
                       lambda: eseval.SimBrowser([], headless=True))
    try:
        assert sb.client().call("login", cluster="stub", timeout=1)["signed_in"] is False
        assert sso.logins == 0
    finally:
        sb.stop()


def test_bridge_stops_when_its_browser_goes_away(served):
    assert served.client().call("login", cluster="stub", timeout=5)["signed_in"]
    served.browsers[0].closed = True  # the analyst closed the Chrome window
    served.thread.join(5)
    assert not served.thread.is_alive() and not served.sock.exists()


def test_bridge_socket_is_private_and_a_live_one_is_not_taken_over(served):
    import stat
    assert stat.S_IMODE(served.sock.stat().st_mode) == 0o600
    with pytest.raises(elastic.ConfigError, match="already running"):
        esbridge.Broker(served.cfg, lambda: None).serve(served.sock)
    assert esbridge.broker_running(served.sock)


def test_a_stale_socket_is_replaced(sso, short_dir):
    import socket as _socket
    cfg = _sso_config(sso.url, short_dir / "profile")
    esbridge.prepare_profile_dir(cfg.profile_dir)
    sock = esbridge.broker_socket(cfg.profile_dir)
    dead = _socket.socket(_socket.AF_UNIX)
    dead.bind(str(sock))
    dead.close()  # a socket file nobody listens on: a crashed bridge
    assert sock.exists() and not esbridge.broker_running(sock)
    sb = _ServedBroker(cfg, sock, lambda: eseval.SimBrowser([]))
    try:
        assert esbridge.broker_running(sock)
    finally:
        sb.stop()


class _Exploding:
    def start(self):
        pass

    def request(self, *a, **k):
        raise KeyError("Contoso Holdings at https://kibana-emea.example.net")

    def login(self, *a, **k):
        raise RuntimeError("https://kibana-emea.example.net/login")

    def close(self):
        pass


@pytest.mark.parametrize("req,code", [
    ("not a dict", "bad_request"),
    ({"op": "ping"}, "bad_request"),                                    # no schema
    ({"schema": esbridge.BROKER_SCHEMA, "op": "shell"}, "bad_cluster"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "shell", "cluster": "stub"}, "bad_request"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "run", "cluster": "elsewhere"}, "bad_cluster"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "run", "cluster": "stub", "terms": "x"}, "bad_request"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "run", "cluster": "stub", "tier2": "gpt"}, "bad_request"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "run", "cluster": "stub", "log": "rel.jsonl"},
     "bad_request"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "login", "cluster": "stub", "timeout": 0}, "bad_request"),
    ({"schema": esbridge.BROKER_SCHEMA, "op": "login", "cluster": "stub"}, "bridge_error"),
])
def test_broker_fails_closed_and_says_nothing_it_should_not(tmp_path, req, code):
    cfg = _sso_config("https://kibana-stub.example.net", tmp_path / "p")
    reply = esbridge.Broker(cfg, _Exploding).handle(req)
    assert reply["ok"] is False and reply["code"] == code
    assert "example.net" not in reply["message"] and "Contoso" not in reply["message"]


def test_broker_run_with_a_failing_transport_is_a_refusal_not_a_page(tmp_path):
    cfg = _sso_config("https://kibana-stub.example.net", tmp_path / "p")
    reply = esbridge.Broker(cfg, _Exploding).handle(
        {"schema": esbridge.BROKER_SCHEMA, "op": "run", "cluster": "stub", "tier2": "none",
         "query": {"index": "logs-app-*", "size": 1}})
    assert reply["ok"] is False and reply["code"] == "bridge_error"
    assert "example.net" not in reply["message"] and "Contoso" not in reply["message"]


def test_bridge_code_never_reads_exports_or_stores_a_cookie():
    """The session stays in Chrome: no Playwright call that lifts cookies out
    of the browser or writes them anywhere is in the bridge."""
    import re as _re
    src = Path(esbridge.__file__).read_text()
    for call in ("storage_state", ".cookies(", "add_cookies", "clear_cookies", "Network.getCookies",
                 "Storage.getCookies", "document.cookie"):
        assert call not in src, call
    assert not _re.search(r"Set-Cookie|cookiejar", src)


def test_poll_timeout_comes_from_the_site_map(fixture, short_dir):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), slow=True).start()
    try:
        cfg = _sso_config(kb.url, short_dir / "profile", poll_timeout_s=1)
        assert cfg.poll_timeout_s == 1.0
        esbridge.prepare_profile_dir(cfg.profile_dir)
        sb = _ServedBroker(cfg, esbridge.broker_socket(cfg.profile_dir), lambda: eseval.SimBrowser([]))
        try:
            assert sb.client().call("login", cluster="stub", timeout=5)["signed_in"]
            report = sb.client().call("run", cluster="stub", tier2="none",
                                      query={"index": "logs-app-*", "size": 1})["report"]
            assert report["refused"]["code"] == "incomplete"
            assert kb.deleted  # the server-side search was released
        finally:
            sb.stop()
    finally:
        kb.stop()


# -- the CLI against a running bridge ------------------------------------------------------


@pytest.fixture
def site_map(served, short_dir):
    path = short_dir / "elastic.json"
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": served.sso.url}}
    raw["profile_dir"] = served.cfg.profile_dir
    path.write_text(json.dumps(raw))
    return str(path)


def test_es_login_then_many_es_smoke_runs_through_the_cli(served, site_map, capsys, fixture):
    from hider import cli

    assert cli.main(["es-login", "--config", site_map, "--cluster", "stub", "--timeout", "5"]) == 0
    out = capsys.readouterr()
    # the Kibana URL is masked like everything else: cluster names only
    for stream in (out.out, out.err):
        assert served.sso.url not in stream and "127.0.0.1" not in stream and "http" not in stream
    assert "signed in: cluster stub" in out.out
    for _ in range(3):
        rc = cli.main(["es-smoke", "--config", site_map, "--cluster", "stub", "--tier2", "none",
                       "--since", "now-6h", "--count-by", "agent.name", "--interval", "1h"])
        res = capsys.readouterr()
        assert rc == 0 and res.out.startswith("OK ") and "buckets=" in res.out
        for v in fixture.truth:
            if len(v) > 4:
                assert v not in res.out
    assert served.sso.logins == 1
    assert cli.main(["es-logout", "--config", site_map]) == 0
    assert "bridge stopped" in capsys.readouterr().out
    served.thread.join(10)
    rc = cli.main(["es-smoke", "--config", site_map, "--cluster", "stub", "--tier2", "none"])
    res = capsys.readouterr()
    assert rc == 2 and "REFUSED" in res.out and "code=session_expired" in res.out


def test_es_smoke_through_the_bridge_checks_empty_fields_and_takes_typed_seeds(
        served, site_map, capsys, fixture):
    from hider import cli

    assert cli.main(["es-login", "--config", site_map, "--cluster", "stub", "--timeout", "5"]) == 0
    capsys.readouterr()
    base = ["es-smoke", "--config", site_map, "--cluster", "stub", "--tier2", "none",
            "--since", "now-6h"]
    # the zero-hit check is a second run in the bridge
    assert cli.main(base + ["--phrase", "returned HTTP", "--phrase-field", "transaction.name"]) == 3
    out = capsys.readouterr().out
    assert out.startswith("EMPTY ") and "transaction.name holds no documents" in out
    # a typed seed in the bridge gives the label an identifier filter needs
    server = next(eseval.flatten(d.source)["agent.name"] for d in fixture.docs
                  if d.index == "logs-app-*")
    cfg = served.cfg
    label = esbridge.seed_terms(cfg, elastic.EsScrubber(cfg, tier2="none"),
                                [f"SERVER_NAME={server}"])[0]
    assert cli.main(base + ["--term", f"SERVER_NAME={server}", "--eq", f"agent.name={label}",
                            "--phrase", "returned HTTP", "--phrase", "429"]) in (0, 3)
    res = capsys.readouterr()
    assert res.out.startswith(("OK ", "EMPTY ")) and server not in res.out
    assert f"seeded    {label}" in res.err
    assert cli.main(base + ["--term", "PASSWORD=hunter2"]) == 2
    res = capsys.readouterr()
    assert "code=bad_request" in res.out and "hunter2" not in res.out


def test_es_login_timeout_masks_the_url_too(sso, short_dir, capsys):
    from hider import cli

    cfg = _sso_config(sso.url, short_dir / "profile")
    esbridge.prepare_profile_dir(cfg.profile_dir)
    sb = _ServedBroker(cfg, esbridge.broker_socket(cfg.profile_dir),
                       lambda: eseval.SimBrowser([], headless=True))
    path = short_dir / "elastic.json"
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": sso.url}}
    raw["profile_dir"] = cfg.profile_dir
    path.write_text(json.dumps(raw))
    try:
        assert cli.main(["es-login", "--config", str(path), "--cluster", "stub",
                         "--timeout", "1"]) == 1
        out = capsys.readouterr()
        assert "timed out: cluster stub" in out.out
        assert "127.0.0.1" not in out.out + out.err and "http" not in out.out + out.err
    finally:
        sb.stop()


# -- the browser transport, when it can run --------------------------------------------


def _browser_available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    import os
    return os.path.exists("/Applications/Google Chrome.app") or bool(
        shutil.which("google-chrome") or shutil.which("google-chrome-stable"))


def _kibana_cookie_rows(profile: Path, host: str) -> list[tuple]:
    """Cookie rows Chrome wrote to the profile's cookie store for ``host``."""
    import sqlite3
    import tempfile
    rows = []
    for db in profile.rglob("Cookies"):
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "c.db"
            shutil.copy(db, copy)  # Chrome holds a lock on the original
            con = sqlite3.connect(copy)
            try:
                rows += con.execute("SELECT host_key, name, is_persistent FROM cookies "
                                    "WHERE host_key LIKE ?", (f"%{host}%",)).fetchall()
            except sqlite3.DatabaseError:
                pass
            finally:
                con.close()
    return rows


@pytest.mark.skipif(not _browser_available(), reason="playwright and Chrome are needed")
def test_browser_login_keeps_the_session_and_it_dies_with_the_browser(fixture, short_dir):
    """Real Chrome, real session cookie: the sign-in serves every request
    while this browser lives, and the next browser starts signed out. Before
    the fix, login() closed the browser and the first run here was refused."""
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), sso_headless=True).start()
    profile = short_dir / "profile"
    transport = esbridge.BrowserTransport(profile)
    try:
        cfg = _sso_config(kb.url, profile, vocabulary=True)
        cluster = cfg.cluster("stub")
        index = elastic.VocabularyIndex(None)
        built, _ = eseval.build_vocabulary(cfg, kb.engine)
        index.put("stub", built)   # as es-login leaves it

        def bridge(t):
            return esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                                   esbridge.KibanaSession(t, poll_interval=0.1), index=index)

        assert transport.login(cluster, timeout=20)
        for _ in range(2):
            o = bridge(transport).run("stub", {"index": "logs-worker-*", "size": 3})
            assert o.refused is None and o.hits_shown == 3
            assert all(h["_index"].startswith(".ds-") for h in o.output["hits"]["hits"])
            assert eseval._leaks(o.output, fixture.truth) == []
        assert kb.logins == 1
        posts = [p for m, p, _ in kb.calls if m == "POST"]
        assert posts and posts[0] == esbridge.SEARCH_PATH
        # Kibana ends the session: refused, and a login in the same browser recovers
        kb.expire()
        with pytest.raises(elastic.Refused) as e:
            bridge(transport).run("stub", {"index": "logs-worker-*", "size": 1})
        assert e.value.code == "session_expired"
        assert transport.login(cluster, timeout=20)
        assert bridge(transport).run("stub", {"index": "logs-worker-*", "size": 1}).refused is None
        transport.close()
        # nothing reached the bridge's directory, and the next browser is signed
        # out (the stub's IdP now behaves like the real one for headless, so it
        # cannot quietly sign the new browser back in)
        assert _kibana_cookie_rows(profile, "127.0.0.1") == []
        assert not list(profile.rglob("Cookies"))
        kb.sso_headless = False
        transport = esbridge.BrowserTransport(profile)
        with pytest.raises(elastic.Refused) as e:
            bridge(transport).run("stub", {"index": "logs-worker-*", "size": 1})
        assert e.value.code == "session_expired" and kb.logins == 2
    finally:
        transport.close()
        kb.stop()


@pytest.mark.skipif(not _browser_available(), reason="playwright and Chrome are needed")
def test_browser_headless_sso_never_completes(fixture, short_dir):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices)).start()
    transport = esbridge.BrowserTransport(short_dir / "profile", headless=True)
    try:
        assert transport.login(elastic.Cluster("stub", kb.url), timeout=3) is False
        assert kb.logins == 0
    finally:
        transport.close()
        kb.stop()


@pytest.mark.skipif(not _browser_available(), reason="playwright and Chrome are needed")
def test_broker_with_real_chrome_serves_many_runs_from_one_login(fixture, short_dir):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), sso_headless=True).start()
    cfg = _sso_config(kb.url, short_dir / "profile")
    profile = esbridge.prepare_profile_dir(cfg.profile_dir)
    sb = _ServedBroker(cfg, esbridge.broker_socket(profile),
                       lambda: esbridge.BrowserTransport(profile, headless=True))
    try:
        assert sb.client(60).call("login", cluster="stub", timeout=20)["signed_in"]
        for _ in range(3):
            r = sb.client(60).call("run", cluster="stub", tier2="none",
                                   query={"index": "logs-app-*", "size": 2})["report"]
            assert r["refused"] is None and r["hits_shown"] == 2
        assert kb.logins == 1
    finally:
        sb.stop()
        kb.stop()


# -- the job-name vocabulary on the live path ------------------------------------


def test_a_page_before_the_vocabulary_is_built_is_refused_and_never_submitted(stub, tmp_path):
    """Fail closed: until the cluster's names are known, no page is shown,
    and the query itself never reaches Kibana."""
    b = _bridge(stub, tmp_path, vocabulary=False)   # as a bridge is mid-build
    n = len(stub.engine.requests)
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", {"index": "logs-app-*", "size": 1})
    assert e.value.code == "vocabulary_building"
    assert "does not yet cover" in e.value.message
    assert len(stub.engine.requests) == n       # nothing was submitted
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    assert rows[-1]["refused"] == "vocabulary_building"


def test_a_built_vocabulary_is_applied_once_per_case_and_logged_as_counts(stub, tmp_path):
    b = _bridge(stub, tmp_path)
    n = len(stub.engine.requests)
    b.run("stub", {"index": "logs-app-*", "size": 1})
    b.run("stub", {"index": "logs-app-*", "size": 1})
    assert len(stub.engine.requests) == n + 2   # two queries, no vocabulary read
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    applied = [r for r in rows if r.get("vocabulary") == "applied"]
    assert len(applied) == 1 and applied[0]["state"] in ("ready", "stale")
    assert applied[0]["fields"]["job.name"] > 0
    # counts and field names, never a name
    blob = json.dumps(rows)
    for job, _message, _phrase in eseval.UNMARKED_JOBS:
        assert job not in blob


def test_an_unmarked_job_name_is_labelled_on_the_first_live_page(stub, tmp_path, fixture):
    b = _bridge(stub, tmp_path)
    job, message, phrase = eseval.UNMARKED_JOBS[0]
    o = b.run("stub", {"index": "logs-worker-*", "time_range": {"gte": "now-6h", "lte": "now"},
                       "size": 5, "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
    page = json.dumps(o.output)
    assert o.hits_shown >= 1 and job not in page and "finished with warnings" in page
    assert eseval._leaks(o.output, fixture.truth) == []


def test_smoke_shows_each_vocabulary_field_against_its_cap(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    q = esbridge.smoke_query(b.config, size=0, since="now-6h")
    assert esbridge.smoke(b, "stub", q) == 0
    line = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("VOCAB"))
    assert "labels.site_name=" in line and f"/{CFG0.vocabulary_max}" in line
    # the example map lists every field it may list, so nothing is left out
    assert "NOT READ" not in line
    # the caps are read against what the fixture actually holds, so this
    # stays true as the fixture grows
    counts = b.vocabulary["stub"]["fields"]
    widest = max(counts, key=lambda f: counts[f])
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": stub.url}}
    raw["vocabulary"]["max"] = counts[widest]  # exactly at it: 100% of the cap
    cfg = elastic.parse(raw, source="test")
    index = elastic.VocabularyIndex(None)
    built, _ = eseval.build_vocabulary(cfg, stub.engine)
    index.put("stub", built)
    b2 = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), b.session,
                         log_path=tmp_path / "d2.jsonl", index=index)
    assert esbridge.smoke(b2, "stub", q) == 0
    # an investigation about to stop, said before it does
    assert widest in capsys.readouterr().out.split("NEAR CAP: ")[1]


def test_a_build_over_the_cap_leaves_the_saved_vocabulary_alone(stub, tmp_path):
    """The cap is the build's, not the case's: a field with more values than
    the site map allows abandons the build and teaches the index nothing."""
    b = _bridge(stub, tmp_path)
    counts = b.vocabulary["stub"]["fields"] if b.vocabulary else {}
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": stub.url}}
    raw["vocabulary"]["max"] = 1   # the fixture has more job names than this
    cfg = elastic.parse(raw, source="test")
    index = elastic.VocabularyIndex(None)
    with pytest.raises(elastic.Refused) as e:
        eseval.build_vocabulary(cfg, stub.engine)
    assert e.value.code == "vocabulary" and "vocabulary.max" in e.value.message
    assert index.get("stub") is None
    # and a case on that bridge is refused rather than shown
    cold = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), b.session,
                           log_path=tmp_path / "d3.jsonl", index=index)
    with pytest.raises(elastic.Refused) as e:
        cold.run("stub", {"index": "logs-app-*", "size": 1})
    assert e.value.code == "vocabulary_building"


def test_smoke_names_the_learnable_fields_a_site_map_leaves_out(stub, tmp_path, capsys):
    """A site map that lists fewer fields than it could is a choice, and the
    values of the fields it skips stay readable in message text. Names only,
    and only names the map itself already holds."""
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": stub.url}}
    raw["vocabulary"]["fields"] = ["job.name"]
    b = _bridge(stub, tmp_path)
    b.config = elastic.parse(raw, source="test")
    b.scrubber = elastic.EsScrubber(b.config, tier2="none")
    assert esbridge.smoke(b, "stub", esbridge.smoke_query(b.config, size=0, since="now-6h")) == 0
    line = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("VOCAB"))
    assert "NOT READ (readable in text): labels.resource_name, labels.site_name, " \
           "labels.tenant_full_name, labels.tenant_name" in line
    assert "job.name=" in line  # what it does read is still counted


def test_the_smoke_report_reports_readable_words_without_naming_them(stub, tmp_path, fixture):
    """es-smoke output is read by scripts and agents as well as people, so
    a real customer name is never in it unasked. The label and the field
    it came from are decisions and always reported - enough to go and look
    the name up. The decision log carries neither word nor name."""
    b = _bridge(stub, tmp_path)
    s = b.scrubber
    label = s.label_for(b.config.rule("job.name"), "Backup")
    assert s.readable_words.get(label) == "Backup"
    report = esbridge.run_case(b, "stub", {"index": "logs-app-*", "size": 1})
    assert {"label": label, "field": "job.name"} in report["readable_words"]
    assert "readable_names" not in report            # not merely unprinted
    assert "Backup" not in json.dumps(report)
    assert "Backup" not in (tmp_path / "decisions.jsonl").read_text()


def test_the_words_come_back_only_when_the_operator_asks(stub, tmp_path, fixture):
    b = _bridge(stub, tmp_path)
    b.scrubber.label_for(b.config.rule("job.name"), "Backup")
    report = esbridge.run_case(b, "stub", {"index": "logs-app-*", "size": 1}, show_names=True)
    assert "Backup" in report["readable_names"]
    assert "Backup" not in (tmp_path / "decisions.jsonl").read_text()
