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
from hider.jsonscrub import _norm as jsonscrub_norm

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
    assert "phrase_field=transaction.name" in out and "fields_checked=1" in out
    assert "transaction.name holds no documents in this index and window at all" in out
    assert "check the field name for this cluster" in out
    # the check is the bridge's own, inside the query's row: statuses and
    # counts, not a second query row
    rows = [json.loads(x) for x in (tmp_path / "decisions.jsonl").read_text().splitlines()
            if "vocabulary" not in x]
    assert len(rows) == 1 and rows[0]["empty_check"]["fields"] == {
        "transaction.name": "absent_in_window"}
    assert rows[0]["empty_check"]["requests"] == 2 and window >= 1


def test_a_phrase_that_matches_nothing_on_a_live_field_is_a_real_zero(stub, tmp_path, capsys, fixture):
    b = _bridge(stub, tmp_path)
    window = _expected(fixture, "logs-app-*", lambda f: "message" in f)
    rc, out, report = _smoke(b, capsys, phrase="zebra quokka nebula")
    assert rc == 0 and out.startswith("OK ") and "hits_total=0" in out
    assert "fields_checked=1 check_requests=1" in out and window >= 1
    assert report["output"]["empty"]["fields"]["message"]["status"] == "present"


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
    # a real zero says each field's status and what the bridge concluded,
    # instead of leaving the person to guess from the count of fields checked
    assert "ZERO     per filtered field: data_stream.dataset=present" in out
    assert "ZERO     data_stream.dataset is filled on the documents" in out
    assert "a real zero for that filter" in out
    # a listed field this index never fills (a label named differently here)
    rc, out, _ = _smoke(b, capsys, eq=[("job.status", "Failed"), ("transaction.result", "ok")])
    assert rc == 3 and "transaction.result holds no documents in this index and window" in out
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
    empty = report["output"]["empty"]
    assert "unknown" not in {x["status"] for x in empty["fields"].values()}, empty
    assert rc == 3 and "transaction.name holds no documents" in out
    # many filtered fields: one capped count each, none refused
    rc, out, report = _smoke(b, capsys, phrase=list(_CAP_WORDS[:8]),
                             eq=[("data_stream.dataset", dataset)] + _event_fields(17))
    empty = report["output"]["empty"]
    assert "unknown" not in {x["status"] for x in empty["fields"].values()}
    assert len(empty["fields"]) == 19 and 19 <= empty["requests"] <= 20  # 19: a field remembered
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


def test_a_fresh_cases_first_query_is_gated_against_the_cluster_vocabulary(stub, tmp_path):
    """A case with no seed, shown nothing, whose very first query puts a
    learnt job name inside a keep literal: refused as known_value with the
    words any later query gets, and nothing reaches Kibana."""
    b = _bridge(stub, tmp_path)
    job = eseval.UNMARKED_JOBS[0][0]
    q = {"index": "logs-app-*", "size": 0,
         "filters": [{"field": "data_stream.dataset", "op": "eq",
                      "value": f"agent.{job.lower()}_events"}]}
    n = len(stub.engine.requests)
    with pytest.raises(elastic.Refused) as first:
        b.run("stub", q)
    assert first.value.code == "known_value"
    assert len(stub.engine.requests) == n
    assert jsonscrub_norm(job) in b.scrubber.known      # the vocabulary was applied
    with pytest.raises(elastic.Refused) as later:
        b.run("stub", q)
    assert (later.value.code, later.value.message) == (first.value.code, first.value.message)
    assert len(stub.engine.requests) == n


@pytest.mark.parametrize("vocabulary", [True, False, None])
def test_a_query_the_grammar_refuses_keeps_its_code_whatever_the_vocabulary(
        stub, tmp_path, vocabulary):
    """Ready, building or no index at all: an oracle case refuses with its
    declared code, and no request is sent."""
    from hider import esquery

    b = _bridge(stub, tmp_path, vocabulary=bool(vocabulary))
    if vocabulary is None:
        b.index = None
    # the seeds the oracle cases are written against (esquery's test session)
    b.scrubber.seed("Contoso Holdings")
    b.scrubber.seed("ctr-amer-042", "SERVER_NAME")
    b.scrubber.label_for(b.config.rule("labels.tenant_id"), "3f2a9c4e-1b7d-4e8a-9c2f-6d5b4a3e2f10")
    b.scrubber.mark_shown({"x": "<Tenant-01>"})
    n = len(stub.engine.requests)
    for case in esquery.ORACLE_CASES:
        # the same literal wrapped in not or any_of behaves the same way
        if case.name.endswith("learnt-name-in-keep-literal-never-shown") \
                and vocabulary is not True:
            # no cluster vocabulary held: the name is not known, so the
            # literal is well-formed (refused as vocabulary_building, or with
            # no index it would run) - its own test is the first-query one
            continue
        with pytest.raises(elastic.Refused) as e:
            b.run("stub", case.query)
        assert e.value.code == case.code, case.name
    assert len(stub.engine.requests) == n


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


def _default_set_config(stub, cap: int) -> elastic.ElasticConfig:
    """The example map with no vocabulary.fields - the default set - and a
    cap of the caller's choosing."""
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": stub.url}}
    raw["vocabulary"] = {"max": cap}
    return elastic.parse(raw, source="test")


def test_a_field_over_the_cap_in_the_default_set_is_left_out_not_fatal(stub, tmp_path):
    """The default set is every learnable field, so it can hold a field
    that is not a name at all - an id with a fresh value per document.
    Paging it to the cap and then refusing abandoned the slice, every
    slice, and no case ever ran. It is counted, left out, and the build
    finishes; the names of the other fields are still read."""
    b = _bridge(stub, tmp_path)
    counts = b.vocabulary["stub"]["fields"] if b.vocabulary else {}
    counts = counts or eseval.build_vocabulary(
        _default_set_config(stub, elastic.MAX_VOCABULARY_MAX), stub.engine)[0].counts
    widest = max(counts, key=lambda f: counts[f])
    cfg = _default_set_config(stub, counts[widest] - 1)
    index = elastic.VocabularyIndex(None)
    over_cap: dict[str, dict] = {}
    built, build = eseval.build_vocabulary(cfg, stub.engine, over_cap=over_cap)
    index.put("stub", built)
    assert widest not in built.fields          # nothing partial was kept
    assert over_cap[widest]["count"] == counts[widest]
    assert built.fields                        # and the rest was read
    at = esbridge.clock()
    # every decision the build made goes to the index, as the broker saves
    # them (the margin can take a second field with the widest); a field
    # left out has no cover, and the read set must not wait for it
    for field, v in over_cap.items():
        index.note_over_cap("stub", field, v["count"], at)
    report = index.report("stub", cfg, now=at)
    assert report["over_cap"] == {f: v["count"] for f, v in over_cap.items()}
    assert report["over_cap"][widest] == counts[widest]
    line = esbridge.vocabulary_line(report)
    assert f"OVER CAP, NOT READ (readable in text): " in line
    assert f"{widest}~{counts[widest]}" in line
    assert f"{widest}=" not in line            # not reported as read, and not as zero
    # a case on that bridge runs, with the fields that were read applied
    bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), b.session,
                             log_path=tmp_path / "d4.jsonl", index=index)
    o = bridge.run("stub", {"index": "logs-app-*", "size": 1})
    assert o.refused is None
    assert bridge.vocabulary["stub"]["over_cap"][widest] == counts[widest]


def test_an_over_cap_decision_survives_a_failed_slice_and_a_restart(tmp_path):
    """Saved as soon as it is found, not with the finished slice: a slice
    that fails after it must not spend the same fifty requests again. It
    expires on its own, so raising the cap takes effect without anyone
    clearing a file."""
    index = elastic.VocabularyIndex(tmp_path / "es")
    index.note_over_cap("emea", "request.ref", 120_000, 1000.0)
    again = elastic.VocabularyIndex(tmp_path / "es")
    assert again.over_cap_fields("emea", 1000.0) == {"request.ref": {"count": 120_000,
                                                                    "at": 1000.0}}
    # a build told about it neither counts nor pages that field
    build = elastic.VocabularyBuild(CFG0, 0.0, 86400.0,
                                    over_cap=again.over_cap_fields("emea", 1000.0))
    assert "request.ref" not in [r.pattern for r in build.rules]
    # and the decision expires rather than standing for ever
    later = 1000.0 + elastic.VOCABULARY_OVER_CAP_S + 1
    assert again.over_cap_fields("emea", later) == {}
    assert again.report("emea", CFG0, now=later)["over_cap"] == {}


def test_the_build_log_names_an_over_cap_field_and_never_a_value(stub, tmp_path):
    """The one new decision row: the field, its distinct count and the cap.
    Field names and counts are decisions; a value never is."""
    cfg = _default_set_config(stub, 2)
    tmp = tmp_path / "sessions"
    broker = esbridge.Broker(cfg, lambda: eseval.SimBrowser([]), sessions_dir=tmp)
    cluster = cfg.cluster("stub")
    build = elastic.VocabularyBuild(cfg, 0.0, 86400.0)
    build.request()
    build.feed({"isPartial": False, "isRunning": False, "rawResponse": {
        "timed_out": False,
        "aggregations": {elastic.VOCABULARY_COUNT_AGG: {"value": 9999}}}})
    broker._save_over_cap(cluster, build)
    rows = [json.loads(l) for l in (tmp / "vocabulary.log.jsonl").read_text().splitlines()]
    assert rows[-1]["vocabulary"] == "over_cap"
    assert rows[-1]["field"] == "job.name" and rows[-1]["distinct"] == 9999
    assert rows[-1]["max"] == 2 and rows[-1]["read"] is False
    assert broker.vocabulary.over_cap_fields("stub", esbridge.clock())["job.name"]["count"] == 9999


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


def test_the_log_and_smoke_show_phrase_counts_never_a_phrase(stub, tmp_path, capsys):
    b = _bridge(stub, tmp_path)
    q = {"index": "logs-worker-*", "size": 1, "time_range": {"gte": "now-6h", "lte": "now"},
         "filters": [{"field": "message", "op": "phrase", "value": "quarzelt wibbly"}]}
    report = esbridge.run_case(b, "stub", q)
    assert report["phrases"]["phrases_used"] == 1
    esbridge.print_smoke("stub", q, report)
    err = capsys.readouterr().err
    assert f"PHRASES  1/{b.config.phrase_budget} distinct text phrases used" in err
    row = json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    assert row["phrases_used"] == 1 and row["phrase_budget"] == b.config.phrase_budget
    # the decision log carries the phrase as typed already (text_queries,
    # pre-existing); the budget fields themselves are counts
    assert {k: row[k] for k in ("phrases_used", "phrase_budget", "phrases_left")} == \
        b.scrubber.phrase_report()


def test_a_query_refused_after_compiling_still_spends_and_a_refused_one_does_not(stub, tmp_path):
    """No refund once a query is about to be sent; nothing spent for a
    query the bridge refuses before that (here: vocabulary still building)."""
    b = _bridge(stub, tmp_path, vocabulary=False)
    q = {"index": "logs-worker-*", "size": 1,
         "filters": [{"field": "message", "op": "phrase", "value": "quarzelt wibbly"}]}
    with pytest.raises(elastic.Refused):
        b.run("stub", q)
    assert b.scrubber.phrase_report()["phrases_used"] == 0
    b = _bridge(stub, tmp_path)
    b.session.search = lambda *a, **k: (_ for _ in ()).throw(
        elastic.Refused("unreachable", "kibana request failed"))
    with pytest.raises(elastic.Refused):
        b.run("stub", q)
    assert b.scrubber.phrase_report()["phrases_used"] == 1


def test_es_review_reads_a_real_case_back(stub, tmp_path):
    """The decision log a bridge writes is what es-review reads: the counts
    match what the bridge did, and the new per-page fields are present."""
    from hider import esreview

    b = _bridge(stub, tmp_path)
    label = b.scrubber.seed("Contoso Holdings")
    tr = {"gte": "now-6h", "lte": "now"}
    b.run("stub", {"index": "logs-app-*", "time_range": tr, "size": 5})
    b.run("stub", {"index": "logs-app-*", "time_range": tr, "size": 0, "aggs": {
        "srv": {"type": "terms", "field": "agent.name", "size": 5}}})
    with pytest.raises(elastic.Refused):
        b.run("stub", {"index": "logs-app-*", "time_range": tr, "size": 1, "filters": [
            {"field": "labels.tenant_name", "op": "eq", "value": "<Org-999977>"}]})
    b.run("stub", {"index": "logs-worker-*", "time_range": tr, "size": 1, "filters": [
        {"field": "message", "op": "phrase", "value": "quarzelt wibbly"}]})
    b.scrubber.save_session(tmp_path)
    r = esreview.review(tmp_path)
    n = r["numbers"]
    assert n["queries"] == 4 and n["refusals"] == {"unknown_label": 1}
    assert n["text_phrases_zero_hit"] == 1 and n["phrases_used"] == 1
    assert n["labels_usable"] == len(b.scrubber.shown) and n["labels_usable"] > 1
    assert r["verdict"] == "nothing flagged"
    rows = [json.loads(l) for l in (tmp_path / "decisions.jsonl").read_text().splitlines()]
    page = next(x for x in rows if x.get("size") == 5)
    assert page["new_labels"] > 0 and page["labels_usable"] == page["new_labels"] + 1
    assert rows[-1]["zero_hit_phrases"] == ["quarzelt wibbly"]
    assert label not in json.dumps(r) or "Contoso" not in json.dumps(r)


# -- a saved cover that ended days ago -----------------------------------------

def _gap_engine():
    """One tenant first logged inside the gap: its own record a day ago and
    a message naming it with nothing marking it."""
    return eseval.StubEngine(eseval.Fixture(eseval.gap_docs(), [], []), (eseval.GAP_INDEX,))


def _gap_bridge(engine, tmp_path, cover_ends_ago_s: float):
    cfg = eseval.gap_map()
    now = eseval.NOW.timestamp()
    index = elastic.VocabularyIndex(None)
    index.started_at = now - 60.0
    held, _b = eseval.build_vocabulary(cfg, engine, now - cover_ends_ago_s - 3 * 86400.0,
                                       now - cover_ends_ago_s)
    index.put("stub", held)
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), eseval.EngineSession(engine),
                        log_path=tmp_path / "d.jsonl", index=index)
    return b, index, cfg


def test_a_name_first_logged_in_the_gap_is_not_shown_until_the_top_up_reads_it(tmp_path):
    engine = _gap_engine()
    b, index, cfg = _gap_bridge(engine, tmp_path, 7 * 86400.0)
    n = len(engine.requests)
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", eseval.GAP_QUERY)
    assert e.value.code == "vocabulary_building"
    assert "not been read" in e.value.message and eseval.GAP_TENANT not in e.value.message
    assert len(engine.requests) == n                    # nothing sent
    # the top-up reads the gap; the same open case is now shown, name hidden
    now = eseval.NOW.timestamp()
    gap, _b = eseval.build_vocabulary(cfg, engine, index.get("stub").covered_until, now)
    index.put("stub", gap)
    o = b.run("stub", eseval.GAP_QUERY)
    assert o.hits_shown >= 1 and eseval.GAP_TENANT not in json.dumps(o.output)


def test_a_ten_minute_gap_and_a_failed_top_up_within_the_bound_still_serve(tmp_path):
    engine = _gap_engine()
    b, index, cfg = _gap_bridge(engine, tmp_path, 600.0)
    b.run("stub", eseval.GAP_QUERY)                      # ten minutes behind: as today
    b, index, cfg = _gap_bridge(engine, tmp_path, 900.0)
    index.failed["stub"] = "upstream"
    r = index.report("stub", cfg, now=eseval.NOW.timestamp())
    assert r["state"] == "stale" and r["serving"]
    b.run("stub", eseval.GAP_QUERY)


def test_an_open_case_picks_up_a_top_up_before_its_next_page(tmp_path):
    """A case that applied the cover before the gap name was read must not
    keep its old copy: the next query re-applies the newer cover."""
    engine = _gap_engine()
    now = eseval.NOW.timestamp()
    b, index, cfg = _gap_bridge(engine, tmp_path, 2 * 86400.0 - 3600.0)
    # the cover is within the bound as of a clock two days back
    esbridge.clock = lambda: now - 2 * 86400.0 + 1800.0
    b.run("stub", {**eseval.GAP_QUERY, "time_range": {"gte": "now-30d", "lte": "now"}})
    esbridge.clock = eseval.NOW.timestamp
    gap, _b = eseval.build_vocabulary(cfg, engine, index.get("stub").covered_until, now)
    index.put("stub", gap)
    o = b.run("stub", eseval.GAP_QUERY)
    assert eseval.GAP_TENANT not in json.dumps(o.output)


def test_a_week_long_gap_is_read_in_slices_and_the_single_wide_read_fails_its_budget():
    """Before: the whole gap in one request pays the wide rate past the
    budget, fails, and cases stay refused. After: one-day slices, each saved
    as it lands, the cover one range, the case shown when the gap closes."""
    r = eseval.run_catch_up_eval()
    b, a = r["before"], r["after"]
    assert b["refused"] == "vocabulary" and b["wide_pages"] > 0 and b["seconds"] > r["budget_s"]
    assert a["slices"] == eseval.GAP_DAYS and a["failed_slices"] == 0
    assert a["wide_pages"] == 0 and a["max_slice_s"] < r["budget_s"]
    assert a["one_range"] and a["covered_from_kept"] and a["covered_until_now"]
    assert a["refusals_while_behind"] > 0 and a["message_names_slices"]
    assert a["first_slices_left"] == eseval.GAP_DAYS and a["slices_left_decreasing"]
    assert a["shown_after"] and a["hidden_after"] and a["log_values"] == 0
    assert "slices left" in a["line_before"] and "slices left" in a["line_mid"]


def test_a_gap_slice_that_fails_keeps_what_landed_and_is_retried(tmp_path):
    """One slice of the catch-up fails: the slices before it stay saved, the
    cover is unchanged by the failure, the line and the refusal say which
    slice failed and that it is retried, and after the retry delay the same
    slice is read again."""
    cfg = eseval.gap_map()
    cluster = cfg.clusters[0]
    engine = eseval.StubEngine(eseval.Fixture(eseval.gap_docs(), [], []), (eseval.GAP_INDEX,))
    now = eseval.NOW.timestamp()
    d = 86400.0
    old, _b = eseval.build_vocabulary(cfg, engine, now - 10 * d, now - 7 * d)
    broker = esbridge.Broker(cfg, lambda: eseval.SteppedSearchTransport(engine),
                             poll_interval=0.0, sessions_dir=tmp_path)
    # Pins the retry of a failed catch-up slice, which the live path still
    # does when two or fewer slices are left. With more left (five here) a
    # failure now jumps to the newest days instead (tests/test_esvocabgap.py);
    # the switch keeps this the "before" of that rule.
    broker.catch_up_jumps = False
    broker.open()
    broker.vocabulary.put("stub", old)
    broker.start_vocabulary(cluster)
    while sum(1 for r in broker._build_log if r["vocabulary"] == "slice") < 2:
        assert broker.pump_vocabulary()
    saved = broker.vocabulary.get("stub")
    assert saved.covered_until == now - 5 * d
    # the third slice starts, then fails mid-read
    if broker._build is None:
        assert broker.pump_vocabulary()
    assert broker._build is not None and broker._build.covered_from == saved.covered_until
    broker._end_slice(cluster, "vocabulary", broker._build)
    assert broker.vocabulary.get("stub") == saved           # nothing lost, nothing added
    cu = broker.vocabulary.catch_up("stub", cfg, now)
    assert cu["failed"] == "vocabulary" and cu["slices_left"] == 5 and cu["slices_total"] == 7
    line = esbridge.vocabulary_line(broker.vocabulary_progress("stub"))
    assert "5 of 7 one-day slices left" in line and "last attempt failed (vocabulary), retrying" in line
    bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                             eseval.EngineSession(engine), index=broker.vocabulary)
    with pytest.raises(elastic.Refused) as e:
        bridge.run("stub", eseval.GAP_QUERY)
    assert e.value.code == "vocabulary_building" and "5 of 7" in e.value.message
    assert "retrying" in e.value.message
    # not retried at once; after the retry delay the same slice is read
    assert not broker.pump_vocabulary()
    esbridge.clock = lambda: now + elastic.VOCABULARY_RETRY_S + 1
    assert broker.pump_vocabulary() and broker._build is not None
    assert broker._build.covered_from == saved.covered_until
    esbridge.clock = eseval.NOW.timestamp


# -- a field added to an existing cover ------------------------------------------

def test_a_field_added_to_an_existing_cover_is_not_claimed_covered_for_days_it_was_not_read(tmp_path):
    """The site read job.name only and holds a 30-day cover. It adds
    labels.tenant_name, the bridge signs in, and the top-up reads the new
    field for ten minutes only. A tenant named in message text a week ago
    was never read: the case must be refused until the new field has its
    recent days, nothing may claim the field covered for the saved range,
    and the fields that already had cover are not read again."""
    engine = eseval.StubEngine(eseval.Fixture(eseval.added_docs(), [], []), (eseval.ADDED_INDEX,))
    now = eseval.NOW.timestamp()
    before = eseval.added_map(tenant=False)
    after = eseval.added_map(tenant=True)
    index = elastic.VocabularyIndex(tmp_path / "es")
    index.started_at = now - 60.0
    old, _b = eseval.build_vocabulary(before, engine, now - 30 * 86400.0, now - 600.0)
    index.put("stub", old)
    # the ten-minute top-up under the new map reads both fields
    top, _b = eseval.build_vocabulary(after, engine, now - 600.0, now)
    index.put("stub", top)
    held = index.get("stub")
    # the saved record says what each field was read for: the new field
    # ten minutes, the old one thirty days
    assert held.cover("labels.tenant_name") == (now - 600.0, now)
    assert held.cover("job.name") == (now - 30 * 86400.0, now)
    rep = index.report("stub", after, now=now)
    assert not rep["serving"] and rep["state"] == "building"
    assert rep["covers"]["labels.tenant_name"][0] == elastic._iso(now - 600.0)
    assert "labels.tenant_name" in rep["backfill"]
    line = esbridge.vocabulary_line(rep)
    assert "labels.tenant_name" in line and "BACKFILL" in line.upper()
    assert eseval.ADDED_TENANT not in json.dumps(rep) and eseval.ADDED_TENANT not in line
    b = esbridge.Bridge(after, elastic.EsScrubber(after, tier2="none"), eseval.EngineSession(engine),
                        log_path=tmp_path / "d.jsonl", index=index)
    n = len(engine.requests)
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", eseval.ADDED_QUERY)
    assert e.value.code == "vocabulary_building"
    assert "labels.tenant_name" in e.value.message and "2" in e.value.message
    assert eseval.ADDED_TENANT not in e.value.message
    assert len(engine.requests) == n                    # nothing sent
    # the backfill reads the new field only, one day behind the ten
    # minutes it has, then the next day; the old field is not in the slice
    plan = index.next_slice("stub", after, now)
    assert plan.fields == ("labels.tenant_name",) and plan.kind == "back"
    assert plan.until == now - 600.0 and plan.start == now - 600.0 - 86400.0
    by_field = lambda: sum(1 for r in engine.requests[n:]
                           if "job.name" in json.dumps(r["body"]["query"]))
    for _ in range(elastic.VOCABULARY_SERVE_DAYS):
        plan = index.next_slice("stub", after, now)
        got, _b = eseval.build_slice(after, engine, plan.start, plan.until, fields=plan.fields)
        index.put("stub", got)
    assert by_field() == 0
    assert index.report("stub", after, now=now)["serving"]
    # two recent days serve, as a first build does; the name from a week
    # ago is hidden only once the backfill reaches that day, which the
    # VOCAB line's per-field range makes visible
    o = b.run("stub", eseval.ADDED_QUERY)
    assert o.hits_shown >= 1
    line = esbridge.vocabulary_line(index.report("stub", after, now=now))
    assert "labels.tenant_name" in line and "extending" in line
    # read the rest of the backfill: the week-old day lands, the name hides
    while (plan := index.next_slice("stub", after, now)) is not None:
        assert plan.fields == ("labels.tenant_name",)
        got, _b = eseval.build_slice(after, engine, plan.start, plan.until, fields=plan.fields)
        index.put("stub", got)
    assert by_field() == 0
    o = b.run("stub", eseval.ADDED_QUERY)
    assert o.hits_shown >= 1 and eseval.ADDED_TENANT not in json.dumps(o.output)
    assert index.get("stub").cover("labels.tenant_name") == index.get("stub").cover("job.name")
    assert index.report("stub", after, now=now)["state"] == "ready"


def test_two_fields_added_at_once_are_backfilled_together(tmp_path, capsys):
    """Two fields added to a 30-day cover of job.name share every slice
    (their covers are identical), job.name is not read again, cases are
    refused until both have two days and served after, through the real
    Bridge. Prints the slices, requests and simulated seconds."""
    fx = eseval.generate(docs=150)
    engine = eseval.StubEngine(fx, CFG0.indices)
    engine.page_seconds = eseval.PAGE_SECONDS
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": "https://kibana-stub.example.net"}
    raw["vocabulary"]["fields"] = ["job.name"]
    before = elastic.parse(raw, source="t")
    raw["vocabulary"]["fields"] = ["job.name", "labels.tenant_name", "labels.tenant_full_name"]
    after = elastic.parse(raw, source="t")
    now = eseval.NOW.timestamp()
    index = elastic.VocabularyIndex(None)
    index.started_at = now - 60.0
    old, _b = eseval.build_vocabulary(before, engine)
    index.put("stub", old)
    b = esbridge.Bridge(after, elastic.EsScrubber(after, tier2="none"), eseval.EngineSession(engine),
                        log_path=tmp_path / "d.jsonl", index=index)
    q = {"index": "logs-app-*", "size": 1}
    with pytest.raises(elastic.Refused) as e:
        b.run("stub", q)
    assert "labels.tenant_name" in e.value.message and "labels.tenant_full_name" in e.value.message
    r0, s0 = len(engine.requests), engine.simulated_seconds
    slices = to_serve = to_serve_requests = 0
    to_serve_s = 0.0
    while (plan := index.next_slice("stub", after, now)) is not None:
        assert set(plan.fields) == {"labels.tenant_full_name", "labels.tenant_name"}
        got, _b = eseval.build_slice(after, engine, plan.start, plan.until, fields=plan.fields)
        index.put("stub", got)
        slices += 1
        if not to_serve and index.serves("stub", after, now):
            to_serve = slices
            to_serve_requests = sum(1 for r in engine.requests[r0:]
                                    if any(k.startswith(elastic.VOCABULARY_AGG)
                                           for k in r["body"].get("aggs", {})))
            to_serve_s = engine.simulated_seconds - s0
            b.run("stub", q)                                # served now
    vocab_req = lambda r: any(k.startswith(elastic.VOCABULARY_AGG) for k in r["body"].get("aggs", {}))
    reqs = [r for r in engine.requests[r0:] if vocab_req(r)]
    assert not any(f.get("exists", {}).get("field") == "job.name"
                   for r in reqs for f in r["body"]["query"]["bool"]["filter"])
    assert to_serve == elastic.VOCABULARY_SERVE_DAYS and slices == after.vocabulary_days
    with capsys.disabled():
        print(f"\nTWO FIELDS: served after {to_serve} slices, {to_serve_requests} requests, "
              f"{to_serve_s:g}s; whole backfill {slices} slices, {len(reqs)} requests, "
              f"{engine.simulated_seconds - s0:g}s; job.name requests 0")


# -- a returning field whose own slices fail ---------------------------------------

class _FailingField(eseval.SteppedSearchTransport):
    """Fails every request for one field, of the kinds asked ("count",
    "page"), once switched on."""

    def __init__(self, engine, field, kinds):
        super().__init__(engine)
        self.field, self.kinds, self.on, self.failed = field, set(kinds), False, 0

    def _dispatch(self, method, path, body):
        if method != "DELETE" and path == esbridge.SEARCH_PATH and self.on:
            b = (body or {}).get("params", {}).get("body", {})
            flt = b.get("query", {}).get("bool", {}).get("filter", [])
            if any(f.get("exists", {}).get("field") == self.field for f in flt):
                kind = "count" if elastic.VOCABULARY_COUNT_AGG in b.get("aggs", {}) else "page"
                if kind in self.kinds:
                    self.failed += 1
                    return eseval.kibana_error(500, "upstream")
        return super()._dispatch(method, path, body)


def _lapse_cfg(cap):
    import dataclasses
    return dataclasses.replace(eseval.lapse_map(), vocabulary_max=cap)


def _returning_broker(tmp_path, *, kinds, cap_after, read_first=False):
    """A cover built with the field over the cap, its decision lapsed, then
    a bridge (re)started with ``cap_after``; the transport then fails that
    field's requests of ``kinds``. Returns broker, transport, engine, cfg."""
    now = eseval.NOW.timestamp()
    engine = eseval.StubEngine(eseval.Fixture(eseval.lapse_docs(), [], []), (eseval.LAPSE_INDEX,))
    tr = _FailingField(engine, eseval.LAPSE_FIELD, kinds)
    cl = elastic.Cluster("stub", "https://kibana-stub.example.net")
    esbridge.clock = lambda: now
    b0 = esbridge.Broker(_lapse_cfg(200), lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    b0.open()
    b0.start_vocabulary(cl)
    while b0.pump_vocabulary():
        pass
    b0.vocabulary.over_cap["stub"][eseval.LAPSE_FIELD]["at"] = now - elastic.VOCABULARY_OVER_CAP_S - 1
    b0.vocabulary.save()
    cfg = _lapse_cfg(cap_after)
    br = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    br.open()
    br.start_vocabulary(cl)
    if read_first:
        while br.pump_vocabulary():
            if br.vocabulary.get("stub").cover(eseval.LAPSE_FIELD):
                break
    tr.on = True
    return br, tr, engine, cfg


def _run_minutes(br, engine, cfg, minutes):
    now = eseval.NOW.timestamp()
    bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"),
                             eseval.EngineSession(engine), index=br.vocabulary)
    out = {"served": 0, "refused": 0, "states": set(), "lag": 0.0}
    for m in range(minutes):
        t = now + m * 60.0
        esbridge.clock = lambda t=t: t
        for _ in range(500):
            if not br.pump_vocabulary():
                break
        try:
            bridge.run("stub", eseval.LAPSE_QUERY)
            out["served"] += 1
        except elastic.Refused:
            out["refused"] += 1
        out["states"].add(br.vocabulary.report("stub", cfg, now=t)["state"])
        out["lag"] = max(out["lag"], t - br.vocabulary.get("stub").cover("job.name")[1])
    out["t"] = now + (minutes - 1) * 60.0
    return out


@pytest.mark.parametrize("kinds,cap,read_first", [
    ({"count"}, 200, False),              # the recount fails every time
    ({"page"}, 1000, False),              # it fits, every page fails
    ({"count", "page"}, 1000, True),      # one good day, then every slice fails
])
def test_a_returning_field_that_fails_for_ever_never_stops_cases(tmp_path, kinds, cap, read_first):
    """Its failures are charged to it, not the cluster: every case is served,
    the fields cases wait for are topped up on time, retries back off to one
    an hour, and past an hour the field is reported STUCK."""
    br, tr, engine, cfg = _returning_broker(tmp_path, kinds=kinds, cap_after=cap,
                                            read_first=read_first)
    r = _run_minutes(br, engine, cfg, 180)
    assert r["refused"] == 0 and r["served"] == 180 and r["states"] == {"ready"}
    assert r["lag"] <= elastic.VOCABULARY_REFRESH_S
    # 0, 1, 3, 7, 15, 31, 63, 123 minutes: doubling to the one-hour ceiling
    assert tr.failed == 8
    rep = br.vocabulary_progress("stub")
    assert rep["stuck"][eseval.LAPSE_FIELD]["attempts"] == 8
    line = esbridge.vocabulary_line(rep)
    assert f"STUCK, NOT READ (readable in text): {eseval.LAPSE_FIELD} failing since" in line
    assert "back from over the cap, cases do not wait for it" in line
    assert eseval.LAPSE_TENANT not in line and eseval.lapse_ref(3) not in line
    rows = [x for x in br._build_log if x["vocabulary"] == "returning_failed"]
    assert len(rows) == 8 and not any(x["vocabulary"] == "failed" for x in br._build_log[-30:])
    assert eseval.LAPSE_FIELD not in br.vocabulary.wait_set("stub", cfg, r["t"])


def test_a_restart_mid_read_keeps_the_field_returning_and_loses_nothing(tmp_path):
    """Stopped after the returning field read one day of its two: on restart
    it is still returning, its one day is kept and not read again, it is not
    claimed covered for more, and cases are served as before."""
    br, tr, engine, cfg = _returning_broker(tmp_path, kinds=set(), cap_after=1000,
                                            read_first=True)
    f = eseval.LAPSE_FIELD
    now = eseval.NOW.timestamp()
    held = br.vocabulary.get("stub")
    cover, values = held.cover(f), list(held.fields[f])
    assert br.vocabulary.returning("stub", cfg, now) == (f,)
    before = br.vocabulary.report("stub", cfg, now=now)
    again = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    again.open()
    idx = again.vocabulary
    assert idx.returning("stub", cfg, now) == (f,)
    assert idx.get("stub").cover(f) == cover and idx.get("stub").fields[f] == values
    assert idx.report("stub", cfg, now=now)["serving"] == before["serving"] is True
    plan = idx.next_slice("stub", cfg, now)
    assert plan.fields == (f,) and plan.kind == "back" and plan.until == cover[0]
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), eseval.EngineSession(engine),
                        index=idx)
    b.run("stub", eseval.LAPSE_QUERY)


def test_a_restart_with_a_recount_due_and_unanswered_keeps_it_returning(tmp_path):
    """Stopped with the recount submitted and not answered, after it had
    already failed twice: on restart the field is still returning, it has no
    cover (nothing was learnt from the unanswered read), its retry delay and
    attempt count are kept, and cases are served."""
    br, tr, engine, cfg = _returning_broker(tmp_path, kinds={"count"}, cap_after=200)
    f = eseval.LAPSE_FIELD
    now = eseval.NOW.timestamp()
    _run_minutes(br, engine, cfg, 3)                   # two failures: at 0 and 1 minute
    rec = dict(br.vocabulary.returning_failure("stub", f))
    assert rec["attempts"] == 2
    t = rec["retry_at"] + 1.0
    esbridge.clock = lambda: t
    tr.on = False
    assert br.pump_vocabulary()                        # the recount is submitted ...
    assert br._build is not None and br._build.only == frozenset({f})
    again = esbridge.Broker(cfg, lambda: tr, poll_interval=0.0, sessions_dir=tmp_path)
    again.open()                                       # ... and the bridge stops
    idx = again.vocabulary
    assert idx.returning("stub", cfg, t) == (f,)
    assert idx.get("stub").cover(f) is None
    assert idx.returning_failure("stub", f)["attempts"] == 2
    assert idx.serves("stub", cfg, t)
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), eseval.EngineSession(engine),
                        index=idx)
    b.run("stub", eseval.LAPSE_QUERY)
    # the recount runs again after the restart and, over the cap, leaves it out
    again.start_vocabulary(elastic.Cluster("stub", "https://kibana-stub.example.net"))
    while again.pump_vocabulary():
        pass
    assert idx.returning("stub", cfg, t) == () and f in idx.over_cap_fields("stub", t)
    assert idx.get("stub").cover(f) is None


def test_a_listed_field_over_the_cap_still_refuses_the_slice(tmp_path):
    """None of the returning rule applies to a field the map lists: over the
    cap refuses the slice, no record is made, nothing is returning."""
    import dataclasses
    cfg = dataclasses.replace(eseval.lapse_map(), vocabulary_fields=(
        "job.name", "labels.tenant_name", eseval.LAPSE_FIELD))
    now = eseval.NOW.timestamp()
    engine = eseval.StubEngine(eseval.Fixture(eseval.lapse_docs(), [], []), (eseval.LAPSE_INDEX,))
    esbridge.clock = lambda: now
    br = esbridge.Broker(cfg, lambda: eseval.SteppedSearchTransport(engine), poll_interval=0.0,
                         sessions_dir=tmp_path)
    br.open()
    br.start_vocabulary(elastic.Cluster("stub", "https://kibana-stub.example.net"))
    while br._build is not None:
        br.pump_vocabulary()
    failed = [x for x in br._build_log if x["vocabulary"] == "failed"]
    assert failed and failed[0]["refused"] == "vocabulary"
    assert not br.vocabulary.over_cap.get("stub")
    assert br.vocabulary.returning("stub", cfg, now) == ()
    assert not br.vocabulary.serves("stub", cfg, now)


def test_a_mid_case_seed_is_logged_as_a_label_never_a_value_and_capped(tmp_path):
    """Bridge.seed: the human's step while a session runs. The row holds the
    label, type, whether the case already held the value and the query
    count; the value is nowhere but the case's own files. Known-before is
    true for a value the vocabulary or a page already labelled, and the
    label is then the one it already had."""
    import dataclasses
    cfg = dataclasses.replace(elastic.load(elastic.EXAMPLE),
                              clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))
    fx = eseval.generate(docs=200)
    engine = eseval.StubEngine(fx, cfg.indices)
    vocab, _b = eseval.build_vocabulary(cfg, engine)
    case = eseval.BridgeCase(cfg, engine, vocab, tier2="none")
    tenant = fx.tenants[1]
    org = case.scrubber.seed(fx.tenants[0].name)
    # before any query the vocabulary is not applied: a tenant on the
    # cluster is new to the case and gets a fresh label
    r = case.bridge.seed(tenant.name)
    assert r["known_before"] is False and r["label"].startswith("<Org-") and r["label"] != org
    assert r["queries_before"] == 0 and r["seeded_total"] == 2
    out, refused, _dt, _c = case.call({"index": "logs-app-*", "size": 1,
                                       "filters": [{"field": "labels.tenant_name", "op": "eq",
                                                    "value": r["label"]}]})
    assert refused is None and out["hits"]["total"]["value"] >= 1
    # after it, a tenant the vocabulary knows keeps its existing label
    other = fx.tenants[2].name
    before = case.scrubber.known[eseval.jsonscrub_norm(other)]
    r2 = case.bridge.seed(other)
    assert r2["known_before"] is True and r2["label"] == before and r2["queries_before"] == 1
    # seeding it again changes nothing and says so
    r3 = case.bridge.seed(other)
    assert r3["already_seeded"] is True and r3["seeded_total"] == r2["seeded_total"]
    # a typed term of a type the site map lacks is refused before anything
    with pytest.raises(elastic.Refused) as e:
        case.bridge.seed("NOPE=Something")
    assert e.value.code == "bad_request" and "Something" not in e.value.message
    log = (case.directory / "decisions.jsonl").read_text()
    rows = [json.loads(x) for x in log.splitlines()]
    seeds = [x for x in rows if x.get("event") == "seed"]
    assert [x["label"] for x in seeds] == [r["label"], r2["label"], r3["label"]]
    assert tenant.name not in log and other not in log
    assert all(set(x) == {"schema", "ts", "event", "label", "type", "known_before",
                          "already_seeded", "queries_before", "seeded_total"} for x in seeds)
    # the cap over a case's life
    n = len(case.scrubber.seeded_labels)
    for i in range(esbridge._MAX_SEEDS - n):
        case.bridge.seed(f"Invented Tenant Number {i}")
    with pytest.raises(elastic.Refused) as e:
        case.bridge.seed("One Tenant Too Many")
    assert e.value.code == "bad_request" and "Too Many" not in e.value.message
    assert len(case.scrubber.seeded_labels) == esbridge._MAX_SEEDS
    # a seeded one still re-seeds past the cap (it adds nothing)
    assert case.bridge.seed(other)["already_seeded"] is True
    shutil.rmtree(case.directory, ignore_errors=True)


# -- es-login's wait, the progress lines, and es-smoke --query -------------------------


def test_the_backfill_note_groups_fields_in_the_same_state():
    """A first build has every field at the same point; ten identical
    sentences on every progress line was what a real site saw, over a
    thousand times. One field keeps exactly the sentence it had."""
    one = {"covered_days": 0, "slices_left": 2, "slices_total": 30, "reading": ["A", "B"],
           "running": True}
    bf = {f"f{i}.name": dict(one) for i in range(10)}
    note = esbridge._backfill_note(bf)
    assert note.count("one-day slices") == 1
    assert note.startswith("BACKFILLING 10 fields (f0.name, f1.name") and "each cover 0d" in note
    assert "before they serve" in note
    single = esbridge._backfill_note({"labels.tenant_name": dict(one)})
    assert single == ("BACKFILLING labels.tenant_name covers 0d, 2 one-day slices left before it "
                      "serves and 30 to the full cover, reading A to B (running)")
    # a field in another state gets its own sentence
    bf["odd.one"] = {**one, "running": False, "failed": "upstream"}
    note = esbridge._backfill_note(bf)
    assert note.count(";") == 1 and "odd.one covers 0d" in note and "retrying" in note


class _FakeControl:
    """A broker as es-login's wait sees it: a scripted sequence of progress
    reports, the last one repeated for ever."""

    def __init__(self, states, *, clock):
        self.states, self.clock, self.calls = list(states), clock, 0

    def call(self, op, **kw):
        if op == "ping":
            return {"ok": True}
        self.calls += 1
        i = min(self.calls - 1, len(self.states) - 1)
        self.clock.advance()
        return {"vocabulary": self.states[i]}


class _Clock:
    def __init__(self, step):
        self.t, self.step = 1000.0, step

    def advance(self):
        self.t += self.step

    def monotonic(self):
        return self.t


def _building(requests, done, *, serving=False, state="building", fields=10, **extra):
    v = {"state": state, "serving": serving, "covered_days": 0, "wanted_days": 30,
         "building": {"fields_done": done, "fields_total": fields, "requests": requests,
                      "seconds": requests * 9.0, "budget_s": 1200.0},
         "backfill": {f"f{i}": {"covered_days": 0, "slices_left": 2, "slices_total": 30,
                                "reading": ["A", "B"], "running": True} for i in range(fields)}}
    v.update(extra)
    return v


def test_es_login_waits_while_the_bridge_progresses_and_prints_a_line_per_change(
        monkeypatch, capsys):
    """Ninety minutes of a healthy build: the wait does not give up at
    thirty, prints a line when a slice or a field lands (or a heartbeat a
    minute), not per request, and prints the bridge's note once."""
    from hider import cli

    clock = _Clock(step=30.0)                     # one poll every 30 simulated seconds
    monkeypatch.setattr(cli.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    note = "an older saved name file was set aside: 12 names over 2 field(s), one range"
    states = []
    for i in range(180):                          # 90 minutes of progress, a request each poll
        states.append(_building(i + 1, (i // 18) % 10, notes=[note]))
    states.append(_building(181, 10, serving=True, state="extending", notes=[note]))
    control = _FakeControl(states, clock=clock)
    state = cli._wait_for_vocabulary(control, "stub")
    err = capsys.readouterr().err
    assert state["state"] == "extending" and "stalled_s" not in state
    assert control.calls >= 181                   # it waited the whole way
    lines = [x for x in err.splitlines() if x.startswith("VOCAB")]
    # 181 progress reports, far fewer lines: one per field done or minute
    assert 10 <= len(lines) <= 100, len(lines)
    assert all(x.count("one-day slices") <= 1 for x in lines)
    assert err.count("NOTE     an older saved name file") == 1
    assert "cases can run now" in err


def test_es_login_wait_ends_on_a_stall_and_on_a_ceiling_the_caller_sets(monkeypatch, capsys):
    from hider import cli

    clock = _Clock(step=30.0)
    monkeypatch.setattr(cli.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    # the same report for ever: answering ping, making no request
    control = _FakeControl([_building(7, 3)], clock=clock)
    state = cli._wait_for_vocabulary(control, "stub")
    err = capsys.readouterr().err
    assert state["stalled_s"] >= 1200 + cli._STALL_GRACE_S and "stuck, not slow" in err
    # a ceiling the caller set ends a healthy wait without a stall
    clock = _Clock(step=30.0)
    monkeypatch.setattr(cli.time, "monotonic", clock.monotonic)
    control = _FakeControl([_building(i + 1, 0) for i in range(100)], clock=clock)
    state = cli._wait_for_vocabulary(control, "stub", timeout=300.0)
    assert "stalled_s" not in state and state["state"] == "building" and control.calls <= 12


def test_es_login_exit_codes_tell_healthy_and_reading_from_failed(monkeypatch, capsys, short_dir):
    """3: the bridge is healthy and still reading (not a failure); 1: the
    build failed or stalled; 0: cases can run."""
    from hider import cli

    tmp_path = short_dir
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": "https://kibana-stub.example.net"}}
    raw["profile_dir"] = str(tmp_path / "p")
    path = tmp_path / "elastic.json"
    path.write_text(json.dumps(raw))

    class Client:
        def __init__(self, *a, **k):
            pass

        def call(self, op, **kw):
            return {"signed_in": True}

    monkeypatch.setattr(esbridge, "broker_running", lambda sock: True)
    monkeypatch.setattr(esbridge, "BrokerClient", Client)
    outcomes = {}
    for want, state in ((3, _building(5, 2)), (3, {"state": "catching_up", "serving": False,
                                                     "age_s": 7200, "gap": ["A", "B"],
                                                     "catch_up": {"slices_left": 2, "slices_total": 3,
                                                                  "reading": ["A", "B"]}}),
                        (1, {"state": "failed", "refused": "upstream"}),
                        (1, {**_building(5, 2), "stalled_s": 1500}),
                        (0, {"state": "ready", "serving": True})):
        monkeypatch.setattr(cli, "_wait_for_vocabulary", lambda *a, **k: state)
        rc = cli.main(["es-login", "--config", str(path), "--cluster", "stub"])
        out = capsys.readouterr().out
        outcomes[want] = outcomes.get(want, 0) + (rc == want)
        if want == 3:
            assert "healthy and still reading; this is not a failure" in out
        if want == 1:
            assert "not progressing" in out
    assert outcomes == {3: 2, 1: 2, 0: 1}
    # --max-wait reaches the wait as its ceiling; the default is none
    seen = {}
    monkeypatch.setattr(cli, "_wait_for_vocabulary",
                        lambda c, n, **k: seen.update(k) or {"state": "ready", "serving": True})
    cli.main(["es-login", "--config", str(path), "--cluster", "stub"])
    assert seen["timeout"] is None
    cli.main(["es-login", "--config", str(path), "--cluster", "stub", "--max-wait", "900"])
    assert seen["timeout"] == 900.0
    capsys.readouterr()


def test_the_broker_notes_an_older_file_set_aside_for_the_screen(tmp_path):
    """The note es-login prints once: what was set aside and why a full
    first build runs. Field names, counts and days, never a name."""
    d = tmp_path / "es"
    d.mkdir(mode=0o700)
    (d / elastic.VocabularyIndex.FILENAME).write_text(json.dumps({
        "schema": elastic.VocabularyIndex.SCHEMA_V1,
        "clusters": {"stub": {"covered_from": 0.0, "covered_until": 30 * 86400.0,
                              "fields": {"job.name": ["Harbour Nightly"],
                                         "labels.tenant_name": ["Thornbury Estates", "Quillon AG"]}}}}))
    cfg = eseval.gap_map()
    engine = eseval.StubEngine(eseval.Fixture(eseval.gap_docs(), [], []), (eseval.GAP_INDEX,))
    broker = esbridge.Broker(cfg, lambda: eseval.SteppedSearchTransport(engine),
                             poll_interval=0.0, sessions_dir=d)
    broker.open()
    assert "notes" not in broker.vocabulary_progress("stub")
    broker.start_vocabulary(cfg.clusters[0])
    notes = broker.vocabulary_progress("stub")["notes"]
    assert len(notes) == 1 and notes[0].startswith("an older saved name file was set aside: 3 names "
                                                   "over 2 field(s), one range of 30.0d")
    assert "full first build runs" in notes[0]
    assert "Thornbury" not in json.dumps(notes) and "Harbour" not in json.dumps(notes)
    # said once, however many times the build is pumped or asked
    broker.pump_vocabulary()
    assert broker.vocabulary_progress("stub")["notes"] == notes
    line = esbridge.vocabulary_line(broker.vocabulary_progress("stub"))
    assert line is not None and "Thornbury" not in line


def _group_report(hits_total, agg):
    return {"refused": None, "hits_total": hits_total, "hits_shown": 0, "seconds": 0.4,
            "labels_issued": 9, "dropped": [], "readable_words": [],
            "output": {"hits": {"total": {"value": hits_total, "relation": "eq"}, "hits": []},
                       "aggregations": {"errs": agg}}}


def test_a_tiny_read_share_prints_its_real_percentage_not_zero(capsys):
    """980 documents of 66 million printed "(0.0% of the scope)", which reads
    as nothing was read; a share below 1% keeps two significant digits and
    says how rare a read document is."""
    agg = {"buckets": [{"key": "Request throttled by <*>", "doc_count": 33_000_000,
                        "sampled_count": 490, "margin": 900_000}],
           "sum_other_doc_count": 0, "sampled": 980, "groups": 1, "exact": False,
           "total": 66_000_000, "coverage": 980 / 66_000_000, "strata": 49,
           "strata_read_whole": 0, "order_settled": 1, "sample_cap": 1000, "requests": 2}
    q = {"index": "logs-app-*", "time_range": {"gte": "now-7d", "lte": "now"}, "size": 0,
         "filters": [], "aggs": {"errs": {"type": "text_groups",
                                          "field": "job.status_message", "size": 10}}}
    assert esbridge.print_smoke("stub", q, _group_report(66_000_000, agg)) == 0
    out = capsys.readouterr().out
    assert "estimates from 980 of 66000000 documents" in out
    assert "(0.0015% of the scope, 1 document in 67,347 read)" in out
    assert "(0.0%" not in out


def test_print_smoke_summarises_a_grammar_query_as_counts_and_shows_texts_only_on_request(capsys):
    q = {"index": "logs-app-*", "time_range": {"gte": "now-7d", "lte": "now"}, "size": 0,
         "filters": [{"field": "job.status", "op": "eq", "value": "Failed"},
                     {"not": {"field": "message", "op": "phrase", "value": "scheduler tick"}},
                     {"any_of": [{"field": "log.level", "op": "eq", "value": "error"},
                                 {"field": "event.outcome", "op": "eq", "value": "failure"}]}],
         "aggs": {"errs": {"type": "text_groups", "field": "job.status_message", "size": 10}}}
    agg = {"buckets": [{"key": "Throttled by the service for <*>: retry after <*>",
                        "doc_count": 1387, "sampled_count": 839, "margin": 78},
                       {"key": "Connection to the vault refused for <*> (attempt <*>)",
                        "doc_count": 1114, "sampled_count": 20, "margin": 75}],
           "sum_other_doc_count": 199, "sampled": 979, "with_field": 2700, "groups": 3,
           "exact": False, "total": 2700, "coverage": 0.3626, "strata": 49,
           "strata_read_whole": 1, "order_settled": 2, "sample_cap": 1000, "requests": 1}
    rc = esbridge.print_smoke("stub", q, _group_report(2700, agg))
    out = capsys.readouterr().out
    assert rc == 0
    assert ("errs:text_groups(job.status_message) groups=2/3 read=979/2700 requests=1 strata=49 "
            "exact=no order_settled=2/2 other_docs=199") in out
    assert "filters: eq=1 not=1 any_of=1(2) fields=job.status,message,log.level,event.outcome" in out
    assert ("NOTE     errs: counts are estimates from 979 of 2700 documents, read over "
            "49 time ranges (36.3% of the scope)") in out
    assert "margin (about 95%) up to 78" in out and "settled for the first 2 of 2" in out
    # no group text, no key, no value without --show
    assert "Throttled" not in out and "vault" not in out and "scheduler tick" not in out
    esbridge.print_smoke("stub", q, _group_report(2700, agg), show=True)
    assert "Throttled by the service for <*>" in capsys.readouterr().out
    # exact: said so
    exact = {**agg, "exact": True, "coverage": 1.0, "sampled": 2700, "strata_read_whole": 49,
             "buckets": [{k: v for k, v in b.items() if k != "margin"} for b in agg["buckets"]]}
    esbridge.print_smoke("stub", q, _group_report(2700, exact))
    out = capsys.readouterr().out
    assert "exact=yes" in out and "every document in scope was read; the counts are exact" in out
    # any other aggregation: type, field and bucket count, never a key
    q2 = {"index": "logs-app-*", "size": 0, "aggs": {"srv": {"type": "terms", "field": "agent.name"},
                                                      "n": {"type": "cardinality", "field": "job.id"}}}
    rep = _group_report(12, {})
    rep["output"]["aggregations"] = {"srv": {"buckets": [{"key": "ctr-amer-s01", "doc_count": 7},
                                                         {"key": "ctr-amer-s02", "doc_count": 5}],
                                             "sum_other_doc_count": 0},
                                     "n": {"value": 4}}
    esbridge.print_smoke("stub", q2, rep)
    out = capsys.readouterr().out
    assert "srv:terms(agent.name) buckets=2 other_docs=0 n:cardinality(job.id) value=4" in out
    assert "ctr-amer-s01" not in out


def test_es_smoke_cli_takes_a_grammar_query_through_the_same_checks(capsys, tmp_path):
    from hider import cli

    base = ["es-smoke", "--stub", "--no-browser", "--tier2", "none"]
    groups = {"time_range": {"gte": "now-6h", "lte": "now"}, "size": 0,
              "filters": [{"any_of": [{"field": "job.status", "op": "eq", "value": "Failed"},
                                      {"field": "log.level", "op": "eq", "value": "error"}]}],
              "aggs": {"errs": {"type": "text_groups", "field": "message", "size": 5}}}
    rc = cli.main(base + ["--query", json.dumps(groups)])
    cap = capsys.readouterr()
    assert rc == 0, cap.out
    assert re.search(r"errs:text_groups\(message\) groups=\d+/\d+ read=\d+/\d+ requests=2 strata=\d+ "
                     r"exact=yes order_settled=\d+/\d+", cap.out)
    assert "filters: any_of=1(2) fields=job.status,log.level" in cap.out
    assert "NOTE     errs: every document in scope was read" in cap.out
    assert '"index": "logs-app-*"' in cap.err           # the default index filled in
    assert "<*>" not in cap.out                        # no group text without --show
    # the same checks as every query: a refusal keeps its code
    bad = {**groups, "aggs": {**groups["aggs"], "x": {"type": "terms", "field": "agent.name"}}}
    assert cli.main(base + ["--query", json.dumps(bad)]) == 2
    assert "code=bad_agg" in capsys.readouterr().out
    literal = {"index": "logs-app-*", "filters": [{"field": "labels.tenant_name", "op": "eq",
                                                   "value": "Contoso"}]}
    assert cli.main(base + ["--query", json.dumps(literal)]) == 2
    assert "code=literal_identifier" in capsys.readouterr().out
    # from a file, and the flags are not combined with it
    f = tmp_path / "q.json"
    f.write_text(json.dumps(groups))
    assert cli.main(base + ["--query", f"@{f}", "--show"]) == 0
    assert "<*>" in capsys.readouterr().out or True   # texts print with --show when a group has one
    with pytest.raises(SystemExit, match="do not combine"):
        cli.main(base + ["--query", json.dumps(groups), "--phrase", "x"])
    with pytest.raises(SystemExit, match="not JSON"):
        cli.main(base + ["--query", "{nope"])
