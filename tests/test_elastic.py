"""The Elasticsearch site map and response scrubber. Invented values only."""

from __future__ import annotations

import copy
import json

import pytest

from hider import elastic, esquery, eseval, pipeline

CFG = elastic.load(elastic.EXAMPLE)


def _session(tier2: str = "none") -> elastic.EsScrubber:
    return elastic.EsScrubber(CFG, tier2=tier2)


def _hit(source: dict, index: str = "logs-app-2026.08.20", _id: str = "abc123") -> dict:
    return {"_index": index, "_id": _id, "_score": None, "_source": source}


def _envelope(hits: list[dict], aggs: dict | None = None) -> dict:
    raw = {"took": 3, "timed_out": False,
           "hits": {"total": {"value": len(hits), "relation": "eq"}, "max_score": None,
                    "hits": hits}}
    if aggs is not None:
        raw["aggregations"] = aggs
    return {"id": "s1", "isPartial": False, "isRunning": False, "rawResponse": raw}


APP_DOC = {
    "@timestamp": "2026-08-20T10:00:00.000Z",
    "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
    "event": {"outcome": "failure"},
    "log": {"level": "error", "file": {"path": "/var/log/backup/ctr-amer-042/engine.log"}},
    "message": "Throttled by SharePoint for Fabrikam Industries: object "
               "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f on ctr-amer-042, user "
               "lena.moreau@fabrikam.com, site https://fabrikam.sharepoint.com/sites/Legal",
    "agent": {"name": "ctr-amer-042"},
    "host": {"name": "ctr-amer-042", "ip": "10.44.2.17", "mac": "00:1b:44:11:3a:b7"},
    "cloud": {"account": {"id": "482913650027"}, "instance": {"name": "i-0a1b2c3d4e5f6a7b"}},
    "labels": {"tenant_name": "Fabrikam Industries", "tenant_full_name": "Fabrikam Industries GmbH",
               "tenant_id": "0f9e8d7c-6b5a-4433-9221-0a1b2c3d4e5f", "resource_name": "LegalHold2026"},
    "job": {"id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "status": "Failed",
            "object_id": "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f", "name": "Legal Hold Sync",
            "status_message": "Access denied for lena.moreau@fabrikam.com",
            "counters": {"items": 120, "bytes": 4096, "errors": 3}},
    "tenant": {"users_in_tenant": 48213},
    "process": {"command_line": "engine.exe --tenant Fabrikam Industries"},
}
PLANTED = ["Fabrikam", "7c1d2e3f", "ctr-amer-042", "lena.moreau", "fabrikam.com", "10.44.2.17",
           "00:1b:44", "482913650027", "i-0a1b2c3d", "0f9e8d7c", "LegalHold2026", "9a8b7c6d",
           "Legal Hold Sync", "48213", "engine.exe"]
PLAN = elastic.Plan("logs-app-*")


# -- configuration -----------------------------------------------------------


def test_example_config_loads_and_classifies():
    assert CFG.rule("labels.tenant_name").kind == "identifier"
    assert CFG.rule("event.outcome").kind == "keep"       # glob
    assert CFG.rule("message").kind == "text"
    assert CFG.rule("user.password") is None               # unlisted
    assert CFG.rule("agent.name").shape is not None
    assert "labels.tenant_name" in CFG.source_includes()
    assert CFG.index_allowed("logs-app-2026.08.20")
    assert not CFG.index_allowed(".kibana_security_session_1")


@pytest.mark.parametrize("patch,needle", [
    ({"fields": {"@timestamp": "keep", "x": "secret"}}, "kind must be one of"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier"}}}, "needs a type"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "keep", "type": "GUID"}}}, "only apply"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "JWT"}}}, "secret type"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "S",
                                             "shape": "(?P<a>[a-z]+)-\\d+"}}}, "go together"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "S",
                                             "shape": "(?P<a>[a-z]+)-\\d+", "label": "{a}-x"}}},
     "must include the ordinal"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "S",
                                             "shape": "(?P<a>[a-z]+)-(?P<n>\\d+)",
                                             "label": "{a}-{n}"}}}, "reserved"),
    # the label would itself match the shape: a pseudonym that looks real
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "S",
                                             "shape": "(?P<a>[a-z]+)-\\d+", "label": "{a}-{n}"}}},
     "can itself match"),
    ({"fields": {"@timestamp": "keep", "x": {"kind": "identifier", "type": "TENANT"}}},
     "already uses"),  # <Tenant-NN> is TENANT_ID's prefix
    ({"indices": []}, "indices"),
    ({"time_field": "message"}, "must be listed as keep"),
    ({"max_hits": 0}, "positive integer"),
    ({"poll_timeout_s": 0}, "poll_timeout_s"),
    ({"poll_timeout_s": 601}, "1..600"),
    ({"poll_timeout_s": "120"}, "poll_timeout_s"),
    ({"poll_timeout_s": True}, "poll_timeout_s"),
    ({"extra": 1}, "unknown keys"),
])
def test_malformed_config_is_a_startup_error(patch, needle):
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw.update(patch)
    with pytest.raises(elastic.ConfigError, match=needle):
        elastic.parse(raw)


def test_local_settings_accept_elastic_as_object_or_path(tmp_path, monkeypatch):
    from hider import localcfg
    cfgfile = tmp_path / "es.json"
    cfgfile.write_text(elastic.EXAMPLE.read_text())
    local = tmp_path / "hider.local.json"
    local.write_text(json.dumps({"elastic": str(cfgfile)}))
    monkeypatch.setenv(localcfg.ENV, str(local))
    monkeypatch.delenv(elastic.ENV, raising=False)
    localcfg.settings.cache_clear()
    try:
        assert elastic.active().indices == CFG.indices
        local.write_text(json.dumps({"elastic": 7}))
        localcfg.settings.cache_clear()
        with pytest.raises(RuntimeError, match="dict or str"):
            elastic.active()
    finally:
        localcfg.settings.cache_clear()


# -- the scrubber ------------------------------------------------------------


def test_no_planted_value_survives_and_labels_are_consistent():
    s = _session()
    out = s.scrub_response(_envelope([_hit(APP_DOC)]), PLAN).output
    blob = json.dumps(out).lower()
    for v in PLANTED:
        assert v.lower() not in blob, v
    src = out["hits"]["hits"][0]["_source"]
    # the server keeps its role and region, and the same label everywhere
    assert src["agent"]["name"] == "ctr-amer-s01"
    assert src["host"]["name"] == "ctr-amer-s01"
    assert "ctr-amer-s01" in src["message"]
    assert "ctr-amer-s01" in src["log"]["file"]["path"]
    # the tenant has one label in the field and in the message
    org = src["labels"]["tenant_name"]
    assert org.startswith("<Org-") and org in src["message"]
    # the same GUID under two fields and in the text: one label
    assert src["job"]["object_id"] in src["message"]
    # identifiers that are numbers become labels, counters stay numbers
    assert src["tenant"]["users_in_tenant"].startswith("<Tenant_Size-")
    assert src["job"]["counters"] == {"items": 120, "bytes": 4096, "errors": 3}
    # the vault never holds a secret; the mapping is identifiers only
    assert all(v for v in s.mapping.values())


def test_unlisted_fields_are_dropped_not_shown():
    s = _session()
    out = s.scrub_response(_envelope([_hit(APP_DOC)]), PLAN).output
    src = out["hits"]["hits"][0]["_source"]
    assert "process" not in src
    assert s.dropped == {"process.command_line": 1}
    # the dropped value does not get into the mapping either
    assert not any("engine.exe" in v for v in s.mapping.values())


def test_meta_fields_doc_id_is_labelled_and_index_checked():
    s = _session()
    out = s.scrub_response(_envelope([_hit(APP_DOC, _id="tenant-fabrikam-00017")]), PLAN).output
    assert out["hits"]["hits"][0]["_id"].startswith("<Doc_Id-")
    assert "fabrikam-00017" not in json.dumps(out)
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([_hit(APP_DOC, index=".security-7")]), PLAN)
    assert e.value.code == "bad_index"


@pytest.mark.parametrize("name,allowed", [
    # a data stream's backing index is admitted when the stream matches
    (".ds-logs-app-default-2026.08.20-000001", True),
    (".ds-logs-worker-eu-2026.01.31-000042", True),
    (".ds-traces-apm-default-2026.08.20-1000000", True),  # generations grow past six digits
    (".ds-logs-app-2026-x-2026.08.20-000003", True),       # a stream name with a date-ish part
    ("logs-app-2026.08.20", True),                         # an ordinary index, as before
    # and nothing else that starts with .ds- or looks like one
    (".ds-logs-billing-default-2026.08.20-000001", False),  # stream not allowlisted
    (".ds-logs-app-2026.08.20-000001", False),     # stream logs-app is not logs-app-*
    (".ds-logs-app-default", False),               # no backing suffix
    (".ds-logs-app-default-2026.08.20-01", False), # generation is six digits or more
    (".ds-logs-app-default-20260820-000001", False),
    (".fs-logs-app-default-2026.08.20-000001", False),  # failure store: not the stream
    ("downsample-1h-.ds-logs-app-default-2026.08.20-000001", False),
    (".ds-.kibana_security_session-2026.08.20-000001", False),
    ("logs-app", False),
])
def test_data_stream_backing_indices_are_checked_by_their_stream(name, allowed):
    assert CFG.index_allowed(name) is allowed


def test_a_page_from_a_data_stream_is_scrubbed_and_a_foreign_stream_is_refused():
    s = _session()
    out = s.scrub_response(_envelope([_hit(APP_DOC, index=".ds-logs-app-default-2026.08.20-000001")]),
                           PLAN).output
    assert out["hits"]["hits"][0]["_index"] == ".ds-logs-app-default-2026.08.20-000001"
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([_hit(APP_DOC, index=".ds-audit-default-2026.08.20-000001")]),
                         PLAN)
    assert e.value.code == "bad_index"


def test_poll_timeout_defaults_and_bounds():
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw.pop("poll_timeout_s", None)
    assert elastic.parse(raw).poll_timeout_s == elastic.DEFAULT_POLL_TIMEOUT_S == 120
    raw["poll_timeout_s"] = elastic.MAX_POLL_TIMEOUT_S
    assert elastic.parse(raw).poll_timeout_s == 600
    raw["poll_timeout_s"] = 1.5
    assert elastic.parse(raw).poll_timeout_s == 1.5


def test_hit_decorations_are_dropped():
    hit = _hit(APP_DOC)
    hit["highlight"] = {"message": ["<em>Fabrikam</em> Industries"]}
    hit["sort"] = ["Fabrikam Industries"]
    hit["inner_hits"] = {"x": {"hits": {"hits": [{"_source": {"secret": "Fabrikam"}}]}}}
    s = _session()
    out = s.scrub_response(_envelope([hit]), PLAN).output
    h = out["hits"]["hits"][0]
    assert set(h) == {"_index", "_id", "_score", "_source"}
    assert "fabrikam" not in json.dumps(out).lower()


@pytest.mark.parametrize("raw,code", [
    ({"statusCode": 400, "error": "Bad Request",
      "message": "[parsing_exception] unknown field [Fabrikam Industries]"}, "upstream_error"),
    ({"error": {"type": "index_not_found_exception", "reason": "no such index [logs-fabrikam]"},
      "status": 404}, "upstream_error"),
    ({"id": "s1", "isPartial": True, "isRunning": True, "rawResponse": {"hits": {"hits": []}}},
     "incomplete"),
    ({"id": "s1", "isPartial": True, "isRunning": False,
      "rawResponse": {"hits": {"hits": [], "total": {"value": 0}}}}, "incomplete"),
    ({"rawResponse": {"timed_out": True, "hits": {"hits": []}}}, "incomplete"),
    ({"rawResponse": {"took": 1}}, "malformed"),
    ([], "malformed"),
])
def test_errors_and_incomplete_responses_are_refused_without_the_body(raw, code):
    s = _session()
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(raw, PLAN)
    assert e.value.code == code
    assert "fabrikam" not in str(e.value).lower()
    assert s.refusals == {code: 1}


def test_error_class_keeps_status_and_known_type_only():
    assert elastic.error_class({"statusCode": 404, "message": "[index_not_found_exception] x"}) \
        == "not_found:index_not_found_exception"
    assert elastic.error_class({"statusCode": 500, "message": "[made_up_exception] x"}) == "upstream_error"
    assert elastic.error_class({"statusCode": 429}) == "throttled"
    assert elastic.error_class({"hits": {}}) is None


def test_degraded_tier_refuses_the_whole_page():
    class Boom:
        name = "tier2"

        def detect(self, text, residue):
            raise RuntimeError("model missing")

    s = _session()
    s.pipe.tiers.append(Boom())
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([_hit(APP_DOC)]), PLAN)
    assert e.value.code == "degraded"


def test_leak_check_refuses_rather_than_returning_a_partial_page(monkeypatch):
    s = _session()
    # Sabotage the sweep so a known value survives; the leak check must
    # catch it. This is the only way to reach the branch, which is the point.
    monkeypatch.setattr(s, "_sweep", lambda node: node)
    doc = copy.deepcopy(APP_DOC)
    doc["event"]["outcome"] = "Fabrikam Industries"   # keep field carrying a mapped value
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([_hit(doc)]), PLAN)
    assert e.value.code == "leak"


def test_keep_field_equal_to_a_known_value_is_swept():
    s = _session()
    doc = copy.deepcopy(APP_DOC)
    doc["event"]["outcome"] = "Fabrikam Industries"
    out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output
    assert out["hits"]["hits"][0]["_source"]["event"]["outcome"] == \
        out["hits"]["hits"][0]["_source"]["labels"]["tenant_name"]


def test_aggregation_bucket_keys_on_identifier_fields_are_labelled():
    s = _session()
    plan = elastic.Plan("logs-app-*", {
        "by_srv": elastic.AggPlan("terms", "agent.name", CFG.rule("agent.name"), {
            "last": elastic.AggPlan("top_hits")}),
        "by_tenant": elastic.AggPlan("terms", "labels.tenant_name", CFG.rule("labels.tenant_name")),
        "ds": elastic.AggPlan("terms", "data_stream.dataset", CFG.rule("data_stream.dataset")),
        "n": elastic.AggPlan("cardinality", "labels.tenant_id", CFG.rule("labels.tenant_id")),
        "first": elastic.AggPlan("min", "@timestamp", CFG.rule("@timestamp")),
    })
    aggs = {
        "by_srv": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 2, "buckets": [
            {"key": "ctr-emea-017", "doc_count": 9,
             "last": {"hits": {"total": {"value": 9, "relation": "eq"}, "hits": [_hit(APP_DOC)]}}}]},
        "by_tenant": {"buckets": [{"key": "Fabrikam Industries", "doc_count": 4},
                                  {"key": "Litware Partners", "doc_count": 1}]},
        "ds": {"buckets": [{"key": "app.engine", "doc_count": 5}]},
        "n": {"value": 2},
        "first": {"value": 1755684000000.0, "value_as_string": "2026-08-20T10:00:00.000Z"},
    }
    out = s.scrub_response(_envelope([], aggs), plan).output
    a = out["aggregations"]
    assert a["by_srv"]["buckets"][0]["key"] == "ctr-emea-s01"
    assert a["by_srv"]["sum_other_doc_count"] == 2
    assert a["by_srv"]["buckets"][0]["last"]["hits"]["hits"][0]["_source"]["agent"]["name"] == "ctr-amer-s02"
    assert a["by_tenant"]["buckets"][0]["key"].startswith("<Org-")
    assert a["by_tenant"]["buckets"][0]["key"] != a["by_tenant"]["buckets"][1]["key"]
    assert a["ds"]["buckets"][0]["key"] == "app.engine"
    assert a["n"] == {"value": 2}
    assert a["first"]["value_as_string"] == "2026-08-20T10:00:00.000Z"
    assert "fabrikam" not in json.dumps(out).lower() and "litware" not in json.dumps(out).lower()


def test_unplanned_aggregation_is_refused():
    s = _session()
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([], {"surprise": {"buckets": [{"key": "Fabrikam", "doc_count": 1}]}}),
                         PLAN)
    assert e.value.code == "unplanned_agg"
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope([]), elastic.Plan("logs-app-*", {"x": elastic.AggPlan("cardinality", "labels.tenant_id")}))
    assert e.value.code == "malformed"


def test_bucket_and_hit_caps_are_enforced():
    s = _session()
    too_many = [_hit(APP_DOC, _id=f"d{i}") for i in range(CFG.max_hits + 1)]
    with pytest.raises(elastic.Refused) as e:
        s.scrub_response(_envelope(too_many), PLAN)
    assert e.value.code == "size_cap"


def test_bucket_cap_backstop_holds_for_what_the_grammar_pre_flight_cannot_predict():
    """esquery refuses a histogram that would overrun max_buckets before it is
    sent; this cap stays for a reply that has more anyway (a clock across a
    bucket edge from ours, an upstream that ignores the request)."""
    hist = elastic.Plan("logs-app-*", {"t": elastic.AggPlan("date_histogram", "@timestamp",
                                                            CFG.rule("@timestamp"))})

    def buckets(n):
        return {"t": {"buckets": [{"key": 1_787_227_200_000 + i * 3_600_000, "doc_count": 1}
                                  for i in range(n)]}}

    assert len(_session().scrub_response(_envelope([], buckets(CFG.max_buckets)), hist)
               .output["aggregations"]["t"]["buckets"]) == CFG.max_buckets
    with pytest.raises(elastic.Refused) as e:
        _session().scrub_response(_envelope([], buckets(CFG.max_buckets + 1)), hist)
    assert e.value.code == "size_cap"


def test_seed_and_resolve_label_and_session_round_trip(tmp_path):
    s = _session()
    lab = s.seed("Fabrikam Industries")
    srv = s.seed("ctr-apj-003", "SERVER_NAME")
    assert lab.startswith("<Org-") and srv == "ctr-apj-s01"
    assert s.resolve_label(lab) == ("Fabrikam Industries", "ORG_NAME")
    assert s.resolve_label(srv) == ("ctr-apj-003", "SERVER_NAME")
    assert s.resolve_label("<Org-99>") is None
    first = s.scrub_response(_envelope([_hit(APP_DOC)]), PLAN).output
    server_label = first["hits"]["hits"][0]["_source"]["agent"]["name"]
    assert server_label == "ctr-amer-s02"  # the seeded apj server took s01
    before = dict(s.mapping)
    d = s.save_session(tmp_path / "case")
    assert (d / "vault.json").exists() and (d / "session.json").exists()
    s2 = elastic.EsScrubber.load_session(d, CFG, tier2="none")
    assert s2.mapping == before
    # new values after a restore get new labels, never a reused one
    new = s2.seed("ctr-apj-250", "SERVER_NAME")
    assert new not in before and new.startswith("ctr-apj-s")
    out = s2.scrub_response(_envelope([_hit(APP_DOC)]), PLAN).output
    assert out["hits"]["hits"][0]["_source"]["agent"]["name"] == server_label


def test_text_longer_than_the_cap_is_truncated_then_scrubbed():
    s = _session()
    cfg = elastic.ElasticConfig(CFG.indices, CFG.fields, max_text_chars=60)
    s = elastic.EsScrubber(cfg, tier2="none")
    doc = copy.deepcopy(APP_DOC)
    doc["message"] = "x" * 100 + " Fabrikam Industries"
    out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output
    msg = out["hits"]["hits"][0]["_source"]["message"]
    assert msg.endswith("[truncated]") and "Fabrikam" not in msg


def test_with_tier2_the_fixture_pages_come_out_clean():
    """The classifier adds spans, never removes protection: run the example
    fixture with tier 2 on and hold the same zero-leak property."""
    fx = eseval.generate(docs=120)
    engine = eseval.StubEngine(fx, CFG.indices)
    s = _session("classifier")
    body = {"size": 40, "query": {"match_all": {}}, "_source": {"includes": CFG.source_includes()}}
    for index in CFG.indices:
        raw = engine.search(index, body)
        out = s.scrub_response({"rawResponse": raw}, elastic.Plan(index)).output
        assert eseval._leaks(out, fx.truth) == []
    assert s.degraded == 0


# -- generic log vocabulary through the scrubber, sweep included --------------

_LOG_WORDS = ["Warning", "Info", "Error", "Debug", "Warn", "Critical", "Completed", "Failed",
              "Retry", "INFO", "ERROR"]
_SHAPES = [("{w} Lena Moreau signed in", "Lena Moreau"), ("user Lena Moreau {w}", "Lena Moreau"),
           ("Lena Moreau {w} on sync", "Lena Moreau"), ("{w} Contoso Holdings throttled",
                                                         "Contoso Holdings")]


@pytest.fixture(scope="module")
def tier2_scrubber_factory():
    return lambda: elastic.EsScrubber(CFG, tier2="classifier")


@pytest.mark.parametrize("shape,name", _SHAPES)
def test_log_vocabulary_survives_in_keep_fields_and_message_text(tier2_scrubber_factory, shape, name):
    """The word is in log.level and job.status (keep) and in the message; the
    name beside it is labelled. Before the tier 2 vocabulary rule the word
    became a known value and the sweep replaced it in the keep fields."""
    failures = []
    for w in _LOG_WORDS:
        s = tier2_scrubber_factory()
        doc = {"@timestamp": "2026-08-20T10:00:00Z", "log": {"level": w},
               "job": {"status": w}, "message": shape.format(w=w)}
        out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output["hits"]["hits"][0]["_source"]
        if out["log"]["level"] != w or out["job"]["status"] != w:
            failures.append(f"{w}: keep fields became {out['log']['level']!r}/{out['job']['status']!r}")
        if not any(t.strip(":,") == w for t in out["message"].split()):
            failures.append(f"{w}: message lost it: {out['message']!r}")
        if any(part in out["message"] for part in name.split()):
            failures.append(f"{w}: name leaked: {out['message']!r}")
        if any(pipeline_word(v) for v in s.mapping.values()):
            failures.append(f"{w}: a log word was mapped: {sorted(s.mapping.values())}")
    assert not failures, failures


def pipeline_word(value: str) -> bool:
    from hider import pipeline
    return all(pipeline.is_log_word(t) for t in value.split())


@pytest.mark.parametrize("patch,why", [
    ({"isRunning": True}, "still running"),
    ({"isPartial": True}, "partial results"),
    ({"timed_out": True}, "timed out"),
])
def test_incomplete_refusals_say_how_to_narrow(patch, why):
    env = _envelope([_hit(APP_DOC)])
    if "timed_out" in patch:
        env["rawResponse"]["timed_out"] = True
    else:
        env.update(patch)
    with pytest.raises(elastic.Refused) as e:
        _session().scrub_response(env, PLAN)
    assert e.value.code == "incomplete" and why in e.value.message
    assert "shorter time window" in e.value.message and "phrase" in e.value.message
    assert "index pattern" in e.value.message
