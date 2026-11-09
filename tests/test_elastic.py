"""The Elasticsearch site map and response scrubber. Invented values only."""

from __future__ import annotations

import copy
import json
import re

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
    # Sabotage the sweep and the keep pass so a known value survives; the
    # leak check must catch it. This is the only way to reach the branch,
    # which is the point.
    monkeypatch.setattr(s, "_sweep", lambda node: node)
    monkeypatch.setattr(s, "_keep_value", lambda v: v)
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


# -- a stray sensitive value in a keep field ----------------------------------
#
# "keep" is a declaration, not a guarantee: a real level field held a
# SharePoint personal-site URL among its info/warn spellings. Keep values get
# tier 1 (and the sweep), never tier 2, both in hits and in bucket keys.


def _level_plan():
    return elastic.Plan("logs-worker-*", {
        "levels": elastic.AggPlan("terms", "log.level", CFG.rule("log.level"))})


def test_a_sharepoint_url_in_a_level_field_is_hidden_in_hits_and_bucket_keys():
    s = _session()
    doc = {"@timestamp": "2026-08-20T10:00:00.000Z", "log": {"level": eseval.KEEP_LEAK_VALUE},
           "message": "one site collection moved"}
    aggs = {"levels": {"buckets": [{"key": eseval.KEEP_LEAK_VALUE, "doc_count": 1},
                                   {"key": "info", "doc_count": 40}]}}
    out = s.scrub_response(_envelope([_hit(doc)], aggs), _level_plan()).output
    blob = json.dumps(out)
    for gone in ("lena", "bellpointe", eseval.KEEP_LEAK_SITE, eseval.KEEP_LEAK_WEB):
        assert gone not in blob
    # still one bucket, its key rewritten, its count kept; "info" untouched
    buckets = out["aggregations"]["levels"]["buckets"]
    assert len(buckets) == 2 and buckets[0]["doc_count"] == 1
    assert buckets[0]["key"].startswith("site: ") and buckets[1] == {"key": "info", "doc_count": 40}
    # the hit's value and the bucket key agree, so the field still correlates
    assert out["hits"]["hits"][0]["_source"]["log"]["level"] == buckets[0]["key"]


@pytest.mark.parametrize("value", [*eseval.KEEP_LEVEL_SPELLINGS, *eseval.KEEP_OUTCOME_SPELLINGS,
                                   "Warning", "fatal", "job-step", "HTTP 4xx", "app.engine",
                                   "worker.items", "8.4.1", "2026-08-20T10:00:00.000Z",
                                   "backup-engine"])
def test_ordinary_keep_values_come_back_exactly_as_written(value):
    s = _session()
    doc = {"@timestamp": "2026-08-20T10:00:00.000Z", "log": {"level": value},
           "message": "Worker heartbeat"}
    aggs = {"levels": {"buckets": [{"key": value, "doc_count": 3}]}}
    out = s.scrub_response(_envelope([_hit(doc)], aggs), _level_plan()).output
    assert out["hits"]["hits"][0]["_source"]["log"]["level"] == value
    assert out["aggregations"]["levels"]["buckets"][0]["key"] == value


def test_non_string_keep_values_are_untouched():
    s = _session()
    doc = {"@timestamp": "2026-08-20T10:00:00.000Z", "message": "ok",
           "job": {"counters": {"items": 482913650027, "bytes": 0}},
           "http": {"response": {"status_code": 429}}}
    out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output
    src = out["hits"]["hits"][0]["_source"]
    assert src["job"]["counters"] == {"items": 482913650027, "bytes": 0}
    assert src["http"]["response"]["status_code"] == 429


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


def _old_case_with_log_words(tmp_path):
    """A case as code before the log-vocabulary trim saved it: tier 2 had
    called the bare words "Info" and "ERROR" organisations, so they were
    vaulted and became known values, next to a real organisation that only
    contains a log word."""
    old = _session()
    words = {"Info": old._label("ORG_NAME", "Info"), "ERROR": old._label("ORG_NAME", "ERROR")}
    real = old._label("ORG_NAME", "Info Systems")
    assert old._find_known("Info") and old._find_known("error")  # the old state
    return old.save_session(tmp_path / "case"), words, real


def test_a_saved_case_does_not_bring_back_log_words_as_known_values(tmp_path):
    from hider import research

    d, words, real = _old_case_with_log_words(tmp_path)
    s = elastic.EsScrubber.load_session(d, CFG, tier2="none")
    doc = copy.deepcopy(APP_DOC)
    doc["log"]["level"] = "Info"
    doc["event"]["outcome"] = "error"
    doc["message"] = "Info: nightly job for Info Systems started, no ERROR"
    out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output["hits"]["hits"][0]["_source"]
    # the log words are left alone, in keep fields and in message text
    assert out["log"]["level"] == "Info" and out["event"]["outcome"] == "error"
    assert out["message"] == f"Info: nightly job for {real} started, no ERROR"
    # a value that only contains a log word is still a known value
    assert s._find_known("for Info Systems") and not s._find_known("Info") \
        and not s._find_known("error")
    # the query side follows: a phrase with the word is no longer a known value
    esquery.compile_query({"index": "logs-app-*", "filters": [
        {"field": "message", "op": "phrase", "value": "Info started"}]}, CFG, s)
    # the old labels still unmask answers written before, and survive a re-save
    for value, label in words.items():
        assert s.mapping[label] == value
        assert research.unmask(f"see {label}", s.mapping)[0] == f"see {value}"
    s.save_session(d)
    again = json.loads((d / "session.json").read_text())["mapping"]
    assert {again[lab] for lab in words.values()} == set(words)


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
    eseval.learn_vocabulary(s, engine)  # what the bridge does before the first page
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


def test_a_job_named_only_in_free_text_is_labelled_on_a_fresh_case():
    """The es-eval leak: a status message names a job whose name is in no
    identifier field on the page, on the first call of a fresh case, so
    neither harvesting nor a session's memory can know it. The site map
    declares JOB_NAME an identifier, and the message introduces the name
    with the word "job": that reference is labelled, with the same label
    the name gets as a field value, so correlation survives."""
    doc = copy.deepcopy(APP_DOC)
    doc["job"]["name"] = "Mailbox Sweep"
    doc["job"]["status_message"] = ("Job Harbor Nightly (7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f) "
                                    "scheduled on ctr-amer-042, 61 sites enqueued")
    doc["message"] = "Backup job Fernhill Weekly for tenant Fabrikam Industries completed with 3 warnings"
    s = _session()
    out = s.scrub_response(_envelope([_hit(doc)]), PLAN).output["hits"]["hits"][0]["_source"]
    blob = json.dumps(out)
    assert "Harbor Nightly" not in blob and "Fernhill Weekly" not in blob
    assert out["job"]["status_message"].startswith("Job <Job_Name-")
    # the reference and the field value share one label
    label = s._scrub_text("job Harbor Nightly queued").split()[1]
    assert s.label_for(CFG.rule("job.name"), "Harbor Nightly") == label
    # the word "job" before ordinary text stays ordinary
    for line in ("Scheduler tick: 3 jobs due, 2 running", "picked up job for the queue",
                 "job failed, see Retry policy", "Job Failed (timeout) on the worker"):
        assert s._scrub_text(line) == line


# -- job names with no marker: the case's job-name vocabulary ------------------
#
# "Harbour Nightly finished with warnings": no "job" in front, so _JOB_REF
# cannot see it, and the job's own job.name field is on another document, so
# a fresh case's first page cannot harvest it. The bridge reads every job
# name from the cluster before that page (EsScrubber.vocabulary_request).


def _vocab_reply(*names: str, fields: int = 5, at: int = 0, more: bool = False) -> dict:
    """One composite page: ``names`` for field number ``at``, the others
    empty. ``more`` claims a full page, so the reader asks for another."""
    def page(i):
        got = list(names) if i == at else []
        node = {"buckets": [{"key": {elastic.VOCABULARY_SOURCE: n}, "doc_count": 1} for n in got]}
        if got and more:
            node["after_key"] = {elastic.VOCABULARY_SOURCE: got[-1]}
        return node

    return {"isPartial": False, "isRunning": False, "rawResponse": {
        "took": 1, "timed_out": False, "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        "aggregations": {f"{elastic.VOCABULARY_AGG}_{i}": page(i) for i in range(fields)}}}


def _learn(s, cluster: str, *replies: dict, now: float | None = None, window=None):
    """Drive one paged read to its commit, as the bridge does."""
    fetch = s.vocabulary_fetch(window, now=now)
    for reply in replies or ({},):
        fetch.request()
        fetch.feed(reply)
    return fetch.commit(cluster)


def test_the_fixture_names_jobs_with_no_marker_on_documents_without_the_field():
    """The shapes es-eval must see: a name with no "job" before it, in a
    message whose document has no job field; its job.name is elsewhere."""
    fx = eseval.generate()
    for job, message, _ in eseval.UNMARKED_JOBS:
        assert job in message and not re.search(r"(?i)\bjob\s+" + re.escape(job), message)
        holders = [d for d in fx.docs if d.source.get("message") == message]
        assert len(holders) == 1 and "job" not in holders[0].source
        assert any(d.source.get("job", {}).get("name") == job for d in fx.docs)
        assert fx.truth[job] == "JOB_NAME"


@pytest.mark.parametrize("job,message,_phrase", eseval.UNMARKED_JOBS)
def test_an_unmarked_job_name_is_one_label_on_a_fresh_cases_first_page(job, message, _phrase):
    fx = eseval.generate()
    engine = eseval.StubEngine(fx, CFG.indices)
    bare = _session()
    assert job in bare._scrub_text(message)  # why the vocabulary exists
    s = _session()
    counts, _ = eseval.learn_vocabulary(s, engine)
    assert counts["job.name"] >= len(eseval.UNMARKED_JOBS)
    out = s._scrub_text(message)
    label = s.known[job.casefold()]
    assert out == message.replace(job, label) and job not in out
    assert s.types[label] == "JOB_NAME"


_VOCAB_FIELDS = ["job.name", "labels.tenant_name", "labels.tenant_full_name",
                 "labels.resource_name", "labels.site_name"]


def test_the_vocabulary_request_is_fixed_and_carries_no_value():
    """The only thing a query contributes is its own resolved time bounds."""
    s = _session()
    q = s.vocabulary_fetch().request()
    assert q["params"]["index"] == ",".join(CFG.indices) and q["params"]["ignore_unavailable"]
    body = q["params"]["body"]
    assert body["size"] == 0
    assert body["query"] == {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-30d"}}}]}}
    assert body["aggs"] == {f"{elastic.VOCABULARY_AGG}_{i}": {"composite": {
        "size": elastic.VOCABULARY_PAGE,
        "sources": [{elastic.VOCABULARY_SOURCE: {"terms": {"field": f}}}]}}
        for i, f in enumerate(_VOCAB_FIELDS)}
    s.seed("Contoso Group")
    assert "Contoso" not in json.dumps(s.vocabulary_fetch().request())


def test_the_request_covers_the_cases_own_window_plus_a_margin():
    """A one-hour case reads one hour plus a day on each side, not the whole
    retention period: on a large cluster that is the difference between a
    page and a refusal."""
    s = _session()
    lo = 1_787_227_200.0          # 2026-08-20T12:00:00Z
    bounds = s.vocabulary_fetch((lo, lo + 3600)).request()["params"]["body"] \
        ["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert bounds == {"gte": "2026-08-19T12:00:00.000Z", "lte": "2026-08-21T13:00:00.000Z"}
    # a query with no start or no end falls back to vocabulary.days, and
    # leaves the date math to the cluster's clock
    assert s.vocabulary_fetch().request()["params"]["body"]["query"]["bool"]["filter"][0] \
        == {"range": {"@timestamp": {"gte": "now-30d"}}}


def test_a_window_already_read_is_not_read_again_but_a_wider_one_is():
    s = _session()
    lo = 1_787_227_200.0
    assert s.vocabulary_due("emea", (lo, lo + 3600), now=0.0)
    _learn(s, "emea", _vocab_reply("Harbour Nightly"), now=1.0, window=(lo, lo + 3600))
    # the same case, a second later, and any window inside what was read
    assert not s.vocabulary_due("emea", (lo - 1, lo + 3601), now=2.0)
    assert not s.vocabulary_due("emea", (lo + 60, lo + 120), now=2.0)
    # outside it: a week earlier, or no bounds at all
    assert s.vocabulary_due("emea", (lo - 7 * 86400, lo), now=2.0)
    assert s.vocabulary_due("emea", None, now=2.0)
    # and the fallback read covers every window
    _learn(s, "emea", _vocab_reply("Harbour Nightly"), now=3.0)
    assert not s.vocabulary_due("emea", (lo - 7 * 86400, lo), now=4.0)


def test_a_vocabulary_longer_than_one_page_is_read_in_pages():
    s = _session()
    first = [f"Orchard Sweep {i:05d}" for i in range(elastic.VOCABULARY_PAGE)]
    fetch = s.vocabulary_fetch()
    req = fetch.request()
    assert "after" not in req["params"]["body"]["aggs"][f"{elastic.VOCABULARY_AGG}_0"]["composite"]
    fetch.feed(_vocab_reply(*first, more=True))
    assert fetch.pending()
    req = fetch.request()
    aggs = req["params"]["body"]["aggs"]
    # only the field with more to give is asked again, from where it stopped
    assert list(aggs) == [f"{elastic.VOCABULARY_AGG}_0"]
    assert aggs[f"{elastic.VOCABULARY_AGG}_0"]["composite"]["after"] == \
        {elastic.VOCABULARY_SOURCE: first[-1]}
    fetch.feed(_vocab_reply("Harbour Nightly"))
    assert not fetch.pending()
    assert fetch.commit("c")["job.name"] == elastic.VOCABULARY_PAGE + 1
    assert fetch.requests == 2
    assert "harbour nightly" in s.known  # the last page's names are learnt too


@pytest.mark.parametrize("reply,code", [
    ({"error": {"type": "search_phase_execution_exception", "reason": "x"}, "status": 500},
     "upstream_error"),
    ({**_vocab_reply("Harbour Nightly"), "isPartial": True}, "vocabulary"),
    ({"isPartial": False, "isRunning": False,
      "rawResponse": {"timed_out": False, "hits": {"hits": []}}}, "vocabulary"),
    ("not an object", "vocabulary"),
])
def test_a_vocabulary_that_cannot_be_read_refuses(reply, code):
    s = _session()
    with pytest.raises(elastic.Refused) as e:
        _learn(s, "c", reply, now=0.0)
    assert e.value.code == code
    assert s.vocabulary_due("c", now=1.0)  # still due: nothing was learnt


def test_a_page_that_is_not_the_shape_it_was_asked_for_refuses():
    """The old single-aggregation reply shape, now wrong: a bucket key is an
    object with the composite source in it, never a bare string."""
    s = _session()
    old = {"isPartial": False, "isRunning": False, "rawResponse": {
        "timed_out": False, "aggregations": {f"{elastic.VOCABULARY_AGG}_{i}": {
            "buckets": [{"key": "Harbour Nightly", "doc_count": 1}] if i == 0 else []}
            for i in range(5)}}}
    with pytest.raises(elastic.Refused) as e:
        _learn(s, "c", old, now=0.0)
    assert e.value.code == "vocabulary" and "Harbour" not in e.value.message
    assert "harbour nightly" not in s.known


def test_a_vocabulary_over_its_ceiling_refuses_rather_than_run_on_a_partial_list():
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"]["max"] = 2
    s = elastic.EsScrubber(elastic.parse(raw, source="t"), tier2="none")
    assert _learn(s, "c", _vocab_reply("Harbour Nightly"), now=0.0)["job.name"] == 1
    assert s.vocabulary_report()["near_cap"] == []
    _learn(s, "c", _vocab_reply("Thornbury Estates", at=1), now=700.0)
    assert s.vocabulary_report() == {
        "fields": {"job.name": 0, "labels.tenant_name": 1, "labels.tenant_full_name": 0,
                   "labels.resource_name": 0, "labels.site_name": 0},
        "max": 2, "near_cap": [], "skipped": {}, "omitted": []}
    with pytest.raises(elastic.Refused) as e:
        _learn(s, "c", _vocab_reply("Oak Creek Holdings", "Fernhill Row", "Marlowe Trust", at=4),
               now=1400.0)
    assert e.value.code == "vocabulary"
    assert "labels.site_name has more than 2 distinct values" in e.value.message
    assert "vocabulary.max" in e.value.message and "Oak Creek" not in e.value.message
    assert "Oak Creek Holdings" not in s.known and "oak creek holdings" not in s.known

def test_the_ceiling_counts_a_whole_read_not_one_page_of_it():
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"]["max"] = elastic.VOCABULARY_PAGE
    s = elastic.EsScrubber(elastic.parse(raw, source="t"), tier2="none")
    full = [f"Orchard Sweep {i:05d}" for i in range(elastic.VOCABULARY_PAGE)]
    with pytest.raises(elastic.Refused) as e:
        _learn(s, "c", _vocab_reply(*full, more=True), _vocab_reply("Harbour Nightly"), now=0.0)
    assert e.value.code == "vocabulary" and "more than" in e.value.message
    assert not s.known and s.vocabulary_due("c")


def test_a_read_over_its_time_budget_refuses():
    """A page at a time is only safe if the whole read is bounded: an estate
    wide enough to page forever must not hold the bridge's one lock."""
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"]["budget_s"] = 1
    s = elastic.EsScrubber(elastic.parse(raw, source="t"), tier2="none")
    full = [f"Orchard Sweep {i:05d}" for i in range(elastic.VOCABULARY_PAGE)]
    fetch = s.vocabulary_fetch()
    fetch._t0 -= 2.0  # the first page came back after the budget was gone
    fetch.request()
    with pytest.raises(elastic.Refused) as e:
        fetch.feed(_vocab_reply(*full, more=True))
    assert e.value.code == "vocabulary" and "budget_s" in e.value.message
    assert not s.known and s.vocabulary_due("c")
    # a read that is finished when the budget runs out is not refused: there
    # is nothing left to ask for
    done = s.vocabulary_fetch()
    done._t0 -= 2.0
    done.request()
    done.feed(_vocab_reply("Harbour Nightly"))
    assert done.commit("c")["job.name"] == 1


def test_a_read_that_was_not_finished_cannot_be_committed():
    s = _session()
    full = [f"Orchard Sweep {i:05d}" for i in range(elastic.VOCABULARY_PAGE)]
    fetch = s.vocabulary_fetch()
    fetch.request()
    fetch.feed(_vocab_reply(*full, more=True))
    with pytest.raises(elastic.Refused) as e:
        fetch.commit("c")
    assert e.value.code == "vocabulary"
    assert "harbour nightly" not in s.known and s.vocabulary_due("c")


@pytest.mark.parametrize("key,value", [("max", 0), ("max", 300_000), ("days", 0), ("days", "30"),
                                       ("margin_days", 0), ("margin_days", 90),
                                       ("budget_s", 0), ("budget_s", 1200)])
def test_vocabulary_settings_are_bounded(key, value):
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"][key] = value
    with pytest.raises(elastic.ConfigError, match=f"vocabulary.{key}"):
        elastic.parse(raw, source="t")


def test_with_no_vocabulary_section_every_learnable_field_is_read():
    """The default is everything a site map would be *allowed* to list, not
    job names only: a site that never wrote the section had its tenant and
    resource names readable in message text."""
    raw = json.loads(elastic.EXAMPLE.read_text())
    listed = elastic.parse(raw, source="t")
    del raw["vocabulary"]
    cfg = elastic.parse(raw, source="t")
    read = [r.pattern for r in cfg.vocabulary_rules]
    assert read == [r.pattern for r in cfg.learnable_rules]
    assert set(read) == {"labels.tenant_name", "labels.tenant_full_name",
                         "labels.resource_name", "labels.site_name", "job.name"}
    # the default is exactly what the validator accepts, so a map listing
    # everything it may list gets the same set as one listing nothing
    assert set(read) == {r.pattern for r in listed.vocabulary_rules}
    # and nothing a vocabulary may not hold slipped in
    for r in cfg.vocabulary_rules:
        assert not r.is_glob and r.shape is None
        assert r.type not in elastic.NO_VOCABULARY_TYPES


def test_a_map_that_lists_fewer_fields_reports_the_ones_it_leaves_out():
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"]["fields"] = ["job.name"]
    cfg = elastic.parse(raw, source="t")
    assert cfg.vocabulary_omitted == ("labels.tenant_name", "labels.tenant_full_name",
                                      "labels.resource_name", "labels.site_name")
    s = elastic.EsScrubber(cfg, tier2="none")
    _learn(s, "c", _vocab_reply("Harbour Nightly"), now=0.0)
    assert s.vocabulary_report()["omitted"] == list(cfg.vocabulary_omitted)
    # the default and a map that lists everything leave nothing out
    del raw["vocabulary"]
    assert elastic.parse(raw, source="t").vocabulary_omitted == ()


def test_log_words_and_stopwords_are_never_vocabulary():
    """A job called "Failed" or "default" would erase that word from every
    log level, outcome and namespace in the case."""
    s = _session()
    _learn(s, "c", _vocab_reply("Failed", "Warning", "default", "", "Harbour Nightly"), now=0.0)
    assert s.vocabulary_report()["skipped"] == {"log_word": 2, "stopword": 1, "empty": 1}
    assert s._scrub_text("Failed: default namespace, Warning raised") == \
        "Failed: default namespace, Warning raised"


def test_the_vocabulary_is_read_once_per_cluster_then_every_ten_minutes():
    s = _session()
    assert s.vocabulary_due("emea", now=0.0)
    _learn(s, "emea", _vocab_reply("Harbour Nightly"), now=100.0)
    assert not s.vocabulary_due("emea", now=100.0 + elastic.VOCABULARY_REFRESH_S - 1)
    assert s.vocabulary_due("emea", now=100.0 + elastic.VOCABULARY_REFRESH_S)
    assert s.vocabulary_due("amer", now=101.0)  # each cluster has its own jobs


def test_without_a_learnable_field_there_is_no_vocabulary_request():
    raw = json.loads(elastic.EXAMPLE.read_text())
    names = {"job.name", "labels.tenant_name", "labels.tenant_full_name",
             "labels.resource_name", "labels.site_name"}
    raw["fields"] = {k: v for k, v in raw["fields"].items() if k not in names}
    del raw["vocabulary"]  # the default: everything learnable, and there is none
    s = elastic.EsScrubber(elastic.parse(raw, source="t"), tier2="none")
    assert not s.vocabulary_due("c", now=0.0)
    raw["vocabulary"] = {"fields": []}  # or a site that turns it off
    assert not elastic.EsScrubber(elastic.parse(raw, source="t"), tier2="none").vocabulary_due("c")


def test_the_vocabulary_leaves_ordinary_messages_and_levels_readable():
    """Every clean message template, and the keep fields, come out the same
    with the fixture's vocabulary learnt as without it."""
    fx = eseval.generate()
    engine = eseval.StubEngine(fx, CFG.indices)
    with_vocab, without = _session(), _session()
    eseval.learn_vocabulary(with_vocab, engine)
    for d in fx.docs:
        if d.clean:
            m = d.source["message"]
            assert with_vocab._scrub_text(m) == without._scrub_text(m) == m
    for level in ("info", "warn", "error", "Error", "WARN", "Success", "Failed"):
        assert with_vocab._scrub_text(level) == level


# -- customer names with no marker: the vocabulary over the site's name fields --


def test_the_fixture_names_customers_on_documents_whose_fields_hold_someone_else():
    fx = eseval.generate()
    for field_path, name, message, _ in eseval.UNMARKED_NAMES:
        holders = [d for d in fx.docs if d.source.get("message") == message]
        assert len(holders) == 1
        flat = eseval.flatten(holders[0].source)
        assert name not in flat.values()  # its own fields carry another tenant, never the name
        assert any(eseval.flatten(d.source).get(field_path) == name for d in fx.docs)


@pytest.mark.parametrize("tier2", ["none", "classifier"])
@pytest.mark.parametrize("field_path,name,message,_phrase", eseval.UNMARKED_NAMES)
def test_an_unmarked_customer_name_is_one_label_the_same_as_its_field_label(
        field_path, name, message, _phrase, tier2):
    fx = eseval.generate()
    s = _session(tier2)
    eseval.learn_vocabulary(s, eseval.StubEngine(fx, CFG.indices))
    label = s.label_for(CFG.rule(field_path), name)
    assert s._scrub_text(message) == message.replace(name, label)


@pytest.mark.parametrize("field_path,code", [
    ("labels.principal_name", "UPN_EMAIL: one value per user account"),
    ("labels.tenant_id", "TENANT_ID: one value per object"),
    ("job.id", "GUID: one value per object"),
    ("host.ip", "IPV4: one value per machine"),
    ("cloud.instance.name", "INSTANCE_NAME: one value per machine"),
    ("tenant.users_in_tenant", "TENANT_SIZE: a number"),
    ("cloud.account.id", "CLOUD_ACCOUNT: a number"),
    ("agent.name", "has a shape"),
    ("log.level", "must be a listed identifier"),
    ("data_stream.*", "must be a listed identifier"),
    ("labels.nowhere", "must be a listed identifier"),
])
def test_a_vocabulary_on_a_field_with_too_many_values_is_a_startup_error(field_path, code):
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["vocabulary"]["fields"].append(field_path)
    with pytest.raises(elastic.ConfigError, match=re.escape(code)):
        elastic.parse(raw, source="t")


@pytest.mark.parametrize("value,why", [
    ("Archive", "ordinary_word"), ("Default", "stopword"), ("BACKUP", "ordinary_word"),
    ("Production", "ordinary_word"), ("Exports", "ordinary_word"),   # a structural path word
    ("HR", "short"), ("Ops", "short"), ("2026", "no_letters"), ("Error", "log_word"),
    ("default", "stopword"),
    ("Brackenvault", None), ("LegalHold2031", None), ("Kittiwake", None),
    ("Legal Hold", None), ("Daily Backup", None),   # more than one word: the phrase is specific
])
def test_which_names_are_vocabulary(value, why):
    assert elastic.EsScrubber.vocabulary_skip(value) == why


def test_an_ordinary_word_name_leaves_the_word_readable_and_keeps_its_field_label():
    """Declared: a resource called "Archive" is unprotected in free text
    before a page shows it in its own field; the word stays readable."""
    s = _session()
    _learn(s, "c", _vocab_reply("Archive", "Default", "HR", "Brackenvault", at=3), now=0.0)
    assert s.vocabulary_report()["skipped"] == {"ordinary_word": 1, "stopword": 1, "short": 1}
    line = "Archive completed for the Default policy; HR export ok; Brackenvault at 91%"
    out = s._scrub_text(line)
    assert out.startswith("Archive completed for the Default policy; HR export ok; <Resource_Name-")
    assert "Brackenvault" not in out


def test_a_multi_word_name_of_ordinary_words_hides_that_phrase_and_nothing_else():
    """The cost of protecting "Legal Hold" as a resource: the phrase, in any
    case, is labelled in every message; its words alone are not."""
    s = _session()
    _learn(s, "c", _vocab_reply("Legal Hold", at=3), now=0.0)
    out = s._scrub_text("legal hold applied; hold released; legal review pending")
    assert out.endswith("applied; hold released; legal review pending") and out.startswith("<Resource_Name-")


def test_an_organisations_core_is_held_to_the_same_rules():
    """"Archive AG" is a tenant; its core "Archive" is an ordinary word, so
    it is not registered on its own and "archive" stays readable."""
    s = _session()
    _learn(s, "c", _vocab_reply("Archive AG", "Thornbury Estates Ltd", at=2), now=0.0)
    out = s._scrub_text("Archive AG quota; archive done; Thornbury Estates synced")
    assert "Archive AG" not in out and "archive done" in out and "Thornbury" not in out


def test_one_request_carries_every_vocabulary_field():
    s = _session()
    q = s.vocabulary_fetch().request()["params"]["body"]["aggs"]
    assert len(q) == 5 and s.vocabulary_due("c", now=0.0)
