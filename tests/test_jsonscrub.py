"""JSON obfuscation layer. Synthetic values only."""

import json

from hider import jsonscrub

DOC = {
    "number": "08123456",
    "sys_id": "9f2c1a8b3d4e5f60718293a4b5c6d7e8",
    "short_description": "Restore stuck for Northwind Traders",
    "account": {
        "display_value": "Northwind Traders LLC",
        "value": "4a1b2c3d4e5f60718293a4b5c6d7e8f9",
    },
    "contact": {"display_value": "Gretchen Halvorsen"},
    "u_contact_email": "gretchen.halvorsen@northwindtraders.com",
    "u_contact_phone": "+1 (415) 555-0142",
    "state": "Open",
    "priority": 2,
    "opened_at": "2026-10-01 09:12:00",
    "api_token": "sk-abcdefghijklmnopqrstuvwxyz123456",
    "comments": [
        {
            "text": "Hi Gretchen,\nproxy bkp-prx01.corp.northwindtraders.com at "
            "10.20.30.40, call +44 20 7946 0958.\nBuild 8.1.0.7"
        }
    ],
}
ORIGINALS = [
    "northwind",
    "gretchen",
    "halvorsen",
    "08123456",
    "9f2c1a8b",
    "4a1b2c3d",
    "555-0142",
    "7946",
    "10.20.30.40",
    "sk-abcdef",
    "bkp-prx01",
]


def _run():
    return jsonscrub.scrub(json.loads(json.dumps(DOC)))


def test_no_original_survives():
    res = _run()
    blob = json.dumps(res.output).lower()
    for v in ORIGINALS:
        assert v not in blob, v
    assert res.stats["leaks"] == []


def test_structure_and_non_sensitive_fields_kept():
    out = _run().output
    assert set(out) == set(DOC)
    assert out["state"] == "Open"
    assert out["priority"] == 2
    assert out["opened_at"] == "2026-10-01 09:12:00"
    assert "Build 8.1.0.7" in out["comments"][0]["text"]
    assert out["comments"][0]["text"].startswith("Hi <")


def test_values_map_consistently_and_reversibly():
    res = _run()
    out = res.output
    org = out["short_description"].split("for ", 1)[1]
    assert res.mapping[org] == "Northwind Traders"
    assert res.mapping[out["number"]] == "08123456"
    assert res.mapping[out["u_contact_email"]] == DOC["u_contact_email"]


def test_secrets_destroyed_not_mapped():
    res = _run()
    assert res.output["api_token"] == "<REDACTED:SECRET>"
    assert DOC["api_token"] not in res.mapping.values()


def test_key_classification():
    c = jsonscrub.classify_key
    assert c("u_contact_email") == "UPN_EMAIL"
    assert c("assigned_to") == "PERSON_NAME"
    assert c("sys_created_by") == "PERSON_NAME"
    assert c("account") == "ORG_NAME"
    assert c("account_id").startswith("ID:")
    assert c("caseNumber") == "ID:CASE_NUMBER"
    assert c("password") == "SECRET"
    assert c("state") is None
    assert c("priority") is None
    assert c("status_code") is None


def test_jsonl_fallback():
    doc, jsonl = jsonscrub.parse('{"email": "a.b@x.example.com"}\n{"email": "c@y.org"}\n')
    assert jsonl and len(doc) == 2


def test_descriptors_and_decimals_left_alone():
    assert jsonscrub.classify_key("session_status") is None
    assert jsonscrub.classify_key("creation_time_utc") is None
    res = jsonscrub.scrub({"message": "Processed 45.123456789 GB, build 10.0.17763.1234"})
    assert res.output["message"] == "Processed 45.123456789 GB, build 10.0.17763.1234"


def test_plain_keys_untouched_and_common_words_not_spread():
    res = jsonscrub.scrub(
        {
            "records": [{"message": "Server Records"}, {"message": "the server records"}],
            "backup_server": "x",
        }
    )
    assert "records" in res.output
    assert res.output["records"][1]["message"] == "the server records"


def test_sharepoint_paths_tenant_hosts_and_terms():
    res = jsonscrub.scrub(
        {"message": "GET /sites/acmeUSA-01-X/_api/web for Acme_Prod.onmicrosoft.com by AC team"},
        terms=["AC"],
    )
    msg = res.output["message"]
    assert "acmeUSA" not in msg and "onmicrosoft" not in msg and " AC " not in msg
    assert "/sites/<" in msg and "/_api/web" in msg


def test_sweep_never_rewrites_inside_a_label():
    res = jsonscrub.scrub(
        {"message": "SharePoint said https://acme.sharepoint.com/sites/x", "account": "SharePoint"}
    )
    assert "https://tenant-01.sharepoint.example/spaces/Space-01" in res.output["message"]


def test_log_vocabulary_is_not_a_name_and_prefix_terms():
    res = jsonscrub.scrub(
        {"message": "429 Too Many Requests on Site Pages for acmeimdInternalUse1"},
        terms=["acmeimd*"],
    )
    msg = res.output["message"]
    assert "Too Many Requests" in msg and "Site Pages" in msg
    assert "acmeimd" not in msg.lower()


def test_word_list_is_bundled_not_read_from_the_os(monkeypatch):
    # Linux CI images have no /usr/share/dict/words; the filter must not depend on it.
    import builtins

    real_open = builtins.open

    def guarded(path, *a, **k):
        assert "/usr/share/dict" not in str(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", guarded)
    monkeypatch.setattr(jsonscrub, "_COMMON", None)
    assert jsonscrub._WORDS_FILE.is_relative_to(jsonscrub.Path(jsonscrub.__file__).parent)
    assert all(jsonscrub._is_common(w) for w in ("server", "records", "sites"))
