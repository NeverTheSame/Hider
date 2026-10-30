"""JSON obfuscation layer. Synthetic values only."""

import json
import random
import re

from hider import jsonscrub

DOC = {
    "number": "08123456",
    "sys_id": "9f2c1a8b3d4e5f60718293a4b5c6d7e8",
    "short_description": "Restore stuck for Northwind Traders",
    "account": {"display_value": "Northwind Traders LLC",
                "value": "4a1b2c3d4e5f60718293a4b5c6d7e8f9"},
    "contact": {"display_value": "Gretchen Halvorsen"},
    "u_contact_email": "gretchen.halvorsen@northwindtraders.com",
    "u_contact_phone": "+1 (415) 555-0142",
    "state": "Open",
    "priority": 2,
    "opened_at": "2026-10-01 09:12:00",
    "api_token": "sk-abcdefghijklmnopqrstuvwxyz123456",
    "comments": [{"text": "Hi Gretchen,\nproxy bkp-prx01.corp.northwindtraders.com at "
                          "10.20.30.40, call +44 20 7946 0958.\nBuild 8.1.0.7"}],
}
ORIGINALS = ["northwind", "gretchen", "halvorsen", "08123456", "9f2c1a8b", "4a1b2c3d",
             "555-0142", "7946", "10.20.30.40", "sk-abcdef", "bkp-prx01"]


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
    org =out["short_description"].split("for ", 1)[1]
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
    res = jsonscrub.scrub({"records": [{"message": "Server Records"}, {"message": "the server records"}],
                           "backup_server": "x"})
    assert "records" in res.output
    assert res.output["records"][1]["message"] == "the server records"


def test_sharepoint_paths_tenant_hosts_and_terms():
    res = jsonscrub.scrub(
        {"message": "GET /sites/acmeUSA-01-X/_api/web for Acme_Prod.onmicrosoft.com by AC team"},
        terms=["AC"])
    msg = res.output["message"]
    assert "acmeUSA" not in msg and "onmicrosoft" not in msg and " AC " not in msg
    assert "/sites/<" in msg and "/_api/web" in msg


def test_sweep_never_rewrites_inside_a_label():
    res = jsonscrub.scrub({"message": "SharePoint said https://acme.sharepoint.com/sites/x",
                           "account": "SharePoint"})
    assert "https://tenant-01.sharepoint.example/spaces/Space-01" in res.output["message"]


def test_log_vocabulary_is_not_a_name_and_prefix_terms():
    res = jsonscrub.scrub({"message": "429 Too Many Requests on Site Pages for acmeimdInternalUse1"},
                          terms=["acmeimd*"])
    msg = res.output["message"]
    assert "Too Many Requests" in msg and "Site Pages" in msg
    assert "acmeimd" not in msg.lower()


# ---------------------------------------------------------------------------
# Short values. A value mapped from a sensitive key but under four characters
# used to be neither swept from free text nor counted by the leak check, so
# {"account_id": 482, "notes": "Account 482 escalated"} came back with 482 in
# the notes and leaks: []. The bridge refuses on the leak check, so a blind
# spot there was a blind spot in the bridge.
# ---------------------------------------------------------------------------

def _texts(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _texts(v)
    elif isinstance(node, list):
        for v in node:
            yield from _texts(v)
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
        yield str(node)


def _present(tok, out):
    rx = re.compile(r"(?<![A-Za-z0-9])" + re.escape(tok) + r"(?![A-Za-z0-9])", re.I)
    return any(rx.search(t) for t in _texts(out))


def test_short_value_is_swept_from_prose_and_the_user_example_round_trips():
    res = jsonscrub.scrub({"account_id": 482, "notes": "Account 482 escalated"}, tier2="none")
    label = res.output["account_id"]
    assert label.startswith("<") and res.output["notes"] == f"Account {label} escalated"
    assert res.stats["leaks"] == []
    for one_char in ("q", "7"):  # single characters too, once a sensitive key mapped them
        res = jsonscrub.scrub({"account_id": one_char, "notes": f"account {one_char} flagged"},
                              tier2="none")
        assert res.mapping, one_char
        assert not _present(one_char, res.output), one_char


def test_leak_check_counts_a_short_value_it_still_holds():
    """The check itself, not the sweep: hand it an output that still carries
    the three-character original and it must say so."""
    s = jsonscrub.JsonScrubber(tier2="none")
    res = s.run({"account_id": 482, "notes": "fine"})
    label = res.output["account_id"]
    tampered = {**res.output, "notes": "Account 482 escalated"}
    assert s.leak_check(tampered) == [label]
    assert s.leak_check(res.output) == []


def test_short_values_are_swept_and_the_trade_is_measured():
    """The synthetic export set behind the README numbers. Ninety exports in
    three groups of thirty: prose that quotes the short account id and a
    1-2 character code; prose that never does; and a collision, where an
    innocent count equals the account id both in prose and as a bare number.

    Before (four-character floor):  mentions 30/30 still in output, collision
    30/30 still in output, leak check flagged 0 in every group.
    After:                          0 still in output anywhere, 0 flagged,
    and all 30 collisions over-redacted. That last number is the price: a
    count that equals a mapped value is removed, because leaving it means the
    leak check is lying when it says clean."""
    rng = random.Random(20260830)
    groups = {"mentions": [], "silent": [], "collision": []}
    for i in range(90):
        acct = rng.randint(1, 999)
        code = rng.choice(["ab", "x7", "q", "Z9", "k2"])
        other = rng.randint(1, 999)
        while other == acct:
            other = rng.randint(1, 999)
        g = ("mentions", "silent", "collision")[i % 3]
        if g == "mentions":
            doc = {"account_id": acct, "region_code": code, "retry_count": other,
                   "notes": f"Account {acct} escalated, code {code} applied; retried {other} times"}
        elif g == "silent":
            doc = {"account_id": acct, "region_code": code, "retry_count": other,
                   "notes": f"Escalated after {other} retries, see runbook section 4"}
        else:
            doc = {"account_id": acct, "region_code": code, "retry_count": acct,
                   "notes": f"Escalated after {acct} retries by the on-call"}
        groups[g].append((doc, str(acct), str(other)))

    for g, docs in groups.items():
        still_present = flagged = coincidental_removed = 0
        for doc, acct, other in docs:
            res = jsonscrub.scrub(doc, tier2="none")
            shorts = [v for v in res.mapping.values() if len(v) < 4]
            still_present += any(_present(v, res.output) for v in shorts)
            flagged += bool(res.stats["leaks"])
            innocent = acct if g == "collision" else other
            coincidental_removed += not _present(innocent, res.output)
        assert len(docs) == 30
        assert still_present == 0, g
        assert flagged == 0, g
        assert coincidental_removed == (30 if g == "collision" else 0), g
