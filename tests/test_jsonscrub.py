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
    # The tenant name is the secret and must be gone. The vendor half of the
    # host may survive in pseudonym form: tier 1's TENANT_DOMAIN rule now wins
    # this host and replaces it shape-preservingly (tenant-NN.onmicrosoft.example),
    # which keeps "which SaaS is this" readable and leaks nothing - the vendor
    # suffix is identical for every tenant on earth. "onmicrosoft.com" itself
    # must still be gone, so a pseudonym can never collide with a real host.
    assert "acmeUSA" not in msg and "Acme_Prod" not in msg and " AC " not in msg
    assert "onmicrosoft.com" not in msg
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


# --- a name that is an ordinary word ------------------------------------------
#
# A value under an identifier key used to be remembered and swept across the
# whole export. For a name that is an ordinary English word that meant: one
# ticket whose tenant field said "Archive" turned every other ticket's
# "Moved 40 items to archive" into "Moved 40 items to <Org-01>". The word
# list is jsonscrub.ORDINARY_NAME_WORDS, shared with the Elasticsearch
# scrubber (elastic re-exports it).


_TICKETS = [
    {"ticket": "T-1001", "tenant": "Archive", "job_name": "Retention",
     "notes": "Retention finished for the tenant with 0 errors"},
    {"ticket": "T-1002", "tenant": "Fabrikam Industries", "job_name": "Mailbox",
     "notes": "Mailbox completed; Fabrikam Industries confirmed by phone"},
    {"ticket": "T-1003", "tenant": "Harbour Ridge Ltd", "job_name": "Nightly Sweep",
     "notes": "Moved 40 items to archive, retention unchanged; mailbox quota is fine"},
]


def _ticket_run(case_wide: bool):
    s = jsonscrub.JsonScrubber(tier2="none")
    s.ordinary_words_case_wide = case_wide
    return s.run(json.loads(json.dumps(_TICKETS)))


def test_an_ordinary_word_name_is_readable_outside_its_own_record():
    """The measured before and after, on the same invented export: 3 of the
    6 name values are ordinary words, and ticket 3's note used to lose all
    three of them."""
    before = _ticket_run(True).output
    assert "<" in before[2]["notes"] and "archive" not in before[2]["notes"]
    after = _ticket_run(False).output
    # own fields are still labelled...
    for rec in after:
        assert rec["tenant"].startswith("<") and rec["job_name"].startswith("<")
    # ...the words survive as English in the other ticket's note...
    assert "Moved 40 items to archive, retention unchanged; mailbox quota is fine" \
        == after[2]["notes"]
    # ...and the real names are still hidden everywhere
    assert "Fabrikam" not in json.dumps(after) and "Harbour" not in json.dumps(after)


def test_the_record_that_owns_the_name_still_hides_it_in_its_own_text():
    after = _ticket_run(False).output
    assert "Retention" not in after[0]["notes"]      # ticket 1 owns "Retention"
    assert after[0]["notes"].startswith("<")
    assert "Mailbox" not in after[1]["notes"]        # ticket 2 owns "Mailbox"


def test_a_record_reads_the_same_whatever_records_sit_beside_it():
    """The broken property: what a record said depended on which records
    came with it."""
    alone = jsonscrub.scrub([json.loads(json.dumps(_TICKETS[2]))], tier2="none")
    together = _ticket_run(False)
    assert alone.output[0]["notes"] == together.output[2]["notes"]


def test_a_single_object_export_is_one_record():
    """The declared boundary: elements of the top-level list are records;
    any other shape is one record, so within a single-object export the
    word is hidden throughout, as before."""
    one = jsonscrub.scrub({"tenant": "Archive",
                           "notes": "items moved to archive overnight"}, tier2="none")
    assert one.output["tenant"].startswith("<")
    assert "archive" not in one.output["notes"]
    assert one.output["tenant"] in one.output["notes"]


def test_a_seeded_ordinary_word_is_still_hidden_across_the_export():
    """A person seeding "Archive" as a search term is saying "hide this
    word"; the rule must not demote it just because a tenant field also
    holds it."""
    r = jsonscrub.scrub(json.loads(json.dumps(_TICKETS)), tier2="none", terms=["Archive"])
    assert "archive" not in json.dumps(r.output).lower().replace("<org", "")
    assert r.output[0]["tenant"] == r.output[2]["notes"].split()[4].rstrip(",")


def test_the_export_leak_check_treats_readable_words_as_readable():
    """The leak check reads the same sweep index the substitution does, so
    a word kept out of the index is out of both: an ordinary-word name in
    another record's prose is not a leak, a real name still is."""
    r = _ticket_run(False)
    assert r.stats["leaks"] == []
    s = jsonscrub.JsonScrubber(tier2="none")
    s._label("ORG_NAME", "Fabrikam Industries")
    assert s.leak_check({"notes": "Fabrikam Industries called"}) != []


def test_the_ordinary_word_list_is_shared_not_copied():
    from hider import elastic

    assert elastic.ORDINARY_NAME_WORDS is jsonscrub.ORDINARY_NAME_WORDS


def test_the_run_names_which_words_stay_readable():
    """A clean verdict looks the same whether or not a customer name was
    left readable, so the run has to say which ones. Labels in the stats -
    they end up in .scrub.json, which carries decisions, not data."""
    r = _ticket_run(False)
    assert r.stats["leaks"] == []                      # clean, and still
    labels = r.stats["readable_words"]
    assert len(labels) == 3
    assert all(lab in r.mapping for lab in labels)
    assert sorted(r.mapping[lab] for lab in labels) == ["Archive", "Mailbox", "Retention"]
    # the stats themselves carry no word
    assert "Archive" not in json.dumps(r.stats)


def test_seeding_a_reported_name_takes_it_off_the_list():
    """The loop the report exists to close: it names Archive, you seed
    Archive, it stops being readable and stops being reported."""
    before = _ticket_run(False)
    assert "Archive" in [before.mapping[l] for l in before.stats["readable_words"]]
    after = jsonscrub.scrub(json.loads(json.dumps(_TICKETS)), tier2="none", terms=["Archive"])
    assert "Archive" not in [after.mapping[l] for l in after.stats["readable_words"]]
    assert "archive" not in json.dumps(after.output).lower().replace("<org", "")
