"""Command-line behaviour that the security story depends on.

Regression: ``redact`` built its own tier list and ran tier 1 only, while
``proxy`` ran tier 2. The documented "redact the bundle before pasting it
anywhere" workflow was therefore the one path that let a customer's name
through. Both now build tiers through one function, and this file holds it
that way.
"""

from __future__ import annotations

import pytest

from hider import cli, pipeline

NOTE = ("Rachel Mbeki at Contoso Group escalated case 08123456 for "
        "session 6cafd2ac-dd19-d991-291a-8d565940996d\n")


def run_redact(tmp_path, capsys, text=NOTE, extra=None):
    src = tmp_path / "note.log"
    src.write_text(text, encoding="utf-8")
    rc = cli.main(["redact", str(src)] + (extra or []))
    return rc, capsys.readouterr().out


def test_redact_runs_tier_two_by_default(tmp_path, capsys):
    rc, out = run_redact(tmp_path, capsys)
    assert rc == 0
    assert "Rachel Mbeki" not in out
    assert "Contoso Group" not in out


def test_redact_still_covers_the_shaped_types(tmp_path, capsys):
    _, out = run_redact(tmp_path, capsys)
    assert "6cafd2ac-dd19-d991-291a-8d565940996d" not in out
    assert "08123456" not in out


def test_redact_and_proxy_build_the_same_tiers():
    names = lambda ts: [t.name for t in ts]
    assert names(cli._build_tiers("classifier")) == ["tier1", "tier2"]
    assert names(cli._build_tiers("none")) == ["tier1"]


def test_turning_tier_two_off_is_possible_but_says_so(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    cli.main(["redact", str(src), "--tier2", "none"])
    captured = capsys.readouterr()
    assert "Rachel Mbeki" in captured.out
    assert "tier 2 disabled" in captured.err


def test_the_decision_log_records_no_original_values(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    log = tmp_path / "decisions.jsonl"
    cli.main(["redact", str(src), "--log", str(log)])
    body = log.read_text()
    assert body.strip()
    for secret in ("Rachel Mbeki", "Contoso Group", "6cafd2ac-dd19-d991-291a-8d565940996d"):
        assert secret not in body


def test_a_saved_vault_round_trips_the_answer(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    vault_path = tmp_path / "vault.json"
    cli.main(["redact", str(src), "--vault", str(vault_path)])
    from hider import pseudonym
    v = pseudonym.EntityVault.load(vault_path)
    assert "Rachel Mbeki" in v.detokenize("<Person-01> asked for an update")


def test_a_bad_index_refusal_is_logged_and_printed_as_shapes(tmp_path, capsys):
    """A page whose hits come from indices outside the allowlist is refused
    bad_index as always. The decision-log row carries each refused name as
    a shape with its hit count, es-smoke prints one line a person can read,
    and the refusal itself - what a client receives - is code and message
    only. No letter of any invented name reaches the row or the line."""
    import json as _json

    from hider import elastic, esbridge

    cfg = elastic.parse({**_json.loads(elastic.EXAMPLE.read_text()),
                         "clusters": {"stub": "https://stub.example.net"}}, source="t")
    foreign = ["partial-.ds-tempestite-default-2026.08.20-000042",
               "partial-.ds-tempestite-default-2026.08.20-000042",
               ".fs-quokkastream-default-2026.08.19-000007"]
    hits = [{"_index": name, "_id": f"h{i}", "_score": None,
             "_source": {"message": "filler"}} for i, name in enumerate(foreign)]

    class _Session:
        def probe(self, cluster):
            return None

        def search(self, cluster, body, deadline_s=None):
            return {"id": "x", "isPartial": False, "isRunning": False,
                    "rawResponse": {"took": 1, "timed_out": False,
                                    "hits": {"total": {"value": 3, "relation": "eq"},
                                             "max_score": None, "hits": hits}}}

    log_path = tmp_path / "decisions.jsonl"
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), _Session(),
                        log_path=log_path)
    q = {"index": cfg.indices[0], "time_range": {"gte": "now-6h", "lte": "now"}, "size": 3}
    report = esbridge.run_case(b, "stub", q)
    rc = esbridge.print_smoke("stub", q, report)
    out = capsys.readouterr().out
    assert rc == 2 and report["refused"]["code"] == "bad_index"
    assert report["refused"]["message"] == ("response withheld: a hit came from an index "
                                            "outside the allowlist")
    assert "INDICES  partial-.ds-L-L-9.9.9-9=2, .fs-L-L-9.9.9-9=1" in out
    row = _json.loads(log_path.read_text().splitlines()[-1])
    assert row["refused"] == "bad_index"
    assert row["index_shapes"] == [
        {"index_shape": "partial-.ds-L-L-9.9.9-9", "hits": 2},
        {"index_shape": ".fs-L-L-9.9.9-9", "hits": 1}]
    for word in ("tempestite", "quokkastream"):
        assert word not in out and word not in _json.dumps(row)


def test_es_smoke_waits_out_the_longest_group_read(monkeypatch, capsys):
    """Before: es-smoke waited poll_timeout + 120 - 420 s at the measured
    300 s site - and said the bridge did not answer while it was still
    mid-read (the first week read ran 835 s before the probe deadlines).
    After: the wait is sized to outlive the worst read by construction -
    the read budget plus one in-flight pass, plus the old margin."""
    from hider import elastic, esbridge, eseval

    cfg = elastic.load(elastic.EXAMPLE)
    # the before, pinned as arithmetic: the old wait lost to the read
    old_wait = eseval.MEASURED_SEARCH_LIMIT_S + 120
    assert old_wait == 420 < 835
    # the after: the wait covers the longest read a query can run
    worst_read = (elastic.TEXT_GROUP_READ_BUDGET_LIMITS + 1) * cfg.poll_timeout_s
    assert esbridge.search_wait_s(cfg) == worst_read + 120 > cfg.poll_timeout_s + 120

    captured: list[float] = []
    real = esbridge.BrokerClient

    class Capturing(real):
        def __init__(self, path, *, timeout):
            captured.append(timeout)
            super().__init__(path, timeout=timeout)

        def call(self, op, **fields):
            raise elastic.Refused("session_expired", "no bridge (test)")

    monkeypatch.setattr(esbridge, "BrokerClient", Capturing)
    rc = cli.main(["es-smoke", "--config", str(elastic.EXAMPLE), "--cluster", "emea"])
    out = capsys.readouterr().out
    assert rc != 0 and "session_expired" in out
    # the es-smoke client was built with the sized wait, not the old formula
    assert esbridge.search_wait_s(cfg) in captured


# ---------------------------------------------------------------------------
# redact sweeps a value found once across the whole file
# ---------------------------------------------------------------------------

def _redact_file(tmp_path, capsys, text, extra=None):
    import json as _json

    src = tmp_path / "bundle.md"
    src.write_text(text, encoding="utf-8")
    log = tmp_path / "decisions.jsonl"
    vault_path = tmp_path / "vault.json"
    rc = cli.main(["redact", str(src), "--log", str(log), "--vault", str(vault_path)]
                  + (extra or []))
    out = capsys.readouterr().out
    events = [_json.loads(r) for r in log.read_text().splitlines() if r.strip()]
    return rc, out, events, vault_path


def test_redact_hides_a_value_on_the_line_where_it_stands_without_its_cue(tmp_path, capsys):
    """Tier 1 reads a case number only after the word "case". The table row
    below has the number and no cue; the per-line pass left it readable."""
    text = ("Escalated case 08123456 to the night desk\n"
            "| 08123456 | open | 2 |\n"
            "no number on this line\n")
    rc, out, events, _ = _redact_file(tmp_path, capsys, text, ["--tier2", "none"])
    lines = out.splitlines()
    assert rc == 0 and len(lines) == 3
    assert "08123456" not in out
    label = lines[0].split("case ")[1].split(" ")[0]
    assert label.startswith("<") and lines[1] == f"| {label} | open | 2 |"
    assert lines[2] == "no number on this line"
    swept = [e for e in events if e["tier"] == "sweep"]
    assert [(e["line"], e["entity_type"], e["action"]) for e in swept] == [
        (1, "SUPPORT_CASE_NUMBER", "pseudonymised")]
    assert swept[0]["replacement"] == label


def test_redact_sweeps_a_value_inside_a_link_and_inside_backticks(tmp_path, capsys):
    text = ("Escalated case 08123456 to the night desk\n"
            "see [ticket](https://portal.example.test/t/08123456?x=1) and `08123456`\n"
            "**08123456**, then 08123456.\n")
    _, out, events, _ = _redact_file(tmp_path, capsys, text, ["--tier2", "none"])
    assert "08123456" not in out
    label = out.splitlines()[0].split("case ")[1].split(" ")[0]
    assert f"/t/{label}?x=1) and `{label}`" in out
    assert f"**{label}**, then {label}." in out
    assert sum(e["tier"] == "sweep" for e in events) == 4


def test_redact_sweep_never_touches_a_secret(tmp_path, capsys):
    secret = "Zq7mXp2LrT9nV4kS"
    text = f"password: {secret}\nthe value {secret} again\n"
    _, out, events, vault_path = _redact_file(tmp_path, capsys, text, ["--tier2", "none"])
    assert out.splitlines()[0] == "password: <REDACTED:API_KEY>"
    assert [e["action"] for e in events if e["tier"] != "sweep"] == ["destroyed"]
    assert not [e for e in events if e["tier"] == "sweep"]
    assert secret not in vault_path.read_text() and secret not in str(events)


def test_redact_sweep_switch_limits_the_sweep_to_values_tier_one_found(tmp_path, capsys):
    """Tier 2 hides the name where it is written in full and misses the
    upper-cased cell; tier 1 hides the case number only after its cue."""
    text = ("Rachel Mbeki at Contoso Group escalated case 08123456 today\n"
            "| RACHEL MBEKI | CONTOSO GROUP | 08123456 |\n")

    _, out, events, _ = _redact_file(tmp_path, capsys, text)  # default: all
    assert "RACHEL" not in out and "CONTOSO" not in out and "08123456" not in out
    assert sorted(e["entity_type"] for e in events if e["tier"] == "sweep") == [
        "ORG_NAME", "PERSON_NAME", "SUPPORT_CASE_NUMBER"]

    tmp2 = tmp_path / "t1"
    tmp2.mkdir()
    _, out, events, _ = _redact_file(tmp2, capsys, text,
                                     ["--sweep", "tier1", "--name-parts", "off"])
    second = out.splitlines()[1]
    assert "08123456" not in second          # found by tier 1: swept
    assert "RACHEL MBEKI" in second and "CONTOSO GROUP" in second  # tier 2 only: left
    assert [e["entity_type"] for e in events if e["tier"] == "sweep"] == ["SUPPORT_CASE_NUMBER"]

    tmp3 = tmp_path / "off"
    tmp3.mkdir()
    _, out, events, _ = _redact_file(tmp3, capsys, text, ["--sweep", "off"])
    assert "08123456" in out.splitlines()[1]
    assert not [e for e in events if e["tier"] == "sweep"]


def test_redact_and_the_gateway_sweep_with_one_function(tmp_path):
    from hider import proxy, pseudonym, sweep

    vault = pseudonym.EntityVault(key=b"k")
    vault.pseudonym("PERSON_NAME", "Diego Ferreira")
    vault.pseudonym("SUPPORT_CASE_NUMBER", "08123456")
    gw = proxy.RedactionGateway("http://127.0.0.1:1",
                                pipeline.Pipeline([pipeline.RegexTier()], vault=vault))
    text = "ask Diego Ferreira about 08123456, DIEGO FERREIRA too"
    assert gw.sweep(text, unit="u") == sweep.sweep(vault, text, unit="u")
    assert gw._known_values_in(text) == sweep.known_values_in(vault, text)


# ---------------------------------------------------------------------------
# redact --term: a name a person gives, hidden whatever its length or casing
# ---------------------------------------------------------------------------

def _term_events(events):
    return [e for e in events if e["tier"] == "term"]


def test_redact_term_is_hidden_in_a_sentence_a_table_cell_and_a_link(tmp_path, capsys):
    text = ("HarborRidge asked for a call back tonight\n"
            "| HarborRidge | open | 2 |\n"
            "see [portal](https://harborridge.example.test/t/1)\n")
    rc, out, events, _ = _redact_file(tmp_path, capsys, text, ["--term", "HarborRidge"])
    assert rc == 0 and len(out.splitlines()) == 3
    assert "harborridge" not in out.lower()
    term = _term_events(events)
    assert [e["line"] for e in term] == [0, 1, 2]
    label = term[0]["replacement"]
    assert label.startswith("<") and label.endswith(">")
    # the per-line pass that runs after the term left every label as it was
    assert out.count(label) == 3 and "<<" not in out
    assert out.splitlines()[1] == f"| {label} | open | 2 |"
    assert f"[portal](https://{label}.example.test/t/1)" in out


def test_redact_term_matches_in_any_casing(tmp_path, capsys):
    text = "HarborRidge, harborridge and HARBORRIDGE all rang\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text,
                                     ["--term", "HarborRidge", "--tier2", "none"])
    label = _term_events(events)[0]["replacement"]
    assert out == f"{label}, {label} and {label} all rang\n"
    assert len(_term_events(events)) == 3


def test_redact_term_of_three_letters_is_hidden(tmp_path, capsys):
    text = "HRX opened a ticket, then hrx closed it\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text,
                                     ["--term", "HRX", "--tier2", "none"])
    label = _term_events(events)[0]["replacement"]
    assert out == f"{label} opened a ticket, then {label} closed it\n"


def test_redact_term_is_not_matched_inside_a_longer_word(tmp_path, capsys):
    text = "HRXtra xhrx hrx2 2hrx and HRX.\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text,
                                     ["--term", "HRX", "--tier2", "none", "--sweep", "off"])
    term = _term_events(events)
    # a letter or digit directly before or after keeps the word as it was
    assert len(term) == 1
    label = term[0]["replacement"]
    assert out == f"HRXtra xhrx hrx2 2hrx and {label}.\n"


def test_redact_term_that_contains_another_term_wins_whatever_the_order(tmp_path, capsys):
    text = "Harbor Ridge Marine wrote, and Harbor Ridge phoned\n"
    for n, order in enumerate((["Harbor Ridge", "Harbor Ridge Marine"],
                               ["Harbor Ridge Marine", "Harbor Ridge"])):
        sub = tmp_path / f"o{n}"
        sub.mkdir()
        extra = ["--tier2", "none"]
        for t in order:
            extra += ["--term", t]
        _, out, events, _ = _redact_file(sub, capsys, text, extra)
        term = _term_events(events)
        assert len(term) == 2
        long_label, short_label = term[0]["replacement"], term[1]["replacement"]
        assert long_label != short_label
        assert (term[0]["start"], term[0]["end"]) == (0, len("Harbor Ridge Marine"))
        assert out == f"{long_label} wrote, and {short_label} phoned\n"
        assert "Marine" not in out


def test_redact_term_is_hidden_with_the_sweep_and_tier_two_switched_off(tmp_path, capsys):
    text = "Contoso Group sent a note about HRX\n"
    _, out, events, _ = _redact_file(
        tmp_path, capsys, text,
        ["--term", "Contoso Group", "--term", "HRX", "--tier2", "none", "--sweep", "off"])
    assert "Contoso" not in out and "HRX" not in out
    assert [e["tier"] for e in events] == ["term", "term"]
    assert all(e["entity_type"] == "ORG_NAME" for e in events)


def test_redact_term_decision_log_holds_the_tier_and_the_label_and_not_the_term(
        tmp_path, capsys):
    text = "Contoso Group and HarborRidge, then contoso group again\n"
    _, out, events, _ = _redact_file(
        tmp_path, capsys, text,
        ["--term", "Contoso Group", "--term", "HarborRidge", "--tier2", "none"])
    log_text = (tmp_path / "decisions.jsonl").read_text()
    assert "contoso" not in log_text.lower() and "harborridge" not in log_text.lower()
    term = _term_events(events)
    assert len(term) == 3
    sweep_keys = {"schema", "unit", "line", "start", "end", "entity_type", "action",
                  "tier", "score", "marker", "replacement"}
    for e in term:
        assert set(e) == sweep_keys
        assert e["entity_type"] == "ORG_NAME" and e["action"] == "pseudonymised"
        assert e["marker"] == e["replacement"] and e["replacement"] in out
    # one label for one term, however it was written
    assert term[0]["replacement"] == term[2]["replacement"] != term[1]["replacement"]


@pytest.mark.parametrize("term", ["", "   "])
def test_redact_with_an_empty_term_is_refused_with_exit_code_2(tmp_path, capsys, term):
    src = tmp_path / "note.log"
    src.write_text("Contoso Group wrote\n", encoding="utf-8")
    rc = cli.main(["redact", str(src), "--term", "HRX", "--term", term])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert "--term" in captured.err and "empty" in captured.err


# Invented lines where the name stands inside a shape tier 1 reads. Replacing
# the name before tier 1 ran broke each of these shapes.
_TERM_SHAPES = (
    "mail from anna.novak@contoso.com about the backup\n"
    "login CONTOSO\\anna.novak failed twice\n"
    "site https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/plan.docx\n"
    "tenant contoso.onmicrosoft.com was throttled\n"
    "share \\\\contoso-fs01\\finance\\q3 is offline\n"
    "host contoso-fs01.corp.contoso.com timed out\n"
    "Contoso Group asked for a call, cc anna.novak@contoso.com\n"
    "file C:\\Users\\anna.novak\\Documents\\Contoso\\plan.docx was locked\n"
    "see https://graph.microsoft.com/v1.0/sites/contoso/drives for the list\n"
)


@pytest.mark.parametrize("tier2", ["none", "classifier"])
def test_redact_term_takes_nothing_from_tier_one_and_leaves_no_term_readable(
        tmp_path, capsys, tier2):
    plain_dir, term_dir = tmp_path / "plain", tmp_path / "terms"
    plain_dir.mkdir()
    term_dir.mkdir()
    _, _, plain_events, _ = _redact_file(plain_dir, capsys, _TERM_SHAPES, ["--tier2", tier2])
    _, out, events, _ = _redact_file(
        term_dir, capsys, _TERM_SHAPES,
        ["--tier2", tier2, "--term", "Contoso", "--term", "Contoso Group"])

    def tier_one(evs):
        return {(e["line"], e["start"], e["end"], e["entity_type"])
                for e in evs if e["tier"] == "tier1"}

    # every span tier 1 found without a term it finds with one
    assert tier_one(plain_events) and tier_one(plain_events) <= tier_one(events)
    # no term is readable, in any casing
    assert "contoso" not in out.lower() and "contoso group" not in out.lower()
    # and what stood around the name inside a shape is still hidden
    for word in ("anna.novak", "Finance", "finance", "q3", "fs01"):
        assert word not in out
    assert "<<" not in out


def test_redact_term_inside_a_label_is_replaced_only_where_the_label_kept_it(tmp_path, capsys):
    import re as _re

    text = ("file C:\\Users\\anna.novak\\Documents\\Contoso\\plan.docx was locked\n"
            "tenant contoso.onmicrosoft.com was throttled, Org and user notified\n")
    _, out, _events, _ = _redact_file(
        tmp_path, capsys, text,
        ["--tier2", "none", "--term", "Contoso", "--term", "Org",
         "--term", "tenant", "--term", "user"])
    first, second = out.splitlines()
    # the profile path's label kept the folder name from the original: replaced.
    # "user" stands in that label too, but not in the original: left alone.
    assert _re.fullmatch(
        r"file C:\\Users\\user-01\\Documents\\<Org-\d+>\\plan\.docx was locked", first)
    # "tenant" and "Org" inside labels are left, in prose they are replaced
    assert _re.fullmatch(
        r"<Org-\d+> tenant-01\.onmicrosoft\.example was throttled, "
        r"<Org-\d+> and <Org-\d+> notified", second)
    assert "<<" not in out


def test_redact_term_half_inside_a_tier_one_span_hides_the_piece_tier_one_left(tmp_path, capsys):
    text = "ops@contoso.com Harbor desk called\nthe Harbor office is closed\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text,
                                     ["--tier2", "none", "--term", "com Harbor"])
    term = _term_events(events)
    assert len(term) == 1
    label = term[0]["replacement"]
    first, second = out.splitlines()
    assert "Harbor" not in out and "contoso" not in out.lower()
    assert first.endswith(f" {label} desk called")
    # the piece is a value of its own, so the default sweep hides it elsewhere
    assert second == f"the {label} office is closed"



# ---------------------------------------------------------------------------
# redact --name-parts: a part of a multi-word person name that stands alone
# ---------------------------------------------------------------------------

def _name_part_events(events):
    return [e for e in events if e["tier"] == "name_part"]


def test_redact_hides_a_surname_alone_after_the_full_name_was_found_on_another_line(
        tmp_path, capsys):
    text = ("Escalated by Anna Novak to the night desk\n"
            "Novak confirmed the restore finished\n")
    rc, out, events, _ = _redact_file(tmp_path, capsys, text)
    first, second = out.splitlines()
    assert rc == 0 and first.startswith("Escalated by <Person-")
    assert "Novak" not in out
    parts = _name_part_events(events)
    assert [(e["line"], e["entity_type"]) for e in parts] == [(1, "PERSON_NAME")]
    assert second == f"{parts[0]['replacement']} confirmed the restore finished"


def test_redact_hides_a_first_name_alone(tmp_path, capsys):
    text = ("Escalated by Lena Moreau to the night desk\n"
            "Lena asked for a call back tonight\n")
    _, out, events, _ = _redact_file(tmp_path, capsys, text)
    assert "Lena" not in out and "Moreau" not in out
    assert [e["line"] for e in _name_part_events(events)] == [1]


def test_redact_leaves_a_part_shorter_than_four_letters(tmp_path, capsys):
    text = "Escalated by Anna Fox to the night desk\nFox confirmed, Anna did not\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text)
    assert out.splitlines()[1].startswith("Fox confirmed, <Person-")
    assert len(_name_part_events(events)) == 1


def test_redact_leaves_a_part_that_is_an_ordinary_word(tmp_path, capsys):
    text = "Escalated by Ivan Archive to the night desk\nthe Archive was restored, Ivan too\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text)
    assert out.splitlines()[1].startswith("the Archive was restored, <Person-")
    assert len(_name_part_events(events)) == 1


def test_redact_leaves_a_part_inside_a_label_and_gives_the_part_its_own_label(
        tmp_path, capsys):
    text = "Escalated by Marta Person to the night desk\nPerson confirmed it\n"
    _, out, events, _ = _redact_file(tmp_path, capsys, text)
    first, second = out.splitlines()
    full = first.removeprefix("Escalated by ").split(" ")[0]
    part = _name_part_events(events)[0]["replacement"]
    assert "<<" not in out
    assert full.startswith("<Person-") and part.startswith("<Person-") and part != full
    assert second == f"{part} confirmed it"


def test_redact_name_parts_off_leaves_the_part_readable(tmp_path, capsys):
    text = ("Escalated by Anna Novak to the night desk\n"
            "Novak confirmed the restore finished\n")
    _, out, events, _ = _redact_file(tmp_path, capsys, text, ["--name-parts", "off"])
    assert out.splitlines()[1] == "Novak confirmed the restore finished"
    assert _name_part_events(events) == []


def test_redact_name_parts_loses_nothing_tier_one_found(tmp_path, capsys):
    text = ("mail from anna.novak@contoso.com about the backup\n"
            "Escalated by Anna Novak to the night desk\n"
            "login CONTOSO\\anna.novak failed twice\n"
            "Novak confirmed the restore, Anna agreed\n"
            "| Novak | open |\n"
            "file C:\\Users\\anna.novak\\Documents\\plan.docx was locked\n")
    off_dir, on_dir = tmp_path / "off", tmp_path / "on"
    off_dir.mkdir()
    on_dir.mkdir()
    _, _, off_events, _ = _redact_file(off_dir, capsys, text, ["--name-parts", "off"])
    _, out, on_events, _ = _redact_file(on_dir, capsys, text)

    def tier_one(evs):
        return {(e["line"], e["start"], e["end"], e["entity_type"])
                for e in evs if e["tier"] == "tier1"}

    assert tier_one(off_events) and tier_one(off_events) <= tier_one(on_events)
    assert _name_part_events(on_events) and not _name_part_events(off_events)
    assert "<<" not in out


def test_redact_leaves_a_part_the_file_also_writes_in_lowercase(tmp_path, capsys):
    """A word the note itself writes in lowercase is an ordinary word there.
    `--name-parts all` is the pass without that rule."""
    text = ("Escalated by Anna Novak to the night desk\n"
            "Novak confirmed the restore finished\n"
            "see the novak share for the files\n")
    on_dir, all_dir = tmp_path / "on", tmp_path / "all"
    on_dir.mkdir()
    all_dir.mkdir()
    _, out, events, _ = _redact_file(on_dir, capsys, text)
    assert out.splitlines()[1] == "Novak confirmed the restore finished"
    assert _name_part_events(events) == []
    _, out_all, events_all, _ = _redact_file(all_dir, capsys, text, ["--name-parts", "all"])
    assert "Novak" not in out_all
    assert [e["line"] for e in _name_part_events(events_all)] == [1]


def test_redact_counts_no_lowercase_form_inside_a_hidden_address(tmp_path, capsys):
    """The name in lowercase inside an address tier 1 hid is not prose: the
    parts are still hidden where they stand alone."""
    text = ("mail from anna.novak@contoso.com about the backup\n"
            "Escalated by Anna Novak to the night desk\n"
            "Novak confirmed the restore, Anna agreed\n")
    _, out, events, _ = _redact_file(tmp_path, capsys, text)
    assert "Novak" not in out and "Anna" not in out and "anna.novak" not in out
    assert [e["line"] for e in _name_part_events(events)] == [2, 2]
