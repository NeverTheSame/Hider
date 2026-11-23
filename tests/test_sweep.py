"""The shared known-value sweep (hider/sweep.py), with invented names."""

from __future__ import annotations

import pytest

from hider import pseudonym, sweep


def _vault() -> tuple[pseudonym.EntityVault, str, str]:
    """A person, and an ordinary word tier 2 took for an organisation: the
    word is also the type word inside the person's own label."""
    vault = pseudonym.EntityVault()
    person = vault.pseudonym("PERSON_NAME", "Lena Moreau")
    org = vault.pseudonym("ORG_NAME", "Person")
    assert (person, org) == ("<Person-01>", "<Org-01>")
    return vault, person, org


def test_a_label_already_in_the_text_is_never_swept_into():
    """Before: the vaulted word was replaced inside the label as well, and
    ``<Person-01>`` came out as ``<<Org-01>-01>`` - a label destroyed and
    nothing hidden. The word on its own is still swept."""
    vault, person, org = _vault()
    text = f"{person} opened the ticket; Person records were missing"
    out, events = sweep.sweep(vault, text)
    assert out == f"{person} opened the ticket; {org} records were missing"
    assert len(events) == 1 and events[0]["replacement"] == org
    assert text[events[0]["start"]:events[0]["end"]] == "Person"
    assert "<<" not in out


def test_the_leftover_check_skips_the_same_labels():
    """What the sweep skips the leftover check skips, or a label would be
    what refuses a request: after a sweep nothing is left over."""
    vault, person, _org = _vault()
    assert sweep.known_values_in(vault, f"{person} replied") == []
    out, _ = sweep.sweep(vault, f"{person} opened the ticket; Person records")
    assert sweep.known_values_in(vault, out) == []
    assert sweep.known_values_in(vault, "Person records") == ["Person"]


def test_a_destroyed_secret_marker_and_a_shaped_label_are_protected_too():
    vault = pseudonym.EntityVault()
    host = vault.pseudonym("HOSTNAME_FQDN", "ctr-amer-042.contoso.com")
    assert host.startswith("node-")  # a label that is not in angle brackets
    vault.pseudonym("ORG_NAME", "Key")
    vault.pseudonym("ORG_NAME", "node")
    text = f"<REDACTED:API_KEY> rotated on {host}; the KEY is new, node count is 3"
    out, events = sweep.sweep(vault, text)
    assert out.startswith(f"<REDACTED:API_KEY> rotated on {host};")
    assert [text[e["start"]:e["end"]] for e in events] == ["KEY", "node"]


def test_one_sweeper_for_many_lines_gives_what_a_sweep_per_line_gives():
    """``redact`` compiles the pattern once for a whole file; the gateway
    builds it per call. Same replacements, same events, and the ``labels``
    limit still decides what is swept."""
    vault, person, org = _vault()
    case = vault.pseudonym("SUPPORT_CASE_NUMBER", "08123456")
    lines = ["case 08123456 was reopened", f"{person} said Person records are gone",
             "| 08123456 | Person |", "nothing here"]
    one = sweep.Sweeper(vault)
    assert [one.sweep(t, line=i) for i, t in enumerate(lines)] == \
           [sweep.sweep(vault, t, line=i) for i, t in enumerate(lines)]
    only_case = sweep.Sweeper(vault, {case})
    out, events = only_case.sweep(lines[2], line=2)
    assert out == f"| {case} | Person |" and len(events) == 1 and events[0]["line"] == 2
    assert sweep.Sweeper(pseudonym.EntityVault()).sweep("anything") == ("anything", [])


# ---------------------------------------------------------------------------
# NamePartReplacer: a part of a multi-word person name that stands alone
# ---------------------------------------------------------------------------

def _person(name: str) -> tuple[pseudonym.EntityVault, str]:
    vault = pseudonym.EntityVault()
    return vault, vault.pseudonym("PERSON_NAME", name)


def test_a_surname_standing_alone_is_hidden_after_the_full_name_was_found_elsewhere():
    vault, full = _person("Anna Novak")
    text = "Novak confirmed the restore, Novak's mailbox is back, NOVAK again"
    out, events = sweep.NamePartReplacer(vault).replace(text, unit="u", line=3)
    assert "novak" not in out.casefold()
    assert len(events) == 3 and {e["line"] for e in events} == {3}
    assert all(e["tier"] == "name_part" and e["entity_type"] == "PERSON_NAME"
               and e["action"] == "pseudonymised" for e in events)
    assert all(text[e["start"]:e["end"]].casefold() == "novak" for e in events)


def test_a_first_name_standing_alone_is_hidden():
    vault, _ = _person("Lena Moreau")
    out, events = sweep.NamePartReplacer(vault).replace("Lena asked for a call")
    assert out.startswith("<Person-") and out.endswith("> asked for a call")
    assert len(events) == 1


def test_a_part_shorter_than_four_letters_is_left_alone():
    vault, _ = _person("Anna Fox")
    out, events = sweep.NamePartReplacer(vault).replace("Fox confirmed, Anna did not")
    assert out.startswith("Fox confirmed, <Person-") and len(events) == 1


def test_a_part_that_is_an_ordinary_word_is_left_alone():
    vault, _ = _person("Ivan Archive")
    out, events = sweep.NamePartReplacer(vault).replace("the Archive was restored, Ivan too")
    assert out.startswith("the Archive was restored, <Person-") and len(events) == 1


def test_a_part_inside_a_label_is_left_alone_and_a_longer_word_is_not_a_part():
    vault, full = _person("Marta Person")
    assert full == "<Person-01>"
    text = f"{full} wrote; Person confirmed; Personnel and Persons stayed"
    out, events = sweep.NamePartReplacer(vault).replace(text)
    assert len(events) == 1 and events[0]["replacement"] != full
    assert out == (f"{full} wrote; {events[0]['replacement']} confirmed; "
                   f"Personnel and Persons stayed")
    assert "<<" not in out


def test_a_part_gets_a_label_of_its_own_not_the_full_names():
    vault, full = _person("Anna Novak")
    out, events = sweep.NamePartReplacer(vault).replace(f"{full} and Novak and Anna")
    labels = [e["replacement"] for e in events]
    assert len(labels) == 2 and full not in labels and labels[0] != labels[1]
    assert out == f"{full} and {labels[0]} and {labels[1]}"
    for label in labels:
        assert vault.by_label[label] in {"Novak", "Anna"}
        assert next(e for e in vault.entries.values() if e["label"] == label)["type"] == "PERSON_NAME"
    for e in events:
        assert "Novak" not in str(e) and "Anna" not in str(e)


# ---------------------------------------------------------------------------
# NamePartReplacer given the finished text: a word the file writes in lowercase
# ---------------------------------------------------------------------------

def _a_person_and_a_pair_tier_two_took_for_one() -> pseudonym.EntityVault:
    vault = pseudonym.EntityVault()
    vault.pseudonym("PERSON_NAME", "Anna Novak")
    vault.pseudonym("PERSON_NAME", "Pending Rollout")
    return vault


def test_a_part_the_file_also_writes_in_lowercase_is_left_alone():
    """Tier 2 took "Pending Rollout" for a person, and both words were then
    hidden wherever they stood. The file writes them in lowercase too, so
    here they are ordinary words; the real name beside them is still hidden,
    and a word left out never gets a label."""
    lines = ["Pending Rollout for ring two",
             "the rollout is pending until Friday",
             "Rollout notes: Novak confirmed, Pending on Anna"]
    _, before = sweep.NamePartReplacer(
        _a_person_and_a_pair_tier_two_took_for_one()).replace(lines[2])
    assert len(before) == 4

    vault = _a_person_and_a_pair_tier_two_took_for_one()
    out, events = sweep.NamePartReplacer(vault, finished=lines).replace(lines[2])
    assert len(events) == 2 and "Novak" not in out and "Anna" not in out
    assert out.startswith("Rollout notes: <Person-") and ", Pending on <Person-" in out
    assert not {"Pending", "Rollout"} & set(vault.by_label.values())


def test_a_lowercase_form_inside_a_label_is_not_a_twin():
    """The label of a profile path keeps the path's tail. A lowercase word in
    it is not prose, so the surname is still hidden; the same word in a
    sentence does count."""
    vault, _ = _person("Anna Novak")
    path = vault.pseudonym("WINDOWS_USER_PATH", "C:\\Users\\anna.novak\\novak\\plan.docx")
    assert "novak" in path
    lines = [f"file {path} was locked", "Novak confirmed"]
    out, events = sweep.NamePartReplacer(vault, finished=lines).replace(lines[1])
    assert "Novak" not in out and len(events) == 1

    vault, _ = _person("Anna Novak")
    lines = ["see the novak share for the files", "Novak confirmed"]
    assert sweep.NamePartReplacer(vault, finished=lines).replace(lines[1]) == \
           ("Novak confirmed", [])


def test_a_part_the_vault_stored_in_lowercase_has_no_twin_and_is_still_hidden():
    vault, _ = _person("anna novak")
    lines = ["novak confirmed, Novak agreed"]
    out, events = sweep.NamePartReplacer(vault, finished=lines).replace(lines[0])
    assert "novak" not in out.casefold() and len(events) == 2


# ---------------------------------------------------------------------------
# folders: how a PATH_SEGMENT value is swept
# ---------------------------------------------------------------------------

_MODES = ("all", "cased", "ordinary", "off")


def _folders() -> pseudonym.EntityVault:
    vault = pseudonym.EntityVault()
    assert vault.pseudonym("PATH_SEGMENT", "Finance") == "<Folder-01>"
    assert vault.pseudonym("PATH_SEGMENT", "Payroll") == "<Folder-02>"
    return vault


def _swept(vault, mode, line, lines=()):
    return sweep.Sweeper(vault, folders=mode, lines=list(lines)).sweep(line)[0]


def test_folders_all_hides_the_lowercase_word_in_a_sentence():
    assert _swept(_folders(), "all", "the finance report is late") == \
        "the <Folder-01> report is late"


def test_folders_cased_leaves_the_lowercase_word_and_hides_the_capitalised_one():
    vault = _folders()
    assert _swept(vault, "cased", "the finance report is late") == "the finance report is late"
    assert _swept(vault, "cased", "Finance asked, FINANCE too") == "<Folder-01> asked, <Folder-01> too"


def test_folders_ordinary_leaves_a_word_the_file_writes_in_lowercase():
    vault = _folders()
    lines = ["Finance asked for the report", "the finance report is late", "Payroll called"]
    for line in lines[:2]:
        assert _swept(vault, "ordinary", line, lines) == line
    assert _swept(vault, "ordinary", lines[2], lines) == "<Folder-02> called"
    assert _swept(vault, "ordinary", "the payroll run", lines) == "the payroll run"


def test_folders_ordinary_does_not_count_a_lowercase_form_inside_a_label_or_without_lines():
    vault = _folders()
    protected = vault.pseudonym("WINDOWS_USER_PATH", "D:\\Shares\\finance\\old\\plan.docx")
    lines = [f"file {protected} was locked", "Finance asked"]
    assert _swept(vault, "ordinary", lines[1], lines) == "<Folder-01> asked"
    with pytest.raises(ValueError):
        sweep.Sweeper(vault, folders="ordinary")


def test_folders_off_leaves_every_sentence_alone():
    vault = _folders()
    for line in ("the finance report", "Finance asked", "PAYROLL called"):
        assert _swept(vault, "off", line) == line
    assert sweep.Sweeper(vault, folders="off").known_values_in("Finance and payroll") == []


def test_a_person_a_host_and_a_guid_are_swept_the_same_in_all_four_modes():
    vault = _folders()
    vault.pseudonym("PERSON_NAME", "Lena Moreau")
    vault.pseudonym("IPV4", "203.0.113.7")
    vault.pseudonym("SESSION_GUID", "6cafd2ac-dd19-d991-291a-8d565940996d")
    line = ("ask Lena Moreau, LENA MOREAU too, about 203.0.113.7 and "
            "6CAFD2AC-DD19-D991-291A-8D565940996D")
    results = {m: sweep.Sweeper(vault, folders=m, lines=[line]).sweep(line) for m in _MODES}
    assert len({repr(r) for r in results.values()}) == 1
    assert "Moreau" not in results["off"][0] and "203.0.113.7" not in results["off"][0]
    assert len(results["off"][1]) == 4


def test_the_default_is_all_and_a_bad_mode_is_refused():
    vault = _folders()
    line = "the finance report"
    assert sweep.Sweeper(vault).sweep(line) == sweep.Sweeper(vault, folders="all").sweep(line)
    assert sweep.sweep(vault, line) == sweep.Sweeper(vault, folders="all").sweep(line)
    with pytest.raises(ValueError):
        sweep.Sweeper(vault, folders="some")
