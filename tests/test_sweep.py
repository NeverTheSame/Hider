"""The shared known-value sweep (hider/sweep.py), with invented names."""

from __future__ import annotations

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
