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
