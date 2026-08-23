"""The generator's ground truth has to be exact, or every metric is fiction."""

from __future__ import annotations

import re

from hider import adversarial, entities, generator, markup


def test_ground_truth_offsets_point_at_the_recorded_value():
    corpus = generator.generate(lines=600, seed=99)
    assert corpus.truth
    for occ in corpus.truth:
        line = corpus.unit(occ.unit).lines[occ.line_no]
        assert line[occ.start:occ.end] == occ.value, f"offset drift in {occ.unit}:{occ.line_no}"


def test_no_marker_survives_into_the_corpus():
    """A typo in a template must fail loudly, not leak a literal marker."""
    corpus = generator.generate(lines=600, seed=99)
    for unit in corpus.units:
        for line in unit.lines:
            assert "<<" not in line and ">>" not in line, line


def test_no_unfilled_placeholder_survives():
    corpus = generator.generate(lines=600, seed=99)
    leftover = re.compile(r"\{(TS|TSZ|PID|LEVEL|MS|N|ITEMS|MB|PCT|HTTP|JOBNAME)\}")
    for unit in corpus.units:
        for line in unit.lines:
            assert not leftover.search(line), line


def test_clean_unit_holds_no_seeded_values():
    corpus = generator.generate(lines=400, seed=5)
    assert corpus.clean_units
    seeded_units = {o.unit for o in corpus.truth}
    assert not (corpus.clean_units & seeded_units)


def test_every_spec_type_is_exercised_by_the_templates():
    """A type nobody generates is a type nobody measures."""
    corpus = generator.generate(lines=3000, seed=11)
    seen = {o.entity_type for o in corpus.truth}
    missing = {s.name for s in entities.SPECS} - seen
    assert not missing, f"never generated: {sorted(missing)}"


def test_generation_is_reproducible():
    a = generator.generate(lines=200, seed=42)
    b = generator.generate(lines=200, seed=42)
    assert [u.text for u in a.units] == [u.text for u in b.units]


def test_a_different_seed_gives_different_data():
    a = generator.generate(lines=200, seed=1)
    b = generator.generate(lines=200, seed=2)
    assert [u.text for u in a.units] != [u.text for u in b.units]


def test_markup_records_offsets_for_a_hand_written_line():
    text, found = markup.render("pod <<POD_ID|wkr-amer-prx117>> ok", __import__("random").Random(1))
    assert text == "pod wkr-amer-prx117 ok"
    assert len(found) == 1
    assert text[found[0].start:found[0].end] == "wkr-amer-prx117"


def test_adversarial_offsets_are_exact():
    lines, truth, _ = adversarial.build(seed=3)
    for occ in truth:
        assert lines[occ.line_no][occ.start:occ.end] == occ.value


def test_adversarial_gaps_carry_an_owner():
    """A documented gap without a written reason is just an excuse."""
    for case in adversarial.CASES:
        if not case.expect_tier1:
            assert case.owner.strip(), case.case_id


def test_injection_canaries_carry_no_sensitive_value():
    for payload in adversarial.INJECTION_CANARIES:
        assert "<<" not in payload
