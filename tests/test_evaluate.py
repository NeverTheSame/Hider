"""End-to-end gates.

These are the numbers the project is allowed to claim. They run on a small
corpus so the suite stays fast; ``python -m hider eval`` runs the full one and
exits non-zero on the same conditions.
"""

from __future__ import annotations

import json

import pytest

from hider import entities, evaluate, generator, ner, pipeline, pseudonym, report

LINES = 900
SEED = 20260820

HAS_NER = ner.available()


@pytest.fixture(scope="module")
def scored():
    full, base, redacted, corpus = evaluate.run_with_baseline(
        lines=LINES, seed=SEED, include_ner=HAS_NER
    )
    return full, base, redacted, corpus


def test_no_seeded_value_survives_unexplained(scored):
    """The hard gate. Every survivor must be attributable to a named gap."""
    full = scored[0]
    assert full.unexpected_survivors == []


def test_recall_on_shaped_types(scored):
    full = scored[0]
    assert full.shaped_recall >= 0.99, full.shaped_recall


def test_no_over_redaction_on_clean_lines(scored):
    full = scored[0]
    assert full.clean_lines >= 100
    assert full.clean_lines_with_redaction == 0


def test_custom_recognizers_beat_the_stock_baseline(scored):
    full, base = scored[0], scored[1]
    assert full.shaped_recall > base.shaped_recall + 0.5


def test_no_adversarial_surprises(scored):
    full = scored[0]
    assert [c.case_id for c in full.surprises] == []


def test_tiering_actually_reduces_the_paid_surface(scored):
    full = scored[0]
    assert 0 < full.residue_chars < full.chars
    assert full.cost_reduction > 0.25


@pytest.mark.skipif(not HAS_NER, reason="spaCy model not installed")
def test_freetext_recall_meets_the_floor(scored):
    """Tier 2 is a model: gated at a floor, not at zero, and never hidden."""
    full = scored[0]
    assert full.ner_enabled is True
    assert full.freetext_recall >= evaluate.FREETEXT_RECALL_FLOOR, (
        full.freetext_recall,
        [(s["entity_type"], s["reason"]) for s in full.verbatim_survivors],
    )
    # Honest ceiling, not a marketing number: a small local model does not
    # catch every name, and the report must say so rather than round it away.
    assert full.freetext_recall < 1.0


@pytest.mark.skipif(not HAS_NER, reason="spaCy model not installed")
def test_freetext_misses_are_labelled_as_probabilistic_not_hidden(scored):
    full = scored[0]
    misses = [s for s in full.verbatim_survivors
              if s["reason"] == "tier2 miss (probabilistic tier)"]
    assert misses, "recall below 1.0 must be visible in the survivor list"
    assert all(s["expected_tier"] == entities.TIER_FREETEXT for s in misses)


def test_tier1_only_run_reports_freetext_as_a_phase_boundary():
    """Without tier 2, free-text survivors are owned gaps, not silent passes."""
    full, _ = evaluate.run(lines=200, seed=SEED, include_ner=False,
                           include_adversarial=False)
    assert full.ner_enabled is False
    assert full.freetext_recall == 0.0
    assert not full.below_freetext_floor  # no floor claim without the tier
    survivors = [s for s in full.verbatim_survivors
                 if s["entity_type"] in ("PERSON_NAME", "ORG_NAME")]
    assert survivors
    assert all(s["reason"] == "tier not built yet" for s in survivors)


def test_include_ner_raises_rather_than_silently_skipping(monkeypatch):
    monkeypatch.setattr(ner, "available", lambda: False)
    with pytest.raises(RuntimeError, match="spaCy model"):
        evaluate.run_with_baseline(lines=10, include_ner=True)


def test_injection_bypass_rate_is_not_claimed(scored):
    full = scored[0]
    assert full.to_dict()["adversarial"]["injection_bypass_rate"] is None
    assert full.injection_canaries > 0


def test_nothing_is_reported_as_degraded_on_a_clean_run(scored):
    assert scored[0].degraded_units == 0


def test_report_html_is_self_contained(scored):
    full, base, _, corpus = scored
    pipe = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    rows = report.excerpt_from(corpus, pipe, n=6)
    html = report.build(full, base, rows)
    assert "<title>" in html and "</style>" in html
    for forbidden in ("http://", "src=", "<script", "cdn", "fonts.googleapis"):
        assert forbidden not in html.replace("https://tenant-", "")


def test_report_shows_the_before_and_after(scored):
    full, base, _, corpus = scored
    pipe = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    rows = report.excerpt_from(corpus, pipe, n=6)
    html = report.build(full, base, rows)
    assert "Raw, straight to the provider" in html
    assert "Through Hider" in html
    # A raw value shown on the left must not be findable in the redacted pane.
    raw, redacted, spans, _ = rows[0]
    for s in spans:
        assert raw[s.start:s.end] not in redacted


def test_metrics_json_round_trips(scored, tmp_path):
    full = scored[0]
    path = tmp_path / "metrics.json"
    evaluate.save(full, path)
    d = json.loads(path.read_text())
    assert d["recall_shaped_types"] == round(full.shaped_recall, 4)
    assert d["ner_enabled"] is full.ner_enabled
    assert d["freetext_recall_floor"] == evaluate.FREETEXT_RECALL_FLOOR
    assert d["types"]["POD_ID"]["seeded"] > 0
