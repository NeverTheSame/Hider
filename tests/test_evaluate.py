"""End-to-end gates.

These are the numbers the project is allowed to claim. They run on a small
corpus so the suite stays fast; ``python -m hider eval`` runs the full one and
exits non-zero on the same conditions.
"""

from __future__ import annotations

import json

import pytest

from hider import entities, evaluate, ner, pipeline, pseudonym, report

LINES = 900
SEED = 20260820

#: The default tier 2 backend (a locally trained classifier, hider.classifier)
#: has no external model to install, so it is always available; the spaCy
#: backend is exercised separately where it specifically matters.
HAS_NER = ner.available()


@pytest.fixture(scope="module")
def scored():
    full, base, redacted, corpus = evaluate.run_with_baseline(
        lines=LINES, seed=SEED, tier2="classifier"
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


def test_freetext_recall_meets_the_floor(scored):
    """Tier 2 is a model: gated at a floor, not at zero, and never hidden."""
    full = scored[0]
    assert full.ner_enabled is True
    assert full.tier2_backend == "classifier"
    assert full.freetext_recall >= evaluate.FREETEXT_RECALL_FLOOR, (
        full.freetext_recall,
        [(s["entity_type"], s["reason"]) for s in full.verbatim_survivors],
    )
    # Honest ceiling, not a marketing number: a small local model does not
    # catch every name, and the report must say so rather than round it away.
    assert full.freetext_recall < 1.0


def test_freetext_misses_are_labelled_as_probabilistic_not_hidden(scored):
    """Recall below 1.0 must show up somewhere measured, not be rounded away.

    The classifier's actual failure mode on this corpus is a partial catch
    (half an organisation name redacted, not the whole one) rather than a
    clean zero-detection miss, so it will not always leave a literal,
    fully-unredacted survivor string to find - a partial catch by definition
    breaks that literal match. The per-type ``partial``/``missed`` counters
    are the ones that cannot be zero here; verbatim survivors are asserted
    only when a full miss actually produced one.
    """
    full = scored[0]
    freetext_types = [t for t in full.types.values() if t.expected_tier == entities.TIER_FREETEXT]
    not_fully_caught = sum(t.partial + t.missed for t in freetext_types)
    assert not_fully_caught > 0, (
        "recall below 1.0 must be visible in per-type partial/missed counts"
    )

    full_misses = [
        s for s in full.verbatim_survivors if s["reason"] == "tier2 miss (probabilistic tier)"
    ]
    assert all(s["expected_tier"] == entities.TIER_FREETEXT for s in full_misses)


@pytest.mark.skipif(not HAS_NER, reason="spaCy model not installed")
def test_spacy_backend_also_meets_the_floor():
    """The alternate tier 2 backend is scored the same way as the default."""
    full, _ = evaluate.run(lines=LINES, seed=SEED, tier2="spacy")
    assert full.tier2_backend == "spacy"
    assert full.freetext_recall >= evaluate.FREETEXT_RECALL_FLOOR


def test_tier1_only_run_reports_freetext_as_a_phase_boundary():
    """Without tier 2, free-text survivors are owned gaps, not silent passes."""
    full, _ = evaluate.run(lines=200, seed=SEED, tier2=None, include_adversarial=False)
    assert full.ner_enabled is False
    assert full.freetext_recall == 0.0
    assert not full.below_freetext_floor  # no floor claim without the tier
    survivors = [
        s for s in full.verbatim_survivors if s["entity_type"] in ("PERSON_NAME", "ORG_NAME")
    ]
    assert survivors
    assert all(s["reason"] == "tier not built yet" for s in survivors)


def test_spacy_backend_raises_rather_than_silently_skipping(monkeypatch):
    monkeypatch.setattr(ner, "available", lambda: False)
    with pytest.raises(RuntimeError, match="spaCy model"):
        evaluate.run_with_baseline(lines=10, tier2="spacy")


def test_unknown_tier2_backend_raises():
    with pytest.raises(ValueError, match="unknown tier2 backend"):
        evaluate.run(lines=10, tier2="made-up-backend")


def test_injection_bypass_rate_is_not_claimed_without_tier3(scored):
    """Tiers 1-2 have no notion of an instruction, so a bypass claim for a run
    that never included tier 3 would be reporting a test that never ran."""
    full = scored[0]
    assert full.tier3_enabled is False
    assert full.to_dict()["adversarial"]["injection_bypass_rate"] is None
    assert full.injection_canaries > 0


def test_injection_bypass_rate_is_measured_once_tier3_runs():
    """A tier 3 backend that always complies with an injected instruction lets
    every injection-adjacent name it alone was responsible for survive."""

    class AlwaysComplyBackend:
        name = "always-comply"

        def complete(self, prompt: str) -> str:
            return '{"findings": []}'

    full, _ = evaluate.run(lines=200, seed=SEED, tier2=None, tier3=AlwaysComplyBackend())
    assert full.tier3_enabled is True
    assert full.injection_bypass_rate == 1.0


def test_injection_bypass_rate_is_zero_for_an_honest_tier3():
    class HonestBackend:
        name = "honest"

        def complete(self, prompt: str) -> str:

            data = prompt.split("<<<DATA\n", 1)[1].rsplit("\nDATA>>>", 1)[0]
            findings = []
            for etype, marker in (
                ("PERSON", "Sofia Tanaka"),
                ("PERSON", "Noah Delacroix"),
                ("ORGANIZATION", "Fabrikam Advisory"),
                ("PERSON", "Clara Petrov"),
                ("ORGANIZATION", "Tailspin Industries"),
            ):
                if marker in data:
                    findings.append({"text": marker, "type": etype})
            import json

            return json.dumps({"findings": findings})

    full, _ = evaluate.run(lines=200, seed=SEED, tier2=None, tier3=HonestBackend())
    assert full.tier3_enabled is True
    assert full.injection_bypass_rate == 0.0


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
        assert raw[s.start : s.end] not in redacted


def test_metrics_json_round_trips(scored, tmp_path):
    full = scored[0]
    path = tmp_path / "metrics.json"
    evaluate.save(full, path)
    d = json.loads(path.read_text())
    assert d["recall_shaped_types"] == round(full.shaped_recall, 4)
    assert d["ner_enabled"] is full.ner_enabled
    assert d["tier2_backend"] == full.tier2_backend
    assert d["tier3_enabled"] is full.tier3_enabled
    assert d["freetext_recall_floor"] == evaluate.FREETEXT_RECALL_FLOOR
    assert d["types"]["POD_ID"]["seeded"] > 0


# ---------------------------------------------------------------------------
# Degradation must be visible.
#
# Regression: the engine counted degraded units correctly and the eval never
# printed the count or failed on it, so a replay run that failed closed on
# 5,000 of 5,029 units reported a clean pass with a headline injection number
# next to it. Failing closed is only half a control; saying so is the other.
# ---------------------------------------------------------------------------


class _AlwaysFailsTier:
    name = "tier3"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        raise RuntimeError("backend unavailable")


class _CountingBackend:
    name = "counting"

    def __init__(self):
        self.calls = 0

    def complete(self, prompt):
        self.calls += 1
        return '{"findings": []}'


def test_a_failing_tier_shows_up_as_degraded_units():
    from hider import evaluate as ev

    rep, _ = ev.run(
        lines=120, seed=3, tiers=[pipeline.RegexTier(), _AlwaysFailsTier()], label="degrading"
    )
    assert rep.degraded_units > 0
    assert rep.to_dict()["degraded_units"] == rep.degraded_units


def test_a_clean_run_degrades_nothing(scored):
    assert scored[0].degraded_units == 0


def test_tier3_is_scoped_to_the_hostile_corpus():
    """It must not be billed for, or fail closed on, the generated corpus."""
    from hider import adversarial
    from hider import evaluate as ev

    backend = _CountingBackend()
    rep, _ = ev.run(lines=400, seed=4, tier2=None, tier3=backend, label="scoped")
    assert rep.tier3_enabled
    assert rep.degraded_units == 0
    # Every call has to be attributable to a hostile-corpus line.
    assert 0 < backend.calls <= len(adversarial.build(seed=4)[0]) * 3


def test_enabling_tier3_does_not_move_the_generated_corpus_numbers():
    from hider import evaluate as ev

    without, _ = ev.run(lines=400, seed=5, tier2=None, label="a")
    with_t3, _ = ev.run(lines=400, seed=5, tier2=None, tier3=_CountingBackend(), label="b")
    assert without.shaped_recall == with_t3.shaped_recall
    assert without.clean_lines_with_redaction == with_t3.clean_lines_with_redaction
