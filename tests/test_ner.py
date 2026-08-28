"""Tier 2, the local NER tier: detection, residue discipline, suppression.

Skipped entirely when the spaCy model is not installed, so ``pytest`` in a
tier-1-only environment stays green while making it plain (via the eval
harness) that tier 2 did not run.
"""

from __future__ import annotations

import pytest

pytest.importorskip("en_core_web_sm")

from hider import ner, pipeline, pseudonym  # noqa: E402


class _StubEngine:
    """Deterministic stand-in for Presidio's engine, for the rules tests."""

    def __init__(self, *spans):
        self.spans = spans
        self.calls = 0

    def process_text(self, text, language):
        self.calls += 1

        class A:
            entities = [
                type("E", (), {"start_char": s, "end_char": e, "label_": l})()
                for s, e, l in self.spans
            ]

        return A()


@pytest.fixture(scope="module")
def tier2():
    return ner.LocalNerTier()


@pytest.fixture(scope="module")
def pipe(tier2):
    return pipeline.Pipeline(
        [pipeline.RegexTier(), tier2], vault=pseudonym.EntityVault(key=b"ner-tests")
    )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_person_and_org_in_prose_are_redacted(pipe):
    line = ("Call with Anna Novak at Northwind Holdings on case 07551234: "
            "the restore into https://contoso22.sharepoint.com/sites/Finance "
            "is still queued.")
    r = pipe.redact(line)
    assert "Anna Novak" not in r.text
    assert "Northwind Holdings" not in r.text
    assert "<Person-" in r.text and "<Org-" in r.text
    assert "contoso22" not in r.text


def test_labels_map_to_the_spec_types(pipe):
    line = "Handover: Priya Vargas takes over the escalation."
    r = pipe.redact(line)
    spans = [s for s in r.spans if s.tier == "tier2"]
    assert spans and all(s.entity_type in {"PERSON", "ORGANIZATION"} for s in spans)


def test_tier2_is_billed_against_the_residue_only(tier2):
    line = ("session a41f77c2-9be1-4c33-8f0e-1122aabbccdd on wkr-amer-prx117 "
            "note: spoke with Anna Novak today")
    p = pipeline.Pipeline(
        [pipeline.RegexTier(), tier2], vault=pseudonym.EntityVault(key=b"k")
    )
    p.redact(line)
    offered = p.stats.tiers["tier2"].chars_offered
    assert offered < len(line)
    assert offered > 0


def test_monotonic_with_tier1(tier2):
    line = "Anna Novak at anna.novak@contoso.com on wkr-emea-rg124"
    only1 = pipeline.Pipeline(
        [pipeline.RegexTier()], vault=pseudonym.EntityVault(key=b"k")
    ).detect(line)[0]
    both = pipeline.Pipeline(
        [pipeline.RegexTier(), tier2], vault=pseudonym.EntityVault(key=b"k")
    ).detect(line)[0]

    def cov(spans):
        out = set()
        for s in spans:
            out.update(range(s.start, s.end))
        return out

    assert cov(only1) <= cov(both)
    assert "Anna Novak" not in pipeline.Pipeline(
        [pipeline.RegexTier(), tier2], vault=pseudonym.EntityVault(key=b"k")
    ).redact(line).text


def test_fail_closed_when_the_engine_errors(tier2):
    class Boom:
        def process_text(self, text, language):
            raise RuntimeError("model exploded")

    tier2.engine, real = Boom(), tier2.engine
    try:
        p = pipeline.Pipeline(
            [pipeline.RegexTier(), tier2], vault=pseudonym.EntityVault(key=b"k")
        )
        r = p.redact("session a41f77c2-9be1-4c33-8f0e-1122aabbccdd and Anna Novak")
        assert r.degraded is True
        assert p.stats.tiers["tier2"].errors == 1
        # Tier 1 coverage survives the tier 2 failure.
        assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" not in r.text
    finally:
        tier2.engine = real


def test_results_are_memoised_by_content():
    eng = _StubEngine((0, 10, "PERSON"))
    t = ner.LocalNerTier(engine=eng)
    first = t.detect("Anna Novak wrote a note.", [(0, 24)])
    second = t.detect("Anna Novak wrote a note.", [(0, 24)])
    assert first == second
    assert eng.calls == 1


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        # Kept: real names and organisations.
        ("Anna Novak", 1),
        ("Northwind Holdings", 1),
        # Dropped: log machinery and identifiers the model misreads.
        ("the Daily-EXCH-AUS", 0),   # job policy code behind an article
        ("ETA", 0),                  # acronym
        ("MB/s.", 0),                # unit
        ("TimeoutMs", 0),            # CamelCase config key
        ("Cache] Evicted", 0),       # glued across log structure
        ("8301 MB", 0),              # quantity tagged as a person
    ],
)
def test_suppression_rules(text, expected):
    out = ner.suppress([(0, len(text), "ORGANIZATION", text)])
    assert len(out) == expected


def test_article_is_trimmed_not_fatal():
    text = "the Northwind Group"
    out = ner.suppress([(0, len(text), "ORGANIZATION", text)])
    assert out == [(4, len(text), "ORGANIZATION")]


def test_available_reflects_the_environment():
    assert ner.available() is True
