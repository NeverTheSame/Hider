"""Engine invariants: monotonicity, fail-closed, secret handling.

These are the properties the security argument rests on. If any of them can be
broken, the interview claim "a prompt injection against tier 3 cannot unmask
anything" stops being true.
"""

from __future__ import annotations

import pytest

from hider import entities, pipeline, pseudonym

LINE = ("[Session] session a41f77c2-9be1-4c33-8f0e-1122aabbccdd on wkr-amer-prx117 "
        "for anna.novak@contoso.com token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.QQQQQQQQQQ")


def fresh(tiers=None):
    return pipeline.Pipeline(tiers, vault=pseudonym.EntityVault(key=b"test-key"))


class NoopTier:
    """A later tier that finds nothing. Coverage must not shrink."""

    name = "tier-noop"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        return []


class ExplodingTier:
    name = "tier-boom"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        raise RuntimeError("service unavailable")


class LiarTier:
    """A tier that returns spans it has no business returning.

    Stands in for a compromised or confused tier 3: nonsense offsets, a span
    that tries to cover the whole line, and a zero-width span.
    """

    name = "tier-liar"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        return [
            pipeline.Span(-5, 3, "SESSION_GUID", 0.99, self.name),
            pipeline.Span(0, len(text) + 500, "SESSION_GUID", 0.99, self.name),
            pipeline.Span(10, 10, "SESSION_GUID", 0.99, self.name),
        ]


class AdderTier:
    """A well-behaved later tier that finds one extra thing."""

    name = "tier-adder"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        i = text.find("Session")
        return [pipeline.Span(i, i + 7, "PERSON_NAME", 0.9, self.name)] if i >= 0 else []


def covered_chars(spans):
    out = set()
    for s in spans:
        out.update(range(s.start, s.end))
    return out


# ---------------------------------------------------------------------------
# Monotonicity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("later", [NoopTier(), ExplodingTier(), LiarTier(), AdderTier()])
def test_later_tier_can_never_reduce_coverage(later):
    tier1_only, _ = fresh([pipeline.RegexTier()]).detect(LINE)
    with_later, _ = fresh([pipeline.RegexTier(), later]).detect(LINE)
    assert covered_chars(tier1_only) <= covered_chars(with_later)


def test_adder_tier_actually_adds():
    tier1_only, _ = fresh([pipeline.RegexTier()]).detect(LINE)
    with_adder, _ = fresh([pipeline.RegexTier(), AdderTier()]).detect(LINE)
    assert covered_chars(with_adder) > covered_chars(tier1_only)


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

def test_failing_tier_marks_the_unit_degraded_and_keeps_earlier_coverage():
    p = fresh([pipeline.RegexTier(), ExplodingTier()])
    r = p.redact(LINE)
    assert r.degraded is True
    assert p.stats.tier("tier-boom").errors == 1
    assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" not in r.text


def test_fail_open_is_opt_in_only():
    p = pipeline.Pipeline([pipeline.RegexTier(), ExplodingTier()],
                          vault=pseudonym.EntityVault(key=b"k"), fail_closed=False)
    with pytest.raises(RuntimeError):
        p.redact(LINE)


class UnbuiltTier:
    """A tier slot with no implementation behind it yet."""

    name = "tier-unbuilt"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        raise NotImplementedError("phase not shipped")


def test_unbuilt_tier_is_absent_not_failed():
    p = fresh([pipeline.RegexTier(), UnbuiltTier()])
    r = p.redact(LINE)
    assert r.degraded is False
    assert p.stats.tier("tier-unbuilt").errors == 0


def test_managed_ner_tier_is_built_and_runs():
    """ManagedNerTier used to be the phase-2 stub; it is the shipped trained
    classifier now, so it must actually detect, not silently no-op."""
    p = fresh([pipeline.RegexTier(), pipeline.ManagedNerTier()])
    r = p.redact("Spoke to Anna Novak about the outage.")
    assert r.degraded is False
    assert p.stats.tier("tier2").errors == 0
    assert any(s.entity_type == "PERSON" for s in r.spans)


def test_malformed_spans_cannot_corrupt_the_rewrite():
    p = fresh([pipeline.RegexTier(), LiarTier()])
    r = p.redact(LINE)
    # Nothing outside the text was addressed, and the text is still text.
    assert all(0 <= s.start < s.end <= len(LINE) for s in r.spans)
    assert r.text
    assert "anna.novak@contoso.com" not in r.text


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------

def test_secrets_are_destroyed_not_pseudonymised():
    p = fresh()
    r = p.redact(LINE)
    assert "<REDACTED:JWT>" in r.text
    assert not any(e["type"] in entities.SECRET_TYPES for e in p.vault.entries.values())


def test_vault_refuses_a_secret_outright():
    v = pseudonym.EntityVault(key=b"k")
    with pytest.raises(ValueError):
        v.pseudonym("JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.QQQQ")


def test_overlap_resolution_prefers_the_secret():
    """When an identifier and a credential overlap, the credential wins."""
    spans = [
        pipeline.Span(0, 40, "SESSION_GUID", 0.99, "tier1"),
        pipeline.Span(10, 30, "JWT", 0.5, "tier1"),
    ]
    kept = pipeline.resolve(spans)
    assert [s.entity_type for s in kept] == ["JWT"]


# ---------------------------------------------------------------------------
# Span algebra
# ---------------------------------------------------------------------------

def test_residue_is_what_no_tier_claimed():
    spans = [pipeline.Span(5, 10, "X", 1.0, "t"), pipeline.Span(20, 25, "X", 1.0, "t")]
    assert pipeline.residue_segments(30, spans) == [(0, 5), (10, 20), (25, 30)]


def test_residue_of_fully_covered_text_is_empty():
    assert pipeline.residue_segments(10, [pipeline.Span(0, 10, "X", 1.0, "t")]) == []


def test_overlapping_spans_collapse_to_one():
    spans = [pipeline.Span(0, 10, "A", 0.9, "t"), pipeline.Span(5, 8, "A", 0.9, "t")]
    assert len(pipeline.resolve(spans)) == 1


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------

def test_decision_log_never_records_the_original_value():
    p = fresh()
    r = p.redact(LINE)
    blob = repr(r.events)
    assert r.events
    assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" not in blob
    assert "anna.novak@contoso.com" not in blob
    for e in r.events:
        assert e["schema"] == "hider.redaction.v1"
        assert e["action"] in {"destroyed", "pseudonymised"}


def test_stats_account_for_every_character():
    p = fresh()
    r = p.redact(LINE)
    redacted_chars = sum(s.length for s in r.spans)
    assert p.stats.chars_in == len(LINE)
    assert p.stats.residue_chars == len(LINE) - redacted_chars
