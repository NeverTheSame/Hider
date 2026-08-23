"""The tiered redaction engine.

One engine serves two workloads:

*Async bundle ingest.* A whole bundle goes in, a redacted bundle comes out, and
the latency budget is minutes. Every tier runs. This is the flow that produces
the cost and routing numbers, because it is the one that sees millions of lines.

*Sync prompt proxy.* A chat completion is intercepted in flight, and the budget
is tens of milliseconds on top of the provider call. Only the deterministic
tiers run. Tier 3 never runs in the sync path.

Three rules hold in both:

1. **Monotonicity.** Tiers run in order and may only ADD redactions. A later
   tier can never unmask what an earlier one masked. That makes the expensive,
   promptable tier incapable of reducing coverage no matter what it emits, which
   is the whole reason it is safe to let a language model near this path.
2. **Fail closed.** A tier that errors, times out, or returns malformed output
   does not degrade to passthrough. The engine keeps what it has and marks the
   unit as degraded, so the caller can refuse to forward it.
3. **Secrets are destroyed, identifiers are pseudonymised.** Decided by the
   entity spec, not by the call site.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Protocol, Sequence

from . import entities, pseudonym, recognizers


@dataclass(frozen=True)
class Span:
    """A region of text one tier wants redacted."""

    start: int
    end: int
    entity_type: str
    score: float
    tier: str
    detector: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start


class Tier(Protocol):
    """A detection layer.

    ``detect`` receives the full text plus the segments not yet covered by
    earlier tiers. A cheap deterministic tier reads the whole text; a paid tier
    reads only the residue, which is where the cost saving comes from.
    """

    name: str
    cost_per_1k_chars: float

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]: ...


# ---------------------------------------------------------------------------
# Tier 1: deterministic patterns
# ---------------------------------------------------------------------------


class RegexTier:
    """Presidio pattern recognizers. No NLP engine, no network, no per-call cost."""

    name = "tier1"
    cost_per_1k_chars = 0.0

    def __init__(self, *, include_builtins: bool = True, include_custom: bool = True) -> None:
        if include_custom:
            self.recognizers = recognizers.all_recognizers(include_builtins=include_builtins)
        else:
            # Baseline configuration: stock Presidio patterns only, so the
            # uplift from the domain-specific recognizers is a measured delta.
            self.recognizers = recognizers.builtins()

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        return [
            Span(r.start, r.end, r.entity_type, float(r.score or 0.0), self.name,
                 detector=getattr(r, "recognition_metadata", {}).get(
                     "recognizer_name", "") if getattr(r, "recognition_metadata", None) else "")
            for r in recognizers.analyze(text, self.recognizers)
        ]


# ---------------------------------------------------------------------------
# Tiers 2 and 3: contracts only, phases 2 and 3
# ---------------------------------------------------------------------------


class ManagedNerTier:
    """A managed PII-detection service over the free-text residue. Phase 2.

    Any cloud NER service with a PII endpoint fits behind this interface. The
    contract is written down now so the engine and the eval harness can be built
    against it:

    * Sees only the residue segments, batched into documents under the service
      limit, so shaped tokens already cleared by tier 1 are never paid for.
    * Results are memoised by content hash. The sync path needs this because the
      chat API resends the whole conversation on every turn; without memoisation
      the same history would be re-analysed on each request.
    * Runs inside the operator's own cloud account. That is the point of using a
      managed service here rather than the model provider's own: the boundary
      being defended is the third-party model endpoint, not the cloud in general.
    * Any transport error, throttle, or malformed response fails closed.
    """

    name = "tier2"
    cost_per_1k_chars = 0.001  # placeholder until measured against real pricing

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        raise NotImplementedError("phase 2")


class ResidualClassifierTier:
    """A small self-hosted model as residual classifier. Phase 3.

    Deployed inside the operator's own account, never the model vendor's shared
    endpoint. Contract:

    * Input is data only, wrapped in inert delimiters, never instructions.
    * Output is strict JSON span labelling. Anything non-conforming fails
      closed to redact, it does not fail open to allow.
    * No tools, no retrieval, no memory. It is a classifier, not an agent.
    * Verdicts can only ADD spans. The engine enforces that structurally, so a
      successful prompt injection cannot unmask anything, it can at worst waste
      money or over-redact.
    * A prompt-shield or input-classification layer in front is defence in
      depth, not the control. The control is the add-only rule above.
    * Never runs in the sync proxy path.
    """

    name = "tier3"
    cost_per_1k_chars = 0.02  # placeholder until measured

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        raise NotImplementedError("phase 3")


# ---------------------------------------------------------------------------
# Span algebra
# ---------------------------------------------------------------------------


def _is_secret(entity_type: str) -> bool:
    return pseudonym._canonical_type(entity_type) in entities.SECRET_TYPES


def resolve(spans: Iterable[Span]) -> list[Span]:
    """Collapse overlapping spans, keeping the safest interpretation.

    Priority: a secret beats an identifier (destroying too much is recoverable
    from the vault, leaking a credential is not), then the longer span, then the
    higher score. Ties are broken by tier order so results are deterministic.
    """
    ordered = sorted(
        spans,
        key=lambda s: (-int(_is_secret(s.entity_type)), -s.length, -s.score, s.tier, s.start),
    )
    kept: list[Span] = []
    for s in ordered:
        if any(s.start < k.end and k.start < s.end for k in kept):
            continue
        kept.append(s)
    return sorted(kept, key=lambda s: s.start)


def residue_segments(length: int, spans: Sequence[Span]) -> list[tuple[int, int]]:
    """The parts of the text no tier has claimed yet."""
    out: list[tuple[int, int]] = []
    cursor = 0
    for s in sorted(spans, key=lambda s: s.start):
        if s.start > cursor:
            out.append((cursor, s.start))
        cursor = max(cursor, s.end)
    if cursor < length:
        out.append((cursor, length))
    return out


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class TierStat:
    name: str
    chars_offered: int = 0
    spans_found: int = 0
    chars_redacted: int = 0
    elapsed_s: float = 0.0
    errors: int = 0

    @property
    def estimated_cost(self) -> float:
        return 0.0


@dataclass
class Redaction:
    text: str
    spans: list[Span]
    degraded: bool = False
    events: list[dict] = field(default_factory=list)


@dataclass
class Stats:
    chars_in: int = 0
    lines: int = 0
    tiers: dict[str, TierStat] = field(default_factory=dict)
    #: Characters still unclaimed after the last tier. In a phase 1 run this is
    #: the size of the bill a managed NER tier would have produced, which is the
    #: number the tiering argument rests on.
    residue_chars: int = 0
    degraded_units: int = 0

    def tier(self, name: str) -> TierStat:
        return self.tiers.setdefault(name, TierStat(name))


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


class Pipeline:
    """Runs the tiers in order and rewrites the text."""

    def __init__(
        self,
        tiers: Sequence[Tier] | None = None,
        *,
        vault: pseudonym.EntityVault | None = None,
        min_score: float = 0.4,
        fail_closed: bool = True,
    ) -> None:
        self.tiers: list[Tier] = list(tiers) if tiers is not None else [RegexTier()]
        self.vault = vault if vault is not None else pseudonym.EntityVault()
        self.min_score = min_score
        self.fail_closed = fail_closed
        self.stats = Stats()

    # -- detection ---------------------------------------------------------

    def detect(self, text: str, *, unit: str = "", line_no: int = 0) -> tuple[list[Span], bool]:
        """Run every tier, returning resolved spans and whether we degraded."""
        accumulated: list[Span] = []
        degraded = False
        for tier in self.tiers:
            residue = residue_segments(len(text), accumulated)
            offered = sum(e - s for s, e in residue)
            stat = self.stats.tier(tier.name)
            stat.chars_offered += offered
            t0 = time.perf_counter()
            try:
                found = tier.detect(text, residue)
            except NotImplementedError:
                # An unbuilt tier is absent, not failed. Nothing to record.
                continue
            except Exception:
                stat.errors += 1
                degraded = True
                if self.fail_closed:
                    # Keep what earlier tiers found and mark the unit. The
                    # caller decides whether to forward a degraded unit; the
                    # engine never silently returns less protection.
                    continue
                raise
            finally:
                stat.elapsed_s += time.perf_counter() - t0

            kept = [
                s for s in _sane(found, len(text))
                if s.score >= self.min_score
            ]
            before = _covered(accumulated)
            candidate = resolve(accumulated + kept)
            # Monotonicity, enforced rather than trusted: any character masked
            # before this tier ran stays masked afterwards.
            if not before <= _covered(candidate):
                candidate = resolve(candidate + accumulated)
            accumulated = candidate
            stat.spans_found += len(kept)

        return accumulated, degraded

    # -- rewriting ---------------------------------------------------------

    def redact(self, text: str, *, unit: str = "", line_no: int = 0) -> Redaction:
        spans, degraded = self.detect(text, unit=unit, line_no=line_no)
        self.stats.chars_in += len(text)
        self.stats.lines += 1
        if degraded:
            self.stats.degraded_units += 1

        out: list[str] = []
        events: list[dict] = []
        cursor = 0
        for s in spans:
            out.append(text[cursor:s.start])
            original = text[s.start:s.end]
            if _is_secret(s.entity_type):
                replacement = pseudonym.destroyed_marker(s.entity_type, original)
                action = "destroyed"
            else:
                replacement = self.vault.pseudonym(s.entity_type, original)
                action = "pseudonymised"
            out.append(replacement)
            cursor = s.end
            self.stats.tier(s.tier).chars_redacted += s.length
            events.append(
                {
                    "schema": "hider.redaction.v1",
                    "unit": unit,
                    "line": line_no,
                    "start": s.start,
                    "end": s.end,
                    "entity_type": s.entity_type,
                    "action": action,
                    "tier": s.tier,
                    "score": round(s.score, 3),
                    # What went into the text. Safe to log: it is the
                    # substitute, never the original.
                    "marker": replacement,
                    "replacement": replacement if action == "pseudonymised" else None,
                    # The original value is deliberately absent. A decision log
                    # that records what it redacted is a second copy of the data.
                }
            )
        out.append(text[cursor:])
        redacted = "".join(out)
        self.stats.residue_chars += len(text) - sum(s.length for s in spans)
        return Redaction(redacted, spans, degraded, events)


def _sane(spans: Iterable[Span], length: int) -> list[Span]:
    """Discard spans that cannot refer to real text.

    A tier that is a language model can emit offsets that do not exist, and a
    remote service can return a payload shaped differently from its schema.
    Neither may be allowed to corrupt the rewrite: an unusable span is dropped,
    which loses coverage rather than producing wrong output, and the tier is
    still credited with nothing so the miss shows up in the numbers.
    """
    out: list[Span] = []
    for s in spans:
        if not isinstance(s.start, int) or not isinstance(s.end, int):
            continue
        if s.start < 0 or s.end > length or s.start >= s.end:
            continue
        out.append(s)
    return out


def _covered(spans: Iterable[Span]) -> set[int]:
    out: set[int] = set()
    for s in spans:
        out.update(range(s.start, s.end))
    return out
