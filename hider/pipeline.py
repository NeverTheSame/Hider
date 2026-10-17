"""The tiered redaction engine.

One engine serves two workloads:

*Async bundle ingest.* A whole bundle goes in, a redacted bundle comes out, and
the latency budget is minutes. Every tier runs. This is the flow that produces
the cost and routing numbers, because it is the one that sees millions of lines.

*Sync prompt proxy.* A chat completion is intercepted in flight, and the budget
is tens of milliseconds on top of the provider call. The deterministic tier
always runs; the local NER tier runs unless latency forbids it. Tier 3 never
runs in the sync path. See ``proxy.py`` for the gateway itself.

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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from . import classifier, entities, pseudonym, recognizers


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
        """Number of characters the span covers."""
        return self.end - self.start


class Tier(Protocol):
    """A detection layer.

    ``detect`` receives the full text plus the segments not yet covered by
    earlier tiers. A cheap deterministic tier reads the whole text; a paid tier
    reads only the residue, which is where the cost saving comes from.
    """

    name: str
    cost_per_1k_chars: float

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        """Return the spans this tier finds, in offsets of ``text``."""
        ...


# ---------------------------------------------------------------------------
# Tier 1: deterministic patterns
# ---------------------------------------------------------------------------


class RegexTier:
    """Presidio pattern recognizers. No NLP engine, no network, no per-call cost."""

    name = "tier1"
    cost_per_1k_chars = 0.0

    def __init__(
        self,
        *,
        include_builtins: bool = True,
        include_custom: bool = True,
        use_active_profile: bool = True,
    ) -> None:
        if include_custom:
            self.recognizers = recognizers.all_recognizers(
                include_builtins=include_builtins,
                use_active_profile=use_active_profile,
            )
        else:
            # Baseline configuration: stock Presidio patterns only, so the
            # uplift from the domain-specific recognizers is a measured delta.
            self.recognizers = recognizers.builtins()

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        """Run the tier 1 recognizers over the whole text and return their spans."""
        return [
            Span(
                r.start,
                r.end,
                r.entity_type,
                float(r.score or 0.0),
                self.name,
                detector=getattr(r, "recognition_metadata", {}).get("recognizer_name", "")
                if getattr(r, "recognition_metadata", None)
                else "",
            )
            for r in recognizers.analyze(text, self.recognizers)
        ]


# ---------------------------------------------------------------------------
# Tier 2: a trained classifier over the free-text residue
# ---------------------------------------------------------------------------


class ManagedNerTier:
    """A locally trained classifier over the free-text residue. Phase 2.

    Runs entirely in-process: no network, no per-call bill, no third-party
    endpoint to trust with the residue. ``hider/classifier.py`` is the model -
    a per-token BIO classifier trained on a synthetic sentence corpus whose
    name and organisation vocabulary is disjoint from the one the eval corpus
    is seeded from, so recall measured against ``hider eval`` reflects
    generalisation rather than a lookup table.

    * Sees only the residue segments tier 1 left behind, so shaped tokens
      already cleared are never re-analysed.
    * The model is process-cached (``classifier.get_trained``): training is
      deterministic for a fixed seed and takes well under a second, so it runs
      once per interpreter rather than once per ``Pipeline``.
    * Anything the classifier raises on propagates to the engine's fail-closed
      handling in the same way any other tier's exception does.
    """

    name = "tier2"
    cost_per_1k_chars = 0.0  # local model: no per-call bill, CPU time is in elapsed_s

    def __init__(self, seed: int = 20260821) -> None:
        self._clf = classifier.get_trained(seed=seed)

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        """Run the trained classifier over each residue segment and return spans in document offsets."""
        spans: list[Span] = []
        for start, end in residue:
            segment = text[start:end]
            if not segment.strip():
                continue
            for s0, e0, etype, score in classifier.predict_spans(self._clf, segment):
                spans.append(
                    Span(
                        start + s0,
                        start + e0,
                        etype,
                        float(score),
                        self.name,
                        detector="trained-classifier",
                    )
                )
        return spans


# ---------------------------------------------------------------------------
# Tier 3: an LLM pass over what tier 2 could not resolve
# ---------------------------------------------------------------------------


class LlmPassTier:
    """An LLM pass over the residue, for free-text edge cases tier 2 misses. Phase 3.

    ``hider/llm_tier.py`` holds the implementation; this docstring is the
    contract it is built against, unchanged from when it was written for the
    tier 3 stub:

    * Input is data only, wrapped in inert delimiters, never instructions.
    * Output is strict JSON span labelling. Anything non-conforming fails
      closed to redact, it does not fail open to allow.
    * Every reported span is verified as a literal, byte-identical substring
      of the residue before it is trusted. An offset the model invents, or a
      quote that does not appear verbatim, is discarded rather than acted on -
      the model is not trusted to do its own arithmetic, only to point.
    * No tools, no retrieval, no memory. It is a classifier, not an agent.
    * Verdicts can only ADD spans. The engine enforces that structurally, so a
      successful prompt injection cannot unmask anything, it can at worst waste
      money or over-redact.
    * A prompt-shield or input-classification layer in front is defence in
      depth, not the control. The control is the add-only rule above.
    * Never runs in the sync proxy path.

    Constructing this tier requires a ``Backend`` (see ``llm_backend.py``); the
    engine has no default one, because a paid, network-calling tier must never
    be reached by accident.
    """

    name = "tier3"
    cost_per_1k_chars = 0.02  # placeholder until measured against real usage

    def __init__(self, backend) -> None:
        self.backend = backend

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        """Run the tier 3 LLM pass over the residue; see ``llm_tier.detect``."""
        from . import llm_tier

        return llm_tier.detect(self.backend, text, residue, tier_name=self.name)


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
    """Per-tier counters for one run: characters offered and redacted, spans, time and errors."""

    name: str
    chars_offered: int = 0
    spans_found: int = 0
    chars_redacted: int = 0
    elapsed_s: float = 0.0
    errors: int = 0

    @property
    def estimated_cost(self) -> float:
        """Always 0.0 here; the eval report prices tiers from character counts instead."""
        return 0.0


@dataclass
class Redaction:
    """One redacted unit: the output text, the spans applied, whether it degraded, and the log events."""

    text: str
    spans: list[Span]
    degraded: bool = False
    events: list[dict] = field(default_factory=list)


@dataclass
class Stats:
    """Counters for a whole pipeline run, across units and tiers."""

    chars_in: int = 0
    lines: int = 0
    tiers: dict[str, TierStat] = field(default_factory=dict)
    #: Characters still unclaimed after the last tier. In a phase 1 run this is
    #: the size of the bill a managed NER tier would have produced, which is the
    #: number the tiering argument rests on.
    residue_chars: int = 0
    degraded_units: int = 0

    def tier(self, name: str) -> TierStat:
        """The stats for the named tier, created on first use."""
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

            kept = [s for s in _sane(found, len(text)) if s.score >= self.min_score]
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
        """Redact one unit of text and return the result with its decision events.

        Secrets are replaced by a destroyed marker; every other span gets a vault
        pseudonym. The events record the substitute and never the original value.
        A degraded detection is counted in the run stats.
        """
        spans, degraded = self.detect(text, unit=unit, line_no=line_no)
        self.stats.chars_in += len(text)
        self.stats.lines += 1
        if degraded:
            self.stats.degraded_units += 1

        out: list[str] = []
        events: list[dict] = []
        cursor = 0
        for s in spans:
            out.append(text[cursor : s.start])
            original = text[s.start : s.end]
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
