"""Eval harness: generate, redact, score.

The harness answers four questions and refuses to blur them together.

1. **Recall, per entity type, per tier.** Of N seeded values of type T, how many
   were redacted, and by which tier. Reported three ways: fully covered,
   partially covered (a partial catch still leaks part of the value, so it is
   not a catch), and correctly typed.
2. **Precision, as a false-redaction rate.** Measured on a unit known to contain
   no sensitive values at all, so there is nothing to argue about. Over-redaction
   is the failure mode that destroys bundle utility and with it the trust of the
   engineers who are supposed to use this.
3. **Uplift over the baseline.** The same corpus scored with stock Presidio
   patterns only, so the value of the domain-specific recognizers is a measured
   delta rather than a claim.
4. **Tier routing and cost.** How many characters each tier had to look at.
   With tier 1 in front, the residue is what a paid tier would be billed for.

It also runs two checks that are pass or fail rather than scored: no seeded
value may survive verbatim anywhere in the output, and the adversarial cases
must fail only where a named, documented gap says they will.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Sequence

from . import adversarial, entities, generator, ner, pipeline, pseudonym
from .markup import Occurrence

#: Assumed managed-NER price, US dollars per 1000 characters. Managed PII
#: services typically bill per 1000-character text record; this rate is a
#: list-price assumption and is stated as such wherever a cost appears.
NER_USD_PER_1K_CHARS = 0.001

#: The recall floor for the free-text types tier 2 owns. Tier 1 is held to
#: zero unexplained survivors because it is deterministic: a miss is a defect.
#: Tier 2 is a model, so a miss is a measurement. The gate is therefore a
#: floor, reported next to the number rather than blended into it. On the
#: shipped corpus the floor passes with real headroom (see README); if a
#: change drops recall below it, the eval fails exactly as it would for a
#: tier 1 leak.
FREETEXT_RECALL_FLOOR = 0.75


@dataclass
class TypeScore:
    entity_type: str
    seeded: int = 0
    covered: int = 0
    partial: int = 0
    typed: int = 0
    by_tier: Counter = field(default_factory=Counter)
    expected_tier: str = ""

    @property
    def missed(self) -> int:
        return self.seeded - self.covered

    @property
    def recall(self) -> float:
        return self.covered / self.seeded if self.seeded else 0.0

    @property
    def typed_recall(self) -> float:
        return self.typed / self.seeded if self.seeded else 0.0


@dataclass
class CaseResult:
    """One adversarial scenario, scored against the tier that owns it.

    Shaped and free-text entities are counted separately. A case that plants a
    session GUID next to a person's name is not a tier 1 failure when the name
    survives: tier 1 was never meant to catch it. Mixing the two would let a
    known design boundary masquerade as a defect, or worse, hide a real one.
    """

    case_id: str
    description: str
    expect_tier1: bool
    shaped_seeded: int
    shaped_covered: int
    free_seeded: int
    free_covered: int
    owner: str

    @property
    def caught_all(self) -> bool:
        return self.shaped_seeded > 0 and self.shaped_covered == self.shaped_seeded

    @property
    def surprise(self) -> bool:
        """A miss nobody predicted, which is the only kind worth panicking about."""
        return self.expect_tier1 and not self.caught_all


@dataclass
class Report:
    label: str
    lines: int = 0
    chars: int = 0
    types: dict[str, TypeScore] = field(default_factory=dict)
    groups_total: int = 0
    groups_caught: int = 0
    clean_lines: int = 0
    clean_lines_with_redaction: int = 0
    clean_false_spans: int = 0
    unmatched_spans: int = 0
    total_spans: int = 0
    verbatim_survivors: list[dict] = field(default_factory=list)
    tier_chars_offered: dict[str, int] = field(default_factory=dict)
    tier_chars_redacted: dict[str, int] = field(default_factory=dict)
    tier_elapsed_s: dict[str, float] = field(default_factory=dict)
    residue_chars: int = 0
    degraded_units: int = 0
    cases: list[CaseResult] = field(default_factory=list)
    injection_canaries: int = 0
    vault_size: int = 0
    #: True when the run included a live tier 2 (local NER). Free-text
    #: survivors are a floor-gated measurement when this is set and a phase
    #: boundary when it is not.
    ner_enabled: bool = False

    # -- rolled-up numbers -------------------------------------------------

    @property
    def seeded(self) -> int:
        return sum(t.seeded for t in self.types.values())

    @property
    def covered(self) -> int:
        return sum(t.covered for t in self.types.values())

    @property
    def recall(self) -> float:
        return self.covered / self.seeded if self.seeded else 0.0

    @property
    def shaped_recall(self) -> float:
        """Recall restricted to the types tier 1 is supposed to own.

        Reported separately because averaging in the free-text types, which
        tier 1 is designed not to handle, would understate tier 1 and overstate
        the system. Both numbers appear in the output.
        """
        rel = [t for t in self.types.values() if t.expected_tier == entities.TIER_SHAPED]
        s = sum(t.seeded for t in rel)
        return sum(t.covered for t in rel) / s if s else 0.0

    @property
    def freetext_recall(self) -> float:
        """Recall on the free-text types tier 2 owns, when tier 2 ran."""
        rel = [t for t in self.types.values() if t.expected_tier == entities.TIER_FREETEXT]
        s = sum(t.seeded for t in rel)
        return sum(t.covered for t in rel) / s if s else 0.0

    @property
    def below_freetext_floor(self) -> bool:
        return self.ner_enabled and self.freetext_recall < FREETEXT_RECALL_FLOOR

    @property
    def false_redaction_rate(self) -> float:
        return (self.clean_lines_with_redaction / self.clean_lines) if self.clean_lines else 0.0

    @property
    def naive_ner_cost_usd(self) -> float:
        """Cost of sending everything to a managed NER tier."""
        return self.chars / 1000 * NER_USD_PER_1K_CHARS

    @property
    def tiered_ner_cost_usd(self) -> float:
        """Cost of sending only what tier 1 could not clear."""
        return self.residue_chars / 1000 * NER_USD_PER_1K_CHARS

    @property
    def cost_reduction(self) -> float:
        n = self.naive_ner_cost_usd
        return (n - self.tiered_ner_cost_usd) / n if n else 0.0

    @property
    def unexpected_survivors(self) -> list[dict]:
        """Values that reached the output despite a tier being responsible for them.

        This is the number that has to be zero. Survivors whose owning tier is
        not built yet are counted separately: they are a phase boundary, not a
        leak that snuck past a control that was supposed to hold.
        """
        return [s for s in self.verbatim_survivors if not s["known_gap"]]

    @property
    def surprises(self) -> list[CaseResult]:
        return [c for c in self.cases if c.surprise]

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "lines": self.lines,
            "chars": self.chars,
            "recall_all": round(self.recall, 4),
            "recall_shaped_types": round(self.shaped_recall, 4),
            "recall_freetext_types": round(self.freetext_recall, 4),
            "freetext_recall_floor": FREETEXT_RECALL_FLOOR,
            "ner_enabled": self.ner_enabled,
            "seeded": self.seeded,
            "covered": self.covered,
            "groups": {"total": self.groups_total, "caught": self.groups_caught},
            "precision": {
                "clean_lines": self.clean_lines,
                "clean_lines_with_redaction": self.clean_lines_with_redaction,
                "false_redaction_rate": round(self.false_redaction_rate, 5),
                "clean_false_spans": self.clean_false_spans,
                "unmatched_spans_overall": self.unmatched_spans,
                "total_spans": self.total_spans,
            },
            "verbatim_survivors": {
                "total": len(self.verbatim_survivors),
                "unexpected": len(self.unexpected_survivors),
                "known_gap": len(self.verbatim_survivors)
                - len(self.unexpected_survivors),
                "detail": self.verbatim_survivors[:50],
            },
            "tiers": {
                "chars_offered": self.tier_chars_offered,
                "chars_redacted": self.tier_chars_redacted,
                "elapsed_s": {k: round(v, 4) for k, v in self.tier_elapsed_s.items()},
            },
            "residue_chars": self.residue_chars,
            "cost_usd": {
                "assumed_rate_per_1k_chars": NER_USD_PER_1K_CHARS,
                "everything_to_managed_ner": round(self.naive_ner_cost_usd, 4),
                "residue_only_after_tier1": round(self.tiered_ner_cost_usd, 4),
                "reduction": round(self.cost_reduction, 4),
            },
            "degraded_units": self.degraded_units,
            "vault_size": self.vault_size,
            "types": {
                name: {
                    "seeded": t.seeded, "covered": t.covered, "partial": t.partial,
                    "typed": t.typed, "missed": t.missed,
                    "recall": round(t.recall, 4), "typed_recall": round(t.typed_recall, 4),
                    "expected_tier": t.expected_tier, "by_tier": dict(t.by_tier),
                }
                for name, t in sorted(self.types.items())
            },
            "adversarial": {
                "cases": [
                    {**asdict(c), "caught_all": c.caught_all, "surprise": c.surprise}
                    for c in self.cases
                ],
                "surprises": [c.case_id for c in self.surprises],
                "injection_canaries": self.injection_canaries,
                "injection_bypass_rate": None,
                "injection_note": (
                    "Not applicable in a phase 1 run. Tier 1 has no instructions to "
                    "subvert, so it cannot be injected. The canaries are in the corpus "
                    "and are scored once the tier 3 classifier exists."
                ),
            },
        }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _covered_chars(spans) -> dict[int, object]:
    """Character index -> the span covering it."""
    out: dict[int, object] = {}
    for s in spans:
        for i in range(s.start, s.end):
            out[i] = s
    return out


def _score_line(
    report: Report,
    text: str,
    occs: list[Occurrence],
    spans: list,
    group_state: dict[str, list[bool]],
) -> None:
    cover = _covered_chars(spans)
    report.total_spans += len(spans)

    matched_span_ids: set[int] = set()
    for occ in occs:
        spec = entities.BY_NAME.get(occ.entity_type)
        score = report.types.setdefault(
            occ.entity_type,
            TypeScore(occ.entity_type, expected_tier=spec.expected_tier if spec else ""),
        )
        score.seeded += 1
        hits = [cover.get(i) for i in range(occ.start, occ.end)]
        covering = {id(h): h for h in hits if h is not None}
        for h in covering.values():
            matched_span_ids.add(id(h))
        full = all(h is not None for h in hits)
        if full:
            score.covered += 1
            winner = next(iter(covering.values()))
            score.by_tier[winner.tier] += 1
            if spec and winner.entity_type in spec.detected_as:
                score.typed += 1
        elif covering:
            score.partial += 1
        if occ.group:
            group_state.setdefault(occ.group, []).append(full)

    # Spans that overlap nothing seeded. On a generated unit these are the
    # candidates for over-redaction, though some are legitimately sensitive
    # substrings the generator did not label, so this is reported as a raw
    # count and the clean unit carries the precision claim.
    report.unmatched_spans += sum(1 for s in spans if id(s) not in matched_span_ids)


def run(
    *,
    lines: int = 4000,
    seed: int = 20260820,
    include_custom: bool = True,
    include_adversarial: bool = True,
    include_ner: bool = False,
    label: str = "tier1-custom",
    corpus: generator.Corpus | None = None,
    vault_key: bytes = b"hider-eval-fixed-key",
    tiers: Sequence[pipeline.Tier] | None = None,
) -> tuple[Report, dict[str, list[str]]]:
    """Score one configuration. Returns the report and the redacted text per unit.

    ``include_ner`` adds the local NER tier when the model is available; it
    raises rather than silently skipping when the model is missing, because a
    tier that quietly did not run is how a recall figure ends up lying.
    """
    corp = corpus or generator.generate(lines=lines, seed=seed)
    vault = pseudonym.EntityVault(key=vault_key)
    if tiers is None:
        chosen: list[pipeline.Tier] = [pipeline.RegexTier(include_custom=include_custom)]
        if include_ner:
            chosen.append(ner.LocalNerTier())
    else:
        chosen = list(tiers)
    pipe = pipeline.Pipeline(chosen, vault=vault)
    ner_ran = any(getattr(t, "name", "") == "tier2" for t in chosen)

    report = Report(label=label)
    report.ner_enabled = ner_ran
    truth_by_line: dict[tuple[str, int], list[Occurrence]] = defaultdict(list)
    for occ in corp.truth:
        truth_by_line[(occ.unit, occ.line_no)].append(occ)

    group_state: dict[str, list[bool]] = {}
    redacted: dict[str, list[str]] = {}
    #: Lines of the hostile corpus that belong to a case with a documented gap.
    #: A value surviving there is a known, owned limitation, not a surprise.
    adv_gap_lines: set[int] = set()

    for unit in corp.units:
        out_lines: list[str] = []
        is_clean = unit.path in corp.clean_units
        for i, line in enumerate(unit.lines):
            r = pipe.redact(line, unit=unit.path, line_no=i)
            out_lines.append(r.text)
            occs = truth_by_line.get((unit.path, i), [])
            _score_line(report, line, occs, r.spans, group_state)
            if is_clean:
                report.clean_lines += 1
                if r.spans:
                    report.clean_lines_with_redaction += 1
                    report.clean_false_spans += len(r.spans)
        redacted[unit.path] = out_lines

    if include_adversarial:
        adv_lines, adv_truth, _ = adversarial.build(seed=seed)
        adv_truth_by_line: dict[int, list[Occurrence]] = defaultdict(list)
        for occ in adv_truth:
            adv_truth_by_line[occ.line_no].append(occ)
        shaped_seeded: Counter = Counter()
        shaped_covered: Counter = Counter()
        free_seeded: Counter = Counter()
        free_covered: Counter = Counter()
        # Rebuild the line -> case mapping the same way build() lays it out.
        line_case: dict[int, adversarial.Case] = {}
        n = 0
        for case in adversarial.CASES:
            for _ in case.template.split("\n"):
                line_case[n] = case
                n += 1

        for line_no, case in line_case.items():
            if not case.expect_tier1:
                adv_gap_lines.add(line_no)

        out_lines = []
        for i, line in enumerate(adv_lines):
            r = pipe.redact(line, unit=adversarial.UNIT, line_no=i)
            out_lines.append(r.text)
            occs = adv_truth_by_line.get(i, [])
            _score_line(report, line, occs, r.spans, group_state)
            case = line_case.get(i)
            if case and occs:
                cover = _covered_chars(r.spans)
                for occ in occs:
                    full = all(j in cover for j in range(occ.start, occ.end))
                    spec = entities.BY_NAME.get(occ.entity_type)
                    shaped = spec is not None and spec.expected_tier == entities.TIER_SHAPED
                    if shaped:
                        shaped_seeded[case.case_id] += 1
                        shaped_covered[case.case_id] += int(full)
                    else:
                        free_seeded[case.case_id] += 1
                        free_covered[case.case_id] += int(full)
        redacted[adversarial.UNIT] = out_lines
        report.injection_canaries = len(adversarial.INJECTION_CANARIES)
        report.cases = [
            CaseResult(
                case_id=c.case_id, description=c.description, expect_tier1=c.expect_tier1,
                shaped_seeded=shaped_seeded.get(c.case_id, 0),
                shaped_covered=shaped_covered.get(c.case_id, 0),
                free_seeded=free_seeded.get(c.case_id, 0),
                free_covered=free_covered.get(c.case_id, 0),
                owner=c.owner,
            )
            for c in adversarial.CASES
        ]

    report.groups_total = len(group_state)
    report.groups_caught = sum(1 for v in group_state.values() if all(v))

    # Verbatim survival: an exact-string search over the output, independent of
    # any offset arithmetic. If a seeded value can still be found in the text
    # that would be sent to a provider, the redaction did not happen, whatever
    # the span bookkeeping says.
    all_out = "\n".join("\n".join(v) for v in redacted.values())
    seen: set[str] = set()
    truth_all = list(corp.truth)
    if include_adversarial:
        truth_all += adv_truth
    for occ in truth_all:
        if len(occ.value) < 8 or occ.value in seen:
            continue
        seen.add(occ.value)
        if occ.value in all_out:
            spec = entities.BY_NAME.get(occ.entity_type)
            documented_case = (
                occ.unit == adversarial.UNIT and occ.line_no in adv_gap_lines
            )
            if spec is None or spec.expected_tier == entities.TIER_SHAPED:
                # No tier is allowed to miss this: either a tier 1 leak or an
                # unexplained failure. Fails the eval.
                reason, known_gap = "unexplained", False
            elif spec.expected_tier == entities.TIER_FREETEXT and ner_ran:
                # Tier 2 is a model; its misses are measured against a floor
                # (below_freetext_floor) rather than against zero, and shown
                # in the report as exactly what they are.
                reason, known_gap = "tier2 miss (probabilistic tier)", True
            else:
                reason, known_gap = "tier not built yet", True
            report.verbatim_survivors.append(
                {"entity_type": occ.entity_type, "unit": occ.unit, "line": occ.line_no,
                 "length": len(occ.value),
                 "expected_tier": spec.expected_tier if spec else "",
                 "reason": reason if not documented_case
                           else "documented adversarial gap",
                 "known_gap": known_gap or documented_case}
            )

    report.lines = pipe.stats.lines
    report.chars = pipe.stats.chars_in
    report.residue_chars = pipe.stats.residue_chars
    report.degraded_units = pipe.stats.degraded_units
    report.vault_size = vault.size
    for name, st in pipe.stats.tiers.items():
        report.tier_chars_offered[name] = st.chars_offered
        report.tier_chars_redacted[name] = st.chars_redacted
        report.tier_elapsed_s[name] = st.elapsed_s

    return report, redacted


def run_with_baseline(
    *, include_ner: bool | None = None, **kwargs
) -> tuple[Report, Report, dict[str, list[str]], generator.Corpus]:
    """Run the full configuration and the stock-Presidio baseline on one corpus.

    ``include_ner`` defaults to "on when the NER model is installed", so the
    shipped numbers describe the shipped configuration wherever the repo is
    run with the model present. Passing True when the model is missing raises,
    for the same reason ``run(include_ner=True)`` does.
    """
    lines = kwargs.pop("lines", 4000)
    seed = kwargs.pop("seed", 20260820)
    if include_ner is None:
        include_ner = ner.available()
    elif include_ner and not ner.available():
        raise RuntimeError(
            "include_ner=True but the spaCy model is not installed; "
            "run: pip install https://github.com/explosion/spacy-models/releases/"
            "download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
        )
    corp = generator.generate(lines=lines, seed=seed)
    full, redacted = run(corpus=corp, seed=seed, include_custom=True,
                         include_ner=include_ner,
                         label="presidio + custom recognizers + local NER", **kwargs)
    base, _ = run(corpus=corp, seed=seed, include_custom=False,
                  label="stock Presidio patterns only", **kwargs)
    return full, base, redacted, corp


def save(report: Report, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
