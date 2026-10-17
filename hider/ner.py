"""Tier 2: local, in-process NER over the tier-1 residue. Phase 2, built.

Free-text names and organisations have no shape to match, so tier 1 is designed
to miss them. This tier is what sees them instead: Presidio's NLP engine
(``SpacyNlpEngine``, spaCy under it) run over the residue segments only, which
is the parts of the text tier 1 did not claim.

Design constraints, in the order they were decided:

* **In-process, not a managed service.** The shipped implementation runs inside
  the operator's own process. Nothing about a name that tier 2 examines ever
  leaves the machine, which is a strictly stronger boundary than "inside your
  cloud account". The managed-service variant remains a documented contract in
  ``pipeline.ManagedNerTier`` for operators who out-scale a local model; the
  engine treats the two identically, as one tier slot.
* **Residue only.** ``detect`` receives the segments tier 1 left unclaimed and
  bills itself (in ``Pipeline.stats``) against those characters, never the
  whole line. A paid or remote variant of this tier would be billed the same
  way, which is the entire cost argument for tiering.
* **Memoised by content hash.** The sync proxy path resends the whole
  conversation on every chat turn; without memoisation the same history would
  be re-analysed on each request.
* **Fail closed.** An engine error propagates out of ``detect`` and the
  pipeline marks the unit degraded and keeps earlier coverage; it never
  degrades to passthrough. That behaviour is the pipeline's, not this tier's,
  and it is tested there.
* **Probabilistic, and reported as such.** Unlike tier 1, this tier can miss.
  The eval harness therefore gates it on a measured recall floor rather than
  on zero survivors, and prints the two gates separately instead of blending
  them into one number.

Only PERSON and ORGANIZATION are mapped. spaCy emits many more labels (DATE,
CARDINAL, LAW, ...) and redacting them would gut the bundle: timestamps and
counts are most of what makes a log readable. A narrow tier that owns its
misses honestly beats a broad one that redacts dates.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Sequence
from typing import Protocol

from .pipeline import Span

#: Raw NER labels this tier maps to spec entity types. The keys are spaCy's
#: labels; Presidio's NLP engine already normalises ORG to ORGANIZATION when
#: it hands the spans over, both are accepted to be robust to that mapping
#: being configured either way.
LABEL_MAP = {
    "PERSON": "PERSON",  # -> PERSON_NAME via the canonical type map
    "ORG": "ORGANIZATION",  # -> ORG_NAME
    "ORGANIZATION": "ORGANIZATION",
}

#: Confidence assigned to a mapped span. spaCy gives per-token probabilities
#: that are not comparable across labels; a flat score above the pipeline's
#: ``min_score`` floor is the honest representation of "the model said so".
SPAN_SCORE = 0.8

_CACHE_MAX = 4096


class NlpEngine(Protocol):
    """The slice of Presidio's NLP engine this tier needs."""

    def process_text(self, text: str, language: str): ...


def default_engine() -> NlpEngine:
    """Presidio's spaCy engine, loaded with the small English model.

    Raises if the model is not installed, deliberately: a tier 2 that silently
    cannot run is a redaction layer that looks deployed and is not. Callers
    who want optional NER should probe with :func:`available` first.
    """
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
    engine.load()
    return engine


def available() -> bool:
    """True when the NER model is importable in this environment."""
    import importlib.util

    return importlib.util.find_spec("en_core_web_sm") is not None


# ---------------------------------------------------------------------------
# Suppression: the precision half, same discipline as tier 1
# ---------------------------------------------------------------------------

#: A single token is only name-like if it is a plain word of 3+ characters
#: with exactly one capital letter. The one-capital condition is what removes
#: CamelCase identifiers ("TimeoutMs", "MaxParallelJobs"): a config key is a
#: word welded out of several words, and the uppercase junction in the middle
#: is its signature. Real prose names ("Anna", "Northwind") carry a single
#: capital.
_NAME_LIKE = re.compile(r"^[A-Za-z]{3,}$")

#: Log and JSON structure. A span containing brackets, braces, quotes,
#: slashes or colons is a fragment of machinery ("Cache] Evicted", "MB/s."),
#: not a name; the model glued it across structure that a person never
#: appears inside. Together with the rule above this removes the classic NER
#: noise in logs: "ETA", job policy codes such as "Daily-EXCH-AUS", unit
#: suffixes, field names. None of them are organisations no matter what the
#: model says, and redacting them is the over-redaction that makes engineers
#: stop using the tool.
_STRUCTURAL = re.compile(r"[\]}\[{:\"/\\|<>]")

#: Articles the model likes to glue onto organisation spans ("the Daily-...").
#: The span is trimmed to the name; if nothing name-like remains, it is
#: dropped entirely.
_LEADING_ARTICLE = re.compile(r"^(?:the|a|an)\s+", re.IGNORECASE)


def _is_name_like(token: str) -> bool:
    return (
        bool(_NAME_LIKE.match(token))
        and any(c.islower() for c in token)
        and sum(c.isupper() for c in token) == 1
    )


def suppress(entities: Sequence[tuple[int, int, str, str]]) -> list[tuple[int, int, str]]:
    """Apply the tier 2 precision rules to ``(start, end, label, text)`` tuples.

    Returns ``(start, end, label)`` triples, trimmed and filtered. Every rule
    is named and tested; this is the only place tier 2 removes protection.
    """
    out: list[tuple[int, int, str]] = []
    for start, end, label, text in entities:
        if _STRUCTURAL.search(text):
            continue
        if label == "ORGANIZATION":
            trimmed = _LEADING_ARTICLE.sub("", text)
            if not trimmed:
                continue
            start = start + (len(text) - len(trimmed))
            text = trimmed
            end = start + len(trimmed)
        # A name is made of words, and a word carries lowercase letters.
        # Quantities ("8301 MB"), versions ("v3.1") and acronyms ("ETA",
        # "MB") are not, whatever the model says.
        if not any(any(c.islower() for c in tok) for tok in text.split()):
            continue
        if " " not in text.strip() and "\t" not in text.strip():
            # Single-token span: must look like a name to survive.
            if not _is_name_like(text.strip()):
                continue
        out.append((start, end, label))
    return out


class LocalNerTier:
    """The tier 2 slot: local NER over the residue, memoised, fail-closed."""

    name = "tier2"
    cost_per_1k_chars = 0.0  # in-process; the managed variant prices itself

    def __init__(self, engine: NlpEngine | None = None, *, language: str = "en"):
        self.engine = engine if engine is not None else default_engine()
        self.language = language
        self._cache: dict[str, list[tuple[int, int, str]]] = {}
        self._lock = threading.Lock()

    # -- detection ---------------------------------------------------------

    def _analyse(self, segment: str) -> list[tuple[int, int, str]]:
        key = hashlib.sha256(segment.encode("utf-8")).hexdigest()
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        artifacts = self.engine.process_text(segment, self.language)
        raw = [
            (e.start_char, e.end_char, LABEL_MAP[e.label_], segment[e.start_char : e.end_char])
            for e in artifacts.entities
            if e.label_ in LABEL_MAP
        ]
        spans = suppress(raw)
        with self._lock:
            if len(self._cache) >= _CACHE_MAX:
                self._cache.clear()
            self._cache[key] = spans
        return spans

    def detect(self, text: str, residue: Sequence[tuple[int, int]]) -> list[Span]:
        out: list[Span] = []
        for start, end in residue:
            segment = text[start:end]
            if not segment.strip():
                continue
            for s, e, label in self._analyse(segment):
                out.append(
                    Span(
                        start + s,
                        start + e,
                        label,
                        SPAN_SCORE,
                        self.name,
                        detector=f"spacy:{label}",
                    )
                )
        return out
