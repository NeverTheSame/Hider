"""Tier 2: a trained classifier over free-text residue.

Person and organisation names have no shape a regex can own, so tier 1 is
expected to miss them by design (``entities.TIER_FREETEXT``). This module is
the small, locally trained model that tier 2 runs instead of a hypothetical
managed cloud service: a per-token BIO classifier over the characters tier 1
left behind.

The training data is generated here, from its own vocabulary of first names,
last names and organisation words that is deliberately disjoint from the one
in ``entities.py``. That split is not cosmetic. ``entities.py`` is what the
eval corpus is seeded from; if this module trained on the same strings, a
lookup table could hit 100% recall on the eval set by memorising eight org
names and twenty-eight given names, and the number would say nothing about
whether the model generalises past that dictionary. Training on a disjoint
vocabulary forces the model to key on shape and context - capitalisation,
sentence position, the words around a mention - which is the only thing that
transfers to a real bundle, where nobody's name is in this file.

One overlap is deliberate and should be named rather than glossed over: the
``_ORG_SUFFIX_WORDS`` feature list contains the same generic corporate suffixes
the eval corpus builds organisation names from (holdings, group, partners,
industries, advisory, ag). The names and the organisation head-words are
disjoint; the suffix list is not. It is a hand-written feature encoding generic
domain knowledge, not memorised answers, and "Ltd" would be in it whatever the
eval corpus looked like. But it does lift organisation recall relative to a
corpus whose suffixes the list has never seen, so the honest phrasing is
"disjoint except for the generic corporate-suffix feature list".

Known limitation, stated the way the rest of this project states them: a
linear per-token classifier with a two-name-per-organisation-suffix training
grammar is a small model. It will not match a production NER system's recall,
and its errors are reported in ``hider eval`` rather than assumed away.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Sequence

from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression

# ---------------------------------------------------------------------------
# Training vocabulary - disjoint from entities.py by construction
# ---------------------------------------------------------------------------

_TRAIN_FIRST = [
    "mateo", "freya", "kwame", "ivy", "luca", "nadia", "oskar", "ren",
    "talia", "viktor", "elin", "boas", "sana", "irwin", "meret",
]
_TRAIN_LAST = [
    "berg", "calderon", "dubois", "eriksen", "farah", "giles", "hoxha",
    "imai", "jansen", "kade", "lund", "mercer", "nkemdirim",
]
_TRAIN_ORG_WORDS = ["Meridian", "Vantage", "Solace", "Anchorpoint", "Cobalt", "Driftwood"]
_TRAIN_ORG_SUFFIX = ["Systems", "Networks", "Holdings", "Collective", "Works"]

#: Capitalised single tokens that recur in the log templates but are never a
#: person or org: component tags, bracketed subsystem names, job names. These
#: are the words a naive title-case heuristic would flag, so they are trained
#: as hard negatives rather than left for the classifier to guess about.
_HARD_NEGATIVES = [
    "Session", "Transport", "Retry", "Scheduler", "Stats", "Service", "Queue",
    "Cache", "Info", "Warning", "Error", "Debug", "Audit", "Backup", "Restore",
    "Agent", "Mail", "Graph", "Net", "Dump", "Auth", "Monday", "Tuesday",
    "Wednesday", "January", "February", "Exchange", "SharePoint", "Outlook",
    "Teams", "Engineering", "Support", "Finance", "Legal",
]

_TRIGGER_WORDS = {
    "spoke", "escalated", "reported", "reassigned", "called", "notified",
    "confirmed", "contacted", "informed", "from", "to", "at", "with",
    "loop", "reached", "on", "behalf", "of",
}

_ORG_SUFFIX_WORDS = {w.lower() for w in _TRAIN_ORG_SUFFIX} | {
    "inc", "corp", "corporation", "group", "partners", "holdings",
    "industries", "advisory", "ag", "llc", "ltd",
}

_SENTENCE_TEMPLATES = [
    "Spoke to {P} at {O}; will follow up tomorrow.",
    "Escalated the ticket to {P} from {O} support.",
    "{P} confirmed the restore completed for {O}.",
    "Please loop in {P} before contacting {O} again.",
    "Case reassigned from {P} to the {O} team.",
    "{P} reported the issue on behalf of {O}.",
    "No response yet from {P}; the {O} account is still blocked.",
    "Called {O} and reached {P} directly.",
    "{P} from {O} confirmed the backup window.",
    "Notified {P} that {O} needs a new access token.",
    "{O} escalated through {P} this morning.",
    "{P} closed the case after contacting {O}.",
]

#: Sentences with no seeded entity at all, so the model also learns what a
#: clean line looks like and does not treat every capitalised word as a hit.
_NEGATIVE_TEMPLATES = [
    "{N1} flagged a warning in the {N2} module overnight.",
    "The {N1} job finished before the {N2} window closed.",
    "{N1} and {N2} both reported the same retry count.",
    "Nothing further from the {N1} or {N2} subsystem today.",
    "{N1} logging was quiet; {N2} picked up the load.",
]

_TOKEN_RE = re.compile(r"[A-Za-z]+|[0-9]+|[^\sA-Za-z0-9]")

O_TAG = "O"


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


def tokenize(text: str) -> list[Token]:
    return [Token(m.group(0), m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


def _shape(word: str) -> str:
    if word.isdigit():
        return "digit"
    if word.isupper() and word.isalpha():
        return "upper"
    if word.istitle():
        return "title"
    if word.islower():
        return "lower"
    return "mixed"


def _token_features(tokens: Sequence[Token], i: int) -> dict:
    tok = tokens[i]
    w = tok.text
    prev_w = tokens[i - 1].text if i > 0 else "<START>"
    next_w = tokens[i + 1].text if i + 1 < len(tokens) else "<END>"
    return {
        "bias": 1.0,
        "word.lower": w.lower(),
        "word.shape": _shape(w),
        "word.isalpha": w.isalpha(),
        "word.len": len(w),
        "word.prefix3": w[:3].lower(),
        "word.suffix3": w[-3:].lower(),
        "position.first": i == 0,
        "position.last": i == len(tokens) - 1,
        "prev.lower": prev_w.lower(),
        "prev.istitle": prev_w.istitle(),
        "prev.is_trigger": prev_w.lower() in _TRIGGER_WORDS,
        "next.lower": next_w.lower(),
        "next.istitle": next_w.istitle(),
        "next.is_org_suffix": next_w.lower() in _ORG_SUFFIX_WORDS,
        "word.is_org_suffix": w.lower() in _ORG_SUFFIX_WORDS,
    }


def featurize(tokens: Sequence[Token]) -> list[dict]:
    return [_token_features(tokens, i) for i in range(len(tokens))]


# ---------------------------------------------------------------------------
# BIO labelling of synthetic sentences
# ---------------------------------------------------------------------------


def _label_tokens(tokens: Sequence[Token], spans: Sequence[tuple[int, int, str]]) -> list[str]:
    labels = [O_TAG] * len(tokens)
    for start, end, etype in spans:
        first = True
        for i, tok in enumerate(tokens):
            if tok.start >= start and tok.end <= end:
                labels[i] = f"{'B' if first else 'I'}-{etype}"
                first = False
    return labels


def _render_sentence(rng: random.Random) -> tuple[str, list[tuple[int, int, str]]]:
    if rng.random() < 0.25:
        n1, n2 = rng.sample(_HARD_NEGATIVES, 2)
        template = rng.choice(_NEGATIVE_TEMPLATES)
        return template.format(N1=n1, N2=n2), []

    person = f"{rng.choice(_TRAIN_FIRST).capitalize()} {rng.choice(_TRAIN_LAST).capitalize()}"
    org = f"{rng.choice(_TRAIN_ORG_WORDS)} {rng.choice(_TRAIN_ORG_SUFFIX)}"
    template = rng.choice(_SENTENCE_TEMPLATES)
    text = template.format(P=person, O=org)
    spans = []
    p_start = text.index(person)
    spans.append((p_start, p_start + len(person), "PERSON"))
    o_start = text.index(org)
    spans.append((o_start, o_start + len(org), "ORGANIZATION"))
    return text, spans


def training_examples(seed: int, n_sentences: int) -> tuple[list[dict], list[str]]:
    rng = random.Random(seed)
    features: list[dict] = []
    labels: list[str] = []
    for _ in range(n_sentences):
        text, spans = _render_sentence(rng)
        tokens = tokenize(text)
        features.extend(featurize(tokens))
        labels.extend(_label_tokens(tokens, spans))
    return features, labels


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass
class TrainedNerClassifier:
    vectorizer: DictVectorizer
    model: LogisticRegression
    seed: int
    n_sentences: int


def train(seed: int = 20260821, n_sentences: int = 500) -> TrainedNerClassifier:
    features, labels = training_examples(seed, n_sentences)
    vec = DictVectorizer(sparse=True)
    x = vec.fit_transform(features)
    clf = LogisticRegression(max_iter=500, class_weight="balanced")
    clf.fit(x, labels)
    return TrainedNerClassifier(vectorizer=vec, model=clf, seed=seed, n_sentences=n_sentences)


@lru_cache(maxsize=4)
def get_trained(seed: int = 20260821, n_sentences: int = 500) -> TrainedNerClassifier:
    """Process-wide cache: training takes well under a second, but eval and the
    pipeline both build tiers repeatedly, and retraining on every construction
    would make the identical model a fresh random draw of nothing - the fit is
    deterministic for a fixed seed, so there is nothing gained by repeating it."""
    return train(seed=seed, n_sentences=n_sentences)


def _decode_bio(tokens: Sequence[Token], labels: Sequence[str], scores: Sequence[float]
                 ) -> list[tuple[int, int, str, float]]:
    spans: list[tuple[int, int, str, float]] = []
    i = 0
    while i < len(tokens):
        label = labels[i]
        if label == O_TAG:
            i += 1
            continue
        etype = label.split("-", 1)[1]
        start = tokens[i].start
        end = tokens[i].end
        span_scores = [scores[i]]
        j = i + 1
        while j < len(tokens) and labels[j] in (f"I-{etype}",):
            end = tokens[j].end
            span_scores.append(scores[j])
            j += 1
        spans.append((start, end, etype, sum(span_scores) / len(span_scores)))
        i = j
    return spans


def predict_spans(clf: TrainedNerClassifier, text: str) -> list[tuple[int, int, str, float]]:
    """Label ``text`` and return (start, end, entity_type, score) spans.

    ``text`` is expected to already be the residue tier 1 left behind - a
    substring, not the full line - so offsets returned here are relative to
    that substring and the caller is responsible for shifting them back.
    """
    tokens = tokenize(text)
    if not tokens:
        return []
    feats = featurize(tokens)
    x = clf.vectorizer.transform(feats)
    labels = list(clf.model.predict(x))
    proba = clf.model.predict_proba(x)
    classes = list(clf.model.classes_)
    scores = [proba[i, classes.index(labels[i])] for i in range(len(labels))]
    return _decode_bio(tokens, labels, scores)
