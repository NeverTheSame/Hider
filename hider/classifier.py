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

The suffix grammar was widened after measurement, not by inspection. The
first grammar drew every organisation as a head word plus one of five
title-case suffixes, so the model never saw a short all-caps legal form
("GmbH", "PLC") inside an organisation and labelled every one it met as a
stray acronym: all 45 misses in one eval run were the same two-letter
suffix. The grammar now draws one- and two-word heads, title-case and
abbreviated suffixes, sentences with only a person or only an organisation,
and hard negatives built from the acronyms a support log is full of (ETA,
SLA, VPN), so that "capitals after a name" is not by itself a signal. The
eval corpus's own suffixes are still not in the training set; the lift has
to come from shape.

A second grammar, ``notes=True``, adds markdown lines to the training set
(headings, table rows, bold labels before a colon, list items) and four
features that describe a line's structure. A case note is made of those
lines, and the log and support-sentence grammar never showed the model one.
The default model is the logs-only one and is exactly what it was.

Known limitation, stated the way the rest of this project states them: a
linear per-token classifier trained on a generated grammar is a small model.
It will not match a production NER system's recall, and its errors are
reported in ``hider eval`` rather than assumed away.
"""

from __future__ import annotations

import bisect
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
_TRAIN_ORG_WORDS = [
    "Meridian", "Vantage", "Solace", "Anchorpoint", "Cobalt", "Driftwood",
    "Lantern", "Quarry", "Juniper", "Beacon", "Ridgeline", "Halcyon", "Orchard",
    "Harbor",
]
#: Organisation suffixes the grammar draws from. Two shapes on purpose: the
#: title-case trade words, and the short legal forms most of the world's
#: company registers use, which are abbreviations and so arrive in capitals or
#: mixed case. The eval corpus's suffixes (``entities._ORG_SUFFIX``) are kept
#: out of this list except for the pre-existing "Holdings" overlap, so a
#: suffix the eval uses is one the model has to recognise from shape and from
#: the generic ``_ORG_SUFFIX_WORDS`` feature, never from having been trained on
#: that exact string.
_TRAIN_ORG_SUFFIX = [
    "Systems", "Networks", "Holdings", "Collective", "Works", "Technology",
    "Logistics", "Consulting", "Labs", "Software", "Energy", "Capital",
    "GmbH", "PLC", "LLC", "Ltd", "Inc", "Corp", "SA", "NV", "BV", "Oy", "AB",
    "SE", "KG", "SpA", "Pty",
]

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

#: All-caps tokens that recur in support prose and are never an organisation
#: suffix: units, protocols, service terms. Without these the widened suffix
#: grammar teaches "short capitals after a capitalised word is an
#: organisation", and "Scheduler API" or "the Transport SLA" would be
#: redacted. They are trained as negatives in the positions a suffix occupies.
_HARD_ACRONYMS = [
    "ETA", "SLA", "VPN", "DNS", "API", "SSO", "MFA", "CPU", "RAM", "URL",
    "UTC", "GB", "MB", "TLS", "HTTP", "ID", "OK", "PST", "CET",
]

#: Title-case words that open a log message after a bracketed component tag,
#: and camel-case configuration keys. Neither is a name, both are what a
#: support bundle is mostly made of, and both sit in exactly the position the
#: organisation-only templates put an organisation: first capitalised token
#: after punctuation. They are trained as negatives in log-shaped lines so the
#: model learns the structure (a tag bracket, a quote, inner capitals) rather
#: than having to know the word.
_LOG_VERBS = [
    "Compaction", "Throttle", "Checkpoint", "Replication", "Indexing",
    "Encryption", "Snapshot", "Rotation", "Flushing", "Verification",
    "Handshake", "Throughput", "Enumerating", "Deduplication",
]
_CONFIG_KEYS = [
    "MaxRetries", "BatchSize", "PollIntervalMs", "ThreadCount", "QueueDepth",
    "RetryBudget", "ChunkBytes", "KeepAliveSec", "MaxItems", "FlushEveryMs",
]

_TRIGGER_WORDS = {
    "spoke", "escalated", "reported", "reassigned", "called", "notified",
    "confirmed", "contacted", "informed", "from", "to", "at", "with",
    "loop", "reached", "on", "behalf", "of", "contact", "notify", "ask",
    "ping", "call", "cc", "per", "for",
}

_ORG_SUFFIX_WORDS = {w.lower() for w in _TRAIN_ORG_SUFFIX} | {
    "inc", "corp", "corporation", "group", "partners", "holdings",
    "industries", "advisory", "ag", "llc", "ltd", "sarl", "sas", "srl",
    "oyj", "as", "aps", "kk", "co", "company", "limited", "technologies",
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
    "{O} wants a root cause by Friday; {P} is the contact.",
    "Call with {P} ({O}) ended without a decision.",
    "Tenant belongs to {O}, primary admin {P}.",
    "{P} at {O} approved the maintenance window.",
    "Vendor {O} confirmed the outage; {P} relayed it.",
    "Sent the summary to {P}, copying the {O} service desk.",
    "Per {P}, {O} will migrate next quarter.",
]

#: Sentences with one entity type only. The two-entity templates above teach
#: a person and an organisation as a pair; a real note mentions one without
#: the other at least as often, and a model that has only seen pairs leans on
#: the pair as context.
_PERSON_ONLY_TEMPLATES = [
    "{P} asked for a status update.",
    "Handover: {P} takes over the case tomorrow.",
    "{P} confirmed the mailbox is restored.",
    "Left a voicemail for {P}.",
    "Contact {P} about this.",
    "Notify {P} once the restore completes.",
    "Ask {P} for a fresh bundle before Friday.",
    "Ping {P} if the queue is still blocked.",
]
_ORG_ONLY_TEMPLATES = [
    "Escalation from {O}: the restore is still queued.",
    "{O} reported the issue through the portal.",
    "The {O} tenant was re-indexed overnight.",
    "Waiting on {O} for the change approval.",
    "Customer note: {O} is asking for an update on the restore.",
]

#: Sentences with no seeded entity at all, so the model also learns what a
#: clean line looks like and does not treat every capitalised word as a hit.
_NEGATIVE_TEMPLATES = [
    "{N1} flagged a warning in the {N2} module overnight.",
    "The {N1} job finished before the {N2} window closed.",
    "{N1} and {N2} both reported the same retry count.",
    "Nothing further from the {N1} or {N2} subsystem today.",
    "{N1} logging was quiet; {N2} picked up the load.",
    "{N1} is asking for an {A} on the {N2} queue.",
    "The {N1} {A} returned {A2} after the retry.",
    "{N1} {A} and {N2} {A2} are both healthy.",
    "Checked the {A} for the {N1} module; {A2} is fine.",
    "[{N1}] {V} level {D}, window {D} ms",
    "<{D}> Info     [{N1}] {V} finished for {D} items in {D} ms",
    "[{N1}] {V} started, {N2} {A} reported {D}",
    '  "{N1}": {{ "{K}": {D}, "{K2}": {D} }},',
    '{{"{K}":{D},"{K2}":{D},"msg":"{V}"}}',
    "{V} of the {N1} store completed with code {D}.",
]

#: The notes grammar's own words: headings, column heads, labels and feature
#: phrases of a case note, invented and generic. Disjoint from ``entities.py``
#: and from the name vocabulary above (a test pins both), so a heading word is
#: never also a name the model was shown.
_NOTE_PHRASE_WORDS = [
    "Summary", "Timeline", "Findings", "Overview", "Background", "Resolution",
    "Impact", "Symptoms", "Workaround", "Details", "Scope", "Environment",
    "Decision", "Evidence", "History", "Request", "Cause", "Update", "Review",
    "Plan", "Questions", "Steps", "Actions", "Observations", "Outcome",
]
_NOTE_FEATURE_WORDS = [
    "Retention", "Policy", "Wizard", "Window", "Schedule", "Repository",
    "Proxy", "Console", "Dashboard", "Report", "Settings", "Gateway",
    "Connector", "Catalog", "Archive", "Mapping", "Rule", "Filter", "Queue",
    "Template", "Profile", "Workflow",
]
#: Words that open a two-word label ("Next Steps"), so a label that opens
#: with a word the model never saw is still read by the word after it.
_NOTE_LEAD_WORDS = [
    "Next", "Known", "Current", "Further", "Recent", "Remaining", "Main",
    "Final", "Related", "Previous",
]
_NOTE_COLUMN_WORDS = [
    "Item", "Status", "Owner", "Date", "Count", "Result", "Priority",
    "Severity", "Ticket", "Component", "Version", "Comment", "Reference",
    "Action", "Due", "Region", "Type", "Reviewer",
]
_NOTE_STATUS_WORDS = [
    "open", "closed", "pending", "resolved", "waiting", "blocked", "done",
    "new", "retry", "verified", "queued", "failed", "skipped", "stale",
]
_NOTE_PERSON_LABELS = [
    "Owner", "Contact", "Engineer", "Reporter", "Assignee", "Requester",
    "Manager", "Author", "Admin", "Approver",
]
_NOTE_ORG_LABELS = [
    "Customer", "Account", "Tenant", "Client", "Vendor", "Partner", "Company",
]

#: Cumulative shares of the ten kinds of note line, in the order
#: ``_render_note_line`` tests them: heading, table header, bold label, list
#: item with a feature phrase, sentence with a feature phrase, person in a
#: cell, person after a label, person in a list item, person before a colon
#: (a pasted chat or mail line), person who opens the line, organisation in a
#: cell, organisation after a label; the rest is an organisation in a list item.
_NOTE_MIX = (0.04, 0.07, 0.11, 0.15, 0.18, 0.33, 0.50, 0.64, 0.74, 0.84, 0.92, 0.97)

#: Note-shaped lines with a person. ``{L}`` is a person label, ``{P}`` the
#: person, ``{W}`` a lowercase word, ``{D}`` a number.
_NOTE_PERSON_LIST_TEMPLATES = [
    "- {P} confirmed the restore completed.",
    "- {P} will follow up on {W} items tomorrow.",
    "* {P} asked for a status update.",
    "1. {P} takes over the case.",
    "- Waiting on {P} for the {W} review.",
    "- {P} reported the issue twice.",
    "2. Handover to {P} after the call.",
]
#: What follows a person and a colon in a pasted chat or mail line: lowercase.
_NOTE_CHAT_TEXTS = [
    "can you send the {W} logs again?",
    "the export finished on my side.",
    "i will look at it after lunch.",
    "no change after the restart.",
    "thanks, that worked.",
    "still seeing the same error here.",
    "the {W} items are back now.",
]
#: A person who opens the line with no marker, then a lowercase word.
_NOTE_PERSON_OPEN_TEMPLATES = [
    "{P} restarted the {W} job after the call.",
    "{P} sent two screenshots of the error.",
    "{P} is out until {D} and asked us to wait.",
    "{P} from {O} joined the call at {D}.",
    "{P} shared a new export with {W} items.",
    "{P} agreed to try the workaround tonight.",
]
_NOTE_ORG_LIST_TEMPLATES = [
    "- {O} reported the issue through the portal.",
    "* Waiting on {O} for the change approval.",
    "- The {O} tenant was re-indexed overnight.",
]
#: Note-shaped lines with no name: list items that open with a capitalised
#: phrase, and sentences with a feature phrase in the middle.
_NOTE_LIST_NEGATIVE_TEMPLATES = [
    "- {F} was reviewed after the change.",
    "* {F} fails on the {W} step.",
    "1. {F} still shows {W} items.",
    "- {F}: {W} since the last run.",
    "- **{F}**: {W} after the retry.",
]
_NOTE_SENTENCE_NEGATIVE_TEMPLATES = [
    "The {F} setting was changed before the {W} run.",
    "Opened the {F} page and checked the {W} entries.",
    "After the change the {F} showed {D} items.",
    "Customer confirmed the {F} is {W} now.",
    "Switched the {F} to {W} and retried.",
    "The issue is in the {F} when a {W} item is added.",
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


_HEADING_RE = re.compile(r"\s*#{1,6}\s")
_BOLD_RE = re.compile(r"\*\*|__")


def _structure(tokens: Sequence[Token], text: str) -> list[dict]:
    """Four features per token that describe the line it stands on.

    ``line.heading``: the line opens with one to six hash signs and a blank,
    a markdown heading. ``token.in_pipes``: a pipe stands before the token and
    another after it on the line, a table cell. ``token.in_bold``: an odd
    number of bold marks (``**`` or ``__``) stand before it on the line.
    ``phrase.before_colon``: the run of words the token starts, four at most,
    is followed by a colon, with bold marks allowed between: a label. Its
    value says what follows the colon on the line: ``"end"`` nothing (a
    heading-like label), ``"short"`` one or two words (a label and its value),
    ``"long"`` three or more (a speaker and what they wrote); ``False`` when
    the run is not followed by a colon.
    They read only the text of the line the token stands on; the run of words
    ends with the line.
    """
    out: list[dict] = []
    cache: dict[int, tuple[bool, list[int], list[int], int]] = {}
    for i, tok in enumerate(tokens):
        ls = text.rfind("\n", 0, tok.start) + 1
        if ls not in cache:
            le = text.find("\n", ls)
            le = le if le >= 0 else len(text)
            line = text[ls:le]
            cache[ls] = (bool(_HEADING_RE.match(line)),
                         [m.start() + ls for m in re.finditer(r"\|", line)],
                         [m.start() + ls for m in _BOLD_RE.finditer(line)], le)
        heading, pipes, bolds, le = cache[ls]
        on_line = lambda t: ls <= t.start and t.end <= le
        j, run = i, 0
        while j < len(tokens) and tokens[j].text.isalpha() and on_line(tokens[j]):
            j, run = j + 1, run + 1
        while j < len(tokens) and tokens[j].text == "*" and on_line(tokens[j]):
            j += 1
        colon: bool | str = False
        if 0 < run <= 4 and j < len(tokens) and tokens[j].text == ":" and on_line(tokens[j]):
            rest = sum(1 for t in tokens[j + 1:] if on_line(t) and t.text != "*")
            colon = "end" if rest == 0 else "short" if rest <= 2 else "long"
        k = bisect.bisect_left(pipes, tok.start)
        out.append({
            "line.heading": heading,
            "token.in_pipes": 0 < k < len(pipes),
            "token.in_bold": bisect.bisect_left(bolds, tok.start) % 2 == 1,
            "phrase.before_colon": colon,
        })
    return out


def _token_features(tokens: Sequence[Token], i: int) -> dict:
    tok = tokens[i]
    w = tok.text
    prev_w = tokens[i - 1].text if i > 0 else "<START>"
    next_w = tokens[i + 1].text if i + 1 < len(tokens) else "<END>"
    prev2_w = tokens[i - 2].text if i > 1 else "<START>"
    next2_w = tokens[i + 2].text if i + 2 < len(tokens) else "<END>"
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
        "word.inner_caps": any(ch.isupper() for ch in w[1:]) and not w.isupper(),
        "prev.is_punct": not prev_w.isalnum(),
        "next.is_punct": not next_w.isalnum(),
        "next.is_digit": next_w.isdigit(),
        # Second neighbours separate "Contact Sofia Tanaka" (a verb, then two
        # capitalised tokens) from "Ingrid Moreau from" (a name, then one).
        "prev2.istitle": prev2_w.istitle(),
        "next2.istitle": next2_w.istitle(),
        "prev.lower": prev_w.lower(),
        "prev.istitle": prev_w.istitle(),
        "prev.is_trigger": prev_w.lower() in _TRIGGER_WORDS,
        "next.lower": next_w.lower(),
        "next.istitle": next_w.istitle(),
        "next.is_org_suffix": next_w.lower() in _ORG_SUFFIX_WORDS,
        "word.is_org_suffix": w.lower() in _ORG_SUFFIX_WORDS,
    }


def featurize(tokens: Sequence[Token], text: str | None = None,
              notes: bool = False) -> list[dict]:
    """Features per token. With ``notes`` the four structure features are
    added, read from ``text``; without it the dictionary is what it always was."""
    feats = [_token_features(tokens, i) for i in range(len(tokens))]
    if notes:
        if text is None:
            raise ValueError("notes features read the line: pass text")
        for f, extra in zip(feats, _structure(tokens, text)):
            f.update(extra)
    return feats


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


def _draw_person(rng: random.Random) -> str:
    return f"{rng.choice(_TRAIN_FIRST).capitalize()} {rng.choice(_TRAIN_LAST).capitalize()}"


def _draw_org(rng: random.Random) -> str:
    """One- or two-word head plus a suffix, so the model sees organisations
    of two and three tokens and learns that I-ORGANIZATION can continue."""
    heads = rng.sample(_TRAIN_ORG_WORDS, 2 if rng.random() < 0.3 else 1)
    return " ".join(heads + [rng.choice(_TRAIN_ORG_SUFFIX)])


def _render_sentence(rng: random.Random) -> tuple[str, list[tuple[int, int, str]]]:
    roll = rng.random()
    if roll < 0.3:
        n1, n2 = rng.sample(_HARD_NEGATIVES, 2)
        a1, a2 = rng.sample(_HARD_ACRONYMS, 2)
        k1, k2 = rng.sample(_CONFIG_KEYS, 2)
        template = rng.choice(_NEGATIVE_TEMPLATES)
        text = template.format(N1=n1, N2=n2, A=a1, A2=a2, K=k1, K2=k2,
                               V=rng.choice(_LOG_VERBS), D=rng.randint(1, 9999))
        return text, []

    spans: list[tuple[int, int, str]] = []
    if roll < 0.4:
        person = _draw_person(rng)
        text = rng.choice(_PERSON_ONLY_TEMPLATES).format(P=person)
        entities = [(person, "PERSON")]
    elif roll < 0.5:
        org = _draw_org(rng)
        text = rng.choice(_ORG_ONLY_TEMPLATES).format(O=org)
        entities = [(org, "ORGANIZATION")]
    else:
        person, org = _draw_person(rng), _draw_org(rng)
        text = rng.choice(_SENTENCE_TEMPLATES).format(P=person, O=org)
        entities = [(person, "PERSON"), (org, "ORGANIZATION")]
    for value, etype in entities:
        start = text.index(value)
        spans.append((start, start + len(value), etype))
    return text, spans


def _phrase(rng: random.Random, pool: Sequence[str], lo: int = 1, hi: int = 3) -> str:
    return " ".join(rng.sample(list(pool), rng.randint(lo, hi)))


def _cells(rng: random.Random, n: int, filler) -> list[str]:
    """``n`` table cells made of ``filler(rng)``; one in five is empty."""
    return ["" if rng.random() < 0.2 else filler(rng) for _ in range(n)]


def _plain_cell(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.4:
        return rng.choice(_NOTE_STATUS_WORDS)
    if roll < 0.55:
        return rng.choice(_NOTE_STATUS_WORDS).capitalize()
    if roll < 0.8:
        return str(rng.randint(0, 999))
    return " ".join(rng.sample(_NOTE_STATUS_WORDS, rng.randint(2, 4)))


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _bold_label(rng: random.Random, label: str) -> str:
    return rng.choice(["**{L}**:", "**{L}:**", "{L}:", "- **{L}**:",
                       "- {L}:"]).format(L=label)


def _render_note_line(rng: random.Random) -> tuple[str, list[tuple[int, int, str]]]:
    """One markdown line as a case note writes it, with its entity spans.

    Without a name: a heading, a table header row, a bold label before a
    colon, a list item that opens with a capitalised phrase, a sentence with a
    feature phrase in it. With a name: a person in a table cell, a person
    after a label, a person in a list item, a person before a colon with
    lowercase text after it, a person who opens the line, an organisation in
    a table cell or after a label.
    """
    roll = rng.random()
    entities: list[tuple[str, str]] = []
    if roll < _NOTE_MIX[0]:
        text = "#" * rng.randint(1, 3) + " " + _phrase(
            rng, _NOTE_PHRASE_WORDS + _NOTE_FEATURE_WORDS)
    elif roll < _NOTE_MIX[1]:
        n = rng.randint(3, 5)
        text = _row(_cells(rng, n, lambda r: _phrase(
            r, _NOTE_COLUMN_WORDS, 1, 2 if r.random() < 0.25 else 1)))
    elif roll < _NOTE_MIX[2]:
        label = _phrase(rng, _NOTE_PHRASE_WORDS + _NOTE_COLUMN_WORDS)
        if rng.random() < 0.4:
            label = rng.choice(_NOTE_LEAD_WORDS) + " " + rng.choice(_NOTE_PHRASE_WORDS)
        text = _bold_label(rng, label)
        if rng.random() < 0.5:
            text += " " + " ".join(rng.sample(_NOTE_STATUS_WORDS, 2))
    elif roll < _NOTE_MIX[3]:
        text = rng.choice(_NOTE_LIST_NEGATIVE_TEMPLATES).format(
            F=_phrase(rng, _NOTE_FEATURE_WORDS, 1, 3), W=rng.choice(_NOTE_STATUS_WORDS))
    elif roll < _NOTE_MIX[4]:
        text = rng.choice(_NOTE_SENTENCE_NEGATIVE_TEMPLATES).format(
            F=_phrase(rng, _NOTE_FEATURE_WORDS, 2, 3), W=rng.choice(_NOTE_STATUS_WORDS),
            D=rng.randint(1, 999))
    elif roll < _NOTE_MIX[5]:
        person = _draw_person(rng)
        cells = _cells(rng, rng.randint(3, 5), _plain_cell)
        cells[rng.randrange(len(cells))] = person
        text = _row(cells)
        entities = [(person, "PERSON")]
    elif roll < _NOTE_MIX[6]:
        person = _draw_person(rng)
        text = _bold_label(rng, rng.choice(_NOTE_PERSON_LABELS)) + " " + person
        entities = [(person, "PERSON")]
    elif roll < _NOTE_MIX[7]:
        person = _draw_person(rng)
        text = rng.choice(_NOTE_PERSON_LIST_TEMPLATES).format(
            P=person, W=rng.choice(_NOTE_STATUS_WORDS))
        entities = [(person, "PERSON")]
    elif roll < _NOTE_MIX[8]:
        person = _draw_person(rng)
        head = rng.choice(["{P}:", "{P}:", "**{P}**:", "**{P}:**"]).format(P=person)
        text = head + " " + rng.choice(_NOTE_CHAT_TEXTS).format(
            W=rng.choice(_NOTE_STATUS_WORDS))
        entities = [(person, "PERSON")]
    elif roll < _NOTE_MIX[9]:
        person, org = _draw_person(rng), _draw_org(rng)
        template = rng.choice(_NOTE_PERSON_OPEN_TEMPLATES)
        text = template.format(P=person, O=org, W=rng.choice(_NOTE_STATUS_WORDS),
                               D=rng.randint(1, 99))
        entities = [(person, "PERSON")] + ([(org, "ORGANIZATION")] if "{O}" in template else [])
    elif roll < _NOTE_MIX[10]:
        org = _draw_org(rng)
        cells = _cells(rng, rng.randint(3, 5), _plain_cell)
        cells[rng.randrange(len(cells))] = org
        text = _row(cells)
        entities = [(org, "ORGANIZATION")]
    elif roll < _NOTE_MIX[11]:
        org = _draw_org(rng)
        text = _bold_label(rng, rng.choice(_NOTE_ORG_LABELS)) + " " + org
        entities = [(org, "ORGANIZATION")]
    else:
        org = _draw_org(rng)
        text = rng.choice(_NOTE_ORG_LIST_TEMPLATES).format(O=org)
        entities = [(org, "ORGANIZATION")]
    spans = []
    for value, etype in entities:
        start = text.index(value)
        spans.append((start, start + len(value), etype))
    return text, spans


def training_examples(seed: int, n_sentences: int,
                      notes: bool = False) -> tuple[list[dict], list[str]]:
    """The training set. With ``notes`` it is the same ``n_sentences`` log
    lines, drawn first and the same as without it, then ``n_sentences``
    note-shaped lines, with the four structure features on every token."""
    rng = random.Random(seed)
    features: list[dict] = []
    labels: list[str] = []
    for _ in range(n_sentences):
        text, spans = _render_sentence(rng)
        tokens = tokenize(text)
        features.extend(featurize(tokens, text, notes) if notes else featurize(tokens))
        labels.extend(_label_tokens(tokens, spans))
    if notes:
        for _ in range(n_sentences):
            text, spans = _render_note_line(rng)
            tokens = tokenize(text)
            features.extend(featurize(tokens, text, True))
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
    notes: bool = False


def train(seed: int = 20260821, n_sentences: int = 500,
          notes: bool = False) -> TrainedNerClassifier:
    features, labels = training_examples(seed, n_sentences, notes)
    vec = DictVectorizer(sparse=True)
    x = vec.fit_transform(features)
    clf = LogisticRegression(max_iter=500, class_weight="balanced")
    clf.fit(x, labels)
    return TrainedNerClassifier(vectorizer=vec, model=clf, seed=seed,
                                n_sentences=n_sentences, notes=notes)


@lru_cache(maxsize=4)
def get_trained(seed: int = 20260821, n_sentences: int = 500,
                notes: bool = False) -> TrainedNerClassifier:
    """Process-wide cache: training takes well under a second, but eval and the
    pipeline both build tiers repeatedly, and retraining on every construction
    would make the identical model a fresh random draw of nothing - the fit is
    deterministic for a fixed seed, so there is nothing gained by repeating it."""
    return train(seed=seed, n_sentences=n_sentences, notes=notes)


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
    feats = featurize(tokens, text, clf.notes) if clf.notes else featurize(tokens)
    x = clf.vectorizer.transform(feats)
    labels = list(clf.model.predict(x))
    proba = clf.model.predict_proba(x)
    classes = list(clf.model.classes_)
    scores = [proba[i, classes.index(labels[i])] for i in range(len(labels))]
    return _decode_bio(tokens, labels, scores)
