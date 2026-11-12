"""Live Elasticsearch research, offline core: the field map and the response scrubber.

The design is ``docs/es-bridge-design.md``. This module is the half that
decides what Claude may *see*: a Kibana async-search response comes in, and
either a scrubbed copy goes out or a :class:`Refused` is raised. Nothing
here opens a connection; the query side is ``esquery.py``, the eval and the
stub Kibana are ``eseval.py``, and the live bridge does not exist yet.

The site configuration
----------------------

Index names, field names and naming conventions describe the estate, so they
live in ``hider.local.json`` under ``"elastic"`` (an object, or a path to a
separate JSON file), never in the repo. ``templates/elastic.example.json``
shows the shape with invented names. Every field is one of three kinds, and a
field that is not listed is a fourth:

``keep``
    declared non-sensitive. Filter, range, sort and aggregate freely. Still
    not trusted blindly: every string value gets tier 1 and the known-value
    sweep (never tier 2), in hits and in bucket keys, because a real level
    field held a personal-site URL among its spellings. An ordinary value
    comes back exactly as written.
``identifier``
    the value is replaced by a stable, typed label from the session vault.
    Queries may filter it by *label* only, exact match, never by literal or
    pattern. An optional ``shape`` regex with named groups and a ``label``
    format keep the parts of the value that are not the customer (a server's
    region, say): ``ctr-amer-042`` becomes ``ctr-amer-s01``.
``text``
    free text. Run through tier 1 and tier 2, then swept for every value the
    session already knows. Queries may ``match_phrase`` it.
unlisted
    dropped server side via ``_source.includes`` and dropped again here if
    it arrives anyway. Refused in a query.

A malformed configuration is a startup error, never a silent skip, the same
rule as ``localcfg`` and ``profiles``.

What the scrubber promises
--------------------------

* A degraded tier anywhere in the response refuses the whole response.
* The leak check (every mapped value, any length, at word boundaries) runs
  over the output, and a hit refuses the whole response. Never a partial page.
* An Elasticsearch or Kibana error becomes a fixed error class. The body is
  never forwarded: ES errors echo the query and sometimes the document.
* Aggregation bucket keys on identifier fields are labelled; a key on a
  field the plan did not declare, or an aggregation the plan did not
  declare, is a refusal.
* The mapping (label -> value) stays in this process and in the session
  files under ``out/``; the scrubbed output carries labels only.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import os
import re
import time
import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import entities, jsonscrub, localcfg, paths, pipeline, pseudonym

ENV = "HIDER_ELASTIC"
EXAMPLE = Path(__file__).resolve().parent.parent / "templates" / "elastic.example.json"
SESSIONS = Path(__file__).resolve().parent.parent / "out" / "es"
SESSION_SCHEMA = "hider.es-session.v1"

KINDS = ("keep", "identifier", "text")
#: Fields Elasticsearch adds to every hit, with the kind they get when the
#: site map does not say otherwise. ``_id`` can encode a tenant or a routing
#: key, so it is an identifier; ``_index`` is checked against the allowlist.
META_RULES = {
    "_id": {"kind": "identifier", "type": "DOC_ID"},
    "_score": "keep",
}
_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_FIELD_RE = re.compile(r"^[@A-Za-z_][\w.@*-]{0,127}$")
_FORMAT_FIELD = re.compile(r"\{(\w+)")

DEFAULT_MAX_HITS = 100
DEFAULT_MAX_BUCKETS = 50
DEFAULT_MAX_TEXT_CHARS = 20_000
#: How long one async search may run before it is withheld as incomplete.
#: The ceiling is there because the bridge is serialised: a search that is
#: still polling blocks every other call, so ten minutes is the most one
#: query may hold it. A wider window or a filter is the answer past that.
#: Distinct phrases one query may carry, in its filters and in every
#: aggregation at any depth. A ``filters`` aggregation returns a separate
#: hit count per bucket, so without a cap one query confirms a whole list of
#: guessed words. The ceiling keeps a site from configuring that back in.
DEFAULT_MAX_PHRASES = 8
MAX_PHRASES_CEILING = 16
#: Distinct plain-word phrases one **case** may use on text fields, over all
#: its queries (``max_phrases`` is per query). 0 turns the budget off.
DEFAULT_PHRASE_BUDGET = 150
PHRASE_BUDGET_CEILING = 2000
DEFAULT_POLL_TIMEOUT_S = 120
MAX_POLL_TIMEOUT_S = 600
#: The name vocabulary (:class:`VocabularyBuild`, :class:`VocabularyIndex`).
#: It is built **once per cluster, when the bridge signs in**, over the last
#: ``days``, and topped up every ``VOCABULARY_REFRESH_S`` with only the time
#: since the last read. ``max`` is the hard ceiling per field, above which
#: the build fails rather than leaving a partial list; ``budget_s`` is how
#: long a whole build may take.
#:
#: It used to be read inside each case, for the case's own window. Measured
#: against a real cluster that cannot work: one composite page of 1,000
#: values for one field takes 8 to 35 seconds, every name field holds far
#: more than 1,000 values in an hour, and a one-hour case read 49 hours once
#: the margin was added. No per-case budget a human would wait for covers
#: that, so every case was refused. Once per cluster, with a long budget and
#: a saved result, is the only shape that fits the measured cost.
DEFAULT_VOCABULARY_DAYS = 30
MAX_VOCABULARY_DAYS = 400
DEFAULT_VOCABULARY_MAX = 50_000
MAX_VOCABULARY_MAX = 200_000
#: Values one composite page asks for. Fixed: it is a transport detail, not a
#: safety boundary (the ceiling and the budget are), and a site that could
#: tune it could only make the read slower or heavier.
VOCABULARY_PAGE = 1_000
#: Wall clock **one slice** of a build may take before that slice is
#: abandoned (see :data:`VOCABULARY_SLICE_S`). It used to be the budget for
#: a whole build, which could not work: a build over the whole retention
#: period is hours on a real estate, so one number either refused every
#: build or meant nothing. Per slice, a slow slice fails alone and the next
#: tick retries it, and what is already saved stays saved.
DEFAULT_VOCABULARY_BUDGET_S = 1200.0
MAX_VOCABULARY_BUDGET_S = 7200.0
VOCABULARY_REFRESH_S = 600.0
#: How much of the time range one slice of a build covers. One day, newest
#: first, for two measured reasons. **Cost**: a composite page over a
#: 30-day range was measured at 31 to 297 seconds against 8 to 35 for the
#: same page over a day or an hour, so narrowing the range is what makes a
#: page affordable at all. **Usefulness**: the recent slices are the ones a
#: case needs, they are saved as soon as they are read, and the build keeps
#: extending backwards without holding anything up.
VOCABULARY_SLICE_S = 86400.0
#: How far back the vocabulary must reach before cases are served from it.
#: Until then a case is refused with ``vocabulary_building``; after it,
#: cases run while the older slices are still being read. Two days, so a
#: case about yesterday is covered.
VOCABULARY_SERVE_DAYS = 2
#: How long a failed slice waits before the serve loop tries it again.
VOCABULARY_RETRY_S = 60.0
VOCABULARY_AGG = "hider_vocabulary"
#: The one composite source name in a vocabulary aggregation.
VOCABULARY_SOURCE = "v"
#: The distinct-count probe each field gets before it is paged: one
#: ``cardinality`` aggregation, one request, no paging and no sort.
VOCABULARY_COUNT_AGG = "hider_vocabulary_n"
#: Elasticsearch's ceiling on ``precision_threshold``. Below it a
#: cardinality count is near enough exact; above it the error is a fraction
#: of a percent. Asked for at the cap, so the answer is at its most accurate
#: exactly where the decision is made.
VOCABULARY_PRECISION_CEILING = 40_000
#: How far a cardinality count is assumed to be out, as a share of itself.
#: Elasticsearch's cardinality is approximate (HyperLogLog++); measured
#: error is under 2% at the default precision and a fraction of a percent
#: near the threshold, so 5% is a margin, not an estimate. It is applied in
#: whichever direction **keeps the build running**: a field within the
#: margin of the cap is treated as over it when the field set is the default
#: (left out, the build carries on) and as under it when the site map lists
#: the field itself (paged, with the exact page-time count deciding, because
#: there the answer to "over the cap" is to refuse the slice).
VOCABULARY_PROBE_MARGIN = 0.05
#: How long an "over the cap" decision stands before the field is probed
#: again. A day: long enough that one cover's thirty slices and any restart
#: within the day ask once, short enough that raising the cap or fixing the
#: field takes effect the next day without clearing anything by hand.
VOCABULARY_OVER_CAP_S = 86400.0
#: A field at or above this share of its cap is reported as near it.
VOCABULARY_NEAR_CAP = 0.8
#: Identifier types a site may not read as a vocabulary, and why: one value
#: per person, mailbox, object or machine (tens of thousands, and a terms
#: aggregation over them is the expensive kind), numbers (a vocabulary of
#: numbers would erase counts and sizes from every message), and types tier 1
#: already finds by shape in any text.
NO_VOCABULARY_TYPES: dict[str, str] = {
    **dict.fromkeys(("UPN_EMAIL", "EMAIL", "PERSON_NAME", "USER_NAME", "ACCOUNT_NAME"),
                    "one value per user account"),
    **dict.fromkeys(("GUID", "TENANT_ID", "SESSION_GUID", "OBJECT_GUID", "DOC_ID", "ITEM_ID"),
                    "one value per object; tier 1 finds ids by shape"),
    **dict.fromkeys(("IPV4", "IPV6", "MAC_ADDRESS", "HOSTNAME_FQDN", "SERVER_NAME",
                     "INSTANCE_NAME"), "one value per machine; shaped, found by tier 1 or a site shape"),
    **dict.fromkeys(("TENANT_SIZE", "CLOUD_ACCOUNT"), "a number: it would erase counts from text"),
}
#: One-word names that are ordinary words in log text. The list lives in
#: ``jsonscrub`` because both scrubbers read it - the Elasticsearch one
#: here (``vocabulary_skip``, ``readable_in_text``) and the JSON-export
#: one (``jsonscrub._ordinary_name``) - and the import direction only
#: allows elastic -> jsonscrub. One list, not two copies: a word added
#: for one surface must mean the same on the other. This name stays as
#: the documented spelling; the contents are unchanged.
ORDINARY_NAME_WORDS: frozenset[str] = jsonscrub.ORDINARY_NAME_WORDS
#: Elasticsearch names a data stream's backing indices
#: ``.ds-<stream>-<yyyy.MM.dd>-<generation>``, and a hit names the backing
#: index, never the stream the query targeted. The suffix is fixed, so the
#: stream name is recovered exactly; the greedy group is safe because the
#: anchor is the end of the name.
#: Appended to every ``incomplete`` refusal: the search was too wide to finish
#: whole, and these are the levers the grammar has.
INCOMPLETE_HINT = ("narrow the query: a shorter time window, a more specific phrase or an "
                   "exact filter, or one index pattern instead of a wide one")
_BACKING_INDEX = re.compile(r"^\.ds-(?P<stream>.+)-\d{4}\.\d{2}\.\d{2}-\d{6,}$")
#: A keep value made only of digits and time punctuation (timestamps,
#: durations, versions, counts rendered as strings). T and Z are the only
#: letters an ISO timestamp carries, and no identifier fits this alphabet -
#: a GUID needs hex letters, a name needs letters - so these skip the keep
#: pass entirely. Anything else goes through tier 1.
_TIME_SHAPED = re.compile(r"[0-9 .:,+\-TZ/]{0,64}")


class ConfigError(RuntimeError):
    """The elastic configuration could not be loaded. Never a warning."""


class Refused(Exception):
    """The bridge will not show this to Claude, or will not send this query.

    ``code`` is one of a small fixed vocabulary so a decision log can count
    refusals by kind without ever carrying a value. ``message`` is safe to
    show to the model: it names the rule, not the data.
    """

    def __init__(self, code: str, message: str, *, label: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        #: the label a refusal was about, for the decision log. A label is
        #: not a value - it is what Claude typed - so logging it is safe,
        #: and it is the only way to see a case guessing at labels.
        self.label = label


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldRule:
    pattern: str
    kind: str
    type: str = ""
    shape: re.Pattern | None = dataclasses.field(default=None, compare=False)
    label: str = ""

    @property
    def is_glob(self) -> bool:
        return "*" in self.pattern

    def matches(self, path: str) -> bool:
        if self.is_glob:
            return fnmatch.fnmatchcase(path, self.pattern)
        return path == self.pattern

    @property
    def specificity(self) -> tuple[int, int]:
        return (0 if self.is_glob else 1, len(self.pattern))


@dataclass(frozen=True)
class Cluster:
    """One Kibana the bridge may talk to. The name is what Claude sees."""

    name: str
    kibana: str  # origin, e.g. https://kibana-emea.example.net, no path

    @property
    def host(self) -> str:
        return self.kibana.split("//", 1)[1].split("/", 1)[0].lower()


@dataclass(frozen=True)
class ElasticConfig:
    indices: tuple[str, ...]
    fields: tuple[FieldRule, ...]
    time_field: str = "@timestamp"
    max_hits: int = DEFAULT_MAX_HITS
    max_buckets: int = DEFAULT_MAX_BUCKETS
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    source: str = ""
    #: the live side (``esbridge``): clusters by name, and the dedicated
    #: browser profile. Both optional for the offline core.
    clusters: tuple[Cluster, ...] = ()
    profile_dir: str = ""
    poll_timeout_s: float = DEFAULT_POLL_TIMEOUT_S
    max_phrases: int = DEFAULT_MAX_PHRASES
    phrase_budget: int = DEFAULT_PHRASE_BUDGET
    #: identifier fields read as a vocabulary; None: the site map did not
    #: say, so every field that *could* be read (:attr:`learnable_rules`)
    vocabulary_fields: tuple[str, ...] | None = None
    vocabulary_days: int = DEFAULT_VOCABULARY_DAYS
    vocabulary_max: int = DEFAULT_VOCABULARY_MAX
    vocabulary_budget_s: float = DEFAULT_VOCABULARY_BUDGET_S

    @property
    def learnable_rules(self) -> tuple["FieldRule", ...]:
        """Every identifier field a vocabulary may hold: non-glob, unshaped,
        and of a type outside :data:`NO_VOCABULARY_TYPES`.

        Exactly the set ``_parse_vocabulary`` accepts, so the default can
        never be something a site map would be refused for listing, and a
        map that lists every field it is allowed to list gets the default.
        """
        return tuple(r for r in self.fields
                     if r.kind == "identifier" and not r.is_glob and r.shape is None
                     and r.type not in NO_VOCABULARY_TYPES)

    @property
    def vocabulary_rules(self) -> tuple["FieldRule", ...]:
        if self.vocabulary_fields is None:
            # No vocabulary section: read every field that can be read. The
            # earlier default was JOB_NAME only, which left tenant, full
            # tenant and resource names readable in message text at any
            # site that had not written the section - the common case, and
            # the fields most likely to carry the customer's name.
            return self.learnable_rules
        by = {r.pattern: r for r in self.fields}
        return tuple(by[f] for f in self.vocabulary_fields)

    @property
    def vocabulary_omitted(self) -> tuple[str, ...]:
        """Field names a vocabulary could hold but this map does not read.

        Empty unless the map lists ``vocabulary.fields``, since the default
        is everything. Reported by ``es-smoke`` so a site can see what its
        own list leaves readable in message text; names only, never values.
        """
        read = {r.pattern for r in self.vocabulary_rules}
        return tuple(r.pattern for r in self.learnable_rules if r.pattern not in read)

    def cluster(self, name: str) -> Cluster | None:
        for c in self.clusters:
            if c.name == name:
                return c
        return None

    def rule(self, path: str) -> FieldRule | None:
        """The most specific rule for a dotted field path, or None (unlisted)."""
        best = None
        for r in self.fields:
            if r.matches(path) and (best is None or r.specificity > best.specificity):
                best = r
        return best

    def closest_field(self, name: str) -> str | None:
        """The site-map field most like ``name``, for a refusal hint. Field
        names are what ``summary`` already tells Claude, so naming one here
        discloses nothing new."""
        import difflib
        hit = difflib.get_close_matches(name, [r.pattern for r in self.fields], n=1, cutoff=0.6)
        return hit[0] if hit else None

    def source_includes(self) -> list[str]:
        return [r.pattern for r in self.fields]

    @property
    def shaped_rules(self) -> tuple[FieldRule, ...]:
        return tuple(r for r in self.fields if r.shape is not None)

    def index_allowed(self, name: str) -> bool:
        """An index name a hit came from must match one allowlisted pattern.

        A data stream's backing index is admitted when its *stream* matches:
        ``.ds-logs-app-default-2026.08.20-000001`` under ``logs-app-*``. That
        admits nothing the pattern did not already reach (querying the
        pattern is what returned the backing index), and nothing else that
        starts with ``.ds-``: the name must have the backing-index suffix and
        the stream in front of it must match. A failure-store index
        (``.fs-``) or a downsampled one is not the stream and stays refused.
        """
        if any(fnmatch.fnmatchcase(name, pat) for pat in self.indices):
            return True
        m = _BACKING_INDEX.match(name)
        return m is not None and any(fnmatch.fnmatchcase(m.group("stream"), pat)
                                     for pat in self.indices)

    def summary(self) -> dict:
        """What Claude may be told: names and kinds, nothing else."""
        return {
            "indices": list(self.indices),
            "time_field": self.time_field,
            "fields": {r.pattern: r.kind for r in sorted(self.fields, key=lambda r: r.pattern)},
            "max_hits": self.max_hits,
            "max_buckets": self.max_buckets,
            "max_phrases": self.max_phrases,
            "phrase_budget": self.phrase_budget,
            "clusters": [c.name for c in self.clusters],
        }


def _parse_rule(path: str, raw: Any, source: str) -> FieldRule:
    where = f"{source}: field {path!r}"
    if not _FIELD_RE.match(path):
        raise ConfigError(f"{where}: not a usable field name")
    if isinstance(raw, str):
        raw = {"kind": raw}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a kind string or an object")
    unknown = set(raw) - {"kind", "type", "shape", "label"}
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise ConfigError(f"{where}: kind must be one of {list(KINDS)}, got {kind!r}")
    etype = raw.get("type", "")
    shape_src = raw.get("shape")
    label = raw.get("label", "")
    if kind != "identifier":
        if etype or shape_src or label:
            raise ConfigError(f"{where}: type/shape/label only apply to identifier fields")
        return FieldRule(path, kind)
    if not isinstance(etype, str) or not _TYPE_RE.match(etype):
        raise ConfigError(f"{where}: identifier needs a type like TENANT_ID or SERVER_NAME")
    canonical = pseudonym._canonical_type(etype)
    if canonical in entities.SECRET_TYPES:
        raise ConfigError(f"{where}: {etype} is a secret type; a secret is destroyed by the "
                          "text tiers, it cannot be an identifier field")
    if (shape_src is None) != (not label):
        raise ConfigError(f"{where}: shape and label go together")
    if shape_src is None:
        return FieldRule(path, kind, etype)
    try:
        shape = re.compile(shape_src)
    except re.error as e:
        raise ConfigError(f"{where}: shape does not compile: {e}") from e
    if "n" in shape.groupindex:
        raise ConfigError(f"{where}: the group name 'n' is reserved for the ordinal")
    used = set(_FORMAT_FIELD.findall(label))
    if "n" not in used:
        raise ConfigError(f"{where}: label must include the ordinal {{n}}")
    missing = used - set(shape.groupindex) - {"n"}
    if missing:
        raise ConfigError(f"{where}: label refers to groups {sorted(missing)} the shape "
                          "does not define")
    # A label must never be a value the shape itself matches, or a pseudonym
    # could collide with a real server. Render one with the group text left
    # in and the ordinal set, and demand the shape rejects it.
    probe = {g: "a" for g in shape.groupindex}
    try:
        rendered = label.format(n=1, **probe)
    except (KeyError, ValueError, IndexError) as e:
        raise ConfigError(f"{where}: label format is invalid: {e}") from e
    if shape.fullmatch(rendered) or shape.fullmatch(label.format(n=1, **{g: "1" for g in probe})):
        raise ConfigError(f"{where}: label {label!r} can itself match shape {shape_src!r}; "
                          "a pseudonym must not look like a real value")
    return FieldRule(path, kind, etype, shape, label)


_CLUSTER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d{1,5})?$")


def _parse_clusters(raw: Any, source: str) -> tuple[Cluster, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict) or not raw:
        raise ConfigError(f"{source}: clusters is an object of name -> {{kibana: origin}}")
    out = []
    for name, spec in raw.items():
        if not isinstance(name, str) or not _CLUSTER_NAME.match(name):
            raise ConfigError(f"{source}: cluster names are short lowercase words, got {name!r}")
        if isinstance(spec, str):
            spec = {"kibana": spec}
        if not isinstance(spec, dict) or set(spec) - {"kibana"} or "kibana" not in spec:
            raise ConfigError(f"{source}: cluster {name!r} takes exactly {{kibana: origin}}")
        origin = spec["kibana"]
        if not isinstance(origin, str) or not _ORIGIN.match(origin.rstrip("/")):
            raise ConfigError(f"{source}: cluster {name!r}: kibana must be an origin like "
                              "https://host[:port], no path")
        origin = origin.rstrip("/")
        host = origin.split("//", 1)[1].split(":")[0].lower()
        if origin.startswith("http://") and host not in {"127.0.0.1", "localhost", "::1"}:
            raise ConfigError(f"{source}: cluster {name!r}: plain http is only allowed on loopback")
        out.append(Cluster(name, origin))
    return tuple(out)


def _parse_vocabulary(raw: Any, rules: tuple[FieldRule, ...], source: str) -> dict:
    """``{"fields": [...], "days": 30, "max": 50000, "budget_s": 1200}``,
    all optional.

    Each field must be a listed, non-glob identifier without a shape, of a
    type a vocabulary may hold (:data:`NO_VOCABULARY_TYPES` says which may
    not, and why). Absent: every field that could be listed."""
    if raw is None:
        return {}
    known = {"fields", "days", "max", "budget_s", "_comment"}
    if not isinstance(raw, dict) or set(raw) - known:
        raise ConfigError(f"{source}: vocabulary must be an object with "
                          f"{', '.join(sorted(known - {'_comment'}))}")
    out: dict[str, Any] = {}
    for key, default, ceiling in (("days", DEFAULT_VOCABULARY_DAYS, MAX_VOCABULARY_DAYS),
                                  ("max", DEFAULT_VOCABULARY_MAX, MAX_VOCABULARY_MAX)):
        v = raw.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= ceiling:
            raise ConfigError(f"{source}: vocabulary.{key} must be an integer, 1..{ceiling}")
        out[f"vocabulary_{key}"] = v
    budget = raw.get("budget_s", DEFAULT_VOCABULARY_BUDGET_S)
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) \
            or not 1 <= budget <= MAX_VOCABULARY_BUDGET_S:
        raise ConfigError(f"{source}: vocabulary.budget_s must be a number, "
                          f"1..{MAX_VOCABULARY_BUDGET_S:g}")
    out["vocabulary_budget_s"] = float(budget)
    if "fields" in raw:
        fields = raw["fields"]
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields) \
                or len(set(fields)) != len(fields):
            raise ConfigError(f"{source}: vocabulary.fields must list distinct field names")
        by = {r.pattern: r for r in rules}
        for f in fields:
            r = by.get(f)
            if r is None or r.kind != "identifier" or r.is_glob:
                raise ConfigError(f"{source}: vocabulary field {f} must be a listed identifier "
                                  "field, not a glob")
            if r.shape is not None:
                raise ConfigError(f"{source}: vocabulary field {f} has a shape; the shape "
                                  "already finds its values in text")
            why = NO_VOCABULARY_TYPES.get(r.type)
            if why:
                raise ConfigError(f"{source}: vocabulary field {f} is {r.type}: {why}")
        out["vocabulary_fields"] = tuple(fields)
    return out


def parse(raw: Any, *, source: str = "elastic") -> ElasticConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: top level must be an object")
    allowed = {"_comment", "indices", "fields", "time_field", "max_hits", "max_buckets",
               "max_text_chars", "clusters", "profile_dir", "poll_timeout_s",
               "max_phrases", "phrase_budget", "vocabulary"}
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"{source}: unknown keys {sorted(unknown)}")
    indices = raw.get("indices")
    if not isinstance(indices, list) or not indices or not all(
            isinstance(i, str) and _FIELD_RE.match(i) for i in indices):
        raise ConfigError(f"{source}: indices must be a non-empty list of index patterns")
    fields_raw = raw.get("fields")
    if not isinstance(fields_raw, dict) or not fields_raw:
        raise ConfigError(f"{source}: fields must be a non-empty object")
    rules = tuple(_parse_rule(k, v, source) for k, v in fields_raw.items())
    time_field = raw.get("time_field", "@timestamp")
    if not isinstance(time_field, str) or not _FIELD_RE.match(time_field):
        raise ConfigError(f"{source}: time_field must be a field name")
    caps = {}
    for key, default in (("max_hits", DEFAULT_MAX_HITS), ("max_buckets", DEFAULT_MAX_BUCKETS),
                         ("max_text_chars", DEFAULT_MAX_TEXT_CHARS)):
        v = raw.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ConfigError(f"{source}: {key} must be a positive integer")
        caps[key] = v
    clusters = _parse_clusters(raw.get("clusters"), source)
    profile_dir = raw.get("profile_dir", "")
    if not isinstance(profile_dir, str):
        raise ConfigError(f"{source}: profile_dir must be a path string")
    poll = raw.get("poll_timeout_s", DEFAULT_POLL_TIMEOUT_S)
    if isinstance(poll, bool) or not isinstance(poll, (int, float)) \
            or not 1 <= poll <= MAX_POLL_TIMEOUT_S:
        raise ConfigError(f"{source}: poll_timeout_s must be a number of seconds, "
                          f"1..{MAX_POLL_TIMEOUT_S}")
    phrases = raw.get("max_phrases", DEFAULT_MAX_PHRASES)
    if isinstance(phrases, bool) or not isinstance(phrases, int) \
            or not 0 <= phrases <= MAX_PHRASES_CEILING:
        raise ConfigError(f"{source}: max_phrases must be an integer, 0..{MAX_PHRASES_CEILING} "
                          "(0 turns text queries off)")
    budget = raw.get("phrase_budget", DEFAULT_PHRASE_BUDGET)
    if isinstance(budget, bool) or not isinstance(budget, int) \
            or not 0 <= budget <= PHRASE_BUDGET_CEILING:
        raise ConfigError(f"{source}: phrase_budget must be an integer, 0..{PHRASE_BUDGET_CEILING} "
                          "(0 turns the per-case budget off)")
    cfg = ElasticConfig(tuple(indices), rules, time_field, source=source, clusters=clusters,
                        profile_dir=profile_dir, poll_timeout_s=float(poll),
                        max_phrases=phrases, phrase_budget=budget, **caps)
    tf = cfg.rule(time_field)
    if tf is None or tf.kind != "keep":
        raise ConfigError(f"{source}: time_field {time_field!r} must be listed as keep")
    # Custom identifier types mint labels <Type_Name-NN>; two types that
    # render the same prefix would mint colliding labels for different
    # values, and the built-in prefixes are taken.
    prefixes: dict[str, str] = {s.label_prefix: s.name for s in entities.SPECS}
    for r in rules:
        if r.kind != "identifier" or r.shape is not None or r.type in entities.BY_NAME:
            continue
        canonical = pseudonym._canonical_type(r.type)
        if canonical in entities.BY_NAME:
            continue
        prefix = r.type.title()
        owner = prefixes.setdefault(prefix, r.type)
        if owner != r.type:
            raise ConfigError(f"{source}: identifier type {r.type!r} would label as "
                              f"<{prefix}-NN>, which {owner!r} already uses")
    # last: the fields it names are checked against everything above
    return dataclasses.replace(cfg, **_parse_vocabulary(raw.get("vocabulary"), rules, source))


def load(path: str | Path) -> ElasticConfig:
    p = Path(path).expanduser()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"{p}: not found") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{p}: not valid JSON: {e}") from e
    return parse(raw, source=str(p))


def active() -> ElasticConfig | None:
    """The site's elastic configuration, or None when the machine has none.

    ``HIDER_ELASTIC`` names a file; otherwise ``hider.local.json`` may carry
    ``"elastic"`` as an object or as a path string. Nothing is read from the
    repository's example.
    """
    import os

    env = os.environ.get(ENV)
    if env:
        return load(env)
    raw = localcfg.settings().get("elastic")
    if raw is None:
        return None
    if isinstance(raw, str):
        return load(raw)
    return parse(raw, source="hider.local.json#elastic")


# ---------------------------------------------------------------------------
# The query plan the scrubber needs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AggPlan:
    """What ``esquery`` compiled, in the terms the response scrubber needs."""

    type: str
    field: str = ""
    rule: FieldRule | None = None
    subs: dict[str, "AggPlan"] = dataclasses.field(default_factory=dict)
    #: for ``filters``: the bucket names the caller chose (validated words)
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    index: str
    aggs: dict[str, AggPlan] = dataclasses.field(default_factory=dict)
    size: int = 0


# ---------------------------------------------------------------------------
# Errors from upstream: a class, never the body
# ---------------------------------------------------------------------------

_STATUS_CLASS = {
    400: "bad_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found",
    408: "timeout", 429: "throttled", 500: "upstream_error", 502: "upstream_unavailable",
    503: "upstream_unavailable", 504: "upstream_unavailable",
}
_KNOWN_ES_TYPES = {
    "parsing_exception", "index_not_found_exception", "search_phase_execution_exception",
    "too_many_buckets_exception", "circuit_breaking_exception", "security_exception",
    "illegal_argument_exception", "query_shard_exception", "resource_not_found_exception",
}


def error_class(raw: dict) -> str | None:
    """A fixed string for an error body, or None when ``raw`` is not an error.

    Kibana's shape is ``{"statusCode", "error", "message"}``; Elasticsearch's
    is ``{"error": {"type", "reason", ...}, "status"}``. Only the status and
    a known exception type survive; the message never does.
    """
    status = raw.get("statusCode", raw.get("status"))
    err = raw.get("error")
    if status is None and err is None:
        return None
    if isinstance(status, int) and 200 <= status < 300 and err is None:
        return None
    klass = _STATUS_CLASS.get(status, "upstream_error") if isinstance(status, int) else "upstream_error"
    es_type = None
    if isinstance(err, dict):
        es_type = err.get("type")
    elif isinstance(raw.get("message"), str):
        m = re.match(r"\[(\w+)\]", raw["message"])
        es_type = m.group(1) if m else None
    if es_type in _KNOWN_ES_TYPES:
        return f"{klass}:{es_type}"
    return klass


# ---------------------------------------------------------------------------
# The session scrubber
# ---------------------------------------------------------------------------


@dataclass
class Scrubbed:
    output: dict
    stats: dict


_SHAPE_BOUND_L = r"(?<![A-Za-z0-9_-])"
_SHAPE_BOUND_R = r"(?![A-Za-z0-9_-])"

#: A job named in free text: the word "job", then a title-case run. This is
#: how status messages reference a job whose name sits in no field of the
#: page ("Job Teams Nightly (<id>) scheduled on ..."), which was the one
#: value the harvest-then-sweep order could never see on a fresh case's
#: first page: harvesting reads fields, and the referenced job's field is on
#: some other document. The run ends at the first word that does not start
#: with a capital or a short number, so "for tenant", "(", "scheduled" and
#: sentence punctuation all end it. A run that is nothing but log vocabulary
#: ("Job Failed") is not a name and is left alone; everything else
#: capitalised after "job" is labelled, which is the readability cost the
#: rule accepts and the README declares.
_JOB_REF = re.compile(
    r"(?<![A-Za-z0-9_-])[Jj]ob[ ]+"
    r"((?:[A-Z][\w'’&-]*)(?:[ ](?:[A-Z][\w'’&-]*|\d{1,4}(?![\w-])))*)"
)


class EsScrubber(jsonscrub.JsonScrubber):
    """A case-scoped scrubber for Kibana async-search responses.

    One instance per case. Labels are stable across every response it
    scrubs, so ``<Org-01>`` on the first page is ``<Org-01>`` on the
    fiftieth, and the mapping it accumulates is what ``esquery`` resolves
    labels against on the way out.
    """

    def __init__(self, config: ElasticConfig, *, tier2: str = "classifier",
                 vault: pseudonym.EntityVault | None = None,
                 terms: list[str] | None = None) -> None:
        super().__init__(tier2=tier2, terms=terms)
        if vault is not None:
            self.vault = vault
            self.pipe.vault = vault
        self.config = config
        #: label -> entity type, so a label can be checked against the field
        #: it is used to filter
        self.types: dict[str, str] = {}
        #: Labels this case has actually been **shown**: seeded by the
        #: human, or carried in a page, an aggregation or a tool reply that
        #: went back to Claude. Only these may be used in a query.
        #:
        #: The mapping is not that set and cannot be used as it: applying a
        #: cluster vocabulary mints a label for every name on the estate,
        #: so every low ``<Org-NN>`` exists before a case asks anything. A
        #: guessed label would then resolve to some other customer's name
        #: and the query would run - nobody is unmasked, but the case can
        #: reach and count every customer on the cluster, which it could
        #: not do before the vocabulary existed.
        self.shown: set[str] = set()
        #: Labels the human seeded. The only known values that replace a
        #: *part* of a keep value; see :meth:`_keep_value`.
        self.seeded_labels: set[str] = set()
        #: Keep values this case has been **shown** (normalised: case and
        #: spacing folded), recorded at the same point as :attr:`shown`. A
        #: keep literal containing a learnt name is accepted in a query only
        #: for one of these; see :meth:`keep_literal_shown`.
        self.shown_keep: set[str] = set()
        #: (field, phrase key) of every plain-word phrase this case has
        #: spent, for the per-case ``phrase_budget``. Spent when a query is
        #: about to be sent (:meth:`spend_phrases`), never refunded.
        self.phrases_spent: set[tuple[str, str]] = set()
        #: Measurement switch for es-eval's "before" figure: every known
        #: value matches anywhere in a keep value, as before the keep rule.
        #: Set by nothing in the live path.
        self.keep_parts_swept = False
        # ``readable_words`` and the ``ordinary_words_case_wide`` measurement
        # switch are inherited from JsonScrubber: one shared rule, two ways
        # of deciding which values it covers (the site map here, key
        # classification in an export). See :meth:`readable_in_text`.
        #: label -> the site-map field the readable word came from. The
        #: field is a decision, not data, so it can be reported where the
        #: word itself cannot: it is what tells an operator *which* name
        #: to go and look at before seeding it.
        self.readable_fields: dict[str, str] = {}
        self._learnable_patterns = {r.pattern for r in config.learnable_rules}
        self._learnable_types = {r.type for r in config.learnable_rules}
        self.dropped: dict[str, int] = {}
        self.responses = 0
        self.refusals: dict[str, int] = {}
        self._shape_rx = [
            (r, re.compile(_SHAPE_BOUND_L + r"(?:" + r.shape.pattern + r")" + _SHAPE_BOUND_R))
            for r in config.shaped_rules
        ]
        #: the job-reference rule fires only at a site whose map declares job
        #: names identifiers; without that declaration a job name is not
        #: sensitive and the word "job" in text means nothing special
        self._job_rule = next((r for r in config.fields
                               if r.kind == "identifier" and r.type == "JOB_NAME"), None)
        #: the fields read as a vocabulary, when each cluster's was last
        #: read, and the last read's counts (values per field, skipped by
        #: reason): counts only, for the log and the site's view of its caps
        self._vocab_rules = list(config.vocabulary_rules)
        self._vocabulary_at: dict[str, float] = {}
        self.vocabulary_counts: dict[str, int] = {}
        self.vocabulary_skipped: dict[str, int] = {}
        #: fields the build counted and did not read, field -> distinct
        #: count. Their values stay readable in message text.
        self.vocabulary_over_cap: dict[str, int] = {}
        self._meta = {k: _parse_rule(k, v, "meta") for k, v in META_RULES.items()}
        for t in self.terms:
            if not (t.endswith("*") and len(t) > 2):
                self.seed(t, "ORG_NAME")

    # -- labels ------------------------------------------------------------

    def readable_in_text(self, rule: FieldRule, value: str) -> bool:
        """Whether this value keeps its label in its own field but stays an
        ordinary word everywhere else.

        The vocabulary already declares these words readable: a one-word
        name on :data:`ORDINARY_NAME_WORDS`, a log word, a stopword, a
        value with no letters (:meth:`vocabulary_skip`). Harvesting a page
        used to override that declaration by the back door - a job called
        ``Backup`` seen in its own field was indexed for the case-wide
        sweep, and from then on *every* message in the case lost the word
        ("Backup window opened" -> "<Job-12> window opened"). About 7 in
        100 common job names are ordinary words, so it happened on the
        first pages, and which pages came first decided what a later page
        said.

        Only for a field the vocabulary could learn: a value seeded by the
        human ("the case is about Backup") is a deliberate instruction to
        hide the word, and its rule is not one of these.
        """
        return (rule.pattern in self._learnable_patterns
                and not self.ordinary_words_case_wide
                and bool(self.vocabulary_skip(value)))

    def label_for(self, rule: FieldRule, value: str, *, parts: bool = True) -> str:
        """The stable label for a value seen under an identifier rule."""
        n = jsonscrub._norm(value)
        if n in self.known:
            return self.known[n]
        if rule.shape is None and self.readable_in_text(rule, value):
            # Labelled in its own field, and findable by that label, but
            # never indexed for the case-wide sweep. The document that owns
            # it still hides it in its own text (_local_sweep).
            label = self._label(rule.type, value, index=False)
            self.types.setdefault(label, pseudonym._canonical_type(rule.type, value))
            self.readable_words[label] = value
            self.readable_fields.setdefault(label, rule.pattern)
            return label
        if rule.shape is not None:
            m = rule.shape.fullmatch(value.strip())
            if m is not None:
                while True:
                    ordinal = self.vault.ordinal_for(f"_SHAPE:{rule.type}", n)
                    label = rule.label.format(n=ordinal, **m.groupdict())
                    if label not in self.mapping:
                        break
                    # an ordinal already used by a restored session: bump
                    self.vault._next_ordinal(f"_SHAPE:{rule.type}")
                    self.vault.entries.pop(pseudonym._digest(self.vault.key, f"_SHAPE:{rule.type}", n))
                self._remember(value, label, rule.type)
                self.types[label] = rule.type
                return label
        label = self._label(rule.type, value)
        self.types.setdefault(label, pseudonym._canonical_type(rule.type, value))
        if parts:
            self._register_parts(pseudonym._canonical_type(rule.type, value), value, label)
        return label

    def seed(self, value: str, etype: str = "ORG_NAME") -> str:
        """Register a value the human typed locally ("the case is about X").

        Returns its label. This is how a case starts: the real name never
        goes to Claude, the label does.
        """
        rule = FieldRule("<seed>", "identifier", etype)
        for r in self.config.fields:
            if r.kind == "identifier" and r.type == etype and r.shape is not None:
                rule = r
                break
        label = self.label_for(rule, value)
        # a seeded value matches anywhere in a keep value; a learnt one only
        # as the whole value (see _keep_value)
        self.seeded_labels.add(label)
        # the human is given this label to hand to Claude, so it counts as
        # shown: it is the one label a case starts with
        self.shown.add(label)
        return label

    def _remember(self, value: str, label: str, etype: str, *, index: bool = True,
                  force: bool = False) -> None:
        super()._remember(value, label, etype, index=index, force=force)
        self.types.setdefault(label, etype)

    def resolve_label(self, label: str) -> tuple[str, str] | None:
        """(value, type) for a label this session minted, else None.

        Unmasking an answer for the human. **A query must not use this**:
        see :meth:`shown_label`.
        """
        if label in self.mapping:
            return self.mapping[label], self.types.get(label, "")
        return None

    def shown_label(self, label: str) -> tuple[str, str] | None:
        """(value, type) for a label this case was **shown**, else None.

        What a query may resolve. A label that exists but has not been
        shown is indistinguishable here from one that was never issued -
        both are None, so both refuse the same way and a refusal never
        tells a live guess from a dead one.
        """
        return self.resolve_label(label) if label in self.shown else None

    #: A label embedded in text, for the ``<Type-NN>`` spelling and for a
    #: site map's shaped one (``ctr-amer-s01``, hyphens and all). A whole
    #: string that is a label is matched directly, so this only has to
    #: find the ones inside a message.
    _LABEL_SHAPES = re.compile(r"<[^<>\s\"]{1,80}>|(?<![\w.-])[A-Za-z0-9][\w.-]*-s\d+")

    def spend_phrases(self, phrases: Any) -> None:
        """Charge a compiled query's new phrases to the case. Called once
        the query has passed every check and is about to be sent; not
        refunded if the request then fails or the page is withheld, since
        whether a page is withheld can depend on what the phrase matched."""
        self.phrases_spent.update(phrases)

    def phrase_report(self) -> dict:
        """Counts only, never a phrase: for the decision log, es-smoke and
        es_schema."""
        budget = self.config.phrase_budget
        used = len(self.phrases_spent)
        return {"phrases_used": used, "phrase_budget": budget or None,
                "phrases_left": max(0, budget - used) if budget else None}

    def keep_literal_shown(self, text: str) -> bool:
        """Whether a keep literal that contains a known value may still be
        used: this case was shown exactly that keep value (case and outer
        spaces ignored), the value is not itself a known value, and nothing
        in it is seeded. The caller refuses otherwise, with the same words
        as for a value never shown."""
        n = jsonscrub._norm(text)
        if n not in self.shown_keep or n in self.known:
            return False
        return all(self.known[v] not in self.seeded_labels for _, _, v in self._find_known(text))

    def mark_shown(self, output: Any) -> None:
        """Mark every label - and every keep value - carried by something
        Claude is about to see.

        One pass over the finished output rather than a hook in each
        rewrite path, so a label cannot reach Claude by a route that
        forgot to mark it: whatever is in the output is shown. Bucket keys
        and identifier leaves are whole strings; a message carries labels
        inside it. Runs on the still-marked output, so a keep value
        (:class:`_KeepStr`: a keep leaf, a keep bucket key, ``_index``) is
        recorded as one this case may now use as a literal.
        """
        def walk(node: Any) -> None:
            if isinstance(node, str):
                if isinstance(node, _KeepStr):
                    self.shown_keep.add(jsonscrub._norm(node))
                if not self.mapping:
                    return
                if node in self.mapping:
                    self.shown.add(node)
                    return
                for cand in self._LABEL_SHAPES.findall(node):
                    if cand in self.mapping:
                        self.shown.add(cand)
            elif isinstance(node, dict):
                for k, v in node.items():
                    walk(k)
                    walk(v)
            elif isinstance(node, (list, tuple)):
                for v in node:
                    walk(v)

        walk(output)

    # -- text -------------------------------------------------------------

    def _scrub_text(self, text: str, *, shaped_only: bool = False) -> str:
        # Site shapes first, so a server name inside a message gets the same
        # region-keeping label it gets as a field value.
        for rule, rx in self._shape_rx:
            for m in rx.finditer(text):
                self.label_for(rule, m.group(0))
        if self._job_rule is not None:
            for m in _JOB_REF.finditer(text):
                words = m.group(1).split()
                if all(pipeline.is_log_word(w) for w in words):
                    continue  # "job Failed", "Job Running": an outcome, not a name
                self.label_for(self._job_rule, m.group(1))
        return super()._scrub_text(text, shaped_only=shaped_only)

    # -- the name vocabulary ------------------------------------------------
    #
    # A customer name in free text with nothing that marks it as one ("Tenant
    # Thornbury Estates exceeded its quota", "Harbour Nightly finished") has
    # no shape a rule could read. For a tenant that would not matter much -
    # a message that names a tenant almost always carries the tenant fields
    # on the same document, so harvesting the page covers it - but about
    # three in four messages that name a *job* carry no job field at all.
    # Job names are what the vocabulary is really for.
    #
    # The names come from the cluster, read once per cluster when the bridge
    # signs in (VocabularyBuild), saved (VocabularyIndex) and topped up every
    # VOCABULARY_REFRESH_S. A case does not read anything: it applies what
    # the index already holds, which is local and costs no request. Every
    # value becomes a known value under its field's own rule, so it gets the
    # label it gets as a field value, and the sweep then labels the whole
    # name wherever it appears. The names never reach Claude, and the log
    # holds counts only.

    def apply_vocabulary(self, cluster: str, vocab: "ClusterVocabulary",
                         now: float | None = None,
                         over_cap: dict[str, int] | None = None) -> dict[str, int]:
        """Make every name the index holds for ``cluster`` a known value.

        Local work only: the read happened once, for the whole bridge. The
        skip rules below decide what is safe to register.

        ``over_cap`` names the fields the build counted and did not read,
        with their counts, so this case's own report can say which fields
        stay readable in message text and why.
        """
        self.vocabulary_over_cap = dict(over_cap or {})
        return self._learn_vocabulary(cluster, vocab.fields, now=now,
                                      covers=(vocab.covered_from, vocab.covered_until))

    def vocabulary_applied(self, cluster: str) -> bool:
        return not self._vocab_rules or cluster in self._vocabulary_at

    @staticmethod
    def vocabulary_skip(value: str) -> str | None:
        """Why a value is not made vocabulary, or None. The reasons are the
        readability rules: a value matched as a word in every message must
        not be one that ordinary text, a log level or an outcome uses."""
        v = value.strip()
        if not v:
            return "empty"
        words = v.split()
        if all(pipeline.is_log_word(w) for w in words):
            return "log_word"
        if jsonscrub._norm(v) in jsonscrub._STOPWORDS:
            return "stopword"
        if not any(c.isalpha() for c in v):
            return "no_letters"
        if len(words) == 1:
            if len(v) < 4:
                return "short"
            if v.casefold().strip(".,;:()") in ORDINARY_NAME_WORDS:
                return "ordinary_word"
        return None

    def _learn_vocabulary(self, cluster: str, values: dict[str, list[str]],
                          now: float | None = None,
                          covers: tuple[float | None, float | None] | None = None
                          ) -> dict[str, int]:
        """Make every name a build returned a known value. Called by
        :meth:`apply_vocabulary`, never from a transport."""
        counts: dict[str, int] = {}
        skipped: dict[str, int] = {}
        learnt: list[tuple[FieldRule, str]] = []
        for rule in self._vocab_rules:
            got = values.get(rule.pattern, [])
            counts[rule.pattern] = len(got)
            for key in got:
                why = self.vocabulary_skip(key) if isinstance(key, str) else "empty"
                if why:
                    skipped[why] = skipped.get(why, 0) + 1
                else:
                    learnt.append((rule, key))
        for rule, key in learnt:
            # "Archive AG" is vocabulary, but its core "Archive" would be
            # registered on its own and hide the word everywhere: the core is
            # held to the same readability rules as a name
            core = jsonscrub._LEGAL_SUFFIX.sub("", key.strip())
            self.label_for(rule, key, parts=core == key.strip() or not self.vocabulary_skip(core))
        at = time.monotonic() if now is None else now
        lo, hi = covers if covers is not None else (None, None)
        self._vocabulary_at[cluster] = (at, lo, hi)
        self.vocabulary_counts, self.vocabulary_skipped = counts, skipped
        return counts

    def vocabulary_report(self) -> dict:
        """Counts only: per field, values returned against the cap, plus the
        field names a vocabulary could hold that this case does not know -
        left out by the map (``omitted``) or too wide to read
        (``over_cap``, with the count that decided it)."""
        cap = self.config.vocabulary_max
        over_cap = dict(self.vocabulary_over_cap)
        return {"fields": {f: n for f, n in self.vocabulary_counts.items() if f not in over_cap},
                "max": cap,
                "near_cap": sorted(f for f, n in self.vocabulary_counts.items()
                                   if n >= VOCABULARY_NEAR_CAP * cap and f not in over_cap),
                "skipped": dict(self.vocabulary_skipped),
                "over_cap": over_cap,
                "omitted": list(self.config.vocabulary_omitted)}

    # -- the response ------------------------------------------------------

    def scrub_response(self, raw: Any, plan: Plan) -> Scrubbed:
        """Scrub one Kibana async-search (or raw Elasticsearch) response.

        Raises :class:`Refused` rather than returning anything partial.
        """
        t0 = time.time()
        self.responses += 1
        try:
            return self._scrub_response(raw, plan, t0)
        except Refused as e:
            self.refusals[e.code] = self.refusals.get(e.code, 0) + 1
            raise

    def _refuse(self, code: str, message: str) -> Refused:
        return Refused(code, message)

    def _scrub_response(self, raw: Any, plan: Plan, t0: float) -> Scrubbed:
        if not isinstance(raw, dict):
            raise self._refuse("malformed", "response withheld: not a JSON object")
        klass = error_class(raw)
        if klass is not None:
            raise self._refuse("upstream_error", f"upstream error: {klass}")
        if raw.get("isRunning") is True:
            raise self._refuse("incomplete", f"response withheld: search still running; {INCOMPLETE_HINT}")
        if raw.get("isPartial") is True:
            raise self._refuse("incomplete", "response withheld: partial results (shards failed or "
                                             f"timed out); {INCOMPLETE_HINT}")
        body = raw.get("rawResponse", raw)
        if not isinstance(body, dict) or "hits" not in body:
            raise self._refuse("malformed", "response withheld: no hits section")
        if body.get("timed_out") is True:
            raise self._refuse("incomplete", f"response withheld: search timed out; {INCOMPLETE_HINT}")
        degraded_before = self.degraded
        dropped_before = sum(self.dropped.values())

        # Pass 1: harvest every identifier value in the page, so a tenant
        # named in hit 40 is labelled when it shows up in hit 3's message.
        hits = body["hits"]
        rows = hits.get("hits") if isinstance(hits, dict) else None
        if not isinstance(rows, list):
            raise self._refuse("malformed", "response withheld: hits.hits is not a list")
        if len(rows) > self.config.max_hits:
            raise self._refuse("size_cap", "response withheld: more hits than the cap allows")
        for h in rows:
            self._harvest_hit(h)
        aggs = body.get("aggregations", {})
        if aggs:
            if not isinstance(aggs, dict):
                raise self._refuse("malformed", "response withheld: aggregations is not an object")
            self._harvest_aggs(aggs, plan.aggs)
        elif plan.aggs:
            raise self._refuse("malformed", "response withheld: planned aggregations missing")

        # Pass 2: rewrite.
        out: dict[str, Any] = {}
        out["hits"] = {
            "total": self._total(hits.get("total")),
            "hits": [self._rewrite_hit(h) for h in rows],
        }
        if aggs:
            out["aggregations"] = self._rewrite_aggs(aggs, plan.aggs)

        # Pass 3: sweep with everything learnt during pass 2, then the leak
        # check, the same order as the file scrubber.
        out = self._sweep(out)
        if self.degraded > degraded_before:
            raise self._refuse("degraded", "response withheld: redaction degraded")
        leaks = self.leak_check(out)
        if leaks:
            raise self._refuse("leak", "response withheld: a known value survived redaction")
        # This page is about to go to Claude, so every label in it - and
        # every keep value - is one the case may use from now on. After the
        # leak check: a page that is refused was never shown and teaches no
        # label. Before _unmark, which is what tells a keep value apart.
        self.mark_shown(out)
        out = self._unmark(out)
        stats = {
            "hits": len(rows),
            "mapped_values": len(self.mapping),
            "dropped_fields": sum(self.dropped.values()) - dropped_before,
            "secrets_destroyed": self.secrets_destroyed,
            "seconds": round(time.time() - t0, 3),
        }
        return Scrubbed(out, stats)

    @staticmethod
    def _total(total: Any) -> Any:
        if isinstance(total, dict):
            return {"value": total.get("value"), "relation": total.get("relation", "eq")}
        if isinstance(total, int):
            return {"value": total, "relation": "eq"}
        return None

    # -- hits --------------------------------------------------------------

    def _leaves(self, node: Any, prefix: str = ""):
        """(dotted path, scalar-or-list) pairs; lists of scalars stay whole."""
        if isinstance(node, dict):
            for k, v in node.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, dict):
                    yield from self._leaves(v, path)
                elif isinstance(v, list) and any(isinstance(x, dict) for x in v):
                    for i, x in enumerate(v):
                        yield from self._leaves(x, path) if isinstance(x, dict) else ((path, x),)
                else:
                    yield path, v

    def _rule_for(self, path: str) -> FieldRule | None:
        if path in self._meta:
            return self._meta[path]
        return self.config.rule(path)

    def _harvest_hit(self, hit: Any) -> None:
        if not isinstance(hit, dict):
            raise self._refuse("malformed", "response withheld: a hit is not an object")
        idx = hit.get("_index")
        if not isinstance(idx, str) or not self.config.index_allowed(idx):
            raise self._refuse("bad_index", "response withheld: a hit came from an index "
                                            "outside the allowlist")
        if "_id" in hit and hit["_id"] is not None:
            self.label_for(self._meta["_id"], str(hit["_id"]))
        for section in ("_source", "fields"):
            src = hit.get(section)
            if src is None:
                continue
            if not isinstance(src, dict):
                raise self._refuse("malformed", f"response withheld: {section} is not an object")
            for path, value in self._leaves(src):
                rule = self._rule_for(path)
                if rule is None or rule.kind != "identifier":
                    continue
                for v in (value if isinstance(value, list) else [value]):
                    if self._mappable(v):
                        self.label_for(rule, str(v))

    @contextlib.contextmanager
    def _local_sweep(self, hit: Any):
        """Hide this document's own ordinary-word names in *this* document's
        text, and nowhere else.

        A document whose job field says ``Backup`` and whose message says
        "Backup finished" is naming the job twice; hiding one and not the
        other would be pointless. On any other document the same word is
        ordinary English and stays. The index entry lives for the length
        of one hit, which is what makes a page scrub the same whatever
        pages came before it.
        """
        local: list[str] = []
        if self.readable_words and isinstance(hit, dict):
            for section in ("_source", "fields"):
                if not isinstance(hit.get(section), dict):
                    continue
                for path, value in self._leaves(hit[section]):
                    rule = self._rule_for(path)
                    if rule is None or rule.kind != "identifier" or not isinstance(value, str):
                        continue
                    n = jsonscrub._norm(value)
                    if self.known.get(n) in self.readable_words and n not in local:
                        local.append(n)
        for n in local:
            self._index_value(n)
        try:
            yield
        finally:
            for n in local:
                self._unindex_value(n)

    def _rewrite_hit(self, hit: dict) -> dict:
        with self._local_sweep(hit):
            return self._rewrite_hit_inner(hit)

    def _rewrite_hit_inner(self, hit: dict) -> dict:
        out: dict[str, Any] = {"_index": _keep_mark(hit["_index"])}
        if "_id" in hit and hit["_id"] is not None:
            out["_id"] = self.label_for(self._meta["_id"], str(hit["_id"]))
        if "_score" in hit:
            out["_score"] = hit["_score"]
        for section in ("_source", "fields"):
            if isinstance(hit.get(section), dict):
                out[section] = self._rewrite_doc(hit[section], "")
        for k in hit:
            if k not in {"_index", "_id", "_score", "_source", "fields", "sort", "_type",
                         "_ignored", "_version", "_seq_no", "_primary_term"}:
                # highlight, inner_hits, matched_queries, anything new: not
                # planned, not shown
                self._drop(f"<hit>.{k}")
        return out

    def _drop(self, path: str) -> None:
        self.dropped[path] = self.dropped.get(path, 0) + 1

    def _rewrite_doc(self, node: dict, prefix: str) -> dict:
        out: dict[str, Any] = {}
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                sub = self._rewrite_doc(v, path)
                if sub:
                    out[k] = sub
                continue
            if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                subs = [self._rewrite_doc(x, path) if isinstance(x, dict)
                        else self._rewrite_leaf(path, x) for x in v]
                subs = [s for s in subs if s is not _DROP]
                if subs:
                    out[k] = subs
                continue
            leaf = self._rewrite_leaf(path, v)
            if leaf is not _DROP:
                out[k] = leaf
        return out

    def _rewrite_leaf(self, path: str, value: Any) -> Any:
        rule = self._rule_for(path)
        if rule is None:
            self._drop(path)
            return _DROP
        if isinstance(value, list):
            items = [self._rewrite_leaf(path, x) for x in value]
            return [x for x in items if x is not _DROP]
        if value is None or isinstance(value, bool):
            return value
        if rule.kind == "identifier":
            if not self._mappable(value):
                return value
            return self.label_for(rule, str(value))
        if rule.kind == "text":
            if not isinstance(value, str):
                return value
            if len(value) > self.config.max_text_chars:
                value = value[: self.config.max_text_chars] + " [truncated]"
            return self._scrub_text(value)
        return self._keep_value(value)

    def _keep_value(self, value: Any) -> Any:
        """A keep-field value, with tier 1 run over it.

        "Keep" means the site declared the field non-sensitive, but a real
        level field held a SharePoint personal-site URL among its info/warn
        spellings, and a keep value reaches Claude both in hits and as a
        bucket key. So every string keep value gets tier 1 (never tier 2),
        and a match is replaced the way it would be in a message. Numbers,
        booleans and time-shaped strings are returned untouched (nothing
        sensitive fits in ``_TIME_SHAPED``, and every hit carries a
        timestamp, so skipping them is most of the cost).

        **Known values are matched narrowly here.** A name learnt from the
        vocabulary or harvested off a page replaces a keep value only when
        it *is* the value (ignoring case and outer spaces), never a part of
        a longer one: with ~10k vocabulary names in the sweep, a job called
        Harborsync turned ``logs-agent.harborsync_events-prod`` into
        ``logs-agent.<Job-03>_events-prod`` in the index, dataset and
        namespace, and Claude could no longer filter by the dataset. A
        value the human **seeded** still matches anywhere, as does anything
        tier 1 recognises by shape. Declared cost: a customer name inside a
        longer keep value (an index named after a customer) is readable.

        The result is marked (:class:`_KeepStr`) so the pass-3 sweep and
        the leak check apply the same rule; :meth:`_unmark` drops the mark.
        """
        if not isinstance(value, str) or _TIME_SHAPED.fullmatch(value):
            return value
        if len(value) > self.config.max_text_chars:
            value = value[: self.config.max_text_chars] + " [truncated]"
        whole = self._keep_whole(value)
        if whole is not None:
            return whole
        self._known_only = self._keep_only()
        try:
            out = self._scrub_text(value, shaped_only=True)
        finally:
            self._known_only = None
        return out if out in self.mapping else _keep_mark(out)

    def _keep_only(self) -> set[str] | None:
        """The labels allowed to match inside a keep value: the seeded ones."""
        return None if self.keep_parts_swept else self.seeded_labels

    def _keep_whole(self, value: str) -> str | None:
        """The label for a keep value that is wholly a known value, else None."""
        n = jsonscrub._norm(value)
        if n in self.known and n not in jsonscrub._STOPWORDS \
                and self.known[n] not in self.readable_words:
            return self.known[n]
        return None

    @classmethod
    def _unmark(cls, node: Any) -> Any:
        if isinstance(node, _KeepStr):
            return str.__str__(node)
        if isinstance(node, dict):
            return {k: cls._unmark(v) for k, v in node.items()}
        if isinstance(node, list):
            return [cls._unmark(v) for v in node]
        return node

    def leak_check(self, out: Any) -> list[str]:
        """As the file scrubber's, with a keep value checked by the keep
        rule: a learnt value inside a longer keep value is readable by
        declaration, not a leak; a seeded one is."""
        leaked: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if not jsonscrub._PLAIN_KEY.match(str(k)):
                        walk(k)
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
            elif isinstance(node, _KeepStr):
                if self._keep_whole(node) is not None:
                    leaked.add(self._keep_whole(node))
                self._known_only = self._keep_only()
                try:
                    hits = self._find_known(str.__str__(node))
                finally:
                    self._known_only = None
                for _, _, v in hits:
                    leaked.add(self.known[v])
            elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
                for _, _, v in self._find_known(str(node)):
                    leaked.add(self.known[v])

        walk(out)
        return sorted(leaked)

    # -- aggregations ------------------------------------------------------

    def _harvest_aggs(self, aggs: dict, plans: dict[str, AggPlan]) -> None:
        for name, node in aggs.items():
            plan = plans.get(name)
            if plan is None:
                raise self._refuse("unplanned_agg", "response withheld: an aggregation the "
                                                    "query did not declare came back")
            if not isinstance(node, dict):
                raise self._refuse("malformed", "response withheld: aggregation is not an object")
            buckets = node.get("buckets")
            if isinstance(buckets, list):
                for b in buckets:
                    if not isinstance(b, dict):
                        continue
                    if plan.rule is not None and plan.rule.kind == "identifier" and "key" in b:
                        self.label_for(plan.rule, str(b["key"]))
                    self._harvest_aggs(_sub_aggs(b), plan.subs)
            elif isinstance(buckets, dict):
                for b in buckets.values():
                    if isinstance(b, dict):
                        self._harvest_aggs(_sub_aggs(b), plan.subs)
            if plan.type == "top_hits":
                inner = node.get("hits", {}).get("hits", [])
                for h in inner if isinstance(inner, list) else []:
                    self._harvest_hit(h)

    def _rewrite_aggs(self, aggs: dict, plans: dict[str, AggPlan]) -> dict:
        out: dict[str, Any] = {}
        for name, node in aggs.items():
            plan = plans[name]
            out[name] = self._rewrite_agg(node, plan)
        return out

    def _rewrite_agg(self, node: dict, plan: AggPlan) -> dict:
        out: dict[str, Any] = {}
        if plan.type in {"terms", "date_histogram", "histogram"}:
            buckets = node.get("buckets")
            if not isinstance(buckets, list):
                raise self._refuse("malformed", "response withheld: bucket list missing")
            if len(buckets) > self.config.max_buckets:
                raise self._refuse("size_cap", "response withheld: more buckets than the cap")
            rows = []
            for b in buckets:
                row: dict[str, Any] = {}
                if plan.rule is not None and plan.rule.kind == "identifier":
                    row["key"] = self.label_for(plan.rule, str(b.get("key")))
                else:
                    # a keep-field key passes through _keep_value like a hit's
                    # leaf: an aggregation over the field is the other way a
                    # stray sensitive value in a keep field reaches Claude.
                    # Still one bucket, its key rewritten, its count kept.
                    row["key"] = self._keep_value(b.get("key"))
                    if "key_as_string" in b:
                        row["key_as_string"] = self._keep_value(b["key_as_string"])
                row["doc_count"] = b.get("doc_count")
                row.update(self._rewrite_aggs(_sub_aggs(b), plan.subs))
                rows.append(row)
            out["buckets"] = rows
            for k in ("doc_count_error_upper_bound", "sum_other_doc_count"):
                if k in node:
                    out[k] = node[k]
            return out
        if plan.type == "filters":
            buckets = node.get("buckets")
            if not isinstance(buckets, dict):
                raise self._refuse("malformed", "response withheld: filters buckets missing")
            out["buckets"] = {}
            for name in plan.names:
                b = buckets.get(name)
                if not isinstance(b, dict):
                    continue
                row = {"doc_count": b.get("doc_count")}
                row.update(self._rewrite_aggs(_sub_aggs(b), plan.subs))
                out["buckets"][name] = row
            return out
        if plan.type == "top_hits":
            inner = node.get("hits", {})
            rows = inner.get("hits", []) if isinstance(inner, dict) else []
            if len(rows) > self.config.max_hits:
                raise self._refuse("size_cap", "response withheld: more hits than the cap allows")
            return {"hits": {"total": self._total(inner.get("total") if isinstance(inner, dict) else None),
                             "hits": [self._rewrite_hit(h) for h in rows]}}
        if plan.type == "percentiles":
            vals = node.get("values")
            return {"values": vals if isinstance(vals, dict) else {}}
        # single-value metrics: min, max, avg, sum, value_count, cardinality
        out["value"] = node.get("value")
        if "value_as_string" in node:
            out["value_as_string"] = node["value_as_string"]
        return out

    # -- sweep -------------------------------------------------------------

    def _sweep(self, node: Any) -> Any:
        if isinstance(node, dict):
            return {k: self._sweep(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self._sweep(v) for v in node]
        if isinstance(node, _KeepStr):
            # a keep value: the whole-value rule of _keep_value, again with
            # whatever pass 2 learnt
            whole = self._keep_whole(node)
            if whole is not None:
                return whole
            self._known_only = self._keep_only()
            try:
                return _keep_mark(self._substitute(str.__str__(node)))
            finally:
                self._known_only = None
        if isinstance(node, str):
            if node in self.mapping:
                return node
            n = jsonscrub._norm(node)
            # The whole-string branch has to honour the readable-word rule
            # too, or a message that is just "Backup" would lose the word
            # case-wide by this route while the sweep index does not.
            if n in self.known and n not in jsonscrub._STOPWORDS \
                    and self.known[n] not in self.readable_words:
                return self.known[n]
            return self._substitute(node)
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            n = jsonscrub._norm(str(node))
            if n in self.known and self.known[n] not in self.readable_words:
                return self.known[n]
        return node

    # -- persistence -------------------------------------------------------

    def save_session(self, directory: str | Path) -> Path:
        """Write the sensitive half of a case next to its vault. Gitignored.

        Decisions elsewhere, data here: this is the one file that holds the
        real values, and it stays under ``out/``.
        """
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        self.vault.save(d / "vault.json")
        (d / "session.json").write_text(json.dumps({
            "schema": SESSION_SCHEMA,
            "mapping": self.mapping,
            "types": self.types,
            # labels only, no values: which of them the case has been shown
            "shown": sorted(self.shown),
            # labels only: which values the human seeded (they match inside
            # a keep value; learnt ones only as the whole value)
            "seeded": sorted(self.seeded_labels),
            # keep values this case was shown (they are values, which is
            # why they are in this file and nowhere else)
            "shown_keep": sorted(self.shown_keep),
            # phrases this case spent against phrase_budget, as typed
            # (normalised) - what Claude wrote, kept with the case's values
            "phrases_spent": sorted([f, k] for f, k in self.phrases_spent),
            # labels only: which of them are ordinary words, labelled in
            # their own field and readable in text everywhere else
            "readable_words": sorted(self.readable_words),
        }, indent=1), encoding="utf-8")
        return d

    @classmethod
    def load_session(cls, directory: str | Path, config: ElasticConfig, *,
                     tier2: str = "classifier") -> "EsScrubber":
        d = Path(directory)
        vault = pseudonym.EntityVault.load(d / "vault.json")
        raw = json.loads((d / "session.json").read_text(encoding="utf-8"))
        if raw.get("schema") != SESSION_SCHEMA:
            raise ConfigError(f"{d}: not a session directory")
        s = cls(config, tier2=tier2, vault=vault)
        for label, value in raw["mapping"].items():
            etype = raw["types"].get(label, "UNKNOWN")
            if log_vocabulary_only(value):
                # Saved before tier 2 stopped reading log words as names. Not
                # a known value any more, or the sweep would label log.level
                # again; still in the mapping, so answers already written
                # with its label unmask and a re-save keeps it.
                s.mapping.setdefault(label, value)
                s.types.setdefault(label, etype)
                continue
            s._remember(value, label, etype)
        # Which labels this case had been shown. A case saved **before**
        # that was recorded gets none: the mapping cannot stand in for it,
        # because a case saved after a cluster vocabulary was applied holds
        # a label for every name on the estate, and trusting those would
        # restore exactly the guessing channel this closes. The cost is
        # that a restored old case must see a label on a page again (one
        # query) or have its term re-seeded before using it.
        s.shown = {lab for lab in raw.get("shown") or () if lab in s.mapping}
        # A case saved before seeds were recorded has none: its seeded
        # values then match a keep value only whole, like a learnt one.
        s.seeded_labels = {lab for lab in raw.get("seeded") or () if lab in s.mapping}
        # A case saved before keep values were recorded starts with none: a
        # keep literal it could use must come back on a page again.
        s.shown_keep = {str(v) for v in raw.get("shown_keep") or ()}
        # A case saved before the phrase budget starts at zero spent: what
        # it used was never recorded, and guessing a count would be worse.
        s.phrases_spent = {(str(p[0]), str(p[1])) for p in raw.get("phrases_spent") or ()
                           if isinstance(p, (list, tuple)) and len(p) == 2}
        # Which labels are ordinary words, labelled in their own field and
        # readable in text everywhere else. A case saved **before** this was
        # recorded has them indexed for the case-wide sweep, as it was saved;
        # the declared default is to **demote them**, by the same test a
        # fresh case applies, so a restored case scrubs a page exactly as a
        # fresh one does - determinism is the property the rule exists for,
        # and a case that changed its mind about a word on restart would
        # have none of it. The cost: a word that was being hidden case-wide
        # becomes readable outside its own document, and an ordinary word
        # the human *seeded* on purpose is demoted with the rest (it cannot
        # be told from a harvested one with only the type to go on) - seed
        # it again to get it back.
        saved = raw.get("readable_words")
        labels = list(saved) if saved is not None else [
            lab for lab, value in s.mapping.items()
            if s.types.get(lab) in s._learnable_types and cls.vocabulary_skip(value)]
        for lab in labels:
            value = s.mapping.get(lab)
            if value is None:
                continue
            s.readable_words[lab] = value
            s._unindex_value(jsonscrub._norm(value))
        return s


@dataclass
class ClusterVocabulary:
    """What one cluster's name vocabulary holds, and what it covers.

    ``fields`` maps a field pattern to the distinct values read for it.
    These are **real customer names**, so this object is only ever written
    to the vocabulary file (0600 under the sessions directory, gitignored)
    and never to a log, a report or anything Claude sees.
    """

    covered_from: float
    covered_until: float
    built_at: float = 0.0
    fields: dict[str, list[str]] = dataclasses.field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {f: len(v) for f, v in self.fields.items()}

    def total(self) -> int:
        return sum(len(v) for v in self.fields.values())

    def merge(self, other: "ClusterVocabulary") -> "ClusterVocabulary":
        """Fold a top-up into what is already known, keeping order and
        dropping values already held."""
        fields = {f: list(v) for f, v in self.fields.items()}
        for f, values in other.fields.items():
            have = set(fields.setdefault(f, []))
            fields[f] += [v for v in values if v not in have and not have.add(v)]
        return ClusterVocabulary(min(self.covered_from, other.covered_from),
                                 max(self.covered_until, other.covered_until),
                                 other.built_at or self.built_at, fields)

    def covered_days(self, now: float) -> float:
        """How far back the cover reaches from ``now``, in days. What the
        VOCAB line shows and the only thing a user can use to know whether
        a name from a given day can be known at all."""
        return max(0.0, (self.covered_until - self.covered_from) / 86400.0)

    def serves(self, config: "ElasticConfig", now: float) -> bool:
        """Whether a case may be served from this cover.

        The recent slices are enough: they are what a case asks about, and
        waiting for the whole retention period means waiting hours. A name
        logged only in a day not yet covered is **not known** until the
        build reaches it - stated in AGENTS.md and visible on the VOCAB
        line as the covered range.
        """
        want = min(VOCABULARY_SERVE_DAYS * 86400.0, config.vocabulary_days * 86400.0)
        # How far back the cover reaches, not how fresh it is: a stale
        # cover is still served (with its age on the VOCAB line), which is
        # the trade the ten-minute refresh already accepted. ``now`` is
        # here because what counts as enough depends on the site map.
        return self.covered_until - self.covered_from >= want - 1.0

    def complete(self, config: "ElasticConfig", now: float) -> bool:
        """Whether the cover reaches the whole of ``vocabulary.days``."""
        return self.covered_from <= now - config.vocabulary_days * 86400.0 + 1.0

    def to_json(self) -> dict:
        return {"covered_from": self.covered_from, "covered_until": self.covered_until,
                "built_at": self.built_at, "fields": self.fields}

    @classmethod
    def from_json(cls, raw: Any) -> "ClusterVocabulary | None":
        if not isinstance(raw, dict):
            return None
        try:
            fields = {str(f): [v for v in vs if isinstance(v, str)]
                      for f, vs in (raw.get("fields") or {}).items() if isinstance(vs, list)}
            return cls(float(raw["covered_from"]), float(raw["covered_until"]),
                       float(raw.get("built_at") or 0.0), fields)
        except (KeyError, TypeError, ValueError):
            return None


class VocabularyIndex:
    """The built vocabularies, by cluster, saved beside the case state.

    Saved because the build is expensive and paid once per bridge: without
    a file, every ``es-login`` would pay it again. The file holds real
    names, so it lives under the sessions directory (gitignored), its
    directory is 0700 and the file is 0600, and nothing else in the system
    reads it - a log line, a report or a reply to Claude carries counts.
    """

    FILENAME = "vocabulary.json"
    SCHEMA = "hider.es-vocabulary.v1"

    def __init__(self, directory: str | Path | None) -> None:
        self.directory = Path(directory) if directory is not None else None
        self.clusters: dict[str, ClusterVocabulary] = {}
        #: cluster -> field -> ``{"count": n, "at": t}``: the fields a build
        #: found over ``vocabulary.max`` and therefore did not read. Saved
        #: beside the names and **not** inside a :class:`ClusterVocabulary`,
        #: because the decision has to outlive a slice that fails after it:
        #: that is what stops the next slice spending the same fifty
        #: requests. Counts and field names, never a value.
        self.over_cap: dict[str, dict[str, dict]] = {}
        #: Runtime only, set by the broker, never saved: when this bridge
        #: started, which clusters have a top-up or slice in flight, and
        #: which cluster's last slice failed and why. The state line reads
        #: them so a bridge is not charged for the time it was not running
        #: (see :meth:`report`).
        self.started_at: float | None = None
        self.in_progress: set[str] = set()
        self.failed: dict[str, str] = {}
        self.load()

    @property
    def path(self) -> Path | None:
        return None if self.directory is None else self.directory / self.FILENAME

    def get(self, cluster: str) -> ClusterVocabulary | None:
        return self.clusters.get(cluster)

    def put(self, cluster: str, vocab: ClusterVocabulary) -> None:
        held = self.clusters.get(cluster)
        self.clusters[cluster] = vocab if held is None else held.merge(vocab)
        self.save()

    def note_over_cap(self, cluster: str, field: str, count: int, now: float) -> None:
        """Remember that ``field`` has more distinct values than the cap, so
        the next slice neither counts nor pages it. Saved at once, before
        the slice it was found in is whole: a slice that fails afterwards
        must not cost the same fifty requests again."""
        self.over_cap.setdefault(cluster, {})[field] = {"count": int(count), "at": float(now)}
        self.save()

    def over_cap_fields(self, cluster: str, now: float) -> dict[str, dict]:
        """The over-the-cap decisions still standing for a cluster. They
        expire after :data:`VOCABULARY_OVER_CAP_S` so a cap raised, or a
        field that stops being id-shaped, takes effect on its own."""
        held = self.over_cap.get(cluster) or {}
        return {f: v for f, v in held.items()
                if now - float(v.get("at", 0.0)) < VOCABULARY_OVER_CAP_S}

    def load(self) -> None:
        path = self.path
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # unreadable or half-written: rebuild rather than guess
        if not isinstance(raw, dict) or raw.get("schema") != self.SCHEMA:
            return
        for name, entry in (raw.get("clusters") or {}).items():
            vocab = ClusterVocabulary.from_json(entry)
            if vocab is not None:
                self.clusters[str(name)] = vocab
        for name, entry in (raw.get("over_cap") or {}).items():
            if not isinstance(entry, dict):
                continue
            kept = {str(f): {"count": int(v.get("count", 0)), "at": float(v.get("at", 0.0))}
                    for f, v in entry.items()
                    if isinstance(v, dict) and isinstance(v.get("count"), (int, float))
                    and isinstance(v.get("at"), (int, float))}
            if kept:
                self.over_cap[str(name)] = kept

    def save(self) -> None:
        path = self.path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        body = {"schema": self.SCHEMA,
                "clusters": {n: v.to_json() for n, v in self.clusters.items()},
                "over_cap": {n: v for n, v in self.over_cap.items() if v}}
        tmp = path.with_suffix(".tmp")
        old = os.umask(0o077)
        try:
            tmp.write_text(json.dumps(body), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(path)
        finally:
            os.umask(old)

    def report(self, cluster: str, config: ElasticConfig,
               now: float | None = None) -> dict:
        """Counts and coverage for the log and the VOCAB line, never a name.

        Two kinds of field are named as left out, with the reason each
        time: ``omitted``, which the site map's own ``vocabulary.fields``
        leaves out, and ``over_cap``, which a build counted and found too
        wide to read. Both are field names, and ``over_cap`` carries the
        count that decided it. Their values stay readable in message text,
        which is the whole reason they are reported at all.
        """
        vocab = self.clusters.get(cluster)
        t = time.time() if now is None else now
        over_cap = {f: int(v["count"]) for f, v in self.over_cap_fields(cluster, t).items()}
        if vocab is None:
            # Nothing to read is not the same as not having read it yet: a
            # site map with no learnable field (or one that lists none) is
            # ready at once, or every case would wait for a build that is
            # never going to start.
            nothing_to_read = not config.vocabulary_rules
            return {"state": "ready" if nothing_to_read else "building",
                    "serving": nothing_to_read, "complete": nothing_to_read,
                    "fields": {}, "max": config.vocabulary_max,
                    "near_cap": [], "skipped": {}, "over_cap": over_cap,
                    "omitted": list(config.vocabulary_omitted)}
        counts = vocab.counts
        cap = config.vocabulary_max
        serving = vocab.serves(config, t)
        complete = vocab.complete(config, t)
        # Overdue is measured from when the top-up could have started on
        # *this* bridge: the end of the cover, or the bridge's start if that
        # is later. A bridge restarted a day after the last one holds a cover
        # a day old, and its first top-up is due, not overdue - the age it is
        # charged for is time it was not running. The age itself (age_s) is
        # still the honest one, from the end of the cover.
        chance = vocab.covered_until if self.started_at is None \
            else max(vocab.covered_until, self.started_at)
        topping_up = cluster in self.in_progress
        failed = self.failed.get(cluster)
        if not serving:
            # read something, but not far enough back yet to answer a case
            state = "building"
        elif t - vocab.covered_until <= VOCABULARY_REFRESH_S:
            state = "ready" if complete else "extending"
        elif topping_up:
            # the top-up is running: names logged since the cover ended are
            # not known yet, and nothing is wrong
            state = "top_up_due"
        elif failed is not None or t - chance > VOCABULARY_REFRESH_S + config.vocabulary_budget_s:
            # the top-up had its chance on this bridge and did not finish,
            # or its last attempt failed
            state = "stale"
        else:
            # due, and a slice starts next (next_vocabulary_slice puts the
            # newest end first). Nothing is wrong yet: reading the first two
            # days at sign-in takes longer than the refresh interval, so this
            # is the state es-login returns to.
            state = "top_up_due"
        out = {
            "state": state, "serving": serving, "complete": complete,
            "topping_up": topping_up,
            "fields": counts, "max": cap,
            "near_cap": sorted(f for f, n in counts.items() if n >= VOCABULARY_NEAR_CAP * cap),
            "skipped": {},
            "over_cap": over_cap,
            "omitted": list(config.vocabulary_omitted),
            "covered_days": round(vocab.covered_days(t), 2),
            "wanted_days": config.vocabulary_days,
            "age_s": round(max(0.0, t - vocab.covered_until), 1),
        }
        if state == "stale" and failed is not None:
            out["refused"] = failed
        return out


def next_vocabulary_slice(config: "ElasticConfig", held: "ClusterVocabulary | None",
                          now: float) -> tuple[float, float] | None:
    """The next one-day slice to read for a cluster, or None if the cover
    is complete and fresh.

    Newest first, and contiguous: the slice is either the gap between what
    is covered and now (a top-up, which is also the very first slice when
    nothing is held), or the day immediately before the oldest day covered.
    Contiguity is what lets the saved cover stay a single range, and what
    makes a restart resume rather than start over - whatever was saved
    before the bridge stopped is still covered.
    """
    if not config.vocabulary_rules:
        return None
    oldest = now - config.vocabulary_days * 86400.0
    if held is None:
        return (max(oldest, now - VOCABULARY_SLICE_S), now)
    if now - held.covered_until >= VOCABULARY_REFRESH_S:
        # the newest end first: a case cares about now, not about 30 days ago
        return (held.covered_until, now)
    if held.covered_from > oldest + 1.0:
        return (max(oldest, held.covered_from - VOCABULARY_SLICE_S), held.covered_from)
    return None


class VocabularyBuild:
    """One **slice** of a cluster's vocabulary: resumable, paged,
    one field per request.

    Why one field per request rather than one aggregation per field in one
    request: the measured cost is per aggregation, not per round trip (8 to
    35 seconds for a page of 1,000 values), and a request carrying every
    field pays all of them before it can be stopped, checked or logged. One
    field at a time makes the budget enforceable between fields, lets
    progress be logged as it happens, and lets a build resume where it
    stopped. Each request also carries an ``exists`` filter on the field
    it reads, which is what makes the job-name read affordable: most
    documents have no job field.

    Fields are read JOB_NAME-first, because a message naming a tenant
    almost always carries the tenant fields on the same document (the page
    harvest covers it) while about three in four messages naming a job do
    not. If a build is interrupted, the valuable half is the part already
    done.

    **Every field is counted before it is paged.** One ``cardinality``
    request per field per slice (no paging, no sort) says roughly how many
    distinct values the field has in the slice, and a field over
    ``vocabulary.max`` is never paged. Without it, an id-shaped field - a
    per-request reference, say, with a fresh value on almost every document
    - was paged to the cap and *then* refused, which cost fifty-one
    requests and failed the whole slice; the slice was retried and failed
    the same way for ever, so no case ever ran. What happens to the field
    now depends on who chose it:

    * **the default field set** (no ``vocabulary.fields`` in the site map):
      the field is left out, the build carries on with the rest, and the
      decision is saved (``dropped``) so later slices and restarts do not
      ask again for :data:`VOCABULARY_OVER_CAP_S`. The cost is stated: that
      field's values stay readable in message text, and the VOCAB line is
      where a site sees it;
    * **a field the map lists itself**: the slice is refused, as before,
      with a message naming the field and saying to remove it or raise the
      cap. A site that named the field asked for it to be read, and reading
      most of it is not that.

    **Nothing is learnt from a partial read.** A field is committed to the
    build only when its last page has come back; a slice is committed to
    the index only when every field is done. An upstream error, a partial
    or misshapen reply, a listed field over ``vocabulary.max``, or the
    slice over ``vocabulary.budget_s`` leaves the index exactly as it was -
    including every slice already saved, which is the point of slicing: one
    bad day does not cost the twenty-nine good ones. A field left out is
    not a partial read of it: nothing it returned is kept.

    One instance covers one slice (:func:`next_vocabulary_slice` decides
    which), so the budget below is per slice, and ``requests`` and
    ``seconds`` are that slice's.
    """

    def __init__(self, config: ElasticConfig, covered_from: float, covered_until: float, *,
                 clock=None, over_cap: dict[str, Any] | None = None, probe: bool = True) -> None:
        self.config = config
        self.covered_from = covered_from
        self.covered_until = covered_until
        #: fields already known to be over the cap, from an earlier slice or
        #: an earlier run: field -> the count that decided it. They are not
        #: probed and not paged.
        self.remembered: dict[str, int] = {
            f: int((v or {}).get("count", 0)) for f, v in (over_cap or {}).items()}
        #: job names first: see the class docstring
        self.rules = [r for r in sorted(config.vocabulary_rules,
                                        key=lambda r: (r.type != "JOB_NAME", r.pattern))
                      if r.pattern not in self.remembered]
        self.values: dict[str, list[str]] = {r.pattern: [] for r in self.rules}
        #: fields this slice found over the cap: field -> the count that
        #: decided it. The broker saves these, so the next slice skips them.
        self.dropped: dict[str, int] = {}
        self._clock = clock if clock is not None else time.monotonic
        self._t0 = self._clock()
        self._at = 0                      # index of the field being read
        self._after: dict | None = None   # composite after_key for that field
        #: measurement switch, set by nothing in the live path: with it off
        #: a field is paged straight away, which is what the build did
        #: before the probe existed. ``es-eval`` uses it for the "before"
        #: half of the oversized-field figure.
        self._probe = probe
        self._counting = probe            # the next request for this field is the probe
        self.requests = 0
        self.probes = 0
        self.seconds = 0.0
        self.failed: str | None = None

    # -- progress ----------------------------------------------------------

    def pending(self) -> bool:
        return self.failed is None and self._at < len(self.rules)

    @property
    def field(self) -> str | None:
        return self.rules[self._at].pattern if self._at < len(self.rules) else None

    def progress(self) -> dict:
        """Counts only, for the decision log and the VOCAB line."""
        out = {"fields_done": self._at, "fields_total": len(self.rules),
               "field": self.field, "values": {f: len(v) for f, v in self.values.items() if v},
               "requests": self.requests, "probes": self.probes,
               "seconds": round(self.seconds, 1),
               "budget_s": self.config.vocabulary_budget_s}
        # field names and counts, never a value
        if self.dropped:
            out["over_cap"] = dict(self.dropped)
        if self.remembered:
            out["over_cap_remembered"] = dict(self.remembered)
        return out

    def take_dropped(self) -> dict[str, int]:
        """Fields found over the cap since this was last called, for the
        caller to save. Names and counts."""
        out, self.dropped = dict(self.dropped), {}
        self.remembered.update(out)
        return out

    # -- driving -----------------------------------------------------------

    def request(self) -> dict:
        """The next request for the field being read: its distinct count if
        it has not been counted yet, otherwise its next page. One field,
        one ``exists`` filter, no input from Claude and no value in it."""
        rule = self.rules[self._at]
        self.requests += 1
        if self._counting:
            self.probes += 1
            # precision_threshold at the cap (ES's own ceiling above that):
            # the count is at its most accurate exactly where the decision
            # is made, and it is one request with no paging behind it
            agg: dict[str, Any] = {VOCABULARY_COUNT_AGG: {"cardinality": {
                "field": rule.pattern,
                "precision_threshold": min(VOCABULARY_PRECISION_CEILING,
                                           max(1, self.config.vocabulary_max))}}}
        else:
            comp: dict[str, Any] = {
                "size": VOCABULARY_PAGE,
                "sources": [{VOCABULARY_SOURCE: {"terms": {"field": rule.pattern}}}],
            }
            if self._after is not None:
                comp["after"] = self._after
            agg = {f"{VOCABULARY_AGG}_0": {"composite": comp}}
        # ignore_unavailable: a configured pattern one cluster does not have
        # (no traces in EMEA) reads as no names, not as a failed build
        return {"params": {"index": ",".join(self.config.indices), "ignore_unavailable": True,
                           "body": {
            "size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [
                {"range": {self.config.time_field: {"gte": _iso(self.covered_from),
                                                    "lte": _iso(self.covered_until)}}},
                {"exists": {"field": rule.pattern}},
            ]}},
            "aggs": agg,
        }}}

    def feed(self, raw: Any) -> None:
        """Take one reply - a distinct count or a page. Raises
        :class:`Refused`; the index is untouched until the slice is whole."""
        rule = self.rules[self._at]
        aggs = self._aggregations(raw)
        if self._counting:
            self._take_count(rule, aggs)
        else:
            self._take_page(rule, aggs)
        self.seconds = self._clock() - self._t0
        if self.pending() and self.seconds > self.config.vocabulary_budget_s:
            raise self._fail("vocabulary", (
                f"reading one slice of the name vocabulary passed "
                f"{self.config.vocabulary_budget_s:g}s (vocabulary.budget_s, which is per "
                f"slice) after {self.requests} requests and "
                f"{self._at} of {len(self.rules)} fields"))

    def _aggregations(self, raw: Any) -> dict:
        klass = error_class(raw) if isinstance(raw, dict) else None
        if klass is not None:
            raise self._fail("upstream_error", f"upstream error: {klass}")
        if not isinstance(raw, dict) or raw.get("isRunning") is True \
                or raw.get("isPartial") is True:
            raise self._fail("vocabulary", "the name vocabulary could not be read from the "
                                           "cluster")
        body = raw.get("rawResponse", raw)
        aggs = body.get("aggregations") if isinstance(body, dict) else None
        if not isinstance(aggs, dict) or body.get("timed_out") is True:
            raise self._fail("vocabulary", "the name vocabulary reply was incomplete")
        return aggs

    def _next_field(self) -> None:
        self._at += 1
        self._after = None
        self._counting = self._probe

    def _take_count(self, rule: FieldRule, aggs: dict) -> None:
        """One distinct count. Over the cap, the field is never paged."""
        node = aggs.get(VOCABULARY_COUNT_AGG)
        value = node.get("value") if isinstance(node, dict) else None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise self._fail("vocabulary", "the name vocabulary count was not the shape it "
                                           "was asked for")
        count = int(value)
        cap = self.config.vocabulary_max
        listed = self.config.vocabulary_fields is not None
        # The count is approximate, so the margin decides what "near the
        # cap" means - and it is applied in whichever direction keeps the
        # build running. A default field within the margin is left out (the
        # build carries on); a listed field within it is paged, because
        # there "over the cap" means refusing the slice and the exact
        # page-time count should be what does that.
        over = count * (1 - VOCABULARY_PROBE_MARGIN) > cap if listed \
            else count * (1 + VOCABULARY_PROBE_MARGIN) > cap
        if over:
            self._over_cap(rule, count, approximate=True)
            return
        self._counting = False

    def _over_cap(self, rule: FieldRule, count: int, *, approximate: bool) -> None:
        """A field with more distinct values than ``vocabulary.max``."""
        cap = self.config.vocabulary_max
        about = f"about {count}" if approximate else f"more than {cap}"
        if self.config.vocabulary_fields is not None:
            # the map asked for this field by name: reading most of it is
            # not what it asked for
            raise self._fail("vocabulary", (
                f"{rule.pattern} has {about} distinct values in the range read, over the "
                f"vocabulary.max cap of {cap}, and the site map lists {rule.pattern} in "
                f"vocabulary.fields; remove it from vocabulary.fields (its values then stay "
                f"readable in message text) or raise vocabulary.max"))
        # the default field set: leave it out, carry on, and remember it
        self.dropped[rule.pattern] = count
        self.values.pop(rule.pattern, None)
        self._next_field()

    def _take_page(self, rule: FieldRule, aggs: dict) -> None:
        agg = aggs.get(f"{VOCABULARY_AGG}_0")
        buckets = agg.get("buckets") if isinstance(agg, dict) else None
        if not isinstance(buckets, list):
            raise self._fail("vocabulary", "the name vocabulary reply was incomplete")
        got = self.values[rule.pattern]
        for b in buckets:
            key = b.get("key") if isinstance(b, dict) else None
            value = key.get(VOCABULARY_SOURCE) if isinstance(key, dict) else None
            if not isinstance(value, str):
                raise self._fail("vocabulary", "the name vocabulary reply was not the shape "
                                               "it was asked for")
            got.append(value)
        if len(got) > self.config.vocabulary_max:
            # the exact count, and the backstop under the approximate one:
            # a field the probe put under the cap, or a probe that was
            # never asked for, is still never read past it
            self._over_cap(rule, len(got), approximate=False)
            return
        after = agg.get("after_key")
        if len(buckets) < VOCABULARY_PAGE or not isinstance(after, dict):
            self._next_field()       # this field is read whole
        else:
            self._after = after

    def _fail(self, code: str, message: str) -> Refused:
        self.failed = code
        return Refused(code, f"the name vocabulary build failed: {message}")

    def result(self) -> ClusterVocabulary:
        """What was read, once every field is done. Never called on a
        failed or unfinished build."""
        if self.pending() or self.failed:
            raise Refused("vocabulary", "the name vocabulary was not read whole")
        self.seconds = self._clock() - self._t0
        return ClusterVocabulary(self.covered_from, self.covered_until, time.time(),
                                 {f: list(v) for f, v in self.values.items()})


def _iso(t: float) -> str:
    """An epoch instant as the UTC timestamp Elasticsearch parses."""
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


_ALNUM = re.compile(r"[A-Za-z0-9]")


def log_vocabulary_only(value: Any) -> bool:
    """A value made of ``pipeline.LOG_VOCABULARY`` words and nothing else
    alphanumeric ("Info", "ERROR", "Warning - Failed"). "Info Systems" and
    "Error42" are not."""
    if not isinstance(value, str) or not pipeline._WORD.search(value):
        return False
    rest = pipeline._WORD.sub(lambda m: "" if pipeline.is_log_word(m.group(0)) else m.group(0),
                              value)
    return not _ALNUM.search(rest)


_DROP = object()


class _KeepStr(str):
    """A string in a keep position (a keep-field leaf, a keep bucket key,
    a hit's ``_index``), marked between the rewrite and the leak check so
    the sweep and the check apply the keep rule. Never leaves the
    scrubber: :meth:`EsScrubber._unmark` turns it back into a str."""

    __slots__ = ()


def _keep_mark(value: Any) -> Any:
    return _KeepStr(value) if isinstance(value, str) else value


def _sub_aggs(bucket: dict) -> dict:
    return {k: v for k, v in bucket.items()
            if k not in {"key", "key_as_string", "doc_count", "from", "to", "from_as_string",
                         "to_as_string"} and isinstance(v, dict)}
