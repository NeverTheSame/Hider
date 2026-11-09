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

import fnmatch
import json
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
DEFAULT_POLL_TIMEOUT_S = 120
MAX_POLL_TIMEOUT_S = 600
#: The name vocabulary (:class:`VocabularyFetch`): it reads the case's own
#: time window plus a margin, in pages, so a cluster with more distinct
#: names than one terms aggregation can carry is still readable. ``days`` is
#: the fallback window for a query that gives no start bound; ``max`` is the
#: hard ceiling per field, above which the case is refused rather than run on
#: a partial list; ``budget_s`` is how long the whole paged read may take;
#: refresh is how often it is read again so a name first logged mid-case is
#: known within ten minutes.
DEFAULT_VOCABULARY_DAYS = 30
MAX_VOCABULARY_DAYS = 400
DEFAULT_VOCABULARY_MAX = 50_000
MAX_VOCABULARY_MAX = 200_000
#: Values one composite page asks for. Fixed: it is a transport detail, not a
#: safety boundary (the ceiling and the budget are), and a site that could
#: tune it could only make the read slower or heavier.
VOCABULARY_PAGE = 1_000
#: Wall-clock a whole paged read may take before it is refused. A read runs
#: under the bridge's one lock, so it is time no other call can use.
DEFAULT_VOCABULARY_BUDGET_S = 60.0
MAX_VOCABULARY_BUDGET_S = 600.0
#: Added to each side of the case's window: a name's own field record is
#: often logged shortly before the message that mentions it.
DEFAULT_VOCABULARY_MARGIN_DAYS = 1
MAX_VOCABULARY_MARGIN_DAYS = 30
VOCABULARY_REFRESH_S = 600.0
VOCABULARY_AGG = "hider_vocabulary"
#: The one composite source name in a vocabulary aggregation.
VOCABULARY_SOURCE = "v"
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
#: One-word names that are ordinary words in log text. A one-word name is
#: matched as a word anywhere in a message, so a resource called "Archive"
#: would hide "archive" from every line. These are never vocabulary; their
#: own field still gets its label. A fixed list on purpose, not the system
#: dictionary: what is hidden must not depend on the machine it runs on.
ORDINARY_NAME_WORDS: frozenset[str] = frozenset({
    "archive", "archives", "backup", "backups", "default", "defaults", "primary", "secondary",
    "main", "master", "test", "tests", "testing", "dev", "development", "prod", "production",
    "staging", "stage", "demo", "sandbox", "legacy", "temp", "tmp", "shared", "public",
    "private", "general", "common", "global", "local", "internal", "external", "data",
    "files", "file", "documents", "document", "reports", "report", "mail", "mailbox",
    "mailboxes", "inbox", "sites", "site", "teams", "team", "users", "user", "admin",
    "admins", "finance", "legal", "sales", "marketing", "support", "operations", "security",
    "compliance", "audit", "records", "projects", "project", "exports", "export", "imports",
    "import", "logs", "log", "system", "service", "services", "server", "servers", "cloud",
    "storage", "vault", "store", "repository", "library", "home", "office", "retention",
    "hold", "policy", "policies", "daily", "weekly", "monthly", "nightly", "hourly", "full",
    "incremental", "delta", "sync", "job", "jobs", "task", "tasks", "queue", "worker",
    "workers", "agent", "agents", "engine", "cache", "index", "database", "network", "quota",
    "limit", "tenant", "tenants", "resource", "resources", "new", "old", "copy", "final",
    "draft", "current", "latest", "standard", "basic", "premium", "trial", "other", "misc",
    "all", "everyone", "group", "groups", "contacts", "calendar", "notes", "tasks", "onedrive",
    "sharepoint", "exchange", "outlook", "teams", "graph", "portal", "intranet", "extranet",
    *(w for w in paths.STRUCTURAL if " " not in w),
})
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

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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
    #: identifier fields read as a vocabulary; None: the site map did not
    #: say, so every field that *could* be read (:attr:`learnable_rules`)
    vocabulary_fields: tuple[str, ...] | None = None
    vocabulary_days: int = DEFAULT_VOCABULARY_DAYS
    vocabulary_max: int = DEFAULT_VOCABULARY_MAX
    vocabulary_margin_days: int = DEFAULT_VOCABULARY_MARGIN_DAYS
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
    """``{"fields": [...], "days": 30, "max": 50000, "margin_days": 1,
    "budget_s": 60}``, all optional.

    Each field must be a listed, non-glob identifier without a shape, of a
    type a vocabulary may hold (:data:`NO_VOCABULARY_TYPES` says which may
    not, and why). Absent: job names only."""
    if raw is None:
        return {}
    known = {"fields", "days", "max", "margin_days", "budget_s", "_comment"}
    if not isinstance(raw, dict) or set(raw) - known:
        raise ConfigError(f"{source}: vocabulary must be an object with "
                          f"{', '.join(sorted(known - {'_comment'}))}")
    out: dict[str, Any] = {}
    for key, default, ceiling in (("days", DEFAULT_VOCABULARY_DAYS, MAX_VOCABULARY_DAYS),
                                  ("max", DEFAULT_VOCABULARY_MAX, MAX_VOCABULARY_MAX),
                                  ("margin_days", DEFAULT_VOCABULARY_MARGIN_DAYS,
                                   MAX_VOCABULARY_MARGIN_DAYS)):
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
               "max_phrases", "vocabulary"}
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
    cfg = ElasticConfig(tuple(indices), rules, time_field, source=source, clusters=clusters,
                        profile_dir=profile_dir, poll_timeout_s=float(poll),
                        max_phrases=phrases, **caps)
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
        self._meta = {k: _parse_rule(k, v, "meta") for k, v in META_RULES.items()}
        for t in self.terms:
            if not (t.endswith("*") and len(t) > 2):
                self.seed(t, "ORG_NAME")

    # -- labels ------------------------------------------------------------

    def label_for(self, rule: FieldRule, value: str, *, parts: bool = True) -> str:
        """The stable label for a value seen under an identifier rule."""
        n = jsonscrub._norm(value)
        if n in self.known:
            return self.known[n]
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
        return self.label_for(rule, value)

    def _remember(self, value: str, label: str, etype: str, *, index: bool = True,
                  force: bool = False) -> None:
        super()._remember(value, label, etype, index=index, force=force)
        self.types.setdefault(label, etype)

    def resolve_label(self, label: str) -> tuple[str, str] | None:
        """(value, type) for a label this session minted, else None."""
        if label in self.mapping:
            return self.mapping[label], self.types.get(label, "")
        return None

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
    # no shape a rule could read, and its own field is usually on another
    # document than the message, so harvesting a page cannot see it on a fresh
    # case's first call. The cluster can: before the first page of a case on
    # a cluster, and again every VOCABULARY_REFRESH_S, the bridge sends one
    # fixed request, a terms aggregation per field the site map lists under
    # vocabulary.fields, and every value in the reply becomes a known value
    # under that field's own rule, so it gets the label it gets as a field
    # value. The sweep then labels the whole name wherever it appears. The
    # names never reach Claude, and the log holds counts only.

    def vocabulary_due(self, cluster: str, window: tuple[float, float] | None = None,
                       now: float | None = None) -> bool:
        """Is a read needed before showing a page of ``window`` on ``cluster``?

        A read covers an interval, so a later query inside an interval already
        read needs nothing; one reaching outside it does, and so does one
        after the refresh interval. An unbounded query covers the fallback
        window, which is the widest a read ever covers.
        """
        if not self._vocab_rules:
            return False
        at = self._vocabulary_at.get(cluster)
        if at is None:
            return True
        t = time.monotonic() if now is None else now
        if t - at[0] >= VOCABULARY_REFRESH_S:
            return True
        covered_lo, covered_hi = at[1], at[2]
        if window is None:
            # no bounds: only a fallback read (covered_lo None) covers it
            return covered_lo is not None
        if covered_lo is None:
            return False
        # the case's own window against what was read, margins not counted:
        # two queries over "now-6h" a second apart are the same case window,
        # and the margin is exactly the slack that makes them so
        lo, hi = window
        return not (covered_lo <= lo and (covered_hi is None or hi <= covered_hi))

    def vocabulary_window(self, window: tuple[float, float] | None
                          ) -> tuple[float | None, float | None]:
        """The interval a read covers, in epoch seconds; ``None`` is open.

        The case's own window widened by ``vocabulary.margin_days`` on each
        side, because a name's own field record is usually logged a little
        before the message that mentions it. A query with no start or no end
        falls back to ``vocabulary.days`` with no end, the behaviour before
        windowing, expressed as ``(None, None)`` so the request keeps using
        the cluster's clock rather than ours.
        """
        if window is None:
            return None, None
        margin = self.config.vocabulary_margin_days * 86400.0
        lo, hi = window
        return lo - margin, hi + margin

    def vocabulary_fetch(self, window: tuple[float, float] | None = None, *,
                         now: float | None = None) -> "VocabularyFetch":
        """A paged read of the name vocabulary for one case window.

        The caller drives it: while ``pending()``, send ``request()`` and hand
        the reply to ``feed()``; then ``commit(cluster)``. Nothing is learnt
        before the commit, so a refusal anywhere leaves the session unchanged.
        """
        return VocabularyFetch(self, self.vocabulary_window(window), now=now)

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
        """Make every name a read returned a known value. Called by
        :meth:`VocabularyFetch.commit`, never from a transport."""
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
        field names a vocabulary could hold that this map does not read."""
        cap = self.config.vocabulary_max
        return {"fields": dict(self.vocabulary_counts), "max": cap,
                "near_cap": sorted(f for f, n in self.vocabulary_counts.items()
                                   if n >= VOCABULARY_NEAR_CAP * cap),
                "skipped": dict(self.vocabulary_skipped),
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

    def _rewrite_hit(self, hit: dict) -> dict:
        out: dict[str, Any] = {"_index": hit["_index"]}
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
        bucket key. So every string keep value gets the shaped pass a text
        field gets - tier 1 and the known-value sweep, never tier 2 - and a
        match is replaced the way it would be in a message. An ordinary
        value matches nothing and comes back exactly as written, so
        filtering by it still works; a value tier 1 does claim is labelled,
        at the declared cost that filtering by it now needs a label its
        field cannot take. Numbers, booleans and time-shaped strings are
        returned untouched (nothing sensitive fits in ``_TIME_SHAPED``, and
        every hit carries a timestamp, so skipping them is most of the cost).
        """
        if not isinstance(value, str) or _TIME_SHAPED.fullmatch(value):
            return value
        if len(value) > self.config.max_text_chars:
            value = value[: self.config.max_text_chars] + " [truncated]"
        return self._scrub_text(value, shaped_only=True)

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
        if isinstance(node, str):
            if node in self.mapping:
                return node
            n = jsonscrub._norm(node)
            if n in self.known and n not in jsonscrub._STOPWORDS:
                return self.known[n]
            return self._substitute(node)
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            n = jsonscrub._norm(str(node))
            if n in self.known:
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
        return s


class VocabularyFetch:
    """One paged read of the name vocabulary, transport-agnostic.

    Why paged: one ``terms`` aggregation can only return what fits in one
    reply, so a cluster with more distinct names than the cap was refused
    outright - on a large estate, every case, always. A ``composite``
    aggregation pages instead, and the window it pages over is the case's own
    plus a margin rather than the whole retention period, which is what makes
    the read small enough to be worth doing at all.

    Fails closed, and nothing is learnt until :meth:`commit`: an upstream
    error, a partial or timed-out reply, a missing or malformed aggregation,
    a field over ``vocabulary.max`` or a read over ``vocabulary.budget_s``
    all raise :class:`Refused`, and the session is left exactly as it was.
    The request carries no input from Claude but the already-validated time
    bounds of the query being served, and never a value.
    """

    def __init__(self, scrubber: "EsScrubber", covers: tuple[float | None, float | None], *,
                 now: float | None = None) -> None:
        self.scrubber = scrubber
        self.config = scrubber.config
        self.covers = covers
        self.rules = list(scrubber._vocab_rules)
        #: field pattern -> values read so far, in reply order
        self.values: dict[str, list[str]] = {r.pattern: [] for r in self.rules}
        self._after: dict[int, dict | None] = {i: None for i in range(len(self.rules))}
        self._done: set[int] = set()
        self.requests = 0
        self.seconds = 0.0
        self._now = now
        self._t0 = time.monotonic()

    # -- driving -----------------------------------------------------------

    def pending(self) -> bool:
        return len(self._done) < len(self.rules)

    def request(self) -> dict:
        """The next page's request, one composite aggregation per field that
        has more to give."""
        self.requests += 1
        aggs = {}
        for i, rule in enumerate(self.rules):
            if i in self._done:
                continue
            comp: dict[str, Any] = {
                "size": VOCABULARY_PAGE,
                "sources": [{VOCABULARY_SOURCE: {"terms": {"field": rule.pattern}}}],
            }
            if self._after[i] is not None:
                comp["after"] = self._after[i]
            aggs[f"{VOCABULARY_AGG}_{i}"] = {"composite": comp}
        lo, hi = self.covers
        bounds = {"gte": f"now-{self.config.vocabulary_days}d" if lo is None else _iso(lo)}
        if hi is not None:
            bounds["lte"] = _iso(hi)
        # ignore_unavailable: a configured pattern one cluster does not have
        # (no traces in EMEA) reads as no names, not as a failed case
        return {"params": {"index": ",".join(self.config.indices), "ignore_unavailable": True,
                           "body": {
            "size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [{"range": {self.config.time_field: bounds}}]}},
            "aggs": aggs,
        }}}

    def feed(self, raw: Any) -> None:
        """Take one reply. Raises :class:`Refused`; learns nothing."""
        klass = error_class(raw) if isinstance(raw, dict) else None
        if klass is not None:
            raise Refused("upstream_error", f"upstream error: {klass}")
        if not isinstance(raw, dict) or raw.get("isRunning") is True \
                or raw.get("isPartial") is True:
            raise Refused("vocabulary", "response withheld: the name vocabulary could not be "
                                        "read from the cluster")
        body = raw.get("rawResponse", raw)
        aggs = body.get("aggregations") if isinstance(body, dict) else None
        if not isinstance(aggs, dict) or body.get("timed_out") is True:
            raise Refused("vocabulary", "response withheld: the name vocabulary reply was "
                                        "incomplete")
        for i, rule in enumerate(self.rules):
            if i in self._done:
                continue
            agg = aggs.get(f"{VOCABULARY_AGG}_{i}")
            buckets = agg.get("buckets") if isinstance(agg, dict) else None
            if not isinstance(buckets, list):
                raise Refused("vocabulary", "response withheld: the name vocabulary reply was "
                                            "incomplete")
            got = self.values[rule.pattern]
            for b in buckets:
                key = b.get("key") if isinstance(b, dict) else None
                value = key.get(VOCABULARY_SOURCE) if isinstance(key, dict) else None
                if not isinstance(value, str):
                    raise Refused("vocabulary", "response withheld: the name vocabulary reply "
                                                "was not the shape it was asked for")
                got.append(value)
            if len(got) > self.config.vocabulary_max:
                raise Refused("vocabulary", (
                    f"response withheld: {rule.pattern} has more than "
                    f"{self.config.vocabulary_max} distinct values in the window read "
                    f"(the cap is vocabulary.max); narrow the query's time range, or raise "
                    "vocabulary.max in the site map"))
            after = agg.get("after_key")
            if len(buckets) < VOCABULARY_PAGE or not isinstance(after, dict):
                self._done.add(i)
            else:
                self._after[i] = after
        self.seconds = time.monotonic() - self._t0
        if self.pending() and self.seconds > self.config.vocabulary_budget_s:
            raise Refused("vocabulary", (
                f"response withheld: reading the name vocabulary passed "
                f"{self.config.vocabulary_budget_s:g}s (vocabulary.budget_s) after "
                f"{self.requests} requests; narrow the query's time range"))

    def commit(self, cluster: str) -> dict[str, int]:
        """Learn everything read, atomically. Counts per field, never values."""
        if self.pending():
            raise Refused("vocabulary", "response withheld: the name vocabulary was not "
                                        "read whole")
        self.seconds = time.monotonic() - self._t0
        return self.scrubber._learn_vocabulary(cluster, self.values, now=self._now,
                                               covers=self.covers)


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


def _sub_aggs(bucket: dict) -> dict:
    return {k: v for k, v in bucket.items()
            if k not in {"key", "key_as_string", "doc_count", "from", "to", "from_as_string",
                         "to_as_string"} and isinstance(v, dict)}
