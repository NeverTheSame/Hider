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
    passed through unchanged. Filter, range, sort and aggregate freely.
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
from pathlib import Path
from typing import Any

from . import entities, jsonscrub, localcfg, pipeline, pseudonym

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

    def source_includes(self) -> list[str]:
        return [r.pattern for r in self.fields]

    @property
    def shaped_rules(self) -> tuple[FieldRule, ...]:
        return tuple(r for r in self.fields if r.shape is not None)

    def index_allowed(self, name: str) -> bool:
        """An index name a hit came from must match one allowlisted pattern."""
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.indices)

    def summary(self) -> dict:
        """What Claude may be told: names and kinds, nothing else."""
        return {
            "indices": list(self.indices),
            "time_field": self.time_field,
            "fields": {r.pattern: r.kind for r in sorted(self.fields, key=lambda r: r.pattern)},
            "max_hits": self.max_hits,
            "max_buckets": self.max_buckets,
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


def parse(raw: Any, *, source: str = "elastic") -> ElasticConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: top level must be an object")
    allowed = {"_comment", "indices", "fields", "time_field", "max_hits", "max_buckets",
               "max_text_chars", "clusters", "profile_dir"}
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
    cfg = ElasticConfig(tuple(indices), rules, time_field, source=source, clusters=clusters,
                        profile_dir=profile_dir, **caps)
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
    return cfg


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
        self._meta = {k: _parse_rule(k, v, "meta") for k, v in META_RULES.items()}
        for t in self.terms:
            if not (t.endswith("*") and len(t) > 2):
                self.seed(t, "ORG_NAME")

    # -- labels ------------------------------------------------------------

    def label_for(self, rule: FieldRule, value: str) -> str:
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
        return super()._scrub_text(text, shaped_only=shaped_only)

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
            raise self._refuse("incomplete", "response withheld: search still running")
        if raw.get("isPartial") is True:
            raise self._refuse("incomplete", "response withheld: partial results")
        body = raw.get("rawResponse", raw)
        if not isinstance(body, dict) or "hits" not in body:
            raise self._refuse("malformed", "response withheld: no hits section")
        if body.get("timed_out") is True:
            raise self._refuse("incomplete", "response withheld: search timed out")
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
        return value  # keep

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
                    row["key"] = b.get("key")
                    if "key_as_string" in b:
                        row["key_as_string"] = b["key_as_string"]
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
            s._remember(value, label, raw["types"].get(label, "UNKNOWN"))
        return s


_DROP = object()


def _sub_aggs(bucket: dict) -> dict:
    return {k: v for k, v in bucket.items()
            if k not in {"key", "key_as_string", "doc_count", "from", "to", "from_as_string",
                         "to_as_string"} and isinstance(v, dict)}
