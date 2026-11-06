"""Measure the Elasticsearch core offline: synthetic documents, a stub Kibana, numbers.

    python -m hider es-eval                     # example site map, writes out/es-eval.json
    python -m hider es-eval --config my.json    # a real site map, still no network

Nothing here talks to a cluster. :func:`generate` builds documents in the
three index shapes the design describes, from ``templates/elastic_fixtures.json``
and the entity generators, and records every customer value it plants.
:class:`StubEngine` answers the compiled async-search bodies from those
documents, and :class:`StubKibana` wraps it in the ``/internal/search/ese``
protocol (``kbn-xsrf``, ``x-elastic-internal-origin``, an async id, poll until
``isRunning`` is false) so the live bridge can be tested against it later
without a cluster either.

:func:`run_eval` drives a session the way Claude would, learning labels from
one response and using them in the next, and reports:

* **response leak rate**: scrubbed pages that still carry a planted value.
  Gate: zero. Refusals are counted separately, never as leaks.
* **refusals**, by code, and the **refusal rate on clean traffic**: pages
  whose text held no customer value at all.
* **label round trip**: a label learnt from a page, used as a filter,
  compiles to the real value and comes back as the same label.
* **oracle cases**: every entry in ``esquery.ORACLE_CASES`` refused with the
  code it declares.
* **field coverage**: how the fixture's field paths fall across the kinds,
  so default-deny blind spots are visible.
* **text queries**: how many phrase searches the run issued, because
  confirming a guessed word by hit count is the declared residual channel.
* **latency**: p50 and p95 of compile + scrub per page, tier 2 warm.
"""

from __future__ import annotations

import json
import math
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import Cookie, CookieJar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

from . import elastic, entities, esquery

TEMPLATES = Path(__file__).resolve().parent.parent / "templates" / "elastic_fixtures.json"
OUT = Path(__file__).resolve().parent.parent / "out"
NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
REGIONS = ("amer", "emea", "apj", "aus")
_PLACEHOLDER = re.compile(r"\{([A-Z_]+)\}")
_TOKEN = re.compile(r"[a-z0-9]+")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class Tenant:
    name: str
    full_name: str
    slug: str
    tenant_id: str
    users: int
    account_id: str
    upns: list[str]
    sites: list[str]
    onedrive: list[str]
    objects: list[str]
    jobs: list[tuple[str, str, str]]  # (job name, job id, object id)
    resources: list[str]


@dataclass
class Server:
    name: str
    ip: str
    mac: str
    instance: str


@dataclass
class Doc:
    index: str
    source: dict
    #: planted customer values -> what they are. The ground truth.
    seeded: dict[str, str] = field(default_factory=dict)
    clean: bool = False


@dataclass
class Fixture:
    docs: list[Doc]
    tenants: list[Tenant]
    servers: list[Server]
    unlisted_fields: tuple[str, ...] = ("process.command_line", "user.full_name")

    @property
    def truth(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for d in self.docs:
            out.update(d.seeded)
        return out


def _load() -> dict:
    return json.loads(TEMPLATES.read_text(encoding="utf-8"))


def _gen(etype: str, rng: random.Random) -> str:
    return entities.spec(etype).generate(rng)


def _tenant(rng: random.Random, tpl: dict) -> Tenant:
    name = _gen("ORG_NAME", rng)
    slug = re.sub(r"[^a-z0-9]", "", name.split()[0].lower()) + rng.choice(["", "corp", str(rng.randint(2, 89))])
    full = f"{name} {rng.choice(['Ltd', 'Inc', 'GmbH', 'LLC', 'S.A.'])}"
    upns = []
    for _ in range(3):
        local = _gen("UPN_EMAIL", rng).split("@")[0]
        upns.append(f"{local}@{slug}.com")
    sites = [f"https://{slug}.sharepoint.com/sites/{leaf}"
             for leaf in rng.sample(["Finance", "HR-Records", "Legal", "ProjectPhoenix", "Audit",
                                     "Marketing", "Board"], 3)]
    onedrive = []
    for u in upns[:2]:
        local = u.split("@")[0].replace(".", "_")
        onedrive.append(f"https://{slug}-my.sharepoint.com/personal/{local}_{slug}_com/Documents/"
                        f"{rng.choice(['Budget', 'Notes', 'Plan', 'Report'])}-{rng.randint(1, 99)}.docx")
    jobs = [(rng.choice(tpl["job_names"]), _gen("SESSION_GUID", rng), _gen("OBJECT_GUID", rng))
            for _ in range(3)]
    return Tenant(
        name=name, full_name=full, slug=slug, tenant_id=_gen("TENANT_ID", rng),
        users=rng.randint(40, 95000), account_id=f"{rng.randint(10**11, 10**12 - 1)}",
        upns=upns, sites=sites, onedrive=onedrive,
        objects=[_gen("OBJECT_GUID", rng) for _ in range(3)], jobs=jobs,
        resources=rng.sample(tpl["resource_names"], 2),
    )


def _server(rng: random.Random, role: str) -> Server:
    return Server(
        name=f"{role}-{rng.choice(REGIONS)}-{rng.randint(1, 400):03d}",
        ip=_gen("IPV4", rng),
        mac=":".join(f"{rng.randint(0, 255):02x}" for _ in range(6)),
        instance=f"i-{rng.getrandbits(48):012x}",
    )


def _ts(rng: random.Random) -> str:
    t = NOW - timedelta(seconds=rng.randint(0, 6 * 3600))
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rng.randint(0, 999):03d}Z"


class _Filler:
    """Fill one template for one document, recording what was planted."""

    def __init__(self, rng: random.Random, tenant: Tenant, server: Server) -> None:
        self.rng, self.t, self.s = rng, tenant, server
        self.seeded: dict[str, str] = {}

    def _plant(self, value: str, etype: str) -> str:
        self.seeded[value] = etype
        return value

    def __call__(self, text: str) -> str:
        rng, t, s = self.rng, self.t, self.s

        def one(m: re.Match) -> str:
            k = m.group(1)
            if k == "N":
                return str(rng.randint(1, 64))
            if k == "MS":
                return str(rng.randint(3, 90000))
            if k == "HTTP":
                return str(rng.choice([200, 201, 404, 429, 429, 500, 503]))
            if k == "PCT":
                return str(rng.randint(1, 100))
            if k == "BYTES":
                return str(rng.randint(1000, 5 * 10**9))
            if k == "TENANT_NAME":
                return self._plant(t.name, "ORG_NAME")
            if k == "TENANT_FULL_NAME":
                return self._plant(t.full_name, "ORG_NAME")
            if k == "TENANT_ID":
                return self._plant(t.tenant_id, "TENANT_ID")
            if k == "UPN":
                return self._plant(rng.choice(t.upns), "UPN_EMAIL")
            if k == "SITE_URL":
                return self._plant(rng.choice(t.sites), "SITE_URL")
            if k == "ONEDRIVE_URI":
                return self._plant(rng.choice(t.onedrive), "ONEDRIVE_URI")
            if k == "OBJECT_ID":
                return self._plant(rng.choice(t.objects), "OBJECT_GUID")
            if k == "SESSION_ID":
                return self._plant(rng.choice(t.jobs)[1], "SESSION_GUID")
            if k == "JOB_ID":
                return self._plant(rng.choice(t.jobs)[1], "SESSION_GUID")
            if k == "JOB_NAME":
                return self._plant(rng.choice(t.jobs)[0], "JOB_NAME")
            if k == "RESOURCE":
                return self._plant(rng.choice(t.resources), "RESOURCE_NAME")
            if k == "SERVER":
                return self._plant(s.name, "SERVER_NAME")
            if k == "HOST_IP":
                return self._plant(s.ip, "IPV4")
            return m.group(0)

        return _PLACEHOLDER.sub(one, text)


def generate(*, seed: int = 20261103, docs: int = 600, tenants: int = 8,
             clean_share: float = 0.25) -> Fixture:
    """Documents in the three index shapes, with ground truth.

    ``clean_share`` of the documents carry a message with no customer value
    (their identifier fields are still real; that is what the field map is
    for). The unlisted fields are planted with a customer value on purpose,
    so a failure of default-deny shows up as a leak.
    """
    rng = random.Random(seed)
    tpl = _load()
    ts = [_tenant(rng, tpl) for _ in range(tenants)]
    servers = {
        "ctr": [_server(rng, "ctr") for _ in range(6)],
        "prx": [_server(rng, "prx") for _ in range(6)],
        "api": [_server(rng, "api") for _ in range(3)],
    }
    out: list[Doc] = []
    for i in range(docs):
        index = rng.choices(["logs-app-*", "logs-worker-*", "traces-apm-*"], [6, 3, 2])[0]
        t = rng.choice(ts)
        clean = rng.random() < clean_share
        if index == "logs-app-*":
            s = rng.choice(servers["ctr"])
            f = _Filler(rng, t, s)
            job = rng.choice(t.jobs)
            msg = f(rng.choice(tpl["clean_messages"] if clean else tpl["messages"][index]))
            src = {
                "@timestamp": _ts(rng),
                "data_stream": {"dataset": rng.choice(tpl["datasets"][:3]), "type": "logs",
                                "namespace": "default"},
                "ecs": {"version": "8.11.0"},
                "event": {"outcome": rng.choice(tpl["outcomes"]), "action": "job-step"},
                "log": {"level": rng.choice(tpl["log_levels"]), "logger": "Engine.Jobs",
                        "file": {"path": f(rng.choice(tpl["log_file_paths"]))}},
                "message": msg,
                "agent": {"name": f._plant(s.name, "SERVER_NAME")},
                "host": {"name": s.name, "ip": f._plant(s.ip, "IPV4"),
                         "mac": f._plant(s.mac, "MAC_ADDRESS")},
                "cloud": {"account": {"id": f._plant(t.account_id, "CLOUD_ACCOUNT")},
                          "instance": {"name": f._plant(s.instance, "INSTANCE_NAME")}},
                "labels": {"tenant_name": f._plant(t.name, "ORG_NAME"),
                           "tenant_full_name": f._plant(t.full_name, "ORG_NAME"),
                           "tenant_id": f._plant(t.tenant_id, "TENANT_ID"),
                           "resource_name": f._plant(rng.choice(t.resources), "RESOURCE_NAME")},
                "job": {"id": f._plant(job[1], "SESSION_GUID"),
                        "session_id": f._plant(_gen("SESSION_GUID", rng), "SESSION_GUID"),
                        "object_id": f._plant(job[2], "OBJECT_GUID"),
                        "name": f._plant(job[0], "JOB_NAME"),
                        "status": rng.choice(tpl["job_statuses"]),
                        "status_message": f(rng.choice(tpl["clean_messages"] if clean
                                                       else tpl["messages"][index])),
                        "counters": {"items": rng.randint(0, 400000), "bytes": rng.randint(0, 10**10),
                                     "errors": rng.randint(0, 40)}},
                "tenant": {"users_in_tenant": t.users},
                "service": {"name": "backup-engine", "version": "8.4.1"},
                # unlisted on purpose: must be dropped, never shown
                "process": {"command_line": f"engine.exe --tenant {f._plant(t.name, 'ORG_NAME')}"},
            }
            f.seeded[str(t.users)] = "TENANT_SIZE"
        elif index == "logs-worker-*":
            s = rng.choice(servers["prx"])
            f = _Filler(rng, t, s)
            msg = f(rng.choice(tpl["clean_messages"] if clean else tpl["messages"][index]))
            src = {
                "@timestamp": _ts(rng),
                "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
                "event": {"outcome": rng.choice(tpl["outcomes"])},
                "log": {"level": rng.choice(tpl["log_levels"])},
                "message": msg,
                "agent": {"name": f._plant(s.name, "SERVER_NAME")},
                "host": {"name": s.name, "ip": f._plant(s.ip, "IPV4")},
                "labels": {"tenant_name": f._plant(t.name, "ORG_NAME"),
                           "tenant_id": f._plant(t.tenant_id, "TENANT_ID")},
                "user": {"full_name": f._plant(_gen("PERSON_NAME", rng), "PERSON_NAME")},
            }
        else:
            s = rng.choice(servers["api"])
            f = _Filler(rng, t, s)
            upn = rng.choice(t.upns)
            msg = f(rng.choice(tpl["clean_messages"] if clean else tpl["messages"][index]))
            src = {
                "@timestamp": _ts(rng),
                "data_stream": {"dataset": "apm.transaction", "type": "traces", "namespace": "default"},
                "message": msg,
                "transaction": {"name": f(rng.choice(tpl["transaction_names"])),
                                "duration": {"us": rng.randint(900, 9_000_000)},
                                "result": rng.choice(["HTTP 2xx", "HTTP 4xx", "HTTP 5xx"])},
                "labels": {"principal_name": f._plant(upn, "UPN_EMAIL"),
                           "tenant_id": f._plant(t.tenant_id, "TENANT_ID")},
                "agent": {"name": f._plant(s.name, "SERVER_NAME")},
                "service": {"name": "backup-api"},
            }
        out.append(Doc(index, src, f.seeded, clean))
    return Fixture(out, ts, [x for xs in servers.values() for x in xs])


# ---------------------------------------------------------------------------
# A small Elasticsearch, enough for the grammar
# ---------------------------------------------------------------------------


def flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(flatten(v, p))
            else:
                out[p] = v
    return out


def _unflatten(flat: dict[str, Any]) -> dict:
    out: dict = {}
    for path, v in flat.items():
        cur = out
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def _parse_time(v: Any, *, round_up: bool = False) -> datetime | None:
    """A stored or bound time. As Elasticsearch: a time without a zone is UTC,
    and a bare date read with ``round_up`` (gt, lte) is its last millisecond."""
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
    if not isinstance(v, str):
        return None
    m = re.fullmatch(r"now(?:([+-])(\d+)([smhdwMy]))?(?:/[smhdwMy])?", v)
    if m:
        t = NOW
        if m.group(1):
            n = int(m.group(2)) * (1 if m.group(1) == "+" else -1)
            unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}.get(m.group(3))
            t = t + timedelta(**{unit: n}) if unit else t + timedelta(days=30 * n)
        return t
    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    if round_up and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        t += timedelta(days=1, milliseconds=-1)
    return t


def _term_eq(stored: Any, literal: Any) -> bool:
    """Elasticsearch coerces a numeric string against a numeric field."""
    if isinstance(stored, bool) or isinstance(literal, bool):
        return stored == literal
    if isinstance(stored, (int, float)) and isinstance(literal, str):
        try:
            return stored == type(stored)(literal)
        except ValueError:
            return False
    return stored == literal


def _cmp_value(field_name: str, v: Any):
    if field_name == "@timestamp":
        return _parse_time(v)
    return v


def backing_index(pattern: str) -> str:
    """The backing index a hit from ``pattern`` names, as Elasticsearch
    names a data stream's write index."""
    return f".ds-{pattern.replace('*', 'default')}-2026.08.20-000001"


class StubEngine:
    """Evaluates compiled bodies against the fixture, Elasticsearch-shaped replies."""

    def __init__(self, fixture: Fixture, indices: Iterable[str] = (), *,
                 missing: dict[str, int] | None = None, terms_error: int = 0) -> None:
        self.fixture = fixture
        self.indices = set(indices) or {d.index for d in fixture.docs}
        #: field -> n: every nth document lacks the field, as real documents
        #: do (every fixture document carries every field otherwise)
        self.missing = dict(missing or {})
        #: what a terms aggregation looks like over many shards: each shard
        #: returns only its top terms, so the top bucket is undercounted by
        #: this much, the difference lands in sum_other_doc_count (the total
        #: stays exact, as it does in Elasticsearch), and
        #: doc_count_error_upper_bound says so
        self.terms_error = terms_error
        self.requests: list[dict] = []
        self.lock = threading.Lock()

    # -- matching ----------------------------------------------------------

    def _match(self, flat: dict, clause: dict) -> bool:
        if len(clause) != 1:
            raise ValueError("a clause has one key")
        (kind, spec), = clause.items()
        if kind == "match_all":
            return True
        if kind == "bool":
            return all(self._match(flat, c) for c in spec.get("filter", []))
        if kind == "term":
            (f, v), = spec.items()
            return f in flat and _term_eq(flat[f], v)
        if kind == "terms":
            (f, vs), = spec.items()
            return f in flat and any(_term_eq(flat[f], v) for v in vs)
        if kind == "exists":
            return spec["field"] in flat and flat[spec["field"]] is not None
        if kind == "range":
            (f, bounds), = spec.items()
            if f not in flat:
                return False
            x = _cmp_value(f, flat[f])
            for op, b in bounds.items():
                b = _parse_time(b, round_up=op in ("gt", "lte")) if f == "@timestamp" else b
                if x is None or b is None:
                    return False
                if op == "gte" and not x >= b or op == "gt" and not x > b \
                        or op == "lte" and not x <= b or op == "lt" and not x < b:
                    return False
            return True
        if kind == "match_phrase":
            (f, phrase), = spec.items()
            text = flat.get(f)
            if not isinstance(text, str):
                return False
            want = _TOKEN.findall(phrase.lower())
            have = _TOKEN.findall(text.lower())
            n = len(want)
            return n > 0 and any(have[i:i + n] == want for i in range(len(have) - n + 1))
        raise ValueError(f"unsupported clause {kind}")

    def _select(self, index: str) -> list[Doc]:
        return [d for d in self.fixture.docs if d.index == index]

    @staticmethod
    def _project(flat: dict, includes: list[str] | None) -> dict:
        import fnmatch
        if includes is None:
            return _unflatten(flat)
        keep = {p: v for p, v in flat.items() if any(fnmatch.fnmatchcase(p, i) for i in includes)}
        return _unflatten(keep)

    def _hit(self, index: str, i: int, flat: dict, includes: list[str] | None) -> dict:
        # Real hits name the data stream's backing index, never the pattern
        # or the stream: logs-app-* -> .ds-logs-app-default-2026.08.20-000001
        return {"_index": backing_index(index), "_id": f"{index[:4]}{i:08d}",
                "_score": None, "_source": self._project(flat, includes)}

    def _sorted(self, rows: list[tuple[int, dict]], sort: list[dict]) -> list[tuple[int, dict]]:
        for s in reversed(sort or []):
            (f, spec), = s.items()
            rows.sort(key=lambda r: (r[1].get(f) is None, _cmp_value(f, r[1].get(f)) or 0),
                      reverse=(spec.get("order") == "desc"))
        return rows

    # -- aggregations ------------------------------------------------------

    def _aggs(self, rows: list[tuple[int, dict]], aggs: dict, index: str) -> dict:
        out: dict[str, Any] = {}
        for name, spec in aggs.items():
            sub = spec.get("aggs", {})
            (atype, a), = ((k, v) for k, v in spec.items() if k != "aggs")
            if atype == "terms":
                counts: dict[Any, list] = {}
                for r in rows:
                    v = r[1].get(a["field"])
                    if v is not None:
                        counts.setdefault(v, []).append(r)
                ordered = sorted(counts.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))
                shown = ordered[: a.get("size", 10)]
                bucket_rows = [{"key": k, "doc_count": len(v), **self._aggs(v, sub, index)}
                               for k, v in shown]
                lost = min(self.terms_error, bucket_rows[0]["doc_count"] - 1) if bucket_rows else 0
                if lost > 0:
                    bucket_rows[0]["doc_count"] -= lost
                out[name] = {
                    "doc_count_error_upper_bound": self.terms_error,
                    "sum_other_doc_count": sum(len(v) for _, v in ordered[a.get("size", 10):])
                    + max(lost, 0),
                    "buckets": bucket_rows,
                }
            elif atype == "date_histogram":
                iv = a.get("fixed_interval") or a.get("calendar_interval") or "1h"
                m = re.fullmatch(r"(\d+)(ms|s|m|h|d)", iv)
                step = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] * int(m.group(1)) \
                    if m else {"minute": 60, "hour": 3600, "day": 86400}.get(iv, 86400 * 7)
                buckets: dict[int, list] = {}
                for r in rows:
                    t = _parse_time(r[1].get(a["field"]))
                    if t is None:
                        continue
                    key = int(t.timestamp() // step * step) * 1000
                    buckets.setdefault(key, []).append(r)
                out[name] = {"buckets": [
                    {"key": k, "key_as_string": datetime.fromtimestamp(k / 1000, tz=timezone.utc)
                     .strftime("%Y-%m-%dT%H:%M:%S.000Z"), "doc_count": len(v),
                     **self._aggs(v, sub, index)}
                    for k, v in sorted(buckets.items())]}
            elif atype == "filters":
                out[name] = {"buckets": {
                    fname: {"doc_count": len(sel), **self._aggs(sel, sub, index)}
                    for fname, clause in a["filters"].items()
                    for sel in [[r for r in rows if self._match(r[1], clause)]]}}
            elif atype == "top_hits":
                sel = self._sorted(list(rows), a.get("sort"))[: a.get("size", 1)]
                inc = a.get("_source", {}).get("includes")
                out[name] = {"hits": {"total": {"value": len(rows), "relation": "eq"},
                                      "max_score": None,
                                      "hits": [self._hit(index, i, flat, inc) for i, flat in sel]}}
            elif atype == "cardinality":
                out[name] = {"value": len({r[1].get(a["field"]) for r in rows
                                           if r[1].get(a["field"]) is not None})}
            elif atype == "percentiles":
                vals = sorted(v for v in (r[1].get(a["field"]) for r in rows)
                              if isinstance(v, (int, float)))
                out[name] = {"values": {f"{p:.1f}": (vals[min(len(vals) - 1, int(p / 100 * len(vals)))]
                                                   if vals else None) for p in a.get("percents", [50, 95, 99])}}
            else:  # min max avg sum value_count
                vals = [v for v in (r[1].get(a["field"]) for r in rows) if isinstance(v, (int, float))]
                if a["field"] == "@timestamp":
                    vals = [_parse_time(r[1].get("@timestamp")).timestamp() * 1000 for r in rows
                            if r[1].get("@timestamp")]
                fn = {"min": min, "max": max, "sum": sum, "value_count": len,
                      "avg": lambda xs: sum(xs) / len(xs)}[atype]
                val = fn(vals) if vals else None
                node: dict[str, Any] = {"value": val}
                if a["field"] == "@timestamp" and val is not None and atype in {"min", "max"}:
                    node["value_as_string"] = datetime.fromtimestamp(val / 1000, tz=timezone.utc) \
                        .strftime("%Y-%m-%dT%H:%M:%S.000Z")
                out[name] = node
        return out

    # -- entry point -------------------------------------------------------

    def search(self, index: str, body: dict) -> dict:
        """A raw Elasticsearch response for a compiled body."""
        with self.lock:
            self.requests.append({"index": index, "body": body})
        if index not in self.indices:
            raise KeyError(index)
        rows = [(i, flatten(d.source)) for i, d in enumerate(self._select(index))]
        for f, nth in self.missing.items():
            for i, flat in rows:
                if i % nth == 0:
                    flat.pop(f, None)
        rows = [r for r in rows if self._match(r[1], body.get("query", {"match_all": {}}))]
        total = len(rows)
        aggs = self._aggs(rows, body.get("aggs", {}), index) if body.get("aggs") else None
        rows = self._sorted(rows, body.get("sort"))
        frm, size = body.get("from", 0), body.get("size", 10)
        page = rows[frm: frm + size]
        includes = body.get("_source", {}).get("includes") if isinstance(body.get("_source"), dict) else None
        resp: dict[str, Any] = {
            "took": 7, "timed_out": False,
            "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None,
                     "hits": [self._hit(index, i, flat, includes) for i, flat in page]},
        }
        if aggs is not None:
            resp["aggregations"] = aggs
        return resp


# ---------------------------------------------------------------------------
# The Kibana protocol, stubbed
# ---------------------------------------------------------------------------


def kibana_error(status: int, message: str) -> dict:
    """The body Kibana returns for an error. Deliberately echoes the message,
    because the real one does, and the scrubber must never forward it."""
    return {"statusCode": status,
            "error": {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                      404: "Not Found", 500: "Internal Server Error"}.get(status, "Error"),
            "message": message}


class StubKibana:
    """``POST /internal/search/ese`` with an async id, then poll.

    The first call answers ``isRunning: true`` with an id and an empty
    partial; a poll on ``/internal/search/ese/{id}`` answers the finished
    response. ``kbn-xsrf`` and ``x-elastic-internal-origin: Kibana`` are
    required, as they are on the real endpoint. Loopback only.
    """

    def __init__(self, engine: StubEngine, *, cookie: str | None = None,
                 signed_in: bool = True, slow: bool = False,
                 sso_headless: bool = False, sso: bool = True) -> None:
        self.engine = engine
        #: Sessions are cookies, as Kibana's are: ``sid=<value>`` with no
        #: expiry, so a browser holds it in memory and loses it on exit.
        #: Every request without a live one gets a 302 to /login and a 200
        #: HTML login page, never a 401. ``cookie`` is a session issued up
        #: front (for the plain-HTTP transport); ``signed_in`` says whether
        #: it starts live. A browser gets its own from the SSO flow below.
        self.cookie = cookie
        self.sessions: set[str] = {cookie} if cookie and signed_in else set()
        #: The IdP: GET /login completes for a top-level navigation in a
        #: headed browser and issues a session. Never for a fetch (Chrome
        #: sends Sec-Fetch-Mode: cors; the IdP's auto-post needs a page),
        #: and never for a headless browser (HeadlessChrome in the user
        #: agent), as the real one never did; True lets a headless test
        #: browser sign in.
        self.sso_headless = sso_headless
        #: False: the IdP never completes for anyone, as when a session has
        #: expired and nobody is at the keyboard to sign back in. What
        #: ``es-smoke --stub --expired`` needs, in Chrome as over plain HTTP.
        self.sso = sso
        #: True: the search never finishes (isRunning stays true), to drive
        #: the poll timeout.
        self.slow = slow
        self.pending: dict[str, dict] = {}
        self.deleted: list[str] = []
        self.calls: list[tuple[str, str, dict]] = []
        self.logins = 0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _reply(self, status: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> dict:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b"{}"
                try:
                    return json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    return {}

            def _html(self, status: int, html: str, extra: dict | None = None) -> None:
                data = html.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _has_session(self) -> bool:
                jar = {c.strip() for c in (self.headers.get("Cookie") or "").split(";")}
                return bool(jar & stub.sessions)

            def _sso(self) -> None:
                """The login page and the IdP behind it, in one step."""
                nxt = re.search(r"[?&]next=([^&]+)", self.path)
                target = urllib.parse.unquote(nxt.group(1)) if nxt else "/app/home"
                if not target.startswith("/") or target.startswith("//"):
                    target = "/app/home"
                if self._has_session():
                    return self._html(302, "", {"Location": target})
                headless = "HeadlessChrome" in (self.headers.get("User-Agent") or "")
                navigation = self.headers.get("Sec-Fetch-Mode") == "navigate"
                if not stub.sso or not navigation or (headless and not stub.sso_headless):
                    return self._html(200, LOGIN_PAGE)
                sid = f"sid={uuid.uuid4().hex}"
                stub.sessions.add(sid)
                stub.logins += 1
                self._html(302, "", {"Location": target,
                                     "Set-Cookie": f"{sid}; Path=/; HttpOnly; SameSite=Lax"})

            def _session_ok(self) -> bool:
                """No live session: redirect to the login page, which is a 200."""
                if self.path.startswith("/login"):
                    self._sso()
                    return False
                if self._has_session():
                    return True
                self._html(302, "", {"Location": "/login?next=" + urllib.parse.quote(self.path)})
                return False

            def _authorised(self) -> bool:
                if not self._session_ok():
                    return False
                if not self.headers.get("kbn-xsrf"):
                    self._reply(400, kibana_error(400, "Request must contain a kbn-xsrf header."))
                    return False
                if self.headers.get("x-elastic-internal-origin") != "Kibana":
                    self._reply(400, kibana_error(400, "Request must contain x-elastic-internal-origin."))
                    return False
                return True

            def do_POST(self):
                body = self._body()
                stub.calls.append(("POST", self.path, body))
                if not self._authorised():
                    return
                if self.path == "/internal/security/me":
                    return self._reply(200, {"username": "synthetic.user", "roles": ["viewer"]})
                m = re.fullmatch(r"/internal/search/ese(?:/([\w-]+))?", self.path)
                if not m:
                    return self._reply(404, kibana_error(404, "Not Found"))
                if m.group(1):
                    return self._poll(m.group(1))
                params = body.get("params") if isinstance(body, dict) else None
                if not isinstance(params, dict) or "index" not in params:
                    return self._reply(400, kibana_error(400, "[request body.params.index]: expected value"))
                try:
                    result = stub.engine.search(params["index"], params.get("body") or {})
                except KeyError:
                    return self._reply(404, kibana_error(
                        404, f"[index_not_found_exception] no such index [{params['index']}]"))
                except ValueError as e:
                    return self._reply(400, kibana_error(400, f"[parsing_exception] {e}"))
                sid = uuid.uuid4().hex
                stub.pending[sid] = result
                self._reply(200, {"id": sid, "isPartial": True, "isRunning": True,
                                  "rawResponse": {"took": 0, "timed_out": False,
                                                  "hits": {"total": {"value": 0, "relation": "gte"},
                                                           "hits": []}}})

            def do_GET(self):
                stub.calls.append(("GET", self.path, {}))
                if not self._session_ok():
                    return
                if self.path.startswith("/app/") or self.path == "/":
                    return self._html(200, APP_PAGE)   # the tab the bridge fetches from
                if self.path == "/internal/security/me":
                    if not self._authorised():
                        return
                    return self._reply(200, {"username": "synthetic.user", "roles": ["viewer"]})
                if not self._authorised():
                    return
                m = re.fullmatch(r"/internal/search/ese/([\w-]+)", self.path)
                if not m:
                    return self._reply(404, kibana_error(404, "Not Found"))
                self._poll(m.group(1))

            def do_DELETE(self):
                stub.calls.append(("DELETE", self.path, {}))
                if not self._authorised():
                    return
                m = re.fullmatch(r"/internal/search/ese/([\w-]+)", self.path)
                if m and m.group(1) in stub.pending:
                    stub.deleted.append(m.group(1))
                    del stub.pending[m.group(1)]
                    return self._reply(200, {})
                self._reply(404, kibana_error(404, "Not Found"))

            def _poll(self, sid: str) -> None:
                result = stub.pending.get(sid)
                if result is None:
                    return self._reply(404, kibana_error(404, f"search id [{sid}] not found"))
                if stub.slow:
                    return self._reply(200, {"id": sid, "isPartial": True, "isRunning": True,
                                             "rawResponse": {"hits": {"hits": []}}})
                self._reply(200, {"id": sid, "isPartial": False, "isRunning": False,
                                  "rawResponse": result})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self) -> "StubKibana":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def expire(self) -> None:
        """Kibana ends every session server side (idle timeout, logout)."""
        self.sessions.clear()

    def sign_in(self) -> None:
        """The up-front session is live again (plain-HTTP tests only; a
        browser signs in through /login)."""
        if self.cookie:
            self.sessions.add(self.cookie)


class SimBrowser:
    """Chrome's cookie rules, for tests that cannot run Chrome.

    A session cookie (no Expires, no Max-Age: Kibana's ``sid``) lives in the
    browser's memory and is gone when the browser closes; only persistent
    cookies reach ``profile``, which stands in for the profile on disk and
    outlives the browser. Headless mode says so in the user agent, as
    Chrome does, which is what the IdP keys on. Implements the transport
    interface the bridge uses, plus ``login``, ``start`` and ``closed``.
    """

    UA = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) {}/131.0 Safari/537.36"

    def __init__(self, profile: list[Cookie], *, headless: bool = False,
                 parks: bool = False) -> None:
        self.profile = profile
        self.headless = headless
        #: True: like BrowserTransport._tab, the first request to a cluster
        #: first navigates a tab to Kibana, which goes through /login and the
        #: IdP when there is no session
        self.parks = parks
        self._parked: set[str] = set()
        self.closed = False
        self._jar: CookieJar | None = None
        self._opener = None

    def start(self) -> None:
        if self._jar is None:
            self._jar = CookieJar()
            for c in self.profile:
                self._jar.set_cookie(c)
            self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._jar))

    @property
    def cookies(self) -> list[Cookie]:
        return list(self._jar) if self._jar is not None else []

    def request(self, cluster: elastic.Cluster, method: str, path: str,
                body: dict | None = None, *, navigate: bool = False):
        """An in-page fetch, or with ``navigate`` a top-level page load."""
        from . import esbridge

        self.start()
        if self.parks and not navigate and cluster.name not in self._parked:
            self._parked.add(cluster.name)
            self.request(cluster, "GET", esbridge.APP_PATH, navigate=True)
        url = cluster.kibana + path
        headers = dict(esbridge.HEADERS)
        headers["User-Agent"] = self.UA.format("HeadlessChrome" if self.headless else "Chrome")
        headers["Sec-Fetch-Mode"] = "navigate" if navigate else "cors"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=10) as r:
                return esbridge.Reply(r.status, r.geturl(), r.headers.get("Content-Type", ""),
                                      r.read().decode("utf-8", "replace"), r.geturl() != url)
        except urllib.error.HTTPError as e:
            return esbridge.Reply(e.code, e.geturl() or url, e.headers.get("Content-Type", ""),
                                  e.read().decode("utf-8", "replace"), (e.geturl() or url) != url)
        except (urllib.error.URLError, OSError) as e:
            raise elastic.Refused("unreachable", "kibana unreachable") from e

    def login(self, cluster: elastic.Cluster, *, timeout: float = 5.0) -> bool:
        """Navigate to Kibana and wait to land on it signed in."""
        from . import esbridge

        deadline = time.monotonic() + timeout
        while True:
            r = self.request(cluster, "GET", esbridge.APP_PATH, navigate=True)
            if esbridge._url_host(r.url) == cluster.host and not esbridge._is_login_url(r.url):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def close(self) -> None:
        """The browser exits: persistent cookies are written to the
        profile, session cookies die."""
        if self._jar is not None:
            self.profile[:] = [c for c in self._jar if not c.discard]
        self._jar = None
        self._opener = None


#: What an expired SSO session looks like from the client: a 200 with HTML.
LOGIN_PAGE = """<!DOCTYPE html><html lang="en"><head><title>Elastic</title></head>
<body><div id="login-form"><h1>Welcome to Elastic</h1>
<p>Log in with your corporate account</p><button>Log in with SSO</button></div></body></html>"""
#: The signed-in app shell; the bridge's tab sits here and fetches from it.
APP_PAGE = """<!DOCTYPE html><html lang="en"><head><title>Home - Elastic</title></head>
<body><div id="kibana-body"><nav>Discover</nav><main>Synthetic home</main></div></body></html>"""


# ---------------------------------------------------------------------------
# The eval
# ---------------------------------------------------------------------------


def _leaks(output: Any, truth: dict[str, str]) -> list[str]:
    """Planted values that survive in a scrubbed page, by type (never the value)."""
    return _text_leaks(json.dumps(output), truth)


def _text_leaks(text: str, truth: dict[str, str]) -> list[str]:
    """The same check over raw text: what an MCP client received, a log file."""
    blob = text.lower()
    found = []
    for v, t in truth.items():
        lv = v.lower()
        if len(lv) < 3:
            continue
        for m in re.finditer(re.escape(lv), blob):
            a, b = m.start(), m.end()
            if (a > 0 and blob[a - 1].isalnum()) or (b < len(blob) and blob[b].isalnum()):
                continue
            found.append(t)
            break
    return found


def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(math.ceil(p / 100 * len(xs))) - 1)]


_PLAIN_PHRASES = ["completed with", "Throttled by SharePoint", "access denied", "no license",
                  "Checksum mismatch", "Rate limit", "picked up job", "Health check", "skipped",
                  "returned HTTP"]
_CLEAN_PHRASES = ["Scheduler tick", "Connection pool stats", "GC pause", "Retry policy exhausted",
                  "Token cache refreshed", "Queue depth", "Worker heartbeat", "Upgraded engine",
                  "Graph endpoint"]


class Session:
    """Compile, run against the engine, scrub: one tool call as the bridge will do it."""

    def __init__(self, config: elastic.ElasticConfig, engine: StubEngine, *, tier2: str) -> None:
        self.cfg = config
        self.engine = engine
        self.scrubber = elastic.EsScrubber(config, tier2=tier2)
        self.log: list[dict] = []

    def call(self, query: dict) -> tuple[dict | None, elastic.Refused | None, float, esquery.Compiled | None]:
        t0 = time.perf_counter()
        compiled = None
        try:
            compiled = esquery.compile_query(query, self.cfg, self.scrubber)
            raw = self.engine.search(compiled.body["params"]["index"], compiled.body["params"]["body"])
            envelope = {"id": "x", "isPartial": False, "isRunning": False, "rawResponse": raw}
            out = self.scrubber.scrub_response(envelope, compiled.plan).output
            refused = None
        except elastic.Refused as e:
            out, refused = None, e
        dt = time.perf_counter() - t0
        self.log.append({"refused": refused.code if refused else None,
                         "text_queries": compiled.text_queries if compiled else [],
                         "labels_used": compiled.labels_used if compiled else [], "seconds": dt})
        return out, refused, dt, compiled


class _McpClient:
    """Speaks to the bridge's MCP endpoint over real HTTP and keeps every
    byte it received, so the leak check sees exactly what Claude Code would."""

    def __init__(self, url: str, token: str | None) -> None:
        m = re.match(r"http://127\.0\.0\.1:(\d+)(/.*)", url)
        self.port, self.path, self.token = int(m.group(1)), m.group(2), token
        self.received: list[str] = []
        self._id = 0

    def raw(self, method: str = "POST", body: bytes | None = b"{}", *, path: str | None = None,
            headers: dict | None = None) -> tuple[int, dict, str]:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        try:
            conn.request(method, path or self.path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read().decode("utf-8", "replace")
            status, hdrs = r.status, {k.lower(): v for k, v in r.getheaders()}
        finally:
            conn.close()
        self.received.append(data)
        return status, hdrs, data

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        status, _, data = self.raw(body=json.dumps(msg).encode())
        return json.loads(data) if status == 200 else {"http_status": status}

    def tool(self, name: str, args: dict) -> tuple[Any, str | None]:
        """(payload, None) for a page, (None, refusal code) for a tool error."""
        res = self.rpc("tools/call", {"name": name, "arguments": args}).get("result") or {}
        text = ((res.get("content") or [{}])[0]).get("text", "")
        if res.get("isError"):
            m = re.match(r"refused \(([a-z_]+)\)", text)
            return None, m.group(1) if m else "malformed"
        try:
            return json.loads(text), None
        except json.JSONDecodeError:
            return None, "malformed"


def _oracle_tool(q: Any) -> tuple[str, Any, bool]:
    """The tool an oracle case goes through, its arguments, and whether the
    case reaches the grammar (False: its keys are no tool's, so the tool
    layer refuses it as bad_request before esquery sees it)."""
    from . import esmcp

    if isinstance(q, dict) and "aggs" in q and q.get("size", 0) == 0:
        return "es_aggregate", {k: v for k, v in q.items() if k != "size"}, True
    keys = set(q) if isinstance(q, dict) else set()
    for tool in ("es_count", "es_search"):
        if keys <= esmcp._TOOL_KEYS[tool]:
            return tool, q, True
    return "es_search", q, False


def run_mcp_eval(config: elastic.ElasticConfig, fx: Fixture, *, seed: int = 20261103,
                 tier2: str = "classifier") -> dict:
    """The same estate through the MCP server, as a Claude Code session sees it.

    A stub Kibana serves the fixture; a broker runs on a thread with the
    plain-HTTP transport; one case is opened, seeded with the tenant the
    investigation is about; every request below is real HTTP to the MCP
    endpoint. Measured: leaks in anything received (pages, refusals, errors),
    refusals by code, clean-traffic refusals, label round trips, the oracle
    cases through the tools, transport requests that must be rejected (and
    must not reach Kibana), the decision log, and what a launch hands Claude
    Code (environment, argv, working directory, prompt gate).
    """
    import dataclasses
    import shutil
    import tempfile
    import threading

    from . import esbridge, esmcp

    truth = fx.truth
    cookie = "sid=es-eval"
    kb = StubKibana(StubEngine(fx, config.indices), cookie=cookie).start()
    # a socket path must fit in 104 bytes; the default temp root on macOS does not
    base = Path(tempfile.mkdtemp(prefix="hev-", dir="/tmp" if os.path.isdir("/tmp") else None))
    cfg = dataclasses.replace(config, clusters=(elastic.Cluster("stub", kb.url),),
                              profile_dir=str(base / "profile"))
    rng = random.Random(seed + 2)
    broker = esbridge.Broker(cfg, lambda: esbridge.UrllibTransport(cookie), poll_interval=0.01,
                             sessions_dir=base / "cases")
    sock = esbridge.broker_socket(esbridge.prepare_profile_dir(cfg.profile_dir))
    thread = threading.Thread(target=broker.serve, args=(sock,), daemon=True)
    thread.start()
    for _ in range(500):
        if esbridge.broker_running(sock):
            break
        time.sleep(0.02)
    control = esbridge.BrokerClient(sock, timeout=120)
    tenant = fx.tenants[0].name
    calls: list[dict] = []
    timings: list[float] = []
    try:
        # what the human seeds: the tenant the case is about, and the two
        # labels the oracle cases are written against (esquery: <Org-01>,
        # ctr-amer-s01, <Tenant-01>)
        amer = next(sv.name for sv in fx.servers if "-amer-" in sv.name)
        opened = control.call("open_case", case="es-eval", tier2=tier2, terms=[
            tenant, f"SERVER_NAME={amer}", f"TENANT_ID={fx.tenants[0].tenant_id}"])
        case_label = opened["seeded"][0][0]
        seeded_ok = [lab for lab, _ in opened["seeded"]] == ["<Org-01>", "ctr-amer-s01",
                                                             "<Tenant-01>"]
        c = _McpClient(opened["url"], opened["token"])

        def tool(name: str, args: dict, *, clean: bool = False) -> Any:
            t0 = time.perf_counter()
            payload, code = c.tool(name, args)
            timings.append(time.perf_counter() - t0)
            calls.append({"tool": name, "refused": code, "clean": clean})
            return payload

        # -- the session: handshake, then an investigation -----------------
        init = c.rpc("initialize", {"protocolVersion": esmcp.PROTOCOL_VERSIONS[0],
                                    "capabilities": {}, "clientInfo": {"name": "es-eval"}})
        listed = c.rpc("tools/list").get("result", {}).get("tools", [])
        protocol_ok = (init.get("result", {}).get("serverInfo", {}).get("name") == esmcp.SERVER_NAME
                       and [t.get("name") for t in listed] == list(esmcp.TOOLS))
        schema = tool("es_schema", {})
        protocol_ok = (protocol_ok and seeded_ok and bool(schema)
                       and case_label in schema["case"]["labels"])

        tr = {"gte": "now-6h", "lte": "now"}
        by_case = [{"field": "labels.tenant_name", "op": "eq", "value": case_label}]
        round_trip = {"tried": 0, "passed": 0}

        def check(label_count: Any, want: int) -> None:
            round_trip["tried"] += 1
            round_trip["passed"] += bool(label_count) and \
                label_count["hits_total"]["value"] == want

        # the seeded tenant: label out, real value to Kibana, counted against the fixture
        want = sum(1 for d in fx.docs if d.index == "logs-app-*"
                   and flatten(d.source).get("labels.tenant_name") == tenant)
        check(tool("es_count", {"index": "logs-app-*", "filters": by_case}), want)
        tool("es_search", {"index": "logs-app-*", "time_range": tr, "filters": by_case, "size": 20})
        for index in ("logs-app-*", "logs-worker-*"):
            aggs = tool("es_aggregate", {"index": index, "time_range": tr, "aggs": {
                "srv": {"type": "terms", "field": "agent.name", "size": 10,
                        "aggs": {"last": {"type": "top_hits", "size": 1}}}}})
            # a server label learnt from the page, used as the next filter
            for b in ((aggs or {}).get("aggregations", {}).get("srv", {}).get("buckets") or [])[:4]:
                check(tool("es_count", {"index": index, "time_range": tr, "filters": [
                    {"field": "agent.name", "op": "eq", "value": b["key"]}]}), b["doc_count"])
        tool("es_aggregate", {"index": "logs-app-*", "time_range": tr, "aggs": {
            "over_time": {"type": "date_histogram", "field": config.time_field, "interval": "1h"},
            "tenants": {"type": "cardinality", "field": "labels.tenant_id"}}})
        users = tool("es_aggregate", {"index": "traces-apm-*", "time_range": tr, "aggs": {
            "users": {"type": "terms", "field": "labels.principal_name", "size": 5}}})
        for b in ((users or {}).get("aggregations", {}).get("users", {}).get("buckets") or [])[:3]:
            check(tool("es_count", {"index": "traces-apm-*", "time_range": tr, "filters": [
                {"field": "labels.principal_name", "op": "eq", "value": b["key"]}]}), b["doc_count"])
        for phrase in _PLAIN_PHRASES:
            tool("es_search", {"index": rng.choice(list(config.indices)), "time_range": tr,
                               "size": rng.choice([5, 20, 50]),
                               "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
        tool("es_search", {"index": "logs-app-*", "time_range": tr, "size": 20, "filters": [
            {"field": "message", "op": "phrase", "value": f"Throttled by SharePoint for {case_label}"}]})
        for phrase in _CLEAN_PHRASES:
            tool("es_search", {"index": rng.choice(list(config.indices)), "time_range": tr,
                               "size": 20,
                               "filters": [{"field": "message", "op": "phrase", "value": phrase}]},
                 clean=True)
        session_calls = len(calls)

        # -- the oracle cases, through the tools ---------------------------
        oracle = {"cases": len(esquery.ORACLE_CASES), "refused": 0, "by_grammar": 0,
                  "by_tool_layer": 0, "wrong_code": [], "shown": []}
        for case in esquery.ORACLE_CASES:
            name, args, reaches = _oracle_tool(case.query)
            payload, code = c.tool(name, args)
            want_code = case.code if reaches else "bad_request"
            if code is None:
                oracle["shown"].append(case.name)
            else:
                oracle["refused"] += 1
                oracle["by_grammar" if reaches else "by_tool_layer"] += 1
                if code != want_code:
                    oracle["wrong_code"].append({"case": case.name, "expected": want_code,
                                                 "got": code})

        # -- requests the transport must reject ----------------------------
        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        port = c.port
        rejections = [
            ("no token", _McpClient(opened["url"], None), {}, "POST", None, 401),
            ("wrong token", _McpClient(opened["url"], "x" * 43), {}, "POST", None, 401),
            ("token as Basic", c, {"Authorization": "Basic " + opened["token"]}, "POST", None, 401),
            ("foreign Host (DNS rebinding)", c, {"Host": f"evil.example:{port}"}, "POST", None, 403),
            ("Host without the port", c, {"Host": "127.0.0.1"}, "POST", None, 403),
            ("foreign Origin", c, {"Origin": "https://evil.example"}, "POST", None, 403),
            ("CORS preflight", c, {"Origin": "https://evil.example",
                                   "Access-Control-Request-Method": "POST"}, "OPTIONS", None, 405),
            ("GET (event stream)", c, {}, "GET", None, 405),
            ("DELETE", c, {}, "DELETE", None, 405),
            ("wrong path", c, {}, "POST", "/", 404),
            ("not JSON", c, {"Content-Type": "text/plain"}, "POST", None, 415),
            ("declared body over the cap", c, {"Content-Length": str(esmcp._MAX_BODY + 1)},
             "POST", None, 413),
        ]
        kibana_before = len(kb.calls)
        rejected = {"tried": 0, "rejected": 0, "unexpected": [], "cors_headers": 0}

        def reject(what: str, client: _McpClient, headers: dict, method: str,
                   path: str | None, want_status: int) -> None:
            status, hdrs, _ = client.raw(method, ping if method == "POST" else None, path=path,
                                         headers=headers)
            rejected["tried"] += 1
            rejected["rejected"] += status == want_status
            rejected["cors_headers"] += any(k.startswith("access-control") for k in hdrs)
            if status != want_status:
                rejected["unexpected"].append({"request": what, "expected": want_status,
                                               "got": status})
            c.received.extend(client.received if client is not c else [])

        for r in rejections:
            reject(*r)
        control.call("close_case", token=opened["token"])
        reject("token of a closed case", c, {}, "POST", None, 401)
        rejected["reached_kibana"] = len(kb.calls) - kibana_before
        log_path = base / "cases" / "es-eval" / "decisions.jsonl"
        log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    finally:
        broker.stopping = True
        thread.join(10)
        kb.stop()

    # -- what a launch hands Claude Code -------------------------------------
    hostile_env = {"HOME": "/home/analyst", "PATH": "/usr/bin", "ANTHROPIC_API_KEY": "synthetic",
                   "HIDER_ELASTIC": "/site/elastic.json", "HIDER_VAULT_KEY": "k",
                   "KIBANA_SID": cookie, "ELASTIC_PASSWORD": "synthetic", "PYTHONPATH": "/repo"}
    env = esmcp.claude_env(hostile_env)
    launch = esmcp.prepare_launch("http://127.0.0.1:1/mcp", "t" * 43, config=cfg,
                                  session_json=base / "cases" / "es-eval" / "session.json")
    try:
        argv = esmcp.claude_argv(launch.mcp_config, "why <Org-01>?", settings=launch.settings)
        launch_checks = {
            "env_allowlisted": set(env) == {"HOME", "PATH", "ANTHROPIC_API_KEY"},
            "no_builtin_tools": argv[argv.index("--tools") + 1] == "",
            "only_bridge_tools": argv[argv.index("--allowedTools") + 1].split(",")
            == list(esmcp.ALLOWED_TOOLS),
            "restricted_strict_mcp": "--restricted" in argv and "--strict-mcp-config" in argv,
            "token_not_on_argv": "t" * 43 not in " ".join(argv),
            "workspace_empty": not any(launch.workspace.iterdir()),
            "prompt_hook_installed": "--settings" in argv,
        }
    finally:
        launch.cleanup()
    mapping = esmcp._read_mapping(base / "cases" / "es-eval" / "session.json")
    shapes, seedable = esmcp.config_shapes(cfg), esmcp.seedable_types(cfg)
    server_label = next((k for k in mapping if not k.startswith("<")), "")
    prompt_cases = {  # synthetic prompt -> must it be refused (by the hook: nothing masks it)
        f"How busy is {case_label} on {server_label} over now-7d in logs-app-*?": False,
        f"How busy is {tenant}?": True,
        f"What failed for {fx.tenants[1].upns[0] if fx.tenants[1].upns else 'x@y.com'}?": True,
        f"Job {fx.tenants[1].objects[0] if fx.tenants[1].objects else ''} failed, why?": True,
    }
    prompt_gate = {"cases": len(prompt_cases), "held": 0}
    for text, refuse in prompt_cases.items():
        found = esmcp.prompt_findings(text, mapping, seedable=seedable, shapes=shapes)
        prompt_gate["held"] += bool(found) == refuse
    shutil.rmtree(base, ignore_errors=True)

    received = "\n".join(c.received)
    leaked = _text_leaks(received, truth)
    refusals: dict[str, int] = {}
    for row in calls:
        if row["refused"]:
            refusals[row["refused"]] = refusals.get(row["refused"], 0) + 1
    clean = [r for r in calls if r["clean"]]
    log_rows = [line for line in log_text.splitlines() if line.strip()]
    return {
        "protocol_ok": protocol_ok,
        "tool_calls": session_calls,
        "pages": sum(1 for r in calls if r["refused"] is None),
        "refusals": refusals,
        "clean_calls": len(clean),
        "clean_refused": sum(1 for r in clean if r["refused"]),
        "responses_received": len(c.received),
        "leaks": len(leaked),
        "leaked_types": sorted(set(leaked)),
        "label_round_trip": round_trip,
        "oracle": oracle,
        "rejected_requests": rejected,
        "log_rows": len(log_rows),
        "log_leaks": len(_text_leaks(log_text, truth)),
        "launch": launch_checks,
        "prompt_gate": prompt_gate,
        "latency_s": {"p50": round(_pct(timings, 50), 4), "p95": round(_pct(timings, 95), 4),
                      "max": round(max(timings), 4) if timings else 0.0},
    }


def mcp_gates(m: dict) -> dict[str, bool]:
    rj = m["rejected_requests"]
    return {
        "mcp_protocol": m["protocol_ok"],
        "mcp_no_leaks": m["leaks"] == 0,
        "mcp_oracle_all_refused": m["oracle"]["refused"] == m["oracle"]["cases"]
        and not m["oracle"]["wrong_code"],
        "mcp_round_trip_complete": m["label_round_trip"]["tried"] > 0
        and m["label_round_trip"]["passed"] == m["label_round_trip"]["tried"],
        "mcp_requests_rejected": rj["rejected"] == rj["tried"] and rj["reached_kibana"] == 0
        and rj["cors_headers"] == 0,
        "mcp_log_clean": m["log_rows"] >= m["tool_calls"] - 1 and m["log_leaks"] == 0,
        "mcp_launch_isolated": all(m["launch"].values()),
        "mcp_prompt_gate": m["prompt_gate"]["held"] == m["prompt_gate"]["cases"],
    }


def run_eval(config: elastic.ElasticConfig | None = None, *, seed: int = 20261103, docs: int = 600,
             queries: int = 120, tier2: str = "classifier", mcp: bool = True) -> dict:
    cfg = config or elastic.load(elastic.EXAMPLE)
    fx = generate(seed=seed, docs=docs)
    truth = fx.truth
    engine = StubEngine(fx, cfg.indices)
    rng = random.Random(seed + 1)
    sess = Session(cfg, engine, tier2=tier2)
    s = sess.scrubber

    # The human seeds the case with the tenant it is about, locally.
    case_label = s.seed(fx.tenants[0].name)

    labels: dict[str, list[str]] = {}  # type -> labels learnt so far

    def learn() -> None:
        for label, t in s.types.items():
            if label not in labels.get(t, []):
                labels.setdefault(t, []).append(label)

    learn()
    results: list[dict] = []
    shown_paths: set[str] = set()
    leaks_total = 0
    clean_pages = clean_refused = 0
    timings: list[float] = []

    def run(query: dict, *, clean: bool = False) -> None:
        nonlocal leaks_total, clean_pages, clean_refused
        out, refused, dt, compiled = sess.call(query)
        timings.append(dt)
        row = {"refused": refused.code if refused else None, "leaks": [], "clean": clean}
        if out is not None:
            row["leaks"] = _leaks(out, truth)
            leaks_total += bool(row["leaks"])
            shown_paths.update(_shown_paths(out))
            learn()
        if clean:
            clean_pages += 1
            clean_refused += refused is not None
        results.append(row)

    tr = {"gte": "now-6h", "lte": "now"}
    for i in range(queries):
        kind = i % 10
        if kind in (0, 1):
            phrase = rng.choice(_PLAIN_PHRASES)
            if kind == 1 and labels.get("ORG_NAME"):
                phrase = f"{phrase} for {rng.choice(labels['ORG_NAME'])}" if phrase in (
                    "Throttled by SharePoint", "Rate limit") else phrase
            run({"index": "logs-app-*" if kind == 0 else rng.choice(list(cfg.indices)),
                 "time_range": tr, "size": rng.choice([5, 10, 20, 50]),
                 "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
        elif kind == 2:
            run({"index": "logs-app-*", "time_range": tr, "size": 20,
                 "filters": [{"field": "labels.tenant_name", "op": "eq", "value": case_label}]})
        elif kind == 3:
            run({"index": rng.choice(["logs-app-*", "logs-worker-*"]), "time_range": tr, "size": 0,
                 "aggs": {"by_srv": {"type": "terms", "field": "agent.name", "size": 10,
                                     "aggs": {"last": {"type": "top_hits", "size": 1}}}}})
        elif kind == 4:
            run({"index": "logs-app-*", "time_range": tr, "size": 0,
                 "aggs": {"over_time": {"type": "date_histogram", "field": "@timestamp",
                                        "interval": "1h",
                                        "aggs": {"ds": {"type": "terms", "field": "data_stream.dataset"}}},
                          "tenants": {"type": "cardinality", "field": "labels.tenant_id"},
                          "first": {"type": "min", "field": "@timestamp"},
                          "last": {"type": "max", "field": "@timestamp"}}})
        elif kind == 5 and labels.get("SERVER_NAME"):
            run({"index": "logs-app-*", "time_range": tr, "size": 10,
                 "filters": [{"field": "agent.name", "op": "in",
                              "value": rng.sample(labels["SERVER_NAME"], min(2, len(labels["SERVER_NAME"])))}]})
        elif kind == 6:
            run({"index": "logs-app-*", "time_range": tr, "size": 0,
                 "aggs": {"levels": {"type": "filters", "filters": {
                     "errors": [{"field": "log.level", "op": "eq", "value": "error"}],
                     "warnings": [{"field": "log.level", "op": "eq", "value": "warn"}]},
                     "aggs": {"by_tenant": {"type": "terms", "field": "labels.tenant_name", "size": 10}}}}})
        elif kind == 7:
            run({"index": "traces-apm-*", "time_range": tr, "size": 5,
                 "aggs": {"users": {"type": "terms", "field": "labels.principal_name", "size": 10},
                          "slow": {"type": "percentiles", "field": "transaction.duration.us"}}})
        elif kind == 8 and labels.get("TENANT_ID"):
            run({"index": rng.choice(["traces-apm-*", "logs-worker-*"]), "time_range": tr, "size": 10,
                 "filters": [{"field": "labels.tenant_id", "op": "eq",
                              "value": rng.choice(labels["TENANT_ID"])}]})
        else:
            run({"index": rng.choice(list(cfg.indices)), "time_range": tr, "size": 20,
                 "filters": [{"field": "message", "op": "phrase", "value": rng.choice(_CLEAN_PHRASES)}]},
                clean=True)

    # Label round trip: a label learnt from a page, used as a filter.
    round_trip = {"tried": 0, "passed": 0, "failures": []}
    field_for_type = {}
    for r in cfg.fields:
        if r.kind == "identifier" and not r.is_glob and r.type not in field_for_type:
            field_for_type[r.type] = r
    candidates = [(lab, t) for t, labs in labels.items() for lab in labs
                  if t in field_for_type and t not in {"DOC_ID"}]
    rng.shuffle(candidates)
    for lab, t in candidates[:40]:
        rule = field_for_type[t]
        index = "traces-apm-*" if rule.pattern == "labels.principal_name" else "logs-app-*"
        real = s.mapping[lab]
        round_trip["tried"] += 1
        out, refused, dt, compiled = sess.call({"index": index, "size": 20,
                                                "filters": [{"field": rule.pattern, "op": "eq", "value": lab}]})
        timings.append(dt)
        ok = (compiled is not None and json.dumps(compiled.body).find(json.dumps(real)) >= 0
              and refused is None)
        if ok:
            flat_hits = [flatten(h.get("_source", {})) for h in out["hits"]["hits"]]
            ok = all(h.get(rule.pattern) == lab for h in flat_hits) and not _leaks(out, truth)
            raw_hits = [flatten(d.source) for d in fx.docs if d.index == index
                        and flatten(d.source).get(rule.pattern) in (real, _num(real))]
            ok = ok and out["hits"]["total"]["value"] == len(raw_hits)
        round_trip["passed"] += bool(ok)
        if not ok:
            round_trip["failures"].append({"type": t, "refused": refused.code if refused else None})

    # Oracle cases.
    oracle = {"cases": len(esquery.ORACLE_CASES), "refused": 0, "wrong_code": [], "compiled": []}
    for case in esquery.ORACLE_CASES:
        try:
            esquery.compile_query(case.query, cfg, s)
            oracle["compiled"].append(case.name)
        except elastic.Refused as e:
            if e.code == case.code:
                oracle["refused"] += 1
            else:
                oracle["wrong_code"].append({"case": case.name, "expected": case.code, "got": e.code})

    # Field coverage.
    paths: dict[str, int] = {}
    for d in fx.docs:
        for p in flatten(d.source):
            paths[p] = paths.get(p, 0) + 1
    coverage = {"keep": [], "identifier": [], "text": [], "unlisted": []}
    for p in sorted(paths):
        r = cfg.rule(p)
        coverage[r.kind if r else "unlisted"].append(p)

    lower_truth = {t.lower() for t in truth}
    refusals: dict[str, int] = {}
    for row in results:
        if row["refused"]:
            refusals[row["refused"]] = refusals.get(row["refused"], 0) + 1
    pages = sum(1 for r in results if r["refused"] is None)
    text_queries = sum(len(row["text_queries"]) for row in sess.log)
    report = {
        "schema": "hider.es-eval.v1",
        "config": cfg.source,
        "tier2": tier2,
        "fixture": {"docs": len(fx.docs), "tenants": len(fx.tenants), "servers": len(fx.servers),
                    "planted_values": len(truth), "clean_docs": sum(d.clean for d in fx.docs)},
        "queries": len(results),
        "pages_shown": pages,
        "response_leaks": leaks_total,
        "response_leak_rate": round(leaks_total / pages, 4) if pages else 0.0,
        "refusals": refusals,
        "clean_pages": clean_pages,
        "clean_refused": clean_refused,
        "clean_refusal_rate": round(clean_refused / clean_pages, 4) if clean_pages else 0.0,
        "degraded": s.degraded,
        "label_round_trip": round_trip,
        "oracle": oracle,
        "text_queries": text_queries,
        "labels_issued": len(s.mapping),
        # labels whose value was never planted: tier 2 names, document ids,
        # and the parts of planted values (a tenant's first word, a UPN's
        # domain). An over-redaction figure, reported rather than gated.
        "labels_not_planted": sum(1 for v in s.mapping.values()
                                  if v not in truth and v.lower() not in lower_truth),
        "dropped_field_paths": sorted(s.dropped),
        "field_coverage": {k: len(v) for k, v in coverage.items()},
        "unlisted_fields_seen": coverage["unlisted"],
        "latency_s": {"p50": round(_pct(timings, 50), 4), "p95": round(_pct(timings, 95), 4),
                      "max": round(max(timings), 4) if timings else 0.0},
    }
    gates = {
        "no_leaks": leaks_total == 0,
        "no_degraded": s.degraded == 0,
        "oracle_all_refused": oracle["refused"] == oracle["cases"],
        "round_trip_complete": round_trip["tried"] > 0 and round_trip["passed"] == round_trip["tried"],
        # planted in every fixture, projected out by the engine or dropped
        # here; either way never shown
        "unlisted_never_shown": not (set(fx.unlisted_fields) & shown_paths),
    }
    if mcp:
        # the same fixture through the MCP server, as Claude Code reaches it
        report["mcp"] = run_mcp_eval(cfg, fx, seed=seed, tier2=tier2)
        gates.update(mcp_gates(report["mcp"]))
    report["gates"] = gates
    report["passed"] = all(gates.values())
    return report


def _shown_paths(out: dict) -> set[str]:
    """Every _source path in a scrubbed page, hits and top_hits alike."""
    paths: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "_source" in node and isinstance(node["_source"], dict):
                paths.update(flatten(node["_source"]))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(out)
    return paths


def _num(v: str):
    try:
        return int(v)
    except ValueError:
        return v


def format_report(r: dict) -> str:
    lines = [
        f"fixture           {r['fixture']['docs']} docs, {r['fixture']['planted_values']} planted values, "
        f"{r['fixture']['clean_docs']} clean docs",
        f"queries           {r['queries']} ({r['pages_shown']} pages shown, "
        f"{sum(r['refusals'].values())} refused: {r['refusals'] or 'none'})",
        f"response leaks    {r['response_leaks']} (rate {r['response_leak_rate']})",
        f"clean traffic     {r['clean_refused']}/{r['clean_pages']} refused "
        f"(rate {r['clean_refusal_rate']})",
        f"degraded          {r['degraded']}",
        f"label round trip  {r['label_round_trip']['passed']}/{r['label_round_trip']['tried']}",
        f"oracle cases      {r['oracle']['refused']}/{r['oracle']['cases']} refused with the declared code"
        + (f"; wrong code: {r['oracle']['wrong_code']}" if r['oracle']['wrong_code'] else "")
        + (f"; COMPILED: {r['oracle']['compiled']}" if r['oracle']['compiled'] else ""),
        f"text queries      {r['text_queries']} (declared channel: guess confirmation by hit count)",
        f"labels issued     {r['labels_issued']} ({r['labels_not_planted']} for values never planted: "
        f"ids, name parts, tier 2 calls)",
        f"field coverage    {r['field_coverage']} ; unlisted seen: {r['unlisted_fields_seen']}",
        f"latency           p50 {r['latency_s']['p50']}s  p95 {r['latency_s']['p95']}s  "
        f"max {r['latency_s']['max']}s (tier2={r['tier2']})",
    ]
    m = r.get("mcp")
    if m:
        o, rj = m["oracle"], m["rejected_requests"]
        lines += [
            "-- through the MCP server (real HTTP to the bridge, stub Kibana) --",
            f"mcp tool calls    {m['tool_calls']} ({m['pages']} pages, refused: "
            f"{m['refusals'] or 'none'}); clean traffic {m['clean_refused']}/{m['clean_calls']} "
            f"refused; protocol {'ok' if m['protocol_ok'] else 'FAILED'}",
            f"mcp leaks         {m['leaks']} in {m['responses_received']} responses received"
            + (f" (types: {m['leaked_types']})" if m["leaked_types"] else ""),
            f"mcp round trip    {m['label_round_trip']['passed']}/{m['label_round_trip']['tried']}",
            f"mcp oracle        {o['refused']}/{o['cases']} refused ({o['by_grammar']} by the "
            f"grammar with the declared code, {o['by_tool_layer']} by the tool layer as "
            f"bad_request)" + (f"; wrong code: {o['wrong_code']}" if o["wrong_code"] else "")
            + (f"; SHOWN: {o['shown']}" if o["shown"] else ""),
            f"mcp rejected      {rj['rejected']}/{rj['tried']} transport requests rejected, "
            f"{rj['reached_kibana']} reached Kibana, {rj['cors_headers']} with CORS headers"
            + (f"; unexpected: {rj['unexpected']}" if rj["unexpected"] else ""),
            f"mcp decision log  {m['log_rows']} rows, {m['log_leaks']} with a planted value",
            f"mcp launch        {m['launch']}",
            f"mcp prompt gate   {m['prompt_gate']['held']}/{m['prompt_gate']['cases']} prompts "
            f"decided right",
            f"mcp latency       p50 {m['latency_s']['p50']}s  p95 {m['latency_s']['p95']}s  "
            f"max {m['latency_s']['max']}s",
        ]
    lines += [
        f"gates             {r['gates']}",
        f"PASSED" if r["passed"] else "FAILED",
    ]
    return "\n".join(lines)
