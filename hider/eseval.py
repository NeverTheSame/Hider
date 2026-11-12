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

import dataclasses
import json
import math
import os
import random
import re
import shutil
import tempfile
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
             clean_share: float = 0.25, bulk_jobs: int | None = None,
             estate: bool = False) -> Fixture:
    """Documents in the three index shapes, with ground truth.

    ``clean_share`` of the documents carry a message with no customer value
    (their identifier fields are still real; that is what the field map is
    for). The unlisted fields are planted with a customer value on purpose,
    so a failure of default-deny shows up as a leak.

    ``bulk_jobs`` is the estate's back catalogue of job names (see
    :func:`bulk_job_docs`); ``run_eval`` asks for :data:`BULK_JOBS` of them.
    It defaults to none, so a test that only needs the three index shapes
    does not carry twelve thousand documents it never reads.

    ``estate`` appends the realistic estate (see :func:`estate_docs`): ten
    thousand tenants and jobs in their measured shapes, their free-text
    mentions and the level and outcome spellings. Off by default for the
    same reason, and appended last, so every document above it is
    unchanged either way.
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
    out.extend(unmarked_job_docs(ts, servers))
    out.extend(unmarked_name_docs(ts, servers))
    out.extend(default_map_docs(ts, servers))
    out.extend(keep_leak_docs(ts, servers))
    out.extend(window_case_docs(ts, servers))
    out.extend(bulk_job_docs(bulk_jobs or 0))
    if estate:
        out.extend(estate_docs(ts, servers))
        out.extend(ordinary_word_docs(ts, servers))
        # last of all, and in their own index pattern: the oversized
        # identifier field (see over_cap_docs). No existing query, build or
        # count touches them.
        out.extend(over_cap_docs())
        # after those, in an index pattern of their own: a data stream
        # named after a job (see stream_name_docs)
        out.extend(stream_name_docs())
        # last of all, in their own pattern: a tenant first logged in the
        # gap after a saved cover (see gap_docs)
        out.extend(gap_docs())
    return Fixture(out, ts, [x for xs in servers.values() for x in xs])


#: What one composite page over one field costs on a real cluster, in
#: seconds: measured between 8 and 35. The stub charges these in turn so a
#: build over the fixture reports a realistic time without the eval
#: actually waiting (see ``StubEngine.page_seconds``).
PAGE_SECONDS: tuple[float, ...] = (18.0, 11.0, 27.0, 8.0, 35.0, 14.0, 22.0)
#: What the same page costs over a **wide** range: measured on a real
#: cluster at 31 to 297 seconds for one 1,000-value page over 30 days,
#: against the 8-35 above for the same page over a day or an hour. This is
#: the measurement that killed the single whole-range build - 12 fields of
#: ~10,000 names each is over a hundred pages, which at these numbers is
#: hours, not the twenty minutes the budget allowed - and it is the reason
#: the build now reads one-day slices. The stub charges by the width of
#: the range the request asks for, so the eval shows the difference
#: instead of asserting it.
WIDE_PAGE_SECONDS: tuple[float, ...] = (31.0, 88.0, 142.0, 297.0, 64.0, 210.0, 119.0)
#: A request whose range is wider than this is charged WIDE_PAGE_SECONDS.
WIDE_RANGE_S = 2 * 86400.0
#: What the distinct-count probe before a field is paged costs, in
#: simulated seconds. A ``cardinality`` aggregation has no paging, no sort
#: and no values to return, so it is a fraction of a composite page - but
#: this number is an **assumption**, not a measurement like PAGE_SECONDS: a
#: quarter of the cheapest measured page. The eval's claim about the probe
#: is the request *count*, which is exact; the seconds are here so the
#: report cannot imply the probe is free.
PROBE_SECONDS = 2.0

#: The estate's back catalogue of job names: how many distinct values one
#: vocabulary field holds over the retention period on a cluster that is not
#: small. Twelve thousand is past what one ``terms`` aggregation was asked
#: for (the cap was 10,000), so before the vocabulary was read in pages over
#: the case's own window, every case on this fixture was refused with
#: ``vocabulary`` and no page was ever shown. All names invented, and built
#: by position rather than drawn, so the generator's RNG stream is untouched.
BULK_JOBS = 12_000
_BULK_FIRST = ("Orchard", "Wolds", "Kestrel", "Fenmoor", "Calder", "Brindle", "Harlow",
               "Pentland", "Sableford", "Larkspur", "Tarnmouth", "Ridgeway")
_BULK_SECOND = ("Sweep", "Export", "Rollup", "Retention", "Archive Run", "Reindex",
                "Verify", "Compaction", "Restore Drill", "Inventory")


def bulk_job_name(i: int) -> str:
    return (f"{_BULK_FIRST[i % len(_BULK_FIRST)]} "
            f"{_BULK_SECOND[(i // len(_BULK_FIRST)) % len(_BULK_SECOND)]} {i:05d}")


def bulk_job_docs(count: int = BULK_JOBS) -> list[Doc]:
    """One application document per back-catalogue job name.

    Every one of them is older than any case window the eval uses, which is
    the point: a windowed read must not pay for them, and a read of the whole
    retention period must still either page through them or refuse. They are
    not ground truth - no query returns one and no page shows one - so they
    add volume to the cluster, not values to the leak check.
    """
    docs: list[Doc] = []
    for i in range(count):
        at = (NOW - timedelta(days=10) - timedelta(minutes=2 * i)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-app-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success", "action": "job-step"},
            "log": {"level": "info", "logger": "Engine.Jobs"},
            "message": "Scheduler tick: 1 jobs due, 0 running, 0 queued",
            "job": {"name": bulk_job_name(i), "status": "Success"},
            "service": {"name": "backup-engine", "version": "8.4.1"},
        }, {}))
    return docs


#: Tenant and resource names on a site map with **no** vocabulary section.
#: The default used to be JOB_NAME fields only, so at any site that had not
#: written the section - the common case - a tenant or resource named in
#: message text stayed readable, its own field being on another document.
#: The case window is one hour; the field records sit outside it, inside the
#: margin. (multi-word tenant, resource, the message, a phrase that finds
#: the message without naming either). All values invented.
DEFAULT_MAP_TENANT = "Thornbury Estates"
DEFAULT_MAP_RESOURCE = "vault07"
DEFAULT_MAP_MESSAGE = (f"Quota warning for {DEFAULT_MAP_TENANT}, resource "
                       f"{DEFAULT_MAP_RESOURCE} near capacity")
DEFAULT_MAP_PHRASE = "near capacity"
DEFAULT_MAP_RANGE = {"gte": "now-4h", "lte": "now-3h"}
#: One-word tenant names, which is what many real tenants are called. Each
#: gets the same treatment as the multi-word one; the skip rules
#: (:meth:`elastic.EsScrubber.vocabulary_skip`) drop some of them on purpose,
#: and those stay readable in message text. ``es-eval`` reports which, and
#: AGENTS.md records it as a declared miss - the point of the spread is that
#: the number is measured rather than assumed.
DEFAULT_MAP_ONE_WORD = ("Thornbury", "Brackenvault", "Meridian", "Larkspur",
                        "Archive", "Vault", "Ops", "Nimbus")


def default_map_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """Two documents per name: the message, on a worker document whose own
    tenant field holds someone else, and the record that carries the name in
    its own field, logged before the case's hour. Positions, not draws."""
    docs: list[Doc] = []
    prx, ctr = servers["prx"][4], servers["ctr"][4]
    other = tenants[5]

    def pair(i: int, tenant: str, resource: str, message: str) -> None:
        at = (NOW - timedelta(minutes=200 + i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            "log": {"level": "warn"},
            "message": message,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": other.name, "tenant_id": other.tenant_id},
        }, {tenant: "ORG_NAME", resource: "RESOURCE_NAME", prx.name: "SERVER_NAME",
            prx.ip: "IPV4", other.name: "ORG_NAME", other.tenant_id: "TENANT_ID"}))
        before = (NOW - timedelta(hours=5, minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-app-*", {
            "@timestamp": before,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success", "action": "inventory"},
            "log": {"level": "info", "logger": "Engine.Inventory"},
            "message": "Inventory refreshed",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip},
            "labels": {"tenant_name": tenant, "tenant_full_name": f"{tenant} Limited",
                       "tenant_id": other.tenant_id, "resource_name": resource},
        }, {tenant: "ORG_NAME", f"{tenant} Limited": "ORG_NAME", resource: "RESOURCE_NAME",
            ctr.name: "SERVER_NAME", ctr.ip: "IPV4", other.tenant_id: "TENANT_ID"}))

    pair(0, DEFAULT_MAP_TENANT, DEFAULT_MAP_RESOURCE, DEFAULT_MAP_MESSAGE)
    for i, name in enumerate(DEFAULT_MAP_ONE_WORD):
        pair(i + 1, name, f"vault{i + 10}",
             f"Quota warning for {name}, resource vault{i + 10} near capacity")
    return docs


def default_map_cases() -> list[tuple[str, str, str]]:
    """(tenant, resource, message) for every default-map name, the
    multi-word one first."""
    out = [(DEFAULT_MAP_TENANT, DEFAULT_MAP_RESOURCE, DEFAULT_MAP_MESSAGE)]
    out += [(n, f"vault{i + 10}",
             f"Quota warning for {n}, resource vault{i + 10} near capacity")
            for i, n in enumerate(DEFAULT_MAP_ONE_WORD)]
    return out


#: A sensitive value in a keep field: a real cluster's level field held a
#: SharePoint personal-site URL (a person's name in the path) among its
#: ordinary info/Warning/ERR spellings, once a day. A keep field passes
#: through unchanged by declaration, and the value reaches Claude two ways:
#: in a hit, and as a bucket key when the field's values are aggregated,
#: which the esmcp instructions tell Claude to do before filtering. All
#: values invented; the GUIDs are fixed, not drawn.
KEEP_LEAK_URL = "https://bellpointe-my.sharepoint.com/personal/lena_mareau_bellpointe_com"
KEEP_LEAK_SITE = "8c0e7d9a-4f3b-4a2e-9a1d-5b6c7e8f9a0b"
KEEP_LEAK_WEB = "2b9f3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
KEEP_LEAK_VALUE = f"site: {KEEP_LEAK_SITE}, web: {KEEP_LEAK_WEB}, url: {KEEP_LEAK_URL}"
#: finds the document without naming anything in it
KEEP_LEAK_PHRASE = "one site collection moved"
#: The ordinary spellings a level and outcome field really hold, which must
#: come back from the keep pass exactly as written - as hit values, as
#: bucket keys, and as filter values that still match.
KEEP_LEVEL_SPELLINGS = ("info", "Information", "INFO", "warn", "wrn", "err", "Critical")
KEEP_OUTCOME_SPELLINGS = ("success", "failure")


def keep_leak_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """One worker document whose ``log.level`` holds :data:`KEEP_LEAK_VALUE`,
    then one per level/outcome spelling pair, all inside the 6h spread.
    Positions, not draws: no RNG is consumed."""
    t, prx = tenants[2], servers["prx"][3]
    base = {
        "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
        "agent": {"name": prx.name},
        "host": {"name": prx.name, "ip": prx.ip},
        "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
    }
    common = {prx.name: "SERVER_NAME", prx.ip: "IPV4", t.name: "ORG_NAME",
              t.tenant_id: "TENANT_ID"}
    docs = [Doc("logs-worker-*", {
        **base,
        "@timestamp": (NOW - timedelta(minutes=33)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "event": {"outcome": "success"},
        "log": {"level": KEEP_LEAK_VALUE},
        "message": "Processing finished, one site collection moved",
    }, {**common, KEEP_LEAK_URL: "SITE_URL", "lena_mareau": "PERSON_NAME",
        KEEP_LEAK_SITE: "OBJECT_GUID", KEEP_LEAK_WEB: "OBJECT_GUID"})]
    for i, level in enumerate(KEEP_LEVEL_SPELLINGS):
        docs.append(Doc("logs-worker-*", {
            **base,
            "@timestamp": (NOW - timedelta(minutes=35 + i)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "event": {"outcome": KEEP_OUTCOME_SPELLINGS[i % len(KEEP_OUTCOME_SPELLINGS)]},
            "log": {"level": level},
            "message": "Worker heartbeat",
        }, dict(common), clean=True))
    return docs


#: The one-hour case, the shape the windowed read exists for: a support case
#: scoped to a single hour, a message in that hour naming a job with nothing
#: marking it as a name, and the job's own ``job.name`` record logged hours
#: earlier - outside the case window, inside the margin. On a cluster with
#: :data:`BULK_JOBS` names, this page is only shown if the vocabulary can be
#: read for an hour-wide window; a read of the whole retention period hits
#: the ceiling and refuses the case.
WINDOW_CASE_JOB = "Harbour Ridge Nightly"
WINDOW_CASE_MESSAGE = "Harbour Ridge Nightly finished with warnings on a proxy"
#: finds the message without naming the job
WINDOW_CASE_PHRASE = "finished with warnings on a proxy"
WINDOW_CASE_RANGE = {"gte": "now-2h", "lte": "now-1h"}


def window_case_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """The two documents of :data:`WINDOW_CASE_JOB`: the message inside the
    case's hour, the job's own record ten hours before it."""
    t, prx = tenants[1], servers["prx"][1]
    ctr = servers["ctr"][1]
    at = (NOW - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    before = (NOW - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return [
        Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            "log": {"level": "warn"},
            "message": WINDOW_CASE_MESSAGE,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
        }, {WINDOW_CASE_JOB: "JOB_NAME", prx.name: "SERVER_NAME", prx.ip: "IPV4",
            t.name: "ORG_NAME", t.tenant_id: "TENANT_ID"}),
        Doc("logs-app-*", {
            "@timestamp": before,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success", "action": "job-step"},
            "log": {"level": "info", "logger": "Engine.Jobs"},
            "message": "Scheduler tick: 1 jobs due, 0 running, 0 queued",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip},
            "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
            "job": {"name": WINDOW_CASE_JOB, "status": "Success"},
            "service": {"name": "backup-engine", "version": "8.4.1"},
        }, {WINDOW_CASE_JOB: "JOB_NAME", ctr.name: "SERVER_NAME", ctr.ip: "IPV4",
            t.name: "ORG_NAME", t.tenant_id: "TENANT_ID"}),
    ]


#: Job names in free text with no "job" in front of them, the shape
#: ``elastic._JOB_REF`` cannot see: the name comes first in the message, or
#: after some other word. (job name, message, a phrase that finds the
#: message without naming the job). Each message sits on a worker document
#: with no job field at all; the job's own ``job.name`` is on a separate
#: application document, so a fresh case's first page holds the message and
#: not the field. A fixed list outside the generator's RNG stream, appended
#: after it, so every generated document is unchanged; all names invented.
UNMARKED_JOBS: tuple[tuple[str, str, str], ...] = (
    ("Harbour Nightly", "Harbour Nightly finished with warnings", "finished with warnings"),
    ("Mailbox Sweep", "Mailbox Sweep started on a server, 61 sites enqueued",
     "started on a server"),
    ("Quillon Ledger Export", "Quillon Ledger Export completed after 3 retries",
     "completed after"),
    ("Saltmarsh Retention", "Retry 3 of Saltmarsh Retention scheduled after throttling",
     "scheduled after throttling"),
    ("Kittiwake", "Kittiwake finished, 0 items changed", "items changed"),
)


#: Customer names in free text with nothing that marks them as names, the
#: same shape as UNMARKED_JOBS for the other name fields: (field, the name,
#: the message, a phrase that finds the message without naming it). Each
#: message sits on a worker document whose own tenant field holds a
#: different tenant; the name is in its field only on a separate record
#: document. Appended after the RNG stream, like the job names.
UNMARKED_NAMES: tuple[tuple[str, str, str, str], ...] = (
    ("labels.resource_name", "LegalHold2031", "Resource LegalHold2031 on a server: 24% quota used",
     "24 quota used"),
    ("labels.resource_name", "Brackenvault", "Brackenvault crossed its soft limit",
     "crossed its soft limit"),
    ("labels.tenant_name", "Thornbury Estates", "Tenant Thornbury Estates exceeded its quota",
     "exceeded its quota"),
    ("labels.tenant_full_name", "Pellworth Analytics GmbH",
     "Quota report for Pellworth Analytics GmbH is ready", "quota report for"),
    ("labels.site_name", "Oak Creek Holdings", "Site Oak Creek Holdings failed to sync",
     "failed to sync"),
)


def unmarked_name_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """Two documents per :data:`UNMARKED_NAMES` entry: the message, on a
    worker document of another tenant, and a record that carries the name in
    its field. Positions, not draws: no RNG is consumed."""
    docs: list[Doc] = []
    for i, (field_path, name, message, _phrase) in enumerate(UNMARKED_NAMES):
        other = tenants[(i + 3) % len(tenants)]
        prx = servers["prx"][(i + 2) % len(servers["prx"])]
        at = (NOW - timedelta(minutes=19 + 2 * i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            "log": {"level": "warn"},
            "message": message,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": other.name, "tenant_id": other.tenant_id},
        }, {name: "NAME", prx.name: "SERVER_NAME", prx.ip: "IPV4", other.name: "ORG_NAME",
            other.tenant_id: "TENANT_ID"}))
        t = tenants[i % len(tenants)]
        ctr = servers["ctr"][(i + 3) % len(servers["ctr"])]
        labels = {"tenant_name": t.name, "tenant_full_name": t.full_name,
                  "tenant_id": t.tenant_id, "resource_name": t.resources[0]}
        labels[field_path.split(".", 1)[1]] = name
        before = (NOW - timedelta(hours=4, minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-app-*", {
            "@timestamp": before,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success", "action": "inventory"},
            "log": {"level": "info", "logger": "Engine.Inventory"},
            "message": "Inventory refreshed",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip},
            "labels": labels,
        }, {**{v: "NAME" for v in labels.values()}, labels["tenant_id"]: "TENANT_ID",
            ctr.name: "SERVER_NAME", ctr.ip: "IPV4"}))
    return docs


def unmarked_job_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """Two documents per :data:`UNMARKED_JOBS` entry: the message, on a worker
    document with no job field, and the job's own record on an application
    document. Every field a generated document of that index has, with the
    tenant and server taken by position, not drawn: no RNG is consumed."""
    docs: list[Doc] = []
    for i, (job, message, _phrase) in enumerate(UNMARKED_JOBS):
        t = tenants[i % len(tenants)]
        prx, ctr = servers["prx"][i % len(servers["prx"])], servers["ctr"][i % len(servers["ctr"])]
        at = (NOW - timedelta(minutes=7 + 2 * i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        person = f"Wren Ashdown {i + 1}"
        docs.append(Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            "log": {"level": "info"},
            "message": message,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
            "user": {"full_name": person},
        }, {job: "JOB_NAME", prx.name: "SERVER_NAME", prx.ip: "IPV4", t.name: "ORG_NAME",
            t.tenant_id: "TENANT_ID", person: "PERSON_NAME"}))
        before = (NOW - timedelta(hours=3, minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"hider-es-eval/{job}/id"))
        session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"hider-es-eval/{job}/session"))
        object_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"hider-es-eval/{job}/object"))
        docs.append(Doc("logs-app-*", {
            "@timestamp": before,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "ecs": {"version": "8.11.0"},
            "event": {"outcome": "success", "action": "job-step"},
            "log": {"level": "info", "logger": "Engine.Jobs",
                    "file": {"path": "/var/log/backup/engine.log"}},
            "message": "Scheduler tick: 1 jobs due, 0 running, 0 queued",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip, "mac": ctr.mac},
            "cloud": {"account": {"id": t.account_id}, "instance": {"name": ctr.instance}},
            "labels": {"tenant_name": t.name, "tenant_full_name": t.full_name,
                       "tenant_id": t.tenant_id, "resource_name": t.resources[0]},
            "job": {"id": job_id, "session_id": session_id, "object_id": object_id,
                    "name": job, "status": "Success", "status_message": "Completed",
                    "counters": {"items": 412, "bytes": 1048576, "errors": 0}},
            "tenant": {"users_in_tenant": t.users},
            "service": {"name": "backup-engine", "version": "8.4.1"},
            "process": {"command_line": f"engine.exe --tenant {t.name}"},
        }, {job: "JOB_NAME", ctr.name: "SERVER_NAME", ctr.ip: "IPV4", ctr.mac: "MAC_ADDRESS",
            t.account_id: "CLOUD_ACCOUNT", ctr.instance: "INSTANCE_NAME", t.name: "ORG_NAME",
            t.full_name: "ORG_NAME", t.tenant_id: "TENANT_ID", t.resources[0]: "RESOURCE_NAME",
            job_id: "SESSION_GUID", session_id: "SESSION_GUID", object_id: "OBJECT_GUID",
            str(t.users): "TENANT_SIZE"}))
    return docs


# ---------------------------------------------------------------------------
# A realistic estate
# ---------------------------------------------------------------------------
#
# Everything above this line is a small, tidy fixture: eight tenants, seven
# level spellings, twelve thousand job names all of one shape. A real
# cluster is none of those things, and the shapes it does hold are what
# decide whether a name is vocabulary or stays readable. The shapes and the
# proportions below are from a measurement of one real cluster - shapes and
# counts only, no values; every name here is invented and built by position,
# never drawn, so the generator's RNG stream and every existing document are
# untouched.
#
# What was measured, and how it is modelled:
#
# * level fields hold about 17 spellings of the same few levels, with the
#   commonest ("info") outnumbering the next by about 40 to 1;
# * outcome fields hold success, failure and a rare third, with success
#   about 600 times commoner than failure;
# * about half of tenant names are one word; some carry digits; some are
#   all capitals;
# * job names: a few per cent are one word, about three in ten are two or
#   three words, two in ten are four words or more, one in ten carries
#   digits, a few per cent are an ordinary dictionary word. (The shares
#   named leave a remainder; it is modelled as plain two-word names, which
#   is the commonest shape.)
# * resource names are almost all one word with digits (vault017);
# * each name field holds about ten thousand distinct values over 30 days.
#
# The documents are appended after the generator's RNG stream and after the
# back catalogue, and they sit 6 to 22 days back - outside every window the
# existing cases query, inside the vocabulary build's 30 days. Like
# :func:`bulk_job_docs` they are **not ground truth**: no estate name is in
# ``Fixture.truth``, so the existing leak checks and gates see exactly what
# they saw before. The estate's own readability is measured by the estate
# section of ``run_eval``, against the names listed here.

ESTATE_TENANTS = 10_000
ESTATE_JOBS = 10_000
ESTATE_RESOURCES = 100
#: how many names of each shape class get a free-text mention. Every name
#: of the estate is read by the vocabulary build; a sample of each class is
#: *mentioned in a message with nothing marking it as a name*, which is what
#: the readability check needs and what costs a page to check.
ESTATE_MENTIONS_PER_CLASS = 12
#: the hour the mention documents sit in: its own window, so no existing
#: case can see them and they cannot see an existing case's documents
ESTATE_MENTION_RANGE = {"gte": "now-7d", "lte": "now-6d"}

_EST_HEAD = ("Brack", "Throck", "Fen", "Marl", "Quill", "Saltm", "Harb", "Kest",
             "Pent", "Sabl", "Tarn", "Ridg", "Calp", "Brind", "Harl", "Orch",
             "Wold", "Lark", "Nimb", "Vell", "Dorn", "Esk", "Ryd", "Galt")
_EST_JOB_HEAD = ("Ambl", "Bress", "Cawd", "Derw", "Ellen", "Fairl", "Gilsl", "Hask",
                 "Ivel", "Jarr", "Kelv", "Lund", "Mard", "Nether", "Ousel", "Prest",
                 "Quend", "Rask", "Stean", "Thrux", "Ulv", "Vend", "Wask", "Yarl")
_EST_MID = ("", "a", "e", "en", "in", "el", "er", "on", "ow", "um", "is", "or", "ar", "ey")
_EST_TAIL = ("ley", "ford", "mere", "wick", "holm", "dale", "bury", "stead", "garth",
             "thorpe", "combe", "wold", "beck", "hurst", "vale", "moor", "field",
             "gate", "haven", "ridge", "croft", "shaw", "thwaite", "burn", "cliff",
             "down", "marsh", "pool", "stone", "mouth")
#: 24 x 14 x 30 = 10,080 distinct one-word stems per pool, enough for both
#: ten-thousand-value fields with the pools kept disjoint by their heads.
_EST_SPAN = len(_EST_MID) * len(_EST_TAIL)
_EST_SECOND = ("Estates", "Holdings", "Partners", "Industries", "Logistics", "Analytics",
               "Collective", "Trading", "Ventures", "Networks", "Foundation", "Group")
_EST_SUFFIX = ("Limited", "GmbH", "AG", "LLC", "SpA", "BV")
_EST_JOB_WORD = ("Sweep", "Export", "Rollup", "Verify", "Reindex", "Compaction",
                 "Inventory", "Replication", "Seeding", "Trim", "Tiering", "Scrub")
_EST_JOB_EXTRA = ("Nightly", "Weekend", "Overflow", "Secondary", "Offsite", "Priority")
#: the ordinary dictionary words a few per cent of real names are: every one
#: of these is on :data:`elastic.ORDINARY_NAME_WORDS` or under the length
#: floor, which is the whole point of the class
#: There are only so many of these: a class whose members are dictionary
#: words has far fewer distinct values than its share of the estate, which
#: is true of a real cluster too and is why the distinct count per field
#: lands a little under ten thousand.
#: ("Archive" and "Vault" belong here by shape and are deliberately absent:
#: they are planted values of the existing no-vocabulary-section fixture,
#: and an estate name must never be one of those.)
_EST_ORDINARY = ("Default", "Primary", "Backup", "Staging", "Legacy",
                 "Records", "Retention", "Mailbox", "Sandbox", "Library",
                 "Finance", "Legal", "Compliance", "Operations", "Marketing", "Audit",
                 "Projects", "Exports", "Imports", "Storage", "Repository", "Office",
                 "Secondary", "Incremental", "Nightly", "Weekly", "Monthly", "Delta",
                 "Shared", "Internal", "External", "General", "Common", "Global",
                 "Sales", "Support", "Security", "Inbox")
_EST_RESOURCE_WORD = ("vault", "store", "pool", "node", "shard", "bucket",
                      "volume", "stack", "zone", "tier")
_EST_RESOURCE_PLAIN = ("Quarrowan", "Felstrike", "Mordenhale", "Tilbrake", "Ysgarth")

#: (class key, share in hundredths, what the shape is). Shares sum to 100
#: and the classes are disjoint, so "how many of this shape" is a count and
#: not an estimate.
ESTATE_TENANT_SHAPES: tuple[tuple[str, int, str], ...] = (
    ("tenant-one-word", 40, "one invented word"),
    ("tenant-one-word-ordinary", 5, "one ordinary dictionary word"),
    ("tenant-all-caps", 10, "two words, all capitals"),
    ("tenant-with-digits", 10, "one word and a number"),
    ("tenant-multi-word", 35, "two words"),
)
ESTATE_JOB_SHAPES: tuple[tuple[str, int, str], ...] = (
    ("job-one-word", 5, "one invented word"),
    ("job-one-word-ordinary", 3, "one ordinary dictionary word"),
    ("job-two-words", 32, "two words"),
    ("job-three-words", 30, "three words"),
    ("job-four-plus-words", 20, "four or five words"),
    ("job-with-digits", 10, "two words and a number"),
)
ESTATE_RESOURCE_SHAPES: tuple[tuple[str, int, str], ...] = (
    ("resource-word-digits", 95, "one word and a three-digit number"),
    ("resource-plain-word", 5, "one invented word"),
)


def _estate_stem(pool: tuple[str, ...], i: int) -> str:
    """A one-word invented name, by position. Distinct for distinct ``i``
    within one pool's span, and never equal across two pools (their heads
    are disjoint)."""
    return (pool[(i // _EST_SPAN) % len(pool)] + _EST_MID[(i // len(_EST_TAIL)) % len(_EST_MID)]
            + _EST_TAIL[i % len(_EST_TAIL)]).capitalize()


def _estate_class(shapes: tuple[tuple[str, int, str], ...], i: int) -> str:
    """Which shape class position ``i`` falls in. Interleaved by ``i % 100``
    rather than blocked, so any contiguous sample of the estate holds every
    shape in its measured proportion."""
    at = i % 100
    run = 0
    for key, share, _ in shapes:
        run += share
        if at < run:
            return key
    return shapes[-1][0]


def estate_tenant(i: int) -> tuple[str, str, str]:
    """(shape class, tenant name, tenant full name) for position ``i``."""
    k = _estate_class(ESTATE_TENANT_SHAPES, i)
    stem = _estate_stem(_EST_HEAD, i)
    second = _EST_SECOND[i % len(_EST_SECOND)]
    if k == "tenant-one-word":
        name = stem
    elif k == "tenant-one-word-ordinary":
        # i // 100, not i: a class's positions are every hundredth one, so
        # indexing by i would pick the same handful of words forever
        name = _EST_ORDINARY[(i // 100) % len(_EST_ORDINARY)]
    elif k == "tenant-all-caps":
        name = f"{stem} {second}".upper()
    elif k == "tenant-with-digits":
        name = f"{stem} {i % 900 + 100}"
    else:
        name = f"{stem} {second}"
    return k, name, f"{name} {_EST_SUFFIX[i % len(_EST_SUFFIX)]}"


def estate_job(i: int) -> tuple[str, str]:
    """(shape class, job name) for position ``i``."""
    k = _estate_class(ESTATE_JOB_SHAPES, i)
    stem = _estate_stem(_EST_JOB_HEAD, i)
    word = _EST_JOB_WORD[i % len(_EST_JOB_WORD)]
    extra = _EST_JOB_EXTRA[(i // 7) % len(_EST_JOB_EXTRA)]
    if k == "job-one-word":
        name = stem
    elif k == "job-one-word-ordinary":
        # i // 100, not i: a class's positions are every hundredth one, so
        # indexing by i would pick the same handful of words forever
        name = _EST_ORDINARY[(i // 100) % len(_EST_ORDINARY)]
    elif k == "job-two-words":
        name = f"{stem} {word}"
    elif k == "job-three-words":
        name = f"{stem} {extra} {word}"
    elif k == "job-four-plus-words":
        name = f"{stem} {extra} {word} Run" + (" Secondary" if i % 2 else "")
    else:
        name = f"{stem} {word} {i % 900 + 100}"
    return k, name


def estate_resource(i: int) -> tuple[str, str]:
    """(shape class, resource name) for position ``i``."""
    k = _estate_class(ESTATE_RESOURCE_SHAPES, i)
    word = _EST_RESOURCE_WORD[i % len(_EST_RESOURCE_WORD)]
    # their own invented words, not the tenant pool: a name belongs to one
    # shape class, so the per-class counts mean what they say
    return (k, word + f"{i:03d}") if k == "resource-word-digits" \
        else (k, _EST_RESOURCE_PLAIN[(i // 100) % len(_EST_RESOURCE_PLAIN)
                                     if i >= 100 else i % len(_EST_RESOURCE_PLAIN)])


#: The seventeen level spellings and three outcome spellings a real field
#: holds, with the measured skew: ``info`` about forty times the next
#: spelling, ``success`` about six hundred times ``failure``. They must come
#: back from the keep pass byte for byte, every one of them.
ESTATE_LEVEL_SPELLINGS: tuple[str, ...] = (
    "info", "Info", "Information", "information", "Informational", "INFO",
    "warn", "WARN", "Warning", "warning", "wrn",
    "err", "Error", "error", "ERROR", "debug", "Critical",
)
ESTATE_OUTCOME_SPELLINGS: tuple[str, ...] = ("success", "failure", "ongoing")
#: how many documents each spelling gets. "info" at 40 to 1 over the next,
#: "success" at ~600 to 1 over "failure"; the rest one document each, which
#: is enough for a bucket and keeps the fixture small.
ESTATE_LEVEL_DOCS = 1200
ESTATE_INFO_SHARE = 40


def _estate_level_plan() -> list[str]:
    """One level spelling per document, in the measured proportion, and
    **interleaved**: a real field's spellings are mixed through time, and a
    page of the first hundred documents must hold every one of them, which
    is what makes the spellings checkable as hit values and not only as
    bucket keys."""
    rest = ESTATE_LEVEL_SPELLINGS[1:]
    per = max(2, (ESTATE_LEVEL_DOCS // (ESTATE_INFO_SHARE + len(rest))))
    # the most recent documents, which is what one page of hits holds: one
    # of every spelling
    plan = list(ESTATE_LEVEL_SPELLINGS)
    # then the skew, which is what the bucket counts show
    plan += [ESTATE_LEVEL_SPELLINGS[0]] * (per * ESTATE_INFO_SHARE - 1)
    for sp in rest:
        plan += [sp] * (per - 1)
    return plan


def _estate_outcome(i: int, total: int) -> str:
    """success about 600 times failure, with one rarer third spelling."""
    if i == total - 1:
        return "ongoing"
    if i % max(1, total // 2) == 1:
        return "failure"
    return "success"


#: The clause that finds one shape class's mentions on a worker page without
#: naming anything in them: one per class, each invented and used nowhere
#: else in the fixture.
_EST_CLAUSES = (
    "rolled past the soft ceiling tonight",
    "queued behind the maintenance pause",
    "left two shards waiting on the mover",
    "reported an uneven spread across racks",
    "paused while the catalogue was rebuilt",
    "logged a slower than usual drain",
    "handed back to the scheduler untouched",
    "carried on after the throttle lifted",
    "settled below the warning watermark",
    "needed a second pass over the index",
    "finished behind the published window",
    "tripped the backlog notice twice",
    "cleared the queue with room to spare")


def estate_classes() -> list[tuple[str, str]]:
    """Every shape class, as (kind, class key), in report order."""
    return ([("tenant", k) for k, _, _ in ESTATE_TENANT_SHAPES]
            + [("job", k) for k, _, _ in ESTATE_JOB_SHAPES]
            + [("resource", k) for k, _, _ in ESTATE_RESOURCE_SHAPES])


def estate_names() -> dict[str, list[str]]:
    """Every invented estate name, by shape class."""
    out: dict[str, list[str]] = {k: [] for _, k in estate_classes()}
    for i in range(ESTATE_TENANTS):
        k, name, _full = estate_tenant(i)
        out[k].append(name)
    for i in range(ESTATE_JOBS):
        k, name = estate_job(i)
        out[k].append(name)
    for i in range(ESTATE_RESOURCES):
        k, name = estate_resource(i)
        out[k].append(name)
    return out


def estate_mentions() -> list[tuple[str, str, str, str]]:
    """(shape class, name, message, phrase) for the sampled names of every
    class: the name in free text with nothing marking it as a name, and a
    phrase that finds the message without naming it.

    The sample is spread across the class (every ``len/n``-th member), so it
    is not the first twelve of one spelling. The name's own field record is
    on an estate document days outside :data:`ESTATE_MENTION_RANGE`, so a
    page of these mentions cannot be rescued by harvesting.
    """
    out: list[tuple[str, str, str, str]] = []
    by_class = estate_names()
    for n, (_kind, key) in enumerate(estate_classes()):
        names = by_class[key]
        clause = _EST_CLAUSES[n % len(_EST_CLAUSES)]
        step = max(1, len(names) // ESTATE_MENTIONS_PER_CLASS)
        picked = [names[(j * step) % len(names)] for j in range(ESTATE_MENTIONS_PER_CLASS)]
        seen: set[str] = set()
        for j, name in enumerate(picked):
            if name in seen:
                continue
            seen.add(name)
            # half the mentions lead with the name, half bury it mid-sentence:
            # neither spelling has a marker a rule could read
            # No word of the message outside the name may be a word *of* a
            # name, or the word-by-word check would report the fixture's own
            # vocabulary as a leak ("... run 2" beside a job called
            # "... Run"). The clauses are chosen the same way.
            message = (f"{name} {clause}, attempt {j + 1}" if j % 2 == 0
                       else f"Retry {j} of {name} {clause}")
            out.append((key, name, message, clause))
    return out


def estate_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """The estate: one document per name position, the mention documents,
    and the level/outcome spelling documents.

    Positions, not draws: no RNG is consumed, and nothing here is ground
    truth (see the section comment).
    """
    docs: list[Doc] = []
    ctr, prx = servers["ctr"][2], servers["prx"][3]
    other = tenants[4]
    n = max(ESTATE_TENANTS, ESTATE_JOBS)
    for i in range(n):
        at = (NOW - timedelta(days=8) - timedelta(minutes=2 * i)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        _k, tenant, full = estate_tenant(i % ESTATE_TENANTS)
        _jk, job = estate_job(i % ESTATE_JOBS)
        _rk, resource = estate_resource(i % ESTATE_RESOURCES)
        docs.append(Doc("logs-app-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": _estate_outcome(i, n), "action": "job-step"},
            "log": {"level": ESTATE_LEVEL_SPELLINGS[i % len(ESTATE_LEVEL_SPELLINGS)],
                    "logger": "Engine.Jobs"},
            "message": "Scheduler tick: 1 jobs due, 0 running, 0 queued",
            "labels": {"tenant_name": tenant, "tenant_full_name": full,
                       "tenant_id": other.tenant_id, "resource_name": resource},
            "job": {"name": job, "status": "Success"},
            "service": {"name": "backup-engine", "version": "8.4.1"},
        }, {}))

    # the mentions: free text, no marker, in their own hour
    for i, (_key, _name, message, _phrase) in enumerate(estate_mentions()):
        at = (NOW - timedelta(days=6, hours=1) - timedelta(seconds=10 * i)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            # the commonest spelling, so these documents join the dominant
            # bucket instead of flattening the skew that the spelling
            # documents are there to show
            "log": {"level": ESTATE_LEVEL_SPELLINGS[0]},
            "message": message,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": other.name, "tenant_id": other.tenant_id},
        }, {}))

    # the spelling documents: every level and outcome spelling the estate
    # logs, in the measured proportion, in the estate's own window
    plan = _estate_level_plan()
    for i, level in enumerate(plan):
        at = (NOW - timedelta(days=6, hours=3) - timedelta(seconds=5 * i)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-worker-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": _estate_outcome(i, len(plan))},
            "log": {"level": level},
            "message": "Worker heartbeat, queue depth 0",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip},
            "labels": {"tenant_name": other.name, "tenant_id": other.tenant_id},
        }, {}))
    return docs


# ---------------------------------------------------------------------------
# Names that are ordinary words
# ---------------------------------------------------------------------------
#
# A job really called "Backup" is a name in its own field and an ordinary
# English word everywhere else. The vocabulary already knows that and skips
# it (``elastic.ORDINARY_NAME_WORDS``), but harvesting a page used to
# override the decision: one document whose job field said "Backup" made
# the word a known value for the whole case, and from then on every message
# lost it ("Backup window opened" -> "<Job-12> window opened"). On a real
# cluster about 7 in 100 common job names are ordinary words, so it
# happened on the first pages, and which page came first decided what a
# later page said.
#
# These documents sit **outside** ``vocabulary.days`` on purpose: the
# labels here come from harvesting a page, not from the vocabulary build,
# which is exactly the route that bypassed the rule - and it keeps the
# build's measured cost unchanged. Appended after the estate; all names
# invented in the sense that matters here, which is that they are ordinary
# words and nobody's customer.

#: Seven job names that are ordinary words. Every one is on
#: ``elastic.ORDINARY_NAME_WORDS``, which is what makes the vocabulary skip
#: it; the list itself is not changed here.
ORDINARY_WORD_JOBS: tuple[str, ...] = (
    "Backup", "Retention", "Mailbox", "Inbox", "Audit", "Storage", "Sandbox")
#: the page that shows those names in their own fields, and the page of
#: ordinary messages that use the same words as English
ORDINARY_RANGE = {"gte": "now-41d", "lte": "now-39d"}
ORDINARY_OWN_PHRASE = "closed its run book entry"
ORDINARY_TEXT_PHRASE = "queued behind the overnight window"
#: (job name, the ordinary English sentence that uses the word)
ORDINARY_MESSAGES: tuple[tuple[str, str], ...] = (
    ("Backup", "Backup window opened, 14 items queued behind the overnight window"),
    ("Retention", "Retention policy applied to 3 sites, queued behind the overnight window"),
    ("Mailbox", "Mailbox quota raised for 2 users, queued behind the overnight window"),
    ("Inbox", "Inbox rules synced for the team, queued behind the overnight window"),
    ("Audit", "Audit log export started, queued behind the overnight window"),
    ("Storage", "Storage tier changed to cool, queued behind the overnight window"),
    ("Sandbox", "Sandbox refresh scheduled, queued behind the overnight window"),
)


def ordinary_word_docs(tenants: list[Tenant], servers: dict[str, list[Server]]) -> list[Doc]:
    """Two documents per ordinary-word job name: the one whose own field
    holds it (and whose message names it twice over), and one whose message
    just uses the word. Positions, not draws; not ground truth."""
    docs: list[Doc] = []
    ctr, prx = servers["ctr"][3], servers["prx"][5]
    t = tenants[6]
    for i, (job, message) in enumerate(ORDINARY_MESSAGES):
        at = (NOW - timedelta(days=40) - timedelta(minutes=2 * i)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-app-*", {
            "@timestamp": at,
            "data_stream": {"dataset": "app.engine", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success", "action": "job-step"},
            "log": {"level": "info", "logger": "Engine.Jobs"},
            # the owning document names the job in its text too
            "message": f"{job} {ORDINARY_OWN_PHRASE} after 2 retries",
            "agent": {"name": ctr.name},
            "host": {"name": ctr.name, "ip": ctr.ip},
            "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
            "job": {"name": job, "status": "Success"},
            "service": {"name": "backup-engine", "version": "8.4.1"},
        }, {}))
        later = (NOW - timedelta(days=40) + timedelta(minutes=2 * i + 1)) \
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc("logs-worker-*", {
            "@timestamp": later,
            "data_stream": {"dataset": "worker.items", "type": "logs", "namespace": "default"},
            "event": {"outcome": "success"},
            "log": {"level": "info"},
            "message": message,
            "agent": {"name": prx.name},
            "host": {"name": prx.name, "ip": prx.ip},
            "labels": {"tenant_name": t.name, "tenant_id": t.tenant_id},
        }, {}))
    return docs


#: An identifier field with a fresh value on almost every document, beside
#: the name fields a vocabulary is for. This is the shape that stopped the
#: sliced build finishing at all: with no ``vocabulary`` section every
#: learnable field is read, so a per-request reference typed REQUEST_REF was
#: paged to ``vocabulary.max`` and only then refused - fifty-one requests,
#: the whole slice abandoned, retried, abandoned again, and no case ever
#: served. All values invented; the documents are appended after the estate
#: and live in their own index pattern, so nothing above them moves and no
#: other query or build pays for them.
#:
#: The cap here is **5,000, not the default 50,000**, so the fixture is
#: 5,620 documents rather than 50,000: a site may set any cap, and what the
#: gate measures - one count instead of a page per thousand values - does
#: not depend on which one. At the default cap the same field costs 51
#: requests a slice before the probe and 1 ever after it.
OVER_CAP_INDEX = "logs-ref-*"
OVER_CAP_FIELD = "request.ref"
OVER_CAP_MAX = 5_000
#: distinct references in the newest day (over the cap) and in the day
#: before it (the day the case asks about)
OVER_CAP_REFS = 5_500
OVER_CAP_REFS_YESTERDAY = 120
#: the name the case is about, and the job beside it. Multi-word and
#: invented, so no skip rule drops them and no recognizer has a shape for
#: them: with tier 2 off, a name hidden in message text can only have come
#: from the vocabulary.
OVER_CAP_TENANT = "Wrenfield Quay Holdings"
OVER_CAP_JOB = "Ledger Reconcile Nightly"
OVER_CAP_MESSAGE = f"Quota review for {OVER_CAP_TENANT} completed, 3 shares pending"
OVER_CAP_PHRASE = "shares pending"
#: the case is about yesterday: inside the second slice, outside the first
OVER_CAP_RANGE = {"gte": "now-27h", "lte": "now-25h"}
#: Like the back catalogue and the estate, these documents hold **no**
#: ground truth, so every existing leak check sees exactly what it saw.
#: This is the truth for this gate's own check, and nothing else reads it.
OVER_CAP_TRUTH = {OVER_CAP_TENANT: "ORG_NAME", OVER_CAP_JOB: "JOB_NAME"}


def over_cap_ref(i: int) -> str:
    return f"req-{i:07d}-{'abcdefghjkmnpqrstuvwxyz'[i % 23]}{i % 97:02d}"


def over_cap_docs() -> list[Doc]:
    """The oversized identifier field, the name the case is about, and the
    message that names it with nothing marking it.

    Positions, not draws, and no ground truth: like ``BULK_JOBS`` these are
    appended after the RNG stream, so every figure above them is unchanged.
    """
    docs: list[Doc] = []
    for i in range(OVER_CAP_REFS):
        at = (NOW - timedelta(minutes=1 + (i % 1380))).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc(OVER_CAP_INDEX, {
            "@timestamp": at,
            "log": {"level": "info"},
            "message": "Request accepted, 1 item queued",
            "request": {"ref": over_cap_ref(i)},
        }, {}))
    for i in range(OVER_CAP_REFS_YESTERDAY):
        at = (NOW - timedelta(hours=25, minutes=1 + i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        docs.append(Doc(OVER_CAP_INDEX, {
            "@timestamp": at,
            "log": {"level": "info"},
            "message": "Request accepted, 1 item queued",
            "request": {"ref": over_cap_ref(OVER_CAP_REFS + i)},
        }, {}))
    # the message the case finds, naming the tenant with nothing marking it
    docs.append(Doc(OVER_CAP_INDEX, {
        "@timestamp": (NOW - timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "log": {"level": "warn"},
        "message": OVER_CAP_MESSAGE,
        "request": {"ref": over_cap_ref(OVER_CAP_REFS + OVER_CAP_REFS_YESTERDAY)},
    }, {}))
    # and the record that carries the name in its own field, on another
    # document and outside the hours the case asks for: only the vocabulary
    # can connect the two
    docs.append(Doc(OVER_CAP_INDEX, {
        "@timestamp": (NOW - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "log": {"level": "info"},
        "message": "Inventory refreshed",
        "labels": {"tenant_name": OVER_CAP_TENANT},
        "job": {"name": OVER_CAP_JOB},
    }, {}))
    return docs


def over_cap_map(*, listed: bool) -> elastic.ElasticConfig:
    """The invented site map for those documents, through the real parser.

    ``listed`` is the difference the rule turns on: with no
    ``vocabulary.fields`` the oversized field is in the **default** set and
    is left out; with the map naming it, the site asked for that field by
    name and the slice is refused instead.
    """
    raw = {
        "indices": [OVER_CAP_INDEX],
        "time_field": "@timestamp",
        "clusters": {"stub": "https://kibana-stub.example.net"},
        "vocabulary": {"days": 30, "max": OVER_CAP_MAX, "budget_s": 1200},
        "fields": {
            "@timestamp": "keep",
            "log.level": "keep",
            "message": "text",
            "job.name": {"kind": "identifier", "type": "JOB_NAME"},
            "labels.tenant_name": {"kind": "identifier", "type": "ORG_NAME"},
            OVER_CAP_FIELD: {"kind": "identifier", "type": "REQUEST_REF"},
        },
    }
    if listed:
        raw["vocabulary"]["fields"] = ["job.name", "labels.tenant_name", OVER_CAP_FIELD]
    return elastic.parse(raw, source="over-cap-fixture")


# ---------------------------------------------------------------------------
# A data stream named after a job
# ---------------------------------------------------------------------------
#
# Once the name vocabulary was applied, every learnt name was matched inside
# keep values as well as in text, and a stream whose name happens to contain
# a job's name lost it in its index, dataset and namespace:
# ``logs-agent.harborsync_events-prod`` came back with the job's label in
# the middle, so Claude could no longer filter by the dataset (a keep field
# takes literals, and it only had a label). Now a learnt or harvested name
# replaces a keep value only when it *is* the value. These documents are
# appended after everything else, in an index pattern of their own with a
# map of their own, so no other query, build or count sees them, and they
# hold no ground truth. All names invented.
STREAM_JOB = "Harborsync"
STREAM_INDEX = "logs-agent.harborsync_events-*"
STREAM_DATASET = "agent.harborsync_events"
STREAM_NAMESPACE = "harborsync_events-prod"
STREAM_RANGE = {"gte": "now-6h", "lte": "now"}
#: the job's own record names it in its field and its text; the other
#: message names it with nothing marking it, so only the vocabulary hides it
STREAM_OWN_MESSAGE = f"{STREAM_JOB} finished 3 batches"
STREAM_TEXT_MESSAGE = f"Retry scheduled for {STREAM_JOB} after a throttle"
STREAM_PHRASE = "batches"
STREAM_TEXT_PHRASE = "after a throttle"


def stream_name_docs() -> list[Doc]:
    """Three documents in the job-named stream. Positions, not draws."""
    base = {"data_stream": {"type": "logs", "dataset": STREAM_DATASET,
                            "namespace": STREAM_NAMESPACE},
            "log": {"level": "info"}}
    at = lambda m: (NOW - timedelta(hours=2, minutes=m)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return [
        Doc(STREAM_INDEX, {**base, "@timestamp": at(1), "message": STREAM_OWN_MESSAGE,
                           "job": {"name": STREAM_JOB},
                           # a keep field that holds the whole name: labelled
                           "service": {"name": STREAM_JOB}}, {}),
        Doc(STREAM_INDEX, {**base, "@timestamp": at(2), "message": STREAM_TEXT_MESSAGE,
                           "service": {"name": "agent"}}, {}),
        Doc(STREAM_INDEX, {**base, "@timestamp": at(3), "message": "Heartbeat",
                           "service": {"name": "agent"}}, {}),
    ]


def stream_name_map() -> elastic.ElasticConfig:
    raw = {
        "indices": [STREAM_INDEX],
        "time_field": "@timestamp",
        "clusters": {"stub": "https://kibana-stub.example.net"},
        "fields": {
            "@timestamp": "keep",
            "data_stream.*": "keep",
            "log.level": "keep",
            "service.name": "keep",
            "message": "text",
            "job.name": {"kind": "identifier", "type": "JOB_NAME"},
        },
    }
    return elastic.parse(raw, source="stream-name-fixture")


def run_stream_name_eval(fx: Fixture, *, tier2: str = "none") -> dict:
    """The job-named stream, before and after the keep rule.

    Each run is one fresh case on the same cover: the stream's page, then
    a terms aggregation over the dataset. "Before" sets
    ``keep_parts_swept`` (the measurement switch, set by nothing in the
    live path). Counted: keep values changed (``_index`` and every keep
    leaf of every hit, and every keep bucket key), and whether the job is
    still labelled in its own field, in message text and in the keep
    field that holds the whole name. Tier 2 off, so a name hidden in text
    can only have come from the vocabulary.

    Every call goes through the real ``esbridge.Bridge`` (:class:`BridgeCase`),
    so the vocabulary is applied the way the live path applies it: by the
    case's first query, which is then gated against it.

    Then the other half - a readable value has to be usable: the dataset
    literal, typed by a fresh case that was never shown it, is refused as
    ``known_value``; typed by the case that was shown the page, it runs and
    returns the stream's hits; the whole name typed as the keep field that
    held it stays refused even for that case (it was shown only as a
    label).
    """
    cfg = stream_name_map()
    engine = StubEngine(fx, (STREAM_INDEX,))
    vocab, _build = build_vocabulary(cfg, engine)
    page_q = {"index": STREAM_INDEX, "time_range": STREAM_RANGE, "size": 20}
    agg_q = {"index": STREAM_INDEX, "time_range": STREAM_RANGE, "size": 0,
             "aggs": {"datasets": {"type": "terms", "field": "data_stream.dataset", "size": 10},
                      "namespaces": {"type": "terms", "field": "data_stream.namespace",
                                     "size": 10}}}
    raw_docs = [d.source for d in fx.docs if d.index == STREAM_INDEX]
    keep_paths = ("data_stream.type", "data_stream.dataset", "data_stream.namespace",
                  "log.level", "service.name")

    def get(src: dict, path: str) -> Any:
        for k in path.split("."):
            src = src.get(k) if isinstance(src, dict) else None
        return src

    def one(before: bool) -> dict:
        sess = BridgeCase(cfg, engine, vocab, tier2=tier2)
        sess.scrubber.keep_parts_swept = before
        r = {"shown": False, "keep_values": 0, "keep_changed": 0, "changed_fields": [],
             "index_readable": False, "dataset_readable": False, "namespace_readable": False,
             "bucket_keys_readable": False, "job_field_labelled": False,
             "text_labelled": False, "whole_keep_labelled": False,
             "filter_unshown_refused": None, "filter_shown_hits": 0,
             "filter_shown_requests": 0, "whole_name_refused": None}
        dataset_q = {"index": STREAM_INDEX, "time_range": STREAM_RANGE, "size": 20,
                     "filters": [{"field": "data_stream.dataset", "op": "eq",
                                  "value": STREAM_DATASET}]}
        # never shown the value: a guess, refused before any request
        requests_before = len(engine.requests)
        _out, refused, _dt, _c = sess.call(dataset_q)
        r["filter_unshown_refused"] = refused.code if refused else None
        r["filter_unshown_requests"] = len(engine.requests) - requests_before
        out, refused, _dt, _c = sess.call(page_q)
        if out is None:
            r["refused"] = refused.code if refused else None
            return r
        hits = out["hits"]["hits"]
        r["shown"] = len(hits) == len(raw_docs)
        backing = backing_index(STREAM_INDEX)
        changed: set[str] = set()
        for h in hits:
            r["keep_values"] += 1
            if h["_index"] != backing:
                r["keep_changed"] += 1
                changed.add("_index")
        # match each hit to its raw document by timestamp (a keep field)
        raw_by_ts = {d["@timestamp"]: d for d in raw_docs}
        for h in hits:
            src = h["_source"]
            rd = raw_by_ts.get(src.get("@timestamp"), {})
            for p in keep_paths:
                rv = get(rd, p)
                if rv is None:
                    continue
                r["keep_values"] += 1
                if get(src, p) != rv:
                    r["keep_changed"] += 1
                    changed.add(p)
        r["index_readable"] = all(h["_index"] == backing for h in hits)
        r["dataset_readable"] = all(get(h["_source"], "data_stream.dataset") == STREAM_DATASET
                                    for h in hits)
        r["namespace_readable"] = all(
            get(h["_source"], "data_stream.namespace") == STREAM_NAMESPACE for h in hits)
        label = sess.scrubber.known.get(jsonscrub_norm(STREAM_JOB))
        own = next((h["_source"] for h in hits
                    if get(h["_source"], "job.name") is not None), {})
        r["job_field_labelled"] = bool(label) and get(own, "job.name") == label
        r["whole_keep_labelled"] = bool(label) and get(own, "service.name") == label
        msgs = _messages(out)
        r["text_labelled"] = (bool(label) and not any(STREAM_JOB.casefold() in m.casefold()
                                                      for m in msgs)
                              and sum(1 for m in msgs if label in m) == 2)
        agg, refused, _dt, _c = sess.call(agg_q)
        if agg is not None:
            keys = []
            for name, want in (("datasets", STREAM_DATASET), ("namespaces", STREAM_NAMESPACE)):
                for b in agg["aggregations"][name]["buckets"]:
                    r["keep_values"] += 1
                    keys.append(b["key"] == want)
                    if b["key"] != want:
                        r["keep_changed"] += 1
                        changed.add(f"<bucket>.{name}")
            r["bucket_keys_readable"] = bool(keys) and all(keys)
        r["changed_fields"] = sorted(changed)
        # shown the page: the dataset literal runs and finds the stream
        requests_before = len(engine.requests)
        hit, refused, _dt, _c = sess.call(dataset_q)
        r["filter_shown_requests"] = len(engine.requests) - requests_before
        r["filter_shown_hits"] = ((hit or {}).get("hits", {}).get("total") or {}).get("value", 0) \
            if refused is None else 0
        r["filter_shown_refused"] = refused.code if refused else None
        # the whole name, which came back only as a label, is still refused
        _out, refused, _dt, _c = sess.call({
            "index": STREAM_INDEX, "time_range": STREAM_RANGE, "size": 20,
            "filters": [{"field": "service.name", "op": "eq", "value": STREAM_JOB}]})
        r["whole_name_refused"] = refused.code if refused else None
        return r

    return {"before": one(True), "after": one(False)}


# ---------------------------------------------------------------------------
# A name first logged in the gap after a saved cover
# ---------------------------------------------------------------------------
#
# A bridge restarted days after the last one holds a cover that ends days
# ago. A tenant onboarded in between has never been read, so its name is
# plain English in message text. Fixed documents, appended after everything
# else, in an index pattern and map of their own; no ground truth.
GAP_INDEX = "logs-gap-*"
GAP_TENANT = "Harbor Ridge Quarries"
GAP_MESSAGE = f"Onboarding checks passed for {GAP_TENANT}, 4 sites mapped"
GAP_QUERY = {"index": GAP_INDEX, "time_range": {"gte": "now-2d", "lte": "now"}, "size": 20,
             "filters": [{"field": "message", "op": "phrase", "value": "sites mapped"}]}
#: an older tenant the saved cover did read, so the cover has something in it
GAP_OLD_TENANT = "Wexcombe Lantern Freight"
#: Job names logged across the seven-day gap, one document each, spread
#: evenly: enough that reading the whole gap in one request pays the
#: wide-range rate for more pages than ``budget_s`` allows, while each
#: one-day slice is two pages at the slice rate. Invented, by position.
GAP_JOBS = 12_000
GAP_DAYS = 7


def gap_job(i: int) -> str:
    return f"Gapwater Run {i:05d}"


def gap_docs() -> list[Doc]:
    at = lambda h: (NOW - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return [
        Doc(GAP_INDEX, {"@timestamp": at(24 * 9), "log": {"level": "info"},
                        "message": "Inventory refreshed",
                        "labels": {"tenant_name": GAP_OLD_TENANT}}, {}),
        # the gap tenant's own record, a day ago, and the message naming it
        Doc(GAP_INDEX, {"@timestamp": at(24), "log": {"level": "info"},
                        "message": "Inventory refreshed",
                        "labels": {"tenant_name": GAP_TENANT}}, {}),
        Doc(GAP_INDEX, {"@timestamp": at(20), "log": {"level": "warn"},
                        "message": GAP_MESSAGE,
                        "labels": {"tenant_name": GAP_OLD_TENANT}}, {}),
    ] + [
        Doc(GAP_INDEX, {"@timestamp": at(0.5 + i * (GAP_DAYS * 24.0 - 1.0) / GAP_JOBS),
                        "log": {"level": "info"}, "message": "Run finished",
                        "job": {"name": gap_job(i)}}, {})
        for i in range(GAP_JOBS)
    ]


def run_gap_eval(*, tier2: str = "none") -> dict:
    """A cover saved a week ago, a tenant first logged in the gap, on the
    real Bridge. Measured: what the same page shows with the old cover
    applied and no gate (the leak this closes), that the gated bridge
    refuses with no request, that the top-up the broker would run first is
    the gap itself, that after it the open case is shown with the name
    hidden, and that a ten-minute gap serves."""
    from . import esbridge

    cfg = gap_map()
    fx = Fixture(gap_docs(), [], [])
    engine = StubEngine(fx, (GAP_INDEX,))
    now = NOW.timestamp()
    out: dict = {"gap_h": 168.0, "bound_h": elastic.vocabulary_max_gap(cfg) / 3600.0}
    old, _b = build_vocabulary(cfg, engine, now - 10 * 86400.0, now - 7 * 86400.0)
    # without the gate: the old cover applied, the page as it was shown
    sess = Session(cfg, engine, tier2=tier2, vocabulary=old)
    page, _r, _dt, _c = sess.call(GAP_QUERY)
    out["readable_without_gate"] = GAP_TENANT in " ".join(_messages(page))
    index = elastic.VocabularyIndex(None)
    index.started_at = now - 60.0
    index.put("stub", old)
    saved = esbridge.clock
    esbridge.clock = lambda: now
    try:
        b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2), EngineSession(engine),
                            index=index)
        n = len(engine.requests)
        try:
            b.run("stub", GAP_QUERY)
            out["refused"] = None
        except elastic.Refused as e:
            out["refused"] = e.code
            out["message_names_gap"] = "not been read" in e.message and "to now" in e.message
            out["message_has_value"] = GAP_TENANT in e.message
        out["requests_while_refused"] = len(engine.requests) - n
        rep = index.report("stub", cfg, now=now)
        out["state"] = rep["state"]
        out["line"] = esbridge.vocabulary_line(rep) or ""
        nxt = elastic.next_vocabulary_slice(cfg, index.get("stub"), now)
        # the first slice read is the one right after the cover's end
        out["top_up_first"] = nxt is not None and nxt[0] == index.get("stub").covered_until
        out["slices_to_close"] = 0
        while nxt is not None and index.get("stub").behind(cfg, now):
            top, _b = build_vocabulary(cfg, engine, *nxt)
            index.put("stub", top)
            out["slices_to_close"] += 1
            nxt = elastic.next_vocabulary_slice(cfg, index.get("stub"), now)
        o = b.run("stub", GAP_QUERY)
        msgs = " ".join(_messages(o.output))
        out["shown_after"] = o.hits_shown >= 1
        out["hidden_after"] = GAP_TENANT not in json.dumps(o.output) and "sites mapped" in msgs
        # ten minutes behind: as today
        recent, _b = build_vocabulary(cfg, engine, now - 3 * 86400.0, now - 600.0)
        i2 = elastic.VocabularyIndex(None)
        i2.started_at = now - 86400.0
        i2.put("stub", recent)
        b2 = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2), EngineSession(engine),
                             index=i2)
        b2.run("stub", GAP_QUERY)
        out["ten_minutes_serves"] = True
    except elastic.Refused as e:
        out.setdefault("ten_minutes_serves", False)
        out["error"] = e.code
    finally:
        esbridge.clock = saved
    return out


def _gap_lines(o: dict | None) -> list[str]:
    if not o:
        return []
    return [f"gap after a saved cover  {o['gap_h']:.0f}h behind against a {o['bound_h']:.1f}h "
            f"bound: the gap tenant readable without the gate {o['readable_without_gate']}; "
            f"refused {o.get('refused')} with {o.get('requests_while_refused')} requests, state "
            f"{o.get('state')}; the top-up reads the gap first {o.get('top_up_first')}; after it "
            f"shown {o.get('shown_after')}, name hidden {o.get('hidden_after')}; ten minutes "
            f"behind serves {o.get('ten_minutes_serves')}"]


def gap_map() -> elastic.ElasticConfig:
    return elastic.parse({
        "indices": [GAP_INDEX], "time_field": "@timestamp",
        "clusters": {"stub": "https://kibana-stub.example.net"},
        "fields": {"@timestamp": "keep", "log.level": "keep", "message": "text",
                   "labels.tenant_name": {"kind": "identifier", "type": "ORG_NAME"},
                   "job.name": {"kind": "identifier", "type": "JOB_NAME"}},
    }, source="gap-fixture")


def run_catch_up_eval(*, tier2: str = "none", max_steps: int = 20_000) -> dict:
    """The catch-up after a week down, with the stub charging the slice
    rate over a day and the wide rate over anything wider.

    Before: the gap read as one request from the cover's end to now, as the
    broker did (``VocabularyBuild`` over the whole gap): requests, simulated
    seconds, pages at the wide rate, and whether it failed its budget.
    After: the real ``Broker`` stepping a slice at a time: slices, requests,
    seconds, the worst slice against the budget, wide pages (must be none),
    the saved cover still one range, a case refused throughout with a true
    slices-left count, and the same open case shown after with the gap
    tenant hidden.
    """
    from . import esbridge

    cfg = gap_map()
    cluster = elastic.Cluster("stub", "https://kibana-stub.example.net")
    fx = Fixture(gap_docs(), [], [])
    engine = StubEngine(fx, (GAP_INDEX,))
    engine.page_seconds = PAGE_SECONDS
    engine.wide_page_seconds = WIDE_PAGE_SECONDS
    now = NOW.timestamp()
    gap_s = GAP_DAYS * 86400.0
    out: dict = {"gap_days": GAP_DAYS, "budget_s": cfg.vocabulary_budget_s,
                 "before": {}, "after": {}}
    old, _b = build_vocabulary(cfg, engine, now - gap_s - 3 * 86400.0, now - gap_s)

    # -- before: one read over the whole gap ---------------------------------
    r0, s0, w0 = len(engine.requests), engine.simulated_seconds, engine.wide_pages
    build = elastic.VocabularyBuild(cfg, old.covered_until, now,
                                    clock=lambda: engine.simulated_seconds)
    refused = None
    try:
        while build.pending():
            vq = build.request()["params"]
            build.feed({"isPartial": False, "isRunning": False,
                        "rawResponse": engine.search(vq["index"], vq["body"],
                                                     ignore_unavailable=True)})
    except elastic.Refused as e:
        refused = e.code
    out["before"] = {"requests": len(engine.requests) - r0,
                     "seconds": round(engine.simulated_seconds - s0, 1),
                     "wide_pages": engine.wide_pages - w0, "refused": refused}

    # -- after: the broker, a serve-loop step at a time ------------------------
    transport = SteppedSearchTransport(engine)
    tmp = Path(tempfile.mkdtemp(prefix="hider-es-eval-catchup-"))
    saved_clock = esbridge.clock
    esbridge.clock = lambda: now
    a: dict = {"slices": 0, "requests": 0, "seconds": 0.0, "max_slice_s": 0.0,
               "wide_pages": 0, "failed_slices": 0, "steps": 0, "one_range": False,
               "covered_from_kept": False, "refusals_while_behind": 0,
               "slices_left_seen": [], "message_names_slices": False,
               "shown_after": False, "hidden_after": False, "line_before": "", "line_mid": ""}
    try:
        broker = esbridge.Broker(cfg, lambda: transport, poll_interval=0.0, sessions_dir=tmp)
        broker.open()
        broker.vocabulary.put("stub", old)
        r1, s1, w1 = len(engine.requests), engine.simulated_seconds, engine.wide_pages
        bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2),
                                 EngineSession(engine), index=broker.vocabulary)
        a["line_before"] = esbridge.vocabulary_line(broker.vocabulary_progress("stub")) or ""
        slice_seconds: list[float] = []
        slice_start = engine.simulated_seconds
        last_slices = 0
        broker.start_vocabulary(cluster)
        while a["steps"] < max_steps:
            held = broker.vocabulary.get("stub")
            if held is not None and not held.behind(cfg, now):
                break
            # a case during the catch-up: refused, and told how much is left
            try:
                bridge.run("stub", GAP_QUERY)
            except elastic.Refused as e:
                a["refusals_while_behind"] += 1
                m = re.search(r"(\d+) of (\d+) one-day slices left", e.message)
                if m:
                    a["slices_left_seen"].append(int(m.group(1)))
                    a["message_names_slices"] = True
            if not broker.pump_vocabulary():
                break
            a["steps"] += 1
            done = sum(1 for r in broker._build_log if r["vocabulary"] == "slice")
            if done > last_slices:
                slice_seconds.append(engine.simulated_seconds - slice_start)
                slice_start = engine.simulated_seconds
                last_slices = done
                if a["line_mid"] == "" and done == 2:
                    a["line_mid"] = esbridge.vocabulary_line(
                        broker.vocabulary_progress("stub")) or ""
        held = broker.vocabulary.get("stub")
        a["slices"] = last_slices
        a["failed_slices"] = sum(1 for r in broker._build_log if r["vocabulary"] == "failed")
        a["requests"] = len(engine.requests) - r1
        a["seconds"] = round(engine.simulated_seconds - s1, 1)
        a["max_slice_s"] = round(max(slice_seconds), 1) if slice_seconds else 0.0
        a["wide_pages"] = engine.wide_pages - w1
        a["one_range"] = held is not None and len(broker.vocabulary.clusters) == 1
        a["covered_from_kept"] = held is not None and held.covered_from == old.covered_from
        a["covered_until_now"] = held is not None and now - held.covered_until < 1.0
        a["slices_left_decreasing"] = a["slices_left_seen"] == sorted(
            a["slices_left_seen"], reverse=True) and bool(a["slices_left_seen"])
        a["first_slices_left"] = a["slices_left_seen"][0] if a["slices_left_seen"] else None
        try:
            o = bridge.run("stub", GAP_QUERY)
            a["shown_after"] = o.hits_shown >= 1
            a["hidden_after"] = GAP_TENANT not in json.dumps(o.output)
        except elastic.Refused as e:
            a["refused_after"] = e.code
        a["log_values"] = sum(1 for r in broker._build_log
                              if GAP_TENANT in json.dumps(r) or gap_job(7) in json.dumps(r))
    finally:
        esbridge.clock = saved_clock
    out["after"] = a
    return out


def _catch_up_lines(o: dict | None) -> list[str]:
    if not o:
        return []
    b, a = o["before"], o["after"]
    return [f"catch-up after {o['gap_days']}d down  one wide read: {b['requests']} requests, "
            f"{b['seconds']}s, {b['wide_pages']} pages at the wide rate, "
            f"{'refused ' + b['refused'] if b['refused'] else 'finished'} against a "
            f"{o['budget_s']:g}s budget; sliced: {a['slices']} slices ({a['failed_slices']} failed), "
            f"{a['requests']} requests, {a['seconds']}s, worst slice {a['max_slice_s']}s, "
            f"{a['wide_pages']} wide pages; cover one range {a['one_range']}, start kept "
            f"{a['covered_from_kept']}, end at now {a.get('covered_until_now')}; "
            f"{a['refusals_while_behind']} refusals while behind, slices left "
            f"{a.get('first_slices_left')} first and decreasing {a.get('slices_left_decreasing')}; "
            f"after: shown {a['shown_after']}, name hidden {a['hidden_after']}; values in the "
            f"build log {a.get('log_values')}"]


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


def _query_range_seconds(body: dict) -> float | None:
    """How wide the request's time range is, which is what a composite page
    is charged by. None when the request carries no range."""
    def walk(clause: Any) -> float | None:
        if not isinstance(clause, dict):
            return None
        for kind, spec in clause.items():
            if kind == "bool":
                for c in spec.get("filter", []) if isinstance(spec, dict) else []:
                    got = walk(c)
                    if got is not None:
                        return got
            elif kind == "range" and isinstance(spec, dict):
                for f, bounds in spec.items():
                    if f != "@timestamp" or not isinstance(bounds, dict):
                        continue
                    lo = _parse_time(bounds.get("gte") or bounds.get("gt"))
                    hi = _parse_time(bounds.get("lte") or bounds.get("lt"), round_up=True)
                    if lo is not None and hi is not None:
                        return (hi - lo).total_seconds()
        return None

    return walk(body.get("query"))


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
        self._flat: dict[str, list[tuple[int, dict]]] = {}
        #: Simulated cost of one composite page over one field, in seconds.
        #: An in-memory engine answers instantly, which would make a
        #: vocabulary build look free; on a real cluster a page of 1,000
        #: values for one name field was measured at 8 to 35 seconds. The
        #: cost is charged per field per page, because that is where the
        #: work is - an aggregation, not a round trip. Cycled rather than
        #: random so a run is reproducible. Zero (the default) charges
        #: nothing, which is what every test that is not about timing wants.
        self.page_seconds: tuple[float, ...] = ()
        #: what a page over a range wider than WIDE_RANGE_S costs
        self.wide_page_seconds: tuple[float, ...] = ()
        self.simulated_seconds = 0.0
        self._pages = 0
        #: how many pages were charged at the wide rate: a build that is
        #: slicing properly has none
        self.wide_pages = 0
        #: distinct-count probes the vocabulary build asked for, by field
        self.probe_requests: dict[str, int] = {}
        self._range_s: float | None = None

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

    def _rows(self, index: str) -> list[tuple[int, dict]]:
        """Flattened documents of one index, built once. The rows are only
        ever read, except when ``missing`` is set, which copies."""
        rows = self._flat.get(index)
        if rows is None:
            rows = [(i, flatten(d.source)) for i, d in enumerate(self._select(index))]
            self._flat[index] = rows
        if not self.missing:
            return rows
        out = [(i, dict(flat)) for i, flat in rows]
        for f, nth in self.missing.items():
            for i, flat in out:
                if i % nth == 0:
                    flat.pop(f, None)
        return out

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
            elif atype == "composite":
                if self.page_seconds:
                    # charged by how wide the request's range is: the same
                    # page costs 8-35s over a day and 31-297s over thirty
                    wide = (self._range_s or 0.0) > WIDE_RANGE_S
                    cost = self.wide_page_seconds if wide and self.wide_page_seconds \
                        else self.page_seconds
                    self.simulated_seconds += cost[self._pages % len(cost)]
                    self.wide_pages += int(wide)
                    self._pages += 1
                # One source, as the vocabulary read builds it: values in
                # key order, a page at a time, after_key to carry on.
                (src, term), = a["sources"][0].items()
                f = term["terms"]["field"]
                size = a.get("size", 10)
                after = (a.get("after") or {}).get(src)
                counts = {}
                for r in rows:
                    v = r[1].get(f)
                    if v is not None and (after is None or str(v) > str(after)):
                        counts.setdefault(v, []).append(r)
                ordered = sorted(counts.items(), key=lambda kv: str(kv[0]))
                shown = ordered[:size]
                node = {"buckets": [{"key": {src: k}, "doc_count": len(v),
                                     **self._aggs(v, sub, index)} for k, v in shown]}
                if shown:
                    node["after_key"] = {src: shown[-1][0]}
                out[name] = node
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
                if self.page_seconds and name == elastic.VOCABULARY_COUNT_AGG:
                    # the vocabulary's distinct-count probe, charged so the
                    # report shows what it costs rather than implying it is
                    # free (see PROBE_SECONDS)
                    self.simulated_seconds += PROBE_SECONDS
                    self.probe_requests[a["field"]] = \
                        self.probe_requests.get(a["field"], 0) + 1
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

    def search(self, index: str, body: dict, *, ignore_unavailable: bool = False) -> dict:
        """A raw Elasticsearch response for a compiled body. With
        ``ignore_unavailable`` a pattern the engine does not have matches no
        documents instead of failing, as in Elasticsearch."""
        with self.lock:
            self.requests.append({"index": index, "body": body})
        parts = index.split(",")
        if ignore_unavailable:
            parts = [p for p in parts if p in self.indices]
        elif any(p not in self.indices for p in parts):
            raise KeyError(index)
        if len(parts) > 1 and body.get("size", 10):
            raise ValueError("stub: a search over several indices is aggregation-only")
        self._range_s = _query_range_seconds(body)
        rows = [r for p in parts for r in self._rows(p)]
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
                    result = stub.engine.search(
                        params["index"], params.get("body") or {},
                        ignore_unavailable=params.get("ignore_unavailable") is True)
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


def unmarked_cases() -> list[tuple[str, str]]:
    """(phrase, name) for every unmarked job and customer name."""
    return [(p, j) for j, _, p in UNMARKED_JOBS] + [(p, n) for _, n, _, p in UNMARKED_NAMES]


def name_part_leaks(messages: Iterable[str], phrase: str, name: str) -> list[str]:
    """Words of ``name`` still readable in the message that names it (the one
    holding ``phrase``). Stricter than the whole-value check: "Tenant <Org-01>
    Estates" passes that one and fails this one."""
    want = _TOKEN.findall(phrase.lower())
    out: list[str] = []
    for m in messages:
        toks = _TOKEN.findall(m.lower())
        if not any(toks[i:i + len(want)] == want for i in range(len(toks) - len(want) + 1)):
            continue
        out += [w for w in _TOKEN.findall(name.lower()) if len(w) >= 3 and w in toks]
    return out


def _messages(page: Any) -> list[str]:
    hits = (page or {}).get("hits") if isinstance(page, dict) else None
    rows = hits.get("hits", []) if isinstance(hits, dict) else (hits or [])
    return [str((h.get("_source") or {}).get("message", "")) for h in rows if isinstance(h, dict)]


def unmarked_phrases() -> list[str]:
    """The phrase of every unmarked job and name message: each finds its
    message on a worker page without naming anything."""
    return [p for _, _, p in UNMARKED_JOBS] + [p for _, _, _, p in UNMARKED_NAMES]


def build_slice(config: elastic.ElasticConfig, engine: StubEngine,
                covered_from: float, covered_until: float, *,
                over_cap: dict[str, dict] | None = None, probe: bool = True,
                ) -> tuple[elastic.ClusterVocabulary, elastic.VocabularyBuild]:
    """One slice, driven to completion in one call.

    The stub charges simulated seconds per page (``StubEngine.page_seconds``,
    or ``wide_page_seconds`` when the range is wide) and the build's clock
    reads that, so a slice costs what a real one would without the eval
    waiting for it.

    ``over_cap`` is the caller's record of the fields already found too wide
    to read, mutated here as the slice finds more - the broker keeps the
    same record in its vocabulary index. ``probe`` off is the measurement
    switch: the build pages every field straight away, as it did before the
    distinct count existed.
    """
    build = elastic.VocabularyBuild(config, covered_from, covered_until,
                                    clock=lambda: engine.simulated_seconds,
                                    over_cap=over_cap, probe=probe)
    while build.pending():
        vq = build.request()["params"]
        build.feed({"isPartial": False, "isRunning": False,
                    "rawResponse": engine.search(vq["index"], vq["body"],
                                                 ignore_unavailable=vq["ignore_unavailable"])})
        if over_cap is not None:
            for field, count in build.take_dropped().items():
                over_cap[field] = {"count": count, "at": NOW.timestamp()}
    return build.result(), build


def build_vocabulary(config: elastic.ElasticConfig, engine: StubEngine,
                     covered_from: float | None = None, covered_until: float | None = None,
                     *, over_cap: dict[str, dict] | None = None,
                     ) -> tuple[elastic.ClusterVocabulary, elastic.VocabularyBuild]:
    """The whole cover, slice by slice, as the broker builds it over many
    serve-loop iterations - driven to completion in one call here.

    Callers that only want the names known (tests, es-eval sessions outside
    the bridge) get what a finished build holds. ``run_eval`` drives the
    slices itself, because *when* each slice lands is the thing worth
    measuring.
    """
    until = NOW.timestamp() if covered_until is None else covered_until
    held: elastic.ClusterVocabulary | None = None
    last: elastic.VocabularyBuild | None = None
    requests = probes = 0
    # one record for the whole cover, as the broker's index is: a field
    # found over the cap in the first slice is not counted again in the
    # twenty-nine after it. The caller's own dict when it passes one, so a
    # caller can read the decisions out as the broker reads its index.
    seen_over_cap: dict[str, dict] = {} if over_cap is None else over_cap
    if covered_from is not None:
        # an explicit range: one slice of exactly that width (what a top-up
        # over the refresh window is)
        vocab, build = build_slice(config, engine, covered_from, until,
                                   over_cap=seen_over_cap)
        return vocab, build
    while True:
        nxt = elastic.next_vocabulary_slice(config, held, until)
        if nxt is None:
            break
        vocab, last = build_slice(config, engine, *nxt, over_cap=seen_over_cap)
        requests += last.requests
        probes += last.probes
        held = vocab if held is None else held.merge(vocab)
    if held is None or last is None:    # nothing to read
        return build_slice(config, engine, until - config.vocabulary_days * 86400.0, until,
                           over_cap=seen_over_cap)
    last.requests = requests            # the cover's cost, not the last slice's
    last.probes = probes
    last.remembered = {f: int(v["count"]) for f, v in seen_over_cap.items()}
    return held, last


def build_cover(config: elastic.ElasticConfig, engine: StubEngine, *,
                over_cap: dict[str, dict] | None = None,
                ) -> tuple[elastic.ClusterVocabulary, dict]:
    """Every slice of the cover, newest first, with what each one cost.

    The numbers that matter are not the total: they are **what it costs
    before a case can run** (the recent slices) and **the worst single
    slice against the per-slice budget**. The total is reported too, as
    the thing that used to be one unaffordable build.
    """
    until = NOW.timestamp()
    held: elastic.ClusterVocabulary | None = None
    report = {"slices": 0, "requests": 0, "probes": 0, "seconds": 0.0, "max_slice_s": 0.0,
              "serving_after_slices": None, "serving_requests": 0, "serving_seconds": 0.0,
              "budget_s": config.vocabulary_budget_s, "wide_pages": 0, "over_cap": {}}
    seen_over_cap: dict[str, dict] = {} if over_cap is None else over_cap
    before_all = engine.simulated_seconds
    while True:
        nxt = elastic.next_vocabulary_slice(config, held, until)
        if nxt is None:
            break
        before = engine.simulated_seconds
        vocab, build = build_slice(config, engine, *nxt, over_cap=seen_over_cap)
        held = vocab if held is None else held.merge(vocab)
        took = engine.simulated_seconds - before
        report["slices"] += 1
        report["requests"] += build.requests
        report["probes"] += build.probes
        report["over_cap"] = {f: int(v["count"]) for f, v in seen_over_cap.items()}
        report["max_slice_s"] = round(max(report["max_slice_s"], took), 1)
        if report["serving_after_slices"] is None and held.serves(config, until):
            report["serving_after_slices"] = report["slices"]
            report["serving_requests"] = report["requests"]
            report["serving_seconds"] = round(engine.simulated_seconds - before_all, 1)
    report["seconds"] = round(engine.simulated_seconds - before_all, 1)
    report["wide_pages"] = engine.wide_pages
    report["covered_days"] = round(held.covered_days(until), 2) if held else 0.0
    return held, report


def learn_vocabulary(scrubber: elastic.EsScrubber, engine: StubEngine,
                     cluster: str = "stub") -> tuple[dict[str, int], int]:
    """Build and apply in one step, for a caller that only wants the names
    known (tests, es-eval sessions outside the bridge)."""
    vocab, build = build_vocabulary(scrubber.config, engine)
    return (scrubber.apply_vocabulary(cluster, vocab, over_cap=dict(build.remembered)),
            build.requests)


class EngineSession:
    """The two calls ``esbridge.Bridge`` makes on a Kibana session, answered
    from the stub engine. Lets the eval exercise the real Bridge without a
    browser or an HTTP stub."""

    def __init__(self, engine: StubEngine) -> None:
        self.engine = engine

    def probe(self, cluster) -> None:
        return None

    def search(self, cluster, body: dict) -> dict:
        params = body["params"]
        return {"id": "x", "isPartial": False, "isRunning": False,
                "rawResponse": self.engine.search(
                    params["index"], params["body"],
                    ignore_unavailable=params.get("ignore_unavailable", False))}


#: The guessing run the per-case phrase budget exists to stop: 500 queries,
#: each with 8 different candidate names as phrases on the message field.
#: Candidates are invented; one in ten is a phrase that does match a message
#: in the stream fixture (and is not a known value, so the literal gate lets
#: it through), so a refusal that depended on a match would show up as a
#: second refusal shape.
BUDGET_QUERIES = 500


def budget_candidate(i: int) -> str:
    return STREAM_TEXT_PHRASE if i % 10 == 3 else f"Candor{i:05d} Holdings"


def run_phrase_budget_eval(fx: Fixture, *, tier2: str = "none") -> dict:
    """The guessing run on the real Bridge, budget off (before) and at the
    default (after). Counted: phrases that reached Kibana, queries refused
    with phrase_budget and requests they sent, whether the refusal words
    differ between a batch holding a real name and one that does not, and
    that a used phrase and a label-only phrase still run once spent out."""
    cfg_on = stream_name_map()
    cfg_off = dataclasses.replace(cfg_on, phrase_budget=0)
    engine = StubEngine(fx, (STREAM_INDEX,))
    vocab, _b = build_vocabulary(cfg_on, engine)

    def attack(cfg) -> dict:
        case = BridgeCase(cfg, engine, vocab, tier2=tier2)
        r = {"queries": BUDGET_QUERIES, "sent": 0, "phrases_reached": 0,
             "refused_budget": 0, "refused_requests": 0, "other_refusals": 0,
             "messages": set(), "first_refused_at": None}
        for q in range(BUDGET_QUERIES):
            phrases = [budget_candidate(q * 8 + k) for k in range(8)]
            before = len(engine.requests)
            _out, refused, _dt, _c = case.call({
                "index": STREAM_INDEX, "time_range": STREAM_RANGE, "size": 0,
                "aggs": {"g": {"type": "filters", "filters": {
                    f"p{k}": [{"field": "message", "op": "phrase", "value": p}]
                    for k, p in enumerate(phrases)}}}})
            if refused is None:
                r["sent"] += 1
                r["phrases_reached"] += 8
            elif refused.code == "phrase_budget":
                r["refused_budget"] += 1
                r["refused_requests"] += len(engine.requests) - before
                # the words minus the counts: one shape, whatever the batch held
                r["messages"].add(re.sub(r"\d+", "N", refused.message))
                r["first_refused_at"] = r["first_refused_at"] if r["first_refused_at"] \
                    is not None else q
            else:
                r["other_refusals"] += 1
        r["report"] = case.scrubber.phrase_report()
        r["message_shapes"] = len(r.pop("messages"))
        # spent out: a phrase already used, and a label-only phrase, still run
        used = budget_candidate(0)
        _o, refused, _dt, _c = case.call({"index": STREAM_INDEX, "time_range": STREAM_RANGE,
                                          "size": 0, "filters": [
                                              {"field": "message", "op": "phrase", "value": used}]})
        r["reuse_runs"] = refused is None
        label = case.scrubber.known.get(jsonscrub_norm(STREAM_JOB))
        case.scrubber.shown.add(label)      # as if a page had shown it
        _o, refused, _dt, _c = case.call({"index": STREAM_INDEX, "time_range": STREAM_RANGE,
                                          "size": 0, "filters": [
                                              {"field": "message", "op": "phrase", "value": label}]})
        r["label_only_runs"] = refused is None
        r["case_dir"] = str(case.save())
        return r

    return {"budget": cfg_on.phrase_budget, "before": attack(cfg_off), "after": attack(cfg_on)}


def run_review_eval(cfg: elastic.ElasticConfig, engine: StubEngine,
                    vocab: elastic.ClusterVocabulary, fx: Fixture, guessing_dir: str, *,
                    tier2: str) -> dict:
    """es-review over two cases: the guessing run from the phrase-budget
    gate, and an ordinary investigation on the fixture - a case about one
    tenant that pages its events, aggregates servers and levels, filters by
    a server label it was shown, searches two error fragments and counts.
    The first must be flagged, the second must not, and a directory with no
    log must be reported as no review rather than as clean.
    """
    from . import esreview

    cfg = dataclasses.replace(
        cfg, clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))
    case = BridgeCase(cfg, engine, vocab, tier2=tier2)
    tenant = fx.tenants[0]
    label = case.scrubber.seed(tenant.name)
    tr = {"gte": "now-6h", "lte": "now"}
    by_case = [{"field": "labels.tenant_name", "op": "eq", "value": label}]
    calls = [
        {"index": "logs-app-*", "time_range": tr, "size": 20, "filters": by_case},
        {"index": "logs-app-*", "time_range": tr, "size": 0, "filters": by_case,
         "aggs": {"srv": {"type": "terms", "field": "agent.name", "size": 10},
                  "lvl": {"type": "terms", "field": "log.level", "size": 10}}},
        {"index": "logs-app-*", "time_range": tr, "size": 10,
         "filters": [{"field": "message", "op": "phrase", "value": "throttled by sharepoint"}]},
        {"index": "logs-worker-*", "time_range": tr, "size": 10,
         "filters": [{"field": "message", "op": "phrase", "value": "finished with warnings"}]},
        {"index": "logs-app-*", "time_range": tr, "size": 0, "filters": by_case,
         "aggs": {"h": {"type": "date_histogram", "field": cfg.time_field, "interval": "1h"}}},
    ]
    refusals = 0
    for q in calls:
        out, refused, _dt, _c = case.call(q)
        refusals += refused is not None
        if out is not None and "srv" in (out.get("aggregations") or {}):
            # a server label off the page, used in the next query
            keys = [b["key"] for b in out["aggregations"]["srv"]["buckets"]]
            if keys:
                _o, refused2, _dt, _c = case.call({
                    "index": "logs-app-*", "time_range": tr, "size": 0,
                    "filters": [{"field": "agent.name", "op": "eq", "value": keys[0]}]})
                refusals += refused2 is not None
    ordinary_dir = case.save()
    ordinary = esreview.review(ordinary_dir)
    guessing = esreview.review(guessing_dir)
    missing = esreview.review(Path(tempfile.mkdtemp(prefix="hider-es-eval-nolog-")))
    # the default output carries no value from either case
    blob = "\n".join(esreview.format_review(ordinary) + esreview.format_review(guessing))
    values_leaked = [v for v in (tenant.name, *(d.source.get("job", {}).get("name", "")
                                                 for d in fx.docs[:50]))
                     if v and v in blob]
    return {
        "ordinary": {"queries": ordinary["numbers"].get("queries"), "refusals": refusals,
                     "verdict": ordinary["verdict"], "flagged": ordinary["flagged"],
                     "log_status": ordinary["log_status"]},
        "guessing": {"queries": guessing["numbers"].get("queries"),
                     "verdict": guessing["verdict"], "flagged": guessing["flagged"],
                     "log_status": guessing["log_status"],
                     "zero_hit": guessing["numbers"].get("text_phrases_zero_hit")},
        "missing": {"log_status": missing["log_status"], "verdict": missing["verdict"]},
        "values_in_default_output": len(values_leaked),
    }


class BridgeCase:
    """One case on the real :class:`esbridge.Bridge`, over the stub engine,
    with a built vocabulary held by the bridge's index - the live order of
    compile, apply, gate again, send. Same ``call`` shape as :class:`Session`."""

    def __init__(self, config: elastic.ElasticConfig, engine: StubEngine,
                 vocabulary: elastic.ClusterVocabulary, *, tier2: str) -> None:
        from . import esbridge

        index = elastic.VocabularyIndex(None)
        index.put("stub", vocabulary)
        self.scrubber = elastic.EsScrubber(config, tier2=tier2)
        #: a case directory of its own, with the decision log a real case
        #: writes, so es-review can read the case back
        self.directory = Path(tempfile.mkdtemp(prefix="hider-es-eval-case-"))
        self.bridge = esbridge.Bridge(config, self.scrubber, EngineSession(engine),
                                      log_path=self.directory / "decisions.jsonl", index=index)

    def save(self) -> Path:
        self.scrubber.save_session(self.directory)
        return self.directory

    def call(self, query: dict) -> tuple[dict | None, elastic.Refused | None, float, None]:
        from . import esbridge

        t0 = time.perf_counter()
        saved = esbridge.clock
        esbridge.clock = lambda: NOW.timestamp()
        try:
            return self.bridge.run("stub", query).output, None, time.perf_counter() - t0, None
        except elastic.Refused as e:
            return None, e, time.perf_counter() - t0, None
        finally:
            esbridge.clock = saved


def cold_bridge_refusal(config: elastic.ElasticConfig, engine: StubEngine, *,
                        tier2: str = "none") -> dict:
    """What a case gets on a bridge whose vocabulary has not finished
    building: a refusal with its own code, and no page."""
    from . import esbridge

    cfg = dataclasses.replace(
        config, clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))
    bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2),
                             EngineSession(engine), index=elastic.VocabularyIndex(None))
    query = {"index": "logs-worker-*", "time_range": WINDOW_CASE_RANGE, "size": 20,
             "filters": [{"field": "message", "op": "phrase", "value": WINDOW_CASE_PHRASE}]}
    try:
        out = bridge.run("stub", query)
        return {"refused": None, "shown": bool(out.hits_shown)}
    except elastic.Refused as e:
        return {"refused": e.code, "shown": False, "names_a_rule": "vocabulary" in e.message}


class SteppedSearchTransport:
    """Kibana's async-search protocol over the stub engine, with a page
    that takes **many polls** to finish.

    The broker's serve loop owns the browser, so what matters is not how
    long a page takes but how long one *step* takes. This transport makes
    the difference visible: a submit returns ``isRunning`` at once, each
    poll returns ``isRunning`` until the page's simulated seconds are up,
    and only then does the result come back. A broker that ran a page to
    completion inside one serve-loop iteration cannot answer anything for
    the length of the page; one that submits and polls across iterations
    answers between every step.
    """

    #: how much of a page's simulated cost one poll gets through
    POLL_STEP_S = 5.0

    def __init__(self, engine: StubEngine) -> None:
        self.engine = engine
        self.closed = False
        self.searches: dict[str, dict] = {}
        self._n = 0
        #: every (method, path) the broker made, for the step count
        self.calls: list[tuple[str, str]] = []

    def start(self) -> None:
        return None

    def login(self, cluster, timeout: float = 0.0) -> bool:
        return True

    def close(self) -> None:
        self.closed = True

    def request(self, cluster, method: str, path: str, body: dict | None = None,
                *, navigate: bool = False):
        from . import esbridge

        self.calls.append((method, path))
        url = cluster.kibana + path
        data = self._dispatch(method, path, body)
        return esbridge.Reply(200, url, "application/json", json.dumps(data), False)

    def _dispatch(self, method: str, path: str, body: dict | None) -> dict:
        from . import esbridge

        if method == "DELETE":
            self.searches.pop(path.rsplit("/", 1)[-1], None)
            return {"ok": True}
        if path == esbridge.SEARCH_PATH:
            # Run it now and charge it now; then hand it back over as many
            # polls as its cost takes, which is what a real async search
            # does and what the step count has to see.
            params = (body or {}).get("params", {})
            before = self.engine.simulated_seconds
            result = self.engine.search(params.get("index", ""), params.get("body", {}),
                                        ignore_unavailable=params.get("ignore_unavailable", False))
            cost = self.engine.simulated_seconds - before
            self._n += 1
            sid = f"stub-search-{self._n}"
            self.searches[sid] = {
                "result": result,
                "polls": max(1, int(math.ceil(cost / self.POLL_STEP_S))),
            }
            return {"id": sid, "isRunning": True, "isPartial": True}
        sid = path.rsplit("/", 1)[-1]
        held = self.searches.get(sid)
        if held is None:
            return {"id": sid, "isRunning": False, "isPartial": False,
                    "rawResponse": {"hits": {"total": {"value": 0}, "hits": []}}}
        held["polls"] -= 1
        if held["polls"] > 0:
            return {"id": sid, "isRunning": True, "isPartial": True}
        return {"id": sid, "isRunning": False, "isPartial": False,
                "rawResponse": held["result"]}


def run_over_cap_eval(fx: Fixture, *, tier2: str = "none") -> dict:
    """An identifier field with more distinct values than ``vocabulary.max``,
    in the default field set, on the real broker.

    The shape that stopped the build finishing: with no ``vocabulary``
    section every learnable field is read, and one per-request reference
    with a fresh value on nearly every document was paged to the cap and
    only then refused - so the slice failed, was retried, failed the same
    way, and no case ever ran. What this measures:

    * **what the oversized field costs**, before and after. "Before" is the
      build with ``probe=False`` (the measurement switch, set by nothing in
      the live path) on the map that still refuses, which is what every map
      did before the rule: the requests spent paging that field to the cap,
      and then the slice refused - once a slice, every slice, for ever.
      "After" is one distinct count, once for the whole cover;
    * **the first case is still served** - on a cover built with the field
      left out, about a day the first slice does not reach, with tier 2
      **off**, so a name hidden in message text can only have come from the
      vocabulary;
    * **the report names the field**, with its count, on the VOCAB line and
      in the bridge's vocabulary report - the only place a user is told
      that field's values stay readable in message text;
    * **a map that lists the field itself is still refused**, with a
      message naming it and the two ways out.
    """
    from . import esbridge

    cluster = elastic.Cluster("stub", "https://kibana-stub.example.net")
    cfg = over_cap_map(listed=False)
    engine = StubEngine(fx, (OVER_CAP_INDEX,))
    engine.page_seconds = PAGE_SECONDS
    engine.wide_page_seconds = WIDE_PAGE_SECONDS
    out: dict = {
        "field": OVER_CAP_FIELD, "max": cfg.vocabulary_max, "distinct": OVER_CAP_REFS,
        "fields_default": [r.pattern for r in cfg.vocabulary_rules],
        "before_requests": 0, "before_refused": None, "before_pages_at_default_cap": 0,
        "after_requests": 0, "after_probes": 0, "after_probes_all": 0, "slices": 0,
        "left_out": {}, "names_read": {}, "logged_values": 0,
        "case_shown": False, "case_refused": None, "case_leaks": [], "case_part_leak": False,
        "readable_without_vocabulary": False,
        "reported_on_vocab_line": False, "vocab_line": "",
        "listed_refused": None, "listed_message_names_field": False,
        "listed_message_says_how": False,
    }
    # -- before: no distinct count, so the field is paged to the cap -------
    # on the map that still refuses, which is what every map did before the
    # rule: page to the cap, then abandon the slice
    build = elastic.VocabularyBuild(over_cap_map(listed=True),
                                    NOW.timestamp() - 86400.0, NOW.timestamp(),
                                    clock=lambda: engine.simulated_seconds, probe=False)
    try:
        while build.pending():
            vq = build.request()["params"]
            if build.field == OVER_CAP_FIELD:
                out["before_requests"] += 1
            build.feed({"isPartial": False, "isRunning": False,
                        "rawResponse": engine.search(vq["index"], vq["body"],
                                                     ignore_unavailable=True)})
    except elastic.Refused as e:
        out["before_refused"] = e.code
    # the same field at the default cap, which is what a site actually runs
    out["before_pages_at_default_cap"] = \
        elastic.DEFAULT_VOCABULARY_MAX // elastic.VOCABULARY_PAGE + 1

    # -- after: the real broker, a serve-loop step at a time ---------------
    transport = SteppedSearchTransport(engine)
    tmp = Path(tempfile.mkdtemp(prefix="hider-es-eval-overcap-"))
    saved_clock = esbridge.clock
    esbridge.clock = lambda: NOW.timestamp()
    before_requests = len(engine.requests)
    query = {"index": OVER_CAP_INDEX, "time_range": OVER_CAP_RANGE, "size": 20,
             "filters": [{"field": "message", "op": "phrase", "value": OVER_CAP_PHRASE}]}
    try:
        broker = esbridge.Broker(cfg, lambda: transport, poll_interval=0.0, sessions_dir=tmp)
        broker.open()
        broker.start_vocabulary(cluster)
        steps = 0
        while steps < 4000 and broker.pump_vocabulary():
            steps += 1
            held = broker.vocabulary.get("stub")
            if held is not None and held.serves(cfg, NOW.timestamp()):
                break
        out["after_requests"] = len(engine.requests) - before_requests
        out["slices"] = sum(1 for r in broker._build_log if r["vocabulary"] == "slice")
        # on the oversized field: one count, for the whole cover. The rest
        # are the kept fields' own counts, one each per slice.
        out["after_probes"] = engine.probe_requests.get(OVER_CAP_FIELD, 0)
        out["after_probes_all"] = sum(engine.probe_requests.values())
        out["left_out"] = {f: int(v["count"]) for f, v in
                           broker.vocabulary.over_cap_fields("stub", NOW.timestamp()).items()}
        # the decision log carries the field name and the count, never a value
        rows = [json.dumps(r, sort_keys=True) for r in broker._build_log]
        out["logged_values"] = sum(1 for r in rows if OVER_CAP_TENANT in r
                                   or over_cap_ref(0) in r)
        bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2),
                                 EngineSession(engine), index=broker.vocabulary)
        try:
            page = bridge.run("stub", query)
            out["case_shown"] = bool(page.hits_shown)
            out["case_leaks"] = _leaks(page.output, OVER_CAP_TRUTH)
            out["case_part_leak"] = bool(name_part_leaks(
                _messages(page.output), OVER_CAP_PHRASE, OVER_CAP_TENANT))
        except elastic.Refused as e:
            out["case_refused"] = e.code
        report = bridge.vocabulary.get("stub") or {}
        out["names_read"] = dict(report.get("fields") or {})
        line = esbridge.vocabulary_line(report) or ""
        out["vocab_line"] = line
        out["reported_on_vocab_line"] = (
            OVER_CAP_FIELD in line and str(OVER_CAP_REFS) in line
            and "OVER CAP" in line and OVER_CAP_TENANT not in line)
    finally:
        esbridge.clock = saved_clock
        shutil.rmtree(tmp, ignore_errors=True)

    # The same page with no vocabulary at all: the name is readable, which
    # is what makes "the vocabulary hid it" a measurement rather than a
    # claim (tier 2 is off, and nothing else has a shape for the name).
    bare = Session(cfg, engine, tier2=tier2, vocabulary=None)
    page, _refused, _dt, _c = bare.call(query)
    out["readable_without_vocabulary"] = bool(page is not None and _leaks(page, OVER_CAP_TRUTH))

    # -- a map that lists the field itself: refused, as before -------------
    listed = over_cap_map(listed=True)
    try:
        build_slice(listed, engine, NOW.timestamp() - 86400.0, NOW.timestamp())
    except elastic.Refused as e:
        out["listed_refused"] = e.code
        out["listed_message_names_field"] = OVER_CAP_FIELD in e.message
        out["listed_message_says_how"] = ("vocabulary.fields" in e.message
                                          and "vocabulary.max" in e.message)
    return out


def run_slice_eval(config: elastic.ElasticConfig, fx: Fixture, engine: StubEngine, *,
                   tier2: str = "none") -> dict:
    """The sliced build on the real broker, one serve-loop step at a time.

    What this measures, and why each number is here:

    * **a case is served from the recent slices while the older ones are
      still being read** - the whole reason for slicing. Before it, a case
      waited for the whole of ``vocabulary.days``, which on a real estate
      (12 name fields, ~10,000 names each, 31-297s a page over 30 days) is
      hours, so every case was refused and the bridge looked broken;
    * **requests and simulated seconds to the first case served**, which is
      what the person who signed in actually waits for;
    * **no serve-loop step runs long**: a ping sent after every step is
      answered, and no step costs more than one poll interval, so es-login
      polling the progress and es-logout asking it to stop both get an
      answer mid-build.
    """
    from . import esbridge

    cluster = elastic.Cluster("stub", "https://kibana-stub.example.net")
    cfg = dataclasses.replace(config, clusters=(cluster,))
    transport = SteppedSearchTransport(engine)
    tmp = Path(tempfile.mkdtemp(prefix="hider-es-eval-slices-"))
    before_requests = len(engine.requests)
    before_seconds = engine.simulated_seconds
    saved_clock = esbridge.clock
    esbridge.clock = lambda: NOW.timestamp()
    out: dict = {"steps": 0, "slices_at_first_case": 0, "max_step_s": 0.0,
                 "pings": 0, "pings_answered": 0, "poll_interval_s": esbridge.POLL_INTERVAL_S,
                 "case_shown": False, "case_refused": None, "case_leaks": [],
                 "case_part_leak": False, "still_building_older": False,
                 "refused_before_cover": None, "requests_to_first_case": 0,
                 "seconds_to_first_case": 0.0, "covered_days_at_first_case": 0.0,
                 "wide_pages": 0}
    query = {"index": "logs-worker-*", "time_range": WINDOW_CASE_RANGE, "size": 20,
             "filters": [{"field": "message", "op": "phrase", "value": WINDOW_CASE_PHRASE}]}
    try:
        broker = esbridge.Broker(cfg, lambda: transport, poll_interval=0.0, sessions_dir=tmp)
        broker.open()
        broker.start_vocabulary(cluster)

        def case() -> tuple[dict | None, str | None]:
            bridge = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2=tier2),
                                     EngineSession(engine), index=broker.vocabulary)
            try:
                return bridge.run("stub", query), None
            except elastic.Refused as e:
                return None, e.code

        # before any slice is in, a case is refused with its own code
        _page, out["refused_before_cover"] = case()
        while out["steps"] < 2000:
            t0 = time.perf_counter()
            worked = broker.pump_vocabulary()
            out["max_step_s"] = round(max(out["max_step_s"],
                                          time.perf_counter() - t0), 4)
            if not worked:
                break
            out["steps"] += 1
            # a ping between every step: this is what es-login's progress
            # poll and es-logout's stop are, and both must be answered
            out["pings"] += 1
            out["pings_answered"] += int(broker.handle(
                {"schema": esbridge.BROKER_SCHEMA, "op": "ping"}).get("ok") is True)
            held = broker.vocabulary.get("stub")
            if held is not None and held.serves(cfg, NOW.timestamp()):
                break
        held = broker.vocabulary.get("stub")
        out["requests_to_first_case"] = len(engine.requests) - before_requests
        out["seconds_to_first_case"] = round(engine.simulated_seconds - before_seconds, 1)
        out["covered_days_at_first_case"] = round(held.covered_days(NOW.timestamp()), 2) \
            if held else 0.0
        out["slices_at_first_case"] = sum(1 for r in broker._build_log if r["vocabulary"] == "slice")
        # the older slices are not done: the case below is served from the
        # recent ones while the build carries on
        out["still_building_older"] = elastic.next_vocabulary_slice(
            cfg, held, NOW.timestamp()) is not None
        page, refused = case()
        out["case_refused"] = refused
        if page is not None and page.output is not None:
            out["case_shown"] = bool(page.hits_shown)
            out["case_leaks"] = _leaks(page.output, fx.truth)
            out["case_part_leak"] = bool(name_part_leaks(
                _messages(page.output), WINDOW_CASE_PHRASE, WINDOW_CASE_JOB))
        # and the bridge still answers after the case, with the build live
        out["pings"] += 1
        out["pings_answered"] += int(broker.handle(
            {"schema": esbridge.BROKER_SCHEMA, "op": "ping"}).get("ok") is True)
        out["wide_pages"] = engine.wide_pages
    finally:
        esbridge.clock = saved_clock
        shutil.rmtree(tmp, ignore_errors=True)
    return out


class Session:
    """Compile, run against the engine, scrub: one tool call as the bridge will do it."""

    def __init__(self, config: elastic.ElasticConfig, engine: StubEngine, *, tier2: str,
                 vocabulary: elastic.ClusterVocabulary | None = None) -> None:
        self.cfg = config
        self.engine = engine
        self.scrubber = elastic.EsScrubber(config, tier2=tier2)
        self.log: list[dict] = []
        #: the cluster vocabulary this case starts from, as the bridge hands
        #: it over: already built, applied locally, no request of its own
        self.vocabulary = vocabulary
        self.vocabulary_applied = 0

    def call(self, query: dict) -> tuple[dict | None, elastic.Refused | None, float, esquery.Compiled | None]:
        t0 = time.perf_counter()
        compiled = None
        try:
            compiled = esquery.compile_query(query, self.cfg, self.scrubber,
                                             now=NOW.timestamp())
            if self.vocabulary is not None and not self.scrubber.vocabulary_applied("stub"):
                self.scrubber.apply_vocabulary("stub", self.vocabulary)
                self.vocabulary_applied += 1
            # as the bridge does: a query about to be sent spends its phrases
            self.scrubber.spend_phrases(compiled.new_phrases)
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
    # the fixture sits at NOW, so the build reads the range around NOW; see
    # esbridge.clock. Against a real cluster this is the wall clock.
    esbridge.clock = NOW.timestamp
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
        # Sign in, which starts the one vocabulary build for this bridge,
        # then wait for it as the operator does. Cases opened before it is
        # ready are refused; that refusal is measured offline above.
        # Wait for the **whole** cover here, not just the recent slices a
        # case needs: this section measures the MCP layer, and a build
        # still running in the background would put its own Kibana calls
        # in the middle of the transport-rejection count. That a case runs
        # off the recent slices while the rest builds is measured by
        # run_slice_eval, where it is the point rather than a confounder.
        control.call("vocabulary", cluster="stub", build=True)
        vocab_state: dict = {}
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            vocab_state = control.call("vocabulary", cluster="stub")["vocabulary"]
            if vocab_state.get("state") in ("ready", "top_up_due", "stale"):
                break
            time.sleep(0.005)
        vocabulary_ready = vocab_state.get("state") in ("ready", "top_up_due", "stale")
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
        protocol_ok = (protocol_ok and seeded_ok and bool(schema) and vocabulary_ready
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
        check(tool("es_count", {"index": "logs-app-*", "time_range": tr, "filters": by_case}),
              want)
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

        # -- a fresh case: its first calls are pages with an unmarked job name
        fresh_open = control.call("open_case", case="es-eval-fresh", tier2=tier2, terms=[])
        fresh_client = _McpClient(fresh_open["url"], fresh_open["token"])
        fresh = {"cases": 0, "shown": 0, "part_leaks": 0}
        for phrase, name in unmarked_cases():
            payload, code = fresh_client.tool("es_search", {
                "index": "logs-worker-*", "time_range": tr, "size": 20,
                "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
            fresh["cases"] += 1
            fresh["part_leaks"] += bool(name_part_leaks(_messages(payload), phrase, name))
            fresh["shown"] += bool(payload) and (payload.get("hits_total") or {}).get("value", 0) > 0
        control.call("close_case", token=fresh_open["token"])
        c.received.extend(fresh_client.received)

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
        esbridge.clock = time.time

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
        "fresh_case": fresh,
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
        "mcp_no_leaks": m["leaks"] == 0 and m["fresh_case"]["part_leaks"] == 0,
        "mcp_fresh_case_shown": m["fresh_case"]["shown"] == m["fresh_case"]["cases"]
        == len(unmarked_phrases()),
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


def run_ordinary_word_eval(cfg: elastic.ElasticConfig, engine: StubEngine,
                           vocab: elastic.ClusterVocabulary, *, tier2: str,
                           timings: list[float]) -> dict:
    """A job name that is an ordinary word, before and after the rule.

    Two pages, in order: one showing the names in their own ``job.name``
    fields, then one of ordinary messages that use the same words as
    English. Run twice - once with ``ordinary_words_case_wide`` (the old
    behaviour, kept as a measurement switch) and once without - so the
    before and after figures come from the same documents.

    Also checked: the word is still hidden in the text of the document
    whose own field holds it, the label still filters, and the second page
    scrubs identically whether or not the first page came before it, which
    is the property that was actually broken.
    """
    out: dict = {"words": len(ORDINARY_WORD_JOBS), "labelled_in_field": 0,
                 "swept_before": 0, "swept_after": 0, "readable_after": 0,
                 "own_doc_hidden": 0, "filter_by_label": False, "deterministic": False}
    own_q = {"index": "logs-app-*", "time_range": ORDINARY_RANGE, "size": 20,
             "filters": [{"field": "message", "op": "phrase", "value": ORDINARY_OWN_PHRASE}]}
    text_q = {"index": "logs-worker-*", "time_range": ORDINARY_RANGE, "size": 20,
              "filters": [{"field": "message", "op": "phrase", "value": ORDINARY_TEXT_PHRASE}]}

    def pages(case_wide: bool) -> tuple[list[str], list[str], elastic.EsScrubber]:
        sess = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
        sess.scrubber.ordinary_words_case_wide = case_wide
        own, _refused, dt, _c = sess.call(own_q)
        timings.append(dt)
        text, _refused, dt, _c = sess.call(text_q)
        timings.append(dt)
        return _messages(own), _messages(text), sess.scrubber

    # before: the word is harvested from its own field and swept everywhere
    _own_before, text_before, _s = pages(True)
    out["swept_before"] = sum(1 for job, _m in ORDINARY_MESSAGES
                              if not any(job in m for m in text_before))
    # after: labelled in its own field, ordinary English everywhere else
    own_after, text_after, s = pages(False)
    out["swept_after"] = sum(1 for job, _m in ORDINARY_MESSAGES
                             if not any(job in m for m in text_after))
    out["readable_after"] = len(ORDINARY_MESSAGES) - out["swept_after"]
    out["labelled_in_field"] = sum(1 for job in ORDINARY_WORD_JOBS
                                   if s.known.get(jsonscrub_norm(job)) is not None)
    out["label_count"] = len(s.readable_words)
    # the owning document still hides the name in its own text
    out["own_doc_hidden"] = sum(1 for job in ORDINARY_WORD_JOBS
                                if not any(job in m for m in own_after))
    # the label still filters, on its own field
    label = s.known.get(jsonscrub_norm(ORDINARY_WORD_JOBS[0]))
    if label:
        # the filtering case has to be shown the label first (see the
        # label-guessing rule), so it runs the own-field page and then
        # filters by what that page showed it
        hit2, refused2 = _label_filter(cfg, engine, vocab, tier2, label, timings)
        out["filter_by_label"] = refused2 is None and hit2 is not None and (
            (hit2["hits"]["total"] or {}).get("value", 0) == 1)
    # the second page reads the same with no first page at all
    alone = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    page, _refused, dt, _c = alone.call(text_q)
    timings.append(dt)
    out["deterministic"] = _messages(page) == text_after
    return out


def _label_filter(cfg, engine, vocab, tier2, label, timings):
    """Filter by a label on the case that was shown it: the own-field page
    first, then the filter."""
    sess = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    _own, _refused, dt, _c = sess.call({
        "index": "logs-app-*", "time_range": ORDINARY_RANGE, "size": 20,
        "filters": [{"field": "message", "op": "phrase", "value": ORDINARY_OWN_PHRASE}]})
    timings.append(dt)
    out, refused, dt, _c = sess.call({
        "index": "logs-app-*", "time_range": ORDINARY_RANGE, "size": 5,
        "filters": [{"field": "job.name", "op": "eq", "value": label}]})
    timings.append(dt)
    return out, refused


def jsonscrub_norm(value: str) -> str:
    from . import jsonscrub

    return jsonscrub._norm(value)


def run_guess_eval(cfg: elastic.ElasticConfig, engine: StubEngine,
                   vocab: elastic.ClusterVocabulary, *, tier2: str,
                   timings: list[float]) -> dict:
    """Label guessing on the estate: every guess refused, a shown label kept.

    With a cluster vocabulary applied a case holds a label for every name
    on the estate, so ``<Org-77>`` and its neighbours are live references
    to customers the case has never seen. Guessing them would let a case
    reach and count the whole cluster - no name revealed, every customer
    countable. A label is usable only after the case has been shown it.

    Both halves matter and are measured together: the guesses are refused
    (and with the same code and message as a label that does not exist, so
    a refusal is not an oracle), and a label the case *was* shown still
    works in the next query, or the rule would simply have broken the
    tool.
    """
    out = {"guesses": 0, "refused": 0, "codes": {}, "resolvable_in_mapping": 0,
           "same_message_as_dead": False, "requests": 0,
           "shown_label_works": False, "shown_labels_before_page": 0,
           "logged_label_never_value": True}
    sess = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    s = sess.scrubber
    # The dangerous state, and the ordinary one: the cluster vocabulary is
    # applied, so this case holds a label for every name on the estate
    # before it has been shown a single page.
    s.apply_vocabulary("stub", vocab)
    tr = {"gte": "now-6h", "lte": "now"}
    before_requests = len(engine.requests)

    # A fresh case: nothing seeded, no page yet. Guess a hundred low
    # numbers - on this estate most of them are live labels.
    for n in range(1, 101):
        label = f"<Org-{n:02d}>"
        _out, refused, dt, _c = sess.call({
            "index": "logs-app-*", "time_range": tr, "size": 5,
            "filters": [{"field": "labels.tenant_name", "op": "eq", "value": label}]})
        timings.append(dt)
        out["guesses"] += 1
        out["resolvable_in_mapping"] += int(s.resolve_label(label) is not None)
        if refused is None:
            continue
        out["refused"] += 1
        out["codes"][refused.code] = out["codes"].get(refused.code, 0) + 1
        out["logged_label_never_value"] = out["logged_label_never_value"] and (
            refused.label == label and not any(
                v and v in (refused.message or "") for v in s.mapping.values()))
    # a label that does not exist at all must read the same way
    _out, dead, dt, _c = sess.call({
        "index": "logs-app-*", "time_range": tr, "size": 5,
        "filters": [{"field": "labels.tenant_name", "op": "eq", "value": "<Org-999977>"}]})
    timings.append(dt)
    live = sess.log[0]
    out["same_message_as_dead"] = bool(dead) and dead.code == "unknown_label"
    out["requests"] = len(engine.requests) - before_requests   # no guess reached Kibana
    out["shown_labels_before_page"] = len(s.shown)

    # Now show the case a page, and use a label off it in the next query.
    page, refused, dt, _c = sess.call({
        "index": "logs-app-*", "time_range": tr, "size": 5})
    timings.append(dt)
    shown = sorted(lab for lab in s.shown if s.types.get(lab) == "ORG_NAME")
    if shown:
        hit, refused2, dt, _c = sess.call({
            "index": "logs-app-*", "time_range": tr, "size": 5,
            "filters": [{"field": "labels.tenant_name", "op": "eq", "value": shown[0]}]})
        timings.append(dt)
        out["shown_label_works"] = refused2 is None and hit is not None and (
            (hit["hits"]["total"] or {}).get("value", 0) > 0)
    out["shown_after_page"] = len(s.shown)
    del live
    return out


def run_estate_eval(cfg: elastic.ElasticConfig, engine: StubEngine,
                    vocab: elastic.ClusterVocabulary, *, tier2: str,
                    timings: list[float]) -> dict:
    """The realistic estate, measured per shape class.

    For each class: how many of its names the skip rules drop and why, and
    how many of its free-text mentions are still readable after the
    vocabulary and the scrubber. One page per class rather than one per
    name - the mentions of a class share a phrase, so twelve of them come
    back on one page. That is what keeps the whole section at fourteen
    queries instead of a hundred and forty-four, and the eval's runtime
    inside a minute of where it was.

    Each class gets a **fresh** session: nothing seeded, nothing harvested,
    and every mentioned name's own field record days outside the window the
    page asks for. So what hides a name here is the cluster vocabulary and
    nothing else.
    """
    by_class = estate_names()
    mentions: dict[str, list[tuple[str, str, str]]] = {k: [] for _, k in estate_classes()}
    for key, name, message, phrase in estate_mentions():
        mentions[key].append((name, message, phrase))

    classes: list[dict] = []
    unexpected: list[str] = []
    declared: list[str] = []
    shapes = {k: what for k, _, what in
              (*ESTATE_TENANT_SHAPES, *ESTATE_JOB_SHAPES, *ESTATE_RESOURCE_SHAPES)}
    for kind, key in estate_classes():
        names = by_class[key]
        skipped: dict[str, int] = {}
        for n in names:
            why = elastic.EsScrubber.vocabulary_skip(n)
            if why:
                skipped[why] = skipped.get(why, 0) + 1
        row = {"kind": kind, "class": key, "shape": shapes[key], "names": len(names),
               "distinct": len(set(names)), "skipped": skipped,
               "skipped_total": sum(skipped.values()),
               "mentions": len(mentions[key]), "shown": 0, "readable": 0,
               "part_readable": 0, "declared_miss": 0, "unexpected": []}
        sess = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
        phrase = mentions[key][0][2]
        out, refused, dt, _ = sess.call({
            "index": "logs-worker-*", "time_range": ESTATE_MENTION_RANGE, "size": 20,
            "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
        timings.append(dt)
        row["refused"] = refused.code if refused else None
        msgs = _messages(out) if out is not None else []
        row["shown"] = len(msgs)
        page = " ".join(msgs)
        for name, _message, _p in mentions[key]:
            whole = name in page
            parts = bool(name_part_leaks(msgs, phrase, name))
            if not (whole or parts):
                continue
            row["readable"] += int(whole)
            row["part_readable"] += int(parts and not whole)
            # the one declared miss: a one-word name the skip rules drop is
            # never made vocabulary, so it stays readable in message text
            if whole and len(name.split()) == 1 and elastic.EsScrubber.vocabulary_skip(name):
                row["declared_miss"] += 1
                declared.append(name)
            else:
                row["unexpected"].append(name)
                unexpected.append(name)
        classes.append(row)

    # Every level and outcome spelling the estate logs, through the keep
    # pass: as hit values and as bucket keys, byte for byte, with the
    # measured skew intact.
    levels = {"bucket_keys": 0, "kept": [], "changed": [], "top_ratio": 0.0,
              "outcome_ratio": 0.0, "hit_spellings": 0}
    ls = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    out, refused, dt, _ = ls.call({
        "index": "logs-worker-*", "time_range": ESTATE_MENTION_RANGE, "size": 0,
        "aggs": {"levels": {"type": "terms", "field": "log.level", "size": 40},
                 "outcomes": {"type": "terms", "field": "event.outcome", "size": 10}}})
    timings.append(dt)
    if out is not None:
        buckets = {a: {str(b["key"]): b["doc_count"] for b in out["aggregations"][a]["buckets"]}
                   for a in ("levels", "outcomes")}
        keys = set(buckets["levels"]) | set(buckets["outcomes"])
        want = (*ESTATE_LEVEL_SPELLINGS, *ESTATE_OUTCOME_SPELLINGS)
        levels["bucket_keys"] = len(keys)
        levels["kept"] = sorted(v for v in want if v in keys)
        levels["changed"] = sorted(set(want) - keys)
        counts = sorted(buckets["levels"].values(), reverse=True)
        if len(counts) > 1 and counts[1]:
            levels["top_ratio"] = round(counts[0] / counts[1], 1)
        oc = buckets["outcomes"]
        if oc.get("failure"):
            levels["outcome_ratio"] = round(oc.get("success", 0) / oc["failure"], 1)
    # and as hit values, where a keep field reaches Claude the other way
    out, refused, dt, _ = ls.call({
        "index": "logs-worker-*", "time_range": ESTATE_MENTION_RANGE, "size": 100,
        "filters": [{"field": "message", "op": "phrase", "value": "Worker heartbeat"}]})
    timings.append(dt)
    if out is not None:
        seen = {str(((h.get("_source") or {}).get("log") or {}).get("level"))
                for h in out["hits"]["hits"]}
        levels["hit_spellings"] = len(seen & set(ESTATE_LEVEL_SPELLINGS))
        levels["hit_changed"] = sorted(seen - set(ESTATE_LEVEL_SPELLINGS))

    return {
        "tenants": ESTATE_TENANTS, "jobs": ESTATE_JOBS, "resources": ESTATE_RESOURCES,
        "names": sum(len(v) for v in by_class.values()),
        "distinct_names": len({n for v in by_class.values() for n in v}),
        "mentions": sum(len(v) for v in mentions.values()),
        "classes": classes,
        "readable": sum(c["readable"] for c in classes),
        "part_readable": sum(c["part_readable"] for c in classes),
        "declared_miss": sum(c["declared_miss"] for c in classes),
        "unexpected": sorted(set(unexpected)),
        # the shape of the declared miss, plainly: one-word names the skip
        # rules drop. Invented names, so the report may hold them.
        "declared_examples": sorted(set(declared))[:5],
        "skipped_by_rule": {r: sum(c["skipped"].get(r, 0) for c in classes)
                            for r in sorted({r for c in classes for r in c["skipped"]})},
        "levels": levels,
    }


def run_eval(config: elastic.ElasticConfig | None = None, *, seed: int = 20261103, docs: int = 600,
             queries: int = 120, tier2: str = "classifier", mcp: bool = True) -> dict:
    cfg = config or elastic.load(elastic.EXAMPLE)
    fx = generate(seed=seed, docs=docs, bulk_jobs=BULK_JOBS, estate=True)
    truth = fx.truth
    engine = StubEngine(fx, cfg.indices)
    engine.page_seconds = PAGE_SECONDS
    engine.wide_page_seconds = WIDE_PAGE_SECONDS
    rng = random.Random(seed + 1)

    # Sign-in: the one vocabulary build for this bridge, paid once, with the
    # stub charging what a real page costs. Every case below starts from its
    # result; none of them reads anything.
    vocab, cover = build_cover(cfg, engine)
    build_report = {**cover, "simulated_s": cover["seconds"],
                    "fields": {f: len(v) for f, v in vocab.fields.items()}}
    # ...and one top-up ten minutes later, reading only what is new.
    before_topup = engine.simulated_seconds
    topup_vocab, topup = build_vocabulary(
        cfg, engine, vocab.covered_until,
        vocab.covered_until + elastic.VOCABULARY_REFRESH_S)
    topup_report = {"requests": topup.requests,
                    "simulated_s": round(engine.simulated_seconds - before_topup, 1),
                    "new_values": sum(len(v) for v in topup_vocab.fields.values())}
    vocab = vocab.merge(topup_vocab)

    sess = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    s = sess.scrubber

    # The human seeds the case with the tenant it is about, locally - and
    # with the two values the oracle cases are written against, as the MCP
    # eval does with its terms. A seeded label is one the case has been
    # shown, which is what makes "a label of the wrong type" (rather than
    # "a label you were never shown") the thing those cases test.
    case_label = s.seed(fx.tenants[0].name)
    s.seed(next(sv.name for sv in fx.servers if "-amer-" in sv.name), "SERVER_NAME")
    s.seed(fx.tenants[0].tenant_id, "TENANT_ID")

    labels: dict[str, list[str]] = {}  # type -> labels learnt so far
    _seen_labels: set[str] = set()     # membership, so learn() stays linear:
    # with a cluster vocabulary the session holds tens of thousands of
    # labels, and a list scan per label per query is quadratic twice over

    def learn() -> None:
        # the labels this case has been **shown**, which is the set a query
        # may use: the mapping holds one per vocabulary name too, and those
        # are exactly what a case may not reach (see the label-guessing
        # oracle cases)
        for label in s.shown:
            if label not in _seen_labels:
                _seen_labels.add(label)
                labels.setdefault(s.types.get(label, ""), []).append(label)

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

    # The one-hour case on a cluster with a back catalogue of BULK_JOBS
    # names, now served entirely from the sign-in build: no request of its
    # own, and the job's record is covered because the build read 30 days.
    window_case = {"shown": False, "refused": None, "leaks": [], "part_leak": False,
                   "requests": 0, "seconds": 0.0, "values": {}}
    hour = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    before = engine.simulated_seconds
    out, refused, dt, _ = hour.call({
        "index": "logs-worker-*", "time_range": WINDOW_CASE_RANGE, "size": 20,
        "filters": [{"field": "message", "op": "phrase", "value": WINDOW_CASE_PHRASE}]})
    timings.append(dt)
    window_case["requests"] = 0
    window_case["seconds"] = round(engine.simulated_seconds - before, 3)
    window_case["values"] = dict(hour.scrubber.vocabulary_counts)
    window_case["refused"] = refused.code if refused else None
    if out is not None and (out["hits"]["total"] or {}).get("value", 0) > 0:
        window_case["shown"] = True
        window_case["leaks"] = _leaks(out, truth)
        window_case["part_leak"] = bool(
            name_part_leaks(_messages(out), WINDOW_CASE_PHRASE, WINDOW_CASE_JOB))

    # A case opened before the build has finished is refused, rather than
    # shown against a vocabulary that does not know the customer's name
    # yet. Through the real Bridge, with an index that holds nothing.
    building = cold_bridge_refusal(cfg, engine, tier2=tier2)

    # The sliced build on the real broker, a serve-loop step at a time:
    # a case runs off the recent slices while the older ones are still
    # being read, and the broker answers between every step.
    slices = run_slice_eval(cfg, fx, engine, tier2=tier2)

    # An identifier field with more distinct values than the cap, in the
    # default field set: counted once, left out, and the build carries on.
    # Its own map, its own index pattern and its own engine, so nothing
    # above it moves.
    over_cap = run_over_cap_eval(fx, tier2="none")

    # A data stream named after a job: the name stays readable inside the
    # stream's keep values and is still hidden where it is the whole value.
    # Its own map, index pattern and engine, like the over-cap gate.
    stream_name = run_stream_name_eval(fx, tier2="none")

    # The per-case phrase budget against a guessing run, on the real Bridge.
    phrase_budget = run_phrase_budget_eval(fx, tier2="none")

    # es-review over that guessing run and over an ordinary investigation.
    gap = run_gap_eval(tier2="none")
    catch_up = run_catch_up_eval(tier2="none")
    review = run_review_eval(cfg, engine, vocab, fx, phrase_budget["after"]["case_dir"],
                             tier2=tier2)

    # A site map with no vocabulary section at all, which is what a site has
    # before anyone writes one. The default decides what is read, and a
    # one-hour case names a tenant and a resource whose own fields are on
    # other documents. Under the old JOB_NAME-only default both stayed
    # readable; under the "everything that could be read" default they are
    # labelled, except the one-word names the skip rules drop - which is a
    # declared miss, reported here rather than gated.
    raw_default = json.loads(Path(cfg.source).read_text(encoding="utf-8")) \
        if cfg.source and Path(cfg.source).exists() else json.loads(elastic.EXAMPLE.read_text())
    raw_default.pop("vocabulary", None)
    cfg_default = elastic.parse(raw_default, source="no-vocabulary-section")
    # its own bridge, so its own sign-in build: the default decides which
    # fields that build reads
    before = engine.simulated_seconds
    default_vocab, default_build = build_vocabulary(cfg_default, engine)
    # Counts, reasons and field names only: the names themselves are planted
    # values, and the report must not carry one (the names live in
    # DEFAULT_MAP_ONE_WORD and in AGENTS.md, where they are documentation).
    default_map = {"cases": 0, "shown": 0, "tenants_hidden": 0, "tenants_readable": 0,
                   "resources_readable": 0,
                   "fields_read": [r.pattern for r in cfg_default.vocabulary_rules],
                   "omitted": list(cfg_default.vocabulary_omitted),
                   "requests": 0, "seconds": 0.0, "values": {},
                   "skipped_by_rule": {}, "one_word_names": len(DEFAULT_MAP_ONE_WORD)}
    readable: list[str] = []
    for tenant_name, resource, _message in default_map_cases():
        # a fresh case each time: nothing seeded, nothing harvested, the
        # names' own fields outside the hour the query asks for
        first = Session(cfg_default, engine, tier2=tier2, vocabulary=default_vocab)
        out, refused, dt, _ = first.call({
            "index": "logs-worker-*", "time_range": DEFAULT_MAP_RANGE, "size": 20,
            "filters": [{"field": "message", "op": "phrase", "value": DEFAULT_MAP_PHRASE}]})
        timings.append(dt)
        default_map["cases"] += 1
        default_map["values"] = dict(first.scrubber.vocabulary_counts)
        default_map["skipped_by_rule"] = dict(first.scrubber.vocabulary_skipped)
        if out is None or not (out["hits"]["total"] or {}).get("value", 0):
            continue
        default_map["shown"] += 1
        page = " ".join(_messages(out))
        if tenant_name in page:
            readable.append(tenant_name)
            default_map["tenants_readable"] += 1
        else:
            default_map["tenants_hidden"] += 1
        default_map["resources_readable"] += int(resource in page)
    default_map["requests"] = default_build.requests
    default_map["seconds"] = round(engine.simulated_seconds - before, 1)
    # how many one-word names the skip rules drop, by the rule's own reason
    dropped = {n: elastic.EsScrubber.vocabulary_skip(n) for n in DEFAULT_MAP_ONE_WORD}
    by_reason: dict[str, int] = {}
    for why in dropped.values():
        if why:
            by_reason[why] = by_reason.get(why, 0) + 1
    default_map["one_word_dropped"] = sum(1 for w in dropped.values() if w)
    default_map["one_word_dropped_by_reason"] = by_reason
    # every name left readable is one the skip rules dropped: the declared
    # miss, and nothing beyond it
    default_map["readable_all_skipped"] = all(dropped.get(n) for n in readable)

    estate = run_estate_eval(cfg, engine, vocab, tier2=tier2, timings=timings)
    guesses = run_guess_eval(cfg, engine, vocab, tier2=tier2, timings=timings)
    ordinary = run_ordinary_word_eval(cfg, engine, vocab, tier2=tier2, timings=timings)

    # The keep-field leak: the level value that is a SharePoint personal-site
    # URL, shown both ways it reaches Claude - in a hit, and as a bucket key
    # of an aggregation over the field - plus the fidelity half: the ordinary
    # level and outcome spellings must come back exactly as logged, and a
    # filter by one must still match.
    keep = {"hit_shown": False, "hit_leaks": [], "agg_leaks": [], "bucket_keys": 0,
            "levels_kept": [], "levels_changed": [], "filter_by_level": False}
    kl = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
    out, refused, dt, _ = kl.call({
        "index": "logs-worker-*", "time_range": tr, "size": 20,
        "filters": [{"field": "message", "op": "phrase", "value": KEEP_LEAK_PHRASE}]})
    timings.append(dt)
    if out is not None and (out["hits"]["total"] or {}).get("value", 0) > 0:
        keep["hit_shown"] = True
        keep["hit_leaks"] = _leaks(out, truth)
    out, refused, dt, _ = kl.call({
        "index": "logs-worker-*", "time_range": tr, "size": 0,
        "aggs": {"levels": {"type": "terms", "field": "log.level", "size": 30},
                 "outcomes": {"type": "terms", "field": "event.outcome", "size": 10}}})
    timings.append(dt)
    if out is not None:
        keep["agg_leaks"] = _leaks(out, truth)
        keys = {str(b["key"]) for a in out["aggregations"].values()
                for b in a.get("buckets", [])}
        keep["bucket_keys"] = len(keys)
        spellings = (*KEEP_LEVEL_SPELLINGS, *KEEP_OUTCOME_SPELLINGS)
        keep["levels_kept"] = sorted(v for v in spellings if v in keys)
        keep["levels_changed"] = sorted(set(spellings) - keys)
    out, refused, dt, _ = kl.call({
        "index": "logs-worker-*", "time_range": tr, "size": 5,
        "filters": [{"field": "log.level", "op": "eq", "value": "wrn"}]})
    timings.append(dt)
    keep["filter_by_level"] = (out is not None
                               and (out["hits"]["total"] or {}).get("value", 0) == 1)

    # A fresh case's first page, for each job named with no marker: nothing
    # seeded, nothing harvested yet, the job's own record on another document.
    fresh = {"cases": 0, "shown": 0, "leaks": 0, "leaked_types": [], "part_leaks": 0}
    for phrase, name in unmarked_cases():
        first = Session(cfg, engine, tier2=tier2, vocabulary=vocab)
        out, refused, dt, _ = first.call({
            "index": "logs-worker-*", "time_range": tr, "size": 20,
            "filters": [{"field": "message", "op": "phrase", "value": phrase}]})
        timings.append(dt)
        fresh["cases"] += 1
        if out is not None and (out["hits"]["total"] or {}).get("value", 0) > 0:
            fresh["shown"] += 1
            leaked = _leaks(out, truth)
            if name_part_leaks(_messages(out), phrase, name):
                fresh["part_leaks"] += 1
                leaked = leaked + ["NAME_PART"]
            fresh["leaks"] += bool(leaked)
            fresh["leaked_types"] = sorted(set(fresh["leaked_types"]) | set(leaked))

    # Label round trip: a label learnt from a page, used as a filter.
    since = NOW - timedelta(hours=6)
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
        out, refused, dt, compiled = sess.call({"index": index, "size": 20, "time_range": tr,
                                                "filters": [{"field": rule.pattern, "op": "eq", "value": lab}]})
        timings.append(dt)
        ok = (compiled is not None and json.dumps(compiled.body).find(json.dumps(real)) >= 0
              and refused is None)
        if ok:
            flat_hits = [flatten(h.get("_source", {})) for h in out["hits"]["hits"]]
            ok = all(h.get(rule.pattern) == lab for h in flat_hits) and not _leaks(out, truth)
            raw_hits = [flatten(d.source) for d in fx.docs if d.index == index
                        and flatten(d.source).get(rule.pattern) in (real, _num(real))
                        and _parse_time(flatten(d.source).get("@timestamp")) >= since]
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
        # documents in an index this map does not list are not this map's
        # coverage: the oversized-field fixture has its own index pattern
        # and its own map (see over_cap_docs)
        if not cfg.index_allowed(d.index):
            continue
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
        "fresh_case": fresh,
        "default_map": default_map,
        "estate": estate,
        "label_guessing": guesses,
        "ordinary_words": ordinary,
        "keep_field": keep,
        "window_case": window_case,
        "building_case": building,
        "slices": slices,
        "over_cap": over_cap,
        "stream_name": stream_name,
        "phrase_budget": phrase_budget,
        "review": review,
        "gap": gap,
        "catch_up": catch_up,
        # The one build this bridge paid, and one top-up. No case reads
        # anything: a case applies what the build already holds. Counts and
        # seconds only, never a name.
        "vocabulary": {**s.vocabulary_report(),
                       "build": build_report,
                       "topup": topup_report,
                       "page": elastic.VOCABULARY_PAGE,
                       "page_seconds": list(PAGE_SECONDS),
                       "wide_page_seconds": list(WIDE_PAGE_SECONDS),
                       "bulk_jobs": BULK_JOBS,
                       "cases_served": 3 + fresh["cases"] + default_map["cases"]},
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
        # every unmarked job-name page shown, not refused, and clean
        "fresh_case_no_leaks": fresh["cases"] == len(unmarked_phrases())
        and fresh["shown"] == fresh["cases"] and fresh["leaks"] == 0,
        # a site map with no vocabulary section: every name the skip rules
        # keep is hidden, and every resource. The names the skip rules drop
        # are the declared miss, reported not gated.
        "default_map_names_hidden": default_map["shown"] == default_map["cases"] > 0
        and not default_map["resources_readable"] and default_map["readable_all_skipped"],
        # The realistic estate: every free-text mention still readable is a
        # one-word name the skip rules dropped - the declared miss, reported
        # with its shape and not gated. Anything else readable, whole or by
        # a word of it, fails here.
        "estate_no_unexpected_readable": not estate["unexpected"]
        and estate["mentions"] > 0
        and all(c["shown"] for c in estate["classes"]),
        # Label guessing on the estate: a fresh case guesses a hundred live
        # vocabulary labels, every one is refused as unknown_label, no
        # guess reaches Kibana, and a label the case *was* shown still
        # works in the next query.
        "label_guessing_refused":
            guesses["refused"] == guesses["guesses"] == 100
            and set(guesses["codes"]) == {"unknown_label"}
            and guesses["resolvable_in_mapping"] > 0
            and guesses["same_message_as_dead"]
            and guesses["requests"] == 0
            and guesses["logged_label_never_value"]
            and guesses["shown_label_works"],
        # A job name that is an ordinary word keeps its label in its own
        # field, is hidden in the text of the document that owns it, and
        # stays readable English on every other document - whatever pages
        # the case saw first.
        "ordinary_words_readable":
            ordinary["readable_after"] == ordinary["words"] > 0
            and ordinary["swept_after"] == 0
            and ordinary["swept_before"] == ordinary["words"]
            and ordinary["labelled_in_field"] == ordinary["words"]
            and ordinary["own_doc_hidden"] == ordinary["words"]
            and ordinary["filter_by_label"]
            and ordinary["deterministic"],
        # and every level and outcome spelling the estate logs comes back
        # exactly as written, in bucket keys and in hit values
        "estate_spellings_unchanged": not estate["levels"]["changed"]
        and not estate["levels"].get("hit_changed")
        and estate["levels"]["hit_spellings"] == len(ESTATE_LEVEL_SPELLINGS),
        # the stray URL in a level field: hidden in the hit and in the bucket
        # key, while every ordinary spelling survives and still filters
        "keep_leak_closed": keep["hit_shown"] and not keep["hit_leaks"]
        and not keep["agg_leaks"],
        "keep_values_readable": not keep["levels_changed"]
        and len(keep["levels_kept"]) == len(KEEP_LEVEL_SPELLINGS) + len(KEEP_OUTCOME_SPELLINGS)
        and keep["filter_by_level"],
        # the one-hour case on a cluster with BULK_JOBS names: shown, with
        # the job name labelled, served from the sign-in build at no cost
        "window_case_shown": window_case["shown"] and not window_case["leaks"]
        and not window_case["part_leak"] and window_case["requests"] == 0,
        # every slice fits the per-slice budget, no page was charged at the
        # wide-range rate (a build that slices never asks for one), and a
        # top-up is cheaper than the cover
        "vocabulary_build_in_budget":
            build_report["max_slice_s"] <= cfg.vocabulary_budget_s
            and not build_report["wide_pages"]
            and topup_report["simulated_s"] < build_report["simulated_s"],
        # A case runs off the recent slices while the older ones are still
        # being read, and no serve-loop step blocks the broker: a ping
        # after every step is answered, and no step takes longer than one
        # poll interval.
        "vocabulary_slices_serve_early":
            slices["case_shown"] and not slices["case_leaks"]
            and not slices["case_part_leak"]
            and slices["refused_before_cover"] == "vocabulary_building"
            and slices["still_building_older"]
            and slices["pings"] == slices["pings_answered"] > 0
            and slices["max_step_s"] <= slices["poll_interval_s"],
        # An identifier field over vocabulary.max, in the default field
        # set: counted once rather than paged to the cap, left out, the
        # build finishes, the first case about a day in the cover is still
        # served with the name hidden, and the field and its count are
        # named on the VOCAB line (no value anywhere). A map that lists the
        # field itself is still refused, with a message naming it.
        "over_cap_field_left_out":
            over_cap["before_refused"] == "vocabulary"
            and over_cap["before_requests"] > over_cap["after_probes"] == 1
            and over_cap["left_out"] == {OVER_CAP_FIELD: OVER_CAP_REFS}
            and over_cap["names_read"].get("labels.tenant_name")
            and OVER_CAP_FIELD not in over_cap["names_read"]
            and over_cap["case_shown"] and not over_cap["case_refused"]
            and not over_cap["case_leaks"] and not over_cap["case_part_leak"]
            and over_cap["readable_without_vocabulary"]
            and over_cap["reported_on_vocab_line"]
            and over_cap["logged_values"] == 0
            and over_cap["listed_refused"] == "vocabulary"
            and over_cap["listed_message_names_field"]
            and over_cap["listed_message_says_how"],
        # A data stream named after a job: index, dataset and namespace
        # readable in hits and as bucket keys; the job still labelled in its
        # own field, in message text and in a keep field holding the whole
        # name; and before the rule the stream's keep values did change.
        "stream_name_readable_in_keep":
            (a := stream_name["after"])["shown"]
            and a["index_readable"] and a["dataset_readable"] and a["namespace_readable"]
            and a["bucket_keys_readable"]
            and a["job_field_labelled"] and a["text_labelled"] and a["whole_keep_labelled"]
            and a["changed_fields"] == ["service.name"]
            and stream_name["before"]["keep_changed"] > a["keep_changed"]
            # readable means usable: the dataset literal is refused until
            # the page showed it, then finds the stream; the whole name is
            # refused still
            and a["filter_unshown_refused"] == "known_value"
            and a["filter_unshown_requests"] == 0
            and a["filter_shown_hits"] == len(stream_name_docs())
            and a["whole_name_refused"] == "known_value",
        # The guessing run: before, every phrase reaches Kibana; after, no
        # more than the budget does, every query past it refused with
        # phrase_budget and no request, one refusal shape whatever the batch
        # held, and reuse and label-only phrases still run.
        "phrase_budget_holds":
            phrase_budget["before"]["sent"] == BUDGET_QUERIES
            and (pa := phrase_budget["after"])["report"]["phrases_used"]
            <= phrase_budget["budget"]
            and pa["refused_budget"] == BUDGET_QUERIES - pa["sent"] > 0
            and pa["refused_requests"] == 0 and pa["other_refusals"] == 0
            and pa["message_shapes"] == 1
            and pa["reuse_runs"] and pa["label_only_runs"],
        # es-review flags the guessing run and not an ordinary investigation,
        # reports a missing log as no review (never clean), and prints no
        # value by default
        # A cover saved a week ago: the gap tenant would have been readable,
        # is refused with no request until the top-up (run first) reads the
        # gap, then shown hidden on the same open case; ten minutes serves.
        "gap_fails_closed":
            gap["readable_without_gate"] and gap.get("refused") == "vocabulary_building"
            and gap.get("requests_while_refused") == 0 and gap.get("state") == "catching_up"
            and gap.get("message_names_gap") and not gap.get("message_has_value")
            and gap.get("top_up_first") and gap.get("shown_after") and gap.get("hidden_after")
            and gap.get("ten_minutes_serves"),
        # A week-long gap: one wide read fails its budget (and would for
        # ever); sliced, every slice lands under budget at the slice rate,
        # the cover stays one range from its old start to now, a case is
        # refused throughout with a true, decreasing slices-left count, and
        # the same case is shown with the name hidden once the gap closes.
        "catch_up_sliced":
            catch_up["before"]["refused"] == "vocabulary"
            and catch_up["before"]["wide_pages"] > 0
            and (ca := catch_up["after"])["slices"] == GAP_DAYS
            and ca["failed_slices"] == 0 and ca["wide_pages"] == 0
            and ca["max_slice_s"] < catch_up["budget_s"]
            and ca["one_range"] and ca["covered_from_kept"] and ca["covered_until_now"]
            and ca["refusals_while_behind"] > 0 and ca["message_names_slices"]
            and ca["first_slices_left"] == GAP_DAYS and ca["slices_left_decreasing"]
            and ca["shown_after"] and ca["hidden_after"] and ca["log_values"] == 0,
        "review_flags_guessing":
            review["guessing"]["verdict"] == "flagged"
            and ("zero_hit_phrases" in review["guessing"]["flagged"]
                 or "phrase_budget_pressure" in review["guessing"]["flagged"])
            and review["ordinary"]["verdict"] == "nothing flagged"
            and review["ordinary"]["refusals"] == 0
            and review["ordinary"]["log_status"] == "ok"
            and review["missing"]["log_status"] == "missing"
            and review["missing"]["verdict"] is None
            and review["values_in_default_output"] == 0,
        # a case before the build finishes is refused, not shown
        "vocabulary_building_refuses":
            building["refused"] == "vocabulary_building" and not building["shown"],
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


def _ordinary_lines(o: dict | None) -> list[str]:
    """Job names that are ordinary words: how many lose the word, before
    and after."""
    if not o:
        return []
    return [
        f"ordinary words    {o['words']} job names that are ordinary words, all labelled in "
        f"their own field ({o['labelled_in_field']}/{o['words']}); words lost from ordinary "
        f"messages: {o['swept_before']} before the rule, {o['swept_after']} after "
        f"({o['readable_after']}/{o['words']} readable)",
        f"  and still       hidden in the text of the document that owns the name "
        f"{o['own_doc_hidden']}/{o['words']}; the label filters its own field: "
        f"{'yes' if o['filter_by_label'] else 'NO'}; the same page with no page before it reads "
        f"the same: {'yes' if o['deterministic'] else 'NO - order still decides'}",
    ]


def _guess_lines(g: dict | None) -> list[str]:
    """Label guessing: what a case can reach that it was never shown."""
    if not g:
        return []
    return [
        f"label guessing    {g['refused']}/{g['guesses']} guessed labels refused "
        f"{g['codes'] or 'none'}, of which {g['resolvable_in_mapping']} are live vocabulary "
        f"labels this case holds but was never shown; {g['requests']} reached Kibana; a label "
        f"that does not exist refuses the same way: {g['same_message_as_dead']}; the log keeps "
        f"the label and no value: {g['logged_label_never_value']}",
        f"  shown labels    {g['shown_labels_before_page']} before the first page, "
        f"{g.get('shown_after_page', 0)} after it; a label off that page works in the next "
        f"query: {'yes' if g['shown_label_works'] else 'NO - the rule broke the tool'}",
    ]


def _slice_lines(s: dict | None) -> list[str]:
    """The sliced build on the real broker: when a case can first run, and
    that the broker keeps answering while it builds."""
    if not s:
        return []
    return [
        f"  on the broker   a case over the recent cover is "
        f"{'shown' if s['case_shown'] else 'NOT SHOWN'}"
        + (f" (refused {s['case_refused']})" if s["case_refused"] else "")
        + f", {len(s['case_leaks'])} leaks, "
        f"{'a word of the name readable' if s['case_part_leak'] else 'name hidden'}; "
        f"before any cover it was {s['refused_before_cover'] or 'NOT REFUSED'}; older slices "
        f"{'still building' if s['still_building_older'] else 'ALREADY DONE (nothing proved)'}"
        f" after {s['slices_at_first_case']} slices "
        f"({s['covered_days_at_first_case']}d covered, {s['requests_to_first_case']} requests, "
        f"{s['seconds_to_first_case']}s simulated)",
        f"  steps           {s['steps']} serve-loop steps, longest {s['max_step_s']}s against a "
        f"{s['poll_interval_s']:g}s poll interval; {s['pings_answered']}/{s['pings']} pings "
        f"answered mid-build (es-login's progress and es-logout's stop are these)",
    ]


def _review_lines(o: dict | None) -> list[str]:
    if not o:
        return []
    g, n = o["guessing"], o["ordinary"]
    return [f"es-review        guessing run ({g['queries']} queries, {g['zero_hit']} zero-hit "
            f"phrases): {g['verdict']} {g['flagged']}; ordinary investigation ({n['queries']} "
            f"queries, {n['refusals']} refusals): {n['verdict']} {n['flagged']}; a case with no "
            f"log: {o['missing']['log_status']}, verdict {o['missing']['verdict']}; values in the "
            f"default output: {o['values_in_default_output']}"]


def _phrase_budget_lines(o: dict | None) -> list[str]:
    """The guessing run, before and after the per-case budget. Counts only."""
    if not o:
        return []
    b, a = o["before"], o["after"]
    return [f"phrase budget    {a['queries']} queries of 8 candidate names: "
            f"{b['phrases_reached']} phrase uses ({b['report']['phrases_used']} distinct) "
            f"reached Kibana with no budget, {a['phrases_reached']} "
            f"({a['report']['phrases_used']} distinct) with the default {o['budget']}; "
            f"{a['refused_budget']} "
            f"queries refused phrase_budget from query {a['first_refused_at']}, "
            f"{a['refused_requests']} requests, {a['message_shapes']} refusal shape(s); "
            f"reused phrase runs {a['reuse_runs']}, label-only phrase runs "
            f"{a['label_only_runs']}"]


def _stream_name_lines(o: dict | None) -> list[str]:
    """Keep values changed in the job-named stream, before and after the
    keep rule. Field names and counts only."""
    if not o:
        return []
    b, a = o["before"], o["after"]
    return [
        f"job-named stream keep values changed {b['keep_changed']}/{b['keep_values']} before "
        f"the keep rule ({', '.join(b['changed_fields']) or 'none'}), "
        f"{a['keep_changed']}/{a['keep_values']} after ({', '.join(a['changed_fields']) or 'none'}); "
        f"index, dataset, namespace readable: {a['index_readable']}, {a['dataset_readable']}, "
        f"{a['namespace_readable']}; bucket keys readable: {a['bucket_keys_readable']}; job "
        f"labelled in its field {a['job_field_labelled']}, in text {a['text_labelled']}, "
        f"as a whole keep value {a['whole_keep_labelled']}",
        f"  dataset literal never shown: {a['filter_unshown_refused'] or 'COMPILED'} "
        f"({a.get('filter_unshown_requests', 0)} requests); after the page showed it: "
        f"{a['filter_shown_hits']} hits"
        + (f" (refused {a['filter_shown_refused']})" if a.get("filter_shown_refused") else "")
        + f"; the whole name as a keep literal: {a['whole_name_refused'] or 'COMPILED'}",
    ]


def _over_cap_lines(o: dict | None) -> list[str]:
    """What an identifier field wider than the cap costs, and what is said
    about it. Field names and counts; the fixture's own names never appear
    here, and the whole point of the section is the last line."""
    if not o:
        return []
    return [
        f"over-cap field    {o['field']} has {o['distinct']} distinct values in a day against a "
        f"{o['max']} cap, in the default field set {o['fields_default']}: "
        f"{o['before_requests']} requests on it and then the slice refused with "
        f"{o['before_refused'] or 'NOTHING'} before the rule (at the default "
        f"{elastic.DEFAULT_VOCABULARY_MAX} cap, {o['before_pages_at_default_cap']} a slice, "
        f"every slice, for ever); {o['after_probes']} distinct count after it, for the whole "
        f"cover ({o['after_probes_all']} counts in all, one per kept field per slice)",
        f"  and the build   finished {o['slices']} slices in {o['after_requests']} requests; "
        f"names read {o['names_read'] or 'none'}; the first case about a day in the cover is "
        f"{'shown' if o['case_shown'] else 'NOT SHOWN'}"
        + (f" (refused {o['case_refused']})" if o["case_refused"] else "")
        + f", {len(o['case_leaks'])} leaks, "
        f"{'a word of the name readable' if o['case_part_leak'] else 'name hidden'} "
        f"(tier 2 off, and the same page with no vocabulary "
        f"{'does show the name' if o['readable_without_vocabulary'] else 'HIDES IT ANYWAY'}, "
        f"so the vocabulary is what hid it); {o['logged_values']} values in the build log",
        f"  listed instead  a map naming {o['field']} in vocabulary.fields is still refused "
        f"with {o['listed_refused'] or 'NOTHING'}, message names the field: "
        f"{o['listed_message_names_field']}, says how to fix it: {o['listed_message_says_how']}",
        f"  declared cost   {o['left_out'] or 'nothing'} left out of the vocabulary, so its "
        f"values stay readable in message text; this is the only place a user is told: "
        f"{o['vocab_line'] or 'NOTHING SAID'}",
    ]


def _estate_lines(e: dict | None) -> list[str]:
    """The realistic-estate section: one line per shape class, then the
    skip-rule totals, the declared miss and the spelling check."""
    if not e:
        return []
    lv = e["levels"]
    lines = [
        f"realistic estate  {e['tenants']} tenants, {e['jobs']} jobs, {e['resources']} resources "
        f"({e['distinct_names']} distinct names of {e['names']}), {e['mentions']} free-text "
        f"mentions with no marker; readable after the vocabulary: {e['readable']} whole "
        f"({e['declared_miss']} the declared miss), {e['part_readable']} by a word"
        + (f"; UNEXPECTED {e['unexpected']}" if e["unexpected"] else ""),
    ]
    for c in e["classes"]:
        flag = f"  UNEXPECTED {c['unexpected']}" if c["unexpected"] else ""
        lines.append(
            f"  {c['class']:<26}{c['names']:>5} names ({c['distinct']} distinct, {c['shape']}), "
            f"{c['skipped_total']} dropped by the skip rules {c['skipped'] or '{}'}; "
            f"{c['shown']}/{c['mentions']} mentions on the page, {c['readable']} readable "
            f"({c['declared_miss']} declared), {c['part_readable']} by a word" + flag)
    lines += [
        f"  skip rules      {e['skipped_by_rule'] or 'nothing dropped'} over all "
        f"{e['names']} names",
        f"  declared miss   a one-word name the skip rules drop is never vocabulary and stays "
        f"readable in message text: {e['declared_miss']} of {e['mentions']} mentions, all of them "
        f"one ordinary dictionary word (e.g. {', '.join(e['declared_examples']) or 'none'})",
        f"  spellings       {lv['hit_spellings']}/{len(ESTATE_LEVEL_SPELLINGS)} level spellings "
        f"unchanged as hit values, {len(lv['kept'])}/"
        f"{len(ESTATE_LEVEL_SPELLINGS) + len(ESTATE_OUTCOME_SPELLINGS)} level and outcome "
        f"spellings unchanged as bucket keys ({lv['bucket_keys']} keys); skew kept: commonest "
        f"level {lv['top_ratio']}x the next, success {lv['outcome_ratio']}x failure"
        + (f"; CHANGED {lv['changed'] + lv.get('hit_changed', [])}"
           if lv["changed"] or lv.get("hit_changed") else ""),
    ]
    return lines


def format_report(r: dict) -> str:
    d = r["default_map"]
    b, t = r["vocabulary"]["build"], r["vocabulary"]["topup"]
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
        f"fresh case        {r['fresh_case']['shown']}/{r['fresh_case']['cases']} first pages with an "
        f"unmarked job or customer name shown, {r['fresh_case']['leaks']} leaking "
        f"({r['fresh_case']['part_leaks']} by a word of the name)"
        + (f" (types: {r['fresh_case']['leaked_types']})" if r['fresh_case']['leaked_types'] else ""),
        f"no-vocab site map {d['shown']}/{d['cases']} one-hour pages shown, "
        f"{d['tenants_hidden']} tenant names hidden, {d['tenants_readable']} readable, "
        f"{d['resources_readable']} resources readable"
        + ("" if d["readable_all_skipped"] else "  (A NAME THE RULES KEEP IS READABLE)"),
        f"  one-word names  {d['one_word_dropped']} of {d['one_word_names']} dropped by the "
        f"skip rules {d['one_word_dropped_by_reason'] or 'none'}, of which "
        f"{d['tenants_readable']} left readable in message text (a declared miss); the rest "
        f"happen to be caught by tier 2, which is luck, not the rule",
        f"  default reads   {len(d['fields_read'])} fields {d['fields_read']}; "
        f"{d['requests']} requests over {d['cases']} cases in {d['seconds']}s, "
        f"values {d['values']}",
        *_estate_lines(r.get("estate")),
        *_guess_lines(r.get("label_guessing")),
        *_ordinary_lines(r.get("ordinary_words")),
        f"keep-field leak   hit {'shown' if r['keep_field']['hit_shown'] else 'NOT SHOWN'}, "
        f"{len(r['keep_field']['hit_leaks'])} leaks; aggregation "
        f"{r['keep_field']['bucket_keys']} bucket keys, {len(r['keep_field']['agg_leaks'])} leaks; "
        f"spellings kept {len(r['keep_field']['levels_kept'])}"
        + (f", CHANGED {r['keep_field']['levels_changed']}" if r['keep_field']['levels_changed']
           else "")
        + f"; filter by a spelling {'works' if r['keep_field']['filter_by_level'] else 'BROKEN'}",
        f"one-hour case     {'shown' if r['window_case']['shown'] else 'NOT SHOWN'} "
        f"({r['window_case']['refused'] or 'not refused'}), {len(r['window_case']['leaks'])} leaks, "
        f"{'a word of the name readable' if r['window_case']['part_leak'] else 'name hidden'}; "
        f"it read {r['window_case']['requests']} requests of its own "
        f"({r['window_case']['seconds']}s) - the sign-in build already had the name "
        f"(cluster back catalogue {r['vocabulary']['bulk_jobs']} job names)",
        f"before the build  a case is {r['building_case']['refused'] or 'NOT REFUSED'}, "
        f"{'no page shown' if not r['building_case']['shown'] else 'A PAGE WAS SHOWN'}",
        f"vocabulary build  {b['slices']} one-day slices, newest first: {b['requests']} "
        f"requests ({b['probes']} of them the distinct count every field is given before it is "
        f"paged, at {PROBE_SECONDS:g}s assumed each) and {b['simulated_s']}s simulated for the "
        f"whole {b['covered_days']}d cover, "
        f"worst slice {b['max_slice_s']}s of the {b['budget_s']:g}s per-slice budget, "
        f"{b['wide_pages']} pages charged at the wide-range rate "
        f"({r['vocabulary']['page']} values a page, one field a page, a page over a slice "
        f"{r['vocabulary']['page_seconds']}s against {r['vocabulary']['wide_page_seconds']}s "
        f"over the whole range); values per field against the cap "
        f"{r['vocabulary']['max']}: {b['fields']}",
        f"  to first case   {b['serving_requests']} requests and {b['serving_seconds']}s "
        f"simulated, after {b['serving_after_slices']} slices: what someone signing in waits "
        f"for before a case can run; the rest of the cover is read behind them",
        *_slice_lines(r.get("slices")),
        *_over_cap_lines(r.get("over_cap")),
        *_stream_name_lines(r.get("stream_name")),
        *_phrase_budget_lines(r.get("phrase_budget")),
        *_review_lines(r.get("review")),
        *_gap_lines(r.get("gap")),
        *_catch_up_lines(r.get("catch_up")),
        f"  top-up          {t['requests']} requests, {t['simulated_s']}s simulated, "
        f"{t['new_values']} new values, every {elastic.VOCABULARY_REFRESH_S:g}s; "
        f"{r['vocabulary']['cases_served']} cases served from it, none reading anything; "
        f"skipped {r['vocabulary']['skipped'] or 'none'}",
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
            f"mcp fresh case    {m['fresh_case']['shown']}/{m['fresh_case']['cases']} first pages "
            f"with an unmarked job or customer name shown, {m['fresh_case']['part_leaks']} with a "
            f"word of the name readable (counted in mcp_no_leaks)",
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
