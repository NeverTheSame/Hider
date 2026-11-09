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
    return Fixture(out, ts, [x for xs in servers.values() for x in xs])


#: What one composite page over one field costs on a real cluster, in
#: seconds: measured between 8 and 35. The stub charges these in turn so a
#: build over the fixture reports a realistic time without the eval
#: actually waiting (see ``StubEngine.page_seconds``).
PAGE_SECONDS: tuple[float, ...] = (18.0, 11.0, 27.0, 8.0, 35.0, 14.0, 22.0)

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
        self.simulated_seconds = 0.0
        self._pages = 0

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
                    self.simulated_seconds += self.page_seconds[
                        self._pages % len(self.page_seconds)]
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


def build_vocabulary(config: elastic.ElasticConfig, engine: StubEngine,
                     covered_from: float | None = None, covered_until: float | None = None,
                     ) -> tuple[elastic.ClusterVocabulary, elastic.VocabularyBuild]:
    """What the broker does on sign-in, driven to completion in one call.

    The stub charges simulated seconds per page (``StubEngine.page_seconds``)
    and the build's clock reads that, so a build over the 12,000-name
    fixture costs what a real one would without the eval taking minutes.
    """
    until = NOW.timestamp() if covered_until is None else covered_until
    start = (until - config.vocabulary_days * 86400.0) if covered_from is None else covered_from
    build = elastic.VocabularyBuild(config, start, until,
                                    clock=lambda: engine.simulated_seconds)
    while build.pending():
        vq = build.request()["params"]
        build.feed({"isPartial": False, "isRunning": False,
                    "rawResponse": engine.search(vq["index"], vq["body"],
                                                 ignore_unavailable=vq["ignore_unavailable"])})
    return build.result(), build


def learn_vocabulary(scrubber: elastic.EsScrubber, engine: StubEngine,
                     cluster: str = "stub") -> tuple[dict[str, int], int]:
    """Build and apply in one step, for a caller that only wants the names
    known (tests, es-eval sessions outside the bridge)."""
    vocab, build = build_vocabulary(scrubber.config, engine)
    return scrubber.apply_vocabulary(cluster, vocab), build.requests


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
        control.call("vocabulary", cluster="stub", build=True)
        vocab_state: dict = {}
        for _ in range(3000):
            vocab_state = control.call("vocabulary", cluster="stub")["vocabulary"]
            if vocab_state.get("state") != "building":
                break
            time.sleep(0.01)
        vocabulary_ready = vocab_state.get("state") in ("ready", "stale")
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
    rng = random.Random(seed + 1)

    # Sign-in: the one vocabulary build for this bridge, paid once, with the
    # stub charging what a real page costs. Every case below starts from its
    # result; none of them reads anything.
    vocab, first_build = build_vocabulary(cfg, engine)
    build_report = {"requests": first_build.requests,
                    "simulated_s": round(engine.simulated_seconds, 1),
                    "fields": {f: len(v) for f, v in vocab.fields.items()},
                    "budget_s": cfg.vocabulary_budget_s,
                    "covered_days": round((vocab.covered_until - vocab.covered_from) / 86400.0)}
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

    # The human seeds the case with the tenant it is about, locally.
    case_label = s.seed(fx.tenants[0].name)

    labels: dict[str, list[str]] = {}  # type -> labels learnt so far
    _seen_labels: set[str] = set()     # membership, so learn() stays linear:
    # with a cluster vocabulary the session holds tens of thousands of
    # labels, and a list scan per label per query is quadratic twice over

    def learn() -> None:
        for label, t in s.types.items():
            if label not in _seen_labels:
                _seen_labels.add(label)
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
        "keep_field": keep,
        "window_case": window_case,
        "building_case": building,
        # The one build this bridge paid, and one top-up. No case reads
        # anything: a case applies what the build already holds. Counts and
        # seconds only, never a name.
        "vocabulary": {**s.vocabulary_report(),
                       "build": build_report,
                       "topup": topup_report,
                       "page": elastic.VOCABULARY_PAGE,
                       "page_seconds": list(PAGE_SECONDS),
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
        # the whole build fits its budget, and a top-up is cheap
        "vocabulary_build_in_budget":
            build_report["simulated_s"] <= cfg.vocabulary_budget_s
            and topup_report["simulated_s"] < build_report["simulated_s"],
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
        f"vocabulary build  {b['requests']} requests, {b['simulated_s']}s simulated of a "
        f"{b['budget_s']:g}s budget, over {b['covered_days']} days, once per cluster at "
        f"sign-in ({r['vocabulary']['page']} values a page, one field a page, "
        f"page cost {r['vocabulary']['page_seconds']}s); values per field against the cap "
        f"{r['vocabulary']['max']}: {b['fields']}",
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
