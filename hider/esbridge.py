"""The live session layer: one long-lived browser owns the Kibana SSO session.

    python -m hider es-login --cluster emea         # start the bridge, sign the cluster in
    python -m hider es-smoke --cluster emea         # one scrubbed query through the bridge
    python -m hider es-logout                       # stop the bridge; the session ends
    python -m hider es-smoke --stub                 # whole path in one process, synthetic Kibana

Design (``docs/es-bridge-design.md``): there are no API keys. Each Kibana
sits behind corporate SSO and the session lives in a browser cookie jar.
The cookie never leaves the browser: the bridge launches the installed
Chrome with an off-the-record context, keeps a tab on the Kibana origin,
and runs every request as an in-page ``fetch`` from that tab. Playwright
drives Chrome over a pipe, so no debugging port is open. The bridge
process itself holds no credential.

Kibana's session cookie has no expiry, so it lasts exactly as long as the
browser holding it. ``Broker`` is the process that keeps that browser
alive between commands: ``es-login`` starts it and signs in (headed: the
IdP never completes headless), each ``es-smoke`` sends it one grammar query
over a private socket and gets a scrubbed page back.

Four things this module promises, each tested against ``eseval.StubKibana``:

* **Only well-formed, complete async-search responses reach the scrubber.**
  A login page (Kibana serves it with a 200 after an expired SSO session,
  sometimes via a redirect through the identity provider), any HTML, a
  redirect off the Kibana host, a non-JSON body, a poll timeout, a
  still-running or partial result: every one is a :class:`elastic.Refused`
  with a stable code. The scrubber then applies its own refusals on top.
* **The query is the compiled grammar and nothing else.** ``esquery``
  compiles, this module posts the body verbatim, ``EsScrubber`` reads the
  reply. Labels are resolved on the way out and minted on the way back
  inside those two modules; nothing here sees a value in the clear except
  the raw reply in transit, which is never logged and never leaves the
  broker.
* **No cookie reaches disk.** Nothing here reads, exports or stores one,
  and the off-the-record context keeps Chrome from writing it either.
* **The bridge's directory is its own.** It is created by the bridge with a
  marker file, refused if it points at an existing directory without the
  marker, and refused if it is a stock Chrome profile directory. It holds
  the broker's socket (0600 in a 0700 directory) and nothing of Chrome's.

The MCP server (``esmcp``) runs inside the broker: ``open_case`` on the
broker's socket mints a per-case token and starts an HTTP listener on
127.0.0.1, and every tool call is a :meth:`Bridge.run` on the broker's
thread, the one that owns the browser.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from . import elastic, esquery, jsonscrub

SEARCH_PATH = "/internal/search/ese"
PROBE_PATH = "/internal/security/me"
APP_PATH = "/app/home"
HEADERS = {
    "kbn-xsrf": "true",
    "x-elastic-internal-origin": "Kibana",
    "Content-Type": "application/json",
    "Accept": "application/json",
}
POLL_INTERVAL_S = 1.5
POLL_TIMEOUT_S = 120.0
LOGIN_TIMEOUT_S = 600.0
PROFILE_MARKER = ".hider-es-bridge-profile"
LOG_SCHEMA = "hider.es-bridge.v1"
#: What "now" is when the name vocabulary decides the range to read and
#: whether what it holds has gone stale. A module global because it is a
#: hook for the harnesses, not per-request state: the stub fixtures sit at
#: ``eseval.NOW`` rather than today, and nothing in the live path replaces
#: it. A query's own date math is sent as written and resolved by the
#: cluster; the one narrowing derived from this clock is the window pieces
#: of a text_groups read (epoch-bound range clauses inside the typed
#: window), so bridge-to-cluster clock skew can shift a piece's edges by
#: the skew - the same declared wobble relative ranges already have.
clock = time.time

#: Stock Chrome profile roots. A profile_dir under one of these is the
#: analyst's own browser, whatever the config says.
_STOCK_PROFILE_ROOTS = (
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/Chromium",
    "~/.config/google-chrome",
    "~/.config/chromium",
    "~/AppData/Local/Google/Chrome/User Data",
)
_LOGIN_HINT = re.compile(r"login|sign[ -]?in|authenticate", re.IGNORECASE)


@dataclass
class Reply:
    """One HTTP exchange as the transport saw it, after redirects."""

    status: int
    url: str
    content_type: str
    text: str
    redirected: bool = False


class Transport(Protocol):
    """How requests reach Kibana. Two implementations: the browser, and
    plain urllib for the stub in tests."""

    def request(self, cluster: elastic.Cluster, method: str, path: str,
                body: dict | None = None) -> Reply: ...

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


class UrllibTransport:
    """Plain HTTP with an optional cookie. For the stub Kibana only: a real
    cluster's cookie must stay in the browser, so nothing in the CLI can
    construct this against a configured cluster."""

    def __init__(self, cookie: str | None = None, timeout: float = 10.0) -> None:
        self.cookie = cookie
        self.timeout = timeout

    def request(self, cluster: elastic.Cluster, method: str, path: str,
                body: dict | None = None) -> Reply:
        url = cluster.kibana + path
        headers = dict(HEADERS)
        if self.cookie:
            headers["Cookie"] = self.cookie
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return Reply(r.status, r.geturl(), r.headers.get("Content-Type", ""),
                             r.read().decode("utf-8", "replace"), r.geturl() != url)
        except urllib.error.HTTPError as e:
            return Reply(e.code, e.geturl() or url, e.headers.get("Content-Type", ""),
                         e.read().decode("utf-8", "replace"), (e.geturl() or url) != url)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise elastic.Refused("unreachable", "kibana unreachable") from e

    def close(self) -> None:
        pass


#: Runs inside the Kibana tab. Same-origin fetch, so the session cookie is
#: sent by the browser and never read by us. Returns what ``Reply`` needs.
_FETCH_JS = """
async ({url, method, headers, body}) => {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 30000);
  try {
    const r = await fetch(url, {method, headers, body, credentials: "same-origin",
                                redirect: "follow", signal: ctl.signal});
    const text = await r.text();
    return {status: r.status, url: r.url, redirected: r.redirected,
            contentType: r.headers.get("content-type") || "", text};
  } finally { clearTimeout(t); }
}
"""


class BrowserTransport:
    """The installed Chrome, driven by Playwright over a pipe, signed in
    inside an off-the-record context.

    One browser, one tab per cluster, every request an in-page ``fetch``
    from that tab. Playwright's sync API is single-threaded, so calls are
    serialised under one lock; parallel tabs are a later phase.

    Off the record because a persistent profile writes cookies to disk:
    Chrome flushes even session cookies (Kibana's ``sid``) to the profile's
    cookie database within about 30 seconds, encrypted under the fixed key
    Playwright's ``--use-mock-keychain`` gives it. An off-the-record context
    keeps every cookie, the IdP's included, in memory, and they all go when
    the browser does. The price: nothing is remembered between browsers, so
    the first sign-in of each browser is the full IdP flow.

    Playwright is an optional extra (``requirements-es.txt``) and is
    imported here, never at module load.
    """

    def __init__(self, profile_dir: str | Path, *, headless: bool = True,
                 channel: str = "chrome") -> None:
        self.profile_dir = prepare_profile_dir(profile_dir)
        self.headless = headless
        self.channel = channel
        self._lock = threading.Lock()
        self._pw = None
        self._browser = None
        self._ctx = None
        self._closing = False
        self._tabs: dict[str, Any] = {}
        self._gone = False

    def start(self) -> None:
        """Launch Chrome now rather than on the first request, so a missing
        extra or a locked profile fails at startup."""
        with self._lock:
            self._start()

    def _start(self) -> None:
        if self._gone:
            raise elastic.Refused("session_expired", "the bridge's browser was closed; "
                                                     "run es-login")
        if self._ctx is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:  # pragma: no cover - depends on the extra
            raise RuntimeError("the browser transport needs playwright: "
                               "pip install -r requirements-es.txt") from e
        self._pw = sync_playwright().start()
        # Playwright talks to Chromium over a pipe by default: no
        # --remote-debugging-port, nothing for another local process to attach to.
        # launch() puts Chrome on a throwaway user-data-dir that Playwright
        # deletes at close; new_context() is off the record on top of it.
        self._browser = self._pw.chromium.launch(
            channel=self.channel, headless=self.headless,
            ignore_default_args=["--enable-automation"],
            args=["--no-first-run", "--no-default-browser-check", "--disable-sync"],
        )
        self._browser.on("disconnected", lambda *_: self._went_away())
        self._ctx = self._browser.new_context(accept_downloads=False)

    def _went_away(self) -> None:
        if not self._closing:
            self._gone = True

    def _new_tab(self, cluster: elastic.Cluster):
        page = self._ctx.new_page()
        # the analyst closing the window ends the session, as es-logout does
        page.on("close", lambda *_: self._went_away())
        self._tabs[cluster.name] = page
        return page

    def _tab(self, cluster: elastic.Cluster):
        """The tab parked on the cluster's Kibana, navigated there if needed.

        Landing anywhere but the Kibana host, or on its login page, is the
        expired-session signal: Kibana answers an expired SSO session with a
        redirect and a 200 login page, never a 401.
        """
        self._start()
        page = self._tabs.get(cluster.name)
        if page is None or page.is_closed():
            page = self._new_tab(cluster)
        if _url_host(page.url) != cluster.host or _is_login_url(page.url):
            page.goto(cluster.kibana + APP_PATH, wait_until="domcontentloaded", timeout=30_000)
        if _url_host(page.url) != cluster.host or _is_login_url(page.url):
            raise elastic.Refused("session_expired",
                                  f"cluster {cluster.name}: not signed in; run es-login")
        return page

    def request(self, cluster: elastic.Cluster, method: str, path: str,
                body: dict | None = None) -> Reply:
        with self._lock:
            page = self._tab(cluster)
            try:
                if self._gone:
                    raise RuntimeError("browser closed")
                r = page.evaluate(_FETCH_JS, {
                    "url": cluster.kibana + path, "method": method, "headers": HEADERS,
                    "body": json.dumps(body) if body is not None else None,
                })
            except Exception as e:  # navigation away, abort, closed tab: all refusals
                raise elastic.Refused("unreachable", "kibana request failed in the browser") from e
            return Reply(int(r["status"]), str(r["url"]), str(r["contentType"]), str(r["text"]),
                         bool(r["redirected"]))

    def login(self, cluster: elastic.Cluster, *, timeout: float = LOGIN_TIMEOUT_S) -> bool:
        """Park the cluster's tab on Kibana and wait until it is signed in.

        Returns True once the tab sits on the Kibana host off the login
        page. The identity provider is driven by the human (or completes by
        itself when the IdP remembers them); this only navigates and waits.

        The browser stays open afterwards, and that is the whole point:
        Kibana's session cookie has no expiry, so Chrome holds it in memory
        only and it dies with the browser. A login is only worth anything to
        the process that keeps this browser running (``Broker``). Run it
        headed: headless SSO does not complete against a real IdP.
        """
        with self._lock:
            self._start()
            page = self._tabs.get(cluster.name)
            if page is None or page.is_closed():
                page = self._new_tab(cluster)
            page.goto(cluster.kibana + APP_PATH, wait_until="domcontentloaded", timeout=60_000)
            deadline = time.time() + timeout
            while time.time() < deadline:
                if _url_host(page.url) == cluster.host and not _is_login_url(page.url):
                    page.wait_for_timeout(1500)  # let Kibana set its cookies
                    self._minimise(page)
                    return True
                page.wait_for_timeout(500)
            return False

    @property
    def closed(self) -> bool:
        """True once Chrome has gone away under us (the analyst closed the
        window): the session went with it."""
        return self._gone

    @staticmethod
    def _minimise(page) -> None:
        """Out of the way after sign-in; best effort, the window must stay
        open because closing it ends the session."""
        try:
            cdp = page.context.new_cdp_session(page)
            win = cdp.send("Browser.getWindowForTarget")["windowId"]
            cdp.send("Browser.setWindowBounds", {"windowId": win,
                                                 "bounds": {"windowState": "minimized"}})
        except Exception:
            pass

    def close(self) -> None:
        self._closing = True
        try:
            if self._browser is not None:
                self._browser.close()
        finally:
            self._browser = None
            self._ctx = None
            self._tabs.clear()
            if self._pw is not None:
                self._pw.stop()
                self._pw = None
            self._closing = False
            self._gone = False  # a deliberate close: the next call starts a fresh browser


def prepare_profile_dir(path: str | Path) -> Path:
    """The bridge's own profile directory, created on first use.

    Refuses a stock Chrome profile root and any existing non-empty
    directory without the bridge's marker, so a config typo cannot point
    the bridge at the analyst's everyday browser (and lock it).
    """
    if not str(path).strip():
        raise elastic.ConfigError("profile_dir is required for the live bridge")
    p = Path(path).expanduser().resolve()
    for root in _STOCK_PROFILE_ROOTS:
        r = Path(root).expanduser()
        if r.exists() and (p == r.resolve() or r.resolve() in p.parents):
            raise elastic.ConfigError(f"profile_dir {p} is a stock Chrome profile; the bridge "
                                      "needs its own dedicated profile directory")
    if p.exists():
        if not p.is_dir():
            raise elastic.ConfigError(f"profile_dir {p} is not a directory")
        if any(p.iterdir()) and not (p / PROFILE_MARKER).exists():
            raise elastic.ConfigError(f"profile_dir {p} exists and was not created by the bridge; "
                                      "pick an empty directory")
    else:
        p.mkdir(parents=True, mode=0o700)
    (p / PROFILE_MARKER).write_text("The hider es-bridge's own directory: its control socket "
                                    "lives here. Chrome keeps no cookie or session here.\n")
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def _url_host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/?#]+)", url or "", re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _is_login_url(url: str) -> bool:
    path = re.sub(r"^[a-z]+://[^/]+", "", url or "", flags=re.IGNORECASE)
    return path.split("?", 1)[0].rstrip("/") in {"/login", "/logout", "/security/logged_out"}


# ---------------------------------------------------------------------------
# The async-search client
# ---------------------------------------------------------------------------


class KibanaSession:
    """The ``/internal/search/ese`` protocol over a transport, with every
    malformed outcome turned into a refusal."""

    def __init__(self, transport: Transport, *, poll_interval: float = POLL_INTERVAL_S,
                 poll_timeout: float = POLL_TIMEOUT_S, sleep=time.sleep, idle=None) -> None:
        self.transport = transport
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._sleep = sleep
        #: what to do between polls instead of sleeping: the broker passes
        #: its own hook here so it keeps answering pings while a search
        #: runs on its one thread (None: plain sleep)
        self._idle = idle

    # -- reply validation --------------------------------------------------

    @staticmethod
    def parse_reply(cluster: elastic.Cluster, reply: Reply) -> dict:
        """A JSON object from Kibana on the Kibana host, or a refusal.

        Order matters: a redirect off the host or onto the login page is a
        session problem whatever the body says; HTML anywhere else is also
        treated as the login page when it says so, and malformed otherwise.
        The error *body* is never put in the refusal.
        """
        if _url_host(reply.url) != cluster.host:
            raise elastic.Refused("session_expired",
                                  f"cluster {cluster.name}: redirected off kibana; run es-login")
        if _is_login_url(reply.url):
            raise elastic.Refused("session_expired",
                                  f"cluster {cluster.name}: login page; run es-login")
        ctype = reply.content_type.split(";", 1)[0].strip().lower()
        head = reply.text.lstrip()[:512]
        if ctype == "text/html" or head[:1] == "<":
            if _LOGIN_HINT.search(head):
                raise elastic.Refused("session_expired",
                                      f"cluster {cluster.name}: login page; run es-login")
            raise elastic.Refused("malformed", "response withheld: kibana answered with HTML")
        if ctype not in {"application/json", ""}:
            raise elastic.Refused("malformed", "response withheld: not a JSON response")
        try:
            data = json.loads(reply.text)
        except json.JSONDecodeError:
            raise elastic.Refused("malformed", "response withheld: not valid JSON") from None
        if not isinstance(data, dict):
            raise elastic.Refused("malformed", "response withheld: not a JSON object")
        if reply.status in (401, 403) or data.get("statusCode") in (401, 403):
            raise elastic.Refused("session_expired",
                                  f"cluster {cluster.name}: not authorised; run es-login")
        return data

    # -- protocol ------------------------------------------------------------

    def probe(self, cluster: elastic.Cluster) -> None:
        """A cheap authenticated call. Anything but a JSON object is a refusal.
        The body (it names the signed-in user) is discarded."""
        data = self.parse_reply(cluster, self.transport.request(cluster, "GET", PROBE_PATH))
        if "username" not in data:
            raise elastic.Refused("session_expired",
                                  f"cluster {cluster.name}: no session; run es-login")

    # The protocol is three steps - submit, poll, release - and they are
    # separate methods because one caller needs them separately. ``search``
    # below is the blocking spelling every query uses; the vocabulary build
    # on the broker's serve loop drives the same three steps one serve-loop
    # iteration at a time, so a page that takes minutes never stops the
    # broker answering a ping, a tool call or a stop.

    def submit(self, cluster: elastic.Cluster, body: dict) -> dict:
        """Start an async search. The reply is usually ``isRunning``."""
        return self.parse_reply(
            cluster, self.transport.request(cluster, "POST", SEARCH_PATH, body))

    @staticmethod
    def search_id(data: dict) -> str:
        """The async-search id, checked. A bad one is a refusal, not a URL
        built out of whatever the reply held."""
        sid = data.get("id")
        if not isinstance(sid, str) or not re.fullmatch(r"[\w=/+.-]{1,512}", sid):
            raise elastic.Refused("malformed", "response withheld: bad async search id")
        return sid

    def poll_once(self, cluster: elastic.Cluster, sid: str, body: dict) -> dict:
        """One poll of a search already submitted."""
        return self.parse_reply(
            cluster, self.transport.request(cluster, "POST", f"{SEARCH_PATH}/{sid}", body))

    def release(self, cluster: elastic.Cluster, sid: str | None) -> None:
        """Delete the server-side search. Best effort: Kibana expires it."""
        if isinstance(sid, str) and sid:
            try:
                self.transport.request(cluster, "DELETE", f"{SEARCH_PATH}/{sid}")
            except elastic.Refused:
                pass

    def search(self, cluster: elastic.Cluster, body: dict,
               deadline_s: float | None = None) -> dict:
        """Submit the compiled body, poll to completion, release the search.

        Returns the final envelope for ``EsScrubber.scrub_response``, which
        still applies its own checks (``isPartial``, ``timed_out``, error
        bodies). A poll that does not finish inside ``poll_timeout`` - or
        inside ``deadline_s``, when the caller set a shorter one (a group
        read's probe pass does) - deletes the server-side search and
        refuses as ``incomplete``. Between polls the broker's idle hook
        runs, when it gave one, so the broker answers while it waits.
        """
        limit = min(self.poll_timeout, deadline_s) if deadline_s else self.poll_timeout
        data = self.submit(cluster, body)
        if elastic.error_class(data) is not None:
            return data  # the scrubber turns it into an upstream_error refusal
        sid = data.get("id")
        deadline = time.monotonic() + limit
        try:
            while data.get("isRunning") is True:
                sid = self.search_id(data)
                if time.monotonic() >= deadline:
                    raise elastic.Refused("incomplete", (
                        f"response withheld: search did not finish in "
                        f"{limit:g}s; {elastic.INCOMPLETE_HINT}"))
                (self._idle or self._sleep)(self.poll_interval)
                data = self.poll_once(cluster, sid, body)
                if elastic.error_class(data) is not None:
                    return data
            return data
        finally:
            self.release(cluster, sid if isinstance(sid, str) else None)


# ---------------------------------------------------------------------------
# The bridge
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    cluster: str
    output: dict | None
    refused: str | None
    seconds: float
    hits_total: int | None = None
    hits_shown: int = 0
    text_queries: int = 0


class Bridge:
    """Compile, run on the right cluster, scrub, log. One case per instance.

    ``run`` is what a tool call will do. Everything under one lock: the
    scrubber is not thread-safe and the browser transport is serialised
    anyway. The decision log holds field names, ops, labels, counts and
    timings; never a value, never a raw reply.
    """

    def __init__(self, config: elastic.ElasticConfig, scrubber: elastic.EsScrubber,
                 session: KibanaSession, *, log_path: str | Path | None = None,
                 presence: dict | None = None,
                 group_spans: dict | None = None,
                 index: elastic.VocabularyIndex | None = None) -> None:
        self.config = config
        self.scrubber = scrubber
        #: (index, field) -> when the field was last seen present in that
        #: index, on a page or by an empty-result check. Field names and
        #: times only, so a broker may share one across its cases.
        self.presence: dict[tuple[str, str], float] = presence if presence is not None else {}
        #: index -> (narrowest window span in seconds whose text_groups
        #: sampling pass hit the search limit, when). Spans and times only,
        #: shared across a broker's cases like ``presence``, so a later
        #: wide group question splits past the doomed widths without paying
        #: the wait again. Pruned at GROUP_SPAN_TTL_S.
        self.group_spans: dict[str, tuple[float, float]] = \
            group_spans if group_spans is not None else {}
        self.session = session
        self.log_path = Path(log_path) if log_path else None
        self._lock = threading.Lock()
        self.outcomes: list[Outcome] = []
        #: the built vocabularies, by cluster. The bridge reads it; the
        #: broker builds it. None means no vocabulary at all (a site map
        #: with no learnable field, or a harness that does not want one).
        self.index = index
        #: what the last applied vocabulary held per cluster: counts only
        self.vocabulary: dict[str, dict] = {}
        #: measurement switch, set by nothing in the live path: with it off
        #: a count or histogram whose one search hits the limit is refused
        #: incomplete, as before esquery.read_in_pieces. Tests use it for
        #: the "before" figures.
        self.split_reads = True
        #: what a piece read's waiting and piece sizing are measured on:
        #: wall time in the live path; a harness on the stub passes the
        #: engine's simulated seconds
        self.read_clock = time.monotonic

    def cluster(self, name: str) -> elastic.Cluster:
        c = self.config.cluster(name) if isinstance(name, str) else None
        if c is None:
            raise elastic.Refused("bad_cluster", "cluster must be one of the configured names")
        return c

    def run(self, cluster_name: str, query: dict, *, probe: bool = True,
            tool: str | None = None) -> Outcome:
        """``tool`` is the MCP tool that made the call, for the log."""
        t0 = time.perf_counter()
        row: dict[str, Any] = {"schema": LOG_SCHEMA, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                               "cluster": cluster_name if isinstance(cluster_name, str) else "?"}
        if tool is not None:
            row["tool"] = tool
        outcome = Outcome(row["cluster"], None, None, 0.0)
        with self._lock:
            # what the case could use before this query: the page's growth
            # of both sets goes to the log as counts (es-review reads them)
            labels_before = len(self.scrubber.shown)
            keep_before = len(self.scrubber.shown_keep)
            try:
                cluster = self.cluster(cluster_name)
                # Compile first: a query the grammar refuses on its own keeps
                # its declared code whether the vocabulary is ready, building
                # or absent, and is refused before anything else happens.
                # Compiled on the bridge's clock, so the window bounds a
                # group read pieces by sit where the fixtures (and the
                # cluster) sit.
                compiled = esquery.compile_query(query, self.config, self.scrubber, now=clock())
                # Then the vocabulary (local, no request, once per case per
                # cluster; refuses vocabulary_building until it serves). If
                # this call is the one that applied it, compile again, so the
                # first query is gated against the cluster's names exactly as
                # every later one is - a learnt name in a keep literal is
                # refused here, with the same words, before any request.
                if self._apply_vocabulary(cluster):
                    compiled = esquery.compile_query(query, self.config, self.scrubber,
                                                     now=clock())
                row.update(_describe(query, compiled))
                # Every check has passed and the query will be sent: charge
                # its new phrases now, before the probe and the request, and
                # never refund them - a page withheld after the search (a
                # leak, a size cap) can depend on what the phrase matched,
                # so a refund would make that guess free.
                self.scrubber.spend_phrases(compiled.new_phrases)
                # the probe only for a query that will be sent
                if probe:
                    self.session.probe(cluster)
                # the whole {"params": {"index", "body"}} document: that is
                # what /internal/search/ese takes
                if compiled.group_read is not None:
                    # a text_groups read: a page's worth per request, every
                    # reply scrubbed with its own plan; a wide window is
                    # read in newest-first pieces when a pass hits the
                    # search limit, with the timed-out widths remembered
                    # across this broker's cases (spans only)
                    now = clock()
                    spans = {k: v[0] for k, v in self.group_spans.items()
                             if now - v[1] <= GROUP_SPAN_TTL_S}
                    try:
                        scrubbed, requests = esquery.read_text_groups(
                            lambda body, deadline_s=None: self.session.search(
                                cluster, body, deadline_s),
                            self.scrubber, compiled.group_read, slow_spans=spans,
                            search_limit_s=getattr(self.config, "poll_timeout_s", None),
                            clock=time.monotonic)
                    finally:
                        # keep what the timeouts taught even when the read
                        # was refused: that is what spares the next question
                        now = clock()
                        fresh = {k: ((v, now) if (old := self.group_spans.get(k)) is None
                                     or v < old[0] else old)
                                 for k, v in spans.items()}
                        self.group_spans.clear()
                        self.group_spans.update(fresh)
                    agg = scrubbed.output["aggregations"][compiled.group_read.groups.name]
                    row.update({"requests": requests, "sampled": agg.get("sampled"),
                                "exact": agg.get("exact"), "strata": agg.get("strata")})
                    for k in ("covered_share", "timeouts"):
                        if agg.get(k) is not None:
                            row[k] = agg[k]
                elif compiled.window is not None and self.split_reads:
                    # a closed window: one search as always, and only if it
                    # hits the limit, the window in newest-first pieces -
                    # summed when every aggregation adds up over time, the
                    # newest piece alone when one does not. The widths that
                    # timed out are remembered beside the group reads'
                    # (key count:<index>, spans only)
                    now = clock()
                    spans = {k: v[0] for k, v in self.group_spans.items()
                             if now - v[1] <= GROUP_SPAN_TTL_S}
                    try:
                        scrubbed, requests = esquery.read_in_pieces(
                            lambda body, deadline_s=None: self.session.search(
                                cluster, body, deadline_s),
                            self.scrubber, compiled, self.config.time_field,
                            slow_spans=spans,
                            search_limit_s=getattr(self.config, "poll_timeout_s", None),
                            clock=self.read_clock)
                    finally:
                        now = clock()
                        fresh = {k: ((v, now) if (old := self.group_spans.get(k)) is None
                                     or v < old[0] else old)
                                 for k, v in spans.items()}
                        self.group_spans.clear()
                        self.group_spans.update(fresh)
                    pieces = scrubbed.output.get("pieces")
                    if pieces is not None:
                        # counts, shares and a mode word: never a value
                        row.update({"requests": requests, "pieces": pieces["pieces"],
                                    "piece_read": pieces["read"],
                                    "covered_share": pieces["covered_share"],
                                    "timeouts": pieces["timeouts"]})
                else:
                    envelope = self.session.search(cluster, compiled.body)
                    scrubbed = self.scrubber.scrub_response(envelope, compiled.plan)
                outcome.output = scrubbed.output
                total = scrubbed.output.get("hits", {}).get("total") or {}
                outcome.hits_total = total.get("value") if isinstance(total, dict) else None
                outcome.hits_shown = len(scrubbed.output.get("hits", {}).get("hits", []))
                outcome.text_queries = len(compiled.text_queries)
                if outcome.hits_shown:
                    self._remember_fields(query.get("index"), scrubbed.output)
                if outcome.hits_total == 0:
                    # what the zero means: about the fields, never the value
                    empty = self._explain_empty(cluster, query)
                    if empty is not None:
                        scrubbed.output["empty"] = empty
                        row["empty_check"] = {"requests": empty["requests"],
                                              "seconds": empty["seconds"],
                                              "fields": {f: x["status"]
                                                         for f, x in empty["fields"].items()},
                                              "window_documents": empty.get("window_documents")}
                row.update({"hits_total": outcome.hits_total, "hits_shown": outcome.hits_shown,
                            "dropped_fields": scrubbed.stats.get("dropped_fields", 0),
                            # how many labels and keep values this page made
                            # usable, and the running totals: counts only
                            "new_labels": len(self.scrubber.shown) - labels_before,
                            "new_keep_values": len(self.scrubber.shown_keep) - keep_before,
                            "labels_usable": len(self.scrubber.shown),
                            "keep_values_usable": len(self.scrubber.shown_keep),
                            # the typed phrases whose filter or bucket found
                            # nothing: Claude's own words, already in
                            # text_queries, so the log holds nothing new
                            "zero_hit_phrases": _zero_hit_phrases(query, scrubbed.output)})
                # only on rows that use not or any_of, so every other row
                # is written exactly as before
                if _negated(query.get("filters")) or _alternatives(query.get("filters")):
                    row["unjudged_phrases"] = _unjudged_phrases(query, scrubbed.output)
                    row["negated_phrases"] = _negated_phrases(query)
            except elastic.Refused as e:
                outcome.refused = e.code
                row["refused"] = e.code
                if e.label is not None:
                    # the label Claude typed, never the value behind it:
                    # this is how a case guessing at labels is visible at
                    # all, and a guess is refused before any request
                    row["label"] = e.label
                raise
            finally:
                outcome.seconds = round(time.perf_counter() - t0, 3)
                row["seconds"] = outcome.seconds
                # counts only: where the case stands against its budget
                row.update(self.scrubber.phrase_report())
                self.outcomes.append(outcome)
                self._log(row)
        return outcome

    # -- an empty result: what the zero means ------------------------------

    def _remember_fields(self, index: Any, output: dict) -> None:
        """Every field a page showed non-empty is present in this index:
        remembered for PRESENCE_TTL_S, so a later zero on it needs no
        window check. Field names and a time, nothing else."""
        if not isinstance(index, str):
            return
        now = clock()
        for h in output.get("hits", {}).get("hits", []) or []:
            for path, value in _leaf_paths(h.get("_source") if isinstance(h, dict) else None):
                if value not in (None, "", [], {}):
                    self.presence[(index, path)] = now

    def _presence_count(self, cluster: elastic.Cluster, query: dict,
                        filters: list[dict]) -> int | None:
        """Documents in the query's index and window matching ``filters``,
        counted up to EMPTY_CHECK_CAP. The same compile as any query (label
        rules, caps; the phrases are the query's own, already spent, so
        nothing is charged), then one request with its total capped. None
        when the check itself is refused or fails."""
        probe: dict[str, Any] = {"index": query["index"], "size": 0, "filters": filters}
        if "time_range" in query:
            probe["time_range"] = query["time_range"]
        try:
            compiled = esquery.compile_query(probe, self.config, self.scrubber)
            compiled.body["params"]["body"]["track_total_hits"] = EMPTY_CHECK_CAP
            envelope = self.session.search(cluster, compiled.body)
            out = self.scrubber.scrub_response(envelope, compiled.plan).output
        except elastic.Refused:
            return None
        total = (out.get("hits") or {}).get("total") or {}
        return total.get("value") if isinstance(total.get("value"), int) else None

    def _explain_empty(self, cluster: elastic.Cluster, query: dict) -> dict | None:
        """Why a filtered query found nothing, as facts about its fields.

        Two questions per filtered field, each one capped count
        (``_presence_count``), asked in an order that stops early:

        1. Is the field filled **anywhere in this index and window**? A
           field remembered present in the index within PRESENCE_TTL_S (a
           page showed it, or an earlier check found it) costs no request.
           A field absent from the whole window explains the zero on its
           own - its filter cannot match here, whatever it says - and the
           other fields are not asked about their scope, since that scope
           is empty because of it.
        2. Otherwise, is it filled on the documents the **other plain
           filters** leave? Present: the filter on it matched none of them
           (a real zero for that filter). Absent: the fields never meet on
           one document in this window.

        Fields inside ``any_of`` are checked like plain ones; ``not`` and
        ``any_of`` filters are left out of the "other filters" scope. A
        present field is confirmed at the first hundred documents and an
        absent one has no postings, so the whole check is a few requests
        and milliseconds where the old one counted every document in the
        window per field (30-39 s a day on a real cluster). **Nothing here
        is about the value**: statuses, counts and sentences name fields,
        and a filter's own value never enters its field's count.
        """
        t0 = time.perf_counter()
        plain = [f for f in query.get("filters") or [] if isinstance(f, dict)
                 and "not" not in f and "any_of" not in f and isinstance(f.get("field"), str)]
        inner = [x for f in query.get("filters") or [] if isinstance(f, dict)
                 for x in (f.get("any_of") or []) if isinstance(x, dict)
                 and isinstance(x.get("field"), str)]
        fields = list(dict.fromkeys([f["field"] for f in plain] + [x["field"] for x in inner]))
        index = query.get("index")
        requests = 0
        now = clock()
        result: dict[str, dict] = {}
        window_total: int | None = None
        if not fields:
            window_total = self._presence_count(cluster, query, [])
            requests += 1
        # 1. anywhere in the window
        asked = False
        for name in fields:
            exists = {"field": name, "op": "exists"}
            if now - self.presence.get((index, name), -1e18) < PRESENCE_TTL_S:
                result[name] = {"status": "present_in_window", "in_index": "remembered within the hour"}
                continue
            n_win = self._presence_count(cluster, query, [exists])
            requests += 1
            asked = True
            if n_win is None:
                result[name] = {"status": "unknown"}
            elif n_win > 0:
                self.presence[(index, name)] = now
                result[name] = {"status": "present_in_window",
                                "in_index": (f">={EMPTY_CHECK_CAP}" if n_win >= EMPTY_CHECK_CAP
                                             else n_win)}
            else:
                result[name] = {"status": "absent_in_window", "in_index": 0}
        if fields and not asked:
            # every field came from memory, which is about the index, not
            # this window: one capped count says whether the window holds
            # anything at all before the fields are called present here
            window_total = self._presence_count(cluster, query, [])
            requests += 1
        if any(x["status"] == "absent_in_window" for x in result.values()):
            # explained; is there anything in the window at all?
            if window_total is None:
                window_total = self._presence_count(cluster, query, [])
                requests += 1
        elif fields and window_total != 0 \
                and all(x["status"] == "present_in_window" for x in result.values()):
            # 2. on the documents the other plain filters leave
            left: dict[str, int | None] = {}
            for name in fields:
                others = [f for f in plain if f.get("field") != name]
                if not others:
                    result[name]["status"] = "present"
                    result[name]["scope"] = "window"
                    continue
                n_scope = self._presence_count(cluster, query, others + [{"field": name,
                                                                          "op": "exists"}])
                requests += 1
                result[name]["scope"] = "other filters"
                if n_scope is None:
                    result[name]["status"] = "unknown"
                elif n_scope > 0:
                    result[name]["status"] = "present"
                    result[name]["docs_with_field"] = (f">={EMPTY_CHECK_CAP}"
                                                       if n_scope >= EMPTY_CHECK_CAP else n_scope)
                else:
                    # none carry it among what the others leave - or the
                    # others leave nothing, in which case this field is not
                    # the reason (one count per distinct set of others)
                    key = json.dumps(others, sort_keys=True)
                    if key not in left:
                        left[key] = self._presence_count(cluster, query, others)
                        requests += 1
                    if left[key] == 0:
                        result[name]["status"] = "others_empty"
                    elif left[key] is None:
                        result[name]["status"] = "unknown"
                    else:
                        result[name]["status"] = "absent_in_scope"
                        result[name]["docs_with_field"] = 0
                        result[name]["others_leave"] = (f">={EMPTY_CHECK_CAP}"
                                                        if left[key] >= EMPTY_CHECK_CAP else left[key])
        empty: dict[str, Any] = {"fields": result, "requests": requests,
                                 "seconds": round(time.perf_counter() - t0, 3),
                                 "meaning": _empty_meaning(result, window_total, bool(fields))}
        if window_total is not None:
            empty["window_documents"] = (f">={EMPTY_CHECK_CAP}" if window_total >= EMPTY_CHECK_CAP
                                         else window_total)
        return empty

    def _apply_vocabulary(self, cluster: elastic.Cluster) -> bool:
        """Give this case the names the bridge already read for the cluster.

        No request: the build happened on the bridge's serve loop, a day's
        slice at a time, newest first. A case is refused with
        ``vocabulary_building`` only until the **recent** slices are saved
        (``ClusterVocabulary.serves``); after that it runs while the older
        slices are still being read, because waiting for the whole
        retention period is hours. A name logged only in a day not yet
        covered is not known - the VOCAB line is where the covered range
        is visible. Logged as counts, never a name. True if this call
        applied it (the caller then gates the query again).
        """
        if self.index is None:
            return False
        vocab = self.index.get(cluster.name)
        t = clock()
        # the fields a case waits for: a field back from over the cap is
        # read but not waited for until it serves (VocabularyIndex.returning)
        read = self.index.wait_set(cluster.name, self.config, t)
        if self.scrubber._vocab_rules and vocab is not None \
                and vocab.behind(self.config, t, read):
            # every query, not only a case's first: the gap is a property of
            # the cover now, and an open case is refused the same way. The
            # end is the earliest end among the fields behind: field names
            # and ranges, nothing about this query.
            cu = self.index.catch_up(cluster.name, self.config, t) or {}
            bound = elastic.vocabulary_max_gap(self.config)
            ends = min(vocab.covers[f][1] for f in read
                       if f in vocab.covers and t - vocab.covers[f][1] > bound)
            gap_h = (t - ends) / 3600.0
            raise elastic.Refused(
                "vocabulary_building",
                "response withheld: the name vocabulary for this cluster ends "
                f"{gap_h:.1f}h ago for {', '.join(cu.get('fields') or read)}, past the "
                f"{bound / 3600.0:.1f}h bound, so a name first logged since then has not been "
                "read and could be plain text on this page. Waiting for the top-up that reads "
                f"{elastic._iso(ends)} to now: " + _catch_up_note(cu)
                + "; es-smoke's VOCAB line shows its progress.")
        applied = self.scrubber._vocabulary_at.get(cluster.name)
        if applied is not None and (vocab is None or applied[1] == vocab.covers):
            # this case already holds exactly this cover; a newer one (a
            # top-up or a backfill slice since) is applied again below,
            # locally, before the page
            return False
        if not self.scrubber._vocab_rules:
            return False
        if read and (vocab is None or not vocab.serves(self.config, t, read)):
            raise elastic.Refused(
                "vocabulary_building",
                "response withheld: the name vocabulary for this cluster does not yet cover "
                f"the last {elastic.VOCABULARY_SERVE_DAYS} days for every field it reads (it "
                "is read in one-day slices, newest first, and a page shown before those are "
                "in could leak a customer name in message text). "
                + _backfill_note({f: b for f, b in
                                  self.index.backfill(cluster.name, self.config, t).items()
                                  if b.get("waited", True)})
                + ". Try again shortly; es-smoke's VOCAB line shows how far back each "
                "field's cover reaches.")
        over_cap = {f: int(v["count"])
                    for f, v in self.index.over_cap_fields(cluster.name, clock()).items()}
        counts = self.scrubber.apply_vocabulary(cluster.name, vocab, over_cap=over_cap)
        report = {**self.index.report(cluster.name, self.config, now=clock()),
                  "fields": {f: n for f, n in counts.items() if f not in over_cap},
                  "skipped": dict(self.scrubber.vocabulary_skipped)}
        self.vocabulary[cluster.name] = report
        self._log({"schema": LOG_SCHEMA, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "cluster": cluster.name, "vocabulary": "applied", **report})
        return True

    def seed(self, term: str) -> dict:
        """Add a name to this case while its session runs: the human's step.

        ``term`` is as ``--term`` takes it (a name, or ``TYPE=VALUE``). The
        value is labelled, seeded (it matches inside keep values, as a
        seed does) and marked shown, so Claude may use the label as soon
        as it has it. Reached only through the broker's socket (es-seed),
        never through a tool: a value-to-label step Claude could trigger
        would let it confirm a guess with a count. The decision log gets a
        row with the label, its type, whether the case already held a label
        for the value, how many queries had run, and **never the value**;
        es-review reads those rows back as the human's steps. A case holds
        at most ``_MAX_SEEDS`` seeded names over its life.
        """
        value, etype = parse_term(self.config, term)
        with self._lock:
            label = self.scrubber.known.get(jsonscrub._norm(value))
            known_before = label is not None
            already = label is not None and label in self.scrubber.seeded_labels
            if not already and len(self.scrubber.seeded_labels) >= _MAX_SEEDS:
                raise elastic.Refused("bad_request", f"this case already holds {_MAX_SEEDS} seeded "
                                                     "names, the most a case may; open a new case")
            label = self.scrubber.seed(value, etype)
            row = {"schema": LOG_SCHEMA, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "event": "seed", "label": label, "type": self.scrubber.types.get(label, etype),
                   "known_before": known_before, "already_seeded": already,
                   "queries_before": len(self.outcomes),
                   "seeded_total": len(self.scrubber.seeded_labels)}
            self._log(row)
        return {k: row[k] for k in ("label", "type", "known_before", "already_seeded",
                                    "queries_before", "seeded_total")}

    def _log(self, row: dict) -> None:
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _phrases_of(filters: Any) -> list[str]:
    return [f["value"] for f in filters or [] if isinstance(f, dict)
            and f.get("op") == "phrase" and isinstance(f.get("value"), str)]


def _negated(filters: Any) -> list[dict]:
    return [f["not"] for f in filters or [] if isinstance(f, dict)
            and isinstance(f.get("not"), dict)]


def _alternatives(filters: Any) -> list[list]:
    return [f["any_of"] for f in filters or [] if isinstance(f, dict)
            and isinstance(f.get("any_of"), list)]


def _unjudged_phrases(query: dict, output: dict) -> list[str]:
    """The phrases whose own hit this row cannot say: every phrase inside a
    ``not`` (zero documents means it matched everything in scope; some
    documents says nothing about whether it matched any), and every phrase
    in an ``any_of`` of two or more when the page found something (one of
    them matched, the row cannot say which). Claude's own words, already in
    ``text_queries``; es-review reads them (see its zero_hit_phrases)."""
    filters = query.get("filters")
    out = _phrases_of(_negated(filters))
    total = (output.get("hits") or {}).get("total") or {}
    if not (isinstance(total, dict) and total.get("value") == 0):
        for alts in _alternatives(filters):
            if len(alts) > 1:
                out.extend(_phrases_of(alts))
    return out


def _negated_phrases(query: dict) -> list[str]:
    return _phrases_of(_negated(query.get("filters")))


def _zero_hit_phrases(query: dict, output: dict) -> list[str]:
    """The phrases in this query whose filter (the page) or whose bucket (a
    filters aggregation, at any depth under filters aggregations) matched
    nothing. What a guess that failed looks like in the log; a count of
    them per case is what es-review reads."""
    out: list[str] = []
    total = (output.get("hits") or {}).get("total") or {}
    if isinstance(total, dict) and total.get("value") == 0:
        out.extend(_phrases_of(query.get("filters")))
        # nothing matched any alternative, so each alternative found
        # nothing; a phrase inside a not is never zero-hit (no documents
        # means it matched all of them)
        for alts in _alternatives(query.get("filters")):
            out.extend(_phrases_of(alts))

    def walk(specs: Any, node: Any) -> None:
        if not isinstance(specs, dict) or not isinstance(node, dict):
            return
        for name, spec in specs.items():
            if not isinstance(spec, dict) or spec.get("type") != "filters":
                continue
            buckets = (node.get(name) or {}).get("buckets")
            if not isinstance(buckets, dict):
                continue
            for bname, flt in (spec.get("filters") or {}).items():
                b = buckets.get(bname)
                if isinstance(b, dict) and b.get("doc_count") == 0:
                    out.extend(_phrases_of(flt))
                if isinstance(b, dict):
                    walk(spec.get("aggs"), b)

    walk(query.get("aggs"), output.get("aggregations") or {})
    return out


def _describe(query: dict, compiled: esquery.Compiled) -> dict:
    """The decision-log view of a query: shape, not content."""
    def shape(f: dict) -> dict:
        return {"field": f.get("field"), "op": f.get("op")}

    filters = []
    for f in query.get("filters") or []:
        if not isinstance(f, dict):
            continue
        if isinstance(f.get("not"), dict):
            filters.append({"op": "not", "filters": [shape(f["not"])]})
        elif isinstance(f.get("any_of"), list):
            filters.append({"op": "any_of", "filters": [shape(x) for x in f["any_of"]
                                                        if isinstance(x, dict)]})
        else:
            filters.append(shape(f))

    def agg_shape(aggs: Any) -> list[dict]:
        out = []
        for name, spec in (aggs or {}).items() if isinstance(aggs, dict) else []:
            if isinstance(spec, dict):
                out.append({"name": name, "type": spec.get("type"), "field": spec.get("field"),
                            "aggs": agg_shape(spec.get("aggs"))})
        return out

    return {
        "index": query.get("index"), "size": query.get("size", 10),
        "time_range": query.get("time_range"), "filters": filters,
        "aggs": agg_shape(query.get("aggs")),
        "labels_used": sorted(set(compiled.labels_used)),
        # the phrase as Claude wrote it: labels, not values. The declared channel.
        "text_queries": compiled.text_queries,
    }


def _leaf_paths(node: Any, prefix: str = ""):
    """(dotted path, value) for every scalar or list leaf of a source."""
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                yield from _leaf_paths(v, path)
            else:
                yield path, v


def _empty_meaning(fields: dict[str, dict], window_total: int | None, had_fields: bool) -> str:
    """One sentence per finding, about fields and counts; the filter's
    value is never mentioned."""
    if window_total == 0:
        return ("no document in this index and window at all: the 0 says nothing about the "
                "filters")
    if not had_fields:
        return "no filter and no document: the window holds nothing"
    absent = [n for n, x in fields.items() if x["status"] == "absent_in_window"]
    if absent:
        return ("; ".join(f"{n} is not filled on any document in this index and window: its "
                          "filter cannot match here, whatever it says" for n in absent)
                + "; the other filtered fields were not checked further, since that filter "
                  "alone empties the result")
    parts = []
    present = [n for n, x in fields.items() if x["status"] == "present"]
    if present and all(x["status"] in ("present", "others_empty") for x in fields.values()):
        return ("; ".join(
            f"{n} is filled on the documents the other filters leave"
            + (f" ({fields[n]['docs_with_field']} carry it)" if "docs_with_field" in fields[n]
               else "")
            + ": the filter on it matched none of them" for n in present)
            + " - a real zero for that filter (for a keep field, check its spellings with a "
              "terms aggregation; for a phrase, try fewer words)")
    for name, x in fields.items():
        if x["status"] == "absent_in_scope":
            parts.append(f"{name} is filled in this index ({x.get('in_index')} documents in the "
                         f"window carry it) but on none of the {x.get('others_leave')} documents "
                         "the other filters leave: the filtered fields never meet on one "
                         "document here; drop or widen the other filters to find out")
        elif x["status"] == "present":
            parts.append(f"{name} is filled on the documents the other filters leave: the "
                         "filter on it matched none of them")
        elif x["status"] == "unknown":
            parts.append(f"the check for {name} was refused; the 0 is unexplained")
    return "; ".join(parts) if parts else "the 0 is unexplained"


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------


#: Aggregation names the smoke query uses; fixed so the summary can find them.
COUNT_AGG = "count_by"
TIME_AGG = "per_interval"
#: beside the terms aggregation: how many matching documents have the field
COUNT_FIELD_AGG = "count_by_field"
#: the zero-hit check: per filtered field, documents in scope and with the field
PHRASE_FIELD_AGG = "field_check"
_TYPED_SEED = re.compile(r"^([A-Z][A-Z0-9_]*)=(.+)$", re.DOTALL)


def default_phrase_field(config: elastic.ElasticConfig) -> str | None:
    """The first text rule in the site map: what --phrase searches unless
    --phrase-field names another."""
    return next((r.pattern for r in config.fields if r.kind == "text"), None)


def smoke_query(config: elastic.ElasticConfig, index: str | None = None,
                phrase: str | list[str] | None = None, size: int = 3, *,
                since: str = "now-1h", until: str = "now", count_by: str | None = None,
                interval: str | None = None, buckets: int = 10,
                phrase_field: str | None = None,
                eq: list[tuple[str, str]] | tuple = ()) -> dict:
    """The grammar request for one smoke run.

    Nothing is validated here on purpose: times, fields, values, intervals
    and sizes go to ``esquery`` as given, so a bad one is the grammar's
    refusal (and a decision-log row), never a CLI-side special case. Every
    filter is ANDed: each ``eq`` pair, then each phrase on ``phrase_field``.
    """
    phrases = [phrase] if isinstance(phrase, str) else list(phrase or [])
    q: dict[str, Any] = {"index": index or config.indices[0],
                         "time_range": {"gte": since, "lte": until}, "size": size}
    filters = [{"field": f, "op": "eq", "value": v} for f, v in eq]
    if phrases:
        # no text rule at all: the field is None and the grammar refuses it,
        # rather than the phrase being dropped and the query widened
        field = phrase_field or default_phrase_field(config)
        filters += [{"field": field, "op": "phrase", "value": p} for p in phrases]
    if filters:
        q["filters"] = filters
    hist = ({TIME_AGG: {"type": "date_histogram", "field": config.time_field,
                        "interval": interval}} if interval is not None else {})
    if count_by is not None:
        terms: dict[str, Any] = {"type": "terms", "field": count_by, "size": buckets}
        if hist:
            terms["aggs"] = hist
        q["aggs"] = {COUNT_AGG: terms,
                     COUNT_FIELD_AGG: {"type": "filters", "filters": {
                         "present": [{"field": count_by, "op": "exists"}]}}}
    elif hist:
        q["aggs"] = hist
    return q


def _phrase_filters(query: dict) -> list[dict]:
    return [f for f in query.get("filters") or [] if isinstance(f, dict) and f.get("op") == "phrase"]


def field_probe(query: dict, *, max_buckets: int = elastic.DEFAULT_MAX_BUCKETS
                ) -> tuple[list[dict], list[str]] | None:
    """The check behind a zero-hit filtered query, as grammar queries.

    For each filtered field F, ``filters`` buckets over the same index and
    window: ``s<i>``, the documents the *other* filters leave; ``f<i>``,
    those of them that have F at all; and ``w<i>``, the documents in the
    window that have F, for when the other filters leave nothing to look
    in. F's own phrases and values are never in F's buckets, so the answer
    is about the field, not about the guess.

    The check must never be refused for a query that was allowed. Every
    filter in it is one of the query's own, so its distinct phrases are a
    subset of the query's and fit the same phrase cap; the bucket count
    grows with the number of fields, so the buckets are split across as
    many queries as ``max_buckets`` needs. Returns the queries and the
    field order.
    """
    filters = [f for f in query.get("filters") or [] if isinstance(f, dict)]
    if any("not" in f or "any_of" in f for f in filters):
        # not and any_of are refused inside a filters aggregation, so the
        # check could not be built from them without being refused itself:
        # no check rather than a refused one (es-smoke never builds them)
        return None
    fields = list(dict.fromkeys(f.get("field") for f in filters))
    if not fields:
        return None
    buckets: list[tuple[str, list]] = []
    for i, name in enumerate(fields):
        others = [f for f in filters if f.get("field") != name]
        exists = {"field": name, "op": "exists"}
        if others:
            buckets += [(f"s{i}", others), (f"w{i}", [exists])]
        buckets.append((f"f{i}", others + [exists]))
    step = max(1, max_buckets)
    probes = []
    for at in range(0, len(buckets), step):
        probe: dict[str, Any] = {"index": query["index"], "size": 0, "aggs": {PHRASE_FIELD_AGG: {
            "type": "filters", "filters": dict(buckets[at:at + step])}}}
        if "time_range" in query:
            probe["time_range"] = query["time_range"]
        probes.append(probe)
    return probes, fields


def run_smoke(run, query: dict, *, max_buckets: int = elastic.DEFAULT_MAX_BUCKETS) -> dict:
    """One smoke run through ``run`` (query -> report). A zero-hit result
    comes back already explained by the bridge (``output["empty"]``, see
    ``Bridge._explain_empty``), so there is nothing to add here;
    ``print_smoke`` turns "a filtered field is not filled here" into EMPTY
    and exit code 3. ``max_buckets`` is kept for callers."""
    return run(query)


def seed_terms(config: elastic.ElasticConfig, scrubber: elastic.EsScrubber,
               terms: list[str]) -> list[str]:
    """Seed the case with values the human typed locally; returns their labels.

    ``Contoso Holdings`` seeds an organisation. ``SERVER_NAME=ctr-amer-042``
    seeds a value of that identifier type, so a label for it exists in this
    case and ``--eq agent.name=<that label>`` can filter by it (identifier
    fields take labels only, and each run is a fresh case). The same terms
    in the same order give the same labels on every run.
    """
    return [scrubber.seed(*parse_term(config, t)) for t in terms]


def parse_term(config: elastic.ElasticConfig, term: str) -> tuple[str, str]:
    """``(value, type)`` for one ``--term``: a bare name is an organisation,
    ``TYPE=VALUE`` an identifier type the site map declares."""
    if not isinstance(term, str) or not 0 < len(term) <= 128:
        raise elastic.Refused("bad_request", "a term is a string of up to 128 characters")
    m = _TYPED_SEED.match(term)
    if m is None:
        return term, "ORG_NAME"
    types = {"ORG_NAME"} | {r.type for r in config.fields if r.kind == "identifier"}
    if m.group(1) not in types:
        raise elastic.Refused("bad_request", f"a typed term needs an identifier type from the "
                                             f"site map: {sorted(types)}")
    return m.group(2), m.group(1)


def run_case(bridge: Bridge, cluster: str, query: dict, *, show_names: bool = False) -> dict:
    """One query through a bridge, as the JSON report ``print_smoke`` reads.
    The same report comes back from the broker, so a run prints the same
    whether it happened in this process or in the long-lived one.

    ``show_names`` is the operator asking, out loud, for the words behind
    the readable-word labels. Off by default and off in every automated
    path: es-smoke's output is read by scripts and agents as well as
    people, so a real customer name must never arrive there unasked. With
    it off the words are not in the report at all, not merely unprinted.
    """
    try:
        o = bridge.run(cluster, query)
    except elastic.Refused as e:
        return {"refused": {"code": e.code, "message": e.message},
                "vocabulary": bridge.vocabulary.get(cluster),
                "phrases": bridge.scrubber.phrase_report()}
    s = bridge.scrubber
    # Names that are ordinary words: labelled in their own field, readable
    # as English on every other document. The label and the field it came
    # from are decisions, so they are always reported - enough to go and
    # look the name up, and to seed it once you have. The word itself is
    # data and waits for show_names.
    readable = [{"label": lab, "field": s.readable_fields.get(lab, "?")}
                for lab in sorted(s.readable_words)]
    report = {"refused": None, "output": o.output, "hits_total": o.hits_total,
              "hits_shown": o.hits_shown, "seconds": o.seconds,
              "labels_issued": len(s.mapping), "dropped": sorted(s.dropped),
              "readable_words": readable,
              "phrases": s.phrase_report(),
              "vocabulary": bridge.vocabulary.get(cluster)}
    if show_names:
        report["readable_names"] = sorted(s.readable_words.values())
    return report


def _over_cap_note(v: dict) -> str:
    """The fields a build counted and did not read, with their counts.

    This is the only place a user is told that a real name field is
    unreadable in message text because it has more distinct values than
    ``vocabulary.max`` - nothing refuses, nothing else says it, and the
    names are simply there in the text. Field names and counts.
    """
    over = v.get("over_cap") or {}
    if not over:
        return ""
    return (" OVER CAP, NOT READ (readable in text): "
            + ", ".join(f"{f}~{n}>{v.get('max', '?')}" for f, n in sorted(over.items())))


def _backfill_note(bf: dict | None) -> str:
    """The fields still short of the serving rule, each with the days it
    covers, the slices left before it serves (and before the whole of
    ``vocabulary.days``), the range read next and whether that slice is
    running: field names, counts and ranges only. Nothing in it depends on
    a query, so a refusal carrying it says nothing about a guess."""
    if not bf:
        return "waiting for the next slice"
    # Fields in the same state share one sentence. A first build has every
    # field at the same point, and ten identical sentences on every progress
    # line buried what mattered (a real site printed them over a thousand
    # times); one field keeps exactly the sentence it had.
    groups: dict[str, list[str]] = {}
    for f, b in sorted(bf.items()):
        rng = b.get("reading") or ["?", "?"]
        state = ("running" if b.get("running") else
                 f"last attempt failed ({b['failed']}), {b['attempts']} attempts since "
                 f"{b['failing_since']}, next try {b['next_try']}" if b.get("attempts") else
                 f"last attempt failed ({b['failed']}), retrying" if b.get("failed") else "next")
        tail = ("" if b.get("waited", True) else
                "; back from over the cap, cases do not wait for {it} and {its} values "
                "stay readable in text until {it} serve{s}")
        if b.get("recount"):
            text = ("{F} not read since {it} came back from over the cap: {its} next slice "
                    f"recounts {{it}} against the cap and, if {{it}} fit{{s}}, reads {{its}} first "
                    f"day ({state}); {b['slices_left']} one-day slices before {{it}} serve{{s}}"
                    + tail)
        else:
            text = (f"{{F}} cover{{s}} {b['covered_days']}d, {b['slices_left']} one-day slices "
                    f"left before {{it}} serve{{s}} and {b['slices_total']} to the full cover, "
                    f"reading {rng[0]} to {rng[1]} ({state})" + tail)
        groups.setdefault(text, []).append(f)
    parts = []
    for text, fields in groups.items():
        if len(fields) == 1:
            parts.append(text.format(F=fields[0], it="it", its="its", s="s"))
        else:
            parts.append(text.format(F=f"{len(fields)} fields ({', '.join(fields)}) each",
                                     it="they", its="their", s=""))
    return "BACKFILLING " + "; ".join(parts)


def _stuck_note(v: dict) -> str:
    """Returning fields failing past VOCABULARY_RETURNING_STUCK_S. Cases are
    served; this is the loud form of what the backfill note says."""
    stuck = v.get("stuck") or {}
    if not stuck:
        return ""
    return (" STUCK, NOT READ (readable in text): "
            + ", ".join(f"{f} failing since {x['since']}, {x['attempts']} attempts ({x['code']}), "
                        f"next try {x['next_try']}" for f, x in sorted(stuck.items())))


def _reach_note(v: dict) -> str:
    """How far back the cover reaches and why it stops there, once an
    extension slice (older days for fields that already serve) has failed
    or been narrowed. Cases are served throughout; this says which days a
    name can be known from. Ranges, widths, counts and a code only."""
    r = v.get("reach")
    if not r or r.get("complete"):
        return ""
    head = f" COVER REACHES {r['from']} ({r['days']}d of {r['wanted_days']}d)"
    if r.get("stopped"):
        why = ("did not fit vocabulary.budget_s" if r["code"] == "vocabulary"
               else f"could not be read ({r['code']})")
        return (head + f": STOPS THERE - an older slice of {r['width_h']:g}h, the narrowest, "
                f"{why}, {r['attempts']} attempts since {r['since']}, next try "
                f"{r['next_try']}; names logged only before {r['from']} are not known"
                + (" except the ones read before the catch-up jump (below)"
                   if v.get("held_over") else ""))
    if r.get("attempts"):
        return (head + f": older days are slower to read; the last older slice failed "
                f"({r['code']}), {r['attempts']} attempts since {r['since']}, next try "
                f"{r['next_try']} at {r['width_h']:g}h")
    return head + f": older days read {r['width_h']:g}h at a time (a day did not fit the budget)"


def _held_over_note(v: dict) -> str:
    """After a catch-up jump: the names read before the break are still
    hidden, and the gap between that cover and the new one is not read
    yet. Field names and ranges only."""
    held = v.get("held_over") or {}
    if not held:
        return ""
    return (" CATCH-UP JUMPED, GAP NOT READ YET (names logged only then are readable "
            "until the build reaches their day): "
            + ", ".join(f"{f} {x['gap'][0]} to {x['gap'][1]} ({x['gap_days']}d; names read "
                        f"{x['names_from']} to {x['names_to']} still hidden)"
                        for f, x in sorted(held.items())))


def _frozen_note(v: dict) -> str:
    """Fields read under an earlier field set and no longer read: their
    names are kept and still hidden, as far as the range says, and nothing
    logged since is known. Field names and ranges."""
    frozen = v.get("frozen") or {}
    if not frozen:
        return ""
    return (" NOT READ NOW (names read before still hidden): "
            + ", ".join(f"{f} {a} to {b}" for f, (a, b) in sorted(frozen.items())))


def _catch_up_note(cu: dict | None) -> str:
    """Slices left and the range being read: counts and ranges only."""
    if not cu:
        return "waiting for the next slice"
    if cu.get("expired"):
        head = (f"the saved cover is older than vocabulary.days and is dropped; a fresh build "
                f"reads {cu['slices_left']} one-day slices first")
    else:
        head = f"{cu['slices_left']} of {cu['slices_total']} one-day slices left"
        if cu.get("fields"):
            head += f" for {', '.join(cu['fields'])}"
    rng = cu.get("reading") or ["?", "?"]
    state = ("running" if cu.get("running") else
             f"last attempt failed ({cu['failed']}), retrying" if cu.get("failed") else "next")
    return f"{head}, reading {rng[0]} to {rng[1]} ({state})"


def vocabulary_line(v: dict | None) -> str | None:
    """How close each vocabulary field is to its cap: counts, never values.

    ``NOT READ`` names the identifier fields a vocabulary could hold that
    this site map's ``vocabulary.fields`` leaves out, and ``OVER CAP, NOT
    READ`` the ones a build counted and found too wide to read - their
    values stay readable in message text, which is a choice worth seeing.
    Field names and counts only.
    """
    if not v:
        return None
    if v.get("building"):
        b = v["building"]
        done, total = b["fields_done"], b["fields_total"]
        covered = (f"covering {v['covered_days']}d of {v.get('wanted_days', '?')}d, "
                   f"{'serving cases' if v.get('serving') else 'no case yet'}; "
                   if v.get("covered_days") is not None else "")
        return (f"VOCAB    {covered}slice {done}/{total} fields, {b['requests']} requests, "
                f"{b['seconds']:g}s of {b['budget_s']:g}s a slice"
                + (f", reading {b['field']}" if b.get("field") else "")
                + (f", values so far {b['values']}" if b.get("values") else "")
                + (f"; CATCHING UP, cases refused: {_catch_up_note(v['catch_up'])}"
                   if v.get("catch_up") else "")
                + (f"; {_backfill_note(v['backfill'])}"
                   + ("" if v.get("serving") else ", cases refused")
                   if v.get("backfill") else "")
                + _over_cap_note(v) + _frozen_note(v) + _stuck_note(v) + _reach_note(v)
                + _held_over_note(v))
    if v.get("state") == "failed":
        return (f"VOCAB    build stopped: {v.get('refused')}; no case can run until one finishes"
                + _over_cap_note(v))
    if not v.get("fields"):
        if v.get("state") != "building":
            return ("VOCAB   " + _over_cap_note(v)) if v.get("over_cap") else None
        return "VOCAB    building, no page yet" + _over_cap_note(v)
    # a field whose own cover differs from the cluster figure shows its
    # own days beside its count: the cluster figure is what every field
    # covers, and nothing claims a field covered for days it was not read
    days = v.get("covers_days") or {}
    parts = [f"{f}={n}/{v['max']}"
             + (f" ({days[f]}d)" if f in days and days[f] != v.get("covered_days") else "")
             for f, n in v["fields"].items() if f not in (v.get("over_cap") or {})]
    line = "VOCAB    " + " ".join(parts)
    if v.get("covered_days") is not None:
        # the covered range is the one number that says which days a name
        # can be known from at all: a name logged outside it is not known
        state = v.get("state", "ready")
        if state == "top_up_due":
            state = "top-up running" if v.get("topping_up") else "top-up due"
        line += (f" every field over the last {v['covered_days']}d of {v.get('wanted_days', '?')}d, "
                 f"{state} ({v.get('age_s', 0)}s old)")
        if v.get("state") == "catching_up":
            gap = v.get("gap") or ["?", "now"]
            line += (f" - CATCHING UP: cases refused until the top-up reads {gap[0]} to now "
                     f"({v.get('age_s', 0) / 3600.0:.1f}h, bound "
                     f"{v.get('max_gap_s', 0) / 3600.0:.1f}h): " + _catch_up_note(v.get("catch_up")))
        if v.get("state") == "top_up_due":
            line += (" - cases run; names logged since the cover ended are not known until "
                     "the top-up finishes")
        elif v.get("state") == "stale":
            line += (" - TOP-UP OVERDUE" + (f" ({v['refused']})" if v.get("refused") else "")
                     + ": names logged since are not known")
        elif v.get("state") == "extending":
            line += " - cases run; older days still reading"
            if v.get("backfill"):
                line += ": " + _backfill_note(v["backfill"])
        elif not v.get("serving", True) and v.get("state") != "catching_up":
            line += " - NOT ENOUGH COVER YET: cases are refused"
            if v.get("backfill"):
                line += ": " + _backfill_note(v["backfill"])
        back = {f: b for f, b in (v.get("backfill") or {}).items() if not b.get("waited", True)}
        if back and v.get("state") in ("ready", "top_up_due", "stale", "catching_up"):
            line += " - " + _backfill_note(back)
    if v.get("skipped"):
        line += " skipped=" + ",".join(f"{k}:{n}" for k, n in sorted(v["skipped"].items()))
    if v.get("near_cap"):
        line += f" NEAR CAP: {', '.join(v['near_cap'])}"
    if v.get("omitted"):
        line += (f" NOT READ (readable in text): {', '.join(sorted(v['omitted']))}")
    line += (_over_cap_note(v) + _frozen_note(v) + _stuck_note(v) + _reach_note(v)
             + _held_over_note(v))
    return line


def _bucket_summary(query: dict, output: dict, hits_total: Any) -> tuple[str, list[str]]:
    """Bucket counts for the summary line, and notes when they do not add up.
    Never a key: identifier keys are labels, but even labels and time keys
    only print with ``--show``."""
    aggs = output.get("aggregations") or {}
    parts: list[str] = []
    notes: list[str] = []
    terms = aggs.get(COUNT_AGG)
    if isinstance(terms, dict):
        field = ((query.get("aggs") or {}).get(COUNT_AGG) or {}).get("field")
        rows = terms.get("buckets") or []
        counts = [b.get("doc_count") or 0 for b in rows]
        other = terms.get("sum_other_doc_count") or 0
        err = terms.get("doc_count_error_upper_bound")
        present = (((aggs.get(COUNT_FIELD_AGG) or {}).get("buckets") or {})
                   .get("present") or {}).get("doc_count")
        parts += [f"buckets={len(rows)}", f"bucket_docs={counts}", f"other_docs={other}"]
        if err is not None:
            parts.append(f"count_error_bound={err}")
        if present is not None:
            parts.append(f"docs_with_field={present}")
        nested = [b[TIME_AGG].get("buckets") or [] for b in rows
                  if isinstance(b.get(TIME_AGG), dict)]
        if nested:
            parts.append(f"time_buckets={sum(len(n) for n in nested)}")
        added = sum(counts) + other
        if isinstance(hits_total, int) and added != hits_total:
            if present is not None and added == present:
                notes.append(f"{hits_total - present} of {hits_total} matching documents have no "
                             f"{field} and are in no bucket")
            elif present is not None and added > present:
                notes.append(f"buckets + other_docs = {added}, more than the {present} documents "
                             f"with {field}: some hold several values and count once per value")
            else:
                notes.append(f"buckets + other_docs = {added} does not add up to hits_total="
                             f"{hits_total}" + (f" or to the {present} documents with {field}"
                                                if present is not None else "")
                             + ": treat the bucket counts as approximate")
        if isinstance(err, int) and err > 0:
            notes.append(f"each bucket count may be low by up to {err} "
                         "(doc_count_error_upper_bound: shards return only their top terms)")
        elif err == -1:
            notes.append("the shards could not bound the bucket count error "
                         "(doc_count_error_upper_bound=-1)")
    hist = aggs.get(TIME_AGG)
    if isinstance(hist, dict):
        rows = hist.get("buckets") or []
        parts += [f"time_buckets={len(rows)}",
                  f"bucket_docs={[b.get('doc_count') for b in rows]}"]
    return " ".join(parts), notes


def _filter_shape(filters: Any) -> str:
    """The query's filters as ops and field names: ``eq=1 phrase=2 not=1
    any_of=1(3) fields=labels.tenant_name,message``. Never a value."""
    ops: dict[str, int] = {}
    fields: list[str] = []
    inner = 0
    for f in filters or []:
        if not isinstance(f, dict):
            continue
        if isinstance(f.get("not"), dict):
            ops["not"] = ops.get("not", 0) + 1
            fields.append(str(f["not"].get("field")))
        elif isinstance(f.get("any_of"), list):
            ops["any_of"] = ops.get("any_of", 0) + 1
            inner += len(f["any_of"])
            fields += [str(x.get("field")) for x in f["any_of"] if isinstance(x, dict)]
        else:
            ops[str(f.get("op"))] = ops.get(str(f.get("op")), 0) + 1
            fields.append(str(f.get("field")))
    if not ops:
        return ""
    parts = [f"{op}={n}" + (f"({inner})" if op == "any_of" else "") for op, n in ops.items()]
    return "filters: " + " ".join(parts) + " fields=" + ",".join(dict.fromkeys(fields))


def _pct(share: float) -> str:
    """A share as a percentage a person can act on: one decimal above 1%,
    two significant digits below it - 980 of 66 million is 0.0015%, never
    the "0.0%" that reads as nothing was read."""
    p = 100.0 * share
    if p >= 1.0:
        return f"{p:.1f}%"
    return f"{p:.2g}%" if p > 0 else "0%"


def _agg_summary(query: dict, output: dict) -> tuple[list[str], list[str]]:
    """Every aggregation the query named, as type, field and bucket counts
    (the smoke flags' own aggregations are summarised by _bucket_summary).
    For text_groups: how many groups, how many documents were read of how
    many, the requests it took and how far the reply says to trust the
    counts and the order. Never a key or a group's text: those print with
    --show only."""
    aggs = output.get("aggregations") or {}
    asked = query.get("aggs") or {}
    parts: list[str] = []
    notes: list[str] = []
    for name, spec in asked.items() if isinstance(asked, dict) else []:
        if name in (COUNT_AGG, TIME_AGG) or not isinstance(spec, dict):
            continue
        got = aggs.get(name)
        if not isinstance(got, dict):
            continue
        atype, field = spec.get("type"), spec.get("field")
        if atype == "text_groups":
            n = len(got.get("buckets") or [])
            share = got.get("covered_share")
            parts.append(
                f"{name}:text_groups({field}) groups={n}/{got.get('groups')} "
                f"read={got.get('sampled')}/{got.get('total')} requests={got.get('requests')} "
                f"strata={got.get('strata')} exact={'yes' if got.get('exact') else 'no'} "
                f"order_settled={got.get('order_settled')}/{n} "
                f"other_docs={got.get('sum_other_doc_count')}"
                + (f" covered={_pct(share)}" if isinstance(share, (int, float))
                   and share < 1.0 else ""))
            if isinstance(share, (int, float)) and share < 1.0:
                cov = got.get("covered") or {}
                notes.append(
                    f"{name}: the groups describe only the newest "
                    f"{_pct(share)} of the asked window "
                    f"(epoch ms {cov.get('from')} to {cov.get('to')}); the older part was "
                    f"not read - {got.get('timeouts')} sampling pass(es) hit the search "
                    "limit. The counts and the total are for the covered part alone; a "
                    "group may be commoner in the unread part")
            if got.get("exact"):
                notes.append(f"{name}: every document in scope was read; the counts are exact"
                             + (f", {n} of {got.get('groups')} groups shown" if n != got.get("groups")
                                else ""))
            else:
                margins = [b.get("margin") for b in got.get("buckets") or [] if "margin" in b]
                cov = got.get("coverage")
                share_txt = "?" if cov is None else _pct(cov) + (
                    f" of the scope, 1 document in {round(1 / cov):,} read" if 0 < cov < 0.01
                    else " of the scope")
                notes.append(
                    f"{name}: counts are estimates from {got.get('sampled')} of "
                    f"{got.get('total')} documents, read over "
                    f"{got.get('strata')} time ranges ({share_txt}), the newest of each range "
                    f"scaled to the range; margin "
                    f"(about 95%) up to {max(margins) if margins else '?'} on a group; the order "
                    f"is settled for the first {got.get('order_settled')} of {n} groups and not "
                    "known beyond; a group rarer than one per range's read may be missing, and "
                    "a burst at the end of one range is counted as that range")
            if got.get("unbucketed"):
                notes.append(f"{name}: {got['unbucketed']} documents in scope have no time field "
                             "and were in no slice")
            continue
        buckets = got.get("buckets")
        if isinstance(buckets, list):
            parts.append(f"{name}:{atype}({field}) buckets={len(buckets)}"
                         + (f" other_docs={got['sum_other_doc_count']}"
                            if "sum_other_doc_count" in got else ""))
        elif isinstance(buckets, dict):
            parts.append(f"{name}:{atype} buckets={len(buckets)} "
                         f"bucket_docs={[b.get('doc_count') for b in buckets.values()]}")
        elif "value" in got:
            parts.append(f"{name}:{atype}({field}) value={got.get('value')}")
        elif "values" in got:
            parts.append(f"{name}:{atype}({field}) values={len(got.get('values') or {})}")
        else:
            parts.append(f"{name}:{atype}({field})")
    return parts, notes


def _empty_findings(empty: dict) -> list[str]:
    """Why a zero is EMPTY rather than a real zero, one line per reason;
    [] when every filtered field is filled where the filters look (the
    zero is real). Field names and counts only."""
    fields = empty.get("fields") or {}
    if empty.get("window_documents") == 0:
        return ["no document in this index and window at all: 0 hits says nothing"]
    out = []
    for name, x in fields.items():
        if x["status"] == "absent_in_window":
            out.append(f"{name} holds no documents in this index and window at all: its filter "
                       f"cannot match anything here; check the field name for this cluster")
        elif x["status"] == "absent_in_scope":
            out.append(f"{name} holds no documents among the {x.get('others_leave')} the other "
                       f"filters leave ({x.get('in_index')} in the window carry it): its filter "
                       "cannot match anything here; drop or widen the other filters")
        elif x["status"] == "unknown":
            out.append(f"the check for {name} was refused: the 0 means unknown")
    return out


def phrase_line(p: dict | None) -> str | None:
    """Where the case stands against its phrase budget. Counts only."""
    if not p:
        return None
    if p.get("phrase_budget") is None:
        return f"PHRASES  {p['phrases_used']} distinct text phrases used (no per-case budget)"
    return (f"PHRASES  {p['phrases_used']}/{p['phrase_budget']} distinct text phrases used "
            f"this case, {p['phrases_left']} left")


def print_smoke(cluster: str, query: dict, report: dict, *, show: bool = False) -> int:
    """Decisions only. Exit code 0 on a clean page, 2 on a refusal, 3 when a
    filtered query had nothing to search (EMPTY: zero hits that mean nothing)."""
    refused = report.get("refused")
    vline = vocabulary_line(report.get("vocabulary"))
    pline = phrase_line(report.get("phrases"))
    if refused:
        print(f"REFUSED  cluster={cluster} code={refused['code']}: {refused['message']}")
        if vline:
            print(vline)
        if pline:
            print(pline, file=sys.stderr)
        return 2
    tr = query.get("time_range") or {}
    output = report.get("output") or {}
    phrases = _phrase_filters(query)
    empty = output.get("empty")
    findings = _empty_findings(empty) if empty is not None else []
    buckets, notes = _bucket_summary(query, output, report.get("hits_total"))
    line = (f"{'EMPTY' if findings else 'OK':<9}cluster={cluster} index={query['index']} "
            f"since={tr.get('gte')} until={tr.get('lte')} hits_total={report['hits_total']} "
            f"shown={report['hits_shown']} labels_issued={report['labels_issued']} "
            f"dropped_field_paths={len(report['dropped'])} seconds={report['seconds']}")
    if phrases:
        line += f" phrase_field={phrases[0]['field']} phrases={len(phrases)}"
    if empty is not None:
        line += (f" fields_checked={len(empty['fields'])} check_requests={empty['requests']} "
                 f"check_seconds={empty['seconds']}")
    agg_parts, agg_notes = _agg_summary(query, output)
    print(line + (f" {buckets}" if buckets else "") + (f" {' '.join(agg_parts)}" if agg_parts else ""))
    shape = _filter_shape(query.get("filters"))
    if shape:
        print(f"         {shape}")
    if empty is not None:
        # a zero, real or not: the per-field statuses, so nobody has to
        # guess them from the count of fields checked. Field names and
        # status words only.
        statuses = " ".join(f"{n}={x.get('status', '?')}"
                            for n, x in (empty.get("fields") or {}).items())
        print(f"ZERO     per filtered field: {statuses or 'no filtered fields'}")
        if not findings and empty.get("meaning"):
            # a real zero used to print OK and nothing else; say what the
            # bridge concluded, in its own sentence
            print(f"ZERO     {empty['meaning']}")
    for finding in findings:
        print(f"         {finding}")
    for note in notes + agg_notes:
        print(f"NOTE     {note}")
    if report["dropped"]:
        print(f"         unlisted fields dropped: {report['dropped']}")
    readable = report.get("readable_words") or []
    if readable:
        # Labels and fields: decisions, safe for a script or an agent to
        # read. stderr, with the other operator notes, so stdout stays the
        # one decision line.
        where = ", ".join(f"{r['label']} ({r['field']})" for r in readable)
        print(f"READABLE  {len(readable)} name(s) are ordinary words and stay readable in "
              f"message text outside the document that holds them: {where}. "
              f"Re-run with --show-readable-names to see the words, then --term NAME for "
              f"any that is a real customer name.", file=sys.stderr)
        names = report.get("readable_names")
        if names:
            # only when the operator asked for them by flag
            print(f"          names: {', '.join(names)}", file=sys.stderr)
    if pline:
        print(pline, file=sys.stderr)
    if vline:
        print(vline)
    if show:
        print(json.dumps(output, indent=1))
    return 3 if findings else 0


def smoke(bridge: Bridge, cluster: str, query: dict, *, show: bool = False) -> int:
    """Run one query end to end in this process and print decisions only."""
    return print_smoke(cluster, query, run_case(bridge, cluster, query), show=show)


# ---------------------------------------------------------------------------
# The broker: one long-lived browser, so one sign-in serves many runs
# ---------------------------------------------------------------------------
#
# Kibana's session cookie carries no expiry. Chrome keeps such a cookie in
# memory only and drops it when the browser exits, so a sign-in lasts
# exactly as long as the Chrome process that made it. The broker is the
# process that keeps that Chrome alive: ``es-login`` starts it (headed,
# because headless SSO never completes against the real IdP) and asks it
# to sign in; every ``es-smoke`` asks it to run one query; ``es-logout``,
# closing the Chrome window, or BROKER_IDLE_S without a request ends it, and
# the session with it.
#
# The socket speaks the bridge's interface, not the transport's: a grammar
# query in, a scrubbed page or a refusal out. Compiling, the Kibana round
# trip and scrubbing all happen in here, so a raw reply never crosses the
# socket and a local process that finds it can get what Claude can get and
# nothing more. It lives in the bridge's own profile directory (0700) and
# is itself 0600. Nothing in this module reads, exports or stores a cookie.

BROKER_SOCKET = "hider-bridge.sock"
BROKER_SCHEMA = "hider.es-broker.v1"
BROKER_IDLE_S = 8 * 3600
BROKER_START_S = 60.0
_MAX_REQUEST = 1 << 20
_MAX_REPLY = 64 << 20
_SUN_PATH_MAX = 103  # macOS: 104 bytes including the terminating NUL
_TIER2 = ("classifier", "spacy", "none")
_MAX_TERMS = 20
#: An empty result's check counts documents **carrying a filtered field**
#: with track_total_hits capped here: enough to say "filled here", and
#: Elasticsearch stops collecting at the cap, so a present field answers in
#: milliseconds and an absent one (no postings for it in the window) at
#: once. The old check counted every document in the window per field.
EMPTY_CHECK_CAP = 100
#: how long a field seen present in an index (on a page, or by a check) is
#: remembered, so a later zero's window check for it costs no request
PRESENCE_TTL_S = 3600.0
#: how long the bridge trusts "a text_groups sampling pass over this span
#: hit the search limit" per index: long enough that the week question asked
#: through a working session never pays the probing twice, short enough that
#: a cluster whose load has fallen is probed again within the hour
GROUP_SPAN_TTL_S = 3600.0
#: seeded names a case may hold over its life: what it was opened with plus
#: what es-seed adds while a session runs
_MAX_SEEDS = 40


def broker_socket(profile_dir: str | Path) -> Path:
    """Where the broker for a profile listens. Not created here."""
    if not str(profile_dir).strip():
        raise elastic.ConfigError("profile_dir is required for the live bridge")
    p = Path(profile_dir).expanduser().resolve() / BROKER_SOCKET
    if len(os.fsencode(str(p))) > _SUN_PATH_MAX:
        raise elastic.ConfigError(f"profile_dir is too deep for a local socket (at most "
                                  f"{_SUN_PATH_MAX - len(BROKER_SOCKET) - 1} bytes); pick a "
                                  "shorter path")
    return p


def _send(conn: socket.socket, msg: dict) -> None:
    conn.sendall(json.dumps(msg).encode() + b"\n")


def _recv(conn: socket.socket, limit: int) -> Any:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = conn.recv(1 << 16)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise ValueError("message too large")
    if not buf.endswith(b"\n"):
        raise ValueError("truncated message")
    return json.loads(buf)


def _fail(code: str, message: str) -> dict:
    return {"ok": False, "code": code, "message": message}


class Broker:
    """The long-lived owner of the bridge's browser. Single-threaded on
    purpose: Playwright's sync API belongs to the thread that started it,
    and the bridge is serialised anyway."""

    def __init__(self, config: elastic.ElasticConfig, transport_factory, *,
                 idle_timeout: float = BROKER_IDLE_S,
                 poll_interval: float = POLL_INTERVAL_S,
                 sessions_dir: str | Path | None = None) -> None:
        from . import esmcp

        self.config = config
        self._factory = transport_factory
        self.transport = None
        self.idle_timeout = idle_timeout
        self.poll_interval = poll_interval
        self.stopping = False
        self.last_used = time.monotonic()
        #: cases open for MCP sessions, by token; the vaults live under here
        self.sessions_dir = Path(sessions_dir or elastic.SESSIONS)
        self.cases = esmcp.CaseBook(config, self.sessions_dir)
        #: the MCP listener, started by the first open_case
        self.mcp = None
        #: the cluster vocabularies, saved beside the case state. Built once
        #: per cluster on sign-in and topped up on the serve loop; see
        #: _pump_vocabulary.
        self.vocabulary = elastic.VocabularyIndex(self.sessions_dir)
        # a top-up is overdue only once it has had its chance on this bridge
        self.vocabulary.started_at = clock()
        self._build: elastic.VocabularyBuild | None = None
        self._build_cluster: elastic.Cluster | None = None
        #: why the last build for a cluster stopped, if it did. A waiting
        #: caller has to be able to tell "still going" from "it failed, and
        #: nothing is coming unless you ask again".
        self._build_failed: dict[str, str] = {}
        #: sentences for the screen of whoever waits on a cluster's build
        self._notes: dict[str, list[str]] = {}
        #: when a cluster whose last slice failed may be tried again
        self._retry_at: dict[str, float] = {}
        #: the slice in flight is an **extension** (older days for fields
        #: that already serve): its failure is charged to the extension,
        #: not the cluster (see ``VocabularyIndex.note_extend_failure``)
        self._build_extension: tuple[float, float] | None = None
        #: measurement switch, set by nothing in the live path: with it off
        #: a failed extension slice is charged to the cluster and retried
        #: whole, as before the rule. Tests use it for the "before" figure.
        self.extend_shrinks = True
        #: the slice in flight is a **catch-up** with more than a first
        #: build's slices left: the fields whose cover a jump would set
        #: aside (see ``_catch_up_jump``), else None
        self._build_catch_up: tuple[str, ...] | None = None
        #: measurement switch, set by nothing in the live path: with it off
        #: a slow or failing catch-up slice is read through or retried as
        #: before the rule. Tests use it for the "before" figures.
        self.catch_up_jumps = True
        #: the clock a slice's budget is measured on: wall time (None) in
        #: the live path; a harness on the stub passes the engine's
        #: simulated seconds so a budget can be exceeded without waiting
        self.build_clock = None
        #: the async search in flight for the build, if any: submitted on
        #: one serve-loop iteration, polled on later ones
        self._page: dict | None = None
        self._build_log: list[dict] = []
        #: clusters signed in to this bridge, in sign-in order
        self._signed_in: list[elastic.Cluster] = []
        #: the listening socket while serve() runs: what _search_idle
        #: answers on between the polls of a long search
        self._srv: socket.socket | None = None
        #: the measurement switch behind the liveness before-tests; nothing
        #: in the live path sets it False
        self.idle_answers = True
        #: re-entrancy guard: the idle hook pumps one vocabulary step, and
        #: nothing it causes may pump another
        self._idling = False

    def _search_idle(self, seconds: float) -> None:
        """What a session does between polls instead of sleeping: keep
        the broker alive on its one thread. **One vocabulary step first**
        (the same step the serve loop takes between connections), because a
        model asking wide questions back to back kept the thread inside
        reads for 20 minutes at a time and the top-up starved until the
        cover fell behind the gap bound and every case was refused - the
        failure the serve loop's own pumping already prevents between
        requests. Then a ping (and a stop) is answered as ever, and
        anything else gets ``busy`` at once instead of hanging on a broker
        that is mid-search until its own socket timeout. The browser stays
        on this thread throughout; the step and the case's poll share it,
        so each stretches the other a little (declared)."""
        deadline = time.monotonic() + seconds
        if self.idle_answers and not self._idling:
            self._idling = True
            try:
                self.pump_vocabulary()
            finally:
                self._idling = False
        srv = self._srv
        if srv is None or not self.idle_answers:
            time.sleep(max(0.0, deadline - time.monotonic()))
            return
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                try:
                    srv.settimeout(min(remaining, 0.2))
                    conn, _ = srv.accept()
                except (socket.timeout, TimeoutError, BlockingIOError):
                    continue
                except OSError:
                    time.sleep(max(0.0, deadline - time.monotonic()))
                    return
                with conn:
                    conn.settimeout(5.0)
                    try:
                        req = _recv(conn, _MAX_REQUEST)
                    except (ValueError, OSError):
                        reply = _fail("bad_request", "malformed request")
                    else:
                        op = req.get("op") if isinstance(req, dict) else None
                        if op in ("ping", "stop"):
                            # stop is accepted now and lands once the search
                            # in flight finishes; es-logout keeps waiting on
                            # the socket, which stays until then
                            reply = self.handle(req)
                        else:
                            reply = _fail("busy", "the bridge is mid-search (a wide "
                                                  "text_groups read can take minutes); only "
                                                  "ping and stop answer until it finishes - "
                                                  "try again")
                    try:
                        _send(conn, reply)
                    except OSError:
                        pass
        finally:
            try:
                srv.settimeout(1.0)
            except OSError:
                pass

    def open(self) -> None:
        """Start the browser before listening, so a broken setup fails at
        startup instead of on the first login."""
        if self.transport is None:
            self.transport = self._factory()
            start = getattr(self.transport, "start", None)
            if start is not None:
                start()

    def handle(self, req: Any) -> dict:
        """One request, one reply; never raises."""
        self.last_used = time.monotonic()
        if not isinstance(req, dict) or req.get("schema") != BROKER_SCHEMA:
            return _fail("bad_request", "not a bridge request")
        op = req.get("op")
        try:
            if op == "ping":
                return {"ok": True, "clusters": [c.name for c in self.config.clusters]}
            if op == "stop":
                self.stopping = True
                return {"ok": True}
            if op == "open_case":
                return self._open_case(req)
            if op == "close_case":
                return {"ok": True, "closed": self.cases.close(req.get("token"))}
            if op == "preflight":
                # human-only, read-only: what stays readable on a cluster,
                # in one report (see hider/espreflight.py). probes=False
                # reads only what the bridge already holds: 0 requests.
                from . import espreflight

                probes = bool(req.get("probes", True))
                show_values = bool(req.get("show_values", False))
                names = ([req["cluster"]] if isinstance(req.get("cluster"), str)
                         else [c.name for c in self.config.clusters])
                reports = {}
                for n in names:
                    cl = self.config.cluster(n)
                    if cl is None:
                        return _fail("bad_cluster", "cluster must be one of the configured names")
                    search = None
                    if probes:
                        self.open()
                        sess = KibanaSession(self.transport, poll_interval=self.poll_interval,
                                             poll_timeout=self.config.poll_timeout_s)
                        search = (lambda body, _c=cl, _s=sess: _s.search(_c, body))
                    reports[n] = espreflight.gather(
                        self.config, n, self.vocabulary, search, now=clock(),
                        tier2=req.get("tier2", "none"), show_values=show_values)
                return {"ok": True, "preflight": reports}
            if op == "seed_case":
                # the human adding a name to an open case, by the case's
                # name over this 0600 socket: no token, no tool, no value in
                # the reply beyond what the human just typed
                terms, _t2 = self._terms_tier2(req)
                if not terms:
                    return _fail("bad_request", "seed_case needs at least one term")
                return {"ok": True, "seeded": self.cases.seed(req.get("case"), terms)}
            name = req.get("cluster")
            cluster = self.config.cluster(name) if isinstance(name, str) else None
            if cluster is None:
                return _fail("bad_cluster", "cluster must be one of the configured names")
            self.open()
            if op == "login":
                timeout = req.get("timeout", LOGIN_TIMEOUT_S)
                if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                        or not 1 <= timeout <= 3600:
                    return _fail("bad_request", "timeout is 1..3600 seconds")
                signed_in = bool(self.transport.login(cluster, timeout=timeout))
                if signed_in:
                    self.start_vocabulary(cluster)
                return {"ok": True, "signed_in": signed_in,
                        "vocabulary": self.vocabulary_progress(cluster.name)}
            if op == "vocabulary":
                # ``build`` starts one if none is held and none is running:
                # what es-login does after signing in, and what a transport
                # that is already authenticated (the stub, a smoke run) asks
                # for directly.
                if req.get("build"):
                    self.open()
                    self.start_vocabulary(cluster)
                return {"ok": True, "vocabulary": self.vocabulary_progress(cluster.name)}
            if op == "run":
                return {"ok": True, "report": self._run(cluster, req)}
            return _fail("bad_request", "unknown op")
        except elastic.Refused as e:
            return _fail(e.code, e.message)
        except Exception:  # fail closed, and keep whatever it was out of the reply
            return _fail("bridge_error", "the bridge failed on this request; nothing was returned")

    @staticmethod
    def _terms_tier2(req: dict) -> tuple[list[str], str]:
        terms = req.get("terms", [])
        tier2 = req.get("tier2", "classifier")
        if not isinstance(terms, list) or len(terms) > _MAX_TERMS or not all(
                isinstance(t, str) and 0 < len(t) <= 128 for t in terms):
            raise elastic.Refused("bad_request", f"terms is a list of up to {_MAX_TERMS} strings")
        if tier2 not in _TIER2:
            raise elastic.Refused("bad_request", f"tier2 is one of {list(_TIER2)}")
        return terms, tier2

    def _touch(self) -> None:
        self.last_used = time.monotonic()

    def _open_case(self, req: dict) -> dict:
        """Open a case for one Claude Code session: load or create its vault,
        seed the human's terms, mint the token, start the MCP listener.

        The reply carries the token and the labels, never a value: the
        mapping stays in the case directory for the human's own process."""
        from . import esmcp

        terms, tier2 = self._terms_tier2(req)
        self.open()
        if self.mcp is None:
            self.mcp = esmcp.McpHttpServer(self.config, self.cases, on_request=self._touch)
        session = KibanaSession(self.transport, poll_interval=self.poll_interval,
                                poll_timeout=self.config.poll_timeout_s,
                                idle=self._search_idle)
        token, case, replaced = self.cases.open(req.get("case"), terms, tier2, session,
                                                self.vocabulary)
        return {"ok": True, "url": self.mcp.url, "token": token, "replaced": replaced,
                "seeded": [[lab, case.scrubber.types.get(lab, "")] for lab in case.seeded]}

    # -- the name vocabulary -----------------------------------------------
    #
    # Built once per cluster when the bridge signs in, not once per case.
    # The measured page cost (8-35s for 1,000 values of one field) makes a
    # per-case read impossible: no budget a human waits for covers it, and
    # every case was refused. Here it is paid once per bridge, saved, and
    # topped up every VOCABULARY_REFRESH_S with only the time since the
    # last read.
    #
    # It runs on the serve loop, one page per iteration, because Playwright's
    # sync API belongs to that thread - a background thread cannot touch the
    # browser. That also keeps the loop answering ping, stop and tool calls
    # between pages instead of disappearing for twenty minutes.

    def start_vocabulary(self, cluster: elastic.Cluster, *, now: float | None = None) -> None:
        """Begin the next slice for a cluster, if one is due."""
        if not self.config.vocabulary_rules or self._build is not None:
            return
        if cluster not in self._signed_in:
            self._signed_in.append(cluster)
        t = clock() if now is None else now
        if t < self._retry_at.get(cluster.name, 0.0):
            return  # a slice failed moments ago; do not spin on it
        untrusted = self.vocabulary.untrusted.pop(cluster.name, None)
        if untrusted is not None:
            # a one-range file from before covers were kept per field: not
            # trusted, dropped, and a first build starts. Field names and
            # counts only.
            self._log_vocabulary(cluster.name, "untrusted", {
                **untrusted, "read": False,
                "why": "saved with one range for the cluster and no per-field record"})
            # and said on screen: without this a first build after an
            # upgrade looks like a bridge that forgot everything
            self._note(cluster.name, (
                f"an older saved name file was set aside: {sum((untrusted.get('fields') or {}).values())} "
                f"names over {len(untrusted.get('fields') or {})} field(s), one range of "
                f"{untrusted.get('covered_days', '?')}d for the whole cluster and no per-field "
                "record, so it could claim days a field was never read for. A full first build "
                f"runs instead: two one-day slices before the first case, the rest behind it"))
        dropped = self.vocabulary.drop_expired(cluster.name, self.config, t)
        if dropped is not None:
            # field names and counts only, never a name
            self._log_vocabulary(cluster.name, "expired", {
                "fields": dropped, "values": sum(dropped.values())})
            self._note(cluster.name, (
                f"the saved name cover for {', '.join(sorted(dropped))} ended more than "
                f"{self.config.vocabulary_days} days ago and was dropped ({sum(dropped.values())} "
                "names); a fresh first build runs, newest day first"))
        held = self.vocabulary.get(cluster.name)
        read = self.vocabulary.wait_set(cluster.name, self.config, t)
        if held is not None and held.behind(self.config, t, read):
            bound = elastic.vocabulary_max_gap(self.config)
            ends = min(held.covers[f][1] for f in read
                       if f in held.covers and t - held.covers[f][1] > bound)
            self.vocabulary.catch_up_from.setdefault(cluster.name, ends)
        elif held is not None:
            self.vocabulary.catch_up_from.pop(cluster.name, None)
        plan = self.vocabulary.next_slice(cluster.name, self.config, t)
        if plan is None:
            return
        held_now = self.vocabulary.get(cluster.name)
        self._build_catch_up = None
        if plan.kind == "forward" and held_now is not None:
            bound = elastic.vocabulary_max_gap(self.config)
            behind = tuple(f for f in plan.fields if (c := held_now.cover(f)) is not None
                           and t - c[1] > bound)
            if behind:
                end = min(held_now.cover(f)[1] for f in behind)
                left = math.ceil((t - end) / elastic.VOCABULARY_SLICE_S - 1e-9)
                if left > elastic.VOCABULARY_SERVE_DAYS:
                    self._build_catch_up = behind
        self._build_extension = (plan.start, plan.until) if (
            plan.kind == "back" and held_now is not None and plan.fields
            and all(held_now.field_serves(f, self.config, t) for f in plan.fields)) else None
        self._build = elastic.VocabularyBuild(
            self.config, plan.start, plan.until, clock=self.build_clock,
            # fields an earlier slice (or an earlier run) counted and found
            # over the cap: not counted again, not paged
            over_cap=self.vocabulary.over_cap_fields(cluster.name, t),
            # the fields this slice is for: a field being backfilled reads
            # on its own, the ones that already have cover are not re-read
            fields=plan.fields)
        self._build_cluster = cluster
        self._build_failed.pop(cluster.name, None)
        self.vocabulary.failed.pop(cluster.name, None)
        self.vocabulary.in_progress.add(cluster.name)
        self.vocabulary.building[cluster.name] = plan.fields
        self._log_vocabulary(cluster.name, "start", {**self._build.progress(), "kind": plan.kind})

    def _end_slice(self, cluster: elastic.Cluster, code: str, build) -> None:
        """A slice that failed teaches the index nothing. Everything saved
        by earlier slices stays saved, and this one is retried later.

        A slice that read only returning fields is charged to those fields
        (``note_returning_failure``: doubling delay, saved), not to the
        cluster: the fields cases wait for are not marked failed, not shown
        stale and not held back by the retry delay."""
        fields = set(getattr(build, "only", None) or ())
        back = set(self.vocabulary.returning(cluster.name, self.config, clock()))
        if fields and fields <= back:
            got = self.vocabulary.note_returning_failure(cluster.name, sorted(fields), code,
                                                         clock())
            self._log_vocabulary(cluster.name, "returning_failed",
                                 {**build.progress(), "refused": code, "retry": got})
            self.vocabulary.in_progress.discard(cluster.name)
            self.vocabulary.building.pop(cluster.name, None)
            self._drop_page()
            self._build = self._build_cluster = None
            return
        if self._build_catch_up and self.catch_up_jumps:
            self._catch_up_jump(cluster, build, code)
            return
        ext = self._build_extension
        if ext is not None and self.extend_shrinks:
            # older days on slower storage: the recent cover is fine, so the
            # cluster is not failed, not stale and not held back; the next
            # attempt at this edge covers half the range (see
            # VocabularyIndex.note_extend_failure)
            got = self.vocabulary.note_extend_failure(cluster.name, code, ext[1] - ext[0],
                                                      ext[1], clock())
            self._log_vocabulary(cluster.name, "extend_failed",
                                 {**build.progress(), "refused": code,
                                  "next_width_s": got["width"], "attempts": got["attempts"],
                                  "retry_at": elastic._iso(got["retry_at"])})
            self.vocabulary.in_progress.discard(cluster.name)
            self.vocabulary.building.pop(cluster.name, None)
            self._drop_page()
            self._build = self._build_cluster = None
            self._build_extension = None
            return
        self._log_vocabulary(cluster.name, "failed", {**build.progress(), "refused": code})
        self._build_failed[cluster.name] = code
        self.vocabulary.failed[cluster.name] = code
        self.vocabulary.in_progress.discard(cluster.name)
        self.vocabulary.building.pop(cluster.name, None)
        self._retry_at[cluster.name] = clock() + elastic.VOCABULARY_RETRY_S
        self._drop_page()
        self._build = self._build_cluster = None

    def _catch_up_jump(self, cluster: elastic.Cluster, build, why: str) -> None:
        """A catch-up through slow (or failing) days would keep every case
        refused for longer than a first build takes. Abandon the slice -
        nothing it read is kept, as with any slice that does not finish -
        and set the cover of the fields it was for aside
        (``VocabularyIndex.hold_over``): their names stay applied, and they
        are read again as a first build is, newest day first, cases served
        after two days, then back through the gap until the new cover
        touches the old one. Not a failure: the cluster is not marked
        failed or held back. Field names, ranges, counts and a code only."""
        fields = self._build_catch_up or ()
        moved = self.vocabulary.hold_over(cluster.name, fields)
        self._log_vocabulary(cluster.name, "catch_up_jumped",
                             {**build.progress(), "why": why, "held_over": moved})
        self._note(cluster.name, (
            f"the catch-up from {', '.join(f'{f} ending {r[1]}' for f, r in sorted(moved.items()))} "
            f"was too slow to wait for ({why}); the newest days are read first, as a first build "
            "is, and the gap behind them afterwards. Names read before the break stay hidden; "
            "names logged only in the gap are readable until the build reaches their day"))
        self.vocabulary.in_progress.discard(cluster.name)
        self.vocabulary.building.pop(cluster.name, None)
        self._drop_page()
        self._build = self._build_cluster = None
        self._build_catch_up = self._build_extension = None

    def _drop_page(self) -> None:
        """Release the async search in flight, if any."""
        page, self._page = self._page, None
        if page is None:
            return
        try:
            page["session"].release(page["cluster"], page.get("sid"))
        except Exception:
            pass

    def pump_vocabulary(self) -> bool:
        """**One step** of the build in flight: submit a page, poll a page
        once, or take a finished page. Returns True if it did work, so the
        serve loop knows not to idle out.

        One step, not one page, is the whole point. A page over a slice is
        8 to 35 seconds (and was minutes before slicing), and the browser
        belongs to this thread: a pump that ran a page to completion left
        the broker unable to answer a ping, a tool call or a stop for that
        long. es-login timed out against its own broker, and es-logout then
        read the timeout as "no bridge" and left it running. Each step here
        is one HTTP call, so no serve-loop iteration is longer than one
        poll interval.
        """
        build, cluster = self._build, self._build_cluster
        if build is None or cluster is None:
            # starting the next slice is work: the loop must not idle out
            # between slices, and a caller driving it step by step must not
            # read "nothing to do" as "the build is over"
            return self._start_due_vocabulary()
        self.last_used = time.monotonic()   # a build in flight is not an idle bridge
        page = self._page
        try:
            if page is None:
                session = KibanaSession(self.transport, poll_interval=self.poll_interval,
                                        poll_timeout=self.config.poll_timeout_s)
                body = build.request()
                data = session.submit(cluster, body)
                self._page = {"session": session, "cluster": cluster, "body": body,
                              "sid": data.get("id") if isinstance(data.get("id"), str) else None,
                              "deadline": time.monotonic() + self.config.poll_timeout_s,
                              "data": data}
                if data.get("isRunning") is True:
                    self._page["sid"] = session.search_id(data)
                    return True          # poll it on the next iteration
                done = data
            else:
                if time.monotonic() >= page["deadline"]:
                    raise elastic.Refused("incomplete", (
                        f"the name vocabulary page did not finish in "
                        f"{self.config.poll_timeout_s:g}s"))
                data = page["session"].poll_once(page["cluster"], page["sid"], page["body"])
                if data.get("isRunning") is True:
                    page["sid"] = page["session"].search_id(data)
                    return True          # still running: come back next iteration
                done = data
            self._drop_page()
            build.feed(done)
        except elastic.Refused as e:
            self._save_over_cap(cluster, build)
            self._end_slice(cluster, e.code, build)
            return True
        except Exception as e:  # a transport fault is the same answer
            self._save_over_cap(cluster, build)
            self._end_slice(cluster, type(e).__name__, build)
            return True
        self._save_over_cap(cluster, build)
        if build.pending():
            if self._build_catch_up and self.catch_up_jumps and build.seconds > \
                    elastic.VOCABULARY_CATCH_UP_SLOW_SHARE * self.config.vocabulary_budget_s:
                self._catch_up_jump(cluster, build, "slow")
                return True
            self._log_vocabulary(cluster.name, "progress", build.progress())
            return True
        # the slice is whole: save it, and let the next iteration plan the
        # next slice. A restart resumes from here rather than starting over.
        how = self.vocabulary.put(cluster.name, build.result())
        if self._build_extension is not None:
            self.vocabulary.note_extend_success(cluster.name)
            self._build_extension = None
        self.vocabulary.note_returning_progress(cluster.name, getattr(build, "only", None) or ())
        returned = self.vocabulary.settle_over_cap(cluster.name, self.config, clock())
        if returned:
            # back under the cap and serving on its own: waited for from now
            self._log_vocabulary(cluster.name, "returned", {"fields": returned})
        self._build_failed.pop(cluster.name, None)
        self.vocabulary.failed.pop(cluster.name, None)
        self.vocabulary.in_progress.discard(cluster.name)
        self.vocabulary.building.pop(cluster.name, None)
        self._log_vocabulary(cluster.name, "slice",
                             {**build.progress(), "saved_as": how,
                              **self.vocabulary.report(cluster.name, self.config, now=clock())})
        self._build = self._build_cluster = None
        return True

    def _save_over_cap(self, cluster: elastic.Cluster, build) -> None:
        """Save, at once, any field this step found over ``vocabulary.max``.

        At once, and not with the finished slice, because the decision has
        to survive a slice that fails after it: that is what stops the next
        attempt spending the same requests on the same field. Field names
        and counts go to the index and the decision log; never a value.
        """
        for field, count in build.take_dropped().items():
            self.vocabulary.note_over_cap(cluster.name, field, count, clock())
            self._log_vocabulary(cluster.name, "over_cap",
                                 {"field": field, "distinct": count,
                                  "max": self.config.vocabulary_max,
                                  "read": False})

    def _start_due_vocabulary(self) -> bool:
        """Start the next slice for any signed-in cluster that has one due:
        a top-up, or another day of cover to reach back for. True if one
        started."""
        for cluster in self._signed_in:
            if self.vocabulary.untrusted.get(cluster.name) is not None \
                    or self.vocabulary.next_slice(cluster.name, self.config, clock()) is not None:
                self.start_vocabulary(cluster)
                return self._build is not None
        return False

    def _note(self, cluster: str, text: str) -> None:
        """A sentence for the screen of whoever waits on this cluster's build
        (es-login prints each once): field names, counts and days only."""
        notes = self._notes.setdefault(cluster, [])
        if text not in notes:
            notes.append(text)

    def vocabulary_progress(self, cluster: str) -> dict:
        """Counts and state for the caller's own screen; never a name."""
        report = self.vocabulary.report(cluster, self.config, now=clock())
        if self._notes.get(cluster):
            report = {**report, "notes": list(self._notes[cluster])}
        if self._build is not None and self._build_cluster is not None \
                and self._build_cluster.name == cluster:
            report = {**report, "building": self._build.progress()}
            report.setdefault("state", "building")
        elif cluster in self._build_failed and report.get("state") == "building":
            # nothing held and nothing running: say so, or a caller waiting
            # for "ready" waits for ever
            report = {**report, "state": "failed", "refused": self._build_failed[cluster]}
        # a failed top-up reads as stale from the index itself (its failed
        # map), so the page's VOCAB line and this report agree
        return report

    def _log_vocabulary(self, cluster: str, event: str, body: dict) -> None:
        row = {"schema": LOG_SCHEMA, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "cluster": cluster, "vocabulary": event, **body}
        self._build_log.append(row)
        path = self.sessions_dir / "vocabulary.log.jsonl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        except OSError:
            pass  # a decision log that cannot be written must not stop the bridge

    def _run(self, cluster: elastic.Cluster, req: dict) -> dict:
        terms, tier2 = self._terms_tier2(req)
        log = req.get("log")
        if log is not None and not (isinstance(log, str) and os.path.isabs(log)):
            raise elastic.Refused("bad_request", "log is an absolute path")
        show_names = req.get("show_names", False)
        if not isinstance(show_names, bool):
            raise elastic.Refused("bad_request", "show_names is true or false")
        scrubber = elastic.EsScrubber(self.config, tier2=tier2)
        seeded = seed_terms(self.config, scrubber, terms)
        session = KibanaSession(self.transport, poll_interval=self.poll_interval,
                                poll_timeout=self.config.poll_timeout_s,
                                idle=self._search_idle)
        bridge = Bridge(self.config, scrubber, session, log_path=log, index=self.vocabulary,
                        presence=self.cases.presence, group_spans=self.cases.group_spans)
        report = run_case(bridge, cluster.name, req.get("query"), show_names=show_names)
        report["seeded"] = seeded
        return report

    def serve(self, socket_path: str | Path) -> None:
        """Listen until stopped, idle, or the browser goes away."""
        path = Path(socket_path)
        if path.exists() or path.is_symlink():
            if broker_running(path):
                raise elastic.ConfigError("a bridge is already running for this profile")
            path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            srv.bind(str(path))
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        srv.listen(8)
        srv.settimeout(1.0)
        self._srv = srv
        # One thread for both listeners: the private socket (es-login,
        # es-smoke, es-research) and, once a case is open, the MCP endpoint.
        # Playwright's sync API belongs to this thread, so every tool call
        # has to run on it too.
        sel = selectors.DefaultSelector()
        sel.register(srv, selectors.EVENT_READ, "control")
        mcp_registered = False
        try:
            while not self.stopping:
                if time.monotonic() - self.last_used > self.idle_timeout:
                    break
                if self.transport is not None and getattr(self.transport, "closed", False):
                    break
                if self.mcp is not None and not mcp_registered:
                    sel.register(self.mcp.socket, selectors.EVENT_READ, "mcp")
                    mcp_registered = True
                # One vocabulary page per iteration, on this thread because
                # the browser lives on it. A page is slow (8-35s measured),
                # so the loop answers between pages rather than vanishing
                # for the length of a build.
                building = self.pump_vocabulary()
                for key, _ in sel.select(timeout=0.0 if building else 1.0):
                    if key.data == "mcp":
                        self.mcp.handle_request()
                        continue
                    try:
                        conn, _ = srv.accept()
                    except (socket.timeout, TimeoutError, BlockingIOError):
                        continue
                    self._control(conn)
        finally:
            sel.close()
            self._srv = None
            srv.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            self.cases.close_all()
            if self.mcp is not None:
                self.mcp.server_close()
                self.mcp = None
            if self.transport is not None:
                self.transport.close()

    def _control(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(30.0)
            try:
                reply = self.handle(_recv(conn, _MAX_REQUEST))
            except (ValueError, OSError):
                reply = _fail("bad_request", "malformed request")
            try:
                _send(conn, reply)
            except OSError:
                pass


def search_wait_s(config: elastic.ElasticConfig) -> float:
    """How long a client should wait on an op that may run a search: the
    longest one group question can take - the read budget plus one pass in
    flight, each pass bounded by the site's search limit - plus the margin
    the single-search wait always had. es-smoke used to wait
    ``poll_timeout + 120`` and gave up at 420 s on a 300 s site while the
    bridge was still mid-read; this wait outlives the worst read by
    construction."""
    return (elastic.TEXT_GROUP_READ_BUDGET_LIMITS + 1) * config.poll_timeout_s + 120.0


class BrokerClient:
    """What es-smoke, es-login and es-logout use to reach the broker. No
    broker is a refusal (``session_expired``): nothing else holds a session."""

    def __init__(self, socket_path: str | Path, *, timeout: float) -> None:
        self.path = Path(socket_path)
        self.timeout = timeout

    def call(self, op: str, **fields: Any) -> dict:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(self.timeout)
        try:
            try:
                conn.connect(str(self.path))
            except (FileNotFoundError, ConnectionRefusedError):
                raise elastic.Refused("session_expired", "no bridge is running for this "
                                                         "profile; run es-login") from None
            _send(conn, {"schema": BROKER_SCHEMA, "op": op, **fields})
            reply = _recv(conn, _MAX_REPLY)
        except (socket.timeout, TimeoutError):
            raise elastic.Refused("unreachable", "the bridge did not answer in time") from None
        except (OSError, ValueError):
            raise elastic.Refused("unreachable", "the bridge did not answer") from None
        finally:
            conn.close()
        if not isinstance(reply, dict):
            raise elastic.Refused("malformed", "the bridge answered with something else")
        if not reply.get("ok"):
            raise elastic.Refused(str(reply.get("code") or "bridge_error"),
                                  str(reply.get("message") or "the bridge refused"))
        return reply


def broker_running(socket_path: str | Path) -> bool:
    return broker_state(socket_path) == "running"


def broker_state(socket_path: str | Path) -> str:
    """``running``, ``busy`` or ``absent``.

    A client must be able to tell a busy broker from a dead one. It could
    not before: any refusal, a timeout included, read as "no bridge", so
    es-logout printed "no bridge was running" at a broker that was mid-page
    and left it alive holding the Kibana session. A connect that fails is
    absent; a connect that succeeds and then times out is busy; a socket
    file that is still there is at worst busy.
    """
    try:
        BrokerClient(socket_path, timeout=5.0).call("ping")
        return "running"
    except elastic.Refused as e:
        if e.code == "session_expired":   # nothing accepted the connection
            return "absent"
        return "busy" if Path(socket_path).exists() else "absent"


def spawn_broker(socket_path: Path, argv: list[str], *, wait: float = BROKER_START_S) -> None:
    """Start ``python -m hider es-broker`` detached and wait until it answers.

    Its output goes nowhere: a broker that dies at startup is reported here
    with the command to run it in the foreground, which shows why.
    """
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.Popen([sys.executable, "-m", "hider", "es-broker", *argv], cwd=root,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("the bridge exited while starting; run `python -m hider "
                               "es-broker` in the foreground to see why")
        if broker_running(socket_path):
            return
        time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("the bridge did not start in time")
