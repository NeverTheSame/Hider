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

from . import elastic, esquery

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
#: it. It never changes what a *query* selects - a query's date math is
#: sent as written and resolved by the cluster.
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
                 poll_timeout: float = POLL_TIMEOUT_S, sleep=time.sleep) -> None:
        self.transport = transport
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._sleep = sleep

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

    def search(self, cluster: elastic.Cluster, body: dict) -> dict:
        """Submit the compiled body, poll to completion, release the search.

        Returns the final envelope for ``EsScrubber.scrub_response``, which
        still applies its own checks (``isPartial``, ``timed_out``, error
        bodies). A poll that does not finish inside ``poll_timeout`` deletes
        the server-side search and refuses as ``incomplete``.
        """
        data = self.submit(cluster, body)
        if elastic.error_class(data) is not None:
            return data  # the scrubber turns it into an upstream_error refusal
        sid = data.get("id")
        deadline = time.monotonic() + self.poll_timeout
        try:
            while data.get("isRunning") is True:
                sid = self.search_id(data)
                if time.monotonic() >= deadline:
                    raise elastic.Refused("incomplete", (
                        f"response withheld: search did not finish in "
                        f"{self.poll_timeout:g}s; {elastic.INCOMPLETE_HINT}"))
                self._sleep(self.poll_interval)
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
                 index: elastic.VocabularyIndex | None = None) -> None:
        self.config = config
        self.scrubber = scrubber
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
                compiled = esquery.compile_query(query, self.config, self.scrubber)
                # Then the vocabulary (local, no request, once per case per
                # cluster; refuses vocabulary_building until it serves). If
                # this call is the one that applied it, compile again, so the
                # first query is gated against the cluster's names exactly as
                # every later one is - a learnt name in a keep literal is
                # refused here, with the same words, before any request.
                if self._apply_vocabulary(cluster):
                    compiled = esquery.compile_query(query, self.config, self.scrubber)
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
                envelope = self.session.search(cluster, compiled.body)
                scrubbed = self.scrubber.scrub_response(envelope, compiled.plan)
                outcome.output = scrubbed.output
                total = scrubbed.output.get("hits", {}).get("total") or {}
                outcome.hits_total = total.get("value") if isinstance(total, dict) else None
                outcome.hits_shown = len(scrubbed.output.get("hits", {}).get("hits", []))
                outcome.text_queries = len(compiled.text_queries)
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
        if self.scrubber._vocab_rules and vocab is not None \
                and vocab.behind(self.config, t):
            # every query, not only a case's first: the gap is a property of
            # the cover now, and an open case is refused the same way
            gap_h = (t - vocab.covered_until) / 3600.0
            cu = self.index.catch_up(cluster.name, self.config, t) or {}
            raise elastic.Refused(
                "vocabulary_building",
                "response withheld: the name vocabulary for this cluster ends "
                f"{gap_h:.1f}h ago, past the {elastic.vocabulary_max_gap(self.config) / 3600.0:.1f}h "
                "bound, so a name first logged since then has not been read and could be plain "
                "text on this page. Waiting for the top-up that reads "
                f"{elastic._iso(vocab.covered_until)} to now: " + _catch_up_note(cu)
                + "; es-smoke's VOCAB line shows its progress.")
        applied = self.scrubber._vocabulary_at.get(cluster.name)
        if applied is not None and (vocab is None or applied[2] is None
                                    or applied[2] >= vocab.covered_until):
            # this case already holds this cover; a newer one (a top-up
            # since) is applied again below, locally, before the page
            return False
        if not self.scrubber._vocab_rules:
            return False
        if vocab is None or not vocab.serves(self.config, t):
            raise elastic.Refused(
                "vocabulary_building",
                "response withheld: the name vocabulary for this cluster does not yet cover "
                f"the last {elastic.VOCABULARY_SERVE_DAYS} days (it is read in one-day "
                "slices, newest first, and a page shown before those are in could leak a "
                "customer name in message text). Try again shortly; es-smoke's VOCAB line "
                "shows how far back the cover reaches.")
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

    def _log(self, row: dict) -> None:
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _phrases_of(filters: Any) -> list[str]:
    return [f["value"] for f in filters or [] if isinstance(f, dict)
            and f.get("op") == "phrase" and isinstance(f.get("value"), str)]


def _zero_hit_phrases(query: dict, output: dict) -> list[str]:
    """The phrases in this query whose filter (the page) or whose bucket (a
    filters aggregation, at any depth under filters aggregations) matched
    nothing. What a guess that failed looks like in the log; a count of
    them per case is what es-review reads."""
    out: list[str] = []
    total = (output.get("hits") or {}).get("total") or {}
    if isinstance(total, dict) and total.get("value") == 0:
        out.extend(_phrases_of(query.get("filters")))

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
    filters = []
    for f in query.get("filters") or []:
        if isinstance(f, dict):
            filters.append({"field": f.get("field"), "op": f.get("op")})

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
    """One smoke run through ``run`` (query -> report), plus the zero-hit check.

    Zero hits on a filtered query is ambiguous: nothing matches, or a field
    it filtered holds nothing here (the wrong text field for this index, a
    label field named differently on this cluster). The check tells them
    apart with one more query (more when the buckets need splitting),
    reported under ``field_probe``; ``print_smoke`` turns "nothing to
    search" into EMPTY and exit code 3.
    """
    report = run(query)
    built = field_probe(query, max_buckets=max_buckets)
    if report.get("refused") or built is None or report.get("hits_total") != 0:
        return report
    probes, fields = built
    got: dict[str, Any] = {}
    window = None
    for probe in probes:
        checked = run(probe)
        if checked.get("refused"):
            report["field_probe"] = {"refused": checked["refused"]}
            return report
        window = checked.get("hits_total")
        got.update(((checked.get("output") or {}).get("aggregations") or {})
                   .get(PHRASE_FIELD_AGG, {}).get("buckets", {}))
    report["field_probe"] = {"docs_in_window": window, "queries": len(probes), "fields": [
        {"field": name,
         "in_scope": got.get(f"s{i}", {}).get("doc_count") if f"s{i}" in got else window,
         "with_field": got.get(f"f{i}", {}).get("doc_count"),
         "in_window": got.get(f"w{i}", {}).get("doc_count") if f"w{i}" in got
         else got.get(f"f{i}", {}).get("doc_count")}
        for i, name in enumerate(fields)]}
    return report


def seed_terms(config: elastic.ElasticConfig, scrubber: elastic.EsScrubber,
               terms: list[str]) -> list[str]:
    """Seed the case with values the human typed locally; returns their labels.

    ``Contoso Holdings`` seeds an organisation. ``SERVER_NAME=ctr-amer-042``
    seeds a value of that identifier type, so a label for it exists in this
    case and ``--eq agent.name=<that label>`` can filter by it (identifier
    fields take labels only, and each run is a fresh case). The same terms
    in the same order give the same labels on every run.
    """
    types = {"ORG_NAME"} | {r.type for r in config.fields if r.kind == "identifier"}
    labels = []
    for t in terms:
        m = _TYPED_SEED.match(t)
        if m is None:
            labels.append(scrubber.seed(t))
            continue
        if m.group(1) not in types:
            raise elastic.Refused("bad_request", f"a typed term needs an identifier type from the "
                                                 f"site map: {sorted(types)}")
        labels.append(scrubber.seed(m.group(2), m.group(1)))
    return labels


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


def _catch_up_note(cu: dict | None) -> str:
    """Slices left and the range being read: counts and ranges only."""
    if not cu:
        return "waiting for the next slice"
    if cu.get("expired"):
        head = (f"the saved cover is older than vocabulary.days and is dropped; a fresh build "
                f"reads {cu['slices_left']} one-day slices first")
    else:
        head = f"{cu['slices_left']} of {cu['slices_total']} one-day slices left"
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
                + _over_cap_note(v))
    if v.get("state") == "failed":
        return (f"VOCAB    build stopped: {v.get('refused')}; no case can run until one finishes"
                + _over_cap_note(v))
    if not v.get("fields"):
        if v.get("state") != "building":
            return ("VOCAB   " + _over_cap_note(v)) if v.get("over_cap") else None
        return "VOCAB    building, no page yet" + _over_cap_note(v)
    parts = [f"{f}={n}/{v['max']}" for f, n in v["fields"].items()
             if f not in (v.get("over_cap") or {})]
    line = "VOCAB    " + " ".join(parts)
    if v.get("covered_days") is not None:
        # the covered range is the one number that says which days a name
        # can be known from at all: a name logged outside it is not known
        state = v.get("state", "ready")
        if state == "top_up_due":
            state = "top-up running" if v.get("topping_up") else "top-up due"
        line += (f" over the last {v['covered_days']}d of {v.get('wanted_days', '?')}d, "
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
        elif not v.get("serving", True) and v.get("state") != "catching_up":
            line += " - NOT ENOUGH COVER YET: cases are refused"
    if v.get("skipped"):
        line += " skipped=" + ",".join(f"{k}:{n}" for k, n in sorted(v["skipped"].items()))
    if v.get("near_cap"):
        line += f" NEAR CAP: {', '.join(v['near_cap'])}"
    if v.get("omitted"):
        line += (f" NOT READ (readable in text): {', '.join(sorted(v['omitted']))}")
    line += _over_cap_note(v)
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


def _probe_findings(probe: dict) -> list[str]:
    """Why a zero is empty, one line per reason; [] when the zero is real."""
    if probe.get("refused"):
        return [f"0 hits, and the check that the filtered fields hold documents was refused "
                f"({probe['refused']['code']}): the 0 means unknown"]
    if not probe.get("docs_in_window"):
        return ["no document in this index and window at all: 0 hits says nothing"]
    out = []
    for f in probe["fields"]:
        hint = "; check the field name for this cluster" + (
            " or pick another --phrase-field" if f.get("phrase") else "")
        if f["in_scope"] and not f["with_field"]:
            out.append(f"{f['field']} holds no documents among the {f['in_scope']} the other "
                       f"filters leave: its filter cannot match anything here{hint}")
        elif not f["in_scope"] and not f["in_window"]:
            out.append(f"{f['field']} holds no documents in this index and window at all: its "
                       f"filter cannot match anything here{hint}")
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
    probe = report.get("field_probe")
    if probe and not probe.get("refused") and phrases:
        for f in probe["fields"]:
            f["phrase"] = f["field"] == phrases[0]["field"]
    findings = _probe_findings(probe) if probe is not None else []
    buckets, notes = _bucket_summary(query, output, report.get("hits_total"))
    line = (f"{'EMPTY' if findings else 'OK':<9}cluster={cluster} index={query['index']} "
            f"since={tr.get('gte')} until={tr.get('lte')} hits_total={report['hits_total']} "
            f"shown={report['hits_shown']} labels_issued={report['labels_issued']} "
            f"dropped_field_paths={len(report['dropped'])} seconds={report['seconds']}")
    if phrases:
        line += f" phrase_field={phrases[0]['field']} phrases={len(phrases)}"
    if probe is not None and not probe.get("refused"):
        if phrases:
            pf = next(f for f in probe["fields"] if f["field"] == phrases[0]["field"])
            line += f" phrase_field_docs={pf['with_field']}/{pf['in_scope']}"
        line += f" fields_checked={len(probe['fields'])}"
    print(line + (f" {buckets}" if buckets else ""))
    for finding in findings:
        print(f"         {finding}")
    for note in notes:
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
        #: when a cluster whose last slice failed may be tried again
        self._retry_at: dict[str, float] = {}
        #: the async search in flight for the build, if any: submitted on
        #: one serve-loop iteration, polled on later ones
        self._page: dict | None = None
        self._build_log: list[dict] = []
        #: clusters signed in to this bridge, in sign-in order
        self._signed_in: list[elastic.Cluster] = []

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
                                poll_timeout=self.config.poll_timeout_s)
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
        dropped = self.vocabulary.drop_expired(cluster.name, self.config, t)
        if dropped is not None:
            # counts and days only, never a name
            self._log_vocabulary(cluster.name, "expired", {
                "covered_days": round(dropped.covered_days(t), 2),
                "ended_days_ago": round((t - dropped.covered_until) / 86400.0, 2),
                "values": dropped.total()})
        held = self.vocabulary.get(cluster.name)
        if held is not None and held.behind(self.config, t):
            self.vocabulary.catch_up_from.setdefault(cluster.name, held.covered_until)
        elif held is not None:
            self.vocabulary.catch_up_from.pop(cluster.name, None)
        slice_range = elastic.next_vocabulary_slice(
            self.config, self.vocabulary.get(cluster.name), t)
        if slice_range is None:
            return
        start, until = slice_range
        self._build = elastic.VocabularyBuild(
            self.config, start, until,
            # fields an earlier slice (or an earlier run) counted and found
            # over the cap: not counted again, not paged
            over_cap=self.vocabulary.over_cap_fields(cluster.name, t))
        self._build_cluster = cluster
        self._build_failed.pop(cluster.name, None)
        self.vocabulary.failed.pop(cluster.name, None)
        self.vocabulary.in_progress.add(cluster.name)
        self._log_vocabulary(cluster.name, "start", self._build.progress())

    def _end_slice(self, cluster: elastic.Cluster, code: str, build) -> None:
        """A slice that failed teaches the index nothing. Everything saved
        by earlier slices stays saved, and this one is retried later."""
        self._log_vocabulary(cluster.name, "failed", {**build.progress(), "refused": code})
        self._build_failed[cluster.name] = code
        self.vocabulary.failed[cluster.name] = code
        self.vocabulary.in_progress.discard(cluster.name)
        self._retry_at[cluster.name] = clock() + elastic.VOCABULARY_RETRY_S
        self._drop_page()
        self._build = self._build_cluster = None

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
            self._log_vocabulary(cluster.name, "progress", build.progress())
            return True
        # the slice is whole: save it, and let the next iteration plan the
        # next slice. A restart resumes from here rather than starting over.
        how = self.vocabulary.put(cluster.name, build.result())
        self._build_failed.pop(cluster.name, None)
        self.vocabulary.failed.pop(cluster.name, None)
        self.vocabulary.in_progress.discard(cluster.name)
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
            if elastic.next_vocabulary_slice(
                    self.config, self.vocabulary.get(cluster.name), clock()) is not None:
                self.start_vocabulary(cluster)
                return self._build is not None
        return False

    def vocabulary_progress(self, cluster: str) -> dict:
        """Counts and state for the caller's own screen; never a name."""
        report = self.vocabulary.report(cluster, self.config, now=clock())
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
                                poll_timeout=self.config.poll_timeout_s)
        bridge = Bridge(self.config, scrubber, session, log_path=log, index=self.vocabulary)
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
