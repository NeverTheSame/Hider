"""The sync gateway: an OpenAI-compatible proxy that redacts in flight.

This is the boundary the whole stack defends. A chat completion is
intercepted on its way to the provider, every text field the caller wrote is
redacted first, and only the redacted payload is forwarded. The provider's
answer comes back through the vault, so the caller sees real values where the
model saw pseudonyms.

Invariants, in the order that matters:

* **Nothing sensitive crosses, or nothing crosses.** If any unit of the
  request degrades (a tier errored, timed out or returned garbage), the
  request is refused with 503 and the upstream is never contacted. Fail
  closed is a pipeline property; refusing to forward a degraded unit is the
  boundary property, and it is tested here rather than assumed.
* **A known value never crosses.** After the tiers run, the redacted payload
  is swept for every identifier the vault already holds. A hit is replaced
  with its existing pseudonym and logged as a ``sweep`` event; if a value
  somehow still remains, the request is refused. This is the output guardrail
  on the request side: the tiers are probabilistic past tier 1, the vault is
  not.
* **The path stays the caller's.** The Authorization header and vendor
  headers pass through untouched; this gateway holds no provider
  credentials of its own. Point the client's base URL at it and nothing else
  changes.
* **Streaming is rewritten honestly.** ``stream: true`` is forwarded as a
  stream. Each delta is released as soon as it cannot be the start of a
  pseudonym that is still arriving (``HoldbackDetokenizer``), so the client
  sees real values with a delay of at most one label length and never a
  label cut in half. A label the model wrote that the vault does not know is
  left as-is and reported.
* **The decision log records decisions, not data.** One row per request:
  request id, timings, upstream status, counts per entity type, token usage
  from the provider, the degraded flag, sweep hits and unknown labels. The
  substitute, never the original. The file is rotated at 50 MiB into five
  numbered backups (``.1`` newest) so it cannot fill a disk. One debugging
  switch, ``log_request_bodies`` / ``--log-request-bodies``, off by default,
  adds the raw request body to each row; with it on the log *is* the data
  and must stay on the machine.

Implemented with the standard library only, because a data boundary that
grows a web framework also grows that framework's request logging, error
handlers and middleware, each of which becomes a place a raw body can be
retained by accident.
"""

from __future__ import annotations

import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

from . import llm_backend, pipeline, pseudonym

#: Headers that must not be forwarded verbatim: hop-by-hop fields, and the
#: ones whose value this gateway owns.
HOP_BY_HOP = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
    "upgrade", "proxy-authorization", "te", "trailer",
}

DEGRADED_STATUS = 503
UPSTREAM_TIMEOUT_S = 120
LOG_SCHEMA = "hider.proxy.v2"
LOG_MAX_BYTES = 50 * 1024 * 1024   # rotate the decision log past this size
LOG_BACKUPS = 5                    # keep .1 (newest) .. .5 (oldest), delete older

#: A bracketed label as the pipeline mints them, or a destroyed-secret marker.
_LABEL_RE = re.compile(r"<[A-Za-z][A-Za-z_]*-\d+>|<REDACTED:[A-Z_0-9]+>")


class Refused(Exception):
    """A request that must not be forwarded, with an HTTP status and reason."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _error_body(message: str) -> bytes:
    return json.dumps({"error": {"message": message, "type": "hider_gateway"}}).encode()


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class GatewayMetrics:
    """Cumulative counters since start, exposed on ``/healthz``."""

    requests: int = 0
    forwarded: int = 0
    streamed: int = 0
    refused: Counter = field(default_factory=Counter)        # by status
    upstream_status: Counter = field(default_factory=Counter)
    degraded: int = 0
    sweep_hits: int = 0
    unknown_labels: int = 0
    redactions_by_type: Counter = field(default_factory=Counter)
    redact_s: float = 0.0
    upstream_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    tokens_by_model: dict[str, dict[str, int]] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, row: dict) -> None:
        with self._lock:
            self.requests += 1
            if row.get("refused_status"):
                self.refused[str(row["refused_status"])] += 1
            else:
                self.forwarded += 1
                self.upstream_status[str(row.get("upstream_status"))] += 1
            if row.get("stream"):
                self.streamed += 1
            self.degraded += int(bool(row.get("degraded")))
            self.sweep_hits += int(row.get("sweep_hits") or 0)
            self.unknown_labels += len(row.get("unknown_labels") or [])
            for k, v in (row.get("redactions_by_type") or {}).items():
                self.redactions_by_type[k] += v
            self.redact_s += float(row.get("redact_ms") or 0) / 1000
            self.upstream_s += float(row.get("upstream_ms") or 0) / 1000
            usage = row.get("usage") or {}
            if usage:
                self.input_tokens += int(usage.get("input_tokens") or 0)
                self.output_tokens += int(usage.get("output_tokens") or 0)
                m = self.tokens_by_model.setdefault(
                    str(row.get("model") or "?"),
                    {"requests": 0, "input_tokens": 0, "output_tokens": 0})
                m["requests"] += 1
                m["input_tokens"] += int(usage.get("input_tokens") or 0)
                m["output_tokens"] += int(usage.get("output_tokens") or 0)

    def to_dict(self) -> dict:
        with self._lock:
            n = max(1, self.forwarded)
            cost = 0.0
            priced = True
            for model, m in self.tokens_by_model.items():
                p = llm_backend.price_for(model)
                if p is None:
                    priced = False
                    break
                cost += m["input_tokens"] / 1e6 * p[0] + m["output_tokens"] / 1e6 * p[1]
            return {
                "uptime_s": round(time.time() - self.started_at, 1),
                "requests": self.requests,
                "forwarded": self.forwarded,
                "streamed": self.streamed,
                "refused_by_status": dict(self.refused),
                "upstream_status": dict(self.upstream_status),
                "degraded": self.degraded,
                "sweep_hits": self.sweep_hits,
                "unknown_labels": self.unknown_labels,
                "redactions_by_type": dict(self.redactions_by_type),
                "mean_redact_ms": round(self.redact_s / max(1, self.requests) * 1000, 2),
                "mean_upstream_ms": round(self.upstream_s / n * 1000, 2),
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "tokens_by_model": {k: dict(v) for k, v in self.tokens_by_model.items()},
                "cost_usd_list_price": round(cost, 6) if priced else None,
            }


# ---------------------------------------------------------------------------
# Streaming: hold back, then release
# ---------------------------------------------------------------------------


class HoldbackDetokenizer:
    """Detokenise a stream without ever cutting a pseudonym in half.

    Text is buffered; on each feed everything is released except the longest
    tail that is still a proper prefix of some pseudonym the vault holds, so
    the client lags only while a label might actually be arriving. A tail that
    is not the start of any label cannot become one by growing on the right,
    and a tail that is one must be held whole: a cut inside it could release
    the first half of a pseudonym, including a short pseudonym that is itself
    the prefix of a longer one, which is why the prefix set is built over
    proper prefixes (a complete label at the tail is released, and
    detokenised, the moment nothing longer can extend it). The worst case is
    ``H - 1`` characters, ``H`` the longest label, which is what the previous
    implementation held on every feed regardless of content. ``flush``
    releases the tail at end of stream.
    """

    def __init__(self, vault: pseudonym.EntityVault) -> None:
        self.vault = vault
        labels = list(vault.by_label)
        bare = [l[1:-1] for l in labels if l.startswith("<") and l.endswith(">")]
        forms = sorted(set(labels + bare), key=len, reverse=True)
        self.holdback = max((len(l) for l in forms), default=1) - 1
        #: Every proper prefix of every form. A buffer tail is held back iff
        #: it is in this set; membership is O(1) and the longest candidate is
        #: ``holdback`` chars, so each feed costs at most ``holdback`` lookups.
        self._prefixes = frozenset(
            form[:k] for form in forms for k in range(1, len(form))
        )
        #: Longest-first alternation over the complete forms, for the straddle
        #: check in ``feed``: the longest tail that is a label *prefix* can
        #: start inside a *complete* label ("203.0.113.20" ends in "20", a
        #: prefix of other labels), so the prefix rule alone can put the cut
        #: mid-label; any complete label crossing the cut moves it past itself.
        self._rx = re.compile("|".join(map(re.escape, forms))) if forms else None
        self.pending = ""
        self.unknown: list[str] = []
        self._window = ""  # the last few hundred chars fed, for unknown-label spotting

    def _note_unknown(self, text: str) -> None:
        # Scanned over a rolling window of everything fed, not over what was
        # released: an unknown label is not in the vault's regex, so nothing
        # stops the cut from landing inside it.
        self._window = (self._window + text)[-512:]
        for m in _LABEL_RE.finditer(self._window):
            lab = m.group(0)
            if lab.startswith("<REDACTED:") or lab in self.vault.by_label:
                continue
            if lab not in self.unknown:
                self.unknown.append(lab)

    def feed(self, text: str) -> str:
        self._note_unknown(text)
        self.pending += text
        hold = 0
        for k in range(min(len(self.pending), self.holdback), 0, -1):
            if self.pending[-k:] in self._prefixes:
                hold = k
                break
        cut = len(self.pending) - hold
        if self._rx is not None:
            for m in self._rx.finditer(self.pending):
                if m.start() < cut < m.end():
                    # Safe to release whole: were this label still extendable,
                    # it would be a proper prefix of a longer form and the
                    # suffix loop above would already be holding all of it.
                    cut = m.end()
                if m.start() >= cut:
                    break
        if cut <= 0:
            return ""
        out, self.pending = self.pending[:cut], self.pending[cut:]
        return self.vault.detokenize(out)

    def flush(self) -> str:
        out, self.pending = self.pending, ""
        return self.vault.detokenize(out)


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes | None = None
    chunks: Iterator[bytes] | None = None


class RedactionGateway:
    """Redacts chat-completion requests, forwards them, detokenises replies."""

    def __init__(
        self,
        upstream_base: str,
        pipe: pipeline.Pipeline,
        *,
        vault_path: str | Path | None = None,
        log_path: str | Path | None = None,
        log_max_bytes: int | None = LOG_MAX_BYTES,
        log_backups: int = LOG_BACKUPS,
        log_request_bodies: bool = False,
        timeout: int = UPSTREAM_TIMEOUT_S,
    ) -> None:
        self.upstream_base = upstream_base.rstrip("/")
        self.pipe = pipe
        self.vault_path = vault_path
        self.log_path = log_path
        if log_max_bytes is not None and log_max_bytes <= 0:
            raise ValueError("log_max_bytes must be a positive number of bytes")
        self.log_max_bytes = log_max_bytes
        if log_backups < 0:
            raise ValueError("log_backups must be zero or more")
        self.log_backups = log_backups
        # Debugging aid, off by default: the raw request body is the original
        # data, so a log that carries it is a second copy of what the gateway
        # exists to keep from leaving the machine. Never enable on a shared box.
        self.log_request_bodies = log_request_bodies
        self.timeout = timeout
        self.metrics = GatewayMetrics()
        self._log_lock = threading.Lock()
        self._redact_lock = threading.Lock()

    # -- request rewriting -------------------------------------------------

    @staticmethod
    def _collect_texts(body: dict) -> list[str]:
        texts: list[str] = []
        messages = body.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            texts.append(part["text"])
        prompt = body.get("prompt")
        if isinstance(prompt, str):
            texts.append(prompt)
        elif isinstance(prompt, list):
            texts.extend(p for p in prompt if isinstance(p, str))
        return texts

    @staticmethod
    def _write_texts(body: dict, texts: list[str]) -> None:
        it = iter(texts)
        messages = body.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    msg["content"] = next(it)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            part["text"] = next(it)
        prompt = body.get("prompt")
        if isinstance(prompt, str):
            body["prompt"] = next(it)
        elif isinstance(prompt, list):
            body["prompt"] = [next(it) if isinstance(p, str) else p for p in prompt]

    def redact_payload(self, body: dict) -> list[dict]:
        """Redact every caller-authored text field, in place.

        Returns the decision events. Raises :class:`Refused` when a unit is
        degraded, when a known value survives the sweep, or when the payload
        has a shape this gateway does not safely understand; in every case
        nothing has been sent.
        """
        events: list[dict] = []
        texts = self._collect_texts(body)
        with self._redact_lock:
            for i, text in enumerate(texts):
                r = self.pipe.redact(text, unit=f"request[{i}]", line_no=0)
                if r.degraded:
                    raise Refused(
                        DEGRADED_STATUS,
                        "redaction degraded on this request; refusing to forward it",
                    )
                texts[i] = r.text
                events.extend(r.events)
            for i, text in enumerate(texts):
                texts[i], swept = self.sweep(text, unit=f"request[{i}]")
                events.extend(swept)
            leftovers = [i for i, t in enumerate(texts) if self._known_values_in(t)]
        if leftovers:
            raise Refused(
                DEGRADED_STATUS,
                "a known identifier survived redaction; refusing to forward it",
            )
        self._write_texts(body, texts)
        return events

    # -- the sweep ---------------------------------------------------------

    def _known_values_rx(self) -> re.Pattern | None:
        # Every value the vault holds, however short. There used to be a
        # four-character floor so that a two-letter name or a three-letter
        # org did not get swept out of ordinary prose, but a value the vault
        # pseudonymised in one request and the tiers missed in the next
        # crossed to the provider for no better reason than being short, and
        # the leftover check below shared the floor, so it did not refuse
        # either. Word boundaries still apply, so "Ed" is matched as a word
        # and not inside "edited". The over-redaction cost is measured in
        # ``test_sweep_catches_short_identifiers_and_the_cost_is_measured``.
        values = {v: l for l, v in self.pipe.vault.by_label.items() if v}
        if not values:
            return None
        alts = sorted(values, key=len, reverse=True)
        return re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(map(re.escape, alts))
                          + r")(?![A-Za-z0-9])", re.IGNORECASE)

    def _known_values_in(self, text: str) -> list[str]:
        rx = self._known_values_rx()
        return [m.group(0) for m in rx.finditer(text)] if rx else []

    def sweep(self, text: str, *, unit: str = "") -> tuple[str, list[dict]]:
        """Replace any identifier the vault already knows with its pseudonym.

        The tiers past tier 1 are probabilistic; the vault is not. A value
        that was pseudonymised in an earlier request and missed in this one
        gets the same label it had before, so correlation across requests
        survives and the value never crosses. Secrets are never in the vault
        (they are destroyed), so this sweep is identifiers only.
        """
        rx = self._known_values_rx()
        if rx is None:
            return text, []
        by_value = {e["value"].casefold(): (e["label"], e["type"])
                    for e in self.pipe.vault.entries.values()
                    if not e["type"].startswith("_")}
        events: list[dict] = []

        def repl(m: re.Match) -> str:
            hit = by_value.get(m.group(0).casefold())
            if hit is None:
                return m.group(0)
            label, etype = hit
            events.append({
                "schema": "hider.redaction.v1", "unit": unit, "line": 0,
                "start": m.start(), "end": m.end(), "entity_type": etype,
                "action": "pseudonymised", "tier": "sweep", "score": 1.0,
                "marker": label, "replacement": label,
            })
            return label

        return rx.sub(repl, text), events

    # -- upstream ----------------------------------------------------------

    def _request(self, path: str, payload: bytes, headers: dict) -> urllib.request.Request:
        req = urllib.request.Request(
            self.upstream_base + path, data=payload, method="POST"
        )
        for k, v in headers.items():
            if k.lower() not in HOP_BY_HOP:
                req.add_header(k, v)
        req.add_header("X-Hider-Redacted", "v1")
        return req

    def forward(self, path: str, payload: bytes, headers: dict) -> tuple[int, bytes, str]:
        try:
            with urllib.request.urlopen(self._request(path, payload, headers),
                                        timeout=self.timeout) as resp:
                return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers.get("Content-Type", "application/json")
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            # OSError and HTTPException cover the failures urllib does not
            # wrap: a connection reset mid-response, a truncated status line.
            # Any of them means "we could not be sure what the provider saw
            # or returned", which is a refusal, not a passthrough.
            reason = getattr(e, "reason", None) or e
            raise Refused(502, f"upstream unreachable: {reason}") from e

    def forward_stream(self, path: str, payload: bytes, headers: dict):
        """Open the upstream stream. Returns (status, response-or-bytes, ctype).

        A non-2xx answer is read whole and returned as bytes so the caller
        can pass it through as an ordinary error body.
        """
        try:
            resp = urllib.request.urlopen(self._request(path, payload, headers),
                                          timeout=self.timeout)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers.get("Content-Type", "application/json")
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            reason = getattr(e, "reason", None) or e
            raise Refused(502, f"upstream unreachable: {reason}") from e
        return resp.status, resp, resp.headers.get("Content-Type", "text/event-stream")

    # -- response rewriting ------------------------------------------------

    def detokenize_response(self, body: dict) -> list[str]:
        """Detokenise the reply in place. Returns labels the vault does not know."""
        unknown: list[str] = []

        def fix(text: str) -> str:
            for m in _LABEL_RE.finditer(text):
                lab = m.group(0)
                if not lab.startswith("<REDACTED:") and lab not in self.pipe.vault.by_label \
                        and lab not in unknown:
                    unknown.append(lab)
            return self.pipe.vault.detokenize(text)

        choices = body.get("choices")
        if not isinstance(choices, list):
            return unknown
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            msg = choice.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                msg["content"] = fix(msg["content"])
            if isinstance(choice.get("text"), str):
                choice["text"] = fix(choice["text"])
        return unknown

    @staticmethod
    def _usage_of(body: dict) -> dict | None:
        u = body.get("usage") if isinstance(body, dict) else None
        if not isinstance(u, dict):
            return None
        return {"input_tokens": u.get("prompt_tokens", u.get("input_tokens")),
                "output_tokens": u.get("completion_tokens", u.get("output_tokens"))}

    def _rewrite_stream(self, upstream, row: dict) -> Iterator[bytes]:
        """Yield rewritten SSE bytes, detokenising deltas with hold-back."""
        holders: dict[int, HoldbackDetokenizer] = {}
        last_chunk: dict | None = None
        t0 = time.perf_counter()

        def hold(i: int) -> HoldbackDetokenizer:
            h = holders.get(i)
            if h is None:
                h = holders[i] = HoldbackDetokenizer(self.pipe.vault)
            return h

        def final_chunks() -> Iterator[bytes]:
            for i, h in holders.items():
                tail = h.flush()
                if tail and last_chunk is not None:
                    chunk = {**last_chunk, "choices": [{
                        "index": i, "delta": {"content": tail}, "finish_reason": None}]}
                    yield f"data: {json.dumps(chunk)}\n\n".encode()

        try:
            with upstream:
                for raw_line in upstream:
                    line = raw_line.decode("utf-8", errors="replace")
                    if not line.startswith("data:"):
                        yield raw_line
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        yield from final_chunks()
                        yield raw_line
                        continue
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        yield raw_line
                        continue
                    if isinstance(chunk, dict):
                        usage = self._usage_of(chunk)
                        if usage:
                            row["usage"] = usage
                        if chunk.get("model"):
                            row["model"] = chunk["model"]
                        for choice in chunk.get("choices") or []:
                            if not isinstance(choice, dict):
                                continue
                            delta = choice.get("delta")
                            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                                idx = int(choice.get("index") or 0)
                                delta["content"] = hold(idx).feed(delta["content"])
                                last_chunk = {k: v for k, v in chunk.items() if k != "choices"}
                    yield f"data: {json.dumps(chunk)}\n".encode()
            # Upstream closed without [DONE]: release what is held.
            yield from final_chunks()
        finally:
            row["upstream_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            row["unknown_labels"] = sorted({u for h in holders.values() for u in h.unknown})
            self._record(row)

    # -- persistence -------------------------------------------------------

    def _record(self, row: dict) -> None:
        self.metrics.record(row)
        if self.log_path:
            line = json.dumps(row) + "\n"
            with self._log_lock:
                path = Path(self.log_path)
                if self.log_max_bytes is not None and self._log_would_overflow(path, line):
                    self._rotate_log(path)
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        if self.vault_path:
            with self._redact_lock:
                self.pipe.vault.save(self.vault_path)

    def _log_would_overflow(self, path: Path, line: str) -> bool:
        """True when appending ``line`` would take the active log past the cap.

        A row is never split across files: the check runs before the write,
        so a row that does not fit goes whole into a fresh file. A single row
        larger than the cap on its own is still written whole, into an
        otherwise empty file, rather than dropped. Called under ``_log_lock``.
        """
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        return size > 0 and size + len(line.encode("utf-8")) > self.log_max_bytes

    def _rotate_log(self, path: Path) -> None:
        """Move the full active log aside so a fresh one can start at ``path``.

        Numbered backups: ``path.1`` is the most recent full file, ``path.N``
        the oldest, with ``N = log_backups``; anything older is deleted. With
        ``log_backups == 0`` the active file is simply discarded. Called under
        ``_log_lock``.
        """
        backup = lambda n: path.with_name(f"{path.name}.{n}")  # noqa: E731
        if self.log_backups == 0:
            path.unlink(missing_ok=True)
            return
        backup(self.log_backups).unlink(missing_ok=True)
        for n in range(self.log_backups - 1, 0, -1):
            src = backup(n)
            if src.exists():
                src.replace(backup(n + 1))
        path.replace(backup(1))

    # -- one request -------------------------------------------------------

    def handle(self, path: str, payload: bytes, headers: dict) -> Response:
        rid = uuid.uuid4().hex[:16]
        row: dict = {"schema": LOG_SCHEMA, "request_id": rid, "path": path,
                     "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "stream": False, "degraded": False}
        out_headers = {"X-Hider-Request-Id": rid}
        if self.log_request_bodies:
            row["request_body"] = payload.decode("utf-8", errors="replace")
        try:
            return self._handle(path, payload, headers, row, out_headers)
        except Refused as r:
            row["refused_status"] = r.status
            row["refused_reason"] = r.message
            row["degraded"] = r.status == DEGRADED_STATUS
            self._record(row)
            return Response(r.status, {**out_headers, "Content-Type": "application/json"},
                            body=_error_body(r.message))

    def _handle(self, path: str, payload: bytes, headers: dict, row: dict,
                out_headers: dict) -> Response:
        try:
            body = json.loads(payload.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("payload is not a JSON object")
        except (ValueError, UnicodeDecodeError) as e:
            raise Refused(400, f"unparseable payload: {e}") from e
        row["model"] = body.get("model") if isinstance(body.get("model"), str) else None
        row["stream"] = bool(body.get("stream"))

        t0 = time.perf_counter()
        events = self.redact_payload(body)
        row["redact_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        row["redactions"] = len(events)
        row["redactions_by_type"] = dict(Counter(e["entity_type"] for e in events))
        row["redactions_by_tier"] = dict(Counter(e["tier"] for e in events))
        row["sweep_hits"] = sum(1 for e in events if e["tier"] == "sweep")
        row["events"] = events
        forwarded = json.dumps(body).encode("utf-8")

        if row["stream"]:
            status, resp, ctype = self.forward_stream(path, forwarded, headers)
            row["upstream_status"] = status
            if isinstance(resp, bytes):
                row["upstream_ms"] = 0.0
                self._record(row)
                return Response(status, {**out_headers, "Content-Type": ctype}, body=resp)
            return Response(status, {**out_headers, "Content-Type": ctype,
                                     "Cache-Control": "no-cache"},
                            chunks=self._rewrite_stream(resp, row))

        t1 = time.perf_counter()
        status, raw, ctype = self.forward(path, forwarded, headers)
        row["upstream_ms"] = round((time.perf_counter() - t1) * 1000, 2)
        row["upstream_status"] = status
        unknown: list[str] = []
        if status < 400:
            try:
                resp_body = json.loads(raw.decode("utf-8"))
                unknown = self.detokenize_response(resp_body)
                row["usage"] = self._usage_of(resp_body)
                if isinstance(resp_body, dict) and resp_body.get("model"):
                    row["model"] = resp_body["model"]
                raw = json.dumps(resp_body).encode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass  # non-JSON upstream body: pass through untouched
        row["unknown_labels"] = unknown
        if unknown:
            out_headers["X-Hider-Unknown-Labels"] = ",".join(unknown)
        self._record(row)
        return Response(status, {**out_headers, "Content-Type": ctype}, body=raw)


def make_server(host: str, port: int, gateway: RedactionGateway) -> ThreadingHTTPServer:
    """Bind an HTTP server whose handler drives ``gateway``."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # default handler prints to stderr
            return

        def _reply(self, status: int, body: bytes, headers: dict | None = None) -> None:
            self.send_response(status)
            for k, v in (headers or {"Content-Type": "application/json"}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _stream(self, resp: Response) -> None:
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for chunk in resp.chunks or ():
                    if not chunk:
                        continue
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
            finally:
                try:
                    self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    pass

        def do_GET(self):
            if self.path == "/healthz":
                body = json.dumps({
                    "status": "ok",
                    "upstream": gateway.upstream_base,
                    "tiers": [getattr(t, "name", "?") for t in gateway.pipe.tiers],
                    "vault_entries": gateway.pipe.vault.size,
                    "metrics": gateway.metrics.to_dict(),
                }).encode()
                self._reply(200, body)
            else:
                self._reply(404, _error_body("not found"))

        def do_POST(self):
            if self.path not in ("/v1/chat/completions", "/v1/completions"):
                self._reply(404, _error_body("unsupported endpoint"))
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = 0
            payload = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()}
            resp = gateway.handle(self.path, payload, headers)
            if resp.chunks is not None:
                self._stream(resp)
            else:
                self._reply(resp.status, resp.body or b"", resp.headers)

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int, gateway: RedactionGateway) -> None:
    httpd = make_server(host, port, gateway)
    print(f"hider gateway on http://{host}:{port} -> {gateway.upstream_base} "
          f"(tiers: {', '.join(getattr(t, 'name', '?') for t in gateway.pipe.tiers)})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
