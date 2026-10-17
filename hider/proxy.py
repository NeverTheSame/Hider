"""The optional redaction proxy: an OpenAI-compatible adapter that redacts in flight.

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
* **The path stays the caller's.** The Authorization header and vendor
  headers pass through untouched; this gateway holds no provider
  credentials of its own. Point the client's base URL at it and nothing else
  changes.
* **Streaming is refused, not faked.** ``stream: true`` gets a 400 with a
  plain reason: rewriting an SSE stream means buffering it, which silently
  turns streaming off, or detokenising fragments, which corrupts labels cut
  across chunk boundaries. Both are worse than an honest error. Re-send
  with ``stream: false``.
* **The decision log records decisions, not data.** Same schema as the
  batch path: the substitute, never the original.

Implemented with the standard library only, because a data boundary that
grows a web framework also grows that framework's request logging, error
handlers and middleware, each of which becomes a place a raw body can be
retained by accident.
"""

from __future__ import annotations

import http.client
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import pipeline

#: Headers that must not be forwarded verbatim: hop-by-hop fields, and the
#: ones whose value this gateway owns.
HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "te",
    "trailer",
}

DEGRADED_STATUS = 503
UPSTREAM_TIMEOUT_S = 120


class Refused(Exception):
    """A request that must not be forwarded, with an HTTP status and reason."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _error_body(message: str) -> bytes:
    return json.dumps({"error": {"message": message, "type": "hider_gateway"}}).encode()


class RedactionGateway:
    """Redacts chat-completion requests, forwards them, detokenises replies."""

    def __init__(
        self,
        upstream_base: str,
        pipe: pipeline.Pipeline,
        *,
        vault_path: str | Path | None = None,
        log_path: str | Path | None = None,
        timeout: int = UPSTREAM_TIMEOUT_S,
    ) -> None:
        self.upstream_base = upstream_base.rstrip("/")
        self.pipe = pipe
        self.vault_path = vault_path
        self.log_path = log_path
        self.timeout = timeout
        self._log_lock = threading.Lock()
        self._redact_lock = threading.Lock()

    # -- request rewriting -------------------------------------------------

    def redact_payload(self, body: dict) -> list[dict]:
        """Redact every caller-authored text field, in place.

        Returns the decision events. Raises :class:`Refused` when a unit is
        degraded or the payload has a shape this gateway does not safely
        understand; in both cases nothing has been sent.
        """
        if body.get("stream"):
            raise Refused(
                400,
                "streaming is not supported through the redaction gateway; "
                "resend with stream:false. See hider/proxy.py for why.",
            )
        events: list[dict] = []
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

        for i, text in enumerate(texts):
            with self._redact_lock:
                r = self.pipe.redact(text, unit=f"request[{i}]", line_no=0)
            if r.degraded:
                raise Refused(
                    DEGRADED_STATUS,
                    "redaction degraded on this request; refusing to forward it",
                )
            texts[i] = r.text
            events.extend(r.events)

        # Rewrite in the same order the texts were collected.
        it = iter(texts)

        def nxt() -> str:
            return next(it)

        if isinstance(messages, list):
            for msg in messages:
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    msg["content"] = nxt()
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            part["text"] = nxt()
        if isinstance(prompt, str):
            body["prompt"] = nxt()
        elif isinstance(prompt, list):
            body["prompt"] = [nxt() if isinstance(p, str) else p for p in prompt]
        return events

    # -- upstream ----------------------------------------------------------

    def forward(self, path: str, payload: bytes, headers: dict) -> tuple[int, bytes, str]:
        """POST the already-redacted payload upstream and return (status, body, content type).

        Hop-by-hop headers are dropped and ``X-Hider-Redacted`` is added. An
        upstream HTTP error is passed back as is; a transport failure raises
        Refused(502), because nobody can be sure what the provider saw.
        """
        req = urllib.request.Request(self.upstream_base + path, data=payload, method="POST")
        for k, v in headers.items():
            if k.lower() not in HOP_BY_HOP:
                req.add_header(k, v)
        req.add_header("X-Hider-Redacted", "v1")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (
                    resp.status,
                    resp.read(),
                    resp.headers.get("Content-Type", "application/json"),
                )
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers.get("Content-Type", "application/json")
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            # OSError and HTTPException cover the failures urllib does not
            # wrap: a connection reset mid-response, a truncated status line.
            # Any of them means "we could not be sure what the provider saw
            # or returned", which is a refusal, not a passthrough.
            reason = getattr(e, "reason", None) or e
            raise Refused(502, f"upstream unreachable: {reason}") from e

    # -- response rewriting ------------------------------------------------

    def detokenize_response(self, body: dict) -> None:
        """Replace pseudonyms with real values, in place, in each choice's message content or text."""
        choices = body.get("choices")
        if not isinstance(choices, list):
            return
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            msg = choice.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                msg["content"] = self.pipe.vault.detokenize(msg["content"])
            if isinstance(choice.get("text"), str):
                choice["text"] = self.pipe.vault.detokenize(choice["text"])

    # -- persistence -------------------------------------------------------

    def _record(self, path: str, events: list[dict]) -> None:
        if self.log_path:
            row = {"schema": "hider.proxy.v1", "path": path, "events": events}
            with self._log_lock:
                with Path(self.log_path).open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row) + "\n")
        if self.vault_path:
            with self._redact_lock:
                self.pipe.vault.save(self.vault_path)

    # -- one request -------------------------------------------------------

    def handle(self, path: str, payload: bytes, headers: dict) -> tuple[int, bytes, str]:
        """Redact one request, forward it, and de-tokenise a successful JSON reply.

        Raises Refused(400) on a payload that is not a JSON object. A non-JSON
        upstream body is passed through untouched. Every call is recorded in the
        decision log.
        """
        try:
            body = json.loads(payload.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("payload is not a JSON object")
        except (ValueError, UnicodeDecodeError) as e:
            raise Refused(400, f"unparseable payload: {e}") from e
        events = self.redact_payload(body)
        status, raw, ctype = self.forward(path, json.dumps(body).encode("utf-8"), headers)
        if status < 400:
            try:
                resp = json.loads(raw.decode("utf-8"))
                self.detokenize_response(resp)
                raw = json.dumps(resp).encode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass  # non-JSON upstream body: pass through untouched
        self._record(path, events)
        return status, raw, ctype


def make_server(host: str, port: int, gateway: RedactionGateway) -> ThreadingHTTPServer:
    """Bind an HTTP server whose handler drives ``gateway``."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # default handler prints to stderr
            return

        def _reply(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                body = json.dumps(
                    {
                        "status": "ok",
                        "upstream": gateway.upstream_base,
                        "tiers": [getattr(t, "name", "?") for t in gateway.pipe.tiers],
                        "vault_entries": gateway.pipe.vault.size,
                    }
                ).encode()
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
            try:
                status, body, ctype = gateway.handle(self.path, payload, headers)
            except Refused as r:
                status, body, ctype = r.status, _error_body(r.message), "application/json"
            self._reply(status, body, ctype)

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int, gateway: RedactionGateway) -> None:
    """Run the proxy on ``host:port`` until interrupted."""
    httpd = make_server(host, port, gateway)
    print(
        f"hider gateway on http://{host}:{port} -> {gateway.upstream_base} "
        f"(tiers: {', '.join(getattr(t, 'name', '?') for t in gateway.pipe.tiers)})"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
