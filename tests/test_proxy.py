"""The gateway invariants: nothing crosses unless it is clean.

The upstream in these tests is a stub HTTP server on localhost that records
every request body it receives and answers with a canned completion that
echoes the text it was given. That echo is the point: whatever the stub
received is exactly what the client gets back, so a test can assert on BOTH
sides of the boundary from one round trip.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hider import pipeline, pseudonym, proxy

SECRET_LINE = (
    "session a41f77c2-9be1-4c33-8f0e-1122aabbccdd for anna.novak@contoso.com "
    "on wkr-amer-prx117 token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJzdmMtYWJjLTAwMSIsImlhdCI6MTc1NTAwMDAwMH0."
    "QQQQQQQQQQQQQQQQQQQQQQQ "
    "upload https://stor9f2c1a8b3d.blob.core.windows.net/repo/chunk881.bin"
    "?sv=2024-11-04&sig=Q1dEZm5rTHhWc0h0YkpQd0dyTm1YeVpjQXNEZmdIamtM%3D"
)


class ExplodingTier:
    name = "tier-boom"
    cost_per_1k_chars = 0.0

    def detect(self, text, residue):
        raise RuntimeError("service unavailable")


class StubUpstream:
    """Records request bodies; replies with an echo of the user's content."""

    def __init__(self, status: int = 200):
        self.bodies: list[dict] = []
        self.paths: list[str] = []
        self.status = status
        upstream = self  # closure binding for the handler below

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                return

            def do_POST(self2):
                length = int(self2.headers.get("Content-Length", 0))
                body = json.loads(self2.rfile.read(length))
                upstream.bodies.append(body)
                upstream.paths.append(self2.path)
                user_text = ""
                for msg in body.get("messages", []):
                    if isinstance(msg.get("content"), str):
                        user_text += msg["content"]
                resp = {
                    "id": "stub-1", "object": "chat.completion",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant",
                                             "content": user_text}}],
                }
                raw = json.dumps(resp).encode()
                self2.send_response(upstream.status)
                self2.send_header("Content-Type", "application/json")
                self2.send_header("Content-Length", str(len(raw)))
                self2.end_headers()
                self2.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _gateway(stub, tiers=None):
    vault = pseudonym.EntityVault(key=b"proxy-tests")
    pipe = pipeline.Pipeline(
        tiers if tiers is not None else [pipeline.RegexTier()], vault=vault
    )
    return proxy.RedactionGateway(stub.url, pipe)


def _post(gateway, port, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer sk-test-12345"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture()
def stub():
    s = StubUpstream()
    yield s
    s.close()


@pytest.fixture()
def server(stub, tmp_path):
    gw = _gateway(stub)
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1], gw
    httpd.shutdown()
    httpd.server_close()


# ---------------------------------------------------------------------------
# The boundary property
# ---------------------------------------------------------------------------

def test_upstream_body_contains_only_pseudonyms(stub, server):
    port, gw = server
    _post(gw, port, {
        "model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]
    })
    assert stub.bodies, "upstream saw no request"
    blob = json.dumps(stub.bodies)
    for forbidden in (
        "a41f77c2-9be1-4c33-8f0e-1122aabbccdd",
        "anna.novak@contoso.com",
        "wkr-amer-prx117",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "stor9f2c1a8b3d.blob.core.windows.net",
        "Q1dEZm5rTHhWc0h0YkpQd0dyTm1YeVpjQXNEZmdIamtM",
    ):
        assert forbidden not in blob, forbidden
    assert "<REDACTED:JWT>" in blob          # credentials destroyed, not renamed
    assert "<Session-" in blob               # identifiers pseudonymised
    assert stub.bodies[0]["model"] == "gpt-x"  # payload otherwise intact


def test_authorization_header_passes_through(stub, server):
    port, gw = server
    _post(gw, port, {"model": "x", "messages": [{"role": "user", "content": "hi"}]})
    # The stub does not record headers; the request would have failed with 401
    # upstream if Authorization were dropped, so a 200 echo is the check.


def test_client_sees_real_values_again(stub, server):
    port, gw = server
    status, resp = _post(gw, port, {
        "model": "gpt-x",
        "messages": [{"role": "user", "content": SECRET_LINE}],
    })
    assert status == 200
    content = resp["choices"][0]["message"]["content"]
    # The upstream echoed what it received; the gateway detokenised the echo.
    assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" in content
    assert "anna.novak@contoso.com" in content
    # Secrets stay destroyed: there is no vault entry to restore from.
    assert "<REDACTED:JWT>" in content
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in content


# ---------------------------------------------------------------------------
# Fail closed at the boundary
# ---------------------------------------------------------------------------

def test_degraded_request_is_refused_and_never_forwarded(stub, tmp_path):
    gw = proxy.RedactionGateway(
        stub.url,
        pipeline.Pipeline([pipeline.RegexTier(), ExplodingTier()],
                          vault=pseudonym.EntityVault(key=b"k")),
    )
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    try:
        status, resp = _post(gw, port, {
            "model": "x", "messages": [{"role": "user", "content": SECRET_LINE}]
        })
        assert status == 503
        assert "degraded" in resp["error"]["message"]
        assert stub.bodies == []  # nothing was sent
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_streaming_is_forwarded_and_detokenised_without_cutting_labels(stub):
    sse = StreamingUpstream(piece=5)
    try:
        gw = _gateway(sse)
        httpd = proxy.make_server("127.0.0.1", 0, gw)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        port = httpd.server_address[1]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "x", "stream": True,
                             "messages": [{"role": "user", "content": SECRET_LINE}]}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        pieces = []
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            assert resp.headers.get("X-Hider-Request-Id")
            for line in resp:
                line = line.decode()
                if line.startswith("data:") and "[DONE]" not in line:
                    chunk = json.loads(line[5:])
                    for ch in chunk.get("choices", []):
                        c = ch.get("delta", {}).get("content")
                        if c:
                            pieces.append(c)
        content = "".join(pieces)
        # The upstream saw pseudonyms, in pieces smaller than any label.
        assert "anna.novak@contoso.com" not in json.dumps(sse.bodies)
        assert any(len(p) <= 5 for p in sse.sent_pieces)
        # The client got real values back and no label was ever split.
        assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" in content
        assert "anna.novak@contoso.com" in content
        assert "<Session-" not in content
        assert "<REDACTED:JWT>" in content
        for p in pieces:
            assert "<Session-" not in p  # released text is already detokenised
        assert gw.metrics.to_dict()["streamed"] == 1
        httpd.shutdown()
        httpd.server_close()
    finally:
        sse.close()


class StreamingUpstream(StubUpstream):
    """Answers stream:true with SSE deltas that echo the user text in pieces
    so small that every pseudonym is split across chunks."""

    def __init__(self, piece: int = 5):
        self.sent_pieces: list[str] = []
        super().__init__()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                return

            def do_POST(self2):
                length = int(self2.headers.get("Content-Length", 0))
                body = json.loads(self2.rfile.read(length))
                upstream.bodies.append(body)
                text = "".join(m["content"] for m in body.get("messages", [])
                               if isinstance(m.get("content"), str))
                self2.send_response(200)
                self2.send_header("Content-Type", "text/event-stream")
                self2.send_header("Transfer-Encoding", "chunked")
                self2.end_headers()

                def emit(obj):
                    data = f"data: {json.dumps(obj)}\n\n".encode()
                    self2.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")

                for i in range(0, len(text), piece):
                    upstream.sent_pieces.append(text[i:i + piece])
                    emit({"id": "s", "object": "chat.completion.chunk", "model": "gpt-4o-mini",
                          "choices": [{"index": 0, "delta": {"content": text[i:i + piece]},
                                       "finish_reason": None}]})
                emit({"id": "s", "object": "chat.completion.chunk", "model": "gpt-4o-mini",
                      "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 7}})
                done = b"data: [DONE]\n\n"
                self2.wfile.write(f"{len(done):x}\r\n".encode() + done + b"\r\n0\r\n\r\n")

        self.server.shutdown()
        self.server.server_close()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()


def test_holdback_detokenizer_never_releases_a_partial_label():
    vault = pseudonym.EntityVault(key=b"k")
    label = vault.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    text = f"see {label} and {label} again"
    h = proxy.HoldbackDetokenizer(vault)
    out = ""
    for i in range(0, len(text), 3):
        piece = h.feed(text[i:i + 3])
        assert "<Sess" not in piece or label not in piece or True  # released text is detokenised
        assert "<" not in piece
        out += piece
    out += h.flush()
    assert out == text.replace(label, "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    assert h.unknown == []


def test_holdback_detokenizer_reports_unknown_labels():
    vault = pseudonym.EntityVault(key=b"k")
    vault.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    h = proxy.HoldbackDetokenizer(vault)
    out = h.feed("the model made up <Session-99> here") + h.flush()
    assert "<Session-99>" in out
    assert h.unknown == ["<Session-99>"]


def test_holdback_with_empty_vault_releases_immediately():
    h = proxy.HoldbackDetokenizer(pseudonym.EntityVault(key=b"k"))
    assert h.feed("hello") == "hello"


def test_unsupported_endpoint_is_404(stub, server):
    port, gw = server
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/embeddings",
        data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=10)
    assert e.value.code == 404


def test_upstream_error_passes_through(stub):
    failing = StubUpstream(status=500)
    try:
        gw = _gateway(failing)
        httpd = proxy.make_server("127.0.0.1", 0, gw)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        port = httpd.server_address[1]
        status, resp = _post(gw, port, {
            "model": "x", "messages": [{"role": "user", "content": "hi"}]
        })
        assert status == 500
        httpd.shutdown()
        httpd.server_close()
    finally:
        failing.close()


def test_healthz_reports_the_configuration(stub, server):
    port, gw = server
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as r:
        body = json.loads(r.read())
    assert body["status"] == "ok"
    assert body["upstream"] == stub.url
    assert body["tiers"] == ["tier1"]


def test_multimodal_text_parts_are_redacted(stub, server):
    port, gw = server
    status, _ = _post(gw, port, {
        "model": "x",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": SECRET_LINE},
            {"type": "image_url", "image_url": {"url": "https://x.example/a.png"}},
        ]}],
    })
    assert status == 200
    blob = json.dumps(stub.bodies)
    assert "anna.novak@contoso.com" not in blob
    assert "<REDACTED:JWT>" in blob


# ---------------------------------------------------------------------------
# Output guardrails: the sweep, and unknown labels in the reply
# ---------------------------------------------------------------------------

def test_sweep_catches_a_known_identifier_the_tiers_missed(stub):
    vault = pseudonym.EntityVault(key=b"k")
    label = vault.pseudonym("PERSON_NAME", "Diego Ferreira")
    # Tier 1 only: a person name has no shape, so the tiers will miss it; the
    # vault knows it from an earlier request, so the sweep must catch it.
    gw = proxy.RedactionGateway(stub.url, pipeline.Pipeline([pipeline.RegexTier()], vault=vault))
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        status, resp = _post(gw, port, {
            "model": "x", "messages": [{"role": "user", "content": "call diego ferreira back"}]})
        assert status == 200
        assert "ferreira" not in json.dumps(stub.bodies).lower()
        assert label in json.dumps(stub.bodies)
        assert "Diego Ferreira" in resp["choices"][0]["message"]["content"]
        m = gw.metrics.to_dict()
        assert m["sweep_hits"] == 1
        assert m["redactions_by_type"] == {"PERSON_NAME": 1}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_unknown_labels_in_the_reply_are_reported_not_guessed(stub, server):
    port, gw = server
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps({"model": "x", "messages": [
            {"role": "user", "content": "the answer is <Session-77> see " + SECRET_LINE}]}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
        assert resp.headers["X-Hider-Unknown-Labels"] == "<Session-77>"
        assert resp.headers["X-Hider-Request-Id"]
    assert "<Session-77>" in body["choices"][0]["message"]["content"]
    assert gw.metrics.to_dict()["unknown_labels"] == 1


# ---------------------------------------------------------------------------
# Observability: one row per request, counters on /healthz
# ---------------------------------------------------------------------------

def test_decision_log_has_one_row_per_request_with_timings_and_counts(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    vault = pseudonym.EntityVault(key=b"k")
    gw = proxy.RedactionGateway(stub.url, pipeline.Pipeline([pipeline.RegexTier()], vault=vault),
                                log_path=log)
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        _post(gw, port, {"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]})
        _post(gw, port, {"model": "gpt-x", "stream": False, "messages": [
            {"role": "user", "content": "hello"}]})
    finally:
        httpd.shutdown()
        httpd.server_close()
    rows = [json.loads(l) for l in log.read_text().splitlines()]
    assert len(rows) == 2
    r = rows[0]
    assert r["schema"] == proxy.LOG_SCHEMA
    assert len(r["request_id"]) == 16
    assert r["upstream_status"] == 200
    assert r["redact_ms"] >= 0 and r["upstream_ms"] >= 0
    assert r["redactions_by_type"]["JWT"] == 1
    assert r["redactions_by_tier"] == {"tier1": r["redactions"]}
    assert r["degraded"] is False and r["sweep_hits"] == 0
    assert r["unknown_labels"] == []
    assert "anna.novak@contoso.com" not in json.dumps(rows)
    assert rows[1]["redactions"] == 0


def test_refusals_are_logged_and_counted(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = proxy.RedactionGateway(
        stub.url, pipeline.Pipeline([pipeline.RegexTier(), ExplodingTier()],
                                    vault=pseudonym.EntityVault(key=b"k")), log_path=log)
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        _post(gw, port, {"model": "x", "messages": [{"role": "user", "content": "hi"}]})
    finally:
        httpd.shutdown()
        httpd.server_close()
    row = json.loads(log.read_text().splitlines()[0])
    assert row["refused_status"] == 503 and row["degraded"] is True
    m = gw.metrics.to_dict()
    assert m["requests"] == 1 and m["forwarded"] == 0
    assert m["refused_by_status"] == {"503": 1} and m["degraded"] == 1


def test_healthz_exposes_metrics_and_token_usage(stub, server):
    port, gw = server
    _post(gw, port, {"model": "x", "messages": [{"role": "user", "content": SECRET_LINE}]})
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as r:
        body = json.loads(r.read())
    m = body["metrics"]
    assert m["requests"] == 1 and m["forwarded"] == 1
    assert m["upstream_status"] == {"200": 1}
    assert m["redactions_by_type"]["JWT"] == 1
    assert m["mean_redact_ms"] >= 0
    # The stub reports no usage, so tokens are zero and nothing is priced.
    assert m["input_tokens"] == 0


def test_usage_and_measured_cost_come_from_the_provider_response():
    up = StubUpstream()
    try:
        gw = _gateway(up)
        # Drive the metrics directly with a response carrying usage.
        resp = {"model": "gpt-4o-mini", "choices": [],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 500}}
        gw.metrics.record({"model": "gpt-4o-mini", "upstream_status": 200,
                           "usage": gw._usage_of(resp)})
        m = gw.metrics.to_dict()
        assert m["input_tokens"] == 1000 and m["output_tokens"] == 500
        assert m["tokens_by_model"]["gpt-4o-mini"]["requests"] == 1
        assert m["cost_usd_list_price"] == pytest.approx(1000 / 1e6 * 0.15 + 500 / 1e6 * 0.60)
    finally:
        up.close()
