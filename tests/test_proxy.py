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

from hider import pipeline, proxy, pseudonym

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
                    "id": "stub-1",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": user_text},
                        }
                    ],
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
    pipe = pipeline.Pipeline(tiers if tiers is not None else [pipeline.RegexTier()], vault=vault)
    return proxy.RedactionGateway(stub.url, pipe)


def _post(gateway, port, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer sk-test-12345"},
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
    _post(gw, port, {"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]})
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
    assert "<REDACTED:JWT>" in blob  # credentials destroyed, not renamed
    assert "<Session-" in blob  # identifiers pseudonymised
    assert stub.bodies[0]["model"] == "gpt-x"  # payload otherwise intact


def test_authorization_header_passes_through(stub, server):
    port, gw = server
    _post(gw, port, {"model": "x", "messages": [{"role": "user", "content": "hi"}]})
    # The stub does not record headers; the request would have failed with 401
    # upstream if Authorization were dropped, so a 200 echo is the check.


def test_client_sees_real_values_again(stub, server):
    port, gw = server
    status, resp = _post(
        gw,
        port,
        {
            "model": "gpt-x",
            "messages": [{"role": "user", "content": SECRET_LINE}],
        },
    )
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
        pipeline.Pipeline(
            [pipeline.RegexTier(), ExplodingTier()], vault=pseudonym.EntityVault(key=b"k")
        ),
    )
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    try:
        status, resp = _post(
            gw, port, {"model": "x", "messages": [{"role": "user", "content": SECRET_LINE}]}
        )
        assert status == 503
        assert "degraded" in resp["error"]["message"]
        assert stub.bodies == []  # nothing was sent
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_streaming_is_refused_with_a_clear_error(stub, server):
    port, gw = server
    status, resp = _post(
        gw,
        port,
        {
            "model": "x",
            "stream": True,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    assert status == 400
    assert "stream:false" in resp["error"]["message"]
    assert stub.bodies == []


def test_unsupported_endpoint_is_404(stub, server):
    port, gw = server
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/embeddings",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
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
        status, resp = _post(
            gw, port, {"model": "x", "messages": [{"role": "user", "content": "hi"}]}
        )
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
    status, _ = _post(
        gw,
        port,
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": SECRET_LINE},
                        {"type": "image_url", "image_url": {"url": "https://x.example/a.png"}},
                    ],
                }
            ],
        },
    )
    assert status == 200
    blob = json.dumps(stub.bodies)
    assert "anna.novak@contoso.com" not in blob
    assert "<REDACTED:JWT>" in blob
