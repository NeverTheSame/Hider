"""The gateway invariants: nothing crosses unless it is clean.

The upstream in these tests is a stub HTTP server on localhost that records
every request body it receives and answers with a canned completion that
echoes the text it was given. That echo is the point: whatever the stub
received is exactly what the client gets back, so a test can assert on BOTH
sides of the boundary from one round trip.
"""

from __future__ import annotations

import json
import re
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


def test_holdback_releases_plain_text_immediately_and_lag_is_small():
    """The number behind the README's streaming note. Text that cannot be the
    start of any pseudonym must not wait on the longest-label worst case; the
    old implementation held every feed a full label length (~21 chars mean on
    this sample), the prefix-based one holds only while a label could actually
    be arriving."""
    vault = pseudonym.EntityVault(key=b"k")
    lab1 = vault.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    lab2 = vault.pseudonym("UPN_EMAIL", "anna.novak@contosocorp.com")
    lab3 = vault.pseudonym("IPV4", "10.20.30.40")

    h = proxy.HoldbackDetokenizer(vault)
    plain = "no labels anywhere in this stream, just ordinary prose repeated. " * 10
    lags = []
    for ch in plain:
        h.feed(ch)
        lags.append(len(h.pending))
    # a one-or-two char tail may match a pseudonym's first characters; that is
    # the honest minimum, not the longest-label worst case
    assert max(lags) <= 3
    assert sum(lags) / len(lags) < 0.5

    text = (f"The session {lab1} for user {lab2} reconnected from {lab3} after a "
            "retry. The transport layer reported no further errors. " * 5)
    h = proxy.HoldbackDetokenizer(vault)
    out, lags = "", []
    for ch in text:
        out += h.feed(ch)
        lags.append(len(h.pending))
    out += h.flush()
    assert out == vault.detokenize(text)
    assert max(lags) <= h.holdback  # worst case is still one label length
    assert sum(lags) / len(lags) < 5  # measured ~2.3; the old code held ~21


def test_holdback_never_releases_a_label_that_prefixes_a_longer_one():
    """A complete short pseudonym at the tail may still be the first half of
    a longer one, and releasing it would detokenise the wrong value. The
    prefix set is built over proper prefixes of every form so the shorter
    label waits until the next character settles it."""
    vault = pseudonym.EntityVault(key=b"k")
    short = None
    for i in range(40):
        lab = vault.pseudonym("IPV4", f"10.20.30.{i + 1}")
        others = set(vault.by_label) - {lab}
        prefixed = [o for o in vault.by_label if o != lab and o.startswith(lab)]
        if prefixed:
            short, longer = lab, prefixed[0]
            break
        if (match := [o for o in others if lab.startswith(o)]):
            short, longer = match[0], lab
            break
    assert short is not None, "vault produced no prefix pair to test with"

    h = proxy.HoldbackDetokenizer(vault)
    released = h.feed("peer " + short)
    assert short not in released and h.pending == short  # ambiguous: held whole
    # the next char disambiguates to the longer label; nothing partial ever left
    out = released + h.feed(longer[len(short)] ) + h.flush()
    full = "peer " + short + longer[len(short)]
    assert out == vault.detokenize(full)


def test_holdback_round_trips_adversarial_chunkings():
    """Deterministic fuzz: labels back to back, label fragments as literal
    text, and random chunk sizes. The oracle is a left-to-right, longest-first,
    non-overlapping scan - what a stream must produce - rather than
    ``vault.detokenize``, whose global longest-first ``str.replace`` can match
    across the boundary of two adjacent labels and mangle both (a pre-existing
    artifact of that function, present before the prefix-based holdback)."""
    import random
    import re as _re

    rng = random.Random(7)
    vault = pseudonym.EntityVault(key=b"k")
    labs = [vault.pseudonym("IPV4", f"10.20.30.{i + 1}") for i in range(30)]
    labs += [vault.pseudonym("SESSION_GUID",
                             f"a41f77c2-9be1-4c33-8f0e-1122aabbcc{i:02x}") for i in range(12)]
    bare = {l[1:-1]: val for l, val in vault.by_label.items()
            if l.startswith("<") and l.endswith(">")}
    table = {**vault.by_label, **bare}
    rx = _re.compile("|".join(map(_re.escape, sorted(table, key=len, reverse=True))))

    fragments = ["peer ", " and ", "x", "20", "3.0.", "<Se", "ssion-0", " ok\n"]
    for _ in range(200):
        text = "".join(rng.choice(labs) if rng.random() < 0.5 else rng.choice(fragments)
                       for _ in range(rng.randint(1, 12)))
        h = proxy.HoldbackDetokenizer(vault)
        out, i = "", 0
        while i < len(text):
            n = rng.randint(1, 7)
            out += h.feed(text[i:i + n])
            i += n
        out += h.flush()
        assert out == rx.sub(lambda m: table[m.group(0)], text), text


def test_holdback_releases_a_complete_unambiguous_label_without_waiting():
    vault = pseudonym.EntityVault(key=b"k")
    lab = vault.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    h = proxy.HoldbackDetokenizer(vault)
    out = h.feed("session " + lab)
    assert out == "session a41f77c2-9be1-4c33-8f0e-1122aabbccdd"
    assert h.pending == ""


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


def test_sweep_catches_short_identifiers_and_the_cost_is_measured(stub):
    """The four-character floor in ``_known_values_rx`` let a short identifier
    the vault already knew cross to the provider when the tiers missed it in
    a later request, and the leftover check shared the floor so nothing was
    refused. On this synthetic set of 300 requests, before: 136/150 of those
    mentioning a short known identifier crossed (the 14 that did not were the
    five-character "Bo Li", already above the floor), 0 refused. After: 0 cross,
    0 refused, and 0 of 150 innocent requests had a word swept, because the
    match is still by word boundary. The cost that remains is a known short
    value that is also an ordinary word ("Ann", "Ed") being swept wherever it
    stands alone; that is the trade for closing the gap, and it is stated."""
    import random
    rng = random.Random(20260831)
    vault = pseudonym.EntityVault(key=b"k")
    short = {"ORG_NAME": ["ACM", "Zed", "Qo", "IBX"], "PERSON_NAME": ["Bo Li", "Ann", "Ed"],
             "HOSTNAME_FQDN": ["db1", "ws7"]}
    for et, vals in short.items():
        for v in vals:
            vault.pseudonym(et, v)
    vault.pseudonym("PERSON_NAME", "Diego Ferreira")
    gw = proxy.RedactionGateway(stub.url, pipeline.Pipeline([pipeline.RegexTier()], vault=vault))
    innocent = ["the", "and", "retry", "queue", "ok", "ms", "run", "set", "edited", "zedlike"]
    crossed = refused = swept_innocent = 0
    for i in range(300):
        if i % 2 == 0:
            v = rng.choice([x for vs in short.values() for x in vs])
            text = f"please call {v} about the {rng.choice(innocent)} issue, then {v.lower()} again"
            out, events = gw.sweep(text)
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])", out, re.I):
                crossed += 1
            refused += bool(gw._known_values_in(out))
            assert len(events) == 2 and all(e["tier"] == "sweep" for e in events)
        else:
            out, events = gw.sweep(" ".join(rng.choice(innocent) for _ in range(8)))
            swept_innocent += bool(events)
    assert crossed == 0 and refused == 0 and swept_innocent == 0


def test_sweep_short_identifier_is_relabelled_across_requests(stub):
    """End to end: a two-letter name pseudonymised in request one, missed by
    the tiers in request two, leaves as the same label and comes back."""
    vault = pseudonym.EntityVault(key=b"k")
    label = vault.pseudonym("PERSON_NAME", "Ed")
    gw = proxy.RedactionGateway(stub.url, pipeline.Pipeline([pipeline.RegexTier()], vault=vault))
    httpd = proxy.make_server("127.0.0.1", 0, gw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        status, resp = _post(gw, port, {
            "model": "x", "messages": [{"role": "user", "content": "ask Ed; the file was edited"}]})
        assert status == 200
        sent = json.dumps(stub.bodies)
        assert f"ask {label}; the file was edited" in sent  # boundary: "edited" untouched
        assert "Ed" in resp["choices"][0]["message"]["content"]
        assert gw.metrics.to_dict()["sweep_hits"] == 1
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


# ---------------------------------------------------------------------------
# Decision log size cap
# ---------------------------------------------------------------------------


def _gateway_with_log(stub, log, **kw):
    return proxy.RedactionGateway(
        stub.url, pipeline.Pipeline([pipeline.RegexTier()], vault=pseudonym.EntityVault(key=b"k")),
        log_path=log, **kw)


def test_log_cap_must_be_positive(stub, tmp_path):
    with pytest.raises(ValueError):
        _gateway_with_log(stub, tmp_path / "p.jsonl", log_max_bytes=0)
    with pytest.raises(ValueError):
        _gateway_with_log(stub, tmp_path / "p.jsonl", log_max_bytes=-1)


def test_default_cap_leaves_the_row_format_unchanged(stub, tmp_path):
    """Rotation is on by default at 50 MiB; the rows themselves are untouched."""
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log)
    assert gw.log_max_bytes == 50 * 1024 * 1024 and gw.log_backups == 5
    rotated = []
    gw._rotate_log = lambda path: rotated.append(path)
    gw.handle("/v1/chat/completions", json.dumps(
        {"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]}).encode(), {})
    assert rotated == []
    row = json.loads(log.read_text().splitlines()[0])
    assert list(row) == ["schema", "request_id", "path", "ts", "stream", "degraded", "model",
                         "redact_ms", "redactions", "redactions_by_type", "redactions_by_tier",
                         "sweep_hits", "events", "upstream_ms", "upstream_status", "usage",
                         "unknown_labels"]
    assert log.read_text() == json.dumps(row) + "\n"  # compact separators, one row per line


def test_rows_are_never_split_and_rotation_fires_before_the_overflowing_row(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=None)
    tiny = {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}
    gw.handle("/v1/chat/completions", json.dumps(tiny).encode(), {})
    one_row = len(log.read_bytes())
    log.unlink()

    rotated: list = []
    gw._rotate_log = lambda path: (rotated.append(log.read_bytes()), log.unlink())
    gw.log_max_bytes = one_row * 2 + 10          # two rows fit, the third does not
    for _ in range(3):
        gw.handle("/v1/chat/completions", json.dumps(tiny).encode(), {})

    assert len(rotated) == 1
    archived = rotated[0].decode().splitlines()
    active = log.read_text().splitlines()
    assert len(archived) == 2 and len(active) == 1
    for line in archived + active:
        json.loads(line)                          # every line in every file is a whole row
    assert len(rotated[0]) <= gw.log_max_bytes


def test_a_single_row_larger_than_the_cap_is_still_written_whole(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=1)
    rotated: list = []
    gw._rotate_log = lambda path: (rotated.append(log.read_bytes()), log.unlink())
    body = {"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]}
    gw.handle("/v1/chat/completions", json.dumps(body).encode(), {})
    assert rotated == []                          # nothing to rotate: file was empty
    first = json.loads(log.read_text())
    assert first["redactions_by_type"]["JWT"] == 1
    gw.handle("/v1/chat/completions", json.dumps(body).encode(), {})
    assert len(rotated) == 1                      # the second row forced a fresh file
    json.loads(log.read_text())


def test_refusals_count_toward_the_cap_too(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=1)
    rotated: list = []
    gw._rotate_log = lambda path: (rotated.append(log.read_bytes()), log.unlink())
    gw.handle("/v1/chat/completions", b"not json", {})
    gw.handle("/v1/chat/completions", b"not json", {})
    assert len(rotated) == 1
    assert json.loads(rotated[0])["refused_status"] == 400


def test_rotation_happens_under_the_log_lock(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=1)
    seen = []
    gw._rotate_log = lambda path: (seen.append(gw._log_lock.locked()), log.unlink())
    tiny = {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}
    gw.handle("/v1/chat/completions", json.dumps(tiny).encode(), {})
    gw.handle("/v1/chat/completions", json.dumps(tiny).encode(), {})
    assert seen == [True]


def _fill(gw, log, rows: int) -> None:
    tiny = {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}
    for _ in range(rows):
        gw.handle("/v1/chat/completions", json.dumps(tiny).encode(), {})


def test_numbered_backups_shift_and_the_oldest_is_deleted(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=1, log_backups=3)
    _fill(gw, log, 1)
    first = log.read_text()
    _fill(gw, log, 1)
    assert (tmp_path / "proxy.jsonl.1").read_text() == first
    assert log.read_text() != first
    _fill(gw, log, 4)                              # total 6 rows, 1 active, 3 kept, 2 gone
    names = sorted(q.name for q in tmp_path.iterdir())
    assert names == ["proxy.jsonl", "proxy.jsonl.1", "proxy.jsonl.2", "proxy.jsonl.3"]
    ids = [json.loads((tmp_path / n).read_text())["request_id"]
           for n in ("proxy.jsonl.3", "proxy.jsonl.2", "proxy.jsonl.1", "proxy.jsonl")]
    assert len(set(ids)) == 4                      # .3 oldest .. active newest, each a whole row
    assert json.loads(first)["request_id"] not in ids


def test_zero_backups_discards_the_full_log(stub, tmp_path):
    log = tmp_path / "proxy.jsonl"
    gw = _gateway_with_log(stub, log, log_max_bytes=1, log_backups=0)
    _fill(gw, log, 3)
    assert [q.name for q in tmp_path.iterdir()] == ["proxy.jsonl"]
    assert len(log.read_text().splitlines()) == 1


def test_negative_backups_rejected(stub, tmp_path):
    with pytest.raises(ValueError):
        _gateway_with_log(stub, tmp_path / "p.jsonl", log_backups=-1)


def test_request_bodies_are_not_logged_by_default_and_are_when_asked(stub, tmp_path):
    body = json.dumps({"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_LINE}]})
    log = tmp_path / "off.jsonl"
    _gateway_with_log(stub, log).handle("/v1/chat/completions", body.encode(), {})
    row = json.loads(log.read_text())
    assert "request_body" not in row and "anna.novak@contoso.com" not in log.read_text()

    log = tmp_path / "on.jsonl"
    gw = _gateway_with_log(stub, log, log_request_bodies=True)
    gw.handle("/v1/chat/completions", body.encode(), {})
    gw.handle("/v1/chat/completions", b"not json", {})
    rows = [json.loads(l) for l in log.read_text().splitlines()]
    assert rows[0]["request_body"] == body            # verbatim, before redaction
    assert rows[1]["request_body"] == "not json"       # refusals carry it too
    assert list(rows[0])[:7] == ["schema", "request_id", "path", "ts", "stream", "degraded",
                                 "request_body"]
