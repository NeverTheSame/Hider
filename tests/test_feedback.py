"""The feedback channel: records on disk, listed by the CLI, posted by the UI."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from hider import feedback, webserver


def test_record_and_load(tmp_path):
    p = tmp_path / "fb.jsonl"
    row = feedback.record("missed", "  Diego Ferreira ", entity_type="person_name",
                          run="run-1", note="in a comment field", path=p)
    assert row["kind"] == "missed" and row["text"] == "Diego Ferreira"
    assert row["entity_type"] == "PERSON_NAME"
    rows = feedback.load(p)
    assert rows == [row]
    s = feedback.summary(rows)
    assert s["total"] == 1 and s["by_kind"]["missed"] == 1
    assert s["by_entity_type"] == {"PERSON_NAME": 1}


@pytest.mark.parametrize("kind,text", [("bogus", "x"), ("missed", "   "), ("wrong", "x" * 3000)])
def test_unusable_reports_are_rejected(tmp_path, kind, text):
    with pytest.raises(ValueError):
        feedback.record(kind, text, path=tmp_path / "fb.jsonl")


def test_web_api_records_feedback(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback, "DEFAULT_PATH", tmp_path / "fb.jsonl")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webserver.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        body = json.dumps({"kind": "wrong", "text": "8.1.0.7", "entity_type": "IPV4",
                           "note": "a build number"}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/feedback", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
            assert json.loads(r.read())["kind"] == "wrong"
        bad = urllib.request.Request(f"http://127.0.0.1:{port}/api/feedback",
                                     data=json.dumps({"kind": "nope", "text": "x"}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(bad, timeout=10)
        assert e.value.code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()
    rows = feedback.load(tmp_path / "fb.jsonl")
    assert len(rows) == 1 and rows[0]["text"] == "8.1.0.7" and rows[0]["source"] == "web"
