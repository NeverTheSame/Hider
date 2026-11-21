"""Command-line behaviour that the security story depends on.

Regression: ``redact`` built its own tier list and ran tier 1 only, while
``proxy`` ran tier 2. The documented "redact the bundle before pasting it
anywhere" workflow was therefore the one path that let a customer's name
through. Both now build tiers through one function, and this file holds it
that way.
"""

from __future__ import annotations

import pytest

from hider import cli

NOTE = ("Rachel Mbeki at Contoso Group escalated case 08123456 for "
        "session 6cafd2ac-dd19-d991-291a-8d565940996d\n")


def run_redact(tmp_path, capsys, text=NOTE, extra=None):
    src = tmp_path / "note.log"
    src.write_text(text, encoding="utf-8")
    rc = cli.main(["redact", str(src)] + (extra or []))
    return rc, capsys.readouterr().out


def test_redact_runs_tier_two_by_default(tmp_path, capsys):
    rc, out = run_redact(tmp_path, capsys)
    assert rc == 0
    assert "Rachel Mbeki" not in out
    assert "Contoso Group" not in out


def test_redact_still_covers_the_shaped_types(tmp_path, capsys):
    _, out = run_redact(tmp_path, capsys)
    assert "6cafd2ac-dd19-d991-291a-8d565940996d" not in out
    assert "08123456" not in out


def test_redact_and_proxy_build_the_same_tiers():
    names = lambda ts: [t.name for t in ts]
    assert names(cli._build_tiers("classifier")) == ["tier1", "tier2"]
    assert names(cli._build_tiers("none")) == ["tier1"]


def test_turning_tier_two_off_is_possible_but_says_so(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    cli.main(["redact", str(src), "--tier2", "none"])
    captured = capsys.readouterr()
    assert "Rachel Mbeki" in captured.out
    assert "tier 2 disabled" in captured.err


def test_the_decision_log_records_no_original_values(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    log = tmp_path / "decisions.jsonl"
    cli.main(["redact", str(src), "--log", str(log)])
    body = log.read_text()
    assert body.strip()
    for secret in ("Rachel Mbeki", "Contoso Group", "6cafd2ac-dd19-d991-291a-8d565940996d"):
        assert secret not in body


def test_a_saved_vault_round_trips_the_answer(tmp_path, capsys):
    src = tmp_path / "note.log"
    src.write_text(NOTE, encoding="utf-8")
    vault_path = tmp_path / "vault.json"
    cli.main(["redact", str(src), "--vault", str(vault_path)])
    from hider import pseudonym
    v = pseudonym.EntityVault.load(vault_path)
    assert "Rachel Mbeki" in v.detokenize("<Person-01> asked for an update")


def test_a_bad_index_refusal_is_logged_and_printed_as_shapes(tmp_path, capsys):
    """A page whose hits come from indices outside the allowlist is refused
    bad_index as always. The decision-log row carries each refused name as
    a shape with its hit count, es-smoke prints one line a person can read,
    and the refusal itself - what a client receives - is code and message
    only. No letter of any invented name reaches the row or the line."""
    import json as _json

    from hider import elastic, esbridge

    cfg = elastic.parse({**_json.loads(elastic.EXAMPLE.read_text()),
                         "clusters": {"stub": "https://stub.example.net"}}, source="t")
    foreign = ["partial-.ds-tempestite-default-2026.08.20-000042",
               "partial-.ds-tempestite-default-2026.08.20-000042",
               ".fs-quokkastream-default-2026.08.19-000007"]
    hits = [{"_index": name, "_id": f"h{i}", "_score": None,
             "_source": {"message": "filler"}} for i, name in enumerate(foreign)]

    class _Session:
        def probe(self, cluster):
            return None

        def search(self, cluster, body, deadline_s=None):
            return {"id": "x", "isPartial": False, "isRunning": False,
                    "rawResponse": {"took": 1, "timed_out": False,
                                    "hits": {"total": {"value": 3, "relation": "eq"},
                                             "max_score": None, "hits": hits}}}

    log_path = tmp_path / "decisions.jsonl"
    b = esbridge.Bridge(cfg, elastic.EsScrubber(cfg, tier2="none"), _Session(),
                        log_path=log_path)
    q = {"index": cfg.indices[0], "time_range": {"gte": "now-6h", "lte": "now"}, "size": 3}
    report = esbridge.run_case(b, "stub", q)
    rc = esbridge.print_smoke("stub", q, report)
    out = capsys.readouterr().out
    assert rc == 2 and report["refused"]["code"] == "bad_index"
    assert report["refused"]["message"] == ("response withheld: a hit came from an index "
                                            "outside the allowlist")
    assert "INDICES  partial-.ds-L-L-9.9.9-9=2, .fs-L-L-9.9.9-9=1" in out
    row = _json.loads(log_path.read_text().splitlines()[-1])
    assert row["refused"] == "bad_index"
    assert row["index_shapes"] == [
        {"index_shape": "partial-.ds-L-L-9.9.9-9", "hits": 2},
        {"index_shape": ".fs-L-L-9.9.9-9", "hits": 1}]
    for word in ("tempestite", "quokkastream"):
        assert word not in out and word not in _json.dumps(row)


def test_es_smoke_waits_out_the_longest_group_read(monkeypatch, capsys):
    """Before: es-smoke waited poll_timeout + 120 - 420 s at the measured
    300 s site - and said the bridge did not answer while it was still
    mid-read (the first week read ran 835 s before the probe deadlines).
    After: the wait is sized to outlive the worst read by construction -
    the read budget plus one in-flight pass, plus the old margin."""
    from hider import elastic, esbridge, eseval

    cfg = elastic.load(elastic.EXAMPLE)
    # the before, pinned as arithmetic: the old wait lost to the read
    old_wait = eseval.MEASURED_SEARCH_LIMIT_S + 120
    assert old_wait == 420 < 835
    # the after: the wait covers the longest read a query can run
    worst_read = (elastic.TEXT_GROUP_READ_BUDGET_LIMITS + 1) * cfg.poll_timeout_s
    assert esbridge.search_wait_s(cfg) == worst_read + 120 > cfg.poll_timeout_s + 120

    captured: list[float] = []
    real = esbridge.BrokerClient

    class Capturing(real):
        def __init__(self, path, *, timeout):
            captured.append(timeout)
            super().__init__(path, timeout=timeout)

        def call(self, op, **fields):
            raise elastic.Refused("session_expired", "no bridge (test)")

    monkeypatch.setattr(esbridge, "BrokerClient", Capturing)
    rc = cli.main(["es-smoke", "--config", str(elastic.EXAMPLE), "--cluster", "emea"])
    out = capsys.readouterr().out
    assert rc != 0 and "session_expired" in out
    # the es-smoke client was built with the sized wait, not the old formula
    assert esbridge.search_wait_s(cfg) in captured
