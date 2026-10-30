"""Prompt masking, unmasking, CSV merge and the Claude Code bridge. Synthetic values only."""

import json
import subprocess

import pytest

from hider import csvmerge, research

MAPPING = {
    "<Org-01>": "Northwind",
    "<Person-03>": "Gretchen Halvorsen",
    "<Site_Name-12>": "nwHR-Payroll",
    "https://tenant-01.sharepoint.example/spaces/Space-02": "https://northwind.sharepoint.com/sites/nwHR-Payroll",
}


def test_mask_prompt_replaces_known_values_and_terms():
    masked, extra, n = research.mask_prompt(
        "Why did nwHR-Payroll fail for Northwind? Ask gretchen halvorsen. Also nwlegal2.",
        MAPPING, terms=["nw*"])
    assert "Northwind" not in masked and "nwHR" not in masked and "gretchen" not in masked
    assert "<Site_Name-12>" in masked and "<Org-01>" in masked and "<Person-03>" in masked
    assert "nwlegal2" not in masked and extra == {"<Term-01>": "nwlegal2"}
    assert n == 4
    assert research.prompt_leaks(masked, MAPPING, ["nw*"]) == 0


def test_mask_prompt_leaves_existing_labels_alone():
    masked, _, n = research.mask_prompt("see <Org-01> and Space-02", MAPPING, terms=["Space*"])
    assert masked.startswith("see <Org-01> and ")


def test_unmask_round_trip_and_bare_labels():
    text = ("`<Site_Name-12>` failed; owner Person-03 at "
            "https://tenant-01.sharepoint.example/spaces/Space-02/Lists/x. <Guid-99> unknown. "
            "<REDACTED:SECRET> stays.")
    out, n, unknown = research.unmask(text, MAPPING)
    assert "`nwHR-Payroll` failed; owner Gretchen Halvorsen at " in out
    assert "https://northwind.sharepoint.com/sites/nwHR-Payroll/Lists/x" in out
    assert n == 3 and unknown == ["<Guid-99>"]
    assert "<REDACTED:SECRET> stays." in out


def test_unmask_bare_label_only_when_bracketed_form_is_mapped():
    out, n, _ = research.unmask("Release-2024 and Person-03", MAPPING)
    assert out == "Release-2024 and Gretchen Halvorsen" and n == 1


def test_csv_merge_orders_parts_and_drops_repeated_headers():
    head = "Creation Time (UTC),Status,Message\n"
    files = [("Pol-08-12-2026-07-18-01-part2.csv", head + '1/1/2026 0:02,Error,"b, c"\n'),
             ("Pol-08-12-2026-07-18-01-part1.csv", head + "1/1/2026 0:01,Success,a\n")]
    doc = csvmerge.merge(files, {"policy": "Pol", "region": None})
    assert doc["policy"] == "Pol" and "region" not in doc
    assert doc["session_start"] == "2026-08-12 07:18:01" and doc["parts"] == 2
    assert [r["message"] for r in doc["records"]] == ["a", "b, c"]
    assert set(doc["records"][0]) == {"creation_time_utc", "status", "message"}
    assert "Error 1" in csvmerge.summary(doc)


def test_csv_merge_refuses_mismatched_columns():
    with pytest.raises(ValueError):
        csvmerge.merge([("a-part1.csv", "A,B\n1,2\n"), ("a-part2.csv", "A,C\n1,2\n")])


CLEAN_STATS = {"mapped_values": 4, "secrets_destroyed": 0, "degraded_lines": 0, "leaks": []}


def _write_run(stem: str, stats: dict | None = CLEAN_STATS) -> str:
    """A run on disk: output, mapping, and (unless ``stats`` is None) the scrub
    record the bridge checks, as ``webserver.obfuscate_text`` would write it."""
    out = research.RUNS / f"{stem}.obfuscated.json"
    text = json.dumps({"records": [{"message": "<Site_Name-12> failed for <Org-01>"}]})
    out.write_text(text)
    (research.RUNS / f"{stem}.mapping.json").write_text(json.dumps(
        {"note": "x", "terms": ["nw*"], "mapping": MAPPING}))
    if stats is not None:
        research.write_scrub_record(out, text, stats)
    return stem


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(research, "RUNS", tmp_path / "json")
    monkeypatch.setattr(research, "RESEARCH", tmp_path / "research")
    research.RUNS.mkdir()
    return _write_run("r1")


def test_ask_sends_only_masked_data_in_a_locked_down_run(run, monkeypatch):
    seen = {}

    def fake_run(cmd, cwd, **kw):
        seen["cmd"], seen["files"] = cmd, sorted(p.name for p in cwd.iterdir())
        seen["data"] = (cwd / research.DATA_NAME).read_text()
        reply = {"result": "`<Site_Name-12>` failed 1 time for `<Org-01>`.", "is_error": False,
                 "total_cost_usd": 0.01, "permission_denials": []}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(reply), "")

    monkeypatch.setattr(research.subprocess, "run", fake_run)
    r = research.ask(run, "Why did <Site_Name-12> fail?")
    cmd = seen["cmd"]
    for flag in ("--restricted", "--strict-mcp-config", "--no-session-persistence"):
        assert flag in cmd
    assert cmd[cmd.index("--tools") + 1] == "Read,Grep,Glob"
    assert seen["files"] == ["CLAUDE.md", "data.json"]
    assert "Northwind" not in seen["data"] and "Northwind" not in " ".join(cmd)
    assert r["answer"] == "`nwHR-Payroll` failed 1 time for `Northwind`."
    assert r["replaced"] == 2
    assert (research.RESEARCH / r["saved"].split("/")[-1] / "answer.md").exists()


def test_ask_refuses_a_prompt_with_customer_values(run, monkeypatch):
    monkeypatch.setattr(research.subprocess, "run", lambda *a, **k: pytest.fail("sent"))
    with pytest.raises(ValueError):
        research.ask(run, "Why did Northwind fail?")
    with pytest.raises(ValueError):
        research.ask(run, "what about nwfinance?")  # caught by the saved prefix term


# ---------------------------------------------------------------------------
# Fail closed: a run the scrubber flagged, or one it cannot vouch for, never
# reaches Claude Code. One test per refusal branch; each also proves that no
# subprocess was started and no workspace holding the data was created.
# ---------------------------------------------------------------------------

@pytest.fixture
def never_runs(monkeypatch):
    monkeypatch.setattr(research.subprocess, "run",
                        lambda *a, **k: pytest.fail("Claude Code was invoked on a refused run"))
    monkeypatch.setattr(research.shutil, "copyfile",
                        lambda *a, **k: pytest.fail("the obfuscated file was copied into a workspace"))


def _refused(stem: str) -> str:
    with pytest.raises(research.RunRefused) as e:
        research.ask(stem, "Why did <Site_Name-12> fail?")
    with pytest.raises(research.RunRefused):
        research.make_workspace(stem)
    return str(e.value)


def test_refuses_a_run_the_leak_check_flagged(run, never_runs):
    _write_run("leaky", {**CLEAN_STATS, "leaks": ["<Person-03>", "<Org-01>"]})
    why = _refused("leaky")
    assert "leak check flagged 2" in why and "<Person-03>" in why
    assert "Gretchen" not in why  # labels, never values


def test_refuses_a_run_with_degraded_lines(run, never_runs):
    _write_run("degraded", {**CLEAN_STATS, "degraded_lines": 3})
    assert "3 line(s) degraded" in _refused("degraded")


def test_refuses_a_run_with_no_scrub_record(run, never_runs):
    """A pair written by an older version, or by hand, has nothing to show it
    was checked. Not knowing is a refusal, not a pass."""
    _write_run("norecord", None)
    assert "no scrub record" in _refused("norecord")


def test_refuses_an_unreadable_or_unknown_record(run, never_runs):
    _write_run("garbled")
    research.scrub_record_path(research.RUNS / "garbled.obfuscated.json").write_text("{not json")
    assert "unreadable" in _refused("garbled")
    _write_run("otherschema")
    p = research.scrub_record_path(research.RUNS / "otherschema.obfuscated.json")
    rec = json.loads(p.read_text())
    p.write_text(json.dumps({**rec, "schema": "somebody-elses.v9"}))
    assert "unknown schema" in _refused("otherschema")


@pytest.mark.parametrize("damage", [
    {"leaks": None}, {"leaks": "none"}, {"leaks": [1]}, {"degraded_lines": "0"},
    {"degraded_lines": True}, {"degraded_lines": -1}, {"output_sha256": None},
], ids=lambda d: next(iter(d)) + "=" + repr(next(iter(d.values()))))
def test_refuses_a_malformed_record_rather_than_reading_it_as_clean(run, never_runs, damage):
    """Every field the verdict depends on is type-checked. ``leaks: None`` or
    ``degraded_lines: "0"`` must not be read as nothing-to-report."""
    _write_run("malformed")
    p = research.scrub_record_path(research.RUNS / "malformed.obfuscated.json")
    p.write_text(json.dumps({**json.loads(p.read_text()), **damage}))
    assert "malformed" in _refused("malformed")


def test_refuses_an_output_edited_after_the_leak_check(run, never_runs):
    """The record vouches for specific bytes. A file replaced or edited since
    carries a verdict about some other file."""
    _write_run("edited")
    out = research.RUNS / "edited.obfuscated.json"
    out.write_text(out.read_text().replace("<Org-01>", "Northwind"))
    assert "does not match its scrub record" in _refused("edited")


def test_clean_record_is_returned_and_list_runs_marks_flagged_ones(run):
    rec = research.scrub_verdict("r1")
    assert rec["leaks"] == [] and rec["degraded_lines"] == 0
    _write_run("leaky", {**CLEAN_STATS, "leaks": ["<Org-01>"]})
    _write_run("norecord", None)
    by = {r["run"]: r for r in research.list_runs()}
    assert by["r1"]["clean"] is True and by["r1"]["refusal"] == ""
    assert by["leaky"]["clean"] is False and "leak check" in by["leaky"]["refusal"]
    assert by["norecord"]["clean"] is False and "no scrub record" in by["norecord"]["refusal"]


def test_obfuscate_text_writes_the_record_the_bridge_checks(tmp_path, monkeypatch):
    """End to end through the real scrubber: the obfuscation both the web UI
    and ``scrub-json`` use writes the verdict record, it holds labels and
    counts only, and the bridge accepts the clean run it describes. The
    flagged cases above build their records from the same ``stats`` shape
    ``jsonscrub`` produces."""
    from hider import webserver
    monkeypatch.setattr(webserver, "OUT", tmp_path / "json")
    monkeypatch.setattr(research, "RUNS", tmp_path / "json")
    result = webserver.obfuscate_text(json.dumps(
        {"records": [{"user": "anna.novak@contosocorp.com", "message": "ok"}]}),
        "export.json", tier2="none")
    assert result["stats"]["leaks"] == [] and result["stats"]["degraded_lines"] == 0
    rec_path = tmp_path / "json" / f"{result['run']}.scrub.json"
    assert rec_path.exists() and result["saved"]["scrub"] == str(rec_path)
    rec = json.loads(rec_path.read_text())
    assert rec["schema"] == research.SCRUB_SCHEMA
    assert "anna.novak" not in rec_path.read_text()  # decisions, not data
    assert research.scrub_verdict(result["run"])["output_sha256"] == rec["output_sha256"]


def test_web_api_ask_refuses_a_flagged_run_before_starting_a_job(tmp_path, monkeypatch):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from hider import webserver

    monkeypatch.setattr(research, "RUNS", tmp_path / "json")
    research.RUNS.mkdir()
    _write_run("leaky", {**CLEAN_STATS, "leaks": ["<Org-01>"]})
    _write_run("norecord", None)
    monkeypatch.setattr(research.subprocess, "run",
                        lambda *a, **k: pytest.fail("Claude Code was invoked on a refused run"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webserver.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        for stem, expect in (("leaky", "leak check"), ("norecord", "no scrub record")):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/ask",
                data=json.dumps({"run": stem, "text": "Why did <Site_Name-12> fail?"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(req, timeout=10)
            assert e.value.code == 400
            assert expect in json.loads(e.value.read())["error"]
        assert webserver._JOBS == {}
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/runs", method="GET")
        with urllib.request.urlopen(req, timeout=10) as r:
            runs = {x["run"]: x for x in json.loads(r.read())["runs"]}
        assert runs["leaky"]["clean"] is False and runs["norecord"]["clean"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_words_only_seen_inside_real_values_are_masked():
    public = "https://tenant-01.sharepoint.example/spaces/Space-02 failed"
    only_url = {k: v for k, v in MAPPING.items() if k.startswith("https://")}
    masked, extra, n = research.mask_prompt(
        "Did northwind sharepoint sites fail?", only_url, public=public)
    assert "northwind" not in masked.lower() and "sharepoint" in masked
    assert list(extra.values()) == ["northwind"]


def test_url_label_does_not_swallow_trailing_punctuation():
    from hider import jsonscrub
    res = jsonscrub.scrub({"message": "Failed site https://acme.sharepoint.com/sites/HR-Pay: 429 Too Many Requests"},
                          tier2="none")
    assert ": 429 Too Many Requests" in res.output["message"]
    assert all(not v.endswith(":") for v in res.mapping.values())
