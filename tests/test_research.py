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
        MAPPING,
        terms=["nw*"],
    )
    assert "Northwind" not in masked and "nwHR" not in masked and "gretchen" not in masked
    assert "<Site_Name-12>" in masked and "<Org-01>" in masked and "<Person-03>" in masked
    assert "nwlegal2" not in masked and extra == {"<Term-01>": "nwlegal2"}
    assert n == 4
    assert research.prompt_leaks(masked, MAPPING, ["nw*"]) == 0


def test_mask_prompt_leaves_existing_labels_alone():
    masked, _, n = research.mask_prompt("see <Org-01> and Space-02", MAPPING, terms=["Space*"])
    assert masked.startswith("see <Org-01> and ")


def test_unmask_round_trip_and_bare_labels():
    text = (
        "`<Site_Name-12>` failed; owner Person-03 at "
        "https://tenant-01.sharepoint.example/spaces/Space-02/Lists/x. <Guid-99> unknown. "
        "<REDACTED:SECRET> stays."
    )
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
    files = [
        ("Pol-08-12-2026-07-18-01-part2.csv", head + '1/1/2026 0:02,Error,"b, c"\n'),
        ("Pol-08-12-2026-07-18-01-part1.csv", head + "1/1/2026 0:01,Success,a\n"),
    ]
    doc = csvmerge.merge(files, {"policy": "Pol", "region": None})
    assert doc["policy"] == "Pol" and "region" not in doc
    assert doc["session_start"] == "2026-08-12 07:18:01" and doc["parts"] == 2
    assert [r["message"] for r in doc["records"]] == ["a", "b, c"]
    assert set(doc["records"][0]) == {"creation_time_utc", "status", "message"}
    assert "Error 1" in csvmerge.summary(doc)


def test_csv_merge_refuses_mismatched_columns():
    with pytest.raises(ValueError):
        csvmerge.merge([("a-part1.csv", "A,B\n1,2\n"), ("a-part2.csv", "A,C\n1,2\n")])


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(research, "RUNS", tmp_path / "json")
    monkeypatch.setattr(research, "RESEARCH", tmp_path / "research")
    research.RUNS.mkdir()
    (research.RUNS / "r1.obfuscated.json").write_text(
        json.dumps({"records": [{"message": "<Site_Name-12> failed for <Org-01>"}]})
    )
    (research.RUNS / "r1.mapping.json").write_text(
        json.dumps({"note": "x", "terms": ["nw*"], "mapping": MAPPING})
    )
    return "r1"


def test_ask_sends_only_masked_data_in_a_locked_down_run(run, monkeypatch):
    seen = {}

    def fake_run(cmd, cwd, **kw):
        seen["cmd"], seen["files"] = cmd, sorted(p.name for p in cwd.iterdir())
        seen["data"] = (cwd / research.DATA_NAME).read_text()
        reply = {
            "result": "`<Site_Name-12>` failed 1 time for `<Org-01>`.",
            "is_error": False,
            "total_cost_usd": 0.01,
            "permission_denials": [],
        }
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


def test_words_only_seen_inside_real_values_are_masked():
    public = "https://tenant-01.sharepoint.example/spaces/Space-02 failed"
    only_url = {k: v for k, v in MAPPING.items() if k.startswith("https://")}
    masked, extra, n = research.mask_prompt(
        "Did northwind sharepoint sites fail?", only_url, public=public
    )
    assert "northwind" not in masked.lower() and "sharepoint" in masked
    assert list(extra.values()) == ["northwind"]


def test_url_label_does_not_swallow_trailing_punctuation():
    from hider import jsonscrub

    res = jsonscrub.scrub(
        {"message": "Failed site https://acme.sharepoint.com/sites/HR-Pay: 429 Too Many Requests"},
        tier2="none",
    )
    assert ": 429 Too Many Requests" in res.output["message"]
    assert all(not v.endswith(":") for v in res.mapping.values())
