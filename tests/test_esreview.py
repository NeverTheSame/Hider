"""es-review: what a case did, read back from its decision log. Invented rows."""

from __future__ import annotations

import json
import os

import pytest

from hider import elastic, esreview

CFG = elastic.load(elastic.EXAMPLE)


def _row(**kw) -> dict:
    base = {"schema": "hider.es-decision.v1", "ts": "2026-11-11T10:00:00", "cluster": "emea",
            "tool": "es_search", "index": "logs-app-*", "size": 10, "filters": [], "aggs": [],
            "labels_used": [], "text_queries": [], "hits_total": 3, "hits_shown": 3,
            "seconds": 0.1, "phrases_used": 0, "phrase_budget": 150, "phrases_left": 150,
            "new_labels": 4, "new_keep_values": 2, "labels_usable": 4, "keep_values_usable": 2,
            "zero_hit_phrases": []}
    base.update(kw)
    return base


def _write(tmp_path, rows, *, session: bool = True):
    (tmp_path / "decisions.jsonl").write_text(
        "\n".join(json.dumps(r) if isinstance(r, dict) else r for r in rows) + "\n")
    if session:
        s = elastic.EsScrubber(CFG, tier2="none")
        s.seed("Harbour Ridge Holdings")
        s.save_session(tmp_path)
    return tmp_path


def test_a_missing_or_unreadable_log_is_no_review_not_a_clean_case(tmp_path):
    r = esreview.review(tmp_path)
    assert r["log_status"] == "missing" and r["verdict"] is None and r["signals"] == []
    text = "\n".join(esreview.format_review(r))
    assert "NO REVIEW" in text and "not a clean case" in text and "nothing flagged" not in text
    _write(tmp_path, ["{not json", "[1,2]"], session=False)
    r = esreview.review(tmp_path)
    assert r["log_status"] == "unreadable" and r["verdict"] is None and r["unreadable_rows"] == 2


def test_the_numbers_and_an_ordinary_case_is_not_flagged(tmp_path):
    rows = [
        _row(filters=[{"field": "labels.tenant_name", "op": "eq"}], labels_used=["<Org-01>"]),
        _row(tool="es_aggregate", size=0, hits_shown=0, hits_total=40,
             aggs=[{"name": "srv", "type": "terms", "field": "agent.name", "aggs": []}],
             new_labels=6, new_keep_values=0, labels_usable=10),
        _row(filters=[{"field": "message", "op": "phrase"}], text_queries=["throttled by"],
             phrases_used=1, phrases_left=149),
        _row(filters=[{"field": "message", "op": "phrase"}], text_queries=["HTTP 429 after"],
             hits_total=0, hits_shown=0, zero_hit_phrases=["HTTP 429 after"],
             phrases_used=2, phrases_left=148),
        _row(refused="unknown_label", label="<Org-02>", filters=[{"field": "labels.tenant_name",
                                                                   "op": "eq"}]),
        {"schema": "hider.es-decision.v1", "ts": "x", "cluster": "emea", "vocabulary": "applied"},
    ]
    r = esreview.review(_write(tmp_path, rows))
    n = r["numbers"]
    assert n["queries"] == 5 and n["refusals"] == {"unknown_label": 1}
    assert n["pages_shown"] == 3 and n["hits_total"] == 46
    assert n["text_phrases_distinct"] == 2 and n["text_phrases_zero_hit"] == 1
    assert n["phrases_used"] == 2 and n["phrase_budget"] == 150
    assert n["labels_usable"] == 1 and n["labels_issued"] >= 1 and n["session"] == "ok"
    assert r["verdict"] == "nothing flagged" and r["flagged"] == []
    assert all(s["flagged"] is False for s in r["signals"])


def test_the_guessing_case_from_the_example_is_flagged_with_evidence(tmp_path):
    rows = []
    # nine refused labels on consecutive numbers
    for i in range(9):
        rows.append(_row(refused="unknown_label", label=f"<Org-{i + 10:02d}>",
                         filters=[{"field": "labels.tenant_name", "op": "eq"}]))
    # capitalised one-word phrases, each finding nothing, most of the budget
    for i in range(140):
        word = f"Candidate{chr(65 + i % 26)}{i}".rstrip("0123456789") or "Candidate"
        rows.append(_row(filters=[{"field": "message", "op": "phrase"}], text_queries=[word],
                         hits_total=0, hits_shown=0, zero_hit_phrases=[word],
                         phrases_used=i + 1, phrases_left=149 - i))
    # one wide aggregation over an identifier field
    rows.append(_row(tool="es_aggregate", size=0, hits_shown=0, hits_total=900,
                     aggs=[{"name": "t", "type": "terms", "field": "labels.tenant_name",
                            "aggs": []}], new_labels=30, labels_usable=30))
    # three literals typed back
    for _ in range(3):
        rows.append(_row(refused="known_value", filters=[{"field": "data_stream.dataset",
                                                           "op": "eq"}]))
    r = esreview.review(_write(tmp_path, rows))
    assert r["verdict"] == "flagged"
    assert set(r["flagged"]) == {"label_guessing", "zero_hit_phrases", "phrase_budget_pressure",
                                 "wide_collection", "literal_probing"}
    by = {s["name"]: s["evidence"] for s in r["signals"]}
    assert by["label_guessing"]["longest_consecutive_run"] == 9
    assert by["label_guessing"]["labels_typed"][0] == "<Org-10>"
    assert by["zero_hit_phrases"]["zero_hit_name_shaped"] >= 5
    assert by["phrase_budget_pressure"]["share"] >= 0.9
    assert by["wide_collection"]["pages"][0]["aggs"] == ["labels.tenant_name"]
    assert by["literal_probing"]["fields"] == {"data_stream.dataset": 3}
    text = "\n".join(esreview.format_review(r))
    assert "FLAG" in text and "innocent:" in text and "VERDICT  flagged" in text


def test_values_are_printed_only_under_the_flag_and_the_review_writes_nothing(tmp_path):
    rows = [_row(refused="unknown_label", label="<Org-01>",
                 filters=[{"field": "labels.tenant_name", "op": "eq"}])]
    d = _write(tmp_path, rows)
    before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in d.iterdir()}
    plain = "\n".join(esreview.format_review(esreview.review(d)))
    assert "<Org-01>" in plain and "Harbour Ridge" not in plain
    shown = "\n".join(esreview.format_review(esreview.review(d, show_values=True)))
    assert "Harbour Ridge Holdings" in shown
    after = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in d.iterdir()}
    assert before == after


def test_an_old_log_is_reviewable_with_its_gaps_marked(tmp_path):
    old = {"schema": "hider.es-decision.v1", "ts": "t", "cluster": "emea", "index": "logs-app-*",
           "size": 0, "filters": [], "labels_used": [], "text_queries": ["Candidate"],
           "hits_total": 12, "hits_shown": 0, "seconds": 0.1,
           "aggs": [{"name": "g", "type": "filters", "field": None, "aggs": []}]}
    r = esreview.review(_write(tmp_path, [old, {**old, "aggs": [], "text_queries": ["x y"]}],
                               session=False))
    assert r["log_status"] == "ok" and r["verdict"] == "nothing flagged"
    n = r["numbers"]
    assert n["phrases_used"] == "not recorded" and n["labels_usable"] == "not recorded"
    assert n["session"] == "missing"
    by = {s["name"]: s for s in r["signals"]}
    assert by["phrase_budget_pressure"]["flagged"] is None
    assert by["wide_collection"]["flagged"] is None
    assert any("zero_hit_phrases" in note for note in r["not_recorded"])
    text = "\n".join(esreview.format_review(r))
    assert text.count("not recorded") >= 3


def test_the_cli_exit_codes(tmp_path, capsys):
    from hider import cli

    (tmp_path / "c1").mkdir()
    _write(tmp_path / "c1", [_row()])
    assert cli.main(["es-review", "--case", "c1", "--sessions-dir", str(tmp_path)]) == 0
    assert cli.main(["es-review", "--case", "nope", "--sessions-dir", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "NO REVIEW" in out
    assert cli.main(["es-review", "--case", "c1", "--sessions-dir", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out.split("\n", 0)[0])["verdict"] == "nothing flagged"
