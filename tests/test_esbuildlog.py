"""Tests for hider.esbuildlog, against an invented log in a temp folder."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hider import esbuildlog

PY = sys.executable
REPO = Path(__file__).resolve().parents[1]


SCHEMA = "hider.es-bridge.v1"


def _row(word, **extra):
    row = {"schema": SCHEMA,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "cluster": "stub", "vocabulary": word}
    row.update(extra)
    return row


def _write_log(tmp_path, rows, raw_lines=()):
    path = Path(tmp_path) / "vocabulary.log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(r) for r in rows] + list(raw_lines)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _run(path, *extra):
    return subprocess.run(
        [PY, "-m", "hider.esbuildlog", "--log", str(path), *extra],
        capture_output=True, text=True, cwd=REPO, timeout=60)


def test_rows_are_counted_by_event_word(tmp_path):
    path = _write_log(tmp_path, [_row("start"), _row("progress"),
                                 _row("progress"), _row("slice", seconds=3.0,
                                                         requests=2)])
    p = _run(path)
    assert p.returncode == 0
    assert "progress: 2" in p.stdout
    assert "start: 1" in p.stdout
    assert "slice: 1" in p.stdout


def test_slice_seconds_and_requests_min_median_max(tmp_path):
    rows = [_row("slice", seconds=s, requests=q)
            for s, q in ((1.0, 2), (3.0, 4), (9.0, 6), (7.0, 8))]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "seconds: min 1.0 median 5.0 max 9.0" in p.stdout
    assert "requests: min 2.0 median 5.0 max 8.0" in p.stdout


def test_slices_grouped_by_age_of_range_end(tmp_path):
    now = time.time()
    def stamp(offset_s):
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - offset_s))
    rows = [
        # range ended one day ago
        _row("slice", seconds=10.0, requests=5,
             range=["2026-01-01T00:00:00Z", time.strftime(
                 "%Y-%m-%dT%H:%M:%S", time.gmtime(now - 1 * 86400))],
             ts=stamp(0)),
        # range ended six days ago
        _row("slice", seconds=20.0, requests=6,
             range=["2026-01-01T00:00:00Z", time.strftime(
                 "%Y-%m-%dT%H:%M:%S", time.gmtime(now - 6 * 86400))],
             ts=stamp(0)),
        # range ended twelve days ago
        _row("slice", seconds=30.0, requests=7,
             range=["2026-01-01T00:00:00Z", time.strftime(
                 "%Y-%m-%dT%H:%M:%S", time.gmtime(now - 12 * 86400))],
             ts=stamp(0)),
    ]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "under2: 1" in p.stdout
    assert "5-10: 1" in p.stdout
    assert "10-20: 1" in p.stdout
    assert "2-5: 0" in p.stdout
    assert "over20: 0" in p.stdout


def test_slice_rows_without_a_range_are_counted(tmp_path):
    rows = [_row("slice", seconds=1.0, requests=1, range=["2026-01-01T00:00:00Z",
                                                          "2026-01-02T00:00:00Z"]),
            _row("slice", seconds=2.0, requests=2),
            _row("slice", seconds=3.0, requests=3, range=["2026-01-01T00:00:00Z",
                                                          "2026-01-02T00:00:00Z"])]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "slice rows without a range: 1" in p.stdout
    assert "completed slices: 3" in p.stdout


def test_failed_slices_are_grouped_by_code(tmp_path):
    rows = [_row("failed", refused="budget", seconds=1, requests=1),
            _row("failed", refused="budget", seconds=2, requests=2),
            _row("failed", refused="upstream_error", seconds=3, requests=3)]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "budget: 2" in p.stdout
    assert "upstream_error: 1" in p.stdout


def test_older_day_and_returning_field_failures_are_reported_under_their_own_word(tmp_path):
    """The bridge charges a failed older-day extension and a failed
    returning field to themselves, under their own event words. They are
    known words, and they are in the failure table apart from ``failed``."""
    rows = [_row("failed", refused="vocabulary"),
            _row("extend_failed", refused="vocabulary", next_width_s=43200, attempts=1),
            _row("extend_failed", refused="vocabulary", next_width_s=21600, attempts=2),
            _row("returning_failed", refused="upstream_error"),
            _row("catch_up_jumped", why="slow"), _row("expired"), _row("returned")]
    p = _run(_write_log(tmp_path, rows), "--json")
    assert p.returncode == 0
    report = json.loads(p.stdout)
    assert report["unknown_event_words"] == {}
    assert report["failed_slices_by_code"] == {
        "vocabulary": 1, "extend_failed: vocabulary": 2,
        "returning_failed: upstream_error": 1}


def test_over_cap_rows_are_grouped_by_field(tmp_path):
    rows = [_row("over_cap", field="stub.ref", distinct=5500, max=5000),
            _row("over_cap", field="stub.ref", distinct=5600, max=5000),
            _row("over_cap", field="stub.other", distinct=9000, max=5000)]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "stub.ref: 2" in p.stdout
    assert "stub.other: 1" in p.stdout


def test_negative_age_is_its_own_group_and_hidden_when_empty(tmp_path):
    now = time.time()
    rows = [_row("slice", seconds=5.0, requests=5,
                 range=["2026-01-01T00:00:00Z",
                        time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now + 3600))],
                 ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))),
             _row("slice", seconds=6.0, requests=6,
                  range=["2026-01-01T00:00:00Z",
                         time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - 86400))],
                  ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)))]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    # the future-dated range lands in its own group, never in over20
    assert "negative: 1" in p.stdout
    assert "over20: 0" in p.stdout
    # and an empty negative group is not printed at all
    path2 = _write_log(tmp_path / "clean", [_row("slice", seconds=5.0, requests=5,
                                                  range=["2026-01-01T00:00:00Z",
                                                         "2026-01-02T00:00:00Z"])])
    p2 = _run(path2)
    assert p2.returncode == 0
    assert "negative" not in p2.stdout


def test_slice_rows_without_numbers_are_counted(tmp_path):
    rows = [_row("slice", seconds=1.0, requests=1),
            _row("slice", seconds="nine", requests=None),
            _row("slice", seconds=None, requests=3)]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    assert "completed slices: 1" in p.stdout
    assert "without numeric seconds or requests, counted nowhere else: 2" in p.stdout


def test_good_range_with_unreadable_time_is_an_unreadable_time(tmp_path):
    rows = [_row("slice", seconds=1.0, requests=1,
                 range=["2026-01-01T00:00:00Z", "not-a-date"],
                 ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
             _row("slice", seconds=2.0, requests=2,
                  range=["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
                  ts="not-a-time")]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    # the malformed range end stays an unreadable range
    assert "range present but unreadable: 1)" in p.stdout
    # the good range with a row time that cannot be read is an unreadable time
    assert "unreadable time: 1" in p.stdout
    assert "completed slices: 2" in p.stdout  # both still have numbers
    assert "negative: " not in p.stdout.split("by age")[1].split("failed")[0]


def test_existing_but_unreadable_log_is_a_non_zero_no_report(tmp_path):
    path = tmp_path / "broken.log.jsonl"
    path.write_bytes(b"\xff\xfe not utf-8 \xff")
    p = _run(path)
    assert p.returncode != 0
    assert "no report" in (p.stderr + p.stdout).lower()


def test_first_last_and_span_are_reported(tmp_path):
    # times are chosen around a fixed reference so the span holds across a
    # local clock change (DST): the log's ts is local, and the span is
    # computed on parsed local times, so build the rows from parsed times
    # back, not from fixed offsets.
    base = time.mktime(time.strptime("2026-01-10 12:00:00", "%Y-%m-%d %H:%M:%S"))
    rows = [_row("start", ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(base))),
            _row("progress",
                 ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(base + 86400))),
            _row("slice", seconds=1.0, requests=1,
                 ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(base + 2 * 86400)))]
    path = _write_log(tmp_path, rows)
    p = _run(path)
    assert p.returncode == 0
    line = [ln for ln in p.stdout.splitlines() if ln.startswith("first row")][0]
    assert "span 2.0 days" in line


def test_unknown_event_word_is_counted_under_its_own_word(tmp_path):
    path = _write_log(tmp_path, [_row("slice", seconds=1.0, requests=1),
                                 _row("mystery_event", x=1),
                                 _row("mystery_event", x=2)])
    p = _run(path)
    assert p.returncode == 0
    assert "mystery_event: 2 (unknown word)" in p.stdout


def test_missing_log_is_a_non_zero_no_report(tmp_path):
    p = _run(tmp_path / "not-there.jsonl")
    assert p.returncode != 0
    assert "no report" in (p.stderr + p.stdout).lower()


def test_empty_log_is_a_non_zero_no_report(tmp_path):
    path = _write_log(tmp_path, [])
    p = _run(path)
    assert p.returncode != 0
    assert "no report" in (p.stderr + p.stdout).lower()


def test_unreadable_lines_are_counted_and_reported(tmp_path):
    path = _write_log(tmp_path, [_row("slice", seconds=1.0, requests=1)],
                      raw_lines=("{not json", "also not json", "[1, 2]"))
    p = _run(path)
    assert p.returncode == 0
    assert "invalid json lines: 2" in p.stdout
    assert "not objects: 1" in p.stdout


def test_log_of_only_invalid_lines_is_a_non_zero_no_report(tmp_path):
    path = _write_log(tmp_path, [], raw_lines=("nope", "still nope"))
    p = _run(path)
    assert p.returncode != 0
    assert "no report" in (p.stderr + p.stdout).lower()


def test_json_flag_prints_the_same_facts(tmp_path):
    path = _write_log(tmp_path, [_row("slice", seconds=4.0, requests=3)])
    p = _run(path, "--json")
    assert p.returncode == 0
    data = json.loads(p.stdout)
    assert data["completed_slices"]["count"] == 1
    assert data["completed_slices"]["seconds"]["max"] == 4.0
    assert data["rows_by_event"].get("slice") == 1


def test_analyze_refuses_nothing_and_reports_the_whole_log():
    # the real module stays importable and its analyse is a pure function
    rows = [json.loads(json.dumps(_row("progress")))]
    report = esbuildlog.analyze(rows)
    assert report["rows_by_event"] == {"progress": 1}
