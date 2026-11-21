"""Read a vocabulary build log and report its shape.

Human-only, standard library only, run as ``python -m hider.esbuildlog``
with an optional ``--log PATH`` (default ``out/es/vocabulary.log.jsonl``)
and an optional ``--json``. It reports counts, seconds and ranges - field
names appear only in the over-cap section, which is where the VOCAB line
already names them. It never reports a clean result by silence: a missing,
empty or unreadable log exits non-zero saying there is no report, a line
that is not valid JSON is counted and reported, and an event word the
reader does not know is counted under its own word like any other.
"""
from __future__ import annotations

import argparse
import calendar
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from statistics import median

#: the event words the bridge writes today. Anything else is still counted,
#: under its own word - never lumped into a clean-looking total.
KNOWN_EVENTS = frozenset({"start", "progress", "slice", "failed",
                          "over_cap", "untrusted"})

#: age buckets for "how old the end of a slice's range was when the row was
#: written", in days. A negative age (a range end after the row was written)
#: is a fault of its own and never lands in an age bucket.
AGE_BUCKETS = (("under2", 0.0, 2.0), ("2-5", 2.0, 5.0), ("5-10", 5.0, 10.0),
               ("10-20", 10.0, 20.0), ("over20", 20.0, float("inf")))

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _row_ts(row: dict) -> float | None:
    """The row's write time. The bridge writes ``ts`` with a local
    ``strftime``, so it is parsed as local time."""
    ts = row.get("ts")
    if not isinstance(ts, str) or not _TS_RE.match(ts):
        return None
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None


def _iso_utc(value: str) -> float | None:
    """A UTC ISO timestamp as the log's ``range`` carries."""
    if not isinstance(value, str) or not _TS_RE.match(value):
        return None
    try:
        return calendar.timegm(
            datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").timetuple())
    except ValueError:
        return None


def _stats(values: list[float]) -> dict:
    """min/median/max for a list of numbers."""
    if not values:
        return {"count": 0}
    return {"count": len(values), "min": min(values),
            "median": median(values), "max": max(values)}


def _bucket(age_days: float) -> str:
    if age_days < 0.0:
        return "negative"
    for name, low, high in AGE_BUCKETS:
        if low <= age_days < high:
            return name
    return "over20"


def analyze(rows: list[dict]) -> dict:
    """The report: counts and figures only, no values."""
    events: dict[str, int] = {}
    for row in rows:
        word = row.get("vocabulary") or row.get("event")
        events[str(word) if word else "no_event_word"] = \
            events.get(str(word) if word else "no_event_word", 0) + 1
    unknown = {k: v for k, v in events.items() if k not in KNOWN_EVENTS}

    slice_rows = [r for r in rows if r.get("vocabulary") == "slice"]
    slices = [r for r in slice_rows
              if isinstance(r.get("seconds"), (int, float))
              and isinstance(r.get("requests"), (int, float))]
    slices_without_numbers = len(slice_rows) - len(slices)
    with_range: dict[str, list[tuple[float, float]]] = {
        **{n: [] for n, _l, _h in AGE_BUCKETS}, "negative": []}
    no_range = 0
    unparseable_range = 0
    unparseable_time = 0
    for r in slices:
        rng = r.get("range")
        ts = _row_ts(r)
        if rng is None:
            no_range += 1
            continue
        end = _iso_utc(rng[1]) if isinstance(rng, (list, tuple)) and len(rng) == 2 else None
        if end is None:
            unparseable_range += 1
            continue
        if ts is None:
            # a good range but a row time that cannot be read: its own
            # count, not a bad range
            unparseable_time += 1
            continue
        with_range[_bucket((ts - end) / 86400)].append(
            (float(r["seconds"]), float(r["requests"])))

    failed: dict[str, int] = {}
    for r in rows:
        if r.get("vocabulary") == "failed":
            code = str(r.get("refused") or "no_code")
            failed[code] = failed.get(code, 0) + 1

    over_cap: dict[str, int] = {}
    for r in rows:
        if r.get("vocabulary") == "over_cap":
            field = str(r.get("field") or "no_field")
            over_cap[field] = over_cap.get(field, 0) + 1

    times = [t for t in (_row_ts(r) for r in rows) if t is not None]
    rows_no_time = sum(1 for r in rows if _row_ts(r) is None)
    first = min(times) if times else None
    last = max(times) if times else None
    span_days = (last - first) / 86400 if times and last > first else 0.0

    slice_times = [float(r["seconds"]) for r in slices]
    slice_requests = [float(r["requests"]) for r in slices]
    return {
        "rows_by_event": dict(sorted(events.items())),
        "unknown_event_words": dict(sorted(unknown.items())),
        "completed_slices": {
            "count": len(slices),
            "seconds": _stats(slice_times),
            "requests": _stats(slice_requests),
        },
        "slice_rows_without_range": no_range,
        "slice_rows_unparseable_range": unparseable_range,
        "slice_rows_unreadable_time": unparseable_time,
        "slice_rows_without_numbers": slices_without_numbers,
        "slices_by_range_age_days": {
            name: {
                "count": len(pairs),
                "seconds": _stats([s for s, _q in pairs]),
                "requests": _stats([q for _s, q in pairs]),
            } for name, pairs in with_range.items()
        },
        "failed_slices_by_code": dict(sorted(failed.items())),
        "over_cap_rows_by_field": dict(sorted(over_cap.items())),
        "first_row_time": (datetime.fromtimestamp(first).strftime("%Y-%m-%dT%H:%M:%S")
                           if times else None),
        "last_row_time": (datetime.fromtimestamp(last).strftime("%Y-%m-%dT%H:%M:%S")
                          if times else None),
        "span_days": round(span_days, 4),
        "rows_without_parseable_time": rows_no_time,
    }


def _print_text(report: dict) -> None:
    p = print
    p("rows by event word:")
    for word, n in report["rows_by_event"].items():
        star = " (unknown word)" if word in report["unknown_event_words"] else ""
        p(f"  {word}: {n}{star}")
    cs = report["completed_slices"]
    p(f"completed slices: {cs['count']}")
    p(f"  seconds: min {cs['seconds'].get('min')} median {cs['seconds'].get('median')} "
      f"max {cs['seconds'].get('max')}")
    p(f"  requests: min {cs['requests'].get('min')} median {cs['requests'].get('median')} "
      f"max {cs['requests'].get('max')}")
    p(f"slice rows without a range: {report['slice_rows_without_range']}"
      + (f" (range present but unreadable: {report['slice_rows_unparseable_range']})"
         if report["slice_rows_unparseable_range"] else ""))
    if report["slice_rows_unreadable_time"]:
        p(f"slice rows with a good range but an unreadable time: "
          f"{report['slice_rows_unreadable_time']}")
    if report["slice_rows_without_numbers"]:
        p(f"slice rows without numeric seconds or requests, counted nowhere else: "
          f"{report['slice_rows_without_numbers']}")
    p("completed slices by age of range end at write time (days):")
    ages = report["slices_by_range_age_days"]
    for name, _low, _high in AGE_BUCKETS:
        g = ages[name]
        s, q = g["seconds"], g["requests"]
        p(f"  {name}: {g['count']}"
          + (f"  seconds {s.get('min')}/{s.get('median')}/{s.get('max')}"
             f"  requests {q.get('min')}/{q.get('median')}/{q.get('max')}"
             if g["count"] else ""))
    neg = ages["negative"]
    if neg["count"]:
        s, q = neg["seconds"], neg["requests"]
        p(f"  negative: {neg['count']}"
          f"  seconds {s.get('min')}/{s.get('median')}/{s.get('max')}"
          f"  requests {q.get('min')}/{q.get('median')}/{q.get('max')}")
    p(f"failed slices by code:")
    for code, n in report["failed_slices_by_code"].items():
        p(f"  {code}: {n}")
    if not report["failed_slices_by_code"]:
        p("  none")
    p(f"over-cap rows by field:")
    for field, n in report["over_cap_rows_by_field"].items():
        p(f"  {field}: {n}")
    if not report["over_cap_rows_by_field"]:
        p("  none")
    p(f"first row {report['first_row_time']}  last row {report['last_row_time']}"
      f"  span {report['span_days']} days")
    if report["rows_without_parseable_time"]:
        p(f"rows without a parseable time: {report['rows_without_parseable_time']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m hider.esbuildlog",
        description="report the shape of a vocabulary build log")
    ap.add_argument("--log", default="out/es/vocabulary.log.jsonl",
                    help="the build log to read")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args(argv)
    path = Path(args.log)
    if not path.is_file():
        print(f"no report: log not found: {path}", file=sys.stderr)
        return 1
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        print(f"no report: log unreadable: {getattr(e, 'strerror', None) or 'not valid UTF-8'}",
              file=sys.stderr)
        return 1
    if not any(line.strip() for line in lines):
        print("no report: log is empty", file=sys.stderr)
        return 1
    rows: list[dict] = []
    invalid = 0
    not_objects = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            invalid += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            not_objects += 1
    if not rows:
        print(f"no report: {invalid} invalid line(s), none readable",
              file=sys.stderr)
        return 1
    report = analyze(rows)
    report["invalid_json_lines"] = invalid
    report["valid_lines_not_objects"] = not_objects
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
    else:
        _print_text(report)
        if invalid:
            print(f"invalid json lines: {invalid}")
        if not_objects:
            print(f"valid json lines that are not objects: {not_objects}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
