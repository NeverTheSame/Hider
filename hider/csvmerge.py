"""Merge a backup admin portal's "Download logs" CSV parts into one JSON document.

    python -m hider merge-csv FOLDER_OR_FILES... -o session.json [--policy ...]

The portal splits a session log into ``<policy>-<MM-DD-YYYY-HH-MM-SS>-partN.csv``
files with the columns Creation Time (UTC), Status, Message. Parts are ordered
by their number, the header row of each part is dropped, and the column names
become snake_case keys. Runs locally; nothing here reads the rows beyond parsing.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from pathlib import Path

_PART = re.compile(r"-part(\d+)\.csv$", re.I)
_STAMP = re.compile(r"-(\d{2})-(\d{2})-(\d{4})-(\d{2})-(\d{2})-(\d{2})(?:-part\d+)?\.csv$", re.I)


def _key(col: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", col.strip().lower()).strip("_") or "column"


def _part_no(name: str) -> int:
    m = _PART.search(name)
    return int(m.group(1)) if m else 0


def collect(paths: list[str]) -> list[tuple[str, str]]:
    """(file name, text) for every .csv under the given folders or files."""
    files: list[Path] = []
    for p in map(Path, paths):
        files += sorted(p.glob("*.csv")) if p.is_dir() else [p]
    return [(f.name, f.read_text(encoding="utf-8-sig")) for f in files]


def merge(files: list[tuple[str, str]], meta: dict | None = None) -> dict:
    if not files:
        raise ValueError("no CSV files given")
    files = sorted(files, key=lambda f: (_part_no(f[0]), f[0]))
    header: list[str] | None = None
    records: list[dict] = []
    for name, text in files:
        rows = csv.reader(io.StringIO(text.lstrip("﻿")))
        head = next(rows, None)
        if head is None:
            continue
        keys = [_key(c) for c in head]
        if header is None:
            header = keys
        elif keys != header:
            raise ValueError(f"{name}: columns differ from the first part")
        for row in rows:
            if row:
                records.append(dict(zip(keys, row, strict=False)))
    doc: dict = {k: v for k, v in (meta or {}).items() if v}
    m = _STAMP.search(files[0][0])
    if m and "session_start" not in doc:
        mo, d, y, hh, mi, ss = m.groups()
        doc["session_start"] = f"{y}-{mo}-{d} {hh}:{mi}:{ss}"
    doc["parts"] = len(files)
    doc["records"] = records
    return doc


def summary(doc: dict) -> str:
    """Counts only, never row content."""
    st = Counter(r.get("status", "") for r in doc["records"])
    return f"{len(doc['records'])} records from {doc['parts']} part(s); status: " + ", ".join(
        f"{k or '(blank)'} {v}" for k, v in st.most_common()
    )
