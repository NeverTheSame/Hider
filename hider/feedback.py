"""The feedback channel: what the redaction got wrong, from the people using it.

Every number in this project is measured on synthetic data. The one source
of truth about real bundles is the engineer looking at an obfuscated file
who notices a customer name still in it, or a build number that was turned
into a label. This module gives that observation somewhere to go other than
a chat message that nobody turns into a test case.

Two kinds of report:

* ``missed``   - this text should have been hidden and was not;
* ``wrong``    - this text was hidden and should not have been.

Entries are appended to ``out/feedback.jsonl`` (gitignored). A ``missed``
entry necessarily holds the real value that leaked, so the file is as
sensitive as a mapping file and stays on the machine. ``hider feedback``
lists what has been reported so the entries can be turned into recognizer
patterns, classifier training sentences or adversarial cases - each of which
then carries its own test.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "out"
DEFAULT_PATH = OUT / "feedback.jsonl"
KINDS = ("missed", "wrong")
MAX_TEXT = 2000


def record(kind: str, text: str, *, entity_type: str | None = None, run: str | None = None,
           note: str | None = None, source: str = "web", path: str | Path | None = None) -> dict:
    """Append one report. Raises ``ValueError`` on an unusable one."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    text = (text or "").strip()
    if not text:
        raise ValueError("text is empty")
    if len(text) > MAX_TEXT:
        raise ValueError(f"text longer than {MAX_TEXT} characters")
    row = {
        "schema": "hider.feedback.v1",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kind": kind,
        "text": text,
        "entity_type": (entity_type or "").strip().upper() or None,
        "run": (run or "").strip() or None,
        "note": (note or "").strip()[:MAX_TEXT] or None,
        "source": source,
    }
    p = Path(path) if path else DEFAULT_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def load(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else DEFAULT_PATH
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def summary(rows: list[dict]) -> dict:
    by_kind = {k: 0 for k in KINDS}
    by_type: dict[str, int] = {}
    for r in rows:
        by_kind[r.get("kind", "?")] = by_kind.get(r.get("kind", "?"), 0) + 1
        t = r.get("entity_type") or "(unspecified)"
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(rows), "by_kind": by_kind,
            "by_entity_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1]))}
