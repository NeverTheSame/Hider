"""Local, uncommitted settings for this machine: ``hider.local.json``.

Things that would name an employer or its estate if committed: the admin
portal the "Get the logs" prompt opens, and the vendor's own hosts that the
JSON scrubber may leave readable. Looked up at ``HIDER_LOCAL`` or
``hider.local.json`` in the repo root. Without it the page asks for the portal
URL and those hosts are masked like any other, which only over-redacts.

    {"portal_url": "https://portal.example.com/{region}/backup/jobs",
     "vendor_suffixes": ["example.com"], "vendor_hosts": ["helpcenter"]}

A malformed file is a startup error, never a silent skip.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

ENV = "HIDER_LOCAL"
DEFAULT = Path(__file__).resolve().parent.parent / "hider.local.json"
_KEYS = {"portal_url": str, "vendor_suffixes": list, "vendor_hosts": list}


@lru_cache(maxsize=1)
def settings() -> dict:
    path = Path(os.environ.get(ENV) or DEFAULT).expanduser()
    if not path.is_file():
        if os.environ.get(ENV):
            raise RuntimeError(f"{ENV} points at {path}, which is not a readable file")
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path}: top level must be an object")
    for key, typ in _KEYS.items():
        if key in raw and not isinstance(raw[key], typ):
            raise RuntimeError(f"{path}: {key} must be a {typ.__name__}")
    for key in ("vendor_suffixes", "vendor_hosts"):
        if not all(isinstance(v, str) and v for v in raw.get(key, [])):
            raise RuntimeError(f"{path}: {key} must list non-empty strings")
    return raw
