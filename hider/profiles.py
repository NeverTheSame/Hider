"""Site profiles: deployment-specific naming schemes, kept out of the repo.

Tier 1 ships with generic shapes, because the identifier formats a particular
operator uses are themselves information about that operator's estate: region
codes, service tiers, how many worker classes exist. Publishing them alongside
the tool would leak the topology the tool exists to hide.

So the real schemes live in a profile file that is loaded at runtime and never
committed. ``templates/profile.example.json`` shows the shape with invented
values; a deployment copies it, fills in its own patterns, and points
``HIDER_PROFILE`` at it.

Two rules make this safe rather than merely convenient:

* **A profile can only add patterns.** It cannot remove, weaken or override a
  built-in recognizer, so a badly written profile cannot reduce coverage below
  what the repository's own tests measure.
* **A broken profile is a hard error at startup, never a silent skip.** A
  missing file, malformed JSON, an unknown entity label or an uncompilable
  regex raises. The failure mode of a config-driven security control must be
  "refuses to start", not "starts with less protection than you think".
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import entities

ENV_PROFILE = "HIDER_PROFILE"

#: Detector labels a profile is allowed to add patterns for. Restricted to the
#: labels the rest of the engine already understands, so a typo produces an
#: error rather than a pattern that quietly matches nothing.
ALLOWED_LABELS: frozenset[str] = frozenset(
    {s.name for s in entities.SPECS} | {label for s in entities.SPECS for label in s.detected_as}
)

DEFAULT_SCORE = 0.9


class ProfileError(RuntimeError):
    """A profile could not be loaded. Never downgraded to a warning."""


@dataclass(frozen=True)
class SiteProfile:
    name: str
    #: detector label -> tuple of (regex source, score)
    patterns: dict[str, tuple[tuple[str, float], ...]]
    source: str = ""

    @property
    def pattern_count(self) -> int:
        return sum(len(v) for v in self.patterns.values())


def parse(raw: dict, *, source: str = "") -> SiteProfile:
    if not isinstance(raw, dict):
        raise ProfileError(f"{source or 'profile'}: top level must be an object")
    name = raw.get("name") or "unnamed"
    entries = raw.get("patterns")
    if not isinstance(entries, dict) or not entries:
        raise ProfileError(f"{source or 'profile'}: 'patterns' must be a non-empty object")

    out: dict[str, tuple[tuple[str, float], ...]] = {}
    for label, items in entries.items():
        if label not in ALLOWED_LABELS:
            raise ProfileError(
                f"{source or 'profile'}: unknown entity label {label!r}. "
                f"Known labels: {', '.join(sorted(ALLOWED_LABELS))}"
            )
        if isinstance(items, str):
            items = [items]
        if not isinstance(items, list) or not items:
            raise ProfileError(f"{source or 'profile'}: {label} must be a non-empty list")
        built: list[tuple[str, float]] = []
        for item in items:
            if isinstance(item, str):
                regex, score = item, DEFAULT_SCORE
            elif isinstance(item, dict) and "regex" in item:
                regex = item["regex"]
                score = float(item.get("score", DEFAULT_SCORE))
            else:
                raise ProfileError(
                    f"{source or 'profile'}: {label} entries must be a regex string "
                    f"or an object with a 'regex' key, got {item!r}"
                )
            if not isinstance(regex, str) or not regex:
                raise ProfileError(f"{source or 'profile'}: {label} has an empty regex")
            try:
                re.compile(regex)
            except re.error as e:
                raise ProfileError(
                    f"{source or 'profile'}: {label} regex does not compile: {e}"
                ) from e
            if not 0.0 < score <= 1.0:
                raise ProfileError(
                    f"{source or 'profile'}: {label} score {score} is outside (0, 1]"
                )
            built.append((regex, score))
        out[label] = tuple(built)
    return SiteProfile(name=name, patterns=out, source=source)


def load(path: str | Path) -> SiteProfile:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ProfileError(f"{ENV_PROFILE} points at {p}, which is not a readable file")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ProfileError(f"{p}: not valid JSON: {e}") from e
    return parse(raw, source=str(p))


@lru_cache(maxsize=1)
def active() -> SiteProfile | None:
    """The profile named by ``HIDER_PROFILE``, or None.

    Cached, because it is consulted every time a registry is built. Call
    ``active.cache_clear()`` in tests that change the environment.
    """
    path = os.environ.get(ENV_PROFILE)
    if not path:
        return None
    return load(path)
