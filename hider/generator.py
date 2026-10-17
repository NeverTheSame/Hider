"""Synthetic bundle generator.

Fills the placeholder templates in ``templates/`` with generated values and
records, for every value it plants, the exact type, value and location. That
record is the ground truth, so scoring is mechanical: nothing is hand-labelled,
and the labels cannot drift away from the text.

No customer data is involved at any point. The templates hold skeletons only,
and the values come from ``entities.py``. The realism lives in the structure -
field names, ordering, error phrasing, file layout - which is the part that
actually exercises a recognizer.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import markup
from .markup import Occurrence

DEFAULT_TEMPLATES = Path(__file__).resolve().parent.parent / "templates" / "support_bundle.json"

PLACEHOLDER_RE = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")

_LEVELS = ["info", "warn", "debug"]
_JOBNAMES = ["Daily-EXCH-AUS", "Weekly-SPO-EMEA", "Hourly-OD-AMER", "Monthly-TEAMS-APJ"]


def _fill_placeholders(text: str, rng: random.Random) -> str:
    """Replace the non-sensitive ``{NAME}`` placeholders.

    Done with an explicit regex rather than ``str.format`` because many
    templates are JSON lines whose own braces would otherwise be parsed as
    format fields.
    """

    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        if name == "TS":
            return (
                f"{rng.randint(1, 28):02d}.08.2026 {rng.randint(0, 23):02d}:"
                f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{rng.randint(0, 999):03d}"
            )
        if name == "TSZ":
            return (
                f"2026-08-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:"
                f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{rng.randint(0, 999):03d}Z"
            )
        if name == "PID":
            return f"{rng.randint(1, 255):02x}"
        if name == "LEVEL":
            return rng.choice(_LEVELS)
        if name == "MS":
            return str(rng.randint(3, 900000))
        if name == "N":
            return str(rng.randint(1, 64))
        if name == "ITEMS":
            return str(rng.randint(1, 480000))
        if name == "MB":
            return str(rng.randint(1, 20480))
        if name == "PCT":
            return str(rng.randint(1, 100))
        if name == "HTTP":
            return str(rng.choice([200, 201, 404, 429, 429, 500, 503]))
        if name == "JOBNAME":
            return rng.choice(_JOBNAMES)
        return m.group(0)

    return PLACEHOLDER_RE.sub(one, text)


@dataclass
class Unit:
    """One file in the bundle."""

    path: str
    lines: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        """The unit's lines joined with newlines."""
        return "\n".join(self.lines)


@dataclass
class Corpus:
    """A generated bundle: its units, the ground truth for every planted value, and the clean units."""

    units: list[Unit] = field(default_factory=list)
    truth: list[Occurrence] = field(default_factory=list)
    #: Units known to contain no sensitive values. False redactions here are
    #: unambiguous over-redaction, which is how precision is measured without
    #: arguing about edge cases.
    clean_units: set[str] = field(default_factory=set)

    @property
    def total_lines(self) -> int:
        """Number of lines across all units."""
        return sum(len(u.lines) for u in self.units)

    @property
    def total_chars(self) -> int:
        """Number of characters across all units."""
        return sum(len(u.text) for u in self.units)

    def unit(self, path: str) -> Unit:
        """The unit with the given path; raises KeyError if there is none."""
        for u in self.units:
            if u.path == path:
                return u
        raise KeyError(path)


def load_templates(path: str | Path = DEFAULT_TEMPLATES) -> dict:
    """Load the placeholder templates JSON (by default ``templates/support_bundle.json``)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def generate(
    *,
    lines: int = 4000,
    seed: int = 20260820,
    templates: dict | None = None,
    clean_lines: int | None = None,
) -> Corpus:
    """Build a bundle of roughly ``lines`` sensitive-bearing lines plus a clean file.

    ``clean_lines`` defaults to a quarter of ``lines``. Those go into their own
    unit, which carries no seeded entities at all.
    """
    tpl = templates or load_templates()
    rng = random.Random(seed)
    corpus = Corpus()

    files = tpl["files"]
    weights = [f.get("weight", 1) for f in files]
    by_path: dict[str, Unit] = {}
    # A weighted file gets its own resolved path once, so the same file name is
    # reused across the run instead of a new file per line.
    resolved = {id(f): _fill_placeholders(f["path"], rng) for f in files}

    for _ in range(lines):
        f = rng.choices(files, weights=weights, k=1)[0]
        path = resolved[id(f)]
        unit = by_path.get(path)
        if unit is None:
            unit = Unit(path)
            by_path[path] = unit
            corpus.units.append(unit)
        template = _fill_placeholders(rng.choice(f["lines"]), rng)
        line_no = len(unit.lines)
        text, found = markup.render(template, rng, unit=path, line_no=line_no)
        unit.lines.append(text)
        corpus.truth.extend(found)

    n_clean = lines // 4 if clean_lines is None else clean_lines
    if n_clean:
        clean = Unit("Logs/clean/no-sensitive-values.log")
        for _ in range(n_clean):
            clean.lines.append(_fill_placeholders(rng.choice(tpl["clean_lines"]), rng))
        corpus.units.append(clean)
        corpus.clean_units.add(clean.path)

    return corpus
