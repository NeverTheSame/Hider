"""Marked-up text: the mechanism that gives us ground truth for free.

A corpus line is authored (or generated) with sensitive values wrapped in
markers::

    Session <<SESSION_GUID>> on pod <<POD_ID>> failed

Stripping the markers yields the clean line plus the exact character offsets of
every sensitive value in it. No hand-labelling, and the labels cannot drift out
of sync with the text, which is what makes mechanical scoring trustworthy.

Marker grammar::

    <<TYPE>>                 value generated from the spec
    <<TYPE|literal>>         explicit literal value
    <<TYPE|literal|group>>   explicit value belonging to a group

A group ties fragments of ONE logical value together, for adversarial cases such
as an identifier split across a line break. A grouped value counts as caught
only when every one of its fragments was redacted, because a half-redacted
identifier still leaks half an identifier.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass

from . import entities

MARKER_RE = re.compile(r"<<([A-Z0-9_]+)(?:\|([^|>]*))?(?:\|([^|>]*))?>>")


@dataclass(frozen=True)
class Occurrence:
    """One sensitive value at a known location in a known line."""

    entity_type: str
    value: str
    start: int
    end: int
    unit: str = ""        # file path or corpus-unit name
    line_no: int = 0
    group: str = ""       # non-empty when this is a fragment of a split value
    canary: bool = False  # unique sentinel, must never survive redaction

    @property
    def key(self) -> tuple:
        return (self.unit, self.line_no, self.start, self.end, self.entity_type)


def render(
    template: str,
    rng: random.Random,
    *,
    unit: str = "",
    line_no: int = 0,
    canary_types: frozenset[str] = frozenset(),
) -> tuple[str, list[Occurrence]]:
    """Strip markers from ``template``, returning the clean line and offsets."""
    out: list[str] = []
    found: list[Occurrence] = []
    cursor = 0
    pos = 0
    for m in MARKER_RE.finditer(template):
        out.append(template[cursor:m.start()])
        pos += m.start() - cursor
        etype, literal, group = m.group(1), m.group(2), m.group(3)
        spec = entities.spec(etype)
        value = literal if literal else spec.generate(rng)
        out.append(value)
        found.append(
            Occurrence(
                entity_type=etype, value=value, start=pos, end=pos + len(value),
                unit=unit, line_no=line_no, group=group or "",
                canary=etype in canary_types,
            )
        )
        pos += len(value)
        cursor = m.end()
    out.append(template[cursor:])
    return "".join(out), found
