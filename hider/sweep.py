"""The known-value sweep, shared by the gateway and ``hider redact``.

The tiers read one unit at a time and a cue (a word before a case number, a
key before a value) is only there on some of the places a value stands. The
vault is not probabilistic: a value it holds is replaced with its existing
label wherever it appears. The gateway sweeps a request payload with this;
``redact`` sweeps a whole file with it. There is one implementation so the
two paths cannot drift.

Secrets are destroyed, never vaulted, so this sweep is identifiers only.

A pseudonym already standing in the text is never matched into. A vaulted
value that is also the word inside a label (tier 2 takes "Person" for a
name) used to be replaced there too, and ``<Person-01>`` came out as
``<<Org-01>-01>``: one label destroyed and nothing hidden. The leftover
check skips the same places, so a label cannot be what refuses a request.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Collection, Iterator

from . import pseudonym

#: A pseudonym or a destroyed-secret marker as the tiers write them. Labels
#: the vault issued in another shape (a host, an address) are protected by
#: their own text, see :class:`Sweeper`.
_LABEL_RX = r"<[A-Za-z][A-Za-z_]*-\d+>|<REDACTED:[A-Za-z0-9_]+>"


def _entries(vault: pseudonym.EntityVault, labels: Collection[str] | None):
    for e in vault.entries.values():
        if labels is None or e["label"] in labels:
            yield e


def known_values_rx(vault: pseudonym.EntityVault,
                    labels: Collection[str] | None = None) -> re.Pattern | None:
    """One pattern for every value the vault holds, or None when it is empty.

    ``labels`` limits it to the entries carrying one of those labels.

    Every value, however short (a four-character floor used to let a short
    identifier the tiers missed cross to the provider, with the leftover check
    sharing the floor so nothing was refused). Two match modes, by what the
    value is:

    * Shaped values (GUIDs, IPs, hosts, URLs, case numbers, ...) match
      case-insensitively. They never collide with ordinary words, and loggers
      and users re-case them freely.
    * Person and org values match case-sensitively, against the casing the
      vault stored plus its Title/UPPER forms. These are the values that are
      also words: a vault that has learned the person "Bill" must not rewrite
      "please bill the extra hours". The accepted trade, chosen deliberately:
      a name the user lowercases ("call ann") is not swept.

    The gateway's leftover check uses this same pattern, so what the sweep
    skips it skips too: a lowercase name cannot 503, and anything this pattern
    matches is either replaced or refused. Costs in both directions are
    measured in ``test_sweep_wordlike_values_are_case_sensitive_and_measured``.
    """
    shaped: list[str] = []
    wordlike: set[str] = set()
    for e in _entries(vault, labels):
        v = e["value"]
        if not v:
            continue
        if e["type"] in ("PERSON_NAME", "ORG_NAME"):
            wordlike.update({v, v.title(), v.upper()})
        else:
            shaped.append(v)
    parts = []
    if shaped:
        parts.append("(?i:" + "|".join(
            map(re.escape, sorted(shaped, key=len, reverse=True))) + ")")
    if wordlike:
        parts.append("|".join(
            map(re.escape, sorted(wordlike, key=len, reverse=True))))
    if not parts:
        return None
    return re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(parts) + r")(?![A-Za-z0-9])")


class Sweeper:
    """A vault's known values, compiled once for many texts.

    The gateway builds one per call, because its vault grows between calls.
    ``redact`` builds one after its per-line pass and uses it for every line:
    the pattern is an alternation of every value, and compiling it per line
    cost 3 ms a line at 3,000 values, minutes on a large bundle.

    ``labels`` limits the values swept to the entries carrying one of those
    labels. What is protected is never limited: every label the vault issued,
    and anything shaped like a label or a destroyed-secret marker.
    """

    def __init__(self, vault: pseudonym.EntityVault,
                 labels: Collection[str] | None = None) -> None:
        self.rx = known_values_rx(vault, labels)
        self.by_value = {e["value"].casefold(): (e["label"], e["type"])
                         for e in _entries(vault, labels)
                         if not e["type"].startswith("_")}
        issued = sorted({e["label"] for e in vault.entries.values()
                         if e.get("label") and not str(e["label"]).isdigit()},
                        key=len, reverse=True)
        self.protected = re.compile("|".join([*map(re.escape, issued), _LABEL_RX]))

    def _free(self, text: str) -> Iterator[re.Match]:
        """Every match of a known value that touches no label in ``text``."""
        if self.rx is None:
            return
        spans = [m.span() for m in self.protected.finditer(text)]
        starts = [s for s, _e in spans]
        for m in self.rx.finditer(text):
            i = bisect.bisect_right(starts, m.start()) - 1
            if i >= 0 and spans[i][1] > m.start():
                continue  # starts inside a label
            if i + 1 < len(spans) and spans[i + 1][0] < m.end():
                continue  # runs into the next label
            yield m

    def known_values_in(self, text: str) -> list[str]:
        return [m.group(0) for m in self._free(text)]

    def sweep(self, text: str, *, unit: str = "", line: int = 0) -> tuple[str, list[dict]]:
        """Replace any identifier the vault already knows with its pseudonym.

        A value pseudonymised somewhere and missed here gets the same label it
        had before, so correlation survives and the value never crosses. Every
        replacement is a decision event with ``tier: "sweep"``; offsets are
        into ``text`` as it stood when the sweep read it.
        """
        out: list[str] = []
        events: list[dict] = []
        last = 0
        for m in self._free(text):
            hit = self.by_value.get(m.group(0).casefold())
            if hit is None:
                continue
            label, etype = hit
            out += [text[last:m.start()], label]
            last = m.end()
            events.append({
                "schema": "hider.redaction.v1", "unit": unit, "line": line,
                "start": m.start(), "end": m.end(), "entity_type": etype,
                "action": "pseudonymised", "tier": "sweep", "score": 1.0,
                "marker": label, "replacement": label,
            })
        if not events:
            return text, []
        out.append(text[last:])
        return "".join(out), events


class TermReplacer:
    """Names a person gave, hidden wherever they stand, compiled once per file.

    ``terms`` maps each term to the label the vault issued for it. A term
    matches in any casing, whatever its length, and only as a whole: no letter
    or digit directly before or after it, the boundary the sweep uses. When one
    term contains another the longer wins. Every replacement is a decision
    event shaped like the sweep's, with ``tier: "term"``; no event carries the
    term.
    """

    def __init__(self, terms: dict[str, str]) -> None:
        self.by_term = {t.casefold(): label for t, label in terms.items()}
        self.rx = None
        if self.by_term:
            self.rx = re.compile(
                r"(?<![A-Za-z0-9])(?:"
                + "|".join(map(re.escape, sorted(self.by_term, key=len, reverse=True)))
                + r")(?![A-Za-z0-9])", re.IGNORECASE)

    def replace(self, text: str, *, unit: str = "", line: int = 0) -> tuple[str, list[dict]]:
        if self.rx is None:
            return text, []
        out: list[str] = []
        events: list[dict] = []
        last = 0
        for m in self.rx.finditer(text):
            label = self.by_term[m.group(0).casefold()]
            out += [text[last:m.start()], label]
            last = m.end()
            events.append({
                "schema": "hider.redaction.v1", "unit": unit, "line": line,
                "start": m.start(), "end": m.end(), "entity_type": "ORG_NAME",
                "action": "pseudonymised", "tier": "term", "score": 1.0,
                "marker": label, "replacement": label,
            })
        if not events:
            return text, []
        out.append(text[last:])
        return "".join(out), events


def known_values_in(vault: pseudonym.EntityVault, text: str,
                    labels: Collection[str] | None = None) -> list[str]:
    """The known values still readable in ``text``, outside every label."""
    return Sweeper(vault, labels).known_values_in(text)


def sweep(vault: pseudonym.EntityVault, text: str, *, unit: str = "", line: int = 0,
          labels: Collection[str] | None = None) -> tuple[str, list[dict]]:
    """One text swept with a :class:`Sweeper` built for this call."""
    return Sweeper(vault, labels).sweep(text, unit=unit, line=line)
