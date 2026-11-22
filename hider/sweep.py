"""The known-value sweep, shared by the gateway and ``hider redact``.

The tiers read one unit at a time and a cue (a word before a case number, a
key before a value) is only there on some of the places a value stands. The
vault is not probabilistic: a value it holds is replaced with its existing
label wherever it appears. The gateway sweeps a request payload with this;
``redact`` sweeps a whole file with it. There is one implementation so the
two paths cannot drift.

Secrets are destroyed, never vaulted, so this sweep is identifiers only.
"""

from __future__ import annotations

import re
from collections.abc import Collection

from . import pseudonym


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


def known_values_in(vault: pseudonym.EntityVault, text: str,
                    labels: Collection[str] | None = None) -> list[str]:
    rx = known_values_rx(vault, labels)
    return [m.group(0) for m in rx.finditer(text)] if rx else []


def sweep(vault: pseudonym.EntityVault, text: str, *, unit: str = "", line: int = 0,
          labels: Collection[str] | None = None) -> tuple[str, list[dict]]:
    """Replace any identifier the vault already knows with its pseudonym.

    A value pseudonymised somewhere and missed here gets the same label it had
    before, so correlation survives and the value never crosses. Every
    replacement is a decision event with ``tier: "sweep"``; offsets are into
    ``text`` as it stood when the sweep read it. ``labels`` limits the sweep
    to the entries carrying one of those labels.
    """
    rx = known_values_rx(vault, labels)
    if rx is None:
        return text, []
    by_value = {e["value"].casefold(): (e["label"], e["type"])
                for e in _entries(vault, labels)
                if not e["type"].startswith("_")}
    events: list[dict] = []

    def repl(m: re.Match) -> str:
        hit = by_value.get(m.group(0).casefold())
        if hit is None:
            return m.group(0)
        label, etype = hit
        events.append({
            "schema": "hider.redaction.v1", "unit": unit, "line": line,
            "start": m.start(), "end": m.end(), "entity_type": etype,
            "action": "pseudonymised", "tier": "sweep", "score": 1.0,
            "marker": label, "replacement": label,
        })
        return label

    return rx.sub(repl, text), events
