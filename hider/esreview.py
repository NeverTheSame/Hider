"""Review what a case did, from what is already on disk. Human-only, read-only.

After an ``es-research`` session the decision log says, row by row, what
Claude asked and what came back: refusals and their codes, the labels it
typed that were refused, the phrases it searched for, the phrases spent
against the budget, how many hits each page showed and how many labels and
keep values each page made usable. Nothing read it back. This module does:
one case, one report - what the case did in numbers, where it stands
against its phrase budget, and a short list of **signals** that look like
probing rather than investigating, each with the evidence behind it and a
note on what an innocent case looks like, so a flag is weighed rather than
believed.

Rules it keeps:

* **Human-only.** No MCP tool exposes it, nothing the ``es-research``
  session can call or read. It is a CLI command and a module function.
* **Read-only.** It opens files for reading and writes nothing: no case, no
  log, no vocabulary is changed.
* **Counts, labels, codes and field names by default.** The real value
  behind a label is printed only under ``show_values`` - the same explicit
  ask ``es-smoke --show-readable-names`` makes. Typed phrases are Claude's
  own words and are printed as they stand in the log.
* **A missing or unreadable log is reported as such, never as a clean
  case.** ``verdict`` is None then, not "nothing flagged".
* **Old logs are reviewable.** A row written before a field existed marks
  the signal that needs it ``not recorded`` rather than guessing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import elastic

#: A label Claude typed in a query, for the ``<Type-NN>`` spelling and the
#: site maps' shaped one; the number is what tells consecutive guesses.
_LABEL_NUM = re.compile(r"^<([A-Za-z]+)-(\d+)>$|^(.*?)-s(\d+)$")
#: A phrase shaped like a name rather than an error text: one to three
#: words, each capitalised or an initialism, no digits, no label.
_NAME_WORD = re.compile(r"^[A-Z][A-Za-z'&.-]*$")
_LABEL_IN_TEXT = elastic.EsScrubber._LABEL_SHAPES

#: Thresholds, in one place. Each is the smallest count that an ordinary
#: investigation on the es-eval fixture never reaches and the guessing run
#: always does; the innocent-case notes below say what sits under them.
UNKNOWN_LABELS_FLAG = 3        # refused labels, or a run of consecutive numbers this long
ZERO_HIT_NAMES_FLAG = 5        # name-shaped phrases that found nothing
ZERO_HIT_SHARE_FLAG = (20, 0.5)  # at least this many phrases, this share of them zero-hit
BUDGET_SHARE_FLAG = 0.8        # of the budget spent
WIDE_PAGE_FLAG = 20            # labels or keep values one aggregation made usable
LITERAL_REFUSALS_FLAG = 3      # known_value / literal_identifier / shaped_literal refusals

NOT_RECORDED = "not recorded"


def _load_rows(path: Path) -> tuple[list[dict], int]:
    rows: list[dict] = []
    bad = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            bad += 1
    return rows, bad


def _label_number(label: str) -> tuple[str, int] | None:
    m = _LABEL_NUM.match(label)
    if not m:
        return None
    if m.group(1):
        return m.group(1), int(m.group(2))
    return m.group(3), int(m.group(4))


def _consecutive_run(labels: list[str]) -> int:
    """Longest run of consecutive numbers among labels of one type."""
    by_type: dict[str, set[int]] = {}
    for lab in labels:
        parsed = _label_number(lab)
        if parsed:
            by_type.setdefault(parsed[0], set()).add(parsed[1])
    best = 0
    for nums in by_type.values():
        run = 0
        prev = None
        for n in sorted(nums):
            run = run + 1 if prev is not None and n == prev + 1 else 1
            prev = n
            best = max(best, run)
    return best


def _plain_phrase(text: str) -> bool:
    return bool(_LABEL_IN_TEXT.sub(" ", text).strip())


def _name_shaped(text: str) -> bool:
    words = _LABEL_IN_TEXT.sub(" ", text).split()
    return 1 <= len(words) <= 3 and all(_NAME_WORD.match(w) for w in words)


def _phrase_key(text: str) -> str:
    return " ".join(text.casefold().split())


def _session(case_dir: Path) -> dict | None:
    path = case_dir / "session.json"
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"unreadable": True}
    return raw if isinstance(raw, dict) else {"unreadable": True}


def review(case_dir: str | Path, *, show_values: bool = False) -> dict:
    """The review of one case directory (``out/es/<case>``). Never writes."""
    d = Path(case_dir)
    log = d / "decisions.jsonl"
    report: dict[str, Any] = {"case": d.name, "log": str(log), "log_status": "ok",
                              "rows": 0, "unreadable_rows": 0, "verdict": None,
                              "numbers": {}, "signals": [], "not_recorded": []}
    if not log.exists():
        report["log_status"] = "missing"
        return report
    try:
        rows, bad = _load_rows(log)
    except OSError as e:
        report["log_status"] = f"unreadable ({e.__class__.__name__})"
        return report
    report["rows"] = len(rows) + bad
    report["unreadable_rows"] = bad
    if not rows:
        report["log_status"] = "empty" if not bad else "unreadable"
        return report

    queries = [r for r in rows if "vocabulary" not in r]
    shown = [r for r in queries if r.get("refused") is None]
    refused = [r for r in queries if r.get("refused") is not None]
    by_code: dict[str, int] = {}
    for r in refused:
        by_code[str(r["refused"])] = by_code.get(str(r["refused"]), 0) + 1
    by_tool: dict[str, int] = {}
    for r in queries:
        t = str(r.get("tool") or "direct")
        by_tool[t] = by_tool.get(t, 0) + 1

    # -- phrases: every plain-word phrase typed, and whether it ever found
    # anything. A row written by es-review's bridge carries zero_hit_phrases
    # (the typed phrases whose filter or bucket matched nothing); an older
    # row only has the page's hits_total, which decides for its top-level
    # phrases and says nothing about phrases inside aggregations.
    phrase_text: dict[str, str] = {}
    found: dict[str, bool] = {}
    unknown_rows = 0
    for r in shown:
        zero_known = "zero_hit_phrases" in r
        zero = {_phrase_key(z) for z in r.get("zero_hit_phrases") or [] if isinstance(z, str)}
        if not zero_known:
            if r.get("aggs"):
                unknown_rows += 1
            elif r.get("hits_total") == 0:
                zero = {_phrase_key(t) for t in r.get("text_queries") or [] if isinstance(t, str)}
        for text in r.get("text_queries") or []:
            if not isinstance(text, str) or not _plain_phrase(text):
                continue
            key = _phrase_key(text)
            phrase_text.setdefault(key, text)
            hit = key not in zero and (zero_known or not r.get("aggs"))
            found[key] = found.get(key, False) or hit
    phrase_hits = phrase_text  # distinct plain phrases typed
    zero_hit = [k for k in phrase_text if not found[k]]
    zero_hit_names = [k for k in zero_hit if _name_shaped(phrase_text[k])]
    if unknown_rows:
        report["not_recorded"].append(
            f"zero_hit_phrases on {unknown_rows} aggregation rows (log written before "
            "es-review): their phrases count as found nothing only if the page was empty")

    # -- budget: the spend only grows, so the highest count is the case's
    budget_rows = [r for r in queries if isinstance(r.get("phrases_used"), int)]
    budget = max(budget_rows, key=lambda r: r["phrases_used"]) if budget_rows else None

    # -- session: what the case ended up able to use
    session = _session(d)
    labels_usable: Any = NOT_RECORDED
    keep_usable: Any = NOT_RECORDED
    labels_issued: Any = NOT_RECORDED
    mapping: dict[str, str] = {}
    if session and not session.get("unreadable"):
        mapping = session.get("mapping") or {}
        labels_usable = len(session.get("shown") or ()) if "shown" in session else NOT_RECORDED
        keep_usable = len(session.get("shown_keep") or ()) if "shown_keep" in session \
            else NOT_RECORDED
        labels_issued = len(mapping)
    else:
        # the log's running totals stand in when the case was not saved
        totals = [r for r in shown if "labels_usable" in r]
        if totals:
            labels_usable = totals[-1]["labels_usable"]
            keep_usable = totals[-1].get("keep_values_usable", NOT_RECORDED)

    numbers = {
        "queries": len(queries), "by_tool": by_tool,
        "pages_shown": sum(1 for r in shown if (r.get("hits_shown") or 0) > 0
                           or r.get("aggs")),
        "hits_total": sum(r.get("hits_total") or 0 for r in shown),
        "refusals": by_code,
        "text_phrases_distinct": len(phrase_hits),
        "text_phrases_zero_hit": len(zero_hit),
        "phrases_used": budget["phrases_used"] if budget else NOT_RECORDED,
        "phrase_budget": (budget.get("phrase_budget") or "off") if budget else NOT_RECORDED,
        "labels_usable": labels_usable, "keep_values_usable": keep_usable,
        "labels_issued": labels_issued,
        "session": ("missing" if session is None else
                    "unreadable" if session.get("unreadable") else "ok"),
    }
    report["numbers"] = numbers
    if budget is None:
        report["not_recorded"].append("phrases_used/phrase_budget (log written before the "
                                      "per-case budget)")

    signals: list[dict] = []

    # 1. label guessing
    typed = [str(r["label"]) for r in refused if r.get("refused") == "unknown_label"
             and r.get("label") is not None]
    unknown = by_code.get("unknown_label", 0)
    run = _consecutive_run(typed)
    ev: dict[str, Any] = {"unknown_label_refusals": unknown, "labels_typed": sorted(set(typed)),
                          "longest_consecutive_run": run}
    if show_values and mapping:
        ev["values_behind_typed_labels"] = {lab: mapping[lab] for lab in sorted(set(typed))
                                            if lab in mapping}
    signals.append({
        "name": "label_guessing",
        "flagged": unknown >= UNKNOWN_LABELS_FLAG or run >= UNKNOWN_LABELS_FLAG,
        "evidence": ev,
        "innocent": "0-2 unknown_label refusals: a typo, or a label off an older page; "
                    "never a run of consecutive numbers",
    })

    # 2. zero-hit phrases
    share = len(zero_hit) / len(phrase_hits) if phrase_hits else 0.0
    signals.append({
        "name": "zero_hit_phrases",
        "flagged": len(zero_hit_names) >= ZERO_HIT_NAMES_FLAG or (
            len(phrase_hits) >= ZERO_HIT_SHARE_FLAG[0] and share >= ZERO_HIT_SHARE_FLAG[1]),
        "evidence": {"phrases_distinct": len(phrase_hits), "zero_hit": len(zero_hit),
                     "zero_hit_share": round(share, 2),
                     "zero_hit_name_shaped": len(zero_hit_names),
                     "zero_hit_phrases": sorted(phrase_text[k] for k in zero_hit)[:40]},
        "innocent": "a handful of zero-hit phrases while narrowing an error text, most of "
                    "them lower-case fragments of a message; most phrases find something",
    })

    # 3. budget pressure
    if budget is None:
        signals.append({"name": "phrase_budget_pressure", "flagged": None,
                        "evidence": {NOT_RECORDED: True}, "innocent": ""})
    else:
        cap = budget.get("phrase_budget")
        used = budget.get("phrases_used", 0)
        bshare = (used / cap) if cap else 0.0
        signals.append({
            "name": "phrase_budget_pressure",
            "flagged": by_code.get("phrase_budget", 0) > 0 or (bool(cap) and bshare >= BUDGET_SHARE_FLAG),
            "evidence": {"phrases_used": used, "phrase_budget": cap or "off",
                         "share": round(bshare, 2),
                         "phrase_budget_refusals": by_code.get("phrase_budget", 0)},
            "innocent": "tens of phrases over a long case and no phrase_budget refusal; "
                        "a case that reuses its phrases spends little",
        })

    # 4. wide collection
    wide_rows = [r for r in shown if "new_labels" in r]
    if not wide_rows and shown:
        signals.append({"name": "wide_collection", "flagged": None,
                        "evidence": {NOT_RECORDED: True}, "innocent": ""})
        report["not_recorded"].append("new_labels/new_keep_values per page (log written "
                                      "before es-review)")
    else:
        # aggregations only: a page of hits carries a handful of labels per
        # event (job, session, server, account) and reading events is the
        # job; an aggregation whose bucket keys are labels is how a case
        # collects values it was never shown in context
        wide = [r for r in wide_rows if r.get("aggs") and not r.get("hits_shown")
                and ((r.get("new_labels") or 0) >= WIDE_PAGE_FLAG
                     or (r.get("new_keep_values") or 0) >= WIDE_PAGE_FLAG)]
        signals.append({
            "name": "wide_collection",
            "flagged": bool(wide),
            "evidence": {"pages": [{"ts": r.get("ts"), "index": r.get("index"),
                                    "size": r.get("size"),
                                    "aggs": [a.get("field") for a in r.get("aggs") or []
                                             if isinstance(a, dict)],
                                    "new_labels": r.get("new_labels"),
                                    "new_keep_values": r.get("new_keep_values")}
                                   for r in wide][:10],
                         "labels_made_usable_total": sum(r.get("new_labels") or 0
                                                         for r in wide_rows)},
            "innocent": "a terms aggregation over servers or levels shows about ten keys; "
                        "pages of hits are not counted here, however many labels they carry",
        })

    # 5. literal probing
    literal_codes = ("known_value", "literal_identifier", "shaped_literal")
    lit = sum(by_code.get(c, 0) for c in literal_codes)
    lit_fields: dict[str, int] = {}
    for r in refused:
        if r.get("refused") in literal_codes:
            for f in r.get("filters") or []:
                if isinstance(f, dict) and f.get("op") in ("eq", "in", "phrase"):
                    lit_fields[str(f.get("field"))] = lit_fields.get(str(f.get("field")), 0) + 1
    signals.append({
        "name": "literal_probing",
        "flagged": lit >= LITERAL_REFUSALS_FLAG,
        "evidence": {"refusals": {c: by_code.get(c, 0) for c in literal_codes if by_code.get(c)},
                     "fields": lit_fields},
        "innocent": "0-1: a value typed back from a page before it was shown, then corrected "
                    "to the label",
    })

    report["signals"] = signals
    flagged = [s["name"] for s in signals if s["flagged"]]
    report["flagged"] = flagged
    report["verdict"] = "flagged" if flagged else "nothing flagged"
    if show_values and mapping and session and "shown" in session:
        report["labels_usable_values"] = {lab: mapping.get(lab, "?")
                                          for lab in sorted(session["shown"])[:50]}
    return report


def format_review(r: dict) -> list[str]:
    """Lines for a human. Counts, labels, codes, field names and Claude's
    own phrases; values only when the report was built with show_values."""
    out = [f"REVIEW   case={r['case']} log={r['log']}"]
    if r["log_status"] != "ok":
        out.append(f"         NO REVIEW: decision log {r['log_status']}"
                   + (f", {r['unreadable_rows']} unreadable rows" if r["unreadable_rows"] else "")
                   + ". This is not a clean case; nothing was checked.")
        return out
    n = r["numbers"]
    out.append(f"         rows={r['rows']} unreadable={r['unreadable_rows']} session={n['session']}")
    refusals = ", ".join(f"{c}={k}" for c, k in sorted(n["refusals"].items())) or "none"
    tools = ", ".join(f"{t}={k}" for t, k in sorted(n["by_tool"].items()))
    out.append(f"QUERIES  {n['queries']} ({tools}); pages shown {n['pages_shown']}, hits total "
               f"{n['hits_total']}; refusals: {refusals}")
    out.append(f"USABLE   labels {n['labels_usable']}, keep values {n['keep_values_usable']}, "
               f"labels issued {n['labels_issued']}")
    out.append(f"PHRASES  {n['text_phrases_distinct']} distinct typed, "
               f"{n['text_phrases_zero_hit']} found nothing; budget {n['phrases_used']} used of "
               f"{n['phrase_budget']}")
    for s in r["signals"]:
        mark = "FLAG" if s["flagged"] else ("n/a " if s["flagged"] is None else "ok  ")
        ev = s["evidence"]
        if NOT_RECORDED in ev:
            out.append(f"{mark}     {s['name']}: {NOT_RECORDED} in this log")
            continue
        out.append(f"{mark}     {s['name']}: " + json.dumps(ev, sort_keys=True, default=str))
        out.append(f"         innocent: {s['innocent']}")
    for note in r.get("not_recorded") or []:
        out.append(f"NOTE     {note}")
    if r.get("labels_usable_values"):
        out.append("VALUES   " + ", ".join(f"{k}={v}" for k, v in r["labels_usable_values"].items()))
    out.append(f"VERDICT  {r['verdict']}" + (f": {', '.join(r['flagged'])}" if r["flagged"] else ""))
    return out
