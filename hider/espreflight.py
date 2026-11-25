"""es-preflight: what stays readable on a cluster, in one report, for a person.

Before letting a model session at real logs, someone has to decide whether
what stays readable on that cluster is acceptable. The limits are declared
one by one in docs/es/ (AGENTS.md keeps the rules), but what they amount to on one cluster right now
was spread over the VOCAB line, the READABLE line, the build log and the
operator's memory. This gathers them into one read-only report: what is
hidden, what is not, and for each thing that is not, **which declared limit
it is, how big it is in counts and field names, and what to do about it**.

Human-only: a CLI through the broker's 0600 socket, no MCP tool, nothing
the es-research session can call or read. It writes nothing. Counts, field
names and labels by default; the words behind them only under
``--show-values``, as es-review and es-smoke ask.

Findings come in two severities:

* **stop** - a customer name is (or will be) readable to a model session on
  this cluster right now: the vocabulary not serving, a field counted over
  the cap, a field the map leaves out that holds values, a frozen or stuck
  field, a name inside a longer keep value on a sampled page.
* **know** - a declared trade that cannot be closed from here, with its
  size: names the skip rules leave readable (ordinary words, short),
  ordinary-word names harvested on the sample, and the designed channels
  with their caps.

Cost: the bridge already knows most of it (the vocabulary index, the skip
counts after a local apply) for **0 requests**; the probes add one capped
``cardinality`` per omitted field over the vocabulary window and **one
newest page per index pattern** (``PREFLIGHT_SAMPLE`` documents over the
last day, scrubbed by a throwaway case exactly as a page would be; only
counts and field names leave it). ``--no-probes`` skips both.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from . import elastic

#: documents sampled per index pattern, newest first, over the last day
PREFLIGHT_SAMPLE = 50
PREFLIGHT_WINDOW_S = 86400.0
#: An over-cap field this many times past ``vocabulary.max`` is reported as
#: id-shaped: a wide *name* field lands near the cap (tens of thousands of
#: tenants), an id lands orders of magnitude past it (a fresh value on
#: nearly every document - 2-4 million against 50,000 measured on one real
#: cluster). A heuristic, stated as one, costing 0 requests; the line says
#: which fix each shape wants, because the fix for an id is the site map,
#: never the cap.
OVER_CAP_ID_RATIO = 10.0


def _count_body(config: elastic.ElasticConfig, index: str, field: str, now: float) -> dict:
    start = elastic._iso(now - config.vocabulary_days * 86400.0)
    return {"params": {"index": index, "body": {
        "size": 0, "track_total_hits": False,
        "query": {"bool": {"filter": [{"range": {config.time_field: {
            "gte": start, "lte": elastic._iso(now)}}}]}},
        "aggs": {elastic.VOCABULARY_COUNT_AGG: {"cardinality": {
            "field": field,
            "precision_threshold": min(config.vocabulary_max, 40000)}}}}}}


def _sample_body(config: elastic.ElasticConfig, index: str, now: float) -> dict:
    return {"params": {"index": index, "body": {
        "size": PREFLIGHT_SAMPLE, "track_total_hits": True,
        "sort": [{config.time_field: {"order": "desc"}}],
        "query": {"bool": {"filter": [{"range": {config.time_field: {
            "gte": elastic._iso(now - PREFLIGHT_WINDOW_S), "lte": elastic._iso(now)}}}]}},
        "_source": {"includes": config.source_includes()}}}}


def _leaves(node: Any, prefix: str = ""):
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                yield from _leaves(v, path)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str):
                        yield path, x
            elif isinstance(v, str):
                yield path, v


def gather(config: elastic.ElasticConfig, cluster: str,
           index: "elastic.VocabularyIndex | None",
           search: Callable[[dict], Any] | None, *,
           now: float | None = None, tier2: str = "none",
           show_values: bool = False) -> dict:
    """The report for one cluster. ``search`` runs one request envelope and
    returns the raw reply; None skips the probes. Counts, field names and
    labels; values only under ``show_values``, and then under their own key.
    """
    t = time.time() if now is None else now
    report = index.report(cluster, config, now=t) if index is not None else None
    vocab = index.get(cluster) if index is not None else None
    out: dict[str, Any] = {"cluster": cluster, "probes": search is not None,
                           "requests": 0, "seconds": 0.0,
                           "vocabulary": report, "findings": []}
    t0 = time.perf_counter()
    findings: list[dict] = out["findings"]

    def add(fid: str, severity: str, limit: str, size: str, fix: str, **extra) -> None:
        findings.append({"id": fid, "severity": severity, "limit": limit,
                         "size": size, "fix": fix, **extra})

    # -- 0 requests: what the bridge already knows --------------------------
    if report is not None and config.vocabulary_rules:
        if report.get("state") in ("building", "catching_up") or not report.get("serving", False):
            add("vocabulary_not_serving", "stop",
                "a name logged in a day the cover has not reached is not known",
                f"state {report.get('state')}, covers {report.get('covered_days', 0)}d of "
                f"{config.vocabulary_days}d",
                "wait for the build (es-login shows progress); cases are refused meanwhile")
        elif report.get("state") == "stale":
            add("vocabulary_stale", "stop",
                "names logged since the cover ended are not known",
                f"cover ends {report.get('age_s', 0) / 3600.0:.1f}h ago (top-up overdue)",
                "let the top-up finish (es-login shows progress) or restart the bridge")
        for f, n in sorted((report.get("over_cap") or {}).items()):
            cap = int(report.get("max") or config.vocabulary_max)
            ratio = n / max(1, cap)
            if ratio >= OVER_CAP_ID_RATIO:
                size = (f"{f} ~{n} distinct values, about {ratio:.0f}x the cap {cap}: "
                        "id-shaped (a name field lands near the cap, an id far past it)")
                fix = ("fix the site map, not the cap: an id this wide is not a name field - "
                       "type it as an id (a NO_VOCABULARY_TYPES type such as REQUEST_REF) or "
                       "map it keep, so it is never a vocabulary candidate; raising "
                       "vocabulary.max here would page millions of values at 1,000 a request")
            else:
                size = (f"{f} ~{n} distinct values, {ratio:.1f}x the cap {cap}: "
                        "close to the cap, likely a wide name field")
                fix = ("raise vocabulary.max (cost: a page per 1,000 values per slice), or "
                       "list the field in vocabulary.fields to make the build refuse loudly")
            add("over_cap", "stop",
                "a field wider than vocabulary.max is left unread; its values are readable "
                "in message text",
                size, fix, field=f, count=n, cap=cap,
                shape="id" if ratio >= OVER_CAP_ID_RATIO else "name")
        for f, rng in sorted((report.get("frozen") or {}).items()):
            add("frozen", "stop",
                "a field that left the read set keeps only the names already read; values "
                "logged since stay readable in text",
                f"{f} read {rng[0]} to {rng[1]}, nothing since",
                "put the field back in vocabulary.fields, or accept the shrinking cover",
                field=f)
        for f, x in sorted((report.get("stuck") or {}).items()):
            add("stuck", "stop",
                "a returning field keeps failing to read; its values stay readable in text",
                f"{f} failing since {x.get('since')}, {x.get('attempts')} attempts "
                f"({x.get('code')})",
                "fix the upstream fault or remove the field; cases are served meanwhile",
                field=f)
        # the skip counts live in a scrubber after a local apply (0 requests)
        skipped: dict[str, int] = {}
        if vocab is not None:
            s0 = elastic.EsScrubber(config, tier2="none")
            over0 = {f: int(x["count"])
                     for f, x in index.over_cap_fields(cluster, t).items()} if index else {}
            s0.apply_vocabulary(cluster, vocab, t, over_cap=over0)
            skipped = dict(s0.vocabulary_skipped)
            site_words = dict(s0.vocabulary_site_words)
            for f, n in sorted(site_words.items()):
                rule = config.rule(f)
                tenant = rule is not None and rule.type == "ORG_NAME"
                finding = {"field": f, "count": n}
                if show_values:
                    finding["words"] = sorted(
                        v for v in vocab.fields.get(f, [])
                        if isinstance(v, str) and s0.skip_reason(v) == "site_word")
                add("site_words", "stop" if tenant else "know",
                    "a name the site map lists as a word of its own system "
                    "(vocabulary.readable) keeps its label in its own field and is readable "
                    "everywhere else" + (": here it is also the whole name of a customer"
                                         if tenant else ""),
                    f"{f}: {n} name(s)",
                    "take the word off vocabulary.readable" if tenant else
                    "take a word off vocabulary.readable if it is a customer's name", **finding)
        if skipped:
            add("skip_rules", "know",
                "a one-word name that is an ordinary word, short, a stopword or letterless, "
                "or a name the site map lists as readable, is never made vocabulary; it "
                "stays readable in message text",
                ", ".join(f"{k}: {v}" for k, v in sorted(skipped.items())),
                "seed any that is a real customer name per case (--term NAME)",
                counts=skipped)

    # -- the probes ---------------------------------------------------------
    omitted = list((report or {}).get("omitted") or config.vocabulary_omitted)
    if search is None:
        for f in sorted(omitted):
            add("omitted", "stop",
                "a learnable field the site map's vocabulary.fields leaves out is never "
                "read; its values are readable in message text",
                f"{f} (not counted: probes off)",
                "add it to vocabulary.fields, or accept it readable", field=f)
    else:
        for f in sorted(omitted):
            n: Any = "?"
            for pattern in config.indices:
                try:
                    raw = search(_count_body(config, pattern, f, t))
                    out["requests"] += 1
                    body = raw.get("rawResponse", raw) if isinstance(raw, dict) else {}
                    got = ((body.get("aggregations") or {})
                           .get(elastic.VOCABULARY_COUNT_AGG) or {}).get("value")
                    if isinstance(got, int):
                        n = got if n == "?" else n + got
                except Exception:
                    pass
            add("omitted", "stop",
                "a learnable field the site map's vocabulary.fields leaves out is never "
                "read; its values are readable in message text",
                f"{f} ~{n} distinct values over the last {config.vocabulary_days}d",
                "add it to vocabulary.fields, or accept it readable", field=f, count=n)
        # one newest page per index pattern, scrubbed as a page would be:
        # what does a page look like right now, and what on it is readable
        over_cap = {f: int(x["count"])
                    for f, x in (index.over_cap_fields(cluster, t) if index else {}).items()}
        for pattern in config.indices:
            s = elastic.EsScrubber(config, tier2=tier2)
            if vocab is not None:
                s.apply_vocabulary(cluster, vocab, t, over_cap=over_cap)
            try:
                raw = search(_sample_body(config, pattern, t))
                out["requests"] += 1
                scrubbed = s.scrub_response(raw, elastic.Plan(pattern, size=PREFLIGHT_SAMPLE))
            except elastic.Refused as e:
                add("sample_refused", "know",
                    "the sampled page for this pattern was withheld; what it would show is "
                    "unassessed", f"{pattern}: {e.code}",
                    "run es-smoke against the pattern to see the refusal", index=pattern)
                continue
            except Exception:
                add("sample_refused", "know", "the sampled page for this pattern failed",
                    f"{pattern}: error", "check the bridge and sign-in", index=pattern)
                continue
            hits = scrubbed.output.get("hits", {}).get("hits", []) or []
            inside: dict[str, int] = {}
            seen: set[tuple[int, str]] = set()
            labels: set[str] = set()
            values: set[str] = set()
            for i, h in enumerate(hits):
                nodes = list(_leaves(h.get("_source") or {}))
                if isinstance(h.get("_index"), str):
                    nodes.append(("_index", h["_index"]))
                for path, text in nodes:
                    found = s._find_known(text)
                    if found:
                        inside[path] = inside.get(path, 0) + 1
                        seen.add((i, path))
                        for _a, _b, v in found:
                            lab = s.known.get(v)
                            if lab:
                                labels.add(lab)
                                values.add(s.mapping.get(lab, v))
                            else:
                                values.add(v)
            if inside:
                # what a person decides on is the distinct names, not how
                # many sampled documents repeat them: 2 names across the
                # newest 50 documents read "58 to 200 values" before, and
                # the number moved with the sample
                docs_with = len({d for d, _p in seen})
                finding = {"index": pattern, "names": len(labels),
                           "fields": dict(sorted(inside.items())),
                           "labels": sorted(labels), "documents": docs_with,
                           "sampled": len(hits)}
                if show_values:
                    finding["values"] = sorted(values)
                in_index = " (one of them is the hit's own index name: the stream itself "                            "is named after the customer)" if "_index" in inside else ""
                add("name_in_keep", "stop",
                    "a learnt name inside a longer keep value is readable (only a whole "
                    "keep value is replaced)",
                    f"{pattern}: {len(labels)} distinct learnt name(s) "
                    f"({', '.join(sorted(labels))}) inside longer keep values, in "
                    f"{', '.join(f'{p} on {c} doc(s)' for p, c in sorted(inside.items()))}"
                    f"{in_index}; {docs_with} of the newest {len(hits)} documents carry one "
                    "- a sample, so the document counts move between runs, and where the newest "
                    "documents differ from run to run the names move too",
                    "map the field as identifier, keep the stream out of indices, seed the "
                    "name per case (--term), or list it under vocabulary.readable if it is a "
                    "word of the system and no customer's name", **finding)
            if s.readable_words:
                fields = sorted({s.readable_fields.get(lab, "?") for lab in s.readable_words})
                finding = {"index": pattern,
                           "labels": sorted(s.readable_words), "fields": fields}
                if show_values:
                    finding["words"] = sorted(s.readable_words.values())
                add("readable_words", "know",
                    "a name that is an ordinary word is labelled in its own field and "
                    "readable in text everywhere else",
                    f"{pattern}: {len(s.readable_words)} name(s) from "
                    f"{', '.join(fields)}, seen on the newest {len(hits)} documents",
                    "seed any that is a real customer name (--term NAME)", **finding)
    out["seconds"] = round(time.perf_counter() - t0, 3)
    out["stops"] = sum(1 for f in findings if f["severity"] == "stop")
    out["knows"] = sum(1 for f in findings if f["severity"] == "know")
    return out


#: the designed channels, printed under KNOW on every report: not findings,
#: the same on every cluster, each a declared decision with its cap
def _channel_lines(config: elastic.ElasticConfig) -> list[str]:
    return [
        f"DESIGN   by design, every cluster: a case may confirm up to {config.phrase_budget} "
        f"distinct text phrases by hit count ({config.max_phrases} per query); a page shows up "
        f"to {config.max_hits} labels and an aggregation up to {config.max_buckets} keys, all "
        "usable afterwards; keep-field literals are uncapped (a keep field is declared "
        "non-sensitive); a bare name in a keep field that tier 1 has no shape for passes "
        "(tier 2 stays off keep fields by design)",
        "DESIGN   recognizer- and classifier-level declared misses (unformatted phones, TLDs "
        "outside the list, the dotted-organisation head leak, a name beside a level word) are "
        "the same on every cluster: measured by `python -m hider eval`, not here",
    ]


def format_report(reports: dict[str, dict], config: elastic.ElasticConfig) -> list[str]:
    """Lines for a person: counts, field names, labels, ranges. Words only
    where a report was gathered with show_values, under 'VALUES'."""
    from . import esbridge

    lines: list[str] = []
    for cluster, r in reports.items():
        lines.append(f"PREFLIGHT cluster={cluster}: what stays readable to a model session "
                     "right now (read-only"
                     + (f"; {r['requests']} requests, {r['seconds']}s" if r.get("probes")
                        else "; 0 requests, from what the bridge already knows") + ")")
        vline = esbridge.vocabulary_line(r.get("vocabulary"))
        if vline:
            lines.append("HIDDEN   names the vocabulary hides, and how far back: " + vline)
            lines.append("         (these names are on disk in out/es/vocabulary.json, 0600, "
                         "gitignored)")
        elif config.vocabulary_rules:
            lines.append("HIDDEN   no name vocabulary for this cluster yet: nothing in message "
                         "text is hidden beyond tier 1/2 shapes and per-case seeds")
        for f in r["findings"]:
            mark = "STOP " if f["severity"] == "stop" else "KNOW "
            lines.append(f"{mark}    {f['id']}: {f['size']}")
            lines.append(f"         declared limit: {f['limit']}")
            lines.append(f"         what you can do: {f['fix']}")
            if f.get("values") or f.get("words"):
                lines.append("VALUES   " + ", ".join(f.get("values") or f.get("words")))
        lines += _channel_lines(config)
        # the verdict counts findings; the two DESIGN lines are not findings
        # (they are the same on every cluster), so the counts match the
        # KNOW-marked lines above
        if r["stops"]:
            lines.append(f"VERDICT  {r['stops']} stop finding(s), {r['knows']} know finding(s) "
                         "on this cluster: judge each STOP before letting a model session at "
                         "it (the DESIGN lines above hold everywhere)")
        elif r["knows"]:
            lines.append(f"VERDICT  0 stop, {r['knows']} know finding(s) on this cluster: know "
                         "them before you start (the DESIGN lines above hold everywhere)")
        else:
            lines.append("VERDICT  0 stop, 0 know findings: nothing readable to report beyond "
                         "the DESIGN lines above, which hold on every cluster")
    return lines


def short_form(reports: dict[str, dict]) -> tuple[list[str], int]:
    """What es-research prints before opening a case: the STOP findings and
    the verdict, one line each. Returns (lines, stop count)."""
    lines: list[str] = []
    stops = 0
    for cluster, r in reports.items():
        for f in r["findings"]:
            if f["severity"] == "stop":
                stops += 1
                lines.append(f"READABLE on {cluster}: {f['id']}: {f['size']}")
    if stops:
        lines.append(f"{stops} readable finding(s); run es-preflight for the full report")
    return lines, stops
