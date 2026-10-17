"""Self-contained HTML report: what the provider sees, and what it costs.

One page, no external assets, no network. The top half is the two-minute
version: the same bundle excerpt as it would leave the building raw, next to
what Hider actually forwards. The bottom half is the evidence: recall per entity
type per tier, the false-redaction rate, the measured uplift over stock
Presidio, the tier routing, and an explicit list of what does not work yet.
"""

from __future__ import annotations

import html
from pathlib import Path

from . import entities
from .evaluate import FREETEXT_RECALL_FLOOR, NER_USD_PER_1K_CHARS, Report

CSS = """
:root {
  color-scheme: light dark;
  --bg: #fbfaf8; --panel: #ffffff; --ink: #1c1a17; --muted: #6b6560;
  --line: #e3ded7; --accent: #7a4b2a; --raw: #b3261e; --safe: #1f6b3a;
  --raw-bg: rgba(179,38,30,.10); --safe-bg: rgba(31,107,58,.10);
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
:root:not([data-theme="light"]) { }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #16151a; --panel: #1e1d23; --ink: #ece9e4; --muted: #9a938c;
    --line: #322f38; --accent: #d8a06b; --raw: #ff8a80; --safe: #7ddb9b;
    --raw-bg: rgba(255,138,128,.12); --safe-bg: rgba(125,219,155,.12);
  }
}
:root[data-theme="dark"] {
  --bg: #16151a; --panel: #1e1d23; --ink: #ece9e4; --muted: #9a938c;
  --line: #322f38; --accent: #d8a06b; --raw: #ff8a80; --safe: #7ddb9b;
  --raw-bg: rgba(255,138,128,.12); --safe-bg: rgba(125,219,155,.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 40px 24px 80px; }
h1 { font-size: 28px; letter-spacing: -.02em; margin: 0 0 6px; }
h2 { font-size: 18px; margin: 44px 0 12px; letter-spacing: -.01em; }
h3 { font-size: 14px; margin: 22px 0 8px; color: var(--muted);
  text-transform: uppercase; letter-spacing: .08em; font-weight: 600; }
p { margin: 0 0 12px; max-width: 74ch; }
.sub { color: var(--muted); margin-bottom: 28px; }
.kpis { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr)); }
.kpi { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.kpi .n { font-size: 26px; font-weight: 650; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
.kpi .l { color: var(--muted); font-size: 12.5px; margin-top: 2px; }
.kpi .f { color: var(--muted); font-size: 11.5px; margin-top: 6px; }
.split { display: grid; gap: 14px; grid-template-columns: 1fr 1fr; }
@media (max-width: 860px) { .split { grid-template-columns: 1fr; } }
.pane { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.pane > header { padding: 10px 14px; border-bottom: 1px solid var(--line);
  font-size: 12.5px; font-weight: 650; letter-spacing: .02em; }
.pane.raw > header { color: var(--raw); background: var(--raw-bg); }
.pane.safe > header { color: var(--safe); background: var(--safe-bg); }
pre { margin: 0; padding: 12px 14px; overflow-x: auto; font-family: var(--mono);
  font-size: 11.5px; line-height: 1.65; white-space: pre; }
mark { background: var(--raw-bg); color: var(--raw); border-radius: 3px; padding: 0 2px; }
mark.ok { background: var(--safe-bg); color: var(--safe); }
table { width: 100%; border-collapse: collapse; font-size: 13px;
  font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
th, td { text-align: right; padding: 8px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }
th:first-child, td:first-child { text-align: left; }
thead th { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; }
tbody tr:last-child td { border-bottom: none; }
td.good { color: var(--safe); } td.bad { color: var(--raw); }
.tag { display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 999px;
  border: 1px solid var(--line); color: var(--muted); }
.tag.gap { color: var(--accent); border-color: var(--accent); }
.note { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: 8px; padding: 14px 16px; }
.note p:last-child { margin-bottom: 0; }
ul { max-width: 74ch; padding-left: 20px; } li { margin-bottom: 7px; }
footer { color: var(--muted); font-size: 12px; margin-top: 56px;
  border-top: 1px solid var(--line); padding-top: 16px; }
"""


def _highlight_raw(line: str, spans) -> str:
    out: list[str] = []
    cursor = 0
    for s in sorted(spans, key=lambda x: x.start):
        out.append(html.escape(line[cursor:s.start]))
        out.append(f"<mark>{html.escape(line[s.start:s.end])}</mark>")
        cursor = s.end
    out.append(html.escape(line[cursor:]))
    return "".join(out)


def _highlight_out(line: str, replacements: list[str]) -> str:
    esc = html.escape(line)
    for rep in sorted(set(replacements), key=len, reverse=True):
        if not rep:
            continue
        esc = esc.replace(html.escape(rep), f"<mark class='ok'>{html.escape(rep)}</mark>")
    return esc


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _kpi(n: str, label: str, foot: str = "") -> str:
    f = f"<div class='f'>{html.escape(foot)}</div>" if foot else ""
    return f"<div class='kpi'><div class='n'>{n}</div><div class='l'>{html.escape(label)}</div>{f}</div>"


def build(
    report: Report,
    baseline: Report,
    excerpt: list[tuple[str, str, list, list[str]]],
    *,
    title: str = "Hider: what the model provider actually sees",
) -> str:
    tier2_short = {"classifier": "trained classifier", "spacy": "local spaCy NER"}.get(
        report.tier2_backend, report.tier2_backend or "tier 2"
    )

    raw_lines = "\n".join(_highlight_raw(line, spans) for line, _, spans, _ in excerpt)
    out_lines = "\n".join(_highlight_out(red, reps) for _, red, _, reps in excerpt)

    # ---- KPI row ----
    kpis = "".join([
        _kpi(_pct(report.shaped_recall), "recall on shaped identifiers",
             f"{report.covered} of {report.seeded} seeded values, tier 1"),
        _kpi(
            _pct(report.freetext_recall) if report.ner_enabled else "not run",
            "recall on free-text names",
            f"tier 2, {tier2_short}; gated at a floor, not at zero"
            if report.ner_enabled else "no tier 2 backend selected for this run",
        ),
        _kpi(_pct(report.false_redaction_rate), "false-redaction rate",
             f"on {report.clean_lines} lines known to hold nothing sensitive"),
        _kpi(str(len(report.unexpected_survivors)), "unexplained survivors",
             "seeded values still findable verbatim in the output"),
        _kpi(_pct(report.cost_reduction), "paid-tier spend avoided",
             "tier 1 clears this share of characters before any paid tier"),
        _kpi(f"{report.tier_elapsed_s.get('tier1', 0) / max(report.lines, 1) * 1e6:,.0f} us",
             "tier 1 per line", "single-threaded, no network, no NLP model"),
    ])

    # ---- recall table ----
    rows = []
    for name, t in sorted(report.types.items(), key=lambda kv: (-kv[1].seeded, kv[0])):
        b = baseline.types.get(name)
        base_recall = b.recall if b else 0.0
        gap = t.expected_tier != entities.TIER_SHAPED
        cls = "good" if t.recall >= 0.999 else ("bad" if not gap and t.recall < 0.95 else "")
        if t.expected_tier == entities.TIER_FREETEXT:
            tier_note = "tier 2, probabilistic"
        elif t.expected_tier == entities.TIER_CONTEXTUAL:
            tier_note = "tier 3, not built"
        else:
            tier_note = "tier 1"
        rows.append(
            f"<tr><td>{name}<br><span class='tag{' gap' if gap else ''}'>{tier_note}</span></td>"
            f"<td>{t.seeded}</td><td>{t.covered}</td><td>{t.partial}</td>"
            f"<td class='{cls}'>{_pct(t.recall)}</td>"
            f"<td>{_pct(t.typed_recall)}</td>"
            f"<td>{_pct(base_recall)}</td></tr>"
        )
    recall_table = (
        "<div class='scroll'><table><thead><tr><th>Entity type</th><th>Seeded</th>"
        "<th>Fully redacted</th><th>Partial</th><th>Recall</th><th>Typed recall</th>"
        "<th>Stock Presidio</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )

    # ---- adversarial table ----
    arows = []
    for c in report.cases:
        if c.surprise:
            state, cls = "surprise", "bad"
        elif c.caught_all:
            state, cls = "caught", "good"
        elif not c.expect_tier1:
            state, cls = "known gap", ""
        else:
            state, cls = "no shaped entity", ""
        owner = html.escape(c.owner) if c.owner else ""
        arows.append(
            f"<tr><td>{html.escape(c.case_id)}<br><span class='tag'>{html.escape(c.description[:78])}</span>"
            + (f"<br><span class='tag gap'>{owner[:150]}</span>" if owner else "")
            + f"</td><td>{c.shaped_covered} / {c.shaped_seeded}</td>"
            f"<td>{c.free_covered} / {c.free_seeded}</td>"
            f"<td class='{cls}'>{state}</td></tr>"
        )
    adv_table = (
        "<div class='scroll'><table><thead><tr><th>Hostile placement</th>"
        "<th>Shaped caught</th><th>Free text caught</th><th>Verdict</th></tr></thead><tbody>"
        + "".join(arows) + "</tbody></table></div>"
    )

    # ---- tier routing ----
    t1 = report.tier_chars_offered.get("tier1", 0)
    if report.ner_enabled:
        tier2_row = (
            f"<tr><td>tier 2, {tier2_short}, over the residue</td>"
            f"<td>{report.tier_chars_offered.get('tier2', 0):,}</td>"
            f"<td>{report.tier_chars_redacted.get('tier2', 0):,}</td><td>$0.0000</td>"
            f"<td>{report.tier_elapsed_s.get('tier2', 0):.2f} s</td></tr>"
        )
    else:
        tier2_row = (
            f"<tr><td>tier 2, over the residue</td><td>{report.residue_chars:,}</td>"
            f"<td>not run (no backend selected)</td><td>$0.0000</td><td>&mdash;</td></tr>"
        )
    trows = [
        f"<tr><td>tier 1, Presidio patterns</td><td>{t1:,}</td>"
        f"<td>{report.tier_chars_redacted.get('tier1', 0):,}</td><td>$0.0000</td>"
        f"<td>{report.tier_elapsed_s.get('tier1', 0):.2f} s</td></tr>",
        tier2_row,
    ]
    if report.tier3_enabled:
        trows.append(
            f"<tr><td>tier 3, LLM pass, over the residue</td>"
            f"<td>{report.tier_chars_offered.get('tier3', 0):,}</td>"
            f"<td>{report.tier_chars_redacted.get('tier3', 0):,}</td><td>network bound</td>"
            f"<td>{report.tier_elapsed_s.get('tier3', 0):.2f} s</td></tr>"
        )
    trows += [
        f"<tr><td>hypothetical: tier 2 as a paid managed NER</td><td>{report.residue_chars:,}</td>"
        f"<td>n/a</td><td>${report.tiered_ner_cost_usd:.4f}</td><td>network bound</td></tr>",
        f"<tr><td>hypothetical: no tiering, everything to managed NER</td><td>{report.chars:,}</td>"
        f"<td>n/a</td><td>${report.naive_ner_cost_usd:.4f}</td><td>network bound</td></tr>",
    ]
    tier_table = (
        "<div class='scroll'><table><thead><tr><th>Tier</th><th>Characters offered</th>"
        "<th>Characters redacted</th><th>Cost at assumed rate</th><th>Wall time</th>"
        "</tr></thead><tbody>" + "".join(trows) + "</tbody></table></div>"
    )

    return f"""<title>{html.escape(title)}</title>
<style>{CSS}</style>
<div class="wrap">
<h1>{html.escape(title)}</h1>
<p class="sub">Hider. {"Three" if report.tier3_enabled else "Two" if report.ner_enabled else "One"} live
tier{"s" if report.ner_enabled else ""} &mdash; deterministic patterns{f", then {tier2_short} over what they leave" if report.ner_enabled else ""}{", then an LLM pass over the rest" if report.tier3_enabled else ""}
&mdash; measured on a synthetic bundle of
{report.lines:,} lines and {report.chars:,} characters with {report.seeded}
planted values whose type and position are known exactly.</p>

<div class="kpis">{kpis}</div>

<h2>The same excerpt, two destinations</h2>
<p>Left is what a support engineer pasting a log excerpt into a chat window
sends today. Right is what leaves the building once the same text goes through
Hider. Identifiers keep a stable pseudonym, so the correlation an engineer needs
survives; credentials are destroyed outright, because holding one is itself the
risk.</p>
<div class="split">
  <div class="pane raw"><header>Raw, straight to the provider</header><pre>{raw_lines}</pre></div>
  <div class="pane safe"><header>Through Hider</header><pre>{out_lines}</pre></div>
</div>

<h2>Recall, per entity type</h2>
<p>Every value in the corpus was planted deliberately, so nothing here is
hand-labelled. <strong>Typed recall</strong> is stricter than recall: it also
requires the detector to have named the entity correctly, which it honestly
cannot always do, since a session id and a tenant id are the same 36 characters
on the wire. The last column is stock Presidio on the identical corpus, which is
what the custom domain recognizers are measured against.</p>
{recall_table}
<p><span class="tag gap">tier 2, probabilistic</span> marks the free-text
types: tier 1 cannot catch them (they have no shape) and tier 2 is a model, so
its recall is a measurement against a floor
({_pct(FREETEXT_RECALL_FLOOR)}), not a zero-survivor invariant like tier 1's.
The two gates are reported side by side, never blended.</p>

<h2>Over-redaction</h2>
<p>Recall alone is easy to game: redact everything and score 100 percent. The
corpus therefore includes {report.clean_lines} lines that contain no sensitive
value at all, drawn from the same templates. A redaction there is unambiguously
wrong.</p>
<div class="note"><p><strong>{report.clean_lines_with_redaction} of
{report.clean_lines}</strong> clean lines were touched, a false-redaction rate of
{_pct(report.false_redaction_rate)}. Getting there needed two named suppression
rules, both found by this measurement rather than by inspection: stock IP
matching flags build numbers such as <code>8.1.0.7</code>, and public Microsoft
endpoints are not customer data. Both live in one small, tested function,
because suppression is the only part of the engine that removes protection.</p></div>

<h2>Hostile placements</h2>
<p>The generator produces the placements its author thought of, which is exactly
the blind spot that makes self-scored recall untrustworthy. These
{len(report.cases)} cases were written to attack it: identifiers split across
lines, percent-encoded, re-cased, buried in escaped JSON and stack traces. Each
one declares in advance whether tier 1 should catch it, so a documented
limitation can never be mistaken for a pass, or for a defect.</p>
{adv_table}
<p>Surprises, meaning a case expected to pass that did not:
<strong>{len(report.surprises)}</strong>.</p>

<h2>Why tiering, in money</h2>
<p>Tier 1 runs first as a cost gate. It has no per-call price and no network
hop, so every character it clears is a character no paid tier is billed for.
The shipped tier 2 is local and in-process, so it costs nothing per character
either; the two hypothetical rows below keep the original argument visible,
at an assumed managed-NER list rate of ${NER_USD_PER_1K_CHARS} per 1000
characters:</p>
{tier_table}
<p>On this corpus tier 1 clears {_pct(report.cost_reduction)} of the characters
before the NER model is consulted at all. The saving scales with how shaped
the data is, and support bundles are almost all shaped, which is the whole
argument for putting regex in front rather than reaching for a model first.</p>

<h2>What this does not show</h2>
<ul>
<li><strong>The corpus is synthetic.</strong> Real bundles hold placements
nobody thought to generate. The mitigation is procedural: entity formats were
written from public documentation and sanitized structural templates before any
recognizer existed, and the hostile corpus above exists to attack the overlap
that remains. It is a mitigation, not a fix.</li>
<li><strong>One person wrote both sides.</strong> Generator and recognizers came
from one mental model, so independence here is procedural rather than
organisational. Recall on shaped types should be read as an upper bound.</li>
<li><strong>Tier 2 recall is a model's recall.</strong> Free-text names are
caught at {_pct(report.freetext_recall) if report.ner_enabled else "n/a"},
against a floor of {_pct(FREETEXT_RECALL_FLOOR)}. A miss is not a defect the
way a tier 1 miss is; it is the honest ceiling of a {tier2_short if report.ner_enabled else "small"} model, and the
reasons are listed per survivor in the JSON metrics.</li>
<li><strong>Prompt-injection resistance{"" if report.tier3_enabled else " is untested"}.</strong>
{f"{report.injection_bypass_rate:.1%} of injection-adjacent names in this run survived a payload sitting next to them, with tier2={report.tier2_backend or 'off'} also in the pipeline. Tiers 1 and 2 have no notion of an instruction at all, so this number isolates what tier 3 alone would allow through only when tier 2 is disabled for the same run."
if report.tier3_enabled else
f"The {report.injection_canaries} pure-text canaries and 5 name-adjacent cases are already in the corpus, but "
f"no tier 3 backend ran this time, and tiers 1-2 have no instructions to subvert, so reporting a pass "
f"would be dishonest. Pass --tier3 openai (with a cassette) to measure it."}</li>
<li><strong>The hypothetical cost figures use an assumed list rate,</strong>
not an invoice. Characters offered per tier are measured; the dollar
conversion is arithmetic on a published price.</li>
</ul>

<footer>Generated by <code>hider.report</code>. Corpus seed and configuration are
recorded in the accompanying JSON. No customer data was used at any point: the
templates hold typed placeholders only, and every value in this report was
generated locally.</footer>
</div>
"""


def excerpt_from(corpus, pipe, *, unit_hint: str = "", n: int = 14):
    """Pick a demo excerpt and run it, returning rows for the side-by-side view."""
    unit = None
    for u in corpus.units:
        if unit_hint and unit_hint in u.path:
            unit = u
            break
    if unit is None:
        unit = max(
            (u for u in corpus.units if u.path not in corpus.clean_units),
            key=lambda u: len(u.lines),
        )
    rows = []
    for i, line in enumerate(unit.lines[:n]):
        r = pipe.redact(line, unit=unit.path, line_no=i)
        reps = [e["marker"] for e in r.events]
        rows.append((line, r.text, r.spans, reps))
    return rows


def write(path: str | Path, htmltext: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(htmltext, encoding="utf-8")
    return p
