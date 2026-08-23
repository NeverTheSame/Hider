"""Command line entry point.

    python -m hider eval      run the harness, write JSON metrics and the HTML report
    python -m hider generate  write a synthetic bundle to disk
    python -m hider redact    redact a file or stdin
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import evaluate, generator, pipeline, pseudonym, report

OUT = Path(__file__).resolve().parent.parent / "out"


def _cmd_eval(args: argparse.Namespace) -> int:
    full, base, _, corpus = evaluate.run_with_baseline(lines=args.lines, seed=args.seed)
    OUT.mkdir(parents=True, exist_ok=True)

    evaluate.save(full, OUT / "metrics.json")
    evaluate.save(base, OUT / "metrics-baseline.json")

    pipe = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"hider-demo-fixed-key"))
    rows = report.excerpt_from(corpus, pipe, unit_hint=args.excerpt, n=args.excerpt_lines)
    html_path = report.write(OUT / "hider-report.html", report.build(full, base, rows))

    print(f"corpus            {full.lines:,} lines, {full.chars:,} chars, "
          f"{full.seeded} seeded values")
    print(f"recall (shaped)   {full.shaped_recall:.4f}   "
          f"baseline stock Presidio {base.shaped_recall:.4f}")
    print(f"recall (all)      {full.recall:.4f}")
    print(f"false redaction   {full.false_redaction_rate:.4f} "
          f"({full.clean_lines_with_redaction}/{full.clean_lines} clean lines)")
    print(f"survivors         {len(full.unexpected_survivors)} unexplained, "
          f"{len(full.verbatim_survivors) - len(full.unexpected_survivors)} known gap")
    print(f"adversarial       {len(full.surprises)} surprises of {len(full.cases)} cases")
    print(f"tier 1 residue    {full.residue_chars:,} chars "
          f"({1 - full.cost_reduction:.1%} of input would reach a paid tier)")
    print(f"cost at ${evaluate.NER_USD_PER_1K_CHARS}/1k chars   "
          f"tiered ${full.tiered_ner_cost_usd:.4f} vs naive ${full.naive_ner_cost_usd:.4f}")
    print(f"\nwrote {html_path}")
    print(f"wrote {OUT / 'metrics.json'}")

    if full.unexpected_survivors or full.surprises:
        print("\nFAIL: unexplained survivors or unexpected adversarial misses", file=sys.stderr)
        return 1
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    corpus = generator.generate(lines=args.lines, seed=args.seed)
    root = Path(args.out)
    for unit in corpus.units:
        p = root / unit.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(unit.text + "\n", encoding="utf-8")
    (root / "ground-truth.json").write_text(
        json.dumps(
            [
                {"unit": o.unit, "line": o.line_no, "type": o.entity_type,
                 "start": o.start, "end": o.end}
                for o in corpus.truth
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"wrote {len(corpus.units)} files, {corpus.total_lines:,} lines to {root}")
    print("ground truth records positions and types only, never the values")
    return 0


def _cmd_redact(args: argparse.Namespace) -> int:
    vault = pseudonym.EntityVault()
    pipe = pipeline.Pipeline(vault=vault)
    text = Path(args.path).read_text(encoding="utf-8") if args.path else sys.stdin.read()
    events: list[dict] = []
    out = []
    for i, line in enumerate(text.splitlines()):
        r = pipe.redact(line, unit=args.path or "<stdin>", line_no=i)
        out.append(r.text)
        events.extend(r.events)
    sys.stdout.write("\n".join(out) + "\n")
    if args.log:
        Path(args.log).write_text(
            "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
        )
        print(f"\nwrote {len(events)} decision events to {args.log}", file=sys.stderr)
    if args.vault:
        vault.save(args.vault)
        print(f"wrote vault with {vault.size} entries to {args.vault}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hider", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("eval", help="run the eval harness and write the report")
    e.add_argument("--lines", type=int, default=4000)
    e.add_argument("--seed", type=int, default=20260820)
    e.add_argument("--excerpt", default="RestoreSession",
                   help="substring of the unit path to show in the before/after pane")
    e.add_argument("--excerpt-lines", type=int, default=14)
    e.set_defaults(fn=_cmd_eval)

    g = sub.add_parser("generate", help="write a synthetic bundle to disk")
    g.add_argument("--lines", type=int, default=4000)
    g.add_argument("--seed", type=int, default=20260820)
    g.add_argument("--out", default=str(OUT / "bundle"))
    g.set_defaults(fn=_cmd_generate)

    r = sub.add_parser("redact", help="redact a file or stdin")
    r.add_argument("path", nargs="?")
    r.add_argument("--log", help="write the JSONL decision log here")
    r.add_argument("--vault", help="save the pseudonym vault here")
    r.set_defaults(fn=_cmd_redact)

    args = ap.parse_args(argv)
    return args.fn(args)
