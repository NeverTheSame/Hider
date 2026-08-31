"""Command line entry point.

    python -m hider eval      run the harness, write JSON metrics and the HTML report
    python -m hider generate  write a synthetic bundle to disk
    python -m hider redact    redact a file or stdin
    python -m hider proxy     run the redacting OpenAI-compatible gateway
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (
    evaluate,
    generator,
    llm_backend,
    ner,
    pipeline,
    profiles,
    pseudonym,
    report,
)

OUT = Path(__file__).resolve().parent.parent / "out"


def _build_tier3_backend(args: argparse.Namespace):
    """Construct the tier 3 backend from --tier3/--cassette/--record, or None."""
    if args.tier3 == "none":
        return None
    if not args.cassette:
        print("error: --tier3 requires --cassette PATH (add --record to create one "
              "from a live call)", file=sys.stderr)
        raise SystemExit(2)
    if args.record:
        if args.tier3 == "openai":
            real = llm_backend.OpenAIBackend()
        else:
            raise SystemExit(f"error: unknown --tier3 backend {args.tier3!r}")
        return llm_backend.CassetteBackend(path=args.cassette, mode="record", inner=real)
    return llm_backend.CassetteBackend(path=args.cassette, mode="replay")


def _cmd_eval(args: argparse.Namespace) -> int:
    tier2 = None if args.tier2 == "none" else args.tier2
    tier3_backend = _build_tier3_backend(args)
    full, base, _, corpus = evaluate.run_with_baseline(
        lines=args.lines, seed=args.seed, tier2=tier2, tier3=tier3_backend,
    )
    OUT.mkdir(parents=True, exist_ok=True)

    evaluate.save(full, OUT / "metrics.json")
    evaluate.save(base, OUT / "metrics-baseline.json")

    excerpt_tiers: list[pipeline.Tier] = [pipeline.RegexTier()]
    if full.ner_enabled:
        excerpt_tiers.append(evaluate.build_tier2(full.tier2_backend))
    if tier3_backend is not None:
        excerpt_tiers.append(pipeline.LlmPassTier(tier3_backend))
    pipe = pipeline.Pipeline(
        excerpt_tiers, vault=pseudonym.EntityVault(key=b"hider-demo-fixed-key")
    )
    rows = report.excerpt_from(corpus, pipe, unit_hint=args.excerpt, n=args.excerpt_lines)
    html_path = report.write(OUT / "hider-report.html", report.build(full, base, rows))

    print(f"corpus            {full.lines:,} lines, {full.chars:,} chars, "
          f"{full.seeded} seeded values")
    print(f"recall (shaped)   {full.shaped_recall:.4f}   "
          f"baseline stock Presidio {base.shaped_recall:.4f}")
    if full.ner_enabled:
        print(f"recall (freetext) {full.freetext_recall:.4f}   "
              f"floor {evaluate.FREETEXT_RECALL_FLOOR:.2f} "
              f"(tier 2, {evaluate.TIER2_LABELS.get(full.tier2_backend, full.tier2_backend)})")
    print(f"recall (all)      {full.recall:.4f}")
    print(f"false redaction   {full.false_redaction_rate:.4f} "
          f"({full.clean_lines_with_redaction}/{full.clean_lines} clean lines)")
    print(f"survivors         {len(full.unexpected_survivors)} unexplained, "
          f"{len(full.verbatim_survivors) - len(full.unexpected_survivors)} known gap")
    print(f"adversarial       {len(full.surprises)} surprises of {len(full.cases)} cases")
    print(f"degraded units    {full.degraded_units} "
          f"(a tier failed; redaction on those units is incomplete)")
    if full.tier3_enabled:
        rate = full.injection_bypass_rate
        print(f"injection bypass  {rate:.1%} of injection-adjacent names survived "
              f"(tier 3 active, tier2={full.tier2_backend or 'off'})")
    print(f"tier 1 residue    {full.residue_chars:,} chars "
          f"({1 - full.cost_reduction:.1%} of input would reach a paid tier)")
    print(f"cost at ${evaluate.NER_USD_PER_1K_CHARS}/1k chars   "
          f"tiered ${full.tiered_ner_cost_usd:.4f} vs naive ${full.naive_ner_cost_usd:.4f}")
    print(f"\nwrote {html_path}")
    print(f"wrote {OUT / 'metrics.json'}")

    failed = False
    if full.unexpected_survivors or full.surprises:
        print("\nFAIL: unexplained survivors or unexpected adversarial misses",
              file=sys.stderr)
        failed = True
    if full.degraded_units:
        # A degraded unit means some tier did not complete, so that unit's
        # redaction is not the redaction the numbers describe. It was possible
        # for a whole run to degrade quietly: the count was recorded and never
        # printed, so a missing cassette entry looked like a clean pass.
        print(f"\nFAIL: {full.degraded_units} unit(s) degraded during the run; "
              f"the reported coverage does not describe them", file=sys.stderr)
        failed = True
    if full.below_freetext_floor:
        print(f"\nFAIL: freetext recall {full.freetext_recall:.4f} is below the "
              f"floor {evaluate.FREETEXT_RECALL_FLOOR:.2f}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


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
    _announce_profile()
    vault = pseudonym.EntityVault()
    pipe = pipeline.Pipeline(_build_tiers(args.tier2), vault=vault)
    text = Path(args.path).read_text(encoding="utf-8") if args.path else sys.stdin.read()
    events: list[dict] = []
    out = []
    degraded = 0
    for i, line in enumerate(text.splitlines()):
        r = pipe.redact(line, unit=args.path or "<stdin>", line_no=i)
        out.append(r.text)
        events.extend(r.events)
        degraded += int(r.degraded)
    sys.stdout.write("\n".join(out) + "\n")
    if args.log:
        Path(args.log).write_text(
            "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
        )
        print(f"wrote {len(events)} decision events to {args.log}", file=sys.stderr)
    if args.vault:
        vault.save(args.vault)
        print(f"wrote vault with {vault.size} entries to {args.vault}", file=sys.stderr)
    if degraded:
        print(f"REFUSE: {degraded} line(s) degraded during redaction; do not forward "
              f"this output", file=sys.stderr)
        return 1
    return 0


def _build_tiers(which_tier2: str) -> list[pipeline.Tier]:
    """Tier 1, plus tier 2 unless it was explicitly turned off.

    Shared by every command that redacts real input, so the file path and the
    gateway path cannot drift apart. They did once: ``redact`` ran tier 1 only
    while ``proxy`` ran tier 2, which meant the documented "redact the bundle
    before pasting it anywhere" workflow was the one workflow that let a
    customer's name through.
    """
    tiers: list[pipeline.Tier] = [pipeline.RegexTier()]
    if which_tier2 != "none":
        if which_tier2 == "spacy" and not ner.available():
            print("WARNING: spaCy model not installed, tier 2 will not run; "
                  "free-text names will pass through. See requirements-ner.txt.",
                  file=sys.stderr)
        else:
            tiers.append(evaluate.build_tier2(which_tier2))
    else:
        print("WARNING: tier 2 disabled; free-text names and organisations "
              "will pass through unredacted.", file=sys.stderr)
    return tiers


def _announce_profile() -> None:
    prof = profiles.active()
    if prof is not None:
        print(f"site profile: {prof.name} ({prof.pattern_count} extra patterns "
              f"from {prof.source})", file=sys.stderr)


def _cmd_proxy(args: argparse.Namespace) -> int:
    from . import proxy as proxy_mod

    _announce_profile()
    tiers = _build_tiers(args.tier2)
    if args.vault and Path(args.vault).exists():
        vault = pseudonym.EntityVault.load(args.vault)
    else:
        vault = pseudonym.EntityVault()
    pipe = pipeline.Pipeline(tiers, vault=vault)
    gateway = proxy_mod.RedactionGateway(
        args.upstream, pipe, vault_path=args.vault, log_path=args.log
    )
    host, _, port = args.listen.partition(":")
    proxy_mod.serve(host, int(port or "8787"), gateway)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hider", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("eval", help="run the eval harness and write the report")
    e.add_argument("--lines", type=int, default=4000)
    e.add_argument("--seed", type=int, default=20260820)
    e.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier",
                   help="tier 2 backend: the trained classifier (default), local "
                        "spaCy NER, or none")
    e.add_argument("--tier3", choices=["none", "openai"], default="none",
                   help="tier 3 backend: an LLM pass, or none (default)")
    e.add_argument("--cassette", help="cassette JSONL path for --tier3 (record or replay)")
    e.add_argument("--record", action="store_true",
                   help="make a live --tier3 call and append it to --cassette, "
                        "instead of replaying")
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
    r.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier",
                   help="tier 2 backend for free-text names: the trained "
                        "classifier (default), local spaCy NER, or none")
    r.set_defaults(fn=_cmd_redact)

    p = sub.add_parser("proxy", help="run the redacting OpenAI-compatible gateway")
    p.add_argument("--upstream", required=True,
                   help="provider base URL, e.g. https://api.openai.com")
    p.add_argument("--listen", default="127.0.0.1:8787", help="host:port to bind")
    p.add_argument("--vault", help="persist the pseudonym vault here")
    p.add_argument("--log", help="append the JSONL decision log here")
    p.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier",
                   help="tier 2 backend in the sync path: the trained classifier "
                        "(default, fastest), local spaCy NER, or none")
    p.set_defaults(fn=_cmd_proxy)

    args = ap.parse_args(argv)
    return args.fn(args)
