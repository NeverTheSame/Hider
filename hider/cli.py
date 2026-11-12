"""Command line entry point.

    python -m hider eval      run the harness, write JSON metrics and the HTML report
    python -m hider generate  write a synthetic bundle to disk
    python -m hider redact    redact a file or stdin
    python -m hider proxy     run the redacting OpenAI-compatible gateway
    python -m hider serve     run the local JSON obfuscation web UI
    python -m hider scrub-json FILE   obfuscate a JSON file from the shell
    python -m hider utility   measure answer accuracy on raw vs redacted input
    python -m hider feedback  list what users reported as missed or wrongly redacted
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import (
    evaluate,
    generator,
    llm_backend,
    ner,
    pipeline,
    profiles,
    proxy,
    pseudonym,
    report,
)

OUT = Path(__file__).resolve().parent.parent / "out"

#: How long es-logout keeps asking a busy broker to stop before giving up
#: and saying so. A page of the vocabulary read is seconds; a minute is
#: more than enough, and saying "no bridge" at one that is still running is
#: the failure worth avoiding.
_LOGOUT_WAIT_S = 60.0


def _real_backend(kind: str, model: str | None, base_url: str | None,
                  usage: llm_backend.UsageMeter):
    if kind == "openai":
        kw = {"usage": usage}
        if model:
            kw["model"] = model
        if base_url:
            kw["base_url"] = base_url
        return llm_backend.OpenAIBackend(**kw)
    if kind == "anthropic":
        kw = {"usage": usage}
        if model:
            kw["model"] = model
        return llm_backend.AnthropicBackend(**kw)
    raise SystemExit(f"error: unknown backend {kind!r}")


def _build_llm_backend(args: argparse.Namespace, *, flag: str = "--tier3",
                       store_prompts: bool = True):
    """The backend behind ``--tier3``/``--backend``: cassette replay, or a
    live backend wrapped in retries, a breaker and an optional fallback,
    recording into the cassette. ``None`` when the flag is ``none``."""
    kind = getattr(args, "tier3", None) or getattr(args, "backend", None) or "none"
    if kind == "none":
        return None
    if not args.cassette:
        print(f"error: {flag} requires --cassette PATH (add --record to create one "
              "from a live call)", file=sys.stderr)
        raise SystemExit(2)
    from .llm_tier import PROMPT_VERSION
    if args.record:
        usage = llm_backend.UsageMeter()
        primary = _real_backend(kind, args.model, getattr(args, "base_url", None), usage)
        fallback = None
        if getattr(args, "fallback", None) and args.fallback != "none":
            fallback = llm_backend.ResilientBackend(
                _real_backend(args.fallback, getattr(args, "fallback_model", None),
                              None, usage), retries=1)
        resilient = llm_backend.ResilientBackend(primary, fallback=fallback)
        return llm_backend.CassetteBackend(path=args.cassette, mode="record",
                                           inner=resilient, prompt_version=PROMPT_VERSION,
                                           store_prompts=store_prompts)
    return llm_backend.CassetteBackend(path=args.cassette, mode="replay",
                                       prompt_version=PROMPT_VERSION)


def _build_tier3_backend(args: argparse.Namespace):
    return _build_llm_backend(args)


def _add_llm_flags(sp: argparse.ArgumentParser, *, dest: str) -> None:
    sp.add_argument(f"--{dest}", choices=["none", "openai", "anthropic"], default="none",
                    help="LLM backend: an OpenAI-compatible API, the Anthropic API, "
                         "or none (default)")
    sp.add_argument("--model", help="model id for the live backend (provider default "
                                    "otherwise)")
    sp.add_argument("--base-url", help="OpenAI-compatible server to call instead of "
                                       "api.openai.com (a local model, another vendor)")
    sp.add_argument("--fallback", choices=["none", "openai", "anthropic"], default="none",
                    help="backend to try when the primary is exhausted or its "
                         "circuit breaker is open")
    sp.add_argument("--fallback-model")
    sp.add_argument("--cassette", help="cassette JSONL path (record or replay)")
    sp.add_argument("--record", action="store_true",
                    help="make live calls and append them to --cassette, instead of "
                         "replaying")


def _cmd_eval(args: argparse.Namespace) -> int:
    tier2 = None if args.tier2 == "none" else args.tier2
    tier3_backend = _build_tier3_backend(args)
    full, base, _, corpus = evaluate.run_with_baseline(
        lines=args.lines, seed=args.seed, tier2=tier2, tier3=tier3_backend,
        tier3_batch=args.batch, tier3_workers=args.workers,
    )
    OUT.mkdir(parents=True, exist_ok=True)

    evaluate.save(full, OUT / "metrics.json")
    evaluate.save(base, OUT / "metrics-baseline.json")

    excerpt_tiers: list[pipeline.Tier] = [pipeline.RegexTier()]
    if full.ner_enabled:
        excerpt_tiers.append(evaluate.build_tier2(full.tier2_backend))
    if tier3_backend is not None:
        excerpt_tiers.append(pipeline.LlmPassTier(tier3_backend, batch_size=args.batch,
                                                  workers=args.workers))
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
    if full.lookalike_lines:
        print(f"path lookalikes   {full.lookalike_lines_with_redaction}/{full.lookalike_lines} "
              f"lines changed ({full.lookalike_false_spans} spans; system, source, API, "
              f"version paths)")
    if full.credential_lookalike_lines:
        print(f"cred lookalikes   {full.credential_lookalike_lines_with_redaction}/"
              f"{full.credential_lookalike_lines} lines changed "
              f"({full.credential_lookalike_false_spans} spans; key names beside a policy "
              f"word, a mask, a count), plus "
              f"{full.credential_lookalike_misses_destroyed}/"
              f"{full.credential_lookalike_declared_misses} declared misses destroyed")
    print(f"survivors         {len(full.unexpected_survivors)} unexplained, "
          f"{len(full.verbatim_survivors) - len(full.unexpected_survivors)} known gap")
    print(f"adversarial       {len(full.surprises)} surprises of {len(full.cases)} cases")
    print(f"degraded units    {full.degraded_units} "
          f"(a tier failed; redaction on those units is incomplete)")
    if full.tier3_enabled:
        rate = full.injection_bypass_rate
        print(f"injection bypass  {rate:.1%} of injection-adjacent names survived "
              f"(tier 3 active, tier2={full.tier2_backend or 'off'})")
        info = full.tier3_info or {}
        rec = info.get("recording") or {}
        print(f"tier 3 provenance backend={rec.get('backend') or info.get('backend')} "
              f"model={rec.get('model') or info.get('model')} "
              f"prompt={info.get('prompt_version')} "
              f"batch={info.get('batch_size')} cache={info.get('cache')}")
        if info.get("usage"):
            u = info["usage"]
            cost = u.get("cost_usd_list_price")
            print(f"tier 3 usage      {u['calls']} calls, {u['input_tokens']} in / "
                  f"{u['output_tokens']} out tokens, "
                  f"cost {'$%.4f' % cost if cost is not None else 'unpriced model'}")
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


def _cmd_utility(args: argparse.Namespace) -> int:
    from . import utility

    # Hashes only: the utility prompts carry a whole excerpt, secrets included.
    backend = _build_llm_backend(args, flag="--backend", store_prompts=False)
    if backend is None:
        print("error: --backend openai|anthropic is required (with --cassette)",
              file=sys.stderr)
        return 2
    tier2 = None if args.tier2 == "none" else args.tier2
    rep = utility.run(backend, lines=args.lines, seed=args.seed,
                      excerpt_lines=args.excerpt_lines, tier2=tier2)
    OUT.mkdir(parents=True, exist_ok=True)
    utility.save(rep, OUT / "utility.json")
    print(f"excerpt           {rep.excerpt_lines} lines, {rep.excerpt_chars:,} chars, "
          f"{rep.seeded_in_excerpt} seeded values")
    print(f"questions         {rep.n}")
    print(f"accuracy raw      {rep.raw_accuracy:.4f}")
    print(f"accuracy redacted {rep.redacted_accuracy:.4f}")
    print(f"delta             {rep.delta:+.4f}   floor {utility.DELTA_FLOOR:.2f} "
          f"(positive = redaction cost accuracy)")
    for q in rep.questions:
        flag = ("ok " if q.raw_correct else "-- ") + ("ok " if q.redacted_correct else "-- ")
        err = q.redacted_error or q.raw_error or ""
        print(f"  [{flag}] {q.qid:<40} {err}")
    b = rep.backend or {}
    u = b.get("usage") or {}
    rec = b.get("recording") or {}
    print(f"backend           {rec.get('backend') or b.get('name')} "
          f"model={rec.get('model') or b.get('model')} prompt={rep.prompt_version}")
    if u:
        cost = u.get("cost_usd_list_price")
        print(f"usage             {u['calls']} calls, {u['input_tokens']} in / "
              f"{u['output_tokens']} out tokens, "
              f"cost {'$%.4f' % cost if cost is not None else 'unpriced model'}")
    print(f"wrote {OUT / 'utility.json'}")
    failed = False
    if rep.prompt_leaks:
        print(f"\nFAIL: {rep.prompt_leaks} seeded value(s) would have left in a redacted "
              f"prompt; those questions were refused", file=sys.stderr)
        failed = True
    if rep.below_floor:
        print(f"\nFAIL: redaction cost {rep.delta:.1%} accuracy, above the "
              f"{utility.DELTA_FLOOR:.0%} floor", file=sys.stderr)
        failed = True
    return 1 if failed else 0


def _cmd_es_eval(args: argparse.Namespace) -> int:
    from . import elastic, eseval

    cfg = elastic.load(args.config) if args.config else elastic.load(elastic.EXAMPLE)
    report = eseval.run_eval(cfg, seed=args.seed, docs=args.docs, queries=args.queries,
                             tier2=args.tier2)
    print(eseval.format_report(report))
    eseval.OUT.mkdir(parents=True, exist_ok=True)
    path = eseval.OUT / "es-eval.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {path}")
    return 0 if report["passed"] else 1


def _es_config(path: str | None):
    from . import elastic

    if path:
        return elastic.load(path)
    cfg = elastic.active()
    if cfg is None:
        raise SystemExit("no elastic site map: set HIDER_ELASTIC or 'elastic' in hider.local.json, "
                         "or pass --config (or --stub to use the example map)")
    return cfg


def _cmd_es_smoke(args: argparse.Namespace) -> int:
    """One scrubbed query, end to end, printing decisions only.

    Against a real cluster the query goes to the running bridge (es-login
    starts it), which holds the only Kibana session there is. With --stub
    everything runs in this process against a synthetic Kibana.
    """
    from . import elastic, esbridge

    size = args.size if args.size is not None else (0 if args.count_by or args.interval else 3)
    args.eq_pairs = _eq_pairs(args.eq)
    if args.phrase_field and not args.phrase:
        raise SystemExit("--phrase-field names the field --phrase searches; give a --phrase")
    if args.stub:
        return _es_smoke_stub(args, size)
    if args.no_browser or args.expired:
        raise SystemExit("--no-browser and --expired only work with --stub")
    cfg = _es_config(args.config)
    cluster = args.cluster
    if not cluster:
        raise SystemExit(f"--cluster is required; configured: {[c.name for c in cfg.clusters]}")
    q = _smoke_query(esbridge, cfg, args, size)
    client = esbridge.BrokerClient(esbridge.broker_socket(args.profile_dir or cfg.profile_dir),
                                   timeout=cfg.poll_timeout_s + 120)
    # es-smoke is the tool that shows where the bridge is, so it reports the
    # build rather than hiding behind it; a query before it is ready is
    # refused with vocabulary_building, and this says why.
    try:
        _wait_for_vocabulary(client, cluster, timeout=0.0)
    except elastic.Refused:
        pass
    seeded: list[str] = []

    def run(query: dict) -> dict:
        try:
            report = client.call("run", cluster=cluster, query=query, terms=args.term,
                                 tier2=args.tier2, show_names=args.show_readable_names,
                                 log=str(Path(args.log).resolve()) if args.log else None)["report"]
        except elastic.Refused as e:
            return {"refused": {"code": e.code, "message": e.message}}
        seeded[:] = report.get("seeded", [])
        return report

    report = esbridge.run_smoke(run, q, max_buckets=cfg.max_buckets)
    for label in seeded:
        print(f"seeded    {label}  (the real value stays in the bridge)", file=sys.stderr)
    return esbridge.print_smoke(cluster, q, report, show=args.show)


def _eq_pairs(raw: list[str]) -> list[tuple[str, str]]:
    """FIELD=VALUE, split at the first '='. The value goes to the grammar as
    written: an identifier field takes a label this case has issued."""
    pairs = []
    for item in raw:
        field, sep, value = item.partition("=")
        if not sep or not field.strip():
            raise SystemExit(f"--eq takes FIELD=VALUE, got {item!r}")
        pairs.append((field.strip(), value))
    return pairs


def _smoke_query(esbridge, cfg, args: argparse.Namespace, size: int) -> dict:
    q = esbridge.smoke_query(cfg, args.index, args.phrase, size=size, since=args.since,
                             until=args.until, count_by=args.count_by,
                             interval=args.interval, buckets=args.buckets,
                             phrase_field=args.phrase_field, eq=args.eq_pairs)
    print(f"query     {json.dumps(q)}", file=sys.stderr)
    return q


def _es_smoke_stub(args: argparse.Namespace, size: int) -> int:
    """The whole path in one process against a synthetic Kibana. The browser
    signs in through the stub's SSO and runs the query in the same lifetime,
    because its session cookie dies when it closes, as a real one does."""
    import tempfile

    from . import elastic, esbridge, eseval

    fx = eseval.generate(docs=200)
    cfg0 = elastic.load(elastic.EXAMPLE)
    # the synthetic documents sit at eseval.NOW, so the vocabulary build has
    # to read the range around that instant; see esbridge.clock
    esbridge.clock = eseval.NOW.timestamp
    # headless sign-in is allowed here only: the real IdP refuses it. With
    # --expired the IdP is closed too, or Chrome parking its tab would sign
    # the run straight back in.
    stub = eseval.StubKibana(eseval.StubEngine(fx, cfg0.indices), cookie="sid=synthetic-stub",
                             signed_in=not args.expired, sso_headless=True,
                             sso=not args.expired).start()
    try:
        raw = json.loads(elastic.EXAMPLE.read_text())
        raw["clusters"] = {"stub": {"kibana": stub.url}}
        raw["profile_dir"] = args.profile_dir or tempfile.mkdtemp(prefix="hider-es-profile-")
        cfg = elastic.parse(raw, source="stub")
        if args.no_browser:
            transport = esbridge.UrllibTransport(stub.cookie)
        else:
            transport = esbridge.BrowserTransport(cfg.profile_dir)
        try:
            if not args.no_browser and not args.expired:
                transport.login(cfg.cluster("stub"), timeout=30)
            scrubber = elastic.EsScrubber(cfg, tier2=args.tier2)
            try:
                labels = esbridge.seed_terms(cfg, scrubber, args.term)
            except elastic.Refused as e:
                print(f"REFUSED  cluster=stub code={e.code}: {e.message}")
                return 2
            for label in labels:
                print(f"seeded    {label}  (the real value stays here)", file=sys.stderr)
            session = esbridge.KibanaSession(transport, poll_timeout=cfg.poll_timeout_s)
            # the sign-in build, which a real bridge does once and keeps; here
            # it runs in line, printing its progress as the broker logs it
            index = elastic.VocabularyIndex(None)
            cluster = cfg.cluster("stub")
            build = elastic.VocabularyBuild(
                cfg, esbridge.clock() - cfg.vocabulary_days * 86400.0, esbridge.clock())

            def _over_cap() -> dict:
                """Fields counted and left out, for the progress line. The
                stub index has no directory, so this is in memory only."""
                return {"max": cfg.vocabulary_max,
                        "over_cap": {f: int(v["count"]) for f, v in
                                     index.over_cap_fields("stub", esbridge.clock()).items()}}

            try:
                while build.pending():
                    build.feed(session.search(cluster, build.request()))
                    for field, count in build.take_dropped().items():
                        index.note_over_cap("stub", field, count, esbridge.clock())
                    print(esbridge.vocabulary_line({"building": build.progress(), **_over_cap()}),
                          file=sys.stderr)
                index.put("stub", build.result())
            except elastic.Refused as e:
                print(f"REFUSED  cluster=stub code={e.code}: {e.message}")
                return 2
            bridge = esbridge.Bridge(cfg, scrubber, session,
                                     log_path=Path(args.log) if args.log else None,
                                     index=index)
            q = _smoke_query(esbridge, cfg, args, size)
            report = esbridge.run_smoke(
                lambda query: esbridge.run_case(bridge, "stub", query,
                                                show_names=args.show_readable_names),
                q, max_buckets=cfg.max_buckets)
            return esbridge.print_smoke("stub", q, report, show=args.show)
        finally:
            transport.close()
    finally:
        stub.stop()


def _broker_argv(args: argparse.Namespace) -> list[str]:
    argv = []
    if args.config:
        argv += ["--config", str(Path(args.config).expanduser().resolve())]
    if args.profile_dir:
        argv += ["--profile-dir", str(Path(args.profile_dir).expanduser().resolve())]
    return argv


def _cmd_es_login(args: argparse.Namespace) -> int:
    """Sign a cluster in, in the bridge's long-lived Chrome. Starts the
    bridge if it is not running. Prints cluster names, never Kibana URLs."""
    from . import elastic, esbridge

    cfg = _es_config(args.config)
    cluster = cfg.cluster(args.cluster)
    if cluster is None:
        raise SystemExit(f"unknown cluster; configured: {[c.name for c in cfg.clusters]}")
    sock = esbridge.broker_socket(args.profile_dir or cfg.profile_dir)
    if not esbridge.broker_running(sock):
        print("starting the bridge's own Chrome (it stays open: the Kibana session lives "
              "in it and ends with it)", file=sys.stderr)
        try:
            esbridge.spawn_broker(sock, _broker_argv(args))
        except RuntimeError as e:
            raise SystemExit(str(e)) from None
    print(f"signing in cluster {cluster.name} in the bridge's Chrome window; it minimises "
          "itself once Kibana loads", file=sys.stderr)
    try:
        reply = esbridge.BrokerClient(sock, timeout=args.timeout + 60).call(
            "login", cluster=cluster.name, timeout=args.timeout)
    except elastic.Refused as e:
        print(f"REFUSED  cluster={cluster.name} code={e.code}: {e.message}")
        return 2
    if reply["signed_in"]:
        print(f"signed in: cluster {cluster.name}; the session lasts while the bridge runs "
              "(es-logout, closing its window, or 8 hours idle ends it)")
        # The one vocabulary build for this bridge. It is slow - minutes on a
        # large estate - and a case opened before it finishes is refused, so
        # wait here, where someone is already waiting, and show the progress.
        print("reading the cluster's customer names once, so a name in message text can be "
              "labelled. This is the slow part of signing in; cases are refused until it "
              "finishes.", file=sys.stderr)
        state = _wait_for_vocabulary(
            esbridge.BrokerClient(sock, timeout=60), cluster.name)
        if state.get("state") == "building" and not state.get("serving"):
            print(f"the name vocabulary for {cluster.name} does not yet cover the last "
                  f"{elastic.VOCABULARY_SERVE_DAYS} days; cases will be refused until it "
                  "does. The bridge keeps reading - run es-login again to see the progress.")
            return 1
        return 0
    print(f"timed out: cluster {cluster.name} did not reach Kibana; run es-login again")
    return 1


def _cmd_es_logout(args: argparse.Namespace) -> int:
    from . import elastic, esbridge

    cfg = _es_config(args.config)
    sock = esbridge.broker_socket(args.profile_dir or cfg.profile_dir)
    # A busy broker is not a missing one. While the socket file is there,
    # keep asking: a refusal used to print "no bridge was running" at a
    # broker that was mid-page, which left it alive holding the Kibana
    # session - the opposite of what es-logout is for.
    deadline = time.monotonic() + _LOGOUT_WAIT_S
    said = False
    while True:
        try:
            esbridge.BrokerClient(sock, timeout=30).call("stop")
            print("bridge stopped; every Kibana session ended with its browser")
            return 0
        except elastic.Refused as e:
            if esbridge.broker_state(sock) == "absent":
                print("no bridge was running")
                return 0
            if time.monotonic() >= deadline:
                print(f"the bridge is busy and did not stop ({e.code}); it is still running "
                      "and still holds the Kibana session. Try es-logout again.")
                return 1
            if not said:
                print("the bridge is busy (it reads the name vocabulary a page at a time); "
                      "waiting for it to stop", file=sys.stderr)
                said = True
            time.sleep(1.0)


def _cmd_es_broker(args: argparse.Namespace) -> int:
    """The long-lived bridge, in the foreground. es-login starts it detached."""
    from . import esbridge

    cfg = _es_config(args.config)
    profile = esbridge.prepare_profile_dir(args.profile_dir or cfg.profile_dir)
    sock = esbridge.broker_socket(profile)
    broker = esbridge.Broker(cfg, lambda: esbridge.BrowserTransport(profile, headless=False),
                             idle_timeout=args.idle_hours * 3600)
    broker.open()
    print(f"bridge listening for {[c.name for c in cfg.clusters]}; es-logout stops it",
          file=sys.stderr)
    try:
        broker.serve(sock)
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_es_research(args: argparse.Namespace) -> int:
    """Claude Code over the live logs, through the bridge's MCP tools only.

    The bridge (es-login) opens the case and mints its token; this process
    masks the prompt, launches Claude Code restricted to those tools in an
    empty folder with an allowlisted environment, then closes the case and
    unmasks the answer locally."""
    from . import elastic, esbridge

    if args.stub:
        return _es_research_stub(args)
    cfg = _es_config(args.config)
    sock = esbridge.broker_socket(args.profile_dir or cfg.profile_dir)
    if not esbridge.broker_running(sock):
        print("REFUSED  code=session_expired: no bridge is running; start it with "
              "es-login --cluster NAME")
        return 2
    return _es_research(args, esbridge.BrokerClient(sock, timeout=60), elastic.SESSIONS, cfg)


def _cmd_es_review(args: argparse.Namespace) -> int:
    """Review one case from its decision log and saved session: human-only,
    read-only, counts and labels by default. Exit 0 when nothing is flagged,
    1 when something is, 2 when there is no log to review."""
    from . import elastic, esreview

    base = Path(args.sessions_dir) if args.sessions_dir else elastic.SESSIONS
    report = esreview.review(base / args.case, show_values=args.show_values)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("\n".join(esreview.format_review(report)))
    if report["log_status"] != "ok":
        return 2
    return 1 if report["flagged"] else 0


def _es_research(args: argparse.Namespace, client, sessions_dir: Path, cfg) -> int:
    import subprocess

    from . import elastic, esmcp, research

    prompt = None
    if args.prompt is not None:
        prompt = sys.stdin.read() if args.prompt == "-" else args.prompt
    try:
        opened = client.call("open_case", case=args.case, terms=args.term, tier2=args.tier2)
    except elastic.Refused as e:
        print(f"REFUSED  code={e.code}: {e.message}")
        return 2
    token, launch = opened["token"], None
    try:
        if opened["replaced"]:
            print("an earlier Claude session on this case was closed; its tools stop working",
                  file=sys.stderr)
        for label, etype in opened["seeded"]:
            print(f"seeded    {label}  ({etype}; the real value stays in the bridge)",
                  file=sys.stderr)
        extra: dict[str, str] = {}
        session_json = sessions_dir / args.case / "session.json"
        if prompt is not None:
            mapping = esmcp.load_case_mapping(sessions_dir, args.case)
            masking = esmcp.load_case_mapping(sessions_dir, args.case, for_masking=True)
            # What masking cannot replace: an identifier the case does not
            # hold. Checked on the prompt as typed (values the case holds are
            # masked below, so they are not findings), before the preview and
            # whatever --yes says.
            findings = esmcp.prompt_findings(prompt, mapping, seedable=esmcp.seedable_types(cfg),
                                             shapes=esmcp.config_shapes(cfg), known=False)
            if findings:
                for f in findings:
                    print(f"REFUSED  code=prompt_identifier: the prompt was not sent; {f}")
                return 2
            # words the labels show anyway (the region in ctr-amer-s01) are public
            prompt, extra, n = research.mask_prompt(prompt, masking, None, "\n".join(mapping))
            print(f"--- sent to Claude Code ({n} customer value(s) masked) ---\n{prompt}\n---",
                  file=sys.stderr)
            if not args.yes and input("send it? [y/N] ").strip().lower() != "y":
                return 1
        launch = esmcp.prepare_launch(opened["url"], token, config=cfg, session_json=session_json)
        argv = esmcp.claude_argv(launch.mcp_config, prompt, model=args.model,
                                 max_budget_usd=args.max_budget_usd, settings=launch.settings)
        env = esmcp.claude_env()
        if prompt is None:
            print("Claude Code with the hider-es tools only (no shell, no files, no web); "
                  "every prompt you type is checked first, and one holding a customer value or "
                  "an identifier is blocked; exit it to close the case", file=sys.stderr)
            rc = subprocess.run(argv, cwd=launch.workspace, env=env).returncode
            print(f"unmask its answers with:  python -m hider unmask answer.md --mapping "
                  f"{sessions_dir / args.case / 'session.json'}", file=sys.stderr)
            return rc
        t0 = time.time()
        proc = subprocess.run(argv, cwd=launch.workspace, env=env, capture_output=True,
                              text=True, timeout=args.timeout, stdin=subprocess.DEVNULL)
        try:
            reply = json.loads(proc.stdout)
        except json.JSONDecodeError:
            print(f"claude exited {proc.returncode}: {proc.stderr.strip()[:400]}", file=sys.stderr)
            return 1
        if not isinstance(reply, dict) or reply.get("is_error") or proc.returncode:
            result = reply.get("result") if isinstance(reply, dict) else None
            print(f"claude failed: {str(result or proc.stderr)[:400]}", file=sys.stderr)
            return 1
        if reply.get("num_turns") == 0 and str(reply.get("result") or "").startswith(
                "UserPromptSubmit operation blocked by hook"):
            # the hook refused what the check above let through; its reply
            # quotes the prompt, so it is not an answer and is not saved
            print("REFUSED  code=prompt_identifier: the prompt check in Claude Code blocked the "
                  "prompt", file=sys.stderr)
            return 2
        answer_masked = str(reply.get("result") or "")
    finally:
        try:
            client.call("close_case", token=token)
        except elastic.Refused:
            pass
        if launch is not None:
            launch.cleanup()
    # labels minted during the session are in the case file now
    mapping = {**esmcp.load_case_mapping(sessions_dir, args.case), **extra}
    answer, replaced, unknown = research.unmask(answer_masked, mapping)
    answer, shaped = esmcp.unmask_shaped(answer, mapping)
    replaced += shaped
    dest = esmcp.research_dir(research.RESEARCH, args.case)
    (dest / "prompt.sent.txt").write_text(prompt, encoding="utf-8")
    (dest / "answer.masked.md").write_text(answer_masked, encoding="utf-8")
    (dest / "answer.md").write_text(answer, encoding="utf-8")
    print(answer)
    denials = len(reply.get("permission_denials") or [])
    print(f"--- {replaced} labels unmasked, {round(time.time() - t0, 1)} s, cost "
          f"${reply.get('total_cost_usd') or 0:.2f}, {denials} blocked tool calls; saved {dest}",
          file=sys.stderr)
    if unknown:
        print(f"labels not in the case: {', '.join(unknown)}", file=sys.stderr)
    return 0


def _es_research_stub(args: argparse.Namespace) -> int:
    """es-research against a synthetic Kibana: a broker in this process
    speaking plain HTTP to the stub, cases in a throwaway directory."""
    import shutil
    import tempfile
    import threading

    from . import elastic, esbridge, eseval

    fx = eseval.generate(docs=300)
    cfg0 = elastic.load(elastic.EXAMPLE)
    esbridge.clock = eseval.NOW.timestamp  # the fixture's clock; see _es_smoke_stub
    stub = eseval.StubKibana(eseval.StubEngine(fx, cfg0.indices),
                             cookie="sid=synthetic-stub").start()
    # a socket path must fit in 104 bytes; the default temp root on macOS is long
    base = Path(tempfile.mkdtemp(prefix="hes-", dir="/tmp" if Path("/tmp").is_dir() else None))
    try:
        raw = json.loads(elastic.EXAMPLE.read_text())
        raw["clusters"] = {"stub": {"kibana": stub.url}}
        raw["profile_dir"] = str(base / "profile")
        cfg = elastic.parse(raw, source="stub")
        profile = esbridge.prepare_profile_dir(cfg.profile_dir)
        sock = esbridge.broker_socket(profile)
        broker = esbridge.Broker(cfg, lambda: esbridge.UrllibTransport(stub.cookie),
                                 sessions_dir=base / "cases")
        thread = threading.Thread(target=broker.serve, args=(sock,), daemon=True)
        thread.start()
        for _ in range(200):
            if esbridge.broker_running(sock):
                break
            time.sleep(0.02)
        if not args.term:
            print(f"stub: synthetic tenants you can seed with --term: {[t.name for t in fx.tenants[:3]]}",
                  file=sys.stderr)
        try:
            control = esbridge.BrokerClient(sock, timeout=60)
            _wait_for_vocabulary(control, "stub")
            return _es_research(args, control, base / "cases", cfg)
        finally:
            broker.stopping = True
            thread.join(10)
    finally:
        stub.stop()
        shutil.rmtree(base, ignore_errors=True)


def _wait_for_vocabulary(control, cluster: str, *, timeout: float = 1800.0,
                         quiet: bool = False) -> dict:
    """Start the cluster's name vocabulary build and wait for it.

    The build is paid once per bridge, and a case opened before it finishes
    is refused, so every entry point that opens a case waits here first.
    Progress goes to stderr as counts, never a name.
    """
    from . import elastic, esbridge

    def poll(**fields) -> dict | None:
        """One progress call. A refusal is not an answer: a broker mid-page
        can time out a client, and a caller that treated that as the end of
        the build would give up on a bridge that is working. None means
        "ask again"; only a broker that has stopped answering ping at all
        ends the wait."""
        try:
            return control.call("vocabulary", cluster=cluster, **fields)["vocabulary"]
        except elastic.Refused:
            try:
                control.call("ping")
            except elastic.Refused:
                return {"state": "failed", "refused": "the bridge stopped answering"}
            return None

    state = poll(build=True)
    deadline = time.monotonic() + timeout
    shown = None
    # The wait ends when the cover reaches the recent days ("serving"), not
    # when the whole of vocabulary.days is in: that is hours on a real
    # estate, and the older slices keep building behind the case.
    # "failed" ends it as surely, or a caller would wait out the timeout.
    while (state is None or (state.get("state") == "building"
                             and not state.get("serving"))) \
            and time.monotonic() < deadline:
        line = esbridge.vocabulary_line(state) if state else None
        if line and line != shown and not quiet:
            print(line, file=sys.stderr)
            shown = line
        time.sleep(0.05)
        state = poll()
    state = state or {"state": "building"}
    if not quiet:
        line = esbridge.vocabulary_line(state)
        if line:
            print(line, file=sys.stderr)
        if state.get("state") in {"extending", "top_up_due"}:
            print("the recent days are in, so cases can run now; the bridge keeps reading "
                  "further back on its own. A name logged only in a day not yet covered is "
                  "not known until it is - the VOCAB line shows how far back the cover goes.",
                  file=sys.stderr)
        if state.get("state") == "failed":
            print(f"the name vocabulary build stopped: {state.get('refused')}. Cases stay "
                  "refused until the recent days are read; the bridge retries on its own, "
                  "and es-login again shows the progress.", file=sys.stderr)
    return state


def _cmd_es_prompt_check(args: argparse.Namespace) -> int:
    """Claude Code's UserPromptSubmit hook for es-research. Reads the hook's
    JSON on stdin; exit 0 and no output lets the prompt through, exit 2
    blocks it and shows stderr to the human (never to the model). Anything
    unexpected is a block: a hook that fails any other way would let the
    prompt pass."""
    try:
        from . import esmcp

        event = json.loads(sys.stdin.read())
        findings = esmcp.check_prompt_file(args.check, event.get("prompt"))
    except Exception:
        print("hider: the prompt check failed, so the prompt was blocked", file=sys.stderr)
        return 2
    if findings:
        for f in findings:
            print(f"hider: prompt blocked; {f}", file=sys.stderr)
        return 2
    return 0


def _cmd_feedback(args: argparse.Namespace) -> int:
    from . import feedback

    rows = feedback.load(args.path)
    s = feedback.summary(rows)
    print(f"{s['total']} report(s): {s['by_kind']}")
    for t, n in s["by_entity_type"].items():
        print(f"  {t}: {n}")
    for r in rows[-args.last:]:
        text = r["text"] if args.show_values else f"<{len(r['text'])} chars>"
        print(f"{r['ts']}  {r['kind']:<6} {r.get('entity_type') or '-':<16} "
              f"run={r.get('run') or '-'}  {text}  {r.get('note') or ''}")
    if rows and not args.show_values:
        print("(values hidden; pass --show-values to print them)")
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
    proxy_mod = proxy

    _announce_profile()
    tiers = _build_tiers(args.tier2)
    if args.vault and Path(args.vault).exists():
        vault = pseudonym.EntityVault.load(args.vault)
    else:
        vault = pseudonym.EntityVault()
    pipe = pipeline.Pipeline(tiers, vault=vault)
    gateway = proxy_mod.RedactionGateway(
        args.upstream, pipe, vault_path=args.vault, log_path=args.log,
        log_max_bytes=args.log_max_bytes or None, log_backups=args.log_backups,
        log_request_bodies=args.log_request_bodies,
    )
    host, _, port = args.listen.partition(":")
    proxy_mod.serve(host, int(port or "8787"), gateway)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from . import webserver

    _announce_profile()
    host, _, port = args.listen.partition(":")
    webserver.serve(host, int(port or "8790"), tier2=args.tier2,
                    allow_remote=args.allow_remote)
    return 0


def _cmd_scrub_json(args: argparse.Namespace) -> int:
    from . import webserver

    _announce_profile()
    raw = Path(args.path).read_text(encoding="utf-8-sig")
    result = webserver.obfuscate_text(raw, Path(args.path).name, tier2=args.tier2,
                                      terms=args.term)
    s = result["stats"]
    print(f"mapped {s['mapped_values']} values, destroyed {s['secrets_destroyed']} secrets, "
          f"{len(s['leaks'])} leaks, {s['degraded_lines']} degraded lines", file=sys.stderr)
    # The names that are ordinary words. The verdict is clean and stays
    # clean - this is the declared trade, not a defect - but a clean run
    # looks identical whether or not it happened, so say it here, with the
    # words, since this is the one place that both knows them and is
    # talking to the person who can act on it.
    readable = [result["mapping"].get(lab, lab) for lab in s.get("readable_words") or []]
    if readable:
        print(f"READABLE: {len(readable)} name(s) are ordinary words and stay readable in text "
              f"outside the record that holds them: {', '.join(sorted(readable))}. "
              f"Re-run with --term NAME for any that is a real customer name.", file=sys.stderr)
    print(f"wrote {result['saved']['output']}", file=sys.stderr)
    print(f"wrote {result['saved']['mapping']}", file=sys.stderr)
    if s["leaks"] or s["degraded_lines"]:
        print("REVIEW: leak check or degraded lines flagged; do not share as is",
              file=sys.stderr)
        return 1
    return 0


def _cmd_merge_csv(args: argparse.Namespace) -> int:
    from . import csvmerge

    meta = {"policy": args.policy, "workload_tenant": args.tenant, "backup_server": args.backup_server,
            "region": args.region, "session_start": args.session_start,
            "session_status": None if (args.session_status or "").startswith("<")
            else args.session_status}
    doc = csvmerge.merge(csvmerge.collect(args.paths), meta)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{csvmerge.summary(doc)} -> {args.out}")
    return 0


def _cmd_ask(args: argparse.Namespace) -> int:
    from . import research

    mapping, terms, public = research.run_context(args.run)
    prompt = args.prompt if args.prompt != "-" else sys.stdin.read()
    masked, extra, n = research.mask_prompt(prompt, mapping, terms, public)
    print(f"--- sent to Claude Code ({n} customer value(s) masked) ---\n{masked}\n---",
          file=sys.stderr)
    if not args.yes and input("send it? [y/N] ").strip().lower() != "y":
        return 1
    r = research.ask(args.run, masked, model=args.model, extra=extra)
    print(r["answer"])
    print(f"--- {r['replaced']} labels unmasked, {r['seconds']} s, cost ${r['cost_usd'] or 0:.2f}, "
          f"{r['denied_tool_calls']} blocked tool calls; saved {r['saved']}", file=sys.stderr)
    if r["unknown_labels"]:
        print(f"labels not in the mapping: {', '.join(r['unknown_labels'])}", file=sys.stderr)
    return 0


def _cmd_workspace(args: argparse.Namespace) -> int:
    import shlex

    from . import research

    ws = research.make_workspace(args.run, research.RESEARCH)
    cmd = " ".join(shlex.quote(c) for c in research.claude_command())
    print(f"workspace: {ws} (only {research.DATA_NAME} and CLAUDE.md)", file=sys.stderr)
    print(f"start Claude Code there with:\n\n  cd {shlex.quote(str(ws))} && {cmd}\n", file=sys.stderr)
    print(f"then unmask its answers with:  python -m hider unmask answer.md --run {args.run}",
          file=sys.stderr)
    return 0


def _cmd_unmask(args: argparse.Namespace) -> int:
    from . import research

    path = args.mapping or research.resolve_run(args.run)[1]
    mapping, _ = research.load_mapping(path)
    text = sys.stdin.read() if args.path in (None, "-") else Path(args.path).read_text(
        encoding="utf-8")
    out, n, unknown = research.unmask(text, mapping)
    from . import elastic
    try:
        es_case = json.loads(Path(path).read_text(encoding="utf-8")).get("schema") == \
            elastic.SESSION_SCHEMA
    except (OSError, ValueError, AttributeError):
        es_case = False
    if es_case:  # an es-research case: server labels like ctr-amer-s01 have no brackets
        from . import esmcp
        out, shaped = esmcp.unmask_shaped(out, mapping)
        n += shaped
    sys.stdout.write(out)
    print(f"\n--- {n} label(s) unmasked", file=sys.stderr)
    if unknown:
        print(f"labels not in the mapping: {', '.join(unknown)}", file=sys.stderr)
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
    _add_llm_flags(e, dest="tier3")
    e.add_argument("--batch", type=int, default=1,
                   help="tier 3 residue segments per prompt (1 keeps the recorded "
                        "single-segment prompt)")
    e.add_argument("--workers", type=int, default=1,
                   help="concurrent tier 3 batches per unit")
    e.add_argument("--excerpt", default="RestoreSession",
                   help="substring of the unit path to show in the before/after pane")
    e.add_argument("--excerpt-lines", type=int, default=14)
    e.set_defaults(fn=_cmd_eval)

    ut = sub.add_parser("utility", help="measure answer accuracy on raw vs redacted input")
    _add_llm_flags(ut, dest="backend")
    ut.add_argument("--lines", type=int, default=300)
    ut.add_argument("--seed", type=int, default=20260820)
    ut.add_argument("--excerpt-lines", type=int, default=40)
    ut.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    ut.set_defaults(fn=_cmd_utility)

    ee = sub.add_parser("es-eval", help="measure the Elasticsearch core offline: synthetic "
                                        "documents, stub Kibana, leak and refusal numbers")
    ee.add_argument("--config", help="a site map (default: templates/elastic.example.json)")
    ee.add_argument("--docs", type=int, default=600)
    ee.add_argument("--queries", type=int, default=120)
    ee.add_argument("--seed", type=int, default=20261103)
    ee.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    ee.set_defaults(fn=_cmd_es_eval)

    sm = sub.add_parser("es-smoke", help="one scrubbed query through the live bridge "
                                         "(or a local stub Kibana with --stub); prints decisions only")
    sm.add_argument("--cluster", help="configured cluster name")
    sm.add_argument("--config", help="site map file (default: HIDER_ELASTIC / hider.local.json)")
    sm.add_argument("--stub", action="store_true",
                    help="start a synthetic Kibana on loopback and run against it")
    sm.add_argument("--expired", action="store_true",
                    help="with --stub: the stub serves the SSO login page (expect a refusal)")
    sm.add_argument("--no-browser", action="store_true",
                    help="with --stub: plain HTTP instead of Chrome")
    sm.add_argument("--profile-dir", help="override the dedicated browser profile directory "
                                          "(locates the running bridge)")
    sm.add_argument("--index", help="index pattern to query (default: the first configured)")
    sm.add_argument("--phrase", action="append", default=[],
                    help="a phrase on the phrase field; repeat to AND several "
                         "(--phrase 'returned HTTP' --phrase 429)")
    sm.add_argument("--phrase-field", metavar="FIELD",
                    help="the text field --phrase searches (default: the first text field in "
                         "the site map); named in the summary")
    sm.add_argument("--eq", action="append", default=[], metavar="FIELD=VALUE",
                    help="an exact filter, repeatable, ANDed; identifier fields take a label "
                         "this run has issued (see --term TYPE=VALUE)")
    sm.add_argument("--size", type=int, default=None,
                    help="hits on the page (default 3, or 0 with --count-by/--interval)")
    sm.add_argument("--since", default="now-1h",
                    help="Kibana-style start: now-7d, now-1d/d, or an ISO timestamp (default now-1h)")
    sm.add_argument("--until", default="now", help="Kibana-style end (default now)")
    sm.add_argument("--count-by", metavar="FIELD",
                    help="terms aggregation on a site-map field; identifier keys come back as labels")
    sm.add_argument("--interval", metavar="IV",
                    help="split counts by a date histogram on the time field: 1h, 1d, ...")
    sm.add_argument("--buckets", type=int, default=10,
                    help="with --count-by: how many terms buckets (capped by max_buckets)")
    sm.add_argument("--term", action="append", default=[],
                    help="seed the case with a customer name, or TYPE=VALUE for another "
                         "identifier type (SERVER_NAME=...); stays local; repeatable")
    sm.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    sm.add_argument("--show", action="store_true", help="print the scrubbed page")
    sm.add_argument("--show-readable-names", action="store_true",
                    help="print the real words behind the READABLE line (names that are "
                         "ordinary words and stay readable in text). Off by default: this "
                         "output is read by scripts too, so a customer name is never printed "
                         "unasked")
    sm.add_argument("--log", help="append a decision-log row to this JSONL file")
    sm.set_defaults(fn=_cmd_es_smoke)

    lg = sub.add_parser("es-login", help="sign a cluster in, in the bridge's long-lived Chrome "
                                         "(starts the bridge if needed)")
    lg.add_argument("--cluster", required=True)
    lg.add_argument("--config")
    lg.add_argument("--profile-dir")
    lg.add_argument("--timeout", type=float, default=600.0)
    lg.set_defaults(fn=_cmd_es_login)

    rv = sub.add_parser("es-review", help="review what an es-research case did, from its "
                                          "decision log: queries, refusals, phrase spend and "
                                          "signals of probing; read-only, for a human")
    rv.add_argument("--case", required=True, help="the case name (out/es/<case>)")
    rv.add_argument("--sessions-dir", help="where the cases live (default out/es)")
    rv.add_argument("--show-values", action="store_true",
                    help="print the real values behind labels the case used or guessed. Off by "
                         "default: counts, labels, codes and field names only")
    rv.add_argument("--json", action="store_true", help="the full report as JSON")
    rv.set_defaults(fn=_cmd_es_review)

    lo = sub.add_parser("es-logout", help="stop the bridge; its Chrome and every Kibana session "
                                          "in it end")
    lo.add_argument("--config")
    lo.add_argument("--profile-dir")
    lo.set_defaults(fn=_cmd_es_logout)

    br = sub.add_parser("es-broker", help="run the long-lived bridge in the foreground "
                                          "(es-login starts it detached)")
    br.add_argument("--config")
    br.add_argument("--profile-dir")
    br.add_argument("--idle-hours", type=float, default=8.0,
                    help="stop after this long without a request (default 8, a working day)")
    br.set_defaults(fn=_cmd_es_broker)

    rs = sub.add_parser("es-research", help="Claude Code over the live logs through the "
                                            "bridge's MCP tools only; every value a label")
    rs.add_argument("--case", required=True,
                    help="case name; its vault persists under out/es/CASE across sessions")
    rs.add_argument("--term", action="append", default=[],
                    help="seed the case: a customer name, or TYPE=VALUE (SERVER_NAME=...); "
                         "stays local, Claude gets the label; repeatable")
    rs.add_argument("--prompt", help="ask one question headless ('-' reads stdin); without it "
                                     "Claude Code opens interactively")
    rs.add_argument("--yes", action="store_true", help="send the masked prompt without asking")
    rs.add_argument("--model")
    rs.add_argument("--max-budget-usd", type=float, help="with --prompt: stop spending at this")
    rs.add_argument("--timeout", type=int, default=1800, help="with --prompt: seconds")
    rs.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    rs.add_argument("--config")
    rs.add_argument("--profile-dir")
    rs.add_argument("--stub", action="store_true",
                    help="a synthetic Kibana and an in-process bridge; nothing live")
    rs.set_defaults(fn=_cmd_es_research)

    pc = sub.add_parser("es-prompt-check", help="internal: the prompt check es-research installs "
                                                "as Claude Code's UserPromptSubmit hook")
    pc.add_argument("check", help="the launch's prompt-check.json")
    pc.set_defaults(fn=_cmd_es_prompt_check)

    fb = sub.add_parser("feedback", help="list redaction feedback reported from the web UI")
    fb.add_argument("--path", help="feedback JSONL (default out/feedback.jsonl)")
    fb.add_argument("--last", type=int, default=20)
    fb.add_argument("--show-values", action="store_true",
                    help="print the reported text (it may be real customer data)")
    fb.set_defaults(fn=_cmd_feedback)

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
    p.add_argument("--log-max-bytes", type=int, default=proxy.LOG_MAX_BYTES,
                   help="rotate the decision log when it would grow past this many "
                        "bytes (default 50 MiB); 0 disables rotation")
    p.add_argument("--log-backups", type=int, default=proxy.LOG_BACKUPS,
                   help="numbered backups to keep after rotation, .1 newest "
                        "(default 5); 0 discards the full log")
    p.add_argument("--log-request-bodies", action="store_true",
                   help="DEBUG ONLY: record the raw, unredacted request body in each "
                        "decision log row. The log then holds the original data; "
                        "never use on a shared machine or with a log you may share")
    p.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier",
                   help="tier 2 backend in the sync path: the trained classifier "
                        "(default, fastest), local spaCy NER, or none")
    p.set_defaults(fn=_cmd_proxy)

    w = sub.add_parser("serve", help="run the local JSON obfuscation web UI")
    w.add_argument("--listen", default="127.0.0.1:8790", help="host:port to bind")
    w.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    w.add_argument("--allow-remote", action="store_true",
                   help="allow binding a non-loopback address")
    w.set_defaults(fn=_cmd_serve)

    j = sub.add_parser("scrub-json", help="obfuscate a JSON file without the web UI")
    j.add_argument("path")
    j.add_argument("--term", action="append", default=[],
                   help="a customer term to always hide, whatever its length (repeatable)")
    j.add_argument("--tier2", choices=["classifier", "spacy", "none"], default="classifier")
    j.set_defaults(fn=_cmd_scrub_json)

    m = sub.add_parser("merge-csv", help="merge the portal's Download logs CSV parts into JSON")
    m.add_argument("paths", nargs="+", help="a folder of parts, or the part files")
    m.add_argument("-o", "--out", required=True)
    for opt in ("--policy", "--tenant", "--backup-server", "--region", "--session-start",
                "--session-status"):
        m.add_argument(opt)
    m.set_defaults(fn=_cmd_merge_csv)

    a = sub.add_parser("ask", help="ask Claude Code about an obfuscated run, unmask the answer")
    a.add_argument("run", help="run name (see out/json) or path to its .obfuscated.json")
    a.add_argument("prompt", help="the question, or - for stdin")
    a.add_argument("--model")
    a.add_argument("-y", "--yes", action="store_true", help="send without asking")
    a.set_defaults(fn=_cmd_ask)

    ws = sub.add_parser("workspace", help="folder with only the obfuscated file, "
                                          "for an interactive restricted Claude Code session")
    ws.add_argument("run")
    ws.set_defaults(fn=_cmd_workspace)

    u = sub.add_parser("unmask", help="put real values back into text with labels (no model)")
    u.add_argument("path", nargs="?", help="text file, or - / nothing for stdin")
    g2 = u.add_mutually_exclusive_group(required=True)
    g2.add_argument("--run")
    g2.add_argument("--mapping", help="path to a .mapping.json")
    u.set_defaults(fn=_cmd_unmask)

    args = ap.parse_args(argv)
    return args.fn(args)
