# AGENTS.md

Orientation for anyone, human or coding agent, picking this project up. The
README explains *why* the system is shaped the way it is and what it has
measured; this file explains how to work on it without breaking the
properties the README promises.

## What this is, in one paragraph

Hider is a tiered redaction layer for support log bundles on their way to an
LLM provider, plus the gateway that enforces it. Tier 1 is regex (Presidio
patterns and custom recognizers), tier 2 is a locally trained classifier (or
spaCy), tier 3 is an optional LLM pass. Identifiers become stable,
shape-preserving pseudonyms held in a vault; credentials are destroyed. A
measured eval harness gates every change. An OpenAI-compatible proxy applies
it in flight; a loopback web UI applies it to JSON exports and brokers a
restricted Claude Code session over the obfuscated file.

## Non-negotiables

These are enforced by tests. If a change needs one of them relaxed, that is a
design conversation, not a code change.

1. **No real data in the repository, ever.** Templates hold typed
   placeholders. Corpora are generated. Cassettes hold prompts over synthetic
   lines only, and the utility cassette holds hashes rather than prompt
   text because generated secrets are shaped like real ones (GitHub push
   protection rejects them, rightly). Before committing a cassette, read it. `out/`, `*.mapping.json`,
   `hider.local.json`, `vault.json`, `*.profile.json` and `feedback.jsonl` are
   gitignored because they can hold real values; keep it that way.
2. **Monotonicity.** A later tier may only add redactions
   (`pipeline.Pipeline.detect` enforces it). Nothing downstream of tier 1 may
   be able to unmask anything, which is the only reason a model is allowed in
   the path.
3. **Fail closed.** A tier that raises marks the unit degraded; the gateway
   refuses a degraded request with 503 and never contacts upstream; the eval
   fails on any degraded unit. Never map an error to "no findings".
4. **Secrets are destroyed, identifiers are pseudonymised**, decided by
   `entities.py`, never by a call site. The vault raises if asked to store a
   secret.
5. **The model is untrusted.** Tier 3 output must be strict JSON, every
   finding must be a verbatim quote verified against the segment, offsets are
   never taken from the model. Instructions go in the system role, data in the
   user role inside the `<<<DATA` fence.
6. **Every number has a test or a cassette behind it.** A README figure that
   cannot be reproduced with `python -m hider eval` or `utility` from a
   committed cassette is not a figure, it is a claim. Re-record and update the
   README together.
7. **Logs record decisions, not data.** Decision logs, metrics and feedback
   summaries carry the substitute, never the original. The one exception is
   the gateway's `--log-request-bodies` debug switch, off by default, which
   writes the raw body into the decision log; a test pins the default off.

## Layout, by what you are likely to touch

| Task | Start here |
|---|---|
| A shaped identifier is missed or over-matched | `hider/recognizers.py`, add a case to `hider/adversarial.py`, test in `tests/test_recognizers.py` |
| A new entity type | `hider/entities.py` first (the contract), then the recognizer, then `pseudonym._shape` if it needs a shaped label |
| Free-text names missed | `hider/classifier.py` (training grammar and features). Keep the train/eval vocabulary disjoint; `test_training_vocabulary_is_disjoint_from_the_eval_vocabulary` guards it |
| Tier 3 prompt or parsing | `hider/llm_tier.py`. Changing the instruction text changes `PROMPT_VERSION`; committed cassettes stop matching and must be re-recorded |
| A new LLM provider | `hider/llm_backend.py`: implement `complete(prompt) -> str`, split with `split_prompt`, feed a `UsageMeter`, raise `BackendError` on any failure. Wire it in `cli._real_backend` and `_add_llm_flags` |
| Gateway behaviour | `hider/proxy.py`. The request path is `handle -> _handle -> redact_payload (tiers, then sweep) -> forward / forward_stream -> detokenize`. Tests use a stub upstream in `tests/test_proxy.py` |
| Eval metrics or gates | `hider/evaluate.py` (recall, precision, adversarial, injection), `hider/utility.py` (answer accuracy raw vs redacted) |
| JSON exports and the web UI | `hider/jsonscrub.py`, `hider/webserver.py` (single-file page, stdlib server), `hider/research.py` (Claude Code bridge) |
| Site-specific patterns | Never in the repo. `templates/profile.example.json` and `HIDER_PROFILE`; see `hider/profiles.py` |

## Running things

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest                      # the whole suite, no network, no keys
.venv/bin/python -m hider eval                   # recall/precision/adversarial, writes out/
.venv/bin/python -m hider eval --tier2 none --tier3 openai \
    --cassette cassettes/tier3-injection-run1.jsonl      # replay, no key needed
.venv/bin/python -m hider utility --backend anthropic \
    --cassette cassettes/utility-haiku-4-5-run1.jsonl    # replay, no key needed
.venv/bin/python -m hider proxy --upstream https://api.openai.com
.venv/bin/python -m hider serve                  # web UI on 127.0.0.1:8790
```

Live calls need `pip install -r requirements-llm.txt`, a key in the
environment, and `--record` with a cassette path. Cassette replay is the
default and needs neither. The test suite never touches the network.

## Working rules

- **Measure before and after.** Run `python -m hider eval` before a change to
  detection and after it, and quote both in the commit or PR. A recall drop on
  one type to fix another is a trade, and trades are stated.
- **Add the adversarial case first** when fixing a miss. A case declares
  whether tier 1 is expected to catch it and names an owner for any gap.
- **One tier, one job.** Do not make tier 1 regexes try to catch names, or
  tier 3 try to catch GUIDs. The cost argument depends on each tier only
  seeing what the previous ones left.
- **Standard library at the boundary.** `proxy.py` and `webserver.py` take no
  web framework by design. Do not add one.
- **Thread safety.** The pipeline, vault and classifier are shared and not
  thread-safe; the gateway serialises redaction under one lock. Keep any new
  per-request state out of module globals, or lock it.
- **Prompt changes are versioned implicitly.** `llm_tier.PROMPT_VERSION` is a
  hash of the instruction text and is written into cassette headers,
  `metrics.json` and `utility.json`. A README number quoted next to a prompt
  version is the number for that prompt only.
- **Dependencies.** Core: presidio, scikit-learn. Optional extras: `ner`
  (spaCy), `llm` (openai, anthropic). Nothing in the core path may import an
  optional extra at module load.

## Known gaps worth knowing before you start

Listed with owners in the README's Limitations section and in
`adversarial.CASES`. The ones most likely to matter:

- Two tier 1 gaps are deliberately left open so they stay visible in the
  numbers: zero-padded IPv4 octets and forward-slash Windows profile paths.
- Tier 2 recall is a model's recall. The classifier's training grammar is
  narrow (twelve templates); an organisation suffix outside its trained set
  is a realistic miss.
- The injection number is one model, five payloads, one run.
- The utility number is one model, one 40-line excerpt, fifteen questions.
- The gateway serialises redaction; fine for a workstation, the first thing
  to change for a shared deployment.

## Where to take questions and findings

See `CONTRIBUTING.md`. In short: a missed or wrong redaction observed on a
real bundle goes through the web UI's "Report a mistake" form (it stays on
the machine) and reaches the repo only as a placeholder template or a
synthetic adversarial case; everything else goes to GitHub issues.
