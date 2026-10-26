# AGENTS.md — working on Hider

Instructions for anyone, human or coding agent, continuing this project.
The README explains what Hider is and what it has measured; this file explains
how to work on it without breaking the properties that make it trustworthy.

## What this is, in one paragraph

A tiered redaction layer for log bundles on their way to a third-party LLM
provider, and the OpenAI-compatible gateway (`hider/proxy.py`) that enforces it
in the request path. Tier 1 is deterministic regex (Presidio + custom
recognizers), tier 2 is a locally trained classifier (or spaCy NER), tier 3 is
an LLM pass over what is left. Identifiers become stable, shape-preserving
pseudonyms kept in a vault; credentials are destroyed outright. Every claim in
the README has a number from `python -m hider eval` or `python -m hider
utility` behind it.

## The three invariants — never weaken these

Everything else in the codebase is negotiable; these are not. Each is enforced
by tests, not convention:

1. **Monotonicity.** A later tier may only ADD redactions. This is the entire
   reason an LLM is allowed in the path: a successful prompt injection against
   tier 3 can over-redact or waste money, never unmask. Enforced structurally
   in `pipeline.Pipeline.detect`.
2. **Fail closed.** A tier that errors, times out, or returns a malformed
   response never degrades to passthrough. The unit keeps earlier tiers'
   coverage and is marked degraded; the gateway refuses (503) to forward a
   degraded request. A missing cassette entry, an open circuit breaker, an
   exhausted fallback — all raise, none return "no findings".
3. **Secrets are destroyed, identifiers are pseudonymised.** Decided by the
   entity spec (`entities.py`), never by the call site. The vault refuses to
   store a secret; `pseudonym.pseudonym()` raises on one.

Corollaries that follow from them:

- Tier 3's output is untrusted: every finding must be a literal, byte-identical
  quote from the residue or it is discarded. Never accept model-reported
  offsets.
- No default tier 3 backend. A paid, network-calling tier must never run by
  accident.
- The exact-match segment cache must never become a semantic cache: two lines
  that differ only in the name they carry must never share a result.
- The decision log records the substitute, never the original value.

## The no-real-data rule

No real customer data has ever passed through this repository, and nothing may
change that:

- `templates/` holds log-line skeletons with typed placeholders only. To add
  structure from real bundles, follow "Working from real bundles safely" in the
  README: extract placeholder templates where the data already lives, review
  them there, bring only the skeletons out.
- Committed cassettes (`cassettes/*.jsonl`) contain prompts and responses over
  **synthetic** corpus text only. Before committing a new cassette, read it.
- Never commit: `out/` (reports, vaults, mappings, `feedback.jsonl`),
  `hider.local.json`, site profiles (`*.profile.json`), real portal URLs or
  vendor hostnames. All are gitignored; keep them that way.
- A site profile can only ADD patterns and a broken one is a startup error.
  Do not make either configurable.

## Build, test, gate

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest                     # the whole suite must pass, always
.venv/bin/python -m hider eval                 # recall/precision gates; non-zero exit = fail
.venv/bin/python -m hider eval --tier3 openai --cassette cassettes/tier3-injection-run1.jsonl \
    --tier2 none                               # injection gate, replays offline, no key needed
.venv/bin/python -m hider utility --backend anthropic \
    --cassette cassettes/utility-haiku-4-5-run1.jsonl   # utility gate, also offline
```

Rules of the measurement culture, which is the project's actual product:

- **No change to a shipped tier lands without a number.** If you improve a
  recognizer, the eval shows the delta. If you add a tier 3 behaviour, record
  a cassette once and commit it so the number replays without a key.
- **Known gaps are declared, not averaged away.** An adversarial case that
  tier 1 is not expected to catch carries `expect_tier1=False` and a written
  owner in `adversarial.py`. Two known gaps are deliberately unfixed so they
  stay visible; do not "fix" them casually.
- **Precision is reported next to recall.** Over-redaction is the failure mode
  that makes engineers bypass the tool; the clean-lines false-redaction rate
  must stay at zero.
- **Provenance travels with numbers.** Cassettes start with a header naming
  prompt version (`llm_tier.PROMPT_VERSION`, a hash of the instruction text),
  model and backend; `metrics.json` and `utility.json` carry the same. If you
  change the tier 3 or utility instructions, the hash changes, old cassettes
  stop matching by design, and you must re-record — never paper over that.

## Map of the code

| Area | Files | Notes |
|---|---|---|
| Contract | `entities.py` | 18 entity types: formation, owning tier, destroy-vs-pseudonymise. Written before any recognizer; change it first, not last. |
| Tier 1 | `recognizers.py`, `profiles.py` | Regex + suppression rules. Every fix here came from a measured false positive/negative; add a regression test with yours. |
| Tier 2 | `classifier.py` (default), `ner.py` (spaCy) | One interface, two backends. The classifier's training vocabulary must stay disjoint from the eval corpus vocabulary (there is a test). |
| Tier 3 | `llm_tier.py`, `llm_backend.py` | Prompt assembly, strict parsing, literal verification, batching, segment cache / backends, system-role split, retries, circuit breaker, fallback, usage metering, cassettes. |
| Engine | `pipeline.py`, `pseudonym.py` | Span algebra, monotonicity, fail-closed, the vault. |
| Gateway | `proxy.py` | Redact → sweep known vault values → forward → detokenise (buffered or streamed with hold-back) → one log row per request; counters on `/healthz`. Standard library only — do not add a web framework. |
| Measurement | `generator.py`, `markup.py`, `adversarial.py`, `evaluate.py`, `utility.py`, `report.py` | Ground truth comes from markers, never hand labels. |
| JSON / UI / bridge | `jsonscrub.py`, `webserver.py`, `csvmerge.py`, `research.py`, `feedback.py`, `localcfg.py` | Loopback-only UI; restricted Claude Code runs; in-app redaction feedback. |

Tests mirror modules (`tests/test_<module>.py`). Style: module docstrings
explain *why* and state the contract; comments state constraints the code
cannot show; measured claims carry their numbers.

## How to extend, safely

- **New entity type**: spec in `entities.py` (formation, tier, handling,
  label prefix) → recognizer or classifier coverage → generator template
  usage → eval shows it → adversarial case if it has a hostile shape.
- **New tier 3 backend**: implement the `Backend` protocol in
  `llm_backend.py` (one method: prompt string → completion string, raise
  `BackendError` on any failure). Wire it into `cli._real_backend`. Give it
  the usage meter. Record a cassette for the injection and utility runs.
- **New gateway behaviour**: it must be covered in `tests/test_proxy.py` from
  *both* sides of the boundary (what upstream saw, what the client got), the
  way every existing invariant is.

## Roadmap (as of 2026-10-26)

A larger injection-payload set and a second recorded model for tier 3; a
harder utility question set with reasoning questions; an async bundle-ingest
flow that batches tier 3 across lines; turning real feedback entries into
adversarial cases. See the README's Roadmap section.

## Feedback

Two channels, two purposes — see CONTRIBUTING.md for details:

- **Redaction mistakes on your own data**: the "Report a mistake" form in the
  web UI (`python -m hider serve`) or `hider/feedback.py`. Stays on your
  machine (`out/feedback.jsonl`); never attach the raw values to an issue.
- **Bugs, ideas, questions about the project**: GitHub issues at
  <https://github.com/NeverTheSame/Hider/issues>. Reproduce with synthetic
  data (`python -m hider generate`) before filing; never paste real log data.
