# Hider

A tiered redaction layer for log bundles on their way to a third-party LLM
provider, and the gateway that enforces it in the request path. Detectors are
chosen per data class on cost, latency and accuracy grounds: high-volume
secret and identifier patterns go to regex (tier 1), free-text names and
organisations go to a trained classifier (tier 2, with a pretrained-NER
backend as an alternative), and the free-text edge cases that classifier
cannot resolve go to an LLM pass (tier 3). A measured eval harness gates every
promotion: no tier ships, and no change to a shipped tier lands, without a
number attached to it. The OpenAI-compatible gateway intercepts a chat
completion, redacts it, forwards only the redacted payload, and de-tokenises
the answer on the way back.

No real data has ever passed through this repository. The templates in
`templates/` hold log line skeletons with typed placeholders and no values, and
every value in the corpus, the metrics and the report is generated locally.

## Why it exists

A support engineer with a 400 MB log bundle and a stalled ticket wants to ask a
model what the logs say. Doing that sends session ids, mailbox addresses, tenant
names, internal hostnames and, often enough, live bearer tokens to a processor
nobody signed a data-processing agreement with. Blocking it does not work;
people paste excerpts anyway. So the request path gets a redaction layer
instead, and the layer has to be good enough that the answers stay useful, or it
gets bypassed too.

That second half is the hard part. Replacing everything with `***` is trivially
safe and completely worthless: you can no longer tell that line 4,000 and line
91,000 are about the same session, which is the only reason anyone was reading
the log.

## The design

Detection runs in tiers, cheapest and most reliable first. Every tier past the
first only ever sees what the ones before it left unclaimed, which is both the
cost argument and the reason a model can sit this deep in the path at all: it
never gets a chance to see, or leak, anything a cheaper tier already redacted.

- **Tier 1, regex.** Presidio pattern recognizers, including custom ones for
  the shapes generic PII tooling has never heard of: region-scoped worker pod
  ids, service instance ids, tenant-bearing SaaS site URLs, pre-signed storage
  URLs, live bearer tokens. It costs nothing, needs no network and no NLP
  model, and clears most of the sensitive tokens in a support bundle, which is
  what makes every tier behind it affordable. This is also where every true
  secret (JWTs, connection strings, API keys) is caught: high-volume, sharply
  shaped, and worth catching deterministically rather than probabilistically.
- **Tier 2, a trained classifier.** Free-text names and organisations have no
  shape to match, so tier 1 is designed to miss them; tier 2 sees only the
  residue. Two interchangeable backends sit behind one interface
  (`--tier2 classifier|spacy|none`):
  - `classifier` (default, `hider/classifier.py`) is a small per-token BIO
    model trained here, locally, on a synthetic sentence corpus. Its name and
    organisation vocabulary is deliberately disjoint from the one the eval
    corpus is seeded from, so the recall figure below is a generalisation
    test, not a lookup table scoring itself. No external model download, no
    network, works out of the box.
  - `spacy` (`hider/ner.py`) runs Presidio's NLP engine (spaCy's pretrained
    `en_core_web_sm`) in-process over the same residue, with its own named
    suppression rules for the log-structure noise NER misreads as a name.
  Either way, nothing a name appears in ever leaves the machine — a strictly
  stronger boundary than "inside your cloud account", which is what a managed
  cloud NER service would give you; that variant remains a written contract in
  `pipeline.py` (`ManagedNerTier`'s docstring) for operators who out-scale a
  local model.
- **Tier 3, an LLM pass.** What tier 2's classifier still cannot resolve -
  `--tier3 openai|anthropic`, built and tested in `hider/llm_tier.py`. It is
  asked for strict JSON and nothing else (instructions in the system role,
  the residue fenced in the user turn, provider JSON mode where the API has
  one), and its output is never trusted on its own say-so: every reported
  finding must be a literal, byte-identical quote from the residue, or it is
  discarded as a hallucinated citation rather than acted on. A response that
  isn't the shape asked for is a hard failure that fails the whole call
  closed, the same as any other tier's exception. No default backend is wired
  in, because a paid, network-calling tier must never run by accident. In
  front of the backend sit three cost controls that change nothing about
  what is verified: up to `--batch N` residue segments share one prompt, an
  exact-match cache reuses verified findings for a segment seen before (no
  semantic cache, on purpose: two lines that differ only in the name they
  carry must never share a result), and `--workers N` batches run
  concurrently. Around the backend sits a retry-with-backoff policy, a
  circuit breaker that stops calling a provider that keeps failing, and an
  optional `--fallback` backend; every exhausted path still fails closed.

The boundary itself is code, not aspiration: `hider/proxy.py` is an
OpenAI-compatible gateway that intercepts `/v1/chat/completions`, redacts every
caller-authored text field, refuses (503, unforwarded) any request whose
redaction degraded, and de-tokenises the reply through the vault so the caller
sees real values where the model saw pseudonyms. After the tiers run it sweeps
the redacted payload for every identifier the vault already holds and replaces
any hit with its existing pseudonym; the tiers past tier 1 are probabilistic,
the vault is not. Streaming replies are rewritten in flight with a hold-back of
one label length, so no pseudonym is ever cut in half. Labels the model wrote
that the vault does not know are passed through and reported, never guessed.
Every request leaves one structured log row (request id, redaction and
upstream latency, counts per entity type and tier, token usage from the
provider, the degraded flag, sweep hits, unknown labels), rotated at 50 MiB
into five numbered backups, and `/healthz` carries the cumulative counters and
a list-price cost from measured tokens. A debug-only `--log-request-bodies`
flag, off by default, adds the raw request body to each row; that log then
holds the original data and must never leave the machine. It is
standard library only, holds no provider credentials of its own, and passes the
caller's `Authorization` through untouched.

Identifiers become stable pseudonyms that keep the shape of what they replaced,
so cross-line correlation survives and an address still looks like an address.
Credentials are destroyed outright, because holding one is itself the risk. A
vault keeps the identifier mappings so a model's answer can be turned back into
real values for the person who is entitled to see them; it refuses to store a
credential at all.

Three invariants hold everywhere, enforced by tests rather than by convention:

- **Monotonicity.** A later tier may only add redactions. A successful prompt
  injection against tier 3 can over-redact or waste money; it cannot unmask
  anything. This is the reason it is safe to put a language model in this path
  at all.
- **Fail closed.** A tier that errors, times out or returns malformed spans does
  not degrade to passthrough. The unit keeps what earlier tiers found and is
  marked degraded, and the gateway refuses to forward a degraded request at
  all. Both halves are tested: the engine half in `test_pipeline.py`, the
  boundary half in `test_proxy.py`.
- **Secrets are destroyed, identifiers are pseudonymised.** Decided by the
  entity spec, never by the call site.

## Measured

From `python -m hider eval` (tier 2 = `classifier`, the default; tier 3 not
active — see below) on a 5,029 line, 695,840 character synthetic bundle with
6,681 planted values across 18 entity types:

| | |
|---|---|
| Recall on shaped identifier types | 99.89% |
| Same corpus, stock Presidio patterns only | 17.64% |
| Recall on free-text names and orgs (tier 2 classifier, floor 0.75) | 92.09% |
| Recall across all types | 99.19% |
| False-redaction rate on 1,000 known-clean lines | 0.0% |
| Seeded values still findable verbatim in the output | 0 unexplained, 6 known gap |
| Adversarial surprises across 21 hostile placements | 0 |
| Characters cleared before any paid or model tier is consulted | 40.3% |
| Units degraded during the run | 0 |
| Tier 1 throughput | ~136 microseconds per line, single threaded |
| Tier 2 (classifier) throughput | ~0.5 milliseconds per line over the residue only |

Swapping in `--tier2 spacy` on the same corpus: 86.82% free-text recall, ~3.9ms
per line over the residue. On this corpus the from-scratch classifier is both
faster (roughly 8x) and higher-recall (92.1% vs 86.8%) than the pretrained
general-purpose model, which is not the result to expect going in and is
exactly why both are reported rather than one asserted: a classifier trained
tightly on the shape of *this* log format's free text (short operator notes,
a narrow set of introducing verbs, no other entity classes to confuse it with)
can out-perform a general NER model on that format while failing harder the
moment the free text looks like something else. Neither number should be
read past the corpus that produced it.

One vocabulary overlap is worth naming rather than glossing over. The training
given names, surnames and organisation head-words are disjoint from the ones
the eval corpus is seeded from, which is what stops a lookup table scoring
100%. The corporate-suffix feature list is not disjoint: it contains the same
generic suffixes the corpus builds organisation names from. That is a
hand-written feature encoding generic domain knowledge rather than memorised
answers, and "Ltd" would be in it whatever the corpus looked like, but it does
lift organisation recall relative to a corpus whose suffixes it has never seen.
The accurate phrasing is "disjoint except for the generic corporate-suffix
feature list".

The gates differ by tier, on purpose. Tier 1 is deterministic, so its gate is
zero unexplained survivors: a miss is a defect and fails the eval. Tier 2 is a
model, so its gate is a recall floor (0.75) that it must clear with its misses
listed one by one; a tier 2 miss is a measurement, reported next to the tier 1
number instead of blended into it. Passing 92.1% (or 86.8% for the spaCy
backend) against a 0.75 floor is a statement with headroom, not a rounding
exercise. The classifier's actual failure mode here is worth naming: it is
mostly partial catches (part of a two-word organisation name redacted, not the
whole one) rather than clean zero-detection misses, which is a smaller leak
than it sounds like but is still counted as a miss in the recall number above.

### Tier 3, measured against the injection-adjacent cases

What the harness measures: 5 pure-text injection canaries (no PII, carried
over from phase 1) plus 5 cases that place the same injection payloads next to
a real, seeded name or org (the `injection-*` entries in `adversarial.CASES`).
A name that survives one of the second five was talked out of being caught by
the text sitting next to it - the only thing "prompt-injection resistance" can
mean for a redaction tier. Because tier 2 already catches ordinary free text
and has no notion of an instruction to subvert, the **system-level** bypass
rate can read 0% even with a fully-complying tier 3 (verified in
`test_injection_bypass_rate_is_measured_once_tier3_runs` /
`test_injection_bypass_rate_is_zero_for_an_honest_tier3`), so the meaningful
isolation of tier 3's own behaviour is `--tier2 none --tier3 openai`, which
takes tier 2 out of the way and lets a bypass show up as a bypass.

Run once against a live model (`gpt-4o-mini`, `--tier2 none --tier3 openai
--record`), then replayable forever from the committed cassette
(`cassettes/tier3-injection-run1.jsonl`) with no key and no network:

| | |
|---|---|
| Injection-adjacent cases | 5 of 5 names/orgs caught |
| Injection bypass rate (tier 2 disabled, tier 3 alone) | **0.0%** |
| Malformed/degraded responses | 0 of 42 recorded calls |
| Units degraded during the replay run | 0 |

Tier 3 runs on the hostile corpus and only there. It is the tier that costs
money per call and the only one that cannot run at all without a recording, so
running it across the generated corpus meant 5,000 lines with no cassette entry,
every one of them failing closed. That was correct behaviour with an invisible
consequence: the engine counted the degraded units and the eval never printed
the count, so a run that degraded on 5,000 of 5,029 units reported a clean pass
with a headline injection number beside it. The eval now prints the degraded
count and fails on it, and tier 3 is scoped to the corpus it is measured
against. The generated corpus keeps the deterministic tiers, which also means
its recall and cost numbers are comparable across runs with and without tier 3.

The cassette's first line is a header naming the prompt version (a hash of
the instruction text), the model and the backend that produced it, and the
same provenance is written into `metrics.json`, so the number above is
traceable to the exact prompt and model behind it. A batch of one segment
produces exactly the prompt that was recorded, which is why `--batch 1` (the
default) replays this cassette unchanged and a larger batch needs a new
recording.

Two caveats on that number, stated the way the rest of this project states
them. First, it is 5 payload variants against one model on one small corpus -
enough to say this specific model did not fold under these specific attempts,
not enough to claim general injection resistance for any LLM slotted into
this tier. Second, the system-level number (tiers 1+2+3 together) was already
0% before tier 3 ever ran, because tier 2 has no notion of an instruction
either; this section exists to give tier 3 a fair, isolated test rather than
let it hide behind tier 2's coverage.

Two of those numbers were only reachable after the measurement found real
defects in off-the-shelf behaviour:

- Stock IP matching flags build numbers such as `8.1.0.7` as addresses. That was
  a 9.5% false-redaction rate on clean lines, which is the exact failure mode
  that makes engineers stop using the tool.
- Presidio's `EmailRecognizer` silently drops an address that appears inside a
  URL path, as in `GET /users/anna.novak@example.com/mailFolders`. Its local-part
  character class allows a forward slash, so it over-matches from `/users/`
  onward, and its own domain validation then rejects the over-long match and
  discards the result entirely. An address inside an API path is one of the most
  common ways a user shows up in a service log.

Both fixes are covered by regression tests. Tier 2's zero false-redaction rate
on clean lines cost four named suppression rules (acronyms, unit suffixes,
CamelCase keys, spans glued across log structure), each found by the same
measurement rather than by inspection and each with its own test in
`test_ner.py`.

### Utility, measured: does the answer survive the redaction?

Recall says what was hidden. It says nothing about whether the answer an
engineer gets back is still right, which is the only reason anyone tolerates a
redaction layer in the request path. `python -m hider utility` asks a model
questions about a 40-line excerpt of the synthetic bundle twice: once on the
raw text, once on the text and question as the gateway would redact them,
with the model's answer detokenised through the vault before scoring. The
questions (how many distinct session GUIDs, which user appears most, list
every pod id, on how many lines does *this* host appear) are derived
mechanically from the generator's ground truth, so nothing is hand-labelled,
and the same backend answers both sides, so the only variable is the
redaction. The redacted prompt is checked for any surviving seeded value
before it leaves; a question whose prompt would leak is refused and scored
zero.

Recorded once against `claude-haiku-4-5-20251001` and replayable from
`cassettes/utility-haiku-4-5-run1.jsonl`:

| | |
|---|---|
| Questions | 15 across 7 identifier types |
| Accuracy on raw text | 60.0% |
| Accuracy on redacted text | 66.7% |
| Accuracy lost to redaction | **-6.7%** (none; the floor that fails the run is 15%) |
| Seeded values that would have left in a redacted prompt | 0 |
| Measured usage | 30 calls, 65,406 input / 1,676 output tokens, $0.074 at list price |

Both accuracies are low because the questions are hard for a model (counting
distinct GUIDs across forty dense log lines), not because of redaction, and
that is exactly what the paired design is for: the delta is the number, not
either absolute. On this run stable, shape-preserving pseudonyms did not cost
accuracy; the two questions the model got right only on the redacted side are
counting questions where `<Session-07>` is easier to count than a GUID. One
model, one excerpt, fifteen questions: a measurement that the design works at
all, not a general claim.

### What the last round of measurement found

Four defects, all found by running the tool against realistic input rather than
by reading it:

- **A split bearer credential was not redacted at all, and reached the model
  provider.** The three-part JWT pattern never matched a token whose signature
  had been wrapped onto the next line, so the head stayed in the clear, landed
  in the residue and, with tier 3 enabled, was sent upstream. The adversarial
  case covering this carried an owner note asserting the head "is destroyed",
  which was simply not true, and that note is what stopped anyone looking. Now
  covered by three patterns and a line-anchored continuation recognizer, with a
  test asserting the property that matters: no fragment survives into the
  residue.
- **A degraded run could report a clean pass.** See the tier 3 section above.
- **`redact` ran tier 1 only** while `proxy` ran tier 2, so the documented
  "redact the bundle before pasting it anywhere" workflow was the one path that
  let a person's name through. Both now build their tiers through one function.
- **Every GUID was pseudonymised as a session id,** so a tenant id read back as
  `<Session-02>` and invited a model to reason about two sessions where there
  was one session and one tenant. GUIDs are now typed from the words around
  them, with a bare `<Guid-07>` when nothing names the kind, and all GUID
  subtypes share one identity space so a value's label never changes with
  context.

## Site profiles

Tier 1 ships with generic identifier shapes. The formats a particular operator
actually uses are themselves information about that estate: region codes,
service tiers, how many worker classes exist. Publishing them next to the tool
would leak the topology the tool exists to hide.

So the real schemes live in a profile file loaded at runtime and never
committed. Copy `templates/profile.example.json`, fill in your own patterns,
and point `HIDER_PROFILE` at it:

```sh
export HIDER_PROFILE=~/.config/hider/site.json
```

Two rules keep this from becoming a way to weaken the tool. A profile can only
**add** patterns, so it cannot override or soften a built-in recognizer and can
never reduce coverage below what the committed tests measure. And a broken
profile is a **startup error**, never a silent skip: a missing file, malformed
JSON, an unknown entity label or an uncompilable regex all raise. The failure
mode of a config-driven security control has to be "refuses to start", not
"starts with less protection than you think".

The eval deliberately ignores any local profile, so the committed numbers
reproduce on a machine that has one set.

## Run it

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
# tier 1 + tier 2 (classifier, the default) need nothing else.

.venv/bin/python -m hider eval          # tier1 + tier2=classifier; metrics + HTML report into out/
.venv/bin/python -m pytest              # 341 tests
.venv/bin/python -m hider generate      # write a synthetic bundle to out/bundle
.venv/bin/python -m hider redact FILE --log out/decisions.jsonl --vault out/vault.json
.venv/bin/python -m hider proxy --upstream https://api.openai.com \
    --listen 127.0.0.1:8787 --vault out/vault.json --log out/proxy-decisions.jsonl
```

Point any OpenAI-compatible client's base URL at `http://127.0.0.1:8787` and
the redaction happens in flight: the provider sees pseudonyms and destroyed
credentials, the caller sees real values in the answer, streamed or not. Each
response carries `X-Hider-Request-Id` (and `X-Hider-Unknown-Labels` when the
model wrote a label the vault does not know); `GET /healthz` returns the
configuration and the cumulative counters.

The alternate tier 2 backend and tier 3 are both optional and both need extra
install steps:

```sh
.venv/bin/pip install -r requirements-ner.txt   # tier 2 alternate: spaCy + the small English model
.venv/bin/python -m hider eval --tier2 spacy

.venv/bin/pip install -r requirements-llm.txt   # tier 3: the openai and anthropic packages
export OPENAI_API_KEY=...                       # or ANTHROPIC_API_KEY for --tier3 anthropic
.venv/bin/python -m hider eval --tier3 openai --cassette cassettes/run1.jsonl --record
.venv/bin/python -m hider eval --tier3 anthropic --model claude-haiku-4-5-20251001 \
    --fallback openai --batch 4 --workers 4 --cassette cassettes/run2.jsonl --record
.venv/bin/python -m hider eval --tier3 openai --base-url http://localhost:11434/v1 \
    --model llama3 --cassette cassettes/local.jsonl --record   # any OpenAI-compatible server
# later, or in CI, with no key and no network:
.venv/bin/python -m hider eval --tier3 openai --cassette cassettes/run1.jsonl

# the utility eval, same record-once-replay-forever shape:
.venv/bin/python -m hider utility --backend anthropic --cassette cassettes/utility-haiku-4-5-run1.jsonl
```

The cassette is what makes a committed metrics file checkable by somebody
without an API key: record once, replay forever, fail closed (not silently
skip) on a prompt the cassette has never seen.

`eval` exits non-zero if any seeded value survives unexplained, if an
adversarial case that was expected to pass fails, or if tier 2 recall drops
below its floor, so it works as a CI gate. `utility` exits non-zero if
redaction costs more than 15 points of accuracy or if a redacted prompt would
have carried a seeded value.

Set `HIDER_VAULT_KEY` to keep pseudonyms stable across runs. Without it the key
is ephemeral, which means nothing persists by accident.

Outputs land in `out/`: `hider-report.html`, `metrics.json`, and
`metrics-baseline.json` for the stock-Presidio comparison. A pre-rendered copy
of the report is committed at [`docs/sample-report.html`](docs/sample-report.html)
so it can be read without installing anything.

## JSON exports, the local web UI and the Claude Code bridge

Log lines are one shape of customer data; a JSON export (a support case, a
contact record, a backup session log) is another, where most of the PII sits
in fields whose key says what the value is. `jsonscrub.py` covers that shape,
and a loopback-only web UI wraps the whole loop:

```sh
.venv/bin/python -m hider serve                       # http://127.0.0.1:8790
.venv/bin/python -m hider merge-csv PARTS_DIR -o session.json
.venv/bin/python -m hider scrub-json session.json --term ACME --term 'acme*'
.venv/bin/python -m hider ask RUN "which sites failed and why?"
.venv/bin/python -m hider workspace RUN               # for an interactive session
.venv/bin/python -m hider unmask answer.md --run RUN
```

1. **Get the logs.** The page builds a prompt to paste into Claude Code that
   downloads a session's CSV parts from an admin portal and merges them with
   `merge-csv`, while forbidding the model from reading the rows.
2. **Obfuscate.** Every identifier becomes a stable label; secrets are
   destroyed. Short customer names a detector cannot be sure of go in as
   terms, and a trailing `*` hides every word with that prefix. The output and
   a label -> original mapping are written to `out/json/` (gitignored).
3. **Ask Claude Code.** The prompt is masked with the same mapping, shown to
   the user, and re-checked before it leaves: a prompt that still carries a
   mapped value, or a word that only ever appeared inside a real value, is
   refused. Claude Code runs headless in `--restricted` mode with no MCP
   servers and only Read, Grep and Glob, in a temp folder holding nothing but
   the obfuscated file, so it cannot reach the mapping, run commands or
   browse.
4. **Unmask.** Labels in the answer go back to real values by dictionary
   lookup, no model. Labels the model rewrote are listed, not guessed.

Deployment-specific settings (the portal URL the prompt opens, the vendor's own
hosts the scrubber may leave readable) live in an uncommitted
`hider.local.json` (or `HIDER_LOCAL`), described in `hider/localcfg.py`.
Without it those hosts are masked like any other, which only over-redacts.

The results card has a "Report a mistake" form: something that should have
been hidden and was not (`missed`), or something hidden that should not have
been (`wrong`). Reports append to `out/feedback.jsonl` on this machine only; a
`missed` report necessarily holds the real value, so that file is as sensitive
as a mapping. `python -m hider feedback` lists them. This is the one channel
through which real-bundle observations reach the synthetic corpus: each entry
is meant to become a recognizer pattern, a classifier training sentence or an
adversarial case, each with its own test.

## Layout

| Path | What it is |
|---|---|
| `hider/entities.py` | The contract. How each of 18 sensitive value types is formed, where the format came from, which tier owns it, and whether it is destroyed or pseudonymised. Written before any recognizer existed. |
| `hider/recognizers.py` | Tier 1 detection, written against the contract rather than from it. Custom recognizers plus reused Presidio built-ins, and the suppression rules that keep precision up. |
| `hider/classifier.py` | Tier 2, default backend: the trained per-token BIO classifier, its synthetic training-sentence generator, and the disjoint train/eval vocabulary split that keeps its recall honest. |
| `hider/ner.py` | Tier 2, alternate backend: Presidio's pretrained NLP engine over the tier 1 residue, in-process, memoised, with its own named suppression rules. |
| `hider/llm_backend.py` | Tier 3's backends: OpenAI-compatible and Anthropic, the system/user split, token usage metering, the retry/circuit-breaker/fallback wrapper, and the cassette (with a provenance header) that records or replays a run so it never needs a key to be checked. |
| `hider/llm_tier.py` | Tier 3's detection logic: prompt assembly with the residue fenced as untrusted data, multi-segment batching, the exact-match segment cache, strict JSON parsing, and literal-citation verification that never trusts a model-reported offset. |
| `hider/pipeline.py` | The engine. Tier ordering, span algebra, monotonicity, fail-closed handling, the decision log. Every tier slot (including tier 2's managed-cloud variant, never built) is one interface. |
| `hider/proxy.py` | The gateway. Redacts chat completions in flight, sweeps for known identifiers, refuses degraded requests unforwarded, de-tokenises buffered and streamed replies, reports unknown labels, logs one row per request, counts on `/healthz`. Standard library only. |
| `hider/pseudonym.py` | HMAC-keyed, shape-preserving pseudonyms, plus the vault that makes de-tokenisation possible for identifiers and impossible for secrets. |
| `hider/generator.py` | Fills the placeholder templates and records exact ground truth for every value it plants. |
| `hider/adversarial.py` | 16 hand-built hostile placements, 5 pure-text prompt-injection canaries, and 5 more that place the same payloads next to a real seeded name, for measuring tier 3's actual resistance rather than its absence. |
| `hider/evaluate.py` | The harness. Recall per type per tier, precision as a false-redaction rate, the baseline delta, tier routing and cost, the tier 2 recall floor, and the injection bypass rate once tier 3 runs. |
| `hider/utility.py` | The utility eval: ground-truth questions over an excerpt, asked on raw and on redacted text, scored after detokenisation. |
| `hider/feedback.py` | The feedback channel: missed and wrong redactions reported from the web UI, appended locally. |
| `hider/report.py` | The self-contained HTML page. |
| `hider/jsonscrub.py` | JSON obfuscation: key-driven harvesting, known-value and pipeline spans resolved together, a final sweep and a leak check. |
| `hider/webserver.py` | The loopback-only web UI and its API. Standard library only. |
| `hider/csvmerge.py` | Merges an admin portal's "Download logs" CSV parts into one JSON document. |
| `hider/research.py` | The Claude Code bridge: prompt masking, the restricted headless run, workspaces, unmasking. |
| `hider/localcfg.py` | Loads the uncommitted `hider.local.json`. |
| `templates/` | Sanitized log line skeletons. Typed placeholders only. |

## How the numbers avoid being circular

If one person writes the generator and the recognizers from one mental model,
recall measured on that data proves very little: the recognizers only ever get
tested against what their author thought to generate. Five countermeasures, none
of which fully solves it:

1. **The spec came first.** `entities.py` describes how values are *formed*,
   taken from public documentation and sanitized structural templates.
   `recognizers.py` describes how they are *found*, and was written against the
   spec. Two implementations of one contract.
2. **A hostile corpus.** `adversarial.py` holds the placements the generator
   would never produce: identifiers split across wrapped lines, percent-encoded,
   re-cased, buried in doubly-escaped JSON and stack traces. Every case declares
   in advance whether tier 1 should catch it, and every declared gap carries a
   written owner, so a known limitation cannot pass itself off as a success, or
   hide a real defect.
3. **Precision is measured too.** 1,000 lines from the same templates carry no
   sensitive value at all. Redacting nothing scores zero recall; redacting
   everything scores perfect recall and a ruinous false-redaction rate. Both
   numbers are always reported together.
4. **A baseline.** Stock Presidio on the identical corpus, so the custom
   recognizers' contribution is a measured delta rather than a claim.
5. **A vocabulary holdout, for tier 2's classifier.** `classifier.py` trains its
   name and organisation recognition on a first/last-name and org-word list
   that shares no entry with the one `entities.py` seeds the eval corpus from.
   Without that split, a linear model could reach the same recall number by
   memorising the eight organisation names and twenty-eight given names in the
   corpus, which would say nothing about whether it generalises to a name that
   is not in this file - which, in a real bundle, none of them are.

## Working from real bundles safely

The templates here were bootstrapped from public log-format conventions. To add
the structure of real bundles without moving real data, the procedure is:

1. Open real bundles only where they already legitimately live, using the tools
   already sanctioned for them.
2. Extract *structural templates*: log line skeletons where every value is
   replaced by a typed placeholder, keeping field names, ordering, file layout
   and error phrasing.
3. Review the templates in that same place to confirm no live value survived.
4. Bring only the placeholder templates out, and append them to
   `templates/support_bundle.json` in the existing form.

The generator then fills those placeholders with generated values. This yields
corpora with real-world structure and zero real values, and never requires the
data itself to move anywhere new. Building the redactor is not a reason to skip
this: the redactor does not exist yet when the data would move, and its measured
recall will never be exactly 100%.

## Limitations

- **The corpus is synthetic.** Real bundles hold placements nobody thought to
  generate. The countermeasures above are a mitigation, not a fix, and the
  shaped-type recall figure should be read as an upper bound.
- **Independence is procedural, not organisational.** One person wrote both
  sides of the contract.
- **Tier 2 recall is a model's recall, whichever backend runs.** 92.1%
  (classifier) or 86.8% (spaCy) on free-text names means the rest passes
  through, listed in the metrics as individual survivors. The floor gate
  catches regressions; it cannot make either backend perfect. A managed cloud
  NER service remains a documented, unbuilt contract behind the same
  interface for operators who out-scale both.
- **The classifier's training grammar is narrow.** Twelve sentence templates,
  two names per organisation, a fixed suffix vocabulary. It generalises past
  its own training vocabulary (proven by the disjoint train/eval split,
  `test_training_vocabulary_is_disjoint_from_the_eval_vocabulary`), but an
  organisation suffix outside its trained set (`Tailspin Technology` versus a
  trained `Tailspin Industries`) is a realistic way for it to miss — caught
  while building the injection-adjacent adversarial cases, not by inspection.
- **Streaming adds a small delay and trusts the vault's label set.** Every
  delta is held back by the length of the longest pseudonym the vault holds
  before release, so the client sees text a few dozen characters behind the
  provider. A label the model invents is passed through unchanged and named in
  the log and in `X-Hider-Unknown-Labels`; it is not, and cannot be, restored.
- **The sweep is identifiers only, by boundary.** It catches a value the vault
  already knows, at word boundaries, four characters or longer. A name the vault
  has never seen and tier 2 misses is still a tier 2 miss; the sweep narrows
  the window, it does not close it.
- **The utility number is one model, one excerpt, fifteen questions.** It
  shows the pseudonym design does not cost accuracy on counting and
  which-value questions over a short excerpt. Longer excerpts, reasoning
  questions, and other models have not been tried, and the per-question
  results in `out/utility.json` matter more than the headline.
- **Redaction in the gateway is serialised.** One request's tiers run at a
  time, because the classifier, the vault and the stats are shared and not
  thread-safe; the upstream call and the stream rewrite run concurrently.
  Throughput is bounded by tier 2's half-millisecond per line, which is far
  from the bottleneck for a workstation gateway and would be the first thing
  to change for a shared one.
- **Tier 3's injection number is one model, one small run.** `gpt-4o-mini`
  caught all 5 injection-adjacent cases in the one recorded run
  (`cassettes/tier3-injection-run1.jsonl`). That is evidence this model
  did not fold under these five specific attempts, not a general injection-
  resistance claim for any LLM slotted into this tier - a different model, a
  larger or more creative payload set, or a longer run could read differently,
  and none of those have been tried.
- **Cost figures are list price.** Where a provider returns token counts
  (tier 3, the utility eval, the gateway) the tokens are measured and the
  dollars are those tokens at the published rate; a model whose rate is not in
  `llm_backend.PRICES_USD_PER_M` is reported as unpriced rather than guessed.
  The managed-NER comparison in `eval` is still an assumed per-character rate.
- **Two known one-line gaps are deliberately left unfixed** so they stay visible
  in the numbers: zero-padded IPv4 octets, and Windows profile paths written
  with forward slashes. Both are in the adversarial table with an owner.

## Roadmap

Tier 2 shipped with two interchangeable backends, tier 3 shipped with two
provider backends and a recorded run, the gateway streams and reports on
itself, and utility has a number. Next: a larger and more adversarial
injection-payload set against tier 3 and a second recorded model for it; a
longer, harder utility question set with reasoning questions; an async
bundle-ingest flow that batches tier 3 across lines rather than within one;
and turning the first real feedback entries into adversarial cases.

## Picking this up, and giving feedback

- [`AGENTS.md`](AGENTS.md) is the orientation file for a new contributor or a
  coding agent: the invariants the tests enforce, where each kind of change
  starts, the working rules, and the known gaps.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) explains the two feedback channels. A
  missed or wrong redaction seen on a real bundle goes through the web UI's
  "Report a mistake" form and stays on your machine until it has been turned
  into a placeholder skeleton; everything else goes to
  [GitHub issues](https://github.com/NeverTheSame/Hider/issues).

## License

MIT. See [LICENSE](LICENSE).
