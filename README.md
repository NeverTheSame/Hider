# Hider

A tiered redaction layer for log bundles on their way to a third-party LLM
provider. Phase 1 is built and measured: the deterministic tier, the synthetic
corpus, the eval harness and a self-contained before/after report.

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

Detection runs in tiers, cheapest first.

- **Tier 1** is Presidio pattern recognizers, including custom ones for the
  shapes that generic PII tooling has never heard of: region-scoped worker pod
  ids, service instance ids, tenant-bearing SaaS site URLs, pre-signed storage
  URLs. It costs nothing, needs no network and no NLP model, and clears most of
  the sensitive tokens, which is what makes the paid tiers affordable.
- **Tier 2** (a managed PII-detection service, phase 2) sees only the residue
  tier 1 could not clear, and runs inside the operator's own cloud account. The
  boundary being defended is the third-party model endpoint, not the cloud.
- **Tier 3** (a small self-hosted model, phase 3) is a span-labelling classifier
  over what is left, with no tools and add-only authority.

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
  marked degraded, so the caller can refuse to forward it.
- **Secrets are destroyed, identifiers are pseudonymised.** Decided by the
  entity spec, never by the call site.

## Measured, phase 1

From `python -m hider eval` on a 5,024 line, 695,117 character synthetic bundle
with 6,676 planted values across 18 entity types:

| | |
|---|---|
| Recall on shaped identifier types | 99.9% |
| Same corpus, stock Presidio patterns only | 17.6% |
| Recall across all types, free text included | 91.4% |
| False-redaction rate on 1,000 known-clean lines | 0.0% |
| Seeded values still findable verbatim in the output | 0 unexplained, 213 known gap |
| Adversarial surprises across 16 hostile placements | 0 |
| Characters cleared before any paid tier | 39.0% |
| Tier 1 throughput | 108 microseconds per line, about 1.3 M characters per second, single threaded |

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

Both fixes are covered by regression tests.

## Run it

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python -m hider eval          # metrics + HTML report into out/
.venv/bin/python -m pytest              # 102 tests
.venv/bin/python -m hider generate      # write a synthetic bundle to out/bundle
.venv/bin/python -m hider redact FILE --log out/decisions.jsonl --vault out/vault.json
```

`eval` exits non-zero if any seeded value survives unexplained, or if an
adversarial case that was expected to pass fails, so it works as a CI gate.

Set `HIDER_VAULT_KEY` to keep pseudonyms stable across runs. Without it the key
is ephemeral, which means nothing persists by accident.

Outputs land in `out/`: `hider-report.html`, `metrics.json`, and
`metrics-baseline.json` for the stock-Presidio comparison. A pre-rendered copy
of the report is committed at [`docs/sample-report.html`](docs/sample-report.html)
so it can be read without installing anything.

## Layout

| Path | What it is |
|---|---|
| `hider/entities.py` | The contract. How each of 18 sensitive value types is formed, where the format came from, which tier owns it, and whether it is destroyed or pseudonymised. Written before any recognizer existed. |
| `hider/recognizers.py` | Tier 1 detection, written against the contract rather than from it. Custom recognizers plus reused Presidio built-ins, and the suppression rules that keep precision up. |
| `hider/pipeline.py` | The engine. Tier ordering, span algebra, monotonicity, fail-closed handling, the decision log. Tiers 2 and 3 are contracts with their behaviour documented and `NotImplementedError` bodies. |
| `hider/pseudonym.py` | HMAC-keyed, shape-preserving pseudonyms, plus the vault that makes de-tokenisation possible for identifiers and impossible for secrets. |
| `hider/generator.py` | Fills the placeholder templates and records exact ground truth for every value it plants. |
| `hider/adversarial.py` | 16 hand-built hostile placements plus 5 prompt-injection canaries. Each case declares in advance whether tier 1 should catch it. |
| `hider/evaluate.py` | The harness. Recall per type per tier, precision as a false-redaction rate, the baseline delta, tier routing and cost. |
| `hider/report.py` | The self-contained HTML page. |
| `templates/` | Sanitized log line skeletons. Typed placeholders only. |

## How the numbers avoid being circular

If one person writes the generator and the recognizers from one mental model,
recall measured on that data proves very little: the recognizers only ever get
tested against what their author thought to generate. Four countermeasures, none
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
- **Free-text names and organisations are not detected at all** in phase 1. That
  is 213 planted values passing straight through, and it is the whole reason a
  managed NER tier is phase 2 rather than optional.
- **Prompt-injection resistance is untested.** The canaries are in the corpus,
  but tier 1 has no instructions to subvert, so it cannot be injected and
  reporting a pass would be dishonest. That number arrives with tier 3.
- **Cost figures use an assumed list rate.** Characters offered per tier are
  measured; the dollar conversion is arithmetic on a published price, not an
  invoice.
- **Two known one-line gaps are deliberately left unfixed** so they stay visible
  in the numbers: zero-padded IPv4 octets, and Windows profile paths written
  with forward slashes. Both are in the adversarial table with an owner.

## Roadmap

Phase 2: managed PII-detection tier, with the baseline comparison extended to
it. Phase 3: residual classifier, injection canaries scored, bypass rate
reported. Phase 4: OpenAI-compatible proxy, response de-tokenisation, and an
async bundle-ingest flow for whole-bundle jobs. The tier contracts for 2 and 3
are already written down in `pipeline.py`, so the engine and the harness
accommodate them without changes.
