# Hider / PasteGuard comparison

Status: complete. Verdict first, then inventory, detection, masking, and integration, performance, stack and licence comparisons.

Source inspected: https://github.com/sgasser/pasteguard, shallow clone of
`main` at commit `d8bbb3d4fe0cd4a7f10e4ec6cf6ea0d7eb1df4ce` ("Bump version to
0.9.6", 2026-11-07), cloned to `/tmp/pasteguard-H040oA/pasteguard`. Every
path below is relative to that clone. Nothing was installed, run or built;
every statement is from reading files. Files whose names contain "secret"
were not opened (see "Not verified").

## Verdict

**Recommendation: B. Keep Hider and port specific parts.**

Why not the others. A (adopt PasteGuard) fails on the first requirement of
the job: PasteGuard detects none of the identifiers a support bundle is made
of (GUIDs, tenants, hosts, pods, paths, SIDs, logons, case numbers,
organisations; `detector/detector/entities.py` comment, "Detection" section),
and it restores credentials into the model's answer by default
(`src/masking/restorer.ts`), which Hider's contract forbids
(`hider/entities.py` `DESTROY`; `hider/pseudonym.py` `pseudonym` raises).
D (no overlap) is wrong because three secret shapes PasteGuard catches are
real gaps in Hider's destroy class, and they are one pattern each. C
(reference only) under-sells those three: they are cheaper to port than to
re-derive, and PasteGuard's tests for them (`src/secrets/detect.test.ts`,
not read) are a ready source of cases. So B, with a short list, and
everything in the masking, gateway, dashboard and container layers left where
it is.

**Most valuable item:** the three secret shapes in
`src/secrets/patterns/env-vars.ts` and `api-keys.ts` (`*_SECRET` assignments,
colon-assigned passwords, `sk_` with an underscore). They are the only
PasteGuard rules that close a gap in Hider's *destroy* class, where a miss
sends a live credential upstream and a tier 2 catch vaults it, which
`AGENTS.md` calls "worse than a miss". Effort S, no corpus change, no
cassette re-record.

**Most risky item:** GLiNER as a Hider tier 2 backend
(`detector/detector/gliner_layer.py`, `semantic_backend.py`). It brings
`torch` and `transformers` into an optional extra, a 0.99 person floor
calibrated on prose rather than logs (`gliner_layer.py` `PER_LABEL_FLOOR`),
no log-structure guards of its own, and an unmeasured false-redaction rate on
Hider's clean corpus. Its upside, multilingual names and a model that can also
answer `organization` (model card), is real but unproven for this workload.
It is listed as a PORT only because the plan below is a measurement first and
a merge only if the numbers clear Hider's gates.

Effort scale: S is under a day, M is two to five days, L is more than a
week, each including tests and an eval run.

### Component verdicts

No component qualifies for REUSE-AS-IS. Hider runs its tiers in-process in
Python with the standard library at the boundary (`AGENTS.md`); PasteGuard's
only Python is a FastAPI service bound to GLiNER (`detector/detector/app.py`),
and everything else is TypeScript on Bun (`package.json`).

| PasteGuard component | Label | Hider file it would go into | Effort | Reason |
|---|---|---|---|---|
| `src/secrets/patterns/api-keys.ts`: `sk[-_]` prefix | PORT | `hider/recognizers.py` `api_key` | S | Hider's rule is hyphen-only (`(?:sk\|ak\|vk\|pk)-`); Stripe-style `sk_live_` keys are missed. One character class. |
| `src/secrets/patterns/env-vars.ts`: `ENV_SECRET`, `ENV_PASSWORD` | PORT | new `EnvCredentialRecognizer` in `hider/recognizers.py`, registered in `custom()` | S | `*_SECRET[=:]value` is uncaught; `PASSWORD:` and `_PWD:` colon forms are uncaught (Hider's `connection_string` needs `=`). Report the value span only so the key name stays readable, label `API_KEY`, destroyed. |
| `src/secrets/patterns/env-vars.ts`: `CONNECTION_STRING` | NOT-NEEDED | | | Hider's `url_userinfo` destroys `user:pass@` for any scheme and keeps the host readable (`hider/recognizers.py`). |
| `src/secrets/patterns/tokens.ts`, `private-keys.ts` | NOT-NEEDED | | | Hider's `jwt` and `PrivateKeyBlockRecognizer` are wider (fragments, bare body lines). |
| `src/secrets/detect.ts`, `mask.ts`, `request.ts`, `patterns/{index,types,utils}.ts` | NOT-NEEDED | | | Secrets pipeline plumbing; Hider destroys rather than masks and restores. The `block` action is already Hider's default outcome. |
| `src/secrets/detect.test.ts`, `mask.test.ts` | REF-ONLY | `tests/test_recognizers.py` | S | Source of positive and negative cases for the two PORT items above. Not read in this review. |
| `src/pii/detect.ts`: allowlist (anchored regex or literal, never masked) | PORT | `hider/profiles.py` (schema), `hider/pipeline.py` `Pipeline.detect` (apply), `templates/profile.example.json` | S to M | Hider's profiles are additive only; it has no operator precision control except code changes. Must never apply to a secret type. |
| `src/pii/detect.ts`: denylist, `scan_roles`, `subtractPlaceholderOverlaps` | NOT-NEEDED | | | Profiles already add patterns; Hider scans every role on purpose; Hider's tiers never see placeholders. |
| `src/pii/mask.ts`, `request.ts`, `src/privacy/pipeline.ts` | NOT-NEEDED | | | Covered by `hider/pipeline.py`. |
| `detector/detector/deterministic.py`: `_phone` with `phone_regions` | REF-ONLY | `hider/recognizers.py` `FormattedPhoneRecognizer`, `hider/localcfg.py` | S | Hider uses Presidio's fixed eight regions; a site setting could pass `supported_regions`. Idea only, no code to take. |
| `detector/detector/deterministic.py`: IBAN, VAT, credit card, Chinese id | REF-ONLY | `hider/recognizers.py` | M | Low weight: rare in support logs (owner's call). Would add `python-stdnum` (LGPLv2+) and a new spec type, which needs a template line and a utility cassette re-record (`AGENTS.md`). |
| `detector/detector/deterministic.py`: email, IPv4, IPv6 | NOT-NEEDED | | | Hider has Presidio's recognizers plus `upn_email` and `zero_padded_ipv4`. |
| `detector/detector/merge.py`: fragment subtraction | REF-ONLY | `hider/pipeline.py` `resolve` | M | Keeping the uncovered parts of a losing span is an idea worth a test; Hider drops the whole span today. Changes span output, so it would need an eval before and after. |
| `detector/detector/entities.py` | NOT-NEEDED | | | Hider has `Span` and `overlaps` logic. |
| `detector/detector/gliner_layer.py`, `semantic_backend.py` | PORT, measurement-gated | new `hider/gliner_tier.py`, `pyproject.toml` optional extra `gliner`, `hider/cli.py` `--tier2 gliner` | L | Third tier 2 backend behind the `Tier` protocol. Apache-2.0 weights and package. Only merges if it clears the 0.75 recall floor and 0.0% false redaction. |
| `detector/detector/app.py`, `smoke.py`, `detector/pyproject.toml` | NOT-NEEDED | | | HTTP wrapper and image smoke test. |
| `detector/tests/*` | REF-ONLY | `tests/` | S | Test ideas for the deterministic rules; not read. |
| `src/masking/context.ts`, `placeholders.ts`, `service.ts`, `conflict-resolver.ts`, `restore-policy.ts`, `restorer.ts`, `stream-restorer.ts`, `types.ts` | NOT-NEEDED | | | Hider's vault, `resolve` and `HoldbackDetokenizer` have stronger properties ("Masking" section). |
| `src/masking/extractors/openai.ts`: tool-call argument restore and history re-mask | REF-ONLY | `hider/proxy.py` `detokenize_response`, `_rewrite_stream` | S | Hider restores `message.content` only. Useful if proxy clients use tools; secondary. |
| `src/masking/extractors/anthropic.ts`, `responses.ts` | REF-ONLY | `hider/proxy.py` `_collect_texts`, `_write_texts`, `detokenize_response` | M | Field and role map for Anthropic Messages and the Responses API. Secondary: Claude Code reaches Hider through its launcher and the Elasticsearch bridge, not the proxy (owner's call). |
| `src/routes/*`, `src/providers/*`, `src/protocols/*`, `src/index.ts`, `src/config.ts`, `src/middleware/*` | NOT-NEEDED | | | Bun and Hono server, provider clients, YAML config. Hider is standard library at the boundary. |
| `src/logging/*`, `src/routes/dashboard.tsx`, `src/views/*` | NOT-NEEDED | | | Request database and dashboard. Hider logs decisions to a rotated file by design. |
| `src/routes/api.ts` (`/api/mask`) | NOT-NEEDED | | | Hider's CLI `redact` and `scrub-json` cover standalone masking. |
| Route mode, `src/providers/local.ts` | NOT-NEEDED | | | Forwards unmasked data to a local model; contrary to Hider's model. |
| `benchmarks/pii-accuracy/test-data/*.yaml` | REF-ONLY | `hider/adversarial.py` | S | Multilingual sentence shapes as inspiration for adversarial cases. Copying lines verbatim needs Apache notices. |
| `benchmarks/pii-accuracy/run.ts`, `taxonomy.ts`, `types.ts` | NOT-NEEDED | | | `hider/evaluate.py` exists. |
| `config.example.yaml`, `docker/*`, `docker-compose.yml`, `.github/*`, `docs/*`, `biome.json`, `tsconfig*.json`, `bun.lock` | NOT-NEEDED | | | Deployment, CI and docs for a different stack. |

### Port plans, in dependency order

Each plan follows Hider's working rules: add the adversarial case first, run
`python -m hider eval` before and after, assert the pipeline property for
credentials (value absent from the output and from `vault.entries`), and
state any trade (`AGENTS.md` "Working rules", "Known gaps").

**P1. Secret shapes** (`api-keys.ts` `sk[-_]`; `env-vars.ts` `ENV_SECRET`,
`ENV_PASSWORD`). Effort S. **Done.** Built as written below, with three
departures, each measured: the value floor is six characters rather than
PasteGuard's eight (`Hunter6` is a real password, and most six-character
config values that are not secrets are words on the stop list); the rule
checks the value as well as the key name, because `password: required`
would otherwise be destroyed; and the near-miss negatives went into a new
fixed clean unit `adversarial.CREDENTIAL_LOOKALIKES` that `hider eval`
scores, rather than into `tests/` alone, so the cost stays measured on
every run. After: 88 adversarial cases, 0 surprises; 0 of 17 credential
lookalikes changed; clean false redaction still 0.0000; recall unchanged
at 99.75%. Two lines are destroyed on purpose and counted apart
(`CREDENTIAL_LOOKALIKE_MISSES`).

1. `hider/adversarial.py`: add `vendor-stripe-underscore` (`sk_live_` and
   `sk_test_` forms), `env-secret-assign` (`APP_SECRET=`, `JWT_SECRET:`),
   `env-password-colon` (`db_password: value`, `ADMIN_PWD : value`), each
   `expect_tier1=True`, labelled `API_KEY`. Add near-miss negatives to
   `tests/test_recognizers.py` rather than to `templates/` (a template
   change reshuffles the RNG stream): `SECRET_ROTATED=true`, a short
   `sk_` token under 20 characters, `password_policy: strict`.
2. `tests/test_recognizers.py`: recognizer-level tests, plus a
   `Pipeline.redact` test per shape asserting the value is absent from the
   output and from `vault.entries`.
3. `hider/recognizers.py`: widen `api_key` to `(?:sk|ak|vk|pk)[-_]`; add
   `EnvCredentialRecognizer(LocalRecognizer)` with one compiled regex
   `(?i)\b[A-Za-z_][A-Za-z0-9_]{0,128}(?:_SECRET|PASSWORD|_PWD)\s*[=:]\s*['"]?([^\s'"]{8,})`
   reporting group 1 only as `API_KEY`, score 0.9; register in `custom()`.
   Hider's `connection_string` keeps its `Password=` pattern; overlap goes to
   the longer span in `resolve`.
4. Eval: these shapes are not in the generated corpus, so recall is
   unchanged and the clean false-redaction figure is the gate. Corpus
   unchanged, utility cassette unaffected.
5. `README.md` Limitations: note the declared miss that remains (a secret
   value shorter than eight characters, matching PasteGuard's floor).

**P2. Allowlist in site profiles** (`src/pii/detect.ts`
`filterAllowlistedEntities`). Effort S to M. Independent of P1.

1. `tests/test_profiles.py` (or the existing profile tests): a literal
   allowlist entry removes a tier 1 and a tier 2 span whose text equals it;
   a regex entry matches only when anchored to the whole span; an entry
   never removes a span whose type is in `entities.SECRET_TYPES`; an
   absent profile changes nothing (the eval runs with
   `use_active_profile=False`, so committed numbers stay reproducible).
2. `hider/profiles.py`: add `allow: list[{"pattern", "regex"}]` to
   `SiteProfile` and the loader; `templates/profile.example.json`: one
   example entry with an invented value.
3. `hider/pipeline.py` `Pipeline.detect`: after `_sane` and the score
   floor, drop spans matching the active profile's allowlist unless
   `_is_secret`. Removing a tier's own spans before accumulation keeps the
   monotonicity check intact.
4. Eval unchanged by construction (profile off in eval). Corpus unchanged,
   cassette unaffected.

**P3. GLiNER as an optional tier 2 backend** (`gliner_layer.py`,
`semantic_backend.py`). Effort L. Do after P1 and P2; merge only on numbers.

1. `pyproject.toml`: optional extra `gliner = ["gliner>=0.2.27,<0.3"]`
   (pulls `torch`, `transformers`); `requirements-gliner.txt` with the CPU
   torch index note from `docker/Dockerfile`. Nothing imported at module
   load in the core path.
2. `tests/test_gliner_tier.py`: skipped when the package is absent (as the
   spaCy tests are); label mapping `person` to `PERSON`, `organization` to
   `ORGANIZATION`; `location` and `address` not requested, so Hider's
   "no locations" design holds; the log-structure guards applied
   (`trim_log_vocabulary`, `in_dotted_chain`,
   `in_structural_path_segment`, backslash rule) exactly as `hider/ner.py`
   applies them.
3. New `hider/gliner_tier.py`: load once under a lock from
   `HIDER_GLINER_MODEL` (default `urchade/gliner_multi_pii-v1`), windowing
   as in `gliner_layer.py` `_windows`, per-label floors as settings, flat
   span score like `ner.SPAN_SCORE`, residue-only, exceptions propagate to
   the pipeline's fail-closed path.
4. `hider/cli.py` `_add_tier2`: `--tier2 gliner`. `README.md`: report the
   measured pair next to `classifier` and `spacy`, with the model name and
   floors, and the licence (Apache-2.0 weights and package, model card and
   PyPI record).
5. Gate: `python -m hider eval --tier2 gliner` must clear the 0.75 free-text
   recall floor with misses listed, and the 1,000 clean lines must stay at
   0.0% false redaction, including the dotted-namespace and log-vocabulary
   grids. If it fails the clean gate, keep it as a documented experiment,
   not a backend.
6. Corpus and default outputs unchanged, so the utility cassette is
   unaffected unless the default backend is switched, which this plan does
   not propose.

### Top three, in order

1. P1, secret shapes. Closes three destroy-class gaps for under a day.
2. P2, allowlist. Gives operators a precision control without code changes.
3. P3, GLiNER backend as a measured experiment. Potential multilingual and
   organisation gains; merge only on Hider's gates.

### Settled since the previous sections

- `urchade/gliner_multi_pii-v1` is Apache-2.0 (model card front matter),
  fine-tuned from `urchade/gliner_multi-v2.1` on
  `urchade/synthetic-pii-ner-mistral-v1`, languages en, fr, de, es, pt, it.
- `gliner` 0.2.30 is Apache-2.0; `python-stdnum` 2.2 is LGPLv2+ (PyPI
  records). Section 4 is updated.

## Pasteguard inventory

### What it is

PasteGuard is a privacy proxy that sits between an application and an LLM
provider, masks personal data and credentials in the request, forwards the
masked request, and restores the placeholders in the response
(`README.md`, "What PasteGuard Protects"; `AGENTS.md`, "Project"). Licence:
Apache 2.0, "Copyright 2026 Stefan Gasser" (`LICENSE` line 178;
`package.json` `"license": "Apache-2.0"`). Version 0.9.6 (`package.json`).

### Components

Column meanings. "Standalone" asks whether the component can be used without
running the PasteGuard proxy server (`src/index.ts`). "Yes" means the file's
imports are confined to its own module or to type-only imports, as read in
the source. "No" means it is the server or calls server-only state such as
`getConfig()`.

| Path | What it does | Language, runtime | Main dependencies | Standalone |
|---|---|---|---|---|
| `src/index.ts` | Hono server entry: mounts the OpenAI, Anthropic, Codex, `/api`, health, info and dashboard routes, waits for the detector's `/health` and exits if it never answers, starts the daily log cleanup. | TypeScript, Bun | `hono` | No, this is the server. |
| `src/config.ts` | Loads `config.yaml` (falls back to `config.example.yaml`), substitutes `${VAR}` and `${VAR:-default}`, validates with Zod; defines all config types. Default `mode` is `route` in the schema. Ships a default allowlist entry for the Claude Code system prompt sentence. | TypeScript, Bun | `zod`, `yaml`, `node:fs` | Partly: importable, but reads config files from the working directory and is a process-wide singleton (`getConfig`). |
| `src/masking/types.ts` | Defines `TextSpan`, `MaskedSpan` and the `RequestExtractor<TRequest, TResponse>` interface (extract texts, apply masked texts, unmask a response). | TypeScript | none | Yes. |
| `src/masking/placeholders.ts` | Placeholder format `[[TYPE_N]]` for PII and `[[TYPE_N]]` for secrets, and `findPartialPlaceholderStart` for safe splitting of streamed text that may end in a half-emitted `[[`. | TypeScript | none | Yes. |
| `src/masking/context.ts` | `PlaceholderContext` (placeholder to value, value to placeholder, per-type counters); `replaceWithPlaceholders` (same value gets the same placeholder within a context); `restorePlaceholders` (longest placeholder first, string split/join); stream chunk buffering. | TypeScript | `./placeholders`, `./conflict-resolver` (types) | Yes. |
| `src/masking/conflict-resolver.ts` | Overlap resolution ported from Presidio's anonymizer: merge overlapping spans of the same type, then keep highest score, then longest, then earliest. `resolveOverlaps` for unscored spans keeps the longer. | TypeScript | none | Yes. |
| `src/masking/service.ts` | `maskSpans` runs replacement over an array of `TextSpan`s with per-span entity lists and a shared context; `unmaskStreamChunk` and `flushMaskingBuffer` wrap the stream buffering. | TypeScript | `./context`, `./types` | Yes. |
| `src/masking/restorer.ts` | `restoreResponse`: applies the PII context, then the secrets context, through an extractor's `unmaskResponse`. | TypeScript | type import of `MaskingConfig` from `../config` | Yes (type-only import). |
| `src/masking/stream-restorer.ts` | `StreamRestorer` class holding two buffers (PII, secrets) and restoring each streamed text chunk. | TypeScript | type import from `../config`; `./service` | Yes (type-only import). |
| `src/masking/restore-policy.ts` | Optional `[protected]` marker prefix on restored values when `show_markers` is on. | TypeScript | type import from `../config` | Yes. |
| `src/masking/extractors/openai.ts` | Chat Completions extractor: string and multi-part `content`; unmasks `choices[].message.content` and tool-call `arguments`; `remaskOpenAIToolCallArguments` re-masks known values inside serialised JSON tool-call arguments in conversation history, with a hand-written JSON string and number tokenizer. | TypeScript | type imports from `../../providers/openai/types` | Yes (type-only imports). |
| `src/masking/extractors/anthropic.ts` | Messages extractor: `system` (string or blocks, message index -1), `text`, `thinking`, `tool_result` (string or nested blocks, role `tool`); unmasks `text` and `tool_use.input` recursively; `remaskAnthropicToolUseHistory` re-masks values (strings and numbers) in prior `tool_use` inputs. | TypeScript | type imports from `../../providers/anthropic/types` | Yes (type-only imports). |
| `src/masking/extractors/responses.ts` | Generic extractor for the Responses API (used by Codex): walks any JSON, collects strings under a fixed key set (`arguments`, `content`, `delta`, `input`, `instructions`, `output_text`, `stderr`, `stdout`, `text`, …), infers role from `role` or `type`, sets values back by path; JSON-aware restore for `function_call.arguments`. | TypeScript | none | Yes. |
| `src/pii/detect.ts` | HTTP client for the detector's `/analyze`; applies `scan_roles`; subtracts spans already covered by secrets placeholders; allowlist filter (regex anchored to the whole span); denylist literal or regex matches merged additively with detector type winning. `waitForReady` polling. | TypeScript, Bun | `fetch`, `../config` (`getConfig`) | No: needs a running detector service and the config singleton. |
| `src/pii/mask.ts`, `src/pii/request.ts` | PII placeholder generation (`[[PERSON_1]]`) and request-level detect and mask wrappers. | TypeScript | `../masking/*` | `mask()` is standalone; `request.ts` uses `getPIIDetector()`. |
| `src/privacy/pipeline.ts` | Order of operations: secrets first (in-process), then PII via detector; a detector failure raises `PrivacyPipelineDetectionError`; in `mask` mode the PII is masked, in `route` mode only detected. | TypeScript | `../secrets/request`, `../pii/request` | No. |
| `src/secrets/` (10 files: `detect.ts`, `mask.ts`, `request.ts`, `multimodal.test.ts`, `patterns/{api-keys,env-vars,index,private-keys,tokens,types,utils}.ts`) | Not opened (name contains "secret"). From `src/config.ts` lines 182–201 and `config.example.yaml`: ten secret types (OpenSSH and PEM private keys, `sk-` API keys, AWS, GitHub, JWT, bearer token, env password, env secret, connection string), action `mask`, `block` or `route_local`, `max_scan_chars` default 200000, `scan_roles`. From the import map, `src/secrets/mask.ts` reuses `maskSpans`, `resolveOverlaps` and `generateSecretPlaceholder` from `src/masking/`. | TypeScript (by extension) | unknown, not read | Unknown. |
| `src/routes/` (`openai.ts`, `anthropic.ts`, `codex.ts`, `openai-responses.ts`, `api.ts`, `health.ts`, `info.ts`, `dashboard.tsx`, `utils.ts`) | HTTP handlers. `api.ts` registers one route, `POST /mask` (line 282), the standalone mask endpoint documented in `docs/api-reference/mask.mdx` (`text`, `startFrom`, `detect`; returns `masked`, `context`, `counters`, `entities`). Other route files were not read line by line. | TypeScript, Bun | `hono`, `@hono/zod-validator` (from `package.json`) | No. |
| `src/providers/` (`openai/`, `anthropic/`, `local.ts`, `errors.ts`, `forwarded-headers.ts`) | Upstream clients and SSE stream transformers; stream transformers import `StreamRestorer` (import map). Not read line by line. | TypeScript, Bun | `fetch` | No. |
| `src/protocols/responses/stream-transformer.ts` | Streaming restore for the Responses API; imports the responses extractor and `StreamRestorer` (import map). Not read. | TypeScript | `../../masking/*` | No. |
| `src/logging/` (`db.ts`, `logger.ts`, `log-content.ts`) | Request log in SQLite (default `./data/pasteguard.db`) or Postgres, retention in days, `log_masked_content` stores scanned roles after masking (`config.example.yaml`, "Logging settings"). Not read line by line. | TypeScript, Bun | `kysely`, `pg` (from `package.json`) | No. |
| `src/middleware/browser-access.ts` | Not read. Named for browser access control. | TypeScript | unknown | Unknown. |
| `src/views/dashboard/page.tsx`, `src/routes/dashboard.tsx` | Dashboard page (JSX via `hono/jsx`, `tsconfig.json`). Not read. | TypeScript JSX, Bun | `hono-tailwind`, `tailwindcss` | No. |
| `detector/detector/app.py` | FastAPI app with `GET /health` (reports backend and model) and `POST /analyze` (`text`, `phone_regions`, `entities`, `score_threshold` → list of `{entity_type, start, end, score}`); converts Python code-point offsets to UTF-16 offsets for the JS caller; loads the semantic backend at startup. | Python ≥ 3.10 (`detector/pyproject.toml`) | `fastapi`, `uvicorn`, `pydantic` | Yes: a self-contained HTTP service with no dependency on the Bun code. |
| `detector/detector/entities.py` | Nine entity type constants (PERSON, LOCATION, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE, IP_ADDRESS, VAT_CODE, CN_RESIDENT_ID), frozen `Span` dataclass, half-open `overlaps`. | Python | stdlib | Yes. |
| `detector/detector/deterministic.py` | Regex candidates gated by validation, every match scored 1.0: email, IPv6 and IPv4 (`ipaddress`), IBAN (trailing tokens trimmed until valid), EU VAT (country prefix required), Chinese resident ID, credit card (Luhn, 13–19 digits), phone (`PhoneNumberMatcher`, `+` international unless `phone_regions`). Priority order, first accepted span wins overlaps. | Python | `python-stdnum`, `phonenumbers`, stdlib `re`, `ipaddress` | Yes: pure functions, importable without FastAPI or GLiNER. |
| `detector/detector/gliner_layer.py` | GLiNER NER for labels `person`, `location`, `address` (address emitted as LOCATION); per-label floors 0.99 / 0.80 / 0.80 overridable via `GLINER_FLOOR_*`; overlapping windows of ~384 word tokens for long text; `lru_cache` of 4096 windows; inference serialised under a lock; drops out-of-range spans. Default model `urchade/gliner_multi_pii-v1`. | Python | `gliner`, `torch`, `transformers` (via `gliner`) | Yes as a module, but needs the model weights (downloaded from Hugging Face at image build, `docker/Dockerfile`) and a CPU torch install. |
| `detector/detector/semantic_backend.py` | Backend registry (only `gliner` registered); resolves `DETECTOR_MODEL` as local directory (checks `gliner_config.json` and weights) or Hugging Face repo id (validates config before download); `DETECTOR_BACKEND` env; loads once under a lock. | Python | `huggingface-hub` | Yes. |
| `detector/detector/merge.py` | Merges layers: deterministic spans always win; fuzzy spans are cut to the fragments not covered by a deterministic span; among fuzzy, longer then higher score; filters to requested entities before resolution so an unrequested type cannot suppress a requested one. | Python | stdlib | Yes. |
| `detector/detector/smoke.py` | Build-time smoke check: starts the app lifespan, asserts GLiNER is the backend and that an email and "Berlin" are found. | Python | the detector package | Needs the model. |
| `detector/tests/` (5 files) | pytest suites for analyze, deterministic, GLiNER layer, merge, semantic backend. Not read. | Python | `pytest`, `httpx` (dev extras) | Not run. |
| `benchmarks/pii-accuracy/run.ts` | Benchmark runner: loads YAML cases, validates corpus (unknown fields, duplicate ids, expected text absent), POSTs each case to an `/analyze`-shaped endpoint (`--url`, default `http://localhost:3000/analyze`, threshold 0.7), scores `exact` / `contains` (≤ 2 edge chars) / `overlap`, prints pass rate, P, R, F1, F2 by suite, category, language and entity; `core` and `precision` gate the exit code. | TypeScript, Bun | `yaml`, `zod`, `node:fs`, `node:util` | Yes: only needs an HTTP endpoint that speaks the `/analyze` contract; it does not import the server. |
| `benchmarks/pii-accuracy/taxonomy.ts`, `types.ts` | Entity list (9), languages (`en de es fr it nl pl pt ro`), 8 suites with descriptions, Zod schemas for cases. | TypeScript | `zod` | Yes. |
| `benchmarks/pii-accuracy/test-data/*.yaml` | 8 files, 131 cases by `- id:` count: `core` 40, `precision` 31, `eval` 16, `hard` 12, `multilingual-paragraphs` 9, `multilingual-sentences` 9, `boundaries` 8, `precision-paragraphs` 6. Each case: id, suite, category, language, text, expected spans with match mode. | YAML data | none | Yes. |
| `benchmarks/pii-accuracy/README.md` | Explains suites, gating, match modes, and that the corpus is chosen from "product behavior", not from what the detector passes. | Markdown | | |
| `config.example.yaml` | Reference config: `mode`, `server`, `providers` (openai, anthropic, codex), `local` (ollama or openai-compatible), `masking` (markers, allowlist, denylist), `pii_detection` (detector URL `localhost:5002`, timeout, phone regions, threshold 0.7, entities), `secrets_detection`, `logging`, `dashboard`. There is no `config.example.json`. | YAML | | |
| `docker/Dockerfile`, `docker/supervisord.conf`, `docker-compose.yml` | Multi-stage image: Bun build stage, Python build stage (CPU torch, detector install, model fetched into `/opt/models`, offline env vars set), `detector` target (uvicorn on 5002), default all-in-one target running both under `supervisord` with the detector bound to `127.0.0.1:5002`. Compose has a `dev` profile exposing the detector alone. | Dockerfile, ini, YAML | `oven/bun`, `cgr.dev/chainguard/python`, `supervisor` | The `detector` target runs alone. |
| `docs/` (Mintlify `mint.json`, `.mdx`) | Product docs. Read: `concepts/local-first-privacy.mdx`, `concepts/mask-mode.mdx`, `concepts/pii-detection.mdx`, `concepts/route-mode.mdx`, `api-reference/mask.mdx`, head of `configuration/semantic-backends.mdx`. | MDX | | |
| `.github/workflows/ci.yml` | CI: Bun typecheck, benchmark typecheck, Biome check, `bun test`; detector ruff, pyright, pytest; Docker build. `release.yml` not read. | YAML | | |
| `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `biome.json`, `tsconfig*.json`, `bun.lock`, `.conductor/settings.toml` | Agent instructions (`CLAUDE.md` is `@AGENTS.md`), lint and TS config, lockfile. `CONTRIBUTING.md`, `bun.lock` and `.conductor` not read. | | | |

Test file counts by name, not run: 39 `*.test.ts` under `src/`, 5 `test_*.py`
under `detector/tests/`.

### Architecture in one paragraph

PasteGuard is two processes. The proxy is a Bun/Hono HTTP server
(`src/index.ts`) exposing provider-shaped routes (`/openai/v1/...`,
`/anthropic/v1/messages`, `/codex/responses`) plus a standalone `POST
/api/mask` (`src/routes/api.ts`, `docs/api-reference/mask.mdx`). Each route
uses a `RequestExtractor` (`src/masking/types.ts`) to pull text spans out of
the provider's request shape and push masked text back, so the masking core
never knows the wire format. The privacy pipeline (`src/privacy/pipeline.ts`)
runs secrets detection first, in-process in TypeScript, then PII detection
by HTTP call to the second process, a Python FastAPI service
(`detector/detector/app.py`) that combines a regex-plus-checksum layer
(`deterministic.py`) with GLiNER NER (`gliner_layer.py`) and merges them with
deterministic-wins rules (`merge.py`). In `mask` mode, spans become
`[[TYPE_N]]` placeholders held in an in-memory per-request
`PlaceholderContext` (`src/masking/context.ts`), the masked request is
forwarded, and the response, including SSE streams with partial-placeholder
buffering (`src/masking/stream-restorer.ts`), is restored before it returns;
in `route` mode a request with findings is sent to a local model instead
(`docs/concepts/route-mode.mdx`). Operator allowlist and denylist patterns
and `scan_roles` are applied in `src/pii/detect.ts`. Requests are logged to
SQLite or Postgres for a dashboard (`config.example.yaml`). The published
artifact is one container running both processes under supervisord with the
detector on loopback (`docker/Dockerfile`, `docker/supervisord.conf`).

### Not verified

- `src/secrets/**` (10 files), `docs/concepts/secrets-detection.mdx`,
  `docs/configuration/secrets-detection.mdx` and
  `.github/secret_scanning.yml` were not opened because their names contain
  "secret". Everything said about secrets detection comes from
  `src/config.ts`, `config.example.yaml` and the import graph.
- `config.example.json` does not exist in the repo; `config.example.yaml`
  was read instead.
- The benchmark's default endpoint is `http://localhost:3000/analyze`
  (`benchmarks/pii-accuracy/run.ts`, `DEFAULT_ANALYZE_URL`), but no
  `/analyze` route exists in `src/routes/` or `src/index.ts`; the only route
  in `src/routes/api.ts` is `POST /mask`. Whether the published image serves
  `/analyze` on 3000 was not checked because nothing was run.
- Nothing was executed: no tests, no benchmark, no container, no model
  download. Statements about behaviour are from source reading only.
- `src/routes/`, `src/providers/`, `src/protocols/`, `src/logging/`,
  `src/middleware/`, `src/views/`, `detector/tests/`, `CONTRIBUTING.md`,
  `.github/workflows/release.yml`, `bun.lock` and `.conductor/` were listed
  or grepped for imports and route declarations only, not read.
- The middle of `docker/Dockerfile` (about 1.1 KB between the `detector`
  stage's environment lines and the final stage's `COPY` of Bun) was
  truncated in my read; the ONNX-related settings mentioned there were not
  seen.
- The default GLiNER model (`urchade/gliner_multi_pii-v1`): licence, size
  and language coverage were not checked; only the repo id is known from
  `detector/detector/gliner_layer.py` and `docker/Dockerfile`.
- The browser extension is referenced in `README.md` but its source is not
  in this repository.
- Whether the placeholder mapping ever persists beyond a request (for
  example into the request log) was not verified; `src/logging/` was not
  read.
- Exact dependency versions are from `package.json` ranges and
  `detector/pyproject.toml` ranges, not from `bun.lock`.

## Detection: Hider vs PasteGuard

Scope: what each side detects, with what, and the shapes one side catches
that the other does not. Hider paths are relative to the Hider repo root;
PasteGuard paths are relative to the clone. Nothing was run on either side:
behaviour is read from source, and Hider's figures are quoted from its
README, not re-measured. Anything not confirmable from the files is marked
UNVERIFIED.

### Architecture of detection

| | Hider | PasteGuard |
|---|---|---|
| Layers | Tier 1 regex (Presidio `PatternRecognizer` and custom `LocalRecognizer`s, no NLP engine), tier 2 local classifier or spaCy over the residue, optional tier 3 LLM over what tier 2 left (`hider/pipeline.py` `RegexTier`, `ManagedNerTier`, `LlmPassTier`; `hider/recognizers.py`; `hider/ner.py`; `hider/llm_tier.py`). | Two layers in one Python service: a deterministic regex-plus-checksum layer and a GLiNER NER layer, merged deterministic-wins (`detector/detector/deterministic.py`, `gliner_layer.py`, `merge.py`). Secrets are a separate in-process TypeScript regex pass that runs before PII (`src/secrets/detect.ts`, `src/privacy/pipeline.ts`). No LLM layer. |
| Order and residue | Each tier sees only text earlier tiers did not claim; a later tier may only add spans, enforced by a coverage check (`hider/pipeline.py` `Pipeline.detect`, `residue_segments`). | Both detector layers see the whole text; overlaps resolved in `merge.py` (deterministic beats fuzzy, fuzzy fragments not covered survive, longer then higher score). PII detection runs on text already containing secrets placeholders and subtracts spans overlapping them (`src/pii/detect.ts` `subtractPlaceholderOverlaps`). |
| Overlap resolution | Secret beats identifier, then longer, then higher score, then tier order (`hider/pipeline.py` `resolve`). | PII: Presidio-style port, merge same-type overlaps, then highest score, then longest (`src/masking/conflict-resolver.ts` `resolveConflicts`). Secrets: longer span wins, no scores (`resolveOverlaps`). First-position dedupe across secret patterns (`src/secrets/patterns/utils.ts`). |
| Score floor | One pipeline floor, `min_score=0.4`, applied to every tier's spans (`hider/pipeline.py` `Pipeline.__init__`); tier 1 patterns carry 0.5 to 0.95. | Deterministic matches score 1.0 (`deterministic.py` docstring). GLiNER per-label floors person 0.99, location 0.80, address 0.80, raised by the request `score_threshold` (default 0.7) (`gliner_layer.py` `PER_LABEL_FLOOR`; `config.example.yaml`). |
| Context gating | Several rules fire only with a naming word in front: eight-digit case numbers, tracking ids, AWS secret access key, GUID subtype relabelling (`hider/recognizers.py` `SupportCaseRecognizer`, `AwsSecretKeyRecognizer`, `refine`). Named suppression: version-context IPs, vendor hosts, logon inside path (`suppress`). | Checksum gating instead of context: Luhn, IBAN mod-97, EU VAT, Chinese RIC via `python-stdnum`; `ipaddress` for IPv6; `phonenumbers` `Leniency.VALID` (`deterministic.py`). Operator allowlist and denylist, literal or regex (`src/pii/detect.ts`; `src/config.ts` `MaskingSchema`). |
| Which message roles are scanned | Every `messages[].content` string or text part and `prompt`, regardless of role (`hider/proxy.py` `_collect_texts`). | Only roles in `scan_roles`, default `user`, `tool`, `function`, `mcp`; `system`, `developer` and `assistant` text is skipped by default for both PII and secrets (`src/config.ts` `DEFAULT_SCAN_ROLES`; `src/pii/detect.ts` `analyzeRequest`; `src/secrets/detect.ts` `detectSecretsInSpans`). |
| Scan limit | None found in `hider/pipeline.py` or `hider/proxy.py`. | Secrets: first `max_scan_chars` characters only, default 200000, "secrets placed after this limit won't be detected" (`config.example.yaml`; `src/secrets/detect.ts`). PII: GLiNER input is windowed (about 384 word tokens, 64 overlap) so long text is covered (`gliner_layer.py` `_windows`). |
| Offsets | Python code points throughout. | Detector converts code-point offsets to UTF-16 so the Bun side can slice (`detector/detector/app.py` `_utf16_mapper`). |
| Site extension | Additive regex profiles via `HIDER_PROFILE` (`hider/recognizers.py` `profile_recognizers`; `hider/profiles.py`); vendor host list and path structure via `hider.local.json` (`hider/vendors.py`, `hider/paths.py`). | `masking.denylist` (literal or regex, with a type) and `masking.allowlist` in `config.yaml` (`src/config.ts`). A default allowlist entry exempts the Claude Code system prompt sentence (`src/config.ts` `DEFAULT_ALLOWLIST`). |
| Measurement in repo | Eval harness with generated corpus, adversarial cases, clean corpus, cassettes; README quotes 99.76% shaped recall, 99.65% free-text recall, 0.0% false redaction on 1,000 clean lines (`README.md` lines 135 to 139; `hider/evaluate.py`; `hider/adversarial.py`). Not re-run here. | Benchmark runner with 131 YAML cases over 9 entity types and 9 languages, gating `core` and `precision` suites; no result numbers are committed in the repo (`benchmarks/pii-accuracy/run.ts`, `test-data/*.yaml`, `README.md`). Published accuracy figures: UNVERIFIED, none found in the clone. |

### Model layers

| | Hider | PasteGuard |
|---|---|---|
| Default model | Per-token BIO `LogisticRegression` over hand-written features, trained in-process on about 500 generated sentences with a vocabulary disjoint from the eval corpus; PERSON and ORGANIZATION only (`hider/classifier.py` `train`, `_TRAIN_FIRST`, `_TRAIN_ORG_WORDS`). | `urchade/gliner_multi_pii-v1`, a multilingual GLiNER checkpoint, labels `person`, `location`, `address` (address emitted as LOCATION) (`detector/detector/gliner_layer.py` `DEFAULT_MODEL`, `_LABEL_TO_TYPE`). |
| Alternative | spaCy `en_core_web_sm` through Presidio's NLP engine, PERSON and ORG only, flat score 0.8 (`hider/ner.py` `LABEL_MAP`, `SPAN_SCORE`). Optional tier 3 LLM, OpenAI or Anthropic, strict JSON, verbatim-quote verification, add-only (`hider/llm_tier.py`). | Backend registry with one entry, `gliner`; `DETECTOR_MODEL` may point at another GLiNER checkpoint, local or Hugging Face (`detector/detector/semantic_backend.py` `_BACKENDS`). |
| Organisations | Caught by tier 2 (both backends) and tier 3 (`hider/classifier.py`; `hider/ner.py`; `hider/llm_tier.py` `_INSTRUCTIONS`). | Not emitted: "Other structured types (org/address/fiscal/BIC/crypto) are not currently emitted" (`detector/detector/entities.py` comment). No `organization` label in `gliner_layer.py` `_LABELS`. |
| Locations | Not emitted: `ner.py` maps only PERSON and ORG, by design ("redacting them would gut the bundle") (`hider/ner.py` module docstring). | LOCATION and street addresses via GLiNER (`gliner_layer.py`). |
| Log-structure guards | Dotted-chain namespace suppression, structural path segment suppression, backslash-preceded token suppression, log-vocabulary trimming with a second lower-cased reading (`hider/pipeline.py` `in_dotted_chain`, `in_structural_path_segment`, `LOG_VOCABULARY`, `ManagedNerTier._predict`). | None specific to logs found in `gliner_layer.py` or `merge.py`. Out-of-bounds spans are dropped (`gliner_layer.py` `detect_gliner`). Precision is measured by the `precision` and `precision-paragraphs` suites (`benchmarks/pii-accuracy/taxonomy.ts`). |
| Runtime cost | scikit-learn only; training "well under a second" once per process (`hider/pipeline.py` `ManagedNerTier` docstring). spaCy optional extra (`requirements-ner.txt`). | `torch`, `transformers`, `gliner`, model weights baked into the image; inference serialised under one lock; LRU cache of 4096 windows (`detector/pyproject.toml`; `gliner_layer.py` `_infer_lock`, `MODEL_INFERENCE_CACHE_SIZE`; `docker/Dockerfile`). |
| Multilingual | English grammar and features; no language handling found in `classifier.py`. | Model is multilingual; benchmark covers `en de es fr it nl pl pt ro` (`benchmarks/pii-accuracy/taxonomy.ts` `SUPPORTED_LANGUAGES`; `docs/concepts/pii-detection.mdx`). |

### Entity types each side has that the other does not

**Hider only** (pseudonymised unless noted; all in `hider/recognizers.py`
unless noted):

- GUIDs, bare, braced and 32-hex, relabelled SESSION_GUID, TENANT_ID,
  OBJECT_GUID from context (`any_guid`, `refine`, `_GUID_KINDS`).
- Worker pod ids and service instance ids (`worker_pod_id`,
  `service_instance_id`).
- Tenant-bearing SaaS site URLs for sharepoint.com, atlassian.net,
  zendesk.com, slack.com (`tenant_site_url`; `hider/entities.py`
  `TENANT_SITE_HOSTS`).
- Customer domains on public TLDs outside the vendor list
  (`CustomerDomainRecognizer`; `hider/vendors.py`).
- Internal hostnames (`hostname_fqdn`), `*.onmicrosoft.com`
  (`onmicrosoft_tenant_domain`), Azure Key Vault URLs (`azure_key_vault`),
  OneDrive `/personal/` segments (`onedrive_personal_account`), Exchange
  item ids (`exchange_item_id`).
- `DOMAIN\user` logons (`DomainLogonRecognizer`), Windows and Azure AD SIDs
  (`windows_sid`), certificate thumbprints (`CertThumbprintRecognizer`).
- Windows profile paths and UNC home shares (`windows_user_path`), customer
  folder and file names in rooted paths (`CustomerPathRecognizer`;
  `hider/paths.py`).
- Zero-padded IPv4 (`zero_padded_ipv4`).
- Eight-digit support case numbers and Microsoft tracking ids, context-gated
  (`SupportCaseRecognizer`).
- ORGANIZATION names in prose (tier 2 and 3).
- Destroyed: pre-signed storage URLs and any `sig=` parameter
  (`presigned_url`); Azure-style `AccountKey=`, `Server=`, `Password=`
  connection strings (`connection_string`); JWT two-segment heads and
  continuation fragments (`jwt`, `ContinuationFragmentRecognizer`); `ak-`,
  `vk-`, `pk-` prefixed keys (`api_key`); `github_pat_`, Google `AIza`,
  Slack `xox[abeprs]-`, Entra `head~secret`, nine AWS key id prefixes
  (`vendor_credential`); `Basic`, `Negotiate`, `X-Api-Key:` header values
  (`http_credential_header`); cookie values (`CookieHeaderRecognizer`); AWS
  secret access key by its key name (`AwsSecretKeyRecognizer`); bare 40+
  character base64 lines (`PrivateKeyBlockRecognizer.BODY_LINE`).

**PasteGuard only**, with one invented example line each that, on reading
Hider's rules, Hider would leave in the clear or handle differently:

| PasteGuard rule | Where | Invented example line Hider misses | Why Hider misses it |
|---|---|---|---|
| LOCATION, including street addresses | `detector/detector/gliner_layer.py` `_LABEL_TO_TYPE` | `Site contact confirmed the NAS at Keizersgracht 120, Amsterdam is offline.` | Neither tier 2 backend emits LOCATION (`hider/ner.py` `LABEL_MAP`; `hider/classifier.py`). |
| CREDIT_CARD, Luhn-validated, 13 to 19 digits | `deterministic.py` `_credit_card` | `Refund for order 7781 failed: card 4111 1111 1111 1111 declined by issuer.` | No card rule in `hider/recognizers.py`; the digit run is not an eight-digit case number and has no case word. |
| IBAN_CODE, mod-97 via `stdnum.iban` | `deterministic.py` `_iban` | `Payout to DE89 3704 0044 0532 0130 00 rejected: account closed.` | No IBAN rule in `hider/recognizers.py`. |
| VAT_CODE, EU member-state checksum | `deterministic.py` `_vat` | `Invoice header VAT DE136695976 did not validate against VIES.` | No VAT rule in `hider/recognizers.py`. |
| CN_RESIDENT_ID, 18 characters with checksum | `deterministic.py` `_cn_resident_id` | `KYC upload for 11010519900101007X timed out after 30s.` | No rule in `hider/recognizers.py`; `any_guid`'s 32-hex pattern does not match 18 digits. |
| API_KEY_SK with underscore separator (`sk_live_`, `sk_test_`) | `src/secrets/patterns/api-keys.ts` | `Stripe charge failed using sk_live_EXAMPLE0NLY.` | Hider's prefix rule is `(?:sk\|ak\|vk\|pk)-` with a hyphen only (`hider/recognizers.py` `api_key`). Score-only context words do not add a match. |
| ENV_SECRET: `*_SECRET` assigned with `=` or `:` | `src/secrets/patterns/env-vars.ts` | `Loaded config: APP_SECRET=9f8e7d6c5b4a3f2e1d0c4b5a6978 from env.` | No `_SECRET` key-name rule; `AwsSecretKeyRecognizer` is limited to `secret_access_key` (`hider/recognizers.py`). The value is one word, not a base64-only line, so `BODY_LINE` does not apply. |
| ENV_PASSWORD with colon assignment (`PASSWORD:` or `_PWD:`) | `src/secrets/patterns/env-vars.ts` | `settings.yaml: db_password: Tr0ub4dor&3` | Hider's `connection_string` requires `Password=` or `Pwd=` with an equals sign (`hider/recognizers.py` line 186). The `=` form (`DB_PASSWORD=value`) is covered: Presidio's `PatternRecognizer` defaults to `re.DOTALL \| re.MULTILINE \| re.IGNORECASE` (`.venv/lib/python3.11/site-packages/presidio_analyzer/pattern_recognizer.py` line 59, Presidio 2.2.366), and the pattern has no leading word boundary, so `PASSWORD=` inside `DB_PASSWORD=` matches. Confirmed by reading, not by running. |
| National-format phone numbers in any configured region (`phone_regions`) | `deterministic.py` `_phone`; `config.example.yaml` | `Callback requested on 06 12345678 before noon (NL office).` | Hider wraps Presidio's `PhoneRecognizer` with its fixed default regions `US, GB, DE, FR, IL, IN, CA, BR` (`.venv/.../presidio_analyzer/predefined_recognizers/generic/phone_recognizer.py` line 29; `hider/recognizers.py` `FormattedPhoneRecognizer` passes no regions), so a Dutch, Italian or Polish national format is outside Hider's list and has no configuration hook. Whether `phonenumbers` validates this exact invented number is UNVERIFIED (not run). |

Shapes both catch, with the difference in handling noted in the masking
section: email addresses including accented local parts (Hider's UPN rule is ASCII-only, but the stock Presidio `EmailRecognizer` it runs alongside uses `\w`, which is Unicode-aware in Python, at score 0.5 above the 0.4 floor; `.venv/.../predefined_recognizers/generic/email_recognizer.py` line 26; `hider/recognizers.py` `builtins`), IPv4 and IPv6 including compressed IPv6 (`.venv/.../generic/ip_recognizer.py` lines 33 to 41), phone numbers written with `+`,
JWTs, `Bearer` tokens, `AKIA` key ids, `ghp_`-family GitHub tokens,
`-----BEGIN ... PRIVATE KEY-----` blocks (Hider's `MARKER` is
`-----BEGIN[A-Z ]*PRIVATE KEY-----`, which covers `OPENSSH`, `RSA` and
`ENCRYPTED`; `hider/recognizers.py` `PrivateKeyBlockRecognizer`;
`src/secrets/patterns/private-keys.ts`), and `scheme://user:pass@host`
(Hider `url_userinfo` for any scheme, destroying `user:pass@` and keeping
the host; PasteGuard `CONNECTION_STRING` for nine database schemes,
masking the whole URL; `src/secrets/patterns/env-vars.ts`).

Differences inside shared shapes:

- **JWT.** PasteGuard requires three segments each of at least 20
  characters, the first two starting `eyJ`
  (`src/secrets/patterns/tokens.ts`). Hider accepts 8-character segments,
  a two-segment head, and anything after `Bearer`
  (`hider/recognizers.py` `jwt`).
- **Bearer.** PasteGuard needs 40 or more token characters and includes the
  word `Bearer` in the span (`tokens.ts`). Hider needs 10 and keeps the word
  outside the span (`jwt`, pattern `bearer-value`).
- **Private keys.** PasteGuard masks the whole block including markers
  (`private-keys.ts`). Hider claims the body only and leaves the BEGIN and
  END lines readable (`PrivateKeyBlockRecognizer` docstring).
- **Email in URL paths.** Hider's `upn_email` exists because Presidio's
  stock recognizer drops addresses inside `/users/<upn>/` Graph paths
  (`hider/recognizers.py` `upn_email` docstring). PasteGuard's `_EMAIL_RE`
  has a negative lookbehind for `[\w.%+\-@]` only, so a `/` before the
  address is allowed; behaviour on this case is UNVERIFIED (not run).
- **IPv4 near a version word.** Hider suppresses an IPv4 match preceded by
  version context (`hider/recognizers.py` `suppress`, `_VERSION_CONTEXT`).
  PasteGuard has no such rule; it rejects a trailing `.digit` only
  (`deterministic.py` `_IPV4_RE` comment).

### Detection, for support logs going to an LLM

| Aspect | Leans | Because |
|---|---|---|
| Log-native identifiers (GUIDs, tenants, hosts, pods, paths, SIDs, logons, case numbers) | Hider | PasteGuard emits none of these (`detector/detector/entities.py`); Hider has a rule per shape (`hider/recognizers.py`). |
| Credential shapes | Hider, with gaps | Hider covers more vendor prefixes, headers, cookies, SAS, fragments; PasteGuard covers `sk_` with underscore, `_SECRET=` and colon-assigned passwords that Hider lacks (table above). |
| Financial and civil identifiers (card, IBAN, VAT, national id) | PasteGuard, low weight | Checksum-validated rules Hider does not have (`deterministic.py`). Card, IBAN and VAT are rare in support logs (stated by the Hider owner), so this row carries little weight. |
| Person names in English prose | Not decidable from source | Hider quotes 99.65% on its own generated corpus (`README.md` line 137); PasteGuard commits no figure. GLiNER's person floor is 0.99 (`gliner_layer.py`), which trades recall for precision. UNVERIFIED either way. |
| Organisation names | Hider | PasteGuard does not emit organisations (`entities.py` comment). |
| Locations | PasteGuard | Hider does not emit them by design (`hider/ner.py` docstring). |
| Non-English text | PasteGuard | Multilingual model and nine-language benchmark (`taxonomy.ts`); Hider's classifier grammar is English (`hider/classifier.py`). |
| False positives on log structure | Hider | Named suppressions for namespaces, paths, log levels, version strings (`hider/pipeline.py`, `hider/recognizers.py` `suppress`), measured at 0.0% on 1,000 clean lines (`README.md` line 139). PasteGuard measures precision on 37 short negative cases (`test-data/precision*.yaml`). |
| Operator tuning without code | PasteGuard | YAML allowlist and denylist with types (`src/config.ts`). Hider needs a profile JSON of regexes (`hider/profiles.py`). |
| Coverage of system and assistant turns | Hider | Hider scans every message (`hider/proxy.py` `_collect_texts`); PasteGuard skips them by default (`src/config.ts` `DEFAULT_SCAN_ROLES`). |

## Masking: Hider vs PasteGuard

### Comparison

| Aspect | Hider | PasteGuard |
|---|---|---|
| Placeholder format | Shape-preserving pseudonyms: `<Session-01>`, `user-01@tenant-01.example`, `https://tenant-01.sharepoint.example/spaces/Space-01`, `203.0.113.2`, `2001:db8::1`, `C:\Users\user-01\...`, `node-01.tenant.example`, `DOMAIN01\user-01`, `S-1-5-21-0-0-1-500`, `<Folder-01>`, `<File-01>`, `+1-555-0101`, `<Person-01>`, `<Org-01>` (`hider/pseudonym.py` `EntityVault._shape`). Destroyed secrets become `<REDACTED:JWT>`, `<REDACTED:API_KEY>` and so on (`destroyed_marker`). Pseudonym hosts use reserved names (`.example`, TEST-NET-3, 555-01xx) so they cannot collide with real values (`_shape` comments). | Uniform bracketed tokens: `[[PERSON_1]]`, `[[EMAIL_ADDRESS_2]]`; secrets `[[API_KEY_SK_1]]`, `[[JWT_TOKEN_1]]` (`src/masking/placeholders.ts` `PII_PLACEHOLDER_FORMAT`, `generateSecretPlaceholder`). Denylist types are operator-named, e.g. `[[CUSTOMER_ID_1]]` (`config.example.yaml`). No shape is preserved: an IP, a URL and a path all become `[[TYPE_N]]`. |
| Same value appearing twice | One label per value, keyed on `HMAC(vault_key, type + casefolded value)`, so case variants and re-spellings share a label; path labels normalise `%20`, NBSP and case (`hider/pseudonym.py` `_digest`, `_PATH_LABEL_TYPES`). GUID subtypes share one identity space so a tenant id relabelled on one line and bare on the next gets one label (`_GUID_FAMILY`). Related values share a tenant ordinal: `anna@contoso.com`, `contoso.sharepoint.com`, `contoso.onmicrosoft.com` all point at `tenant-01` (`_shape`, `_TENANT_DOMAIN`). Labels are stable across lines, requests and processes when `HIDER_VAULT_KEY` is set; without it the key is ephemeral per process (`_load_key`; `README.md` line 430). | One placeholder per exact string within one `PlaceholderContext` (`src/masking/context.ts` `replaceWithPlaceholders`, `reverseMapping`); `Anna Novak` and `ANNA NOVAK` get two placeholders. The context is created per request: PII masking creates a fresh context unless one is passed, and the pipeline passes none (`src/pii/request.ts` `maskPII`; `src/privacy/pipeline.ts`); secrets masking creates its own (`src/secrets/mask.ts` `maskRequest`). So `[[PERSON_1]]` in one request may be a different person in the next. Within a request, prior assistant tool-call arguments are re-masked with the current contexts (`src/masking/extractors/openai.ts` `remaskOpenAIToolCallArguments`; `anthropic.ts` `remaskAnthropicToolUseHistory`). `/api/mask` lets a caller continue counters via `startFrom` but the mapping must be kept by the caller (`src/routes/api.ts`; `docs/api-reference/mask.mdx`). No cross-request store was found in the files read. |
| Known-value sweep | After the tiers, the redacted payload is swept for every value the vault already holds and replaced with its existing label; if a known value still survives the request is refused (`hider/proxy.py` `sweep`, `_known_values_rx`, `redact_payload`). Person and org values match case-sensitively plus Title and UPPER forms (`_known_values_rx` comment). | No equivalent. The denylist is the operator's fixed list, not a learned one (`src/pii/detect.ts` `findDenylistedEntities`). |
| Restoring originals | `EntityVault.detokenize`: one left-to-right pass choosing the segmentation that restores the most label characters, longest label on ties, never rescanning restored text; bare labels without angle brackets are restored too (`hider/pseudonym.py` `detokenize` docstring). Applied to `choices[].message.content` and `choices[].text` only (`hider/proxy.py` `detokenize_response`). Tool-call arguments are not detokenised (not handled in `detokenize_response`). A label the vault does not know is passed through and reported in `X-Hider-Unknown-Labels` and the log (`hider/proxy.py` `_handle`; `README.md` line 795). Secrets are never restorable (see below). | `restorePlaceholders`: whole-string split/join per placeholder, longest placeholder first (`src/masking/context.ts`). Applied to message content, OpenAI tool-call `arguments` with JSON escaping, Anthropic `text` and `tool_use.input` recursively, Responses API `function_call.arguments` (`src/masking/extractors/openai.ts`, `anthropic.ts`, `responses.ts`). PII context then secrets context (`src/masking/restorer.ts`). Optional `[protected]` marker prefix on restored values (`src/masking/restore-policy.ts`). Unknown or malformed placeholders are left as-is; no reporting found. |
| Streaming | `stream: true` forwarded as SSE; each `delta.content` goes through a `HoldbackDetokenizer` that releases everything except the longest tail that is a proper prefix of some vault label, with a straddle check so a complete label crossing the cut is released whole; worst-case lag is one label length minus one, measured mean about 2 characters (`hider/proxy.py` `HoldbackDetokenizer`, `_rewrite_stream`; `README.md` lines 790 to 795, test `test_holdback_releases_plain_text_immediately_and_lag_is_small`, not run). Only `delta.content` is rewritten; streamed tool-call arguments are not (`_rewrite_stream`). | `StreamRestorer` keeps two buffers (PII, secrets) and holds back from the last unclosed `[[` or a trailing `[` (`src/masking/placeholders.ts` `findPartialPlaceholderStart`; `src/masking/stream-restorer.ts`). OpenAI stream transformer also restores streamed tool-call argument channels with JSON escaping (`src/providers/openai/stream-transformer.ts` `ToolArgumentChannel`, head read only). Anthropic and Responses stream transformers exist but were not read (`src/providers/anthropic/stream-transformer.ts`, `src/protocols/responses/stream-transformer.ts`): UNVERIFIED. |
| When detection fails | Any tier exception marks the unit degraded; earlier coverage is kept (`hider/pipeline.py` `Pipeline.detect`). The gateway refuses a degraded request with 503 and never contacts upstream (`hider/proxy.py` `redact_payload`, `DEGRADED_STATUS`). A known vault value surviving redaction is also a 503. Malformed spans from any tier are dropped before rewriting (`hider/pipeline.py` `_sane`). Tier 3 non-JSON output is a hard failure, a non-verbatim quote is discarded (`hider/llm_tier.py` module docstring). | Detector unreachable, timeout or non-2xx: `detectPII` throws, the pipeline wraps it in `PrivacyPipelineDetectionError`, and the route answers 503 "Detection service unavailable" without forwarding (`src/pii/detect.ts` `detectPII`; `src/privacy/pipeline.ts`; `src/routes/openai.ts` `respondDetectionError`). `/api/mask` answers 503 on either stage failing (`src/routes/api.ts`). At startup the proxy exits if the detector's `/health` never answers (`src/index.ts` `validateStartup`). Secrets detection is in-process regex and is not wrapped in that try (`src/privacy/pipeline.ts`); an exception there would reach Hono's generic 500 handler (`src/index.ts` `app.onError`): UNVERIFIED, no such path was traced. Partial-coverage cases that do not fail: secrets beyond `max_scan_chars` are not scanned (`config.example.yaml`); GLiNER out-of-range spans are dropped silently (`gliner_layer.py`). Route mode forwards unmasked PII to the local model and only detection, not masking, runs (`src/privacy/pipeline.ts`, `config.mode === "mask"` branch). |
| Secrets: destroyed or kept | Destroyed. A secret type is replaced by `<REDACTED:TYPE>`; the vault raises if asked to store one (`hider/pseudonym.py` `pseudonym`, `destroyed_marker`; `hider/pipeline.py` `redact`, `_is_secret`). On overlap a secret span outranks an identifier so a credential is never half-vaulted (`hider/pipeline.py` `resolve`). The AGENTS.md rule that a credential reaching tier 2 "gets vaulted, which is worse than a miss" is why five header and cookie shapes were moved to tier 1 (`AGENTS.md`, "Known gaps"). Secrets are not restorable in the response. | Kept for the request and restored. In `mask` mode the original secret is stored in the in-memory `PlaceholderContext.mapping` and written back into the model's answer wherever `[[API_KEY_SK_1]]` appears (`src/secrets/mask.ts`; `src/masking/restorer.ts` applies `secretsContext`; `src/masking/stream-restorer.ts` `secretsBuffer`). `action: block` returns 400 and forwards nothing; `route_local` sends the unmasked request to the local model (`src/secrets/request.ts`; `docs/concepts/secrets-detection.mdx`). The mapping is not written to the request log: the log stores masked content, entity type names and secret type names, and refuses masked content when secrets were detected but not masked (`src/logging/logger.ts` `RequestLog`; `src/logging/log-content.ts` `shouldLogMaskedContent`). Whether the mapping is retained anywhere else: UNVERIFIED beyond the files read. |
| What the log holds | Decision rows: counts per type and tier, substitute labels, timings, degraded flag, sweep hits, unknown labels; originals absent by design; `--log-request-bodies` debug switch off by default (`hider/proxy.py` module docstring, `handle`; `hider/pipeline.py` `redact` event comment). | Per-request rows in SQLite or Postgres with masked request text (first 20000 characters of scanned roles) when `log_masked_content` is on (default true), entity types, secret types when `log_detected_types` is on, retention 30 days (`src/logging/logger.ts`; `src/logging/log-content.ts`; `config.example.yaml`). |
| Request formats masked | OpenAI chat `messages[].content` (string or text parts) and legacy `prompt` (`hider/proxy.py` `_collect_texts`). Separate paths for JSON exports and Elasticsearch pages (`hider/jsonscrub.py`, `hider/elastic.py`), not compared here. | OpenAI Chat Completions, Anthropic Messages including `system`, `thinking` and `tool_result` blocks, and the Responses API (Codex) via a generic key-based walker (`src/masking/extractors/openai.ts`, `anthropic.ts`, `responses.ts`). |
| Thread model | Redaction is serialised under one lock because the pipeline, vault and classifier are shared (`hider/proxy.py` `_redact_lock`; `AGENTS.md` "Thread safety"). | Contexts are per request and the detector serialises GLiNER inference under its own lock (`gliner_layer.py` `_infer_lock`); the Bun side has no shared masking state found. |

### Masking, for support logs going to an LLM

| Aspect | Leans | Because |
|---|---|---|
| Readability of the masked log to the model | Hider | Shape-preserving pseudonyms keep an IP an IP and a path a path (`hider/pseudonym.py` `_shape`); PasteGuard flattens everything to `[[TYPE_N]]` (`src/masking/placeholders.ts`). Hider's utility eval measured no accuracy loss on its excerpt (`README.md` lines 312 to 314, not re-run). |
| Cross-line and cross-request correlation | Hider | HMAC-keyed vault with casefolding and shared tenant ordinals (`hider/pseudonym.py`); PasteGuard's context is per request and exact-string (`src/masking/context.ts`, `src/privacy/pipeline.ts`). |
| Credential handling | Hider | Destroyed and never restorable (`hider/pseudonym.py` `pseudonym` raises); PasteGuard restores the secret into the answer by default (`src/masking/restorer.ts`). |
| Fail-closed on detector trouble | Both, Hider stricter | Both answer 503 without forwarding (`hider/proxy.py`; `src/routes/openai.ts`). Hider also refuses on a surviving known value and has no scan-length cap; PasteGuard stops scanning secrets at 200000 characters (`config.example.yaml`). |
| Restoring into tool calls and Anthropic blocks | PasteGuard | Restores tool-call arguments, `tool_use.input` and Responses API items, streamed too (`src/masking/extractors/*.ts`; `src/providers/openai/stream-transformer.ts`); Hider restores message content only (`hider/proxy.py` `detokenize_response`, `_rewrite_stream`). |
| Streaming lag | Hider, by its own measurement | Prefix-set holdback with measured mean lag about 2 characters (`hider/proxy.py` `HoldbackDetokenizer`; `README.md` line 793). PasteGuard holds from any `[` that could open a placeholder (`src/masking/placeholders.ts`); no measurement found. |
| Provider coverage | PasteGuard | OpenAI, Anthropic, Codex Responses (`src/routes/`); Hider is OpenAI chat and completions only (`hider/proxy.py` `_collect_texts`). |
| Data at rest in the gateway | Hider | Decision log holds substitutes only (`hider/pipeline.py` `redact`); PasteGuard stores masked request text in a database by default (`config.example.yaml` `log_masked_content`). Both keep originals out of the log. |
| Unknown or invented labels in the answer | Hider | Reported in a header and the log (`hider/proxy.py` `_handle`); PasteGuard leaves them unchanged without reporting (`src/masking/context.ts` `restorePlaceholders`). |

### Not verified in these two sections

- Nothing was run: no Hider test, eval or proxy, no PasteGuard test,
  benchmark, detector or container. Every behaviour above is read from
  source.
- Hider's quoted figures (99.76%, 99.65%, 0.0%, utility accuracy, streaming
  lag) are from `README.md` and were not reproduced.
- PasteGuard publishes no accuracy figures in the clone; GLiNER's recall on
  log-shaped text is unknown.
- Presidio defaults were settled by reading Presidio 2.2.366 in Hider's
  `.venv` (not by running): `PatternRecognizer` matches case-insensitively,
  `PhoneRecognizer` defaults to eight regions, the stock email pattern is
  Unicode-aware, and the IPv6 pattern covers compressed forms. The rows
  above were updated accordingly.
- PasteGuard's Anthropic and Responses stream transformers, and the body of
  `src/routes/anthropic.ts`, `codex.ts` and `openai-responses.ts`, were not
  read; the OpenAI route stands in for them.
- Whether any PasteGuard code path retains the placeholder mapping (and so
  the original secrets) beyond the request's memory. The logger does not
  store it, but not every module was read.
- Whether a thrown error in PasteGuard's in-process secrets pass reaches
  Hono's 500 handler rather than a 503.

## Remaining comparisons: integration, performance, stack fit, licence

Same rules as the sections above: read from source, nothing run, Hider paths
relative to the Hider root, PasteGuard paths relative to the clone, and
anything not confirmable marked UNVERIFIED. Dependency licences were read
from the `METADATA` files in Hider's `.venv` (not run).

### 1. Integration: what each side can sit in front of

| Surface | Hider | PasteGuard |
|---|---|---|
| OpenAI Chat Completions proxy | Yes: any `messages[].content` string or text part, plus legacy `prompt`; response `choices[].message.content` and `choices[].text` detokenised; any path is forwarded to the upstream base (`hider/proxy.py` `_collect_texts`, `detokenize_response`, `make_server` `do_POST`). | Yes: `POST /openai/v1/chat/completions` with Zod validation, tool-call arguments restored (`src/routes/openai.ts`; `src/masking/extractors/openai.ts`). |
| OpenAI Responses API | No handling of `input` or `instructions` in `_collect_texts` (`hider/proxy.py`). | Yes: `/openai/v1/responses` via the generic key-walker extractor (`src/routes/openai-responses.ts`; `src/masking/extractors/responses.ts`; `docs/use-cases/apps.mdx`). |
| Anthropic Messages API | No: the request's top-level `system` and `tool_result` blocks are not collected, and the response reader expects `choices` (`hider/proxy.py` `_collect_texts`, `detokenize_response`). | Yes: `POST /anthropic/v1/messages`, `system`, `text`, `thinking`, `tool_result` blocks, `tool_use.input` restored (`src/routes/anthropic.ts`; `src/masking/extractors/anthropic.ts`). |
| Codex CLI (ChatGPT-login backend) | No. | Yes: `/codex/*`, masking on `/codex/responses`, other Codex endpoints proxied (`src/routes/codex.ts`; `docs/api-reference/codex.mdx`). |
| Claude Code | As a launcher, not a proxy: `hider ask` runs Claude Code headless in `--restricted` mode with only Read, Grep and Glob over an obfuscated file; `es-research` launches it with one MCP server and an allowlisted environment (`README.md` lines 438 to 492 and 493 to 600; `hider/research.py`; `hider/esmcp.py` `claude_env`). | As a proxy: `ANTHROPIC_BASE_URL=http://localhost:3000/anthropic claude` (`docs/use-cases/coding-tools.mdx`). A default allowlist entry exempts the Claude Code system-prompt sentence from masking (`src/config.ts` `DEFAULT_ALLOWLIST`). |
| Other coding agents and apps | None documented beyond the OpenAI-compatible base URL (`README.md` lines 387 to 396). | Cursor, any agent honouring `OPENAI_API_BASE` or `ANTHROPIC_BASE_URL`, Open WebUI, LibreChat, LangChain, LlamaIndex, OpenAI and Anthropic SDKs (`docs/use-cases/coding-tools.mdx`, `api-integration.mdx`, `apps.mdx`). |
| Upstream providers | Whatever `--upstream` points at; the caller's Authorization header passes through and the gateway holds no credentials (`hider/proxy.py` module docstring; `hider/cli.py` `proxy`). | OpenAI, Azure OpenAI, OpenRouter, LiteLLM, Together, Groq, Anthropic, Codex; optional fallback API key per provider (`docs/configuration/providers.mdx`; `src/config.ts`). |
| Local model routing | No. Hider always masks and forwards. | Route mode: requests with findings go to Ollama or any OpenAI-compatible local server (vLLM, llama.cpp, LocalAI) unmasked (`docs/concepts/route-mode.mdx`; `src/providers/local.ts`, not read; `src/privacy/pipeline.ts`). |
| Standalone mask endpoint | No HTTP endpoint; the CLI has `redact FILE` and `scrub-json` (`hider/cli.py` lines 995 and 1032). | `POST /api/mask` with `startFrom` counters and `detect` selection (`src/routes/api.ts`; `docs/api-reference/mask.mdx`). |
| Browser chat (ChatGPT, Claude, Gemini) | No. | Experimental extension for Chrome and Firefox calling `/api/mask`; its source is not in this repo and "is planned to be published" (`docs/use-cases/chat.mdx`). |
| Files and exports | `redact FILE` for log bundles; `merge-csv` and `scrub-json` for JSON exports with `--term` seeds and prefix wildcards; loopback web UI on 127.0.0.1:8790 wrapping get, obfuscate, ask, unmask; `unmask` for answers (`hider/cli.py`; `hider/jsonscrub.py`; `hider/webserver.py`; `README.md` lines 438 to 491). | No file or export path. The only inputs are HTTP request bodies (`src/routes/`). |
| Live Elasticsearch / Kibana | Yes: a broker process owning one off-the-record Chrome signed in to Kibana via Playwright, an MCP server inside it with four tools (`es_schema`, `es_search`, `es_count`, `es_aggregate`), a closed query grammar, per-case vaults, a prompt gate, and an offline `es-eval` with a stub Kibana (`hider/esbridge.py`, `hider/esmcp.py`, `hider/esquery.py`, `hider/elastic.py`, `hider/eseval.py`; `docs/es-bridge-design.md`; `README.md` lines 493 to 600). | No counterpart. No MCP server, no data-source connector, no query grammar found in `src/`. |
| Dashboard and request history | Decision log file, rotated at 50 MiB, plus `/healthz` counters (`hider/proxy.py` module docstring, `do_GET`). No UI for it. | Web dashboard over SQLite or Postgres with masked request text, entity types, latency, retention (`src/routes/dashboard.tsx`, not read; `src/logging/logger.ts`; `docs/configuration/logging.mdx`; `docs/api-reference/dashboard-api.mdx`). |
| Site configuration | `hider.local.json` or `HIDER_LOCAL` (vendor hosts, path structure, Elasticsearch site map), `HIDER_PROFILE` regex profiles, `HIDER_VAULT_KEY` (`hider/localcfg.py`; `hider/profiles.py`; `hider/pseudonym.py` `ENV_KEY`). | `config.yaml` with `${VAR}` substitution, allowlist, denylist, scan roles, phone regions, entity lists (`src/config.ts`; `config.example.yaml`). |
| Deployment | `pip install -r requirements.txt`, then `python -m hider proxy` or `serve`; optional extras per tier (`AGENTS.md` "Running things"; `pyproject.toml`). No container in the repo. | One Docker image with proxy and detector under supervisord; detector alone as a build target; Compose file (`docker/Dockerfile`; `docker/supervisord.conf`; `docker-compose.yml`). |

### 2. Performance: claims and how they were measured

| | Hider | PasteGuard |
|---|---|---|
| Latency or throughput claim | Tier 1 about 1.2 ms per line, single-threaded, 32 recognizers; tier 2 classifier about 0.6 ms per line over the residue; spaCy about 3.9 ms per line, marked stale and not reproducible on this commit (`README.md` lines 145, 146, 166 to 175). A stated regression from about 136 µs to 1.2 ms per line as recognizers were added, with `phonenumbers` named the most expensive (`README.md` lines 1015 to 1024). Gateway redaction is serialised under one lock, so "a bundle of a few thousand lines now costs seconds" (`README.md` lines 826 to 832 and 1021 to 1023). | None found. `README.md`, `docs/**/*.mdx` and the source were searched for latency, throughput, ms, RAM, memory, MB, GB and model size; the hits were timeouts and a dashboard field, not claims. |
| How measured | `python -m hider eval` on a 5,121-line, 711,858-character generated bundle; per-tier `elapsed_s` and `chars_offered` accumulated in `Pipeline.stats` (`README.md` lines 127 to 130; `hider/pipeline.py` `TierStat`, `Pipeline.detect`). The streaming lag figure (mean about 2 characters) comes from a named test (`README.md` lines 790 to 795). Not re-run here. | Per request, `scanTimeMs` is recorded for PII detection and `latency_ms` is stored in the request log (`src/pii/detect.ts` `PIIDetectionResult`; `docs/api-reference/dashboard-api.mdx` line 43). The accuracy benchmark reports no timing (`benchmarks/pii-accuracy/run.ts` `printReport`). |
| Model size | Tier 2 classifier: `LogisticRegression` over about 500 generated sentences, trained in-process "well under a second", cached per process; no size figure given (`hider/classifier.py` `train`; `hider/pipeline.py` `ManagedNerTier` docstring). spaCy alternative: `en_core_web_sm` 3.8.0 wheel (`requirements-ner.txt`); size not stated in repo, UNVERIFIED. | `urchade/gliner_multi_pii-v1` baked into the image at build (`docker/Dockerfile` `detector-builder` stage). Parameter count and on-disk size are not stated anywhere in the clone: UNVERIFIED. Encoder and tokenizer it references: UNVERIFIED (not in clone; `docs/configuration/gliner.mdx` notes offline deployments "must also cache any tokenizer or encoder referenced by `gliner_config.json`"). |
| Memory | No figure in `README.md` or `AGENTS.md`. | No figure. Inference is CPU torch (`docker/Dockerfile` line 49), serialised under one lock, with an LRU cache of 4096 windows (`detector/detector/gliner_layer.py` `_infer_lock`, `MODEL_INFERENCE_CACHE_SIZE`). Route mode docs say "Have local GPU resources" for the local LLM, not for the detector (`docs/concepts/route-mode.mdx`). |
| Startup | Tier 2 trains at first use (`hider/classifier.py` `get_trained`). | Detector loads the model before serving; proxy waits up to 180 s for `/health`; "the first start loads the detection model and can take a little longer" (`detector/detector/app.py` `lifespan`; `src/index.ts` `validateStartup`; `docs/installation.mdx`). Container health check start period 60 s for the all-in-one, 40 s for the detector (`docker/Dockerfile` `HEALTHCHECK`). |
| Timeouts and caps | Upstream 120 s (`hider/proxy.py` `UPSTREAM_TIMEOUT_S`). No scan cap. | Detector call 30 s, request 600 s, health 5 s, startup 180 s; secrets scan capped at 200000 characters; GLiNER windows of 384 word tokens (`config.example.yaml`; `src/constants/timeouts.ts`; `gliner_layer.py` `_max_tokens`). |
| Concurrency | Redaction serialised; upstream call and stream rewrite concurrent; `ThreadingHTTPServer` (`hider/proxy.py` `_redact_lock`, `make_server`; `AGENTS.md` "Thread safety"). | Bun handles requests concurrently; GLiNER inference serialised in the detector (`gliner_layer.py` `_infer_lock`). |
| Cost metering | Tier 3 token usage metered per backend and written to reports (`hider/llm_backend.py` `UsageMeter`; `hider/pipeline.py` `LlmPassTier.to_dict`). | Not applicable; no paid tier. Provider token usage is not read in the files examined: UNVERIFIED. |

### 3. Stack fit: what could move into Hider

PasteGuard is 847 lines of Python in `detector/detector/` and everything else
is TypeScript on Bun (`package.json`; `wc` in the inventory). Hider is
Python 3.11 with Presidio and scikit-learn in the core and standard library at
the HTTP boundary (`pyproject.toml`; `AGENTS.md` "Standard library at the
boundary").

**Python, could move as code** (all Apache-2.0, see section 4):

| PasteGuard file | What it is | Fit in Hider |
|---|---|---|
| `detector/detector/deterministic.py` | Pure functions: regex candidates for email, IPv4, IPv6, IBAN, EU VAT, Chinese RIC, credit card, phone, each gated by `python-stdnum`, `ipaddress` or `phonenumbers`; priority-ordered overlap acceptance. No FastAPI or model imports. | Each function could become a `LocalRecognizer` in `hider/recognizers.py` reporting a new label; the checksum gating is the part Hider lacks. New dependency: `python-stdnum` (not in Hider's `.venv`). `phonenumbers` is already present via Presidio (`.venv/.../phonenumbers-9.0.42.dist-info`). A new entity type needs a template line and a cassette re-record (`AGENTS.md` "Known gaps"). Card, IBAN and VAT are rare in support logs, so this is low weight. |
| `detector/detector/entities.py`, `merge.py` | `Span` dataclass, half-open overlap, deterministic-wins merge with fragment subtraction. | Hider already has `Span`, `resolve` and `residue_segments` (`hider/pipeline.py`). Only the fragment-subtraction idea (keep the uncovered parts of a fuzzy span) is new; Hider drops the whole losing span. |
| `detector/detector/gliner_layer.py`, `semantic_backend.py` | GLiNER loading, per-label floors, overlapping windows, inference lock, checkpoint validation. | Could be a third tier 2 backend behind Hider's `Tier` protocol next to `classifier` and `spacy` (`hider/pipeline.py` `Tier`; `hider/ner.py`). It brings `torch`, `transformers`, `gliner` and `huggingface-hub` (`detector/pyproject.toml`), which would have to be an optional extra like `ner`, since "nothing in the core path may import an optional extra at module load" (`AGENTS.md` "Dependencies"). It would add LOCATION, which Hider declines by design (`hider/ner.py` docstring), and would need Hider's log-structure guards applied to its spans (`hider/pipeline.py` `ManagedNerTier.detect`). |
| `detector/detector/app.py`, `smoke.py` | FastAPI wrapper and image smoke test. | Not needed. Hider calls tiers in-process and takes no web framework. |
| `detector/tests/test_deterministic.py` and siblings | pytest suites. | Portable as test ideas; the `/analyze` and backend tests target the service. Not read. |

**TypeScript, would need rewriting** (the regexes themselves are portable as
text; the surrounding code is not):

| PasteGuard file | What it is | Fit in Hider |
|---|---|---|
| `src/secrets/patterns/*.ts` | Ten secret regexes with a registry. | The three Hider lacks (`sk[-_]`, `*_SECRET\s*[=:]`, `PASSWORD\s*[=:]`) are one `Pattern` each in `hider/recognizers.py`; the rest duplicate rules Hider has (section "Detection"). Add the adversarial case first (`AGENTS.md` "Working rules"). |
| `src/masking/conflict-resolver.ts` | Presidio-style overlap resolution. | Hider uses Presidio itself and its own `resolve`; nothing to take. |
| `src/masking/context.ts`, `placeholders.ts`, `service.ts`, `stream-restorer.ts` | Per-request placeholder map, `[[TYPE_N]]`, stream buffering. | Hider's vault and `HoldbackDetokenizer` cover the same ground with stronger properties (section "Masking"); nothing to take. |
| `src/masking/extractors/anthropic.ts`, `responses.ts` | Anthropic Messages and Responses API text extraction, insertion and restoration, including tool inputs. | This is the gap in Hider's proxy (`hider/proxy.py` `_collect_texts`). The traversal logic would be rewritten in Python; the list of fields and roles is the reusable knowledge. |
| `src/pii/detect.ts` (allowlist, denylist, scan roles) | Operator pattern lists and role filtering. | Hider has additive profiles only (`hider/profiles.py`); an allowlist is a precision tool Hider does not have. Small to write in Python. |
| `src/providers/*/stream-transformer.ts`, `src/protocols/responses/` | SSE rewriting per provider shape. | Would be rewritten; Hider's `_rewrite_stream` handles OpenAI chat deltas only. |
| `benchmarks/pii-accuracy/run.ts` | Benchmark runner. | Hider has `hider/evaluate.py`; not needed. |
| `benchmarks/pii-accuracy/test-data/*.yaml` | 131 labelled cases in nine languages. | Reusable as data for an adversarial or multilingual check, under Apache-2.0 terms. Entity set overlaps Hider's only on EMAIL, IP, PHONE, PERSON. |

**Setup Hider does not need:** Bun and Hono (`package.json`), Zod request
and config validation (`src/config.ts`), YAML config (`config.example.yaml`),
Tailwind and `hono-tailwind` (`package.json`), the dashboard and its SQLite or
Postgres store via `kysely` and `pg` (`src/logging/`, `src/views/`), Docker
and supervisord (`docker/`), Mintlify docs (`docs/mint.json`), Biome
(`biome.json`), route mode and local provider clients (`src/providers/local.ts`),
the browser-extension endpoint and `X-PasteGuard-Source` header
(`docs/api-reference/mask.mdx`), and the UTF-16 offset mapper, which exists
only because the caller is JavaScript (`detector/detector/app.py`
`_utf16_mapper`).

### 4. Licence: Apache-2.0 into an MIT project

This is a reading of the licence texts, not legal advice.

| | Hider | PasteGuard |
|---|---|---|
| Project licence | MIT, "Copyright (c) 2026 Kirill Kuklin" (`LICENSE`; `pyproject.toml` `license = "MIT"`; `README.md` line 1106). | Apache License 2.0, "Copyright 2026 Stefan Gasser" (`LICENSE` line 178; `package.json` `"license": "Apache-2.0"`; `detector/pyproject.toml` `license = { text = "Apache-2.0" }`). |
| NOTICE file | None. | None in the clone (`ls` of the root). So clause 4(d) imposes nothing today. |
| Per-file headers | None seen in the files read. | None seen in the files read; the only copyright statement is `LICENSE` line 178. |
| Core dependency licences | `presidio-analyzer` 2.2.366 MIT; `scikit-learn` 1.9.1 BSD-3-Clause; `phonenumbers` 9.0.42 Apache-2.0; `spacy` 3.8.18 MIT (all from `.venv/lib/python3.11/site-packages/*.dist-info/METADATA`). | `gliner` 0.2.30 is Apache-2.0 and `python-stdnum` 2.2 is LGPLv2+ (PyPI JSON records for `gliner` and `python-stdnum`, fetched 2026-11-07 into `/tmp/pg-licences-*/`). The `gliner` record requires `torch>=2.0.0`, `transformers>=4.51.3,<5.23.0`, `huggingface_hub`, `safetensors`, `sentencepiece`. `torch`, `transformers`, `fastapi`, `huggingface-hub`, `hono`, `zod`, `kysely`, `pg`: UNVERIFIED (not fetched). |
| Model weights | `en_core_web_sm` 3.8.0: licence not stated in the Hider repo, UNVERIFIED. The default classifier is trained from code in the repo, so it carries the repo's MIT licence (`hider/classifier.py`). | `urchade/gliner_multi_pii-v1`: `license: apache-2.0` in the model card front matter (Hugging Face `README.md` of the model, fetched 2026-11-07). Fine-tuned from `urchade/gliner_multi-v2.1` on the dataset `urchade/synthetic-pii-ner-mistral-v1`; card languages en, fr, de, es, pt, it. The card lists `organization` among the labels the model answers, which PasteGuard never requests (`detector/detector/gliner_layer.py` `_LABELS`). Base encoder, parameter count and on-disk size are not in the card: UNVERIFIED. Licences of the base model and of the training dataset: UNVERIFIED (not fetched). |
| Datasets | Corpora are generated from `templates/` at run time and are MIT with the repo (`README.md` lines 13 to 16). | `benchmarks/pii-accuracy/test-data/*.yaml` is part of the repo and therefore Apache-2.0. No external dataset is referenced in the clone. |

**What copying PasteGuard code into Hider would require**, from `LICENSE`
section 4 of the clone (lines quoted in the inventory read):

- Keep the copied files under Apache-2.0. MIT and Apache-2.0 are compatible
  in this direction (Apache code inside an MIT-licensed project), but the
  Apache-licensed portions do not become MIT.
- Ship a copy of the Apache License 2.0 alongside Hider's MIT `LICENSE`
  (clause 4(a)), for example as `LICENSE-APACHE` or a `THIRD_PARTY_NOTICES`
  file, and state in `README.md` which files it covers.
- Retain the copyright notice "Copyright 2026 Stefan Gasser" for the copied
  parts (clause 4(c)).
- Mark modified files with a prominent notice that they were changed
  (clause 4(b)). Since PasteGuard has no per-file headers, a header added to
  each ported file naming the source file and commit `d8bbb3d` would satisfy
  both 4(b) and 4(c).
- Nothing is owed for a NOTICE file because none exists (clause 4(d)).
- Section 3 grants a patent licence that terminates on patent litigation;
  this does not restrict ordinary use.
- Porting ideas rather than code (for example, re-expressing the three
  missing secret regexes as Hider `Pattern`s written independently) carries
  no notice obligation; copying the regex strings verbatim arguably does, so
  the safer course is to treat any verbatim regex as copied code.
- Using the PasteGuard benchmark YAML as a Hider test fixture is a copy of
  Apache-2.0 material and needs the same notices.
- `python-stdnum` is LGPLv2+ (PyPI record). Importing it as an unmodified
  library from MIT code is the ordinary LGPL use and does not change Hider's
  licence; copying or modifying its source would bring in LGPL terms for
  that code. Not legal advice.
- One observation for symmetry: `src/masking/conflict-resolver.ts` says it is
  "based on Microsoft Presidio's logic" and links the Presidio source, but the
  file carries no Presidio (MIT) copyright notice. Hider depends on Presidio
  directly and is unaffected.

### Integration, performance, stack and licence, for support logs going to an LLM

| Aspect | Leans | Because |
|---|---|---|
| Sitting in front of an OpenAI chat client | Both | Both proxy it; Hider additionally refuses on a surviving known value (`hider/proxy.py`), PasteGuard additionally restores tool-call arguments (`src/masking/extractors/openai.ts`). |
| Sitting in front of Claude Code, Cursor, Codex, Anthropic SDK | PasteGuard | Anthropic Messages, Responses and Codex routes exist (`src/routes/`); Hider's proxy reads OpenAI shapes only (`hider/proxy.py` `_collect_texts`, `detokenize_response`). |
| Log bundles as files, JSON exports, CSV merges | Hider | `redact`, `scrub-json`, `merge-csv`, web UI (`hider/cli.py`; `hider/jsonscrub.py`; `hider/webserver.py`); PasteGuard has no file input (`src/routes/`). |
| Live log search (Elasticsearch, Kibana) | Hider | Bridge, MCP tools, query grammar, case vaults (`hider/esbridge.py`, `hider/esmcp.py`, `hider/esquery.py`); no PasteGuard counterpart. |
| Running Claude Code safely over masked data | Hider | Restricted launch, allowlisted environment, prompt gate (`hider/research.py`; `hider/esmcp.py`); PasteGuard relies on proxying and a system-prompt allowlist (`src/config.ts`). |
| Measured speed | Hider | Per-tier ms-per-line figures from a named eval run (`README.md` lines 145 to 146); PasteGuard publishes none. |
| Likely footprint | Hider | scikit-learn and Presidio only in the core (`pyproject.toml`); PasteGuard needs CPU torch and a transformer checkpoint (`detector/pyproject.toml`; `docker/Dockerfile`). Actual sizes UNVERIFIED on both sides. |
| Operator-friendly deployment | PasteGuard | One Docker image, YAML config, dashboard (`docker/Dockerfile`; `config.example.yaml`); Hider is `pip install` plus CLI flags and a JSON side file (`AGENTS.md`; `hider/localcfg.py`). |
| Ease of borrowing code | Mixed | PasteGuard's Python detector is small and dependency-light apart from GLiNER (`detector/detector/deterministic.py`); everything else is TypeScript and would be rewritten. Apache-2.0 notices are required for any verbatim copy (`LICENSE` section 4). |
| Licence friction | Low either way | Apache-2.0 into MIT needs a licence copy and notices, no copyleft (`LICENSE` section 4); model-weight terms UNVERIFIED. |

### Not verified in this section

- Nothing was run, downloaded or installed. Dependency licences come from
  `METADATA` files already present in Hider's `.venv`.
- Licences of `torch`, `transformers`, `fastapi`, `huggingface-hub`, `hono`,
  `zod`, `kysely`, `pg`: not fetched. (`gliner`, `python-stdnum` and the
  default model are now settled above.)
- Size and base encoder of `urchade/gliner_multi_pii-v1`, and everything
  about `gliner_small-v2.1`, the base model `gliner_multi-v2.1` and the
  training dataset: not fetched.
- Licence and size of spaCy `en_core_web_sm` 3.8.0: not stated in the Hider
  repo.
- PasteGuard's Docker image size and runtime memory: no figure anywhere.
- `src/providers/local.ts`, `src/routes/dashboard.tsx`, `src/views/`,
  `detector/tests/`: listed, not read.
- Whether PasteGuard reads provider token usage from responses.
- Hider's own throughput figures were not re-measured; the README itself
  calls the spaCy figure stale.
- The legal reading of Apache-2.0 section 4 is mine, from the licence text,
  and is not legal advice.
