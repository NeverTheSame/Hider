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

| Task | Start here | Read first |
|---|---|---|
| A shaped identifier is missed or over-matched | `hider/recognizers.py`, add a case to `hider/adversarial.py`, test in `tests/test_recognizers.py` | docs/detection-gaps.md |
| A customer path segment missed or a system path over-matched | `recognizers.CustomerPathRecognizer`; structure, system roots and extensions live only in `hider/paths.py` (site additions: `path_structure` in `hider.local.json`); add a `path-*` case to `hider/adversarial.py` or a line to `PATH_LOOKALIKES`, tests in `tests/test_paths.py` | docs/detection-gaps.md |
| A new entity type | `hider/entities.py` first (the contract), then the recognizer, then `pseudonym._shape` if it needs a shaped label | docs/detection-gaps.md |
| Free-text names missed | `hider/classifier.py` (training grammar and features). Keep the train/eval vocabulary disjoint; `test_training_vocabulary_is_disjoint_from_the_eval_vocabulary` guards it | docs/detection-gaps.md |
| Tier 3 prompt or parsing | `hider/llm_tier.py`. Changing the instruction text changes `PROMPT_VERSION`; committed cassettes stop matching and must be re-recorded | README.md |
| A new LLM provider | `hider/llm_backend.py`: implement `complete(prompt) -> str`, split with `split_prompt`, feed a `UsageMeter`, raise `BackendError` on any failure. Wire it in `cli._real_backend` and `_add_llm_flags` | README.md |
| Gateway behaviour | `hider/proxy.py`. The request path is `handle -> _handle -> redact_payload (tiers, then sweep) -> forward / forward_stream -> detokenize`. Tests use a stub upstream in `tests/test_proxy.py` | README.md |
| Eval metrics or gates | `hider/evaluate.py` (recall, precision, adversarial, injection), `hider/utility.py` (answer accuracy raw vs redacted) | docs/detection-gaps.md |
| JSON exports and the web UI | `hider/jsonscrub.py`, `hider/webserver.py` (single-file page, stdlib server), `hider/research.py` (Claude Code bridge) | docs/es/readability.md (jsonscrub's ordinary-word rule) |
| Site-specific patterns | Never in the repo. `templates/profile.example.json` and `HIDER_PROFILE`; see `hider/profiles.py` | README.md |
| Live Elasticsearch research | `hider/elastic.py` (site map, response scrubber, case vault), `hider/esquery.py` (closed grammar, compiler, `ORACLE_CASES`), `hider/eseval.py` (synthetic documents, stub Kibana, `es-eval`), `hider/esreview.py` (`es-review`: a case read back from its decision log), `hider/esutility.py` (the operator-utility section of `es-eval`: scripted investigations scored answered/wrong/blocked), `hider/esbridge.py` (the Kibana session: a long-lived broker process owning one off-the-record Chrome via Playwright, async-search protocol, every malformed reply a refusal, decision log), `hider/esmcp.py` (the MCP server inside the broker: cases and tokens, the four tools, transport guards, the Claude Code launch). Design: `docs/es-bridge-design.md`. Site map example: `templates/elastic.example.json`; the real one is `elastic` in `hider.local.json` or `HIDER_ELASTIC` | docs/es-bridge-design.md, then the docs/es/ file for the area: grammar.md, text-groups.md, session.md, vocabulary.md, readability.md, review-and-seed.md, split-tenant-and-empty.md, preflight-utility-gates.md |

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
.venv/bin/python -m hider es-eval                # Elasticsearch core: leaks, refusals, oracle cases, no cluster
.venv/bin/python -m hider es-smoke --stub        # one query through Chrome against a synthetic Kibana
.venv/bin/python -m hider es-smoke --cluster emea --query '{"time_range": {"gte": "now-7d", "lte": "now"},
    "size": 0, "filters": [{"field": "job.status", "op": "eq", "value": "Failed"}],
    "aggs": {"errs": {"type": "text_groups", "field": "job.status_message", "size": 10}}}'
                                                 # any grammar query, same checks, summary of counts only
.venv/bin/python -m hider es-login --cluster emea # start the bridge, sign in (headed, once per bridge),
                                                 # then build the name vocabulary: minutes on a large estate
.venv/bin/python -m hider es-research --case c1 --term "<customer>"   # Claude Code, bridge tools only
.venv/bin/python -m hider es-research --stub --case demo --prompt "..."  # the same on a synthetic Kibana
.venv/bin/python -m hider es-preflight --cluster emea  # one read-only report: what stays readable on this
                                                 # cluster, which declared limit each miss is, how big, what to do
.venv/bin/python -m hider es-seed --case c1 --term "JOB_NAME=<job>"  # add a name to the open case; the session goes on
.venv/bin/python -m hider es-review --case c1    # read a case back: numbers, phrase spend, probing signals (human-only)
.venv/bin/python -m hider.esbuildlog             # read the vocabulary build log back: slices, seconds by age of range, failures, human-only
.venv/bin/python -m hider es-logout              # stop the bridge; the Kibana session ends with it
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
  (spaCy), `llm` (openai, anthropic), `es` (playwright, for the live Kibana
  session only). Nothing in the core path may import an optional extra at
  module load.

## Rules a change must not break

Each rule is one line: the rule, why, and what pins it. The history,
measurements, declared misses and reasoning behind every rule live in the
doc named in the heading; read it before changing that area. A declared
miss is a decision, not a bug: do not "fix" one without reading its doc.

### Detection (docs/detection-gaps.md)

- **Tier 1 owns every credential shape tier 2 could see** (URL userinfo, `Authorization` headers, cookies, AWS secret, PEM bodies, `sk_live_`-style keys, `*_SECRET=`, `password:`) - tier 2 labels high-entropy runs `ORGANIZATION` and *vaults* them, worse than a miss. Pin: assert the pipeline property (`Pipeline.redact`, value absent from output and `vault.entries`), not just the recognizer; `tests/test_recognizers.py`.
- **`EnvCredentialRecognizer` / `AwsSecretKeyRecognizer` read the key name as evidence and report only the value; the key name must end at the credential word** - keeps prose readable and `client_secret_expires_at:` out. Pin: `adversarial.CREDENTIAL_LOOKALIKES` (17 lines, 0 changed) and `adversarial.CREDENTIAL_LOOKALIKE_MISSES`.
- **`_NON_SECRET_VALUES` stays a short fixed list, never a dictionary** - every word added is a password that then leaks. Pin: `CREDENTIAL_LOOKALIKES`.
- **Vendor credential prefixes and Windows/Microsoft identifiers stay out of the generated corpus; new detector labels borrow an existing spec type via `detected_as`** - any template or generator change reshuffles the one RNG stream and invalidates `cassettes/utility-haiku-4-5-run1.jsonl` (live re-record). Pin: `vendor-*` cases, `test_every_spec_type_is_exercised_by_the_templates`.
- **Phone matching stays hard-gated to digits plus `+ - ( )` and spaces** - the raw matcher redacted 96 of 1,000 clean lines. Pin: fence tests in `tests/test_recognizers.py`.
- **The UNC pattern stays backslash-only** - `//host/users/...` is the tail of an ordinary URL. Pin: `tests/test_recognizers.py`.
- **One vendor list (`hider/vendors.py`), one `recognizers.FILE_EXT`; one path-structure list (`hider/paths.py`)** - jsonscrub and recognizers must agree; site additions go in `hider.local.json`, never the repo. Pin: lookalikes in the clean corpus, `adversarial.PATH_LOOKALIKES`, `tests/test_paths.py`.
- **A path's last segment is a file name, labelled whole or not at all** - `<Folder-03> payroll.xlsb` was a blind-test finding (14 of 75). Pin: `path-file-*` cases, `tests/test_paths.py`.
- **New lookalikes go in `PATH_LOOKALIKES` / `CREDENTIAL_LOOKALIKES`, not `templates/`** - fixed units outside the RNG stream. Pin: their own `eval` lines.
- **Tier 2 suppression rules only remove or narrow spans, never widen, never touch tier 1** (`in_structural_path_segment`, `in_dotted_chain` with its three-label floor, `LOG_VOCABULARY` trim) - monotonicity. Pin: intent tests in `tests/test_paths.py` and `tests/test_recognizers.py` (160-line grid).
- **`redact` (default `--ordinary-words on`) drops a tier 2 claim whose whole text the file also writes in lowercase as a free word (`pipeline.OrdinaryInFile` around tier 2: blank, bracket or quote before; blank or sentence punctuation after); an address, a login, a path segment and a hyphen-joined slug are not free words; tier 1 and `--term` are never touched; the gateway does not run it** - on real notes tier 2 made 231 of 336 replacements that hid nothing sensitive, 114 of them values the note itself wrote in lowercase. Pin: the `OrdinaryInFile` tests in `tests/test_cli.py`.
- **Do not close the dotted-organisation head leak by lowering the three-label floor** - trades a false positive for a real miss; it is the whole 99.65% vs 100% gap. Pin: adversarial cases on `Wood.Partners.Group`, `Newtonsoft.JsonSerializationException`.
- **Two over-destructions are intent** (every cookie value; any line that is only a 40+ char base64 run). Pin: intent tests.
- **Keep the train/eval vocabulary disjoint.** Pin: `test_training_vocabulary_is_disjoint_from_the_eval_vocabulary`.
- **`redact` sweeps every pseudonymised value across the whole file after the per-line pass, with `hider/sweep.py`, the function the gateway uses; there is no second sweep, secrets are never swept, each swept occurrence is an event with `tier: "sweep"`** - a value found on one line stayed readable on another. Pin: `test_redact_hides_a_value_on_the_line_where_it_stands_without_its_cue`, `test_redact_sweep_never_touches_a_secret`, `test_redact_and_the_gateway_sweep_with_one_function`.
- **`redact --term` labels each term `ORG_NAME` before the first line is read and claims it as a layer of its own between tier 1 and tier 2 (`pipeline.TermTier`), never before tier 1; a last pass (`sweep.TermReplacer`) replaces a term still readable in the finished text, inside a label only when that label kept the term from its original value; both hold with `--sweep off` and `--tier2 none`; any casing, any length, whole words only, the longer term wins, an empty term exits 2, each replacement is an event with `tier: "term"` and no event carries the term** - replaced before tier 1, a name inside an address, a login or a site URL broke the shape and left the rest of it readable (`anna.novak@<Org-01>.com`). Pin: the `test_redact_term_*` tests in `tests/test_cli.py`.
- **`redact --name-parts` (default on) reads the finished text after the sweep and the term pass, never before tier 1: each word of four or more letters of a multi-word `PERSON_NAME` the vault holds, not on `jsonscrub.ORDINARY_NAME_WORDS`, gets a label of its own from the vault and is replaced where it stands alone, with the sweep's matcher (`sweep.NamePartReplacer` over `Sweeper`, case-sensitive, whole words, never inside a label); a word the finished text also holds in lowercase, alone and outside every label, is left out before it gets a label (`--name-parts all` hides those too); each replacement is an event with `tier: "name_part"` and no event carries the word; the gateway does not run it** - a surname alone stayed readable after the full name was hidden, a pass before tier 1 would break shapes the way `--term` did, and on real notes 255 of 472 replacements were words of a capitalised pair tier 2 had taken for a person. Pin: the `test_redact_*part*` tests in `tests/test_cli.py` and the `NamePartReplacer` tests in `tests/test_sweep.py`.

### Elasticsearch research

Design: docs/es-bridge-design.md. `es-eval` runs 37 gates (28 + 9 MCP);
all pass, and a change that cannot keep them passing is a design
conversation. Add the oracle case before the rule (`esquery.ORACLE_CASES`,
as with `adversarial.CASES`).

#### Grammar and guessing (docs/es/grammar.md)

- **Every forbidden shape (wildcard, prefix, range, sort, terms include, scripts, raw DSL, literals, wrong-type labels) is refused with its declared code** - the grammar is what keeps a page safe. Gate: `oracle_all_refused`, `mcp_oracle_all_refused`.
- **Identifier fields take labels only.** Gate: `oracle_all_refused`.
- **`max_phrases` caps distinct phrases per query across filters and every aggregation at any depth** (default 8, ceiling 16) - else one `filters` aggregation counts a whole word list. Oracle: `phrase-flooded-filters-agg`.
- **`phrase_budget` caps distinct plain-word phrases per case** (default 150, ceiling 2000); `check_budget` runs last in `compile`; phrases are spent when a query is about to be sent and never refunded; reused and label-only phrases are free; the refusal depends only on counts - a refund would make a guess free. Gate: `phrase_budget_holds`.
- **`not` / `any_of` hold plain filters only, one level deep, in a query's `filters` only; every inner filter goes through `one_filter` with the outer position's name** - same rules, same refusal, no new guessing form. Pin: `test_a_refusal_inside_not_or_any_of_is_the_refusal_outside_word_for_word`, `COMPOUND_TWINS`, `COMPOUND_CASES`; gate `compound_forms_no_new_guesses`.
- **Zero-hit rule**: a phrase inside `not` is never zero-hit; rows using either form also log `unjudged_phrases` / `negated_phrases`. Pin: `esbridge._zero_hit_phrases` tests; `review_flags_guessing`.

#### text_groups (docs/es/text-groups.md)

- **Grouping happens after redaction, in the bridge, never in Elasticsearch** (`categorize_text` groups before redaction, so a hidden name would split groups). Gate: `text_groups_page_equivalent`.
- **No request reads more than `TEXT_GROUP_SAMPLE` (1,000) documents; nothing in a query shapes the read** (`sample`, `strata`, `interval`, `exact`, `newest` refused `raw_dsl`) - keeps a group read no wider than paging. Oracle: `esquery.TEXT_GROUP_CASES`; gate `text_groups_no_new_guesses`.
- **The group key is typeless (`<*>`), except codes after a code word and failure HRESULT/NTSTATUS** - a label's type depends on how it was first labelled, which split one message into two groups. Pin: `test_an_id_labelled_by_its_field_and_one_labelled_in_text_are_one_group`.
- **Only the groups leave; a group response makes no label usable.** A placeholder typed into a phrase is refused `bad_value`. Gate: `text_groups_page_equivalent`.
- **The sample is deterministic (no random sampling)** - otherwise re-asking reads new documents each time. Pin: the same question twice returns the same groups and counts (`tests/test_estextgroups.py`).
- **The reply says how far to trust itself** (`exact`, `sampled`, `coverage`, `margin` = max(binomial, scatter), `order_settled`, `covered`/`covered_share`, `unbucketed`). Pin: `tests/test_estextgroups.py`, `esutility` `week_census`, `tenant_day_census`.
- **A slow pass is split into newest-first window pieces, never refused on a predicted document count; only a read that covered nothing is refused `slow_read`** - a count does not predict wall time. Pin: week-in-pieces tests in `tests/test_estextgroups.py`, `esutility` `slow_week_census`.
- **One question's waiting is bounded to budget + one pass = four site limits** (`TEXT_GROUP_PROBE_FLOOR_S`, `TEXT_GROUP_MAX_TIMEOUTS`, `TEXT_GROUP_READ_BUDGET_LIMITS`) - unbounded it was an hour. Pin: `test_the_waiting_of_one_question_is_bounded_whatever_the_cluster_does`.
- **During a search the broker answers ping, accepts stop, tells others `busy`, pumps one vocabulary step per poll, and never touches the browser from the idle hook** - else the bridge looks dead and the cover falls behind. Pin: `test_before_a_long_read_left_the_broker_deaf`, `test_a_ping_is_answered_and_others_told_busy_during_a_long_read`, `test_the_vocabulary_top_up_survives_back_to_back_long_reads`.
- **A count or aggregation over a closed window whose one search hits the limit is read in newest-first pieces: summed when every aggregation adds up over time (count, date_histogram, filters, sum, min, max, value_count), a top-level terms merged (`exact`, or `bounded` with `doc_count_max`/`order_settled`/`unseen_max`, never more than `size` keys, only the merged keys marked shown), a terms under a date_histogram on aligned pieces, the newest piece alone with `not_split` otherwise (cardinality, percentiles, terms with a sub-aggregation); one search first with the full limit, so a read that fits is unchanged** - a slow 30-day histogram was refused with nothing and the model paid a full limit per guess. Pin: `tests/test_espieces.py`, `tests/test_espiecesterms.py`.
- **Callers wait `esbridge.search_wait_s`; the Claude Code launch sizes MCP tool timeouts to it (`esmcp.tool_wait_ms`)** - a 60 s client cut killed tool calls mid-read. Pin: `test_es_smoke_waits_out_the_longest_group_read`.

#### Session, broker, MCP (docs/es/session.md)

- **Only `esbridge` opens a connection, only from the broker's off-the-record Chrome; the SSO cookie never leaves it or reaches disk.** Every reply goes through `KibanaSession.parse_reply` (an expired session is a 200 login page). Pin: the stub enforces the same rules.
- **A hit's index is checked by its stream, also with Elasticsearch's own `partial-` or `restored-` prefix in front; shrunken, downsampled and failure-store indices stay refused.** Pin: `test_data_stream_backing_indices_are_checked_by_their_stream`.
- **A `bad_index` refusal records the shape of the refused names (`elastic.index_shape`: Elasticsearch's own prefixes as written, every other letter run `L`, digit run `9`) in the decision log, es-smoke and es-review; the refusal a model receives is unchanged** - a name is a customer or system identifier; the shape says which kind of index without saying which. Pin: `test_a_bad_index_refusal_keeps_its_message_and_carries_shapes_for_a_person`, `test_a_bad_index_refusal_is_logged_and_printed_as_shapes`, `test_a_bad_index_refusal_reaches_the_model_as_code_and_message_only`.
- **Clients tell busy from dead** (`broker_state`: `running`/`busy`/`absent`); es-logout never says "no bridge" while the socket exists - else the process keeps the Kibana session.
- **es-login has no wait ceiling by default; exit 0 serving, 1 failure or stall, 3 `--max-wait` reached while healthy.** Pin: `tests/test_esbridge.py` wait tests.
- **es-smoke `--query` sends the query as written through the same path; its default summary carries counts, types and field names, never a key, group text or value** (only `--show` / `--show-readable-names`). Pin: `test_print_smoke_summarises_a_grammar_query_as_counts_and_shows_texts_only_on_request`, `test_es_smoke_cli_takes_a_grammar_query_through_the_same_checks`.
- **The MCP server has four tools taking grammar keys only. Never add a tool that seeds a value, signs in or unmasks** - a value-to-label tool lets Claude mint a label for a guess and confirm it with a count. Gates: `mcp_protocol`, `mcp_requests_rejected`.
- **Claude Code gets an allowlisted environment (`esmcp.claude_env`); nothing goes on a denylist.** Gate: `mcp_launch_isolated`.
- **The prompt is gated (`esmcp.prompt_findings`), interactive hook ending `|| exit 2`** - a broken check blocks. Gate: `mcp_prompt_gate`.

#### Name vocabulary (docs/es/vocabulary.md)

- **The vocabulary is read once per cluster, at sign-in, in one-day slices, never inside a case and never from anything Claude says.** Gates: `vocabulary_build_in_budget` (0 wide pages), `vocabulary_slices_serve_early`.
- **With no `vocabulary` section the default is every learnable field (`learnable_rules`); `NO_VOCABULARY_TYPES`, shaped and glob fields are refused at load.** Gate: `default_map_names_hidden`.
- **Every field is counted before it is paged; a default-set field over the cap is left out and reported, a listed one refuses the slice; the 5% margin applies in whichever direction keeps the build running.** Gate: `over_cap_field_left_out`.
- **Nothing is learnt from a partial, failed or timed-out read of a kept field; the saved vocabulary stays exactly as it was.** Pin: `tests/test_elastic.py`, `tests/test_esbridge.py`.
- **One step per serve-loop iteration** (`submit`/`poll_once`/`release`) - the browser thread must keep answering. Gate: `vocabulary_slices_serve_early`.
- **Logs and the VOCAB line hold counts, requests, seconds and field names, never a name; every surface says what was left out and why** (`omitted`, `over_cap`, `frozen`, `stuck`). Gate: `over_cap_field_left_out`, `field_added_backfilled`.
- **Skip rules (`vocabulary_skip`) are a fixed list, not the system dictionary** - what is hidden must not depend on the machine.
- **Past `vocabulary_max_gap` the cover fails closed: every query of every case is refused `vocabulary_building` before any request; an open case re-applies a newer cover.** A constant, not a site setting - raising it chooses to leak. Gate: `gap_fails_closed`.
- **The catch-up is read forward from the cover's end in one-day slices; the saved cover never claims a range with a hole (`put` replaces a non-touching slice).** Gate: `catch_up_sliced`.
- **The cover is kept per field; a field is never claimed for days it was not read; a v1 file is untrusted and dropped.** Gate: `field_added_backfilled`; pin: `test_a_field_added_to_an_existing_cover_is_not_claimed_covered_for_days_it_was_not_read`, `test_two_fields_added_at_once_are_backfilled_together`.
- **A field returning from over the cap is read but not waited for, never shares a slice with waited fields, and its failures are charged to it alone with a doubling retry** - else one id-like field takes every case down. Gate: `lapsed_decision_serves`; pin: `_FailingField` tests in `tests/test_esbridge.py`.
- **An unchanged field set gets exactly the slices and request counts it had.** Pin: `tests/test_esbridge.py`.
- **A failed extension slice (older days for fields that already serve) is charged to the extension, never the cluster: next try half as wide down to an hour, then a doubling delay; the width is saved; the VOCAB line says how far the cover reaches and why** - one slow old day was retried whole for ever and showed a healthy cover `stale`. Pin: `tests/test_esvocabage.py`.
- **A catch-up slice with more than two days left that fails or passes a quarter of its budget jumps: the slice is dropped, the cover set aside (`held_over`, names still applied, never counted as cover), the newest days read as a first build, then the gap back to the set-aside range, joined into one range** - a slow two-week catch-up refused every case for hours, and one unfit day for ever. Pin: `tests/test_esvocabgap.py`; gate `catch_up_sliced` keeps its figures.

#### Readability, labels and keep fields (docs/es/readability.md)

- **A label may be used only after the case has been shown it** (`EsScrubber.shown`, filled only by `mark_shown` after the leak check); an unshown label is refused `unknown_label` with the same message as a never-issued one, and no request is sent - else a case reaches every customer on the cluster, and the refusal must not be an oracle. Gate: `label_guessing_refused`; oracle `vocabulary-label-never-shown`.
- **An ordinary-word name keeps its label in its own field and is not indexed for the case-wide sweep; a seeded value is untouched** - else what a page says depends on which pages came before it. Gate: `ordinary_words_readable`; JSON exports: `tests/test_jsonscrub.py`.
- **One word list: `jsonscrub.ORDINARY_NAME_WORDS`** (re-exported by `elastic`); import direction only `elastic -> jsonscrub`. Pin: a test.
- **Readable words are reported as labels in persisted surfaces, words only where a human asked; never in the decision log or to the research session.** Pin: tests in `tests/test_jsonscrub.py` / `tests/test_esbridge.py`.
- **Keep fields are checked, not trusted: tier 1 plus the known-value sweep, never tier 2.** Gate: `keep_leak_closed`, `keep_values_readable`.
- **A learnt name replaces a keep value only when it is the whole value; seeded values and tier 1 shapes match anywhere.** Gate: `stream_name_readable_in_keep`.
- **A keep literal containing a learnt name is usable only once that exact keep value was shown (`shown_keep`); every other case refuses with the existing code and words.** Oracle: `learnt-name-in-keep-literal-never-shown`, `SHOWN_KEEP_CASES`.
- **A case's first query is gated against the cluster vocabulary: compile, apply, compile again, then send.** Pin: `test_a_fresh_cases_first_query_is_gated_against_the_cluster_vocabulary`.
- **Keep-field spellings are never normalised.** Gate: `estate_spellings_unchanged`.
- **On the realistic estate nothing is readable except the declared one-word miss; add a shape class, not a fixture.** Gate: `estate_no_unexpected_readable`.

#### Review and seeding (docs/es/review-and-seed.md)

- **A query the grammar refused is logged as closed-vocabulary shape (`refused_shape`): listed fields, grammar ops and types, grammar and `_DSL_WORDS` key names; every free choice (names, values, phrases, labels, invented keys) only counted** - a recurring `bad_agg` could not be explained from a code alone. Pin: `tests/test_esrefused.py`; oracle `dsl-form-aggregation` keeps the Elasticsearch form refused.
- **es-review is human-only, read-only, prints counts/labels/codes by default (values only under `--show-values`), and reports a missing log as no review, never clean.** Gate: `review_flags_guessing`.
- **es-seed is a human step over the broker socket by case name; `es_seed` is never a tool; the value reaches Claude nowhere and the log carries an `event: seed` row with labels only; at most `_MAX_SEEDS` (40).** Pin: `tests/test_esmcp.py`, `test_a_mid_case_seed_is_logged_as_a_label_never_a_value_and_capped`, `tests/test_esreview.py`.

#### Split tenants and empty results (docs/es/split-tenant-and-empty.md)

- **A label-only phrase counts toward `max_phrases`, spends no budget, resolves only a shown label, is logged as the label, and is not a typed guess for es-review.** Pin: `test_label_only_phrases_count_toward_the_per_query_cap_and_spend_no_budget`, `test_the_wider_scope_weakens_nothing_and_the_log_shows_the_label_not_the_name`.
- **Every zero is explained inside the bridge with capped counts (`EMPTY_CHECK_CAP`), never a full scan; the explanation names fields, never a filter's value.** Pin: `tests/test_esempty.py`.
- **An explained zero moves no review signal.** Pin: `test_an_explained_zero_moves_no_review_signal`.

#### es-preflight and operator utility (docs/es/preflight-utility-gates.md)

- **es-preflight is human-only and read-only; exit 0 no STOP, 1 STOP, 2 could not assess - never clean by silence; values only under `--show-values`.** es-research shows the short form and needs `--accept-readable` (headless) or a `y` to continue past STOP. Pin: `tests/test_espreflight.py`.
- **esutility never rewrites a question to fit the grammar; a human step is shown as one.** Pin: `tests/test_esutility.py`.
- **`esmodel` asks questions of Claude Code through the real es-research launch; a row carries labels, counts, codes and the masked answer only (`masked_only`), re-scores from the file alone (`rescore`), and its tally is an observation of one model on one day, never a figure** - a model run has no cassette. Pin: `tests/test_esmodel.py`.
- **Fixed documents for readability checks are appended after the RNG stream** (order in docs/es/preflight-utility-gates.md) so nothing existing moves; **every es-eval figure is the same from run to run** (labels picked from sorted lists).
- **Measurement switches (`idle_answers`, `ordinary_words_case_wide`, `keep_parts_swept`, `lapsed_waited`, `merge(one_range=True)`, `extend_shrinks`, `catch_up_jumps`, `split_reads`, `split_terms`) exist for "before" figures only; nothing in the live path sets them.**
- **`esbridge.clock` is replaced only by harnesses.**

### Other known limits (README Limitations)

The injection number is one model, five payloads, one run; the utility
number is one model, one 40-line excerpt, fifteen questions; the gateway
serialises redaction (fine for a workstation, the first thing to change
for a shared deployment).

## Where to take questions and findings

See `CONTRIBUTING.md`. In short: a missed or wrong redaction observed on a
real bundle goes through the web UI's "Report a mistake" form (it stays on
the machine) and reaches the repo only as a placeholder template or a
synthetic adversarial case; everything else goes to GitHub issues.
