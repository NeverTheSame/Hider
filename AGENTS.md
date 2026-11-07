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
| A customer path segment missed or a system path over-matched | `recognizers.CustomerPathRecognizer`; structure, system roots and extensions live only in `hider/paths.py` (site additions: `path_structure` in `hider.local.json`); add a `path-*` case to `hider/adversarial.py` or a line to `PATH_LOOKALIKES`, tests in `tests/test_paths.py` |
| A new entity type | `hider/entities.py` first (the contract), then the recognizer, then `pseudonym._shape` if it needs a shaped label |
| Free-text names missed | `hider/classifier.py` (training grammar and features). Keep the train/eval vocabulary disjoint; `test_training_vocabulary_is_disjoint_from_the_eval_vocabulary` guards it |
| Tier 3 prompt or parsing | `hider/llm_tier.py`. Changing the instruction text changes `PROMPT_VERSION`; committed cassettes stop matching and must be re-recorded |
| A new LLM provider | `hider/llm_backend.py`: implement `complete(prompt) -> str`, split with `split_prompt`, feed a `UsageMeter`, raise `BackendError` on any failure. Wire it in `cli._real_backend` and `_add_llm_flags` |
| Gateway behaviour | `hider/proxy.py`. The request path is `handle -> _handle -> redact_payload (tiers, then sweep) -> forward / forward_stream -> detokenize`. Tests use a stub upstream in `tests/test_proxy.py` |
| Eval metrics or gates | `hider/evaluate.py` (recall, precision, adversarial, injection), `hider/utility.py` (answer accuracy raw vs redacted) |
| JSON exports and the web UI | `hider/jsonscrub.py`, `hider/webserver.py` (single-file page, stdlib server), `hider/research.py` (Claude Code bridge) |
| Site-specific patterns | Never in the repo. `templates/profile.example.json` and `HIDER_PROFILE`; see `hider/profiles.py` |
| Live Elasticsearch research | `hider/elastic.py` (site map, response scrubber, case vault), `hider/esquery.py` (closed grammar, compiler, `ORACLE_CASES`), `hider/eseval.py` (synthetic documents, stub Kibana, `es-eval`), `hider/esbridge.py` (the Kibana session: a long-lived broker process owning one off-the-record Chrome via Playwright, async-search protocol, every malformed reply a refusal, decision log), `hider/esmcp.py` (the MCP server inside the broker: cases and tokens, the four tools, transport guards, the Claude Code launch). Design: `docs/es-bridge-design.md`. Site map example: `templates/elastic.example.json`; the real one is `elastic` in `hider.local.json` or `HIDER_ELASTIC` |

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
.venv/bin/python -m hider es-login --cluster emea # start the bridge and sign in (headed, once per bridge)
.venv/bin/python -m hider es-research --case c1 --term "<customer>"   # Claude Code, bridge tools only
.venv/bin/python -m hider es-research --stub --case demo --prompt "..."  # the same on a synthetic Kibana
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

## Known gaps worth knowing before you start

Listed with owners in the README's Limitations section and in
`adversarial.CASES`. The ones most likely to matter:

- Forward-slash Windows profile paths used to be the one deliberately open
  tier 1 gap. It is closed: the separator in
  `recognizers.windows_user_path` is a character class, and mixed separators
  within one path match too. The UNC pattern stays backslash-only on purpose,
  because `//host/users/...` is indistinguishable from the tail of an ordinary
  URL and widening it would swallow every Graph call as a filesystem path.
- Vendor credential prefixes (GitHub, AWS, Google, Slack, Entra) are covered
  by `recognizers.vendor_credential`, which reports `API_KEY`. They are
  **not** in the generated corpus, so they do not move the headline recall
  figure; they are measured by the `vendor-*` cases in `adversarial.CASES`
  and by `test_recognizers.py`. The reason is a measurement constraint worth
  knowing before you touch `templates/` or any value generator: the generator
  draws every unit from one RNG stream, so *any* template or generator change
  reshuffles the whole bundle, which shifts the utility excerpt and
  invalidates `cassettes/utility-haiku-4-5-run1.jsonl`. Re-recording that
  needs a live key. Budget for it before adding an entity type, since
  `test_every_spec_type_is_exercised_by_the_templates` requires a new spec
  type to appear in a template.
- **A credential that reaches tier 2 gets vaulted, which is worse than a
  miss.** Tier 2 labels high-entropy runs as `ORGANIZATION`, so anything
  credential-shaped that tier 1 does not claim is pseudonymised into
  `vault.json` under a reversible mapping instead of being destroyed. Five
  shapes were doing this and are now owned by tier 1: URL userinfo
  (`url_userinfo`), `Authorization: Basic` and friends
  (`http_credential_header`), cookie and set-cookie values
  (`CookieHeaderRecognizer`), the AWS secret access key
  (`AwsSecretKeyRecognizer`) and PEM key bodies
  (`PrivateKeyBlockRecognizer`). When you add any credential shape, assert
  the *pipeline* property, not just the recognizer: run `Pipeline.redact` and
  check the value is absent from both the output and `vault.entries`. A
  recognizer-level test passes while the vault still fills up.
- Windows/Microsoft identifiers (`DOMAIN\user`, domain and Azure AD SIDs,
  cert thumbprints, `*.onmicrosoft.com`, support trackingIDs, formatted
  phones) are pseudonymised by tier 1. Their adversarial occurrences borrow
  the closest existing spec type (UPN_EMAIL, TENANT_ID, OBJECT_GUID,
  SITE_URL, SUPPORT_CASE_NUMBER) and each borrowed spec's `detected_as`
  lists the new detector label - the same cassette constraint as above is why
  they are not spec types of their own. The fences (well-known SIDs and
  principals, commit hashes, versions, byte counts, timestamps all survive)
  are tested as intent in `test_recognizers.py`; phone matching in
  particular is hard-gated to digits plus `+ - ( )` and spaces because the
  raw `phonenumbers` matcher redacted 96 of 1,000 clean lines (timestamps).
  Declared misses: unformatted and dot-separated phone spellings.
- URLs, paths and Azure resources: space-tolerant document URLs (fenced on a
  path separator plus a document extension), OneDrive `/personal/` identity
  segments, key vault URLs and Exchange item ids are pseudonymised by tier 1
  (`tenant_site_url`, `onedrive_personal_account`, `azure_key_vault`,
  `exchange_item_id`). Vendor hosts (`graph.microsoft.com`,
  `login.microsoftonline.com`) stay readable. Customer domains in the open
  namespace are claimed by `recognizers.CustomerDomainRecognizer`: any
  public-TLD FQDN that is not a vendor service, in prose too, failing toward
  redaction. The one vendor list is `hider/vendors.py` (pair test: vendor
  suffix AND vendor service label), extended per site via `hider.local.json`;
  jsonscrub and the recognizers both consume it, as does the shared
  `recognizers.FILE_EXT`. If you add a vendor host, add it there and nowhere
  else. Lookalikes (namespaces, file names, missing-space typos, vendor
  hosts) are seeded in the clean corpus, so an over-match shows up as a
  nonzero false-redaction figure on the next eval. Declared misses: TLDs
  outside `_PUBLIC_TLDS`, TitleCase-spelled domains, TLDs shadowed by
  source-file extensions (.py, .md, .rs).
- **Customer file paths.** `recognizers.CustomerPathRecognizer` labels each
  customer folder (`<Folder-NN>`) and file stem (`<File-NN>`, extension kept)
  in a rooted path, plus the account in `/home/<account>` (`user-NN`) and a
  UNC server (`HOSTNAME_FQDN`). The labels are detector labels borrowed by
  the `WINDOWS_USER_PATH` spec (`detected_as`), for the cassette reason
  above. The structural-name list, system roots, API roots and extension
  classes live in `hider/paths.py` and nowhere else; a site adds structure
  through `path_structure`, never in the repo. The generated corpus has
  almost no paths (the rule changes zero generated lines), so the rule is
  measured by the 23 caught `path-*` cases and by `adversarial.PATH_LOOKALIKES`, a
  fixed clean unit outside the RNG stream that `eval` reports as its own
  line. Keep new lookalikes there, not in `templates/`. A `DOMAIN_LOGON`
  match inside a path span is suppressed (`BOARD\BUDGET` is two folders).
  **The last segment is a file name, labelled whole or not at all**, never
  a folder label over its first words (`<Folder-03> payroll.xlsb` was a
  blind-test finding, 14 of 75 paths). `_file_end` reads up to
  `_MAX_NAME_WORDS` (16) more words over colons, commas, codes, amounts and
  space runs (NBSP too) to the first known extension, else the last
  unknown one (`_unknown_ext`: hidden with the name, `<File-01>`, no
  extension shown). It errs long on purpose: prose between a folder path
  and a file named later on the line is hidden with the name, pinned as
  intent in `test_paths.py`. A one-word artifact name (`agent.log`) stays
  readable; a spaced one does not. The vault keys path labels on
  `paths.norm`, so a file keeps one label across hits, pages, case, `%20`
  and space runs. The `path-file-*` cases are the shapes; add the next one
  there first.
  Nine declared misses, each a `path-*` or `bare-file-name` case:
  - rootless relative paths and bare file names;
  - an unquoted lower-case last folder with spaces, and an unquoted
    extensionless file name followed by prose (the same miss);
  - an unquoted file name of more than sixteen words;
  - a folder path ending in prose that later names a source file: the
    source-file fence keeps the whole path readable (older than the
    file-name reader; narrowing the fence would label spaced binaries);
  - folders under a system root;
  - folders in source or binary paths;
  - customer folders in a Windows profile tail, which `windows_user_path`
    keeps readable. Relabelling that tail changes its pseudonym shape, which
    the utility excerpt depends on: a cassette re-record.

  Structure under tier 2: `pipeline.in_structural_path_segment` drops a
  tier 2 span (both backends) inside path segments that are all structural,
  bounded by separators on both sides; prose and final unclosed segments
  are deliberately outside the rule (safe direction), tier 1 spans are
  never touched, intent tests in `test_paths.py`.
- **Dotted names.** `pipeline.in_dotted_chain` suppresses a tier 2 span inside
  a dotted chain of three or more labels, because tier 2 reads .NET namespace
  parts as organisations and vaults them (187 false spans over 145 of 1,000
  clean lines before the rule). The floor is structural, not a vocabulary of
  namespace roots, and it is three rather than two so one-dot organisation
  names stay catchable. Two declared misses straddle it, each with an
  adversarial case and a pinning test: a two-label namespace tail
  (`Newtonsoft.JsonSerializationException`) is still vaulted, and a
  three-label organisation (`Wood.Partners.Group`) is suppressed. The
  two-label case is deliberately NOT in the clean corpus — measuring a
  declared miss as a failure just yields a red test nobody can act on.
- **Log vocabulary is never part of a tier 2 span.** Tier 2 read level and
  status words as names: "Info Lena" as one person, "Debug" as a person on
  its own, "Critical Contoso Holdings" as one organisation. That destroyed
  the word in message text and, once it was a known value, the ES sweep
  replaced it in `log.level` too. `pipeline.LOG_VOCABULARY` lists the words
  (levels, severities, outcomes; no plausible names). Tier 2 reads a segment
  that has one twice, as written and with the words lower-cased, trims the
  words off both readings' spans and keeps the union: a narrowed tier 2
  span, never a widened one, and never a tier 1 span touched. The sweep
  over keep fields is unchanged, on purpose: it is the safety net for a
  misclassified field. On the 160-line grid in `test_recognizers.py`, 54
  words lost and 36 names leaked before, none and 4 after, those 4 leaking
  before too: a lone upper-case-level first name (`WARN Lena`), pinned as a
  declared miss, since tier 2 misses a lone first name beside any word. The
  spaCy tier gets the trim, not the second reading. A real name spelled like
  a vocabulary word (`Trace`) is a declared miss of this rule.
- **OPEN tier 2 gap: the dotted-organisation head leak.** No dotted
  organisation is caught whole. `Wood.Partners` is below the 0.4 score floor
  and missed; `Tailspin.Industries` is caught only from the dot onward, so the
  head leaks and the tail is vaulted under a name that is not the
  organisation. This is the entire difference between 99.65% and 100%
  free-text recall. Suppression cannot fix it — a tier may add or remove
  spans, never widen one — so the fix is a span-widening pass over dotted
  chains or training-grammar work in `classifier.py`. Do not close it by
  lowering the three-label floor; that trades a false positive for a real miss.
- Two deliberate over-destructions live in those rules, both at zero measured
  false redaction: every cookie value is destroyed (names and attributes
  survive) because cookie names are not a reliable signal, and any line that
  is nothing but a 40+ character base64 run is destroyed, which also catches
  public certificate bodies. Both are tested as intent, not discovered as
  behaviour.
- Tier 2 recall is a model's recall. The classifier's training grammar is
  generated and small; a mention shaped unlike anything in it is a realistic
  miss, and the misses are listed one by one in `metrics.json`.
- The injection number is one model, five payloads, one run.
- The utility number is one model, one 40-line excerpt, fifteen questions.
- The gateway serialises redaction; fine for a workstation, the first thing
  to change for a shared deployment.
- **Elasticsearch: the declared text-query channel.** `esquery` lets a
  phrase on a `text` field carry plain words, so a guessed word can be
  confirmed by a hit count. Accepted by decision: every text query is
  logged with its labels and counted by `es-eval`. The width of the
  channel per query is capped: at most `max_phrases` distinct phrases
  (site map, default 8, ceiling 16, 0 turns text queries off), counted
  across the filters and every aggregation at any depth, so one `filters`
  aggregation can no longer return a separate count for a whole word list
  (`phrase-flooded-filters-agg` is the oracle case). Distinct means per
  field, ignoring case and spacing: a phrase reused across buckets is one
  guess, which is also why the zero-hit check, built only from a query's
  own filters, always fits the cap of the query it checks. What the cap
  does **not** close: guesses across queries (`max_phrases` per query, queries
  unlimited, no per-case budget; the log and `es-eval` count them, nothing
  stops them); combinations of the allowed phrases (a `filters`
  aggregation can still count up to `max_buckets` co-occurrences of its
  allowed phrases, so it bounds the vocabulary per query, not the number of
  counts); literals on `keep` fields, which are uncapped because a keep
  field is declared non-sensitive (a sensitive value under `keep` is a
  site-map error); and punctuation variants of one phrase, which count
  separately (safe direction). OR across phrases is not built
  (`any_of` waits for a decision). Identifier fields take
  labels only; each forbidden shape (wildcard, prefix, range, sort, terms
  include, scripts, raw DSL, literals, wrong-type labels) is an
  `esquery.ORACLE_CASES` entry and must be refused with its declared code.
  Add the case before the rule, as with `adversarial.CASES`. Only
  `esbridge` opens a connection, and only from the broker's browser. The
  SSO cookie never leaves Chrome and never reaches disk: Kibana's `sid` is
  a session cookie that dies with the browser, so one long-lived broker
  (`es-login` starts it, `es-smoke` talks to it over a 0600 socket) holds
  the sign-in, and its Chrome context is off the record because a
  persistent profile flushes even session cookies to its cookie database.
  The stub enforces the same rules (cookie sessions, an IdP that refuses
  headless and fetches) and names hits by data-stream backing index
  (`.ds-<stream>-<date>-<gen>`), which `index_allowed` checks by stream. An
  expired Kibana session is a 200 login page, not a 401, so every reply
  goes through `KibanaSession.parse_reply` first. The MCP server
  (`esmcp`) runs inside the broker, because the broker's thread owns the
  browser: per-case bearer token, loopback, `Host` checked, no CORS. Its
  tools take grammar keys only. Never add a tool that seeds a value,
  signs in or unmasks: a value-to-label tool would let Claude mint a label
  for a guess and confirm it with a count. Claude Code is launched with an
  allowlisted environment (`esmcp.claude_env`); a variable it needs goes
  on the allowlist, and nothing goes on a denylist. The prompt is gated
  too (`esmcp.prompt_findings`), headless before launch and interactive
  as a `UserPromptSubmit` hook whose command ends in `|| exit 2`, so a
  broken check blocks. `es-eval` runs the fixture through the real MCP
  endpoint (`mcp_*` gates); all pass. The job-name-in-free-text leak it
  found (a fresh case's first page, the referenced job's field on another
  document) is closed by `elastic._JOB_REF`: "job <Title Case run>" in a
  text field is labelled JOB_NAME when the site map declares that type, at
  the declared cost of hiding any capitalised run right after the word
  "job". `es_schema` and the esmcp instructions also tell Claude that keep
  fields hold spellings as logged (err/Error/ERROR): aggregate a keep
  field's values before an exact filter, then filter with `in` across the
  spellings; values are never normalised. A case saved before the log-vocabulary trim
  may hold "Info" as a value: `load_session` keeps such labels for
  unmasking but not as known values (`elastic.log_vocabulary_only`).

## Where to take questions and findings

See `CONTRIBUTING.md`. In short: a missed or wrong redaction observed on a
real bundle goes through the web UI's "Report a mistake" form (it stays on
the machine) and reaches the repo only as a placeholder template or a
synthetic adversarial case; everything else goes to GitHub issues.
