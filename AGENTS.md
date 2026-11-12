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
| Live Elasticsearch research | `hider/elastic.py` (site map, response scrubber, case vault), `hider/esquery.py` (closed grammar, compiler, `ORACLE_CASES`), `hider/eseval.py` (synthetic documents, stub Kibana, `es-eval`), `hider/esreview.py` (`es-review`: a case read back from its decision log), `hider/esbridge.py` (the Kibana session: a long-lived broker process owning one off-the-record Chrome via Playwright, async-search protocol, every malformed reply a refusal, decision log), `hider/esmcp.py` (the MCP server inside the broker: cases and tokens, the four tools, transport guards, the Claude Code launch). Design: `docs/es-bridge-design.md`. Site map example: `templates/elastic.example.json`; the real one is `elastic` in `hider.local.json` or `HIDER_ELASTIC` |

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
.venv/bin/python -m hider es-login --cluster emea # start the bridge, sign in (headed, once per bridge),
                                                 # then build the name vocabulary: minutes on a large estate
.venv/bin/python -m hider es-research --case c1 --term "<customer>"   # Claude Code, bridge tools only
.venv/bin/python -m hider es-research --stub --case demo --prompt "..."  # the same on a synthetic Kibana
.venv/bin/python -m hider es-review --case c1    # read a case back: numbers, phrase spend, probing signals (human-only)
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
  Three more came from the PasteGuard comparison
  (`docs/pasteguard-comparison.md`, P1) and are owned by tier 1 now: a
  vendor key whose prefix carries an underscore (`sk_live_`; `api_key`'s
  separator is a character class, and the 20-character floor is what keeps
  `sk_live_short` out), a key name ending in `_SECRET` assigned with `=`
  or `:`, and a password assigned with a colon (`db_password: …`, the YAML
  spelling `connection_string` missed because it needs an equals sign).
  The last two are `EnvCredentialRecognizer`, which like
  `AwsSecretKeyRecognizer` reads the **key name as evidence and reports
  only the value**, so the name and the prose around it stay readable. The
  key name must *end* at the credential word, which is what keeps
  `client_secret_expires_at:`, `password_policy:` and
  `vault_password_file:` out.
  **`_NON_SECRET_VALUES` is the one place tier 1 reads English** - a short
  fixed list of config vocabulary (`null`, `required`, `strict`,
  `redacted`, …), every entry a word that would be an indefensible
  password and is a common config value - behind two structural tests (no
  alphanumerics at all is a mask; all digits is a count) and a
  six-character floor. Do not grow it into a dictionary: each word added
  is a password that then leaks. Measured by
  `adversarial.CREDENTIAL_LOOKALIKES`, a second fixed clean unit beside
  `PATH_LOOKALIKES` (17 lines, 0 changed) that `eval` reports on its own
  line; keep new lookalikes there, not in `templates/`.
  **Two declared misses live inside that unit on purpose**
  (`adversarial.CREDENTIAL_LOOKALIKE_MISSES`, counted apart and pinned by
  a test): `db_password: unchanged since install` and
  `APP_SECRET=placeholder_value_here` are destroyed, because an ordinary
  English word to the right of a credential key name cannot be told from a
  secret without reading the sentence, and the safe direction is to
  destroy. Also declared: a secret shorter than six characters, and the
  tail of a value containing a comma or semicolon, which the span stops
  at.
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
  measured by the 25 caught `path-*` cases and by `adversarial.PATH_LOOKALIKES`, a
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
  - a folder path followed only by capitalised words and then a source
    file: indistinguishable from a spaced program name, so readable whole.
    `_file_end` reaches a source or binary extension only across
    program-name words (title-case or digits, no sentence punctuation);
    with prose in between the path ends at the folder, at the declared
    cost of labelling a lower-case spaced program name outside a system
    root (`test_paths.py`);
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
- **Elasticsearch research.** Live Kibana through a closed grammar, a
  long-lived broker that owns the only session, and an MCP server Claude
  Code talks to. The rules below are what keeps a page safe to show;
  each one says why, because the why is what stops the next change
  undoing it.

  **The query grammar, and the declared text-phrase channel.** `esquery`
  lets a phrase on a `text` field carry plain words, so a guessed word
  can be confirmed by a hit count. Accepted by decision: every text query
  is logged with its labels and counted by `es-eval`. The width per query
  is capped at `max_phrases` distinct phrases (site map, default 8,
  ceiling 16, 0 turns text queries off), counted across the filters and
  every aggregation at any depth, so one `filters` aggregation cannot
  return a separate count for a whole word list
  (`phrase-flooded-filters-agg` is the oracle case). Distinct means per
  field, ignoring case and spacing: a phrase reused across buckets is one
  guess, which is also why the zero-hit check, built only from a query's
  own filters, always fits the cap of the query it checks.
  **Guesses across queries are capped per case** by `phrase_budget`
  (site map, default 150, ceiling 2000, 0 turns it off): the distinct
  plain-word phrases a case has used on text fields, distinct as for
  `max_phrases` (per field, case and spacing ignored), kept in
  `EsScrubber.phrases_spent` and saved with the case (in `session.json`,
  beside its other values; a case saved before this starts at zero, since
  what it used was never recorded). A phrase already used and a phrase
  made only of labels cost nothing. `_Compiler.check_budget` runs last in
  `compile`, so a query refused for any other reason spends nothing, and
  refuses `phrase_budget` before any request with a message that depends
  only on the counts. Phrases are **spent when a query is about to be
  sent** (`Bridge.run`, after the vocabulary is applied and the query
  re-gated, before the probe) and **never refunded**: whether a page is
  withheld after the search (leak, size cap) can depend on what the
  phrase matched, so a refund would make that guess free; a query refused
  before sending (grammar, vocabulary building) spends nothing because
  that refusal cannot depend on a match. The cost of no refund: an
  upstream failure or a withheld page still uses the phrases, and a long
  legitimate case re-running after an outage pays twice only for phrases
  it does not reuse verbatim. Why 150: an investigation finds its messages
  with a few phrases per question - an error text, a step name, a label
  with a verb - and a case of a few dozen questions uses tens, not
  hundreds, while 150 is under one twentieth of the 4,000 counts in the
  guessing run below. The cost: a long case that keeps varying its
  wording runs out and is refused; the fix is reusing phrases (free), a
  new case, or the site raising the value. `es_schema` gives Claude the
  count, the budget and the rule; the decision log rows and es-smoke's
  `PHRASES` line carry counts only. Gate: `phrase_budget_holds`.
  What the caps do **not** close, all declared: guesses within the
  budget (150 distinct guesses per case are still possible, and a new
  case starts again - the budget is per case, not per human);
  combinations of the allowed phrases (a `filters` aggregation can still
  count up to `max_buckets` co-occurrences, so the cap bounds the
  vocabulary per query, not the number of counts); literals on `keep`
  fields, uncapped because a keep field is declared non-sensitive (a
  sensitive value under `keep` is a site-map error); and punctuation
  variants of one phrase, which count separately (safe direction). OR
  across phrases is not built - `any_of` waits for a decision.
  Identifier fields take labels only. Every forbidden shape (wildcard,
  prefix, range, sort, terms include, scripts, raw DSL, literals,
  wrong-type labels) is an `esquery.ORACLE_CASES` entry and must be
  refused with its declared code. **Add the case before the rule**, as
  with `adversarial.CASES`.

  **The session lives in one browser, in one process.** Only `esbridge`
  opens a connection, and only from the broker's Chrome. The SSO cookie
  never leaves it and never reaches disk: Kibana's `sid` is a session
  cookie that dies with the browser, so one long-lived broker holds the
  sign-in (`es-login` starts it, `es-smoke` talks to it over a 0600
  socket), and its Chrome context is off the record because a persistent
  profile flushes even session cookies to its cookie database. An expired
  Kibana session is a 200 login page, not a 401, so every reply goes
  through `KibanaSession.parse_reply` first. A hit names its data-stream
  backing index (`.ds-<stream>-<date>-<gen>`), which `index_allowed`
  checks by stream. The stub enforces the same rules (cookie sessions, an
  IdP that refuses headless and fetches).
  Clients must tell a busy broker from a dead one: `broker_state` returns
  `running`/`busy`/`absent` (a failed connect is absent, a timeout with
  the socket file still there is busy), `cli._wait_for_vocabulary` treats
  a refusal as "ask again" while ping still answers, and `es-logout`
  retries for a minute and never says "no bridge" while the socket
  exists - saying it at a live broker leaves the process holding the
  Kibana session, which is the opposite of what es-logout is for.

  **The MCP server runs inside the broker** (`esmcp`), because the
  broker's thread owns the browser: per-case bearer token, loopback,
  `Host` checked, no CORS. Its four tools (`es_schema`, `es_search`,
  `es_count`, `es_aggregate`) take grammar keys only. **Never add a tool
  that seeds a value, signs in or unmasks**: a value-to-label tool would
  let Claude mint a label for a guess and confirm it with a count. Claude
  Code is launched with an allowlisted environment (`esmcp.claude_env`) -
  a variable it needs goes on the allowlist, and nothing goes on a
  denylist. The prompt is gated too (`esmcp.prompt_findings`), headless
  before launch and interactive as a `UserPromptSubmit` hook whose
  command ends in `|| exit 2`, so a broken check blocks.

  **A name in free text with nothing marking it.** "Harbour Nightly
  finished", "Tenant Thornbury Estates exceeded its quota": no shape a
  rule can read. Two mechanisms cover it.
  `elastic._JOB_REF` labels "job \<Title Case run\>" in a text field as
  JOB_NAME when the site map declares that type, at the declared cost of
  hiding any capitalised run right after the word "job".
  Everything else is covered by the cluster's **name vocabulary**: every
  value of every field in `vocabulary.fields` becomes a known value under
  its own field's rule. Fields of a type in `NO_VOCABULARY_TYPES`
  (accounts, ids, machines, numbers), shaped fields and globs are refused
  at load. With **no `vocabulary` section the default is every field that
  could be listed** (`ElasticConfig.learnable_rules`: non-glob, unshaped,
  type outside `NO_VOCABULARY_TYPES`) - exactly the set
  `_parse_vocabulary` accepts, so the default can never be something a
  site map would be refused for, and a map listing everything it may list
  gets the same set as one listing nothing. It was JOB_NAME fields only,
  which left tenant, tenant-full and resource names readable at every
  site that had not written the section: the common case, and the fields
  most likely to hold the customer's name. A map that does list
  `vocabulary.fields` keeps exactly its own list, and
  `vocabulary_omitted` names what it leaves out, reported by
  `vocabulary_report()["omitted"]` and on the `VOCAB` line as `NOT READ
  (readable in text)` - field names only. Gate:
  `default_map_names_hidden`.
  The default set is wide by design, and a site may type an identifier
  anything it likes, so it can contain a field that is not a name at all
  (a per-request reference). That is what the per-field distinct count
  below is for: such a field is counted, left out and reported, rather
  than paged to the cap and taking the slice - and the build - down with
  it. `NO_VOCABULARY_TYPES` is still the only thing refused at load; the
  count is about **width**, not about type.

  **The vocabulary is read once per cluster, at sign-in, in one-day
  slices, newest first.** Never inside a case, and never from anything
  Claude says - the read takes no input from Claude at all, not even a
  time bound. Three shapes failed first, and each failure is why a part
  of the current one exists: one capped `terms` aggregation over the
  retention period refused every case on an estate past the cap; reading
  the *case's own window* costs 8-35s per 1,000-value page, so a one-hour
  case read 49 hours once a margin was added and every case was refused
  again; and reading the whole 30-day range at once costs **31 to 297
  seconds a page** (not 8-35), which on 12 name fields of ~10,000 values
  is over a hundred pages - hours, against a twenty-minute budget.
  So, today:
  - `next_vocabulary_slice` hands out one `VOCABULARY_SLICE_S` (a day) at
    a time, newest first and contiguous, until the cover reaches
    `vocabulary.days`. A day-wide page is charged the cheap rate, and
    `VocabularyIndex` saves each slice as soon as it is whole, so a
    restart resumes rather than starting over.
  - `VocabularyBuild` reads **one field per request** with an `exists`
    filter on it, `VOCABULARY_PAGE` (1,000) values a page, carrying that
    field's `after_key`. One field at a time because the cost is per
    aggregation: a request carrying every field pays for all of them
    before it can be stopped, logged or resumed. Fields are read
    JOB_NAME-first, because a message naming a tenant almost always
    carries the tenant fields on the same document (harvesting the page
    covers it) while about three in four messages naming a job carry no
    job field.
  - **Every field is counted before it is paged**, one `cardinality`
    request per field per slice (`VOCABULARY_COUNT_AGG`,
    `precision_threshold` asked for at the cap). Without it, an id-shaped
    field in the default set - a per-request reference with a fresh value
    on nearly every document - was paged to `vocabulary.max` and *then*
    refused: 51 requests, the slice abandoned, retried, abandoned again,
    and **no case ever served**. What the count does next depends on who
    chose the field:
    - **default set** (no `vocabulary.fields` in the map): the field is
      left out, the build carries on, and the decision is saved
      (`VocabularyIndex.note_over_cap`, at once, before the slice is
      whole, so a slice that fails afterwards does not pay again) for
      `VOCABULARY_OVER_CAP_S` (a day), after which it is counted again;
    - **a field the map lists itself**: the slice is refused, as before,
      with a message naming the field and the two ways out (remove it
      from `vocabulary.fields`, or raise `vocabulary.max`). A site that
      named the field asked for it to be read, and reading most of it is
      not that.
    A cardinality count is **approximate**, so `VOCABULARY_PROBE_MARGIN`
    (5%, well above the measured HyperLogLog++ error) decides what "near
    the cap" means - and it is applied **in whichever direction keeps the
    build running**: a default field within the margin is treated as over
    the cap (left out, build carries on), a listed field within it as
    under (paged, with the exact page-time count deciding, because there
    "over the cap" means refusing the slice). The exact page-time check
    stays as the backstop under both, and takes the same two branches.
    The cost of the count is **one cheap request per kept field per
    slice** - on the es-eval fixture 150 of the cover's 312 requests.
  - **One step per serve-loop iteration**, not one page:
    `KibanaSession.submit` / `poll_once` / `release` are the three steps
    `search` is made of, and `Broker.pump_vocabulary` does one of them
    per iteration, keeping the search in `Broker._page`. The browser
    belongs to that thread, so a pump that ran a whole page left the
    broker answering nothing for its length - es-login timed out against
    its own broker, and es-logout then read that as "no bridge".
  - **The budget is per slice** (`vocabulary.budget_s`, 1200s). One slow
    slice fails alone and is retried after `VOCABULARY_RETRY_S`; the
    slices already saved stay.
  - **A case applies what the index holds** (`apply_vocabulary`,
    `Bridge._apply_vocabulary`): local work, no request, once per case
    per cluster. It is refused with `vocabulary_building` only until the
    cover spans `VOCABULARY_SERVE_DAYS` (2) - `ClusterVocabulary.serves` -
    after which cases run while the older slices are still being read.
    State goes `building` -> `extending` -> `ready`, and the `VOCAB` line
    prints the covered range, the age, `NEAR CAP` at 80% and build
    progress.
  - **Nothing is learnt from a partial, failed or timed-out read of a
    field that is kept**: an upstream error, a partial or misshapen
    reply, a *listed* field over `vocabulary.max` (50,000) or a slice
    over its budget abandons that slice (`VocabularyBuild.failed`,
    `result()` refuses) and leaves the saved vocabulary exactly as it
    was. A field left out for being over the cap is not a partial read of
    it: whatever it returned is dropped (`_over_cap` pops its values) and
    it is absent from the result, not present and short.
  - Logs hold counts, requests, seconds and field names, **never a name**
    (`vocabulary_report`, `VocabularyIndex.report`,
    `vocabulary.log.jsonl`, the `VOCAB` line) - including the `over_cap`
    row, which carries the field name, its distinct count and the cap.
    Every surface that says what the vocabulary holds also says what it
    **left out and why**: `omitted` (the map's own `vocabulary.fields`
    leaves it out) and `over_cap` (counted, too wide to read), on the
    `VOCAB` line as `NOT READ (readable in text)` and `OVER CAP, NOT READ
    (readable in text): field~count>cap`. `esbridge.clock` is what
    the build range and the staleness check read; it is a module global
    because the harnesses' fixtures sit at `eseval.NOW` rather than
    today, and nothing in the live path replaces it.
  - Values that are log words, stopwords, letterless, one word under four
    characters, or one word on the shared `ORDINARY_NAME_WORDS` list are
    skipped (`vocabulary_skip`) - a fixed list on purpose, not the system
    dictionary: what is hidden must not depend on the machine.
  **Measured cost**, with the stub charging `PAGE_SECONDS` (8-35s a page
  over a slice) against `WIDE_PAGE_SECONDS` (31-297s over the whole
  range), so a build that stopped slicing fails its budget in the eval
  rather than quietly costing hours: on the es-eval fixture (5 fields,
  21,751 job names, 30 days) **30 slices, 312 requests and 3,423
  simulated seconds for the whole cover**, worst slice 137s of 1200s -
  but only **20 requests and 211 seconds, two slices, before the first
  case can run**, and 10 requests and 105 seconds for a top-up. Of those
  312 requests, **150 are the per-field distinct counts** (`PROBE_SECONDS`,
  2s each, an assumption stated as one - the claim about the count is its
  request *count*, which is exact); before the count the same cover was
  162 requests and 3,123 seconds, which is what the count buys off: a
  single id-shaped field in the default set cost 51 requests a slice and
  then failed the slice, every slice, for ever. On the
  shape that motivated slicing (12 name fields, ~10,000 values each) the
  first case is roughly eight minutes after sign-in and the full cover
  about two hours, in the background. If a *day's* page costs two minutes
  at some site, a slice is 24 minutes, which **exceeds the per-slice
  budget**: that site must raise `vocabulary.budget_s` (ceiling 7200) or
  list fewer fields. There is no setting at which a cover that size is
  free.
  **Declared costs and misses of this shape:** the first sign-in takes
  minutes before any case can run, and `es-login` waits there showing
  progress; **real customer names are written to disk** in
  `out/es/vocabulary.json` (0600, gitignored, never in the repo), a
  larger on-disk footprint than a case vault because it is every name on
  the cluster rather than the ones a case saw; a name **logged only in a
  day the cover has not reached, or older than `vocabulary.days` (30), is
  not known** - the `VOCAB` line's covered range is where that is
  visible; so is one logged in the gap between top-ups, up to
  `VOCABULARY_REFRESH_S`; and a failed top-up leaves the bridge serving a
  cover that is complete for its range but stale, reported as `stale`
  with its age rather than refusing, the same risk the ten-minute refresh
  already accepts. **`stale` means overdue, not due**: a cover older
  than the refresh interval is `top_up_due` (the top-up runs next, and
  reading the first two days at sign-in always takes longer than the
  interval, so this is what es-login returns to), and becomes `stale`
  only past the interval plus one slice budget, or at once when the
  last top-up failed. **Overdue is measured on this bridge's clock**:
  `VocabularyIndex.report` used to charge the cover's age alone, so a
  bridge restarted a day after the last one said `stale, TOP-UP OVERDUE`
  on its first page while the top-up had just started. The broker now
  tells the index when it started (`started_at`), which clusters have a
  slice in flight (`in_progress`) and whose last slice failed (`failed`),
  all runtime-only and never saved; the state is `top_up_due` while a
  top-up is running (`topping_up`, the line says `top-up running`) or has
  not yet had a slice budget of this bridge's time, and `stale` once it
  has, or at once after a failure (with the refusal). `age_s` and the
  line's age stay honest - from the end of the cover - and the line says
  that names logged since the cover ended are not known until the top-up
  finishes. A bare index with no broker (tests, es-eval sessions) keeps
  the age-alone rule. Cost: a bridge restarted after a week of downtime
  reports `top-up due` for up to twenty minutes while its catch-up slice
  runs, and serves cases that whole time with a week of names unknown -
  which it also did before, under a word that made it look like a fault.
  **Past a bound the gap fails closed.** `ClusterVocabulary.serves`
  checked only how many days the cover spans, never how recent its end
  is, so a bridge restarted a week after the last one served cases off a
  cover a week old: a tenant onboarded in between had never been read and
  was plain text in message text. Now a cover whose end is more than
  `vocabulary_max_gap` behind now (`VOCABULARY_MAX_GAP_S`, an hour, or one
  refresh plus one slice budget if the site's budget makes that longer) is
  `catching_up`: **every query of every case** - an open one too - is
  refused `vocabulary_building` before any request, with a message giving
  the gap in hours, the bound and the range the top-up must read (no
  value, nothing about a guess; the code's meaning, "the vocabulary does
  not yet cover what a page could carry", is the right one). The VOCAB
  line says `CATCHING UP` with the same range, and es-login waits through
  it and says what it is waiting for. A constant rather than a site-map
  setting because a site that raised it would be choosing to leak; it
  scales with `budget_s` so a site that needs long slices is not refused
  during an ordinary slow top-up. Within the bound nothing changes: ten
  minutes behind serves as before, a failed top-up is `stale` and serves.
  **Simple rule, not a time-range one**, because a narrow rule could not be
  shown safe. Routes checked: a query with no time range covers all time;
  a range ending before the gap still returns documents whose message
  names a tenant first logged in the gap (ingest delay, a back-dated
  `@timestamp`, a message about a future onboarding), and the vocabulary
  is read by `@timestamp`, so such a name was never in any slice; a
  `top_hits` under an aggregation and a `filters` bucket reach the same
  documents. **The open-case route** was a second leak: a case applied the
  cover once and never again, so a top-up never reached it; the bridge
  now re-applies (locally, no request) whenever the index holds a newer
  cover than the case does. Order: `next_vocabulary_slice` already reads
  the newest end first, from the cover's end to now, so the gap is the
  first top-up and cases run as soon as it is whole; left as it was.
  **Cost** to a user who restarts the bridge every morning: the overnight
  gap is hours, so every case is refused for as long as that one top-up
  takes - one-day slices from the cover's end to now, each a page per
  1,000 values per field at the slice rate; on a cluster where a day's
  page is 8-35s that is a minute or two a slice, so an overnight gap is
  minutes and a week is about ten. Gate: `gap_fails_closed` on
  `eseval.gap_docs` (own index pattern and map, appended last).
  **The catch-up is read in slices**, not as one request. It was one read
  from the cover's end to now, however wide: after a week down that is
  charged the wide-range rate (31-297s a page against 8-35s over a day),
  which on the gap fixture is **10 requests, 1,392 simulated seconds and
  9 wide pages against a 1,200s budget - refused, retried, refused, for
  ever**, with every case refused the whole time. `next_vocabulary_slice`
  now hands the gap out **forward from the cover's end**, one
  `VOCABULARY_SLICE_S` at a time (the slice size and how one slice is read
  are unchanged; a ten-minute top-up is still one short slice): each
  slice has its own `budget_s`, is saved by `VocabularyIndex.put` as soon
  as it is whole, and a failure or a restart resumes from the cover's new
  end. On the same fixture: **7 slices, 35 requests, 433 seconds, worst
  slice 75s, 0 wide pages**, and the case is shown with the gap tenant
  hidden once the seventh lands. **Why forward, not newest-first**: the
  hard rule is that the saved cover never claims a range with a hole in
  it, and a forward slice always touches the cover, so `merge` extends one
  range. Newest-first would serve cases two slices in - but the recent
  slices would not touch the saved cover, so either the saved cover is
  dropped (a week's gap on a 30-day cover re-reads 23 days that were
  already on disk) or the index holds two ranges with a hole between
  them, which is the thing the rule forbids. The cost of forward: cases
  wait for the whole gap, seven slices for a week rather than two. `put`
  enforces the rule structurally - a slice that does not touch the held
  cover **replaces** it (logged as `saved_as: replaced`) rather than
  bridging the hole; nothing in the live path produces one, and a test
  pins it.
  **A slice of the gap that fails** (its budget, an upstream error, a
  misshapen reply) behaves as any slice does: the slices before it stay
  saved, the cover is unchanged by the failure, the same slice is retried
  after `VOCABULARY_RETRY_S` (a minute) from the cover's end, and cases
  stay refused while the cover is behind the bound. The VOCAB line and
  the refusal say `last attempt failed (<code>), retrying`.
  **A cover that has fallen out of `vocabulary.days`** - its end older
  than the window - is dropped (`VocabularyIndex.drop_expired`, logged as
  `expired` with days and a count), and the build starts as a first build
  does: newest day first, cases after `VOCABULARY_SERVE_DAYS`. Reading
  forward from it would spend slices on days nobody asks about before any
  case could run, and reading from the window's edge would leave a hole.
  Cost: the names it held are lost (every day it covers is outside the
  window, so none would be re-read), and the first case waits the
  first-build time rather than two short slices. A cover that is only
  **partly** out of the window is kept whole and read forward: the old
  part is extra names, not a hole, and `complete()` is true for it.
  **Progress is visible everywhere a user waits**:
  `VocabularyIndex.catch_up` gives slices left and total (total counted
  from where the cover ended when this bridge first found it behind,
  `catch_up_from`, runtime-only), the range being read, and whether that
  slice is running, next, or failed and retrying - counts and ranges
  only. The VOCAB line prints it under `CATCHING UP` (and beside a running
  slice's progress), es-login prints it when it stops waiting, and the
  `vocabulary_building` refusal carries it word for word; none of it
  depends on anything about a guess, and the numbers are what the broker
  does next, not an estimate. Gate: `catch_up_sliced`
  (`eseval.run_catch_up_eval`, on `eseval.gap_docs` with `GAP_JOBS` 12,000
  job names spread over the seven-day gap, the stub charging the slice
  and wide rates): the before and after figures above, the cover one range
  from its old start to now, 145 refusals while behind with the
  slices-left count 7 first and never increasing, the case shown and the
  name hidden after, and no value in the build log.
  Anything that scrubs pages outside the bridge (es-eval's `Session`,
  tests) must build and apply first: `eseval.build_vocabulary`,
  `eseval.learn_vocabulary`.

  **Declared cost of the cap, new and the sharper one: a real name field
  with more distinct values than `vocabulary.max` is left unread under
  the default field set, so its values stay readable in message text.**
  Before, such a field took the whole slice down and the failure was
  loud - nothing ran, which nobody can miss. Now the build finishes and
  the field is simply absent, which is quiet, and **the `VOCAB` line is
  the only place a user sees it** (`OVER CAP, NOT READ (readable in
  text): field~count>cap`, from `VocabularyIndex.report`'s `over_cap`,
  via `Bridge._apply_vocabulary` and `EsScrubber.vocabulary_report`).
  Nothing refuses because of it: a case runs, the page looks clean, and
  that field's names are English in the text. The ways out are the two
  the refusal names - raise `vocabulary.max` (ceiling 200,000; it costs a
  page per 1,000 values per slice) or, if the site wants the failure
  rather than the silence, list the field in `vocabulary.fields`, which
  restores the refusal. A site that does not want the field read at all
  should list the others, which is reported as `omitted` and is the same
  cost stated at load time.
  Two smaller ones: the count is approximate, so a field within 5% of the
  cap is left out of the default set even if it would have fitted; and a
  field whose cardinality drops below the cap is still skipped until the
  decision expires (`VOCABULARY_OVER_CAP_S`, a day).

  **Declared miss: a one-word tenant name the skip rules drop stays
  readable.** Many real tenants are one word, and a one-word value on
  `ORDINARY_NAME_WORDS` or shorter than four characters is never made
  vocabulary, because registering it would hide that word from every
  message. Of the eight invented one-word names in
  `eseval.DEFAULT_MAP_ONE_WORD`, three are dropped (`Archive` and `Vault`
  as `ordinary_word`, `Ops` as `short`) and two of those are then
  readable in message text; the third happens to be caught by tier 2,
  which is luck and not a rule to rely on. A site whose tenants are
  called `Archive` or `Vault` gets no vocabulary protection for them and
  must seed the name with `--term`. Widening the vocabulary is not the
  fix: that is the skip rules' trade, and loosening it erases the word
  everywhere.

  **A name that is an ordinary word keeps its label and stays a word.**
  The skip rules only decide what becomes *vocabulary*; harvesting went
  round them. `_harvest_hit` labels every identifier value on a page and
  `jsonscrub._remember` indexed it for the case-wide sweep, so one
  document whose `job.name` was `Backup` took the word out of every later
  message ("Backup window opened, 14 mailboxes queued" came back as
  "`<Job-12>` window opened"). About 7 in 100 common job names are
  ordinary words, so it happened on the first pages, and **what a page
  said depended on which pages came before it**.
  Now: for a field the vocabulary *could* learn, a value `vocabulary_skip`
  would drop is labelled in its own field as before and is **not** indexed
  for the sweep (`EsScrubber.readable_in_text`, `readable_words`). The
  document that owns it still hides it in its own text (`_local_sweep`
  indexes it for the length of one hit, which is what makes a page
  order-independent), and `_sweep`'s whole-string branch honours the same
  rule. A **seeded** value is untouched - `--term Backup` is a human
  saying "hide this word", and `seed` (at case open, before any page)
  does not go through a learnable rule.
  **The leak check treats these words as readable, by construction**: it
  asks "did a value we promised to hide survive" and reads the same sweep
  index the substitution does, so a word kept out of the index is out of
  both. The alternative - calling it a leak - would refuse every page
  that uses the word in English, which is every page.
  **Declared miss:** if a customer really is called `Backup`, the word is
  readable in message text on every document except the one whose own
  field names it. Seed it to hide it everywhere.
  **Declared default for a case saved before this**: such a word is
  demoted on load, so a restored case scrubs a page exactly as a fresh
  one does - determinism is the point. The cost: a word that case was
  hiding case-wide becomes readable outside its own document, and an
  ordinary word the human *seeded* is demoted with the rest, since a
  restored session has only the type to tell them apart. Seed it again.
  A case saved after the change stores `readable_words` (labels only).
  Gate: `ordinary_words_readable` on `eseval.ORDINARY_WORD_JOBS` - seven
  ordinary-word job names, fixed documents appended after the estate and
  deliberately *outside* `vocabulary.days`, since these labels come from
  harvesting a page rather than from the build. A page showing them in
  their own fields, then a page of ordinary messages using the same
  words: **7 of 7 words lost before the rule, 0 after**, all 7 still
  labelled in their own field, all 7 still hidden in the owning
  document's text, the label still filters, and the second page reads the
  same with no page before it. `ordinary_words_case_wide` is the
  measurement switch behind the "before" figure and is set by nothing in
  the live path.
  **The same rule covers JSON exports** (`jsonscrub`), which had the same
  bug through a different door: any value under an identifier key was
  swept across the whole export, with only `_STOPWORDS` kept out. Measured
  on the invented three-ticket export in `test_jsonscrub.py`: **3 of its 6
  name values are ordinary words and one ticket's note lost all three;
  after the rule it loses none**, while the real names stay hidden.
  `jsonscrub._ordinary_name` is deliberately narrower than
  `vocabulary_skip` - a **one-word** value on the shared list, under the
  name-key families (`ORG_NAME`, `PERSON_NAME`, `NAME:*`) only - because
  adopting the `short` and `no_letters` reasons would stop sweeping the
  short numeric values whose export-wide sweep is the measured trade
  pinned by `test_short_values_are_swept_and_the_trade_is_measured`.
  That trade, seeded terms (a value already known is never demoted; the
  harvest checks `known` first) and the list's contents are all unchanged.
  **A record is an element of the top-level list**; any other shape - a
  single object, or a dict wrapping its lists - is one record, the whole
  export, so in a single-object export the word is hidden throughout,
  as before. Hiding more inside one record is the safe direction;
  guessing deeper boundaries is not, since a wrong guess leaves a name
  readable beside its own field. `_rewrite_record` /
  `_record_ordinary_words` use the same index-overlay mechanism, with the
  overlay derived from what the harvest decided so the two cannot drift.
  **The one word list** is `jsonscrub.ORDINARY_NAME_WORDS` - both
  scrubbers read it and the import direction only allows `elastic ->
  jsonscrub`; `elastic.ORDINARY_NAME_WORDS` re-exports the same object
  (pinned by a test). Contents unchanged.
  Tier 2 may still label such a word in free text on its own judgement:
  unchanged, and left for later.

  **A case can be read back** (`es-review --case NAME`, `hider/esreview.py`)
  from its decision log and saved session, because the log recorded a
  great deal per query and nothing read it: after a session nobody could
  tell an investigation from a case spent probing without reading the
  JSONL. The command is **human-only** (no MCP tool, nothing the
  es-research session can call or read), **read-only** (it writes
  nothing), prints **counts, labels, codes, field names and Claude's own
  typed phrases** by default and the values behind labels only under
  `--show-values` (the same explicit ask as es-smoke's
  `--show-readable-names`), reports a missing or unreadable log as **no
  review** with a non-zero exit and never as a clean case, and reviews a
  log written before it existed with each gap marked `not recorded`.
  It shows the numbers (queries by tool, pages shown, hits, refusals by
  code, labels and keep values the case ended up able to use from
  `session.json` or the log's running totals, labels issued) and the
  phrase spend against the budget, then five signals, each with its
  evidence and a note on what an innocent case looks like; the
  thresholds sit together at the top of the module:
  - `label_guessing`: 3+ `unknown_label` refusals, or a run of 3+
    consecutive label numbers among the labels typed (innocent: 0-2, a
    typo or a label off an older page);
  - `zero_hit_phrases`: 5+ name-shaped phrases (one to three capitalised
    words, no digits) that found nothing, or 20+ phrases with half
    finding nothing (innocent: a handful of lower-case error fragments
    while narrowing);
  - `phrase_budget_pressure`: any `phrase_budget` refusal, or 80% of the
    budget spent (innocent: tens of phrases and no refusal);
  - `wide_collection`: one **aggregation** that made 20+ labels or keep
    values usable - pages of hits are not counted, since a page of
    events carries a handful of labels per event and reading events is
    the job (innocent: a terms over servers or levels, about ten keys);
  - `literal_probing`: 3+ `known_value`/`literal_identifier`/
    `shaped_literal` refusals, with the fields (innocent: 0-1, a value
    typed back before it was shown, then corrected to the label).
  Three fields were added to the decision log for it, all counts or
  Claude's own words: `new_labels`/`new_keep_values` (how many a page made
  usable) with the running totals `labels_usable`/`keep_values_usable`,
  and `zero_hit_phrases` (the typed phrases whose filter or `filters`
  bucket matched nothing - already in `text_queries`, so the log holds
  nothing it did not). Gate: `review_flags_guessing` - the guessing run
  from `phrase_budget_holds` is flagged (`zero_hit_phrases` and
  `phrase_budget_pressure`), an ordinary investigation on the fixture
  (page by tenant label, servers and levels aggregated, a server label
  off that page used next, two error fragments searched, a histogram) is
  not and has no refusal, a case directory with no log is `missing` with
  no verdict, and the default output of both carries no planted value.
  Declared limits: the signals read the shape of what Claude typed, not
  its intent, so a long and clumsy investigation can trip
  `zero_hit_phrases` and a case about many tenants can trip
  `wide_collection` - the innocent note under each flag is there to be
  read; and a bridge not restarted since this change writes none of the
  new fields, which the review then marks rather than infers.

  **Every run says which names stayed readable**, because a clean verdict
  looks identical whether or not it happened, and nobody can seed a name
  they were never told about. Split by who reads the surface:
  - **labels** where the output is persisted or machine-read: the
    `readable_words` key in `jsonscrub`'s run stats and in `.scrub.json`
    (`research.write_scrub_record`). Same rule as the leak list, and
    non-negotiable 7 - those files carry decisions, not data. It is
    **not** a refusal; `scrub_verdict` ignores it, because the run is
    clean and this says what clean does not cover.
  - **the words** only where a human asked: `scrub-json`'s `READABLE:`
    line and the web UI's stats panel resolve the labels against the
    mapping already on that machine. `es-smoke` prints the **count, the
    labels and the field each came from** by default and the words only
    under `--show-readable-names`, which also decides whether they are in
    the report at all (`run_case(show_names=...)`): that output is read
    by scripts and agents as well as people, so a customer name never
    arrives there unasked. The field is a decision, so it is always
    shown, and it is what tells an operator which name to go and look at.
  The bridge's decision log carries counts and labels and **never these
  words**, pinned by a test, and the `es-research` Claude Code session
  never sees the line. Seeding a reported name takes it off the next
  run's list - the loop the report exists to close, pinned by a test.

  **A label may be used only after the case has been shown it.**
  `_learn_vocabulary` labels every name, so applying a cluster vocabulary
  puts a label for every customer on the estate into the case mapping
  (20,033 `ORG_NAME` labels on the fixture) and `resolve_label` accepted
  anything in the mapping. A case about one tenant, shown only
  `<Org-01>`, could filter by `<Org-77>` - a guess - have it resolve to
  `BRINDERWOLD GROUP`, a tenant it had never seen, and the query would
  run: nobody unmasked, but the case could reach and count **every
  customer on the cluster**, which it could not do before the vocabulary
  existed.
  `EsScrubber.shown` is the per-case set of labels the case has actually
  been shown - seeded by the human, or carried in a page, an aggregation
  or a bucket key that went back to Claude. `mark_shown` fills it with
  one walk over the finished output after the leak check: one choke
  point, rather than a hook in each rewrite path, so a label cannot reach
  Claude by a route that forgot to mark it, and a refused page shows
  nothing and teaches no label. It is saved in `session.json` and
  restored with the case. Both label paths in `esquery` - the filter
  value and a label inside a phrase - resolve through `shown_label`,
  which returns None for a label that exists but has not been shown, so
  the refusal is `unknown_label` with the **same message** a label that
  was never issued gets: a refusal must not tell a live guess from a dead
  one, or it becomes the oracle itself. Scrubbing and label numbering are
  untouched; `resolve_label` still unmasks an answer for the human.
  Oracle cases, written first: `unknown-label` (a number no case issues)
  and `vocabulary-label-never-shown` (`<Org-77>`, live on the estate),
  both declared `unknown_label`. A guess is refused at compile time, so
  **no request reaches Kibana**, and the decision log row carries `label`
  - what Claude typed - and never a value (`Refused.label`).
  **Declared default for a case saved before this**: it starts with
  nothing shown. The mapping cannot stand in for the shown set - a case
  saved after a vocabulary was applied holds a label per estate name, and
  trusting those would restore the whole channel - so an old case must
  see a label on a page again (one query) or have its term re-seeded.
  Unmasking an already-written answer is unaffected.
  **What stays open**: nothing stops a case *collecting* labels by
  running wide queries - a page of `max_hits` hits shows that many
  labels, and those are legitimately usable afterwards, so the reachable
  set grows with ordinary work; the cap is `max_hits` and `max_buckets`,
  not this rule. Label numbers are still sequential and guessable, so a
  guess is cheap to make - it is only refused, and the refusal says
  nothing. And the text-phrase counting channel above is unchanged.

  **Keep fields are checked, not trusted.** A keep field used to pass
  through unchanged on the declaration that it holds nothing sensitive,
  and a real level field held a SharePoint personal-site URL among its
  `info`/`Warning`/`ERR` spellings - reaching Claude in hits and as a
  bucket key when the field was aggregated. Every string keep value now
  goes through `EsScrubber._keep_value`: tier 1 plus the known-value
  sweep via `_scrub_text(shaped_only=True)`, never tier 2, in hit leaves
  (`_rewrite_leaf`) and in terms-bucket keys and `key_as_string`
  (`_rewrite_agg`); a match is replaced the way a text field would
  replace it and the bucket stays one bucket under its rewritten key.
  Strings of only digits and time punctuation (`_TIME_SHAPED`:
  timestamps, durations, versions - no identifier fits that alphabet)
  skip the pass, and `jsonscrub._detect_cache` makes repeated values one
  detection, which is why es-eval is not measurably slower.
  **Declared misses and costs:** a keep value tier 1 recognises is
  labelled, so Claude cannot filter by it (a keep field takes literals
  and it only has the label) - for a value like that URL this is the
  point, but it also hides a benign keep value that happens to be
  identifier-shaped (a public-TLD FQDN in a dataset name, say), the same
  fail-toward-redaction trade the recognizers make everywhere; a
  sensitive keep value tier 1 has no shape for (a bare name as a level,
  with no URL, GUID or domain around it) still passes, because tier 2
  deliberately stays off keep fields - a classifier guessing at names
  inside level spellings is how `Critical` stops being filterable; and a
  sensitive value under `keep` is a site-map error first, this pass being
  the net under it.
  **Known values match a keep value whole, unless seeded.** Once the
  name vocabulary put ~10,000 names into the sweep, a job called
  `Harborsync` turned the stream `logs-agent.harborsync_events-prod`
  into `logs-agent.<Job-NN>_events-prod` in `_index`, the dataset and the
  namespace (6 fields across 3 of 50 hits on one site), and Claude could
  no longer filter by the dataset. Now a name **learnt from the
  vocabulary or harvested from a page** replaces a keep value only when
  it *is* the value (case and outer spaces ignored); a value the human
  **seeded** (`EsScrubber.seeded_labels`, saved with the case) and
  anything tier 1 recognises by shape still match anywhere. The same
  rule holds for terms-bucket keys, `key_as_string` and the hit's
  `_index`; text and identifier fields are untouched. The pass-3 sweep
  and the leak check are schema-blind, so `_keep_value` marks its result
  (`elastic._KeepStr`, removed by `_unmark` after the leak check) and
  both apply the same rule to it; the leak check still refuses a seeded
  value inside a keep value, or a known value that is a whole one.
  **Declared cost: a customer name inside a longer keep value is
  readable** - an index, dataset or namespace named after a customer
  (`logs-agent.contoso_events-prod`) shows the name to Claude, and so
  does any keep field whose value merely contains one. What a site
  should do: a stream named per customer is a site-map fact, so declare
  it - map that field as an `identifier` rather than `keep` (it is then
  labelled whole and filterable by label), and keep such streams out of
  `indices` if the index name itself must not be seen; for a single
  case, `--term <name>` seeds it, which hides it inside keep values and
  index names again. A case saved before seeds were recorded has none,
  so its seeded values match keep values only whole until re-seeded.
  Gate: `stream_name_readable_in_keep` (below).
  **A keep literal that contains a learnt name may be used only after the
  case has been shown that exact keep value.** Readable was not usable:
  `esquery._gate_literal` refused any literal containing a known value,
  so the dataset above came back as written and a filter on it was
  refused with `known_value`. Widening the gate to whole-value matching
  would have opened a new channel - a guessed name inside a dataset
  literal, confirmed by a hit count - so instead `EsScrubber.shown_keep`
  records every keep value a page showed (a hit's keep leaf, a terms
  bucket key or `key_as_string`, `_index`), at the one point `shown`
  records labels: `mark_shown`, after the leak check and before
  `_unmark`, which is what still tells a keep value apart. Saved in
  `session.json` (values, so in that file and nowhere else) and
  restored with the case; a case saved before this starts with none and
  must see the value on a page again. An `eq`/`in` literal on a keep
  field passes the gate (`EsScrubber.keep_literal_shown`) when it *is* a
  shown keep value (case and outer spaces ignored), is not itself a known
  value, and contains no seeded value. Everything else is refused with
  the same code and the same words as today, so the refusal cannot tell a
  guess from a value never shown: a keep literal with a learnt name that
  was not shown, a seeded value anywhere, a value that is itself a whole
  learnt name (shown only as its label), tier 1 shapes, every text phrase
  and every range bound. Oracle cases, written first:
  `learnt-name-in-keep-literal-never-shown` (`known_value`; the oracle
  session learns `esquery.ORACLE_LEARNT` the way a page would, not
  seeded, and the es-eval sessions and the MCP case know the same name
  from the vocabulary) and `esquery.SHOWN_KEEP_CASES`, the same literal
  accepted once the page in `shown` has come back.
  **What stays open**, as with labels: a wide query collects shown keep
  values - every index, dataset and level on a page of `max_hits` hits or
  `max_buckets` buckets is usable afterwards, so the reachable set grows
  with ordinary work, and the cap is those two numbers. A keep value with
  a learnt name inside it is still a name shown to Claude; the rule only
  decides whether it may be typed back.
  **A case's first query is gated like every other.** `Bridge.run`
  compiled before it applied the cluster vocabulary, so a fresh case's
  first query was gated against its seeds only: a learnt job name inside
  a dataset literal ran and returned a count. Now the order is compile
  (a query the grammar refuses on its own keeps its declared code
  whether the vocabulary is ready, building or absent), apply (local, no
  request, once per case per cluster; `vocabulary_building` until it
  serves), compile again if that call is the one that applied it, then
  the probe and the request. The first query with a learnt name in a keep
  literal is refused `known_value` with the words a later query gets,
  and nothing reaches Kibana. Cost: a case's first query compiles twice;
  and while the vocabulary is building, a literal carrying a learnt name
  is refused as `vocabulary_building` like any well-formed query, not as
  `known_value` - the bridge cannot know the name yet, and that order
  sends nothing and says nothing about the guess. A bridge with no index
  is unchanged. Test: `test_esbridge.py`
  `test_a_fresh_cases_first_query_is_gated_against_the_cluster_vocabulary`;
  the stream gate runs on the real `Bridge` (`eseval.BridgeCase`).
  `es_schema` and the esmcp instructions tell Claude that keep fields
  hold spellings as logged (err/Error/ERROR): aggregate a keep field's
  values before an exact filter, then filter with `in` across the
  spellings; values are never normalised. A case saved before the
  log-vocabulary trim may hold "Info" as a value - `load_session` keeps
  such labels for unmasking but not as known values
  (`elastic.log_vocabulary_only`).

  **The realistic estate** (`eseval.estate_docs`, the `estate=True` half
  of `generate`, reported under `realistic estate`) is what the
  readability misses are measured on, because the tidy fixture - eight
  tenants, seven level spellings, twelve thousand job names of one shape
  - cannot show which *shapes* survive. It is 10,000 tenants, 10,000 jobs
  and 100 resources in the shapes and proportions measured on one real
  cluster (shapes and counts only, no values; every name invented, built
  by position), with 149 free-text mentions carrying no marker, and the
  seventeen level and three outcome spellings at their measured skew
  (commonest level 47x the next, success 661x failure). Like `BULK_JOBS`
  it is appended after the RNG stream and holds **no ground truth**, so
  every existing gate sees what it saw. Thirteen shape classes, one page
  and one report line each.
  Result: **every shape is hidden except one-word names the skip rules
  drop** - 24 of 149 mentions, all `ordinary_word`/`stopword`, 800 of
  20,100 names - which is the declared miss above, reported and not
  gated. `estate_no_unexpected_readable` fails on anything else readable,
  whole or by a word; `estate_spellings_unchanged` pins all twenty
  spellings byte-for-byte as hit values and as bucket keys. All-caps
  names, names with digits and four-word job names are covered. When
  adding a shape, add a class, not another fixture.

  **Gates.** `es-eval` runs the fixture end to end and through the real
  MCP endpoint; all 32 pass, and a change that cannot keep them passing
  is a design conversation. Page safety: `no_leaks`, `no_degraded`,
  `unlisted_never_shown`, `fresh_case_no_leaks` (with the word-by-word
  `eseval.name_part_leaks`, since a half-hidden name passes the
  whole-value check), `round_trip_complete`. Grammar:
  `oracle_all_refused`. Vocabulary: `default_map_names_hidden`,
  `window_case_shown` (a one-hour case served from the build at no cost
  to itself, on the `BULK_JOBS` back catalogue of 12,000 invented job
  names), `vocabulary_building_refuses`, `vocabulary_build_in_budget`
  (per slice, plus zero pages charged at the wide rate),
  `vocabulary_slices_serve_early` (`eseval.run_slice_eval` drives the
  real `Broker` one step at a time against `SteppedSearchTransport`,
  which hands a page back over as many polls as its cost: a case shown
  off the recent cover while older slices build, refused before it, every
  ping answered, no step longer than one poll interval),
  `over_cap_field_left_out` (`eseval.run_over_cap_eval`, on
  `eseval.over_cap_docs`: an invented `request.ref` field with a fresh
  value on nearly every document, **5,500 distinct in a day against a
  5,000 cap**, in its own index pattern with its own map, driven through
  the real `Broker`. **6 requests on that field and then the slice
  refused before the rule, against 1 distinct count for the whole cover
  after it** - 51 a slice at the default cap - the build finishes, the
  first case about a day in the cover is shown with the name hidden
  (tier 2 off, and the same page with no vocabulary does show the name),
  the field and its count are on the `VOCAB` line, the build log carries
  no value, and a map that lists the field in `vocabulary.fields` is
  still refused with a message naming it). Readability:
  `estate_no_unexpected_readable`, `estate_spellings_unchanged`,
  `ordinary_words_readable`, `keep_leak_closed` (the invented URL in
  `eseval.KEEP_LEAK_VALUE`, shown through a hit and through an
  aggregation; both leaked before the pass), `keep_values_readable`,
  `stream_name_readable_in_keep` (`eseval.run_stream_name_eval` on
  `eseval.stream_name_docs`: three documents in an invented stream
  `logs-agent.harborsync_events-*`, appended after everything else in an
  index pattern and map of their own, tier 2 off; the index, dataset and
  namespace come back as written in hits and as bucket keys, the job is
  labelled in `job.name`, in both messages and in a keep field holding
  the whole name. **Keep values changed: 12 of 20 before the rule, 1 of
  20 after**, the one being the whole-name field; "before" is the
  `keep_parts_swept` measurement switch, set by nothing in the live path.
  Then the dataset literal: refused as `known_value` with **0 requests**
  by a fresh case never shown it, **3 hits** - the whole stream - for the
  case the page showed it to, and the whole job name typed as the keep
  field that held it refused still).
  `phrase_budget_holds` (`eseval.run_phrase_budget_eval`, on the stream
  fixture through the real `Bridge`): 500 queries of 8 candidate names
  each, one in ten a phrase that does match. **4,000 phrase uses (3,601
  distinct) reached Kibana with no budget; 160 (145 distinct) with the
  default**, the other 480 queries refused `phrase_budget` with 0
  requests and one refusal shape whether the batch held the matching
  phrase or not, and a reused and a label-only phrase still run once the
  case is spent out.
  `review_flags_guessing` (`eseval.run_review_eval`, see "A case can be
  read back" above). `gap_fails_closed` (`eseval.run_gap_eval`, on
  `eseval.gap_docs`: a cover ending a week ago against the one-hour
  bound; the gap tenant is readable on that page with the gate off, is
  refused with 0 requests and `catching_up` with it on, the first top-up
  is the gap itself, after it the same open case is shown with the name
  hidden, and a cover ten minutes behind serves). `catch_up_sliced`
  (`eseval.run_catch_up_eval`, see "The catch-up is read in slices"
  above).
  Label use: `label_guessing_refused` - a fresh case on the estate
  guesses a hundred low-numbered labels, **100 of 100 are live labels it
  holds, 100 of 100 refused, 0 reach Kibana**, a nonexistent label
  refuses identically, and a label off the next page does work in the
  query after it, because the rule must not break the tool. Through MCP:
  `mcp_protocol`, `mcp_no_leaks`, `mcp_fresh_case_shown`,
  `mcp_oracle_all_refused`, `mcp_round_trip_complete`,
  `mcp_requests_rejected`, `mcp_log_clean`, `mcp_launch_isolated`,
  `mcp_prompt_gate`.
  Fixed documents for the readability checks are appended after the RNG
  stream so nothing existing moves: `UNMARKED_JOBS`, `UNMARKED_NAMES`,
  `DEFAULT_MAP_*`, `ORDINARY_WORD_JOBS`, the estate, `OVER_CAP_*`,
  `STREAM_*` and, last of all, `GAP_*` (the last three the only ones in index patterns of
  their own, so no other query, build or count pays for them; they hold
  no ground truth either - `OVER_CAP_TRUTH` is that gate's own).

## Where to take questions and findings

See `CONTRIBUTING.md`. In short: a missed or wrong redaction observed on a
real bundle goes through the web UI's "Report a mistake" form (it stays on
the machine) and reaches the repo only as a placeholder template or a
synthetic adversarial case; everything else goes to GitHub issues.
