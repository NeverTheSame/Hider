# Detection: known gaps, fences and declared misses

Moved verbatim from `AGENTS.md` ("Known gaps worth knowing before you start"). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

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

## `redact` sweeps the whole file

`python -m hider redact` reads a file line by line, so a value that tier 1
reads only behind a cue (a case number after the word "case", a key before a
value) or that tier 2 reads in one sentence and not in a table cell stayed
readable on the lines where it stood bare. After the per-line pass `redact`
now replaces every remaining occurrence of a pseudonymised value with its
label, using `hider/sweep.py`, the same function the gateway runs on a
request. Each replacement is a decision event with `tier: "sweep"`; offsets
in it are into the output line as the sweep read it. `--sweep tier1` limits
it to values tier 1 found and `--sweep off` removes it, both for measurement;
the default is `all`.

What it does not do, by design: a secret is destroyed, never vaulted, so a
bare repeat of one on another line is not swept (tier 1 owns every credential
shape, see AGENTS.md). A name a person lowercased is not swept, the accepted
trade documented in `sweep.known_values_rx`. A tier 2 false positive (an
ordinary word taken for a name) is now replaced everywhere in the file, not
once; that is the price of sweeping values tier 2 alone found, and the reason
`--sweep tier1` exists. Shorter forms of a value (an 8-hex prefix of a GUID,
a host without its suffix) are not the vault's value and are not swept.

Measured once, on one real support-case note (markdown, 126 lines, 51
values a reader listed by hand; an observation, not a figure): with no sweep
15 values were hidden; with the sweep 19. The 7 replacements made for values
tier 1 had found were all right (a case number standing bare in a table, a
path, a link). Of the 12 made for values only tier 2 had found, 1 was a real
first name and 11 were tier 2's own wrong guesses repeated. The 30 values
still readable were never found by any tier - site shapes with no rule and
no site profile - which no sweep can help.

A label already in the text is never matched into (`sweep.Sweeper`): a
vaulted word that is also the word inside a label turned `<Person-01>` into
`<<Org-01>-01>` in that run and, the code being shared, could in the gateway
too. Every label the vault issued, anything shaped like one and every
destroyed-secret marker is skipped by the sweep and by the gateway's
leftover check alike. Pin: `tests/test_sweep.py`.

## `redact --term`: a name a person already knows

The tiers find a customer's name only by its shape or its sentence, so a name
that is also an ordinary word, or a three-letter abbreviation, stays readable.
`scrub-json` has taken `--term` for this since the web UI; `redact` now takes
it too (repeatable). Each term gets an `ORG_NAME` label from the vault before
the first line is read, and `sweep.TermReplacer` replaces it on every line
before the line goes to the tiers, so the switches do not matter: it works
with `--sweep off` and `--tier2 none`. A term matches in any casing, whatever
its length, and only as a whole word (no letter or digit directly before or
after it); where one term contains another the longer wins. An empty term
ends the command with exit code 2. Each replacement is an event with
`tier: "term"`, in the shape of the sweep's, and no event carries the term.
The per-line pass leaves a label already in the line as it is, so the terms
run first. What it does not do: a term is not a prefix pattern (`scrub-json`'s
`NAME*` form is not taken), and a shorter form of a name (a surname alone) is
a different term and has to be given.
