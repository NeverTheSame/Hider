# Roadmap

Independently startable tasks. Each says why it matters, where to look and
what "done" means. All work follows CONTRIBUTING.md: synthetic data only, and
`make check` plus `make eval` must pass.

## 1. Detect well-known vendor token formats

**Why.** Tier 1's `API_KEY` recognizer (`recognizers.api_key`) only matches the
`sk-`, `ak-`, `vk-` and `pk-` prefixes. GitHub tokens (`ghp_`, `gho_`,
`github_pat_`), AWS access key IDs (`AKIA`/`ASIA` + 16), Slack tokens (`xox?-`)
and Google API keys (`AIza` + 35) pass through untouched unless context words
happen to sit nearby.
**Where.** `entities.py` (extend the `API_KEY` spec's generator so the corpus
plants them), `recognizers.py`, `tests/test_recognizers.py`.
**Done when.** Each format is destroyed in a unit test, the generator plants
them, `make eval` reports them under `API_KEY` with no unexplained survivor,
and any new base64 or filler vocabulary is added to `ALLOWED_TOKENS`.

## 2. Close the zero-padded IPv4 gap

**Why.** `adversarial.py` carries a declared known gap: the stock IP pattern
rejects zero-padded octets such as `010.020.030.040`. It was left visible on
purpose; fixing it is a one-pattern change.
**Where.** `recognizers.py`, the matching case in `adversarial.py`.
**Done when.** The case flips to "expected caught" with its owner note
removed, the build-number suppression (`8.1.0.7` is not an IP) still holds,
and the README's known-gap count drops by one.

## 3. Close the forward-slash Windows profile path gap

**Why.** `windows_user_path` only matches backslashes, so
`C:/Users/<name>/AppData/...` keeps the account name. Also a declared known
gap in `adversarial.py`.
**Where.** `recognizers.windows_user_path`, `adversarial.py`, tests.
**Done when.** Both slash styles and mixed slashes are caught, the adversarial
case expects a catch, and the false-redaction rate on clean lines stays 0.

## 4. Stream large inputs through `redact`

**Why.** `cli._cmd_redact` reads the whole file into memory before splitting
it into lines, which does not scale to multi-gigabyte bundles.
**Where.** `hider/cli.py`, possibly a small `iter_lines` helper in
`pipeline.py`.
**Done when.** `hider redact FILE` processes line by line with constant
memory, writes output incrementally (stdout or `--out`), keeps the decision log
identical for the same input, and a test covers a generated file larger than a
chosen buffer size.

## 5. Parallel redaction and a committed benchmark

**Why.** Redaction is per line and pure given the vault, but runs on one core.
The README no longer quotes throughput because no committed code measures it.
**Where.** New `hider/bench.py` and a `hider bench` subcommand; a
multiprocessing path in `cli._cmd_redact` with a shared, deterministic vault
key.
**Done when.** `hider bench` prints lines per second per tier on the generated
corpus, `--workers N` gives the same output as `--workers 1` byte for byte, and
the README can quote throughput with the command that produced it.

## 6. One validated config file

**Why.** Settings live in two places with two loaders: site profiles
(`HIDER_PROFILE`, `profiles.py`, add-only patterns) and `hider.local.json`
(`localcfg.py`, portal URL and vendor allow-list), plus CLI flags.
**Where.** `profiles.py`, `localcfg.py`, `cli.py`.
**Done when.** A single `--config PATH` (and `HIDER_CONFIG`) loads both
sections with the existing validation rules (profiles may only add patterns;
a malformed file is a startup error), the old variables keep working with a
deprecation note, and tests cover each error path.

## 7. CSV input for `scrub-json` and machine-readable stats

**Why.** CSV log parts need a separate `merge-csv` step before `scrub-json`,
and `scrub-json` reports its counts only as prose on stderr.
**Where.** `cli.py`, `csvmerge.py`, `webserver.obfuscate_text`.
**Done when.** `hider scrub-json part1.csv part2.csv ...` merges and
obfuscates in one call, `--stats-json PATH` writes the stats dict
(mapped values, leaks, degraded lines, counts by type), and exit codes are
unchanged.

## 8. Phrase-level over-redaction filter in `jsonscrub`

**Why.** Tier 2 hits made only of common words are already not propagated,
but two-word title-case phrases ("Key Vault", "Tax Compliance") can still be
masked as person names where found, which costs readability.
**Where.** `jsonscrub._is_noise`, `jsonscrub._trim_name`, a small curated
phrase list next to `_LOG_VOCAB`.
**Done when.** A synthetic test shows such phrases preserved while real
two-word names next to them are still masked, and the existing jsonscrub tests
pass unchanged.

## 9. Robust unmasking of labels the model reformatted

**Why.** `research.unmask` handles exact labels and labels with dropped angle
brackets. Models also escape them (`\<Person-03\>`), HTML-encode them
(`&lt;Person-03&gt;`) or split URL labels across Markdown links.
**Where.** `research.unmask`, `research._BARE_LABEL`, `tests/test_research.py`.
**Done when.** Each variant maps back only when the canonical label exists in
the mapping, unknown variants are still listed rather than guessed, and the
current tests pass.

## 10. Use reserved address ranges in the synthetic IPv4 generator

**Why.** `entities._ipv4` picks a first octet of 10, 172 or 192 but random
later octets, so it can produce routable public addresses (for example
`172.170.x.x`) instead of RFC 1918 or RFC 5737 ranges.
**Where.** `entities._ipv4`, then regenerate `docs/sample-report.html`.
**Done when.** Every generated IPv4 is in `10/8`, `172.16/12`, `192.168/16` or a
TEST-NET block, a test asserts it over many seeds, and the README metrics are
re-run and updated in the same change.

## 11. Honest SSE streaming in the proxy

**Why.** `proxy.py` answers `stream: true` with a 400, because de-tokenising
fragments can corrupt a label cut across chunk boundaries.
**Where.** `proxy.py`, `tests/test_proxy.py`.
**Done when.** Streaming responses are relayed with a small hold-back buffer
that never emits a partial label (bounded by the longest label shape), the
upstream request is still redacted before forwarding, a degraded request is
still refused, and tests cover a label split at every byte offset.

## 12. Larger injection-payload set for tier 3

**Why.** Tier 3's injection measurement rests on 5 payload variants.
**Where.** `adversarial.INJECTION_MIXED_CASES`, a new cassette under
`cassettes/`.
**Done when.** At least 20 varied payloads (instruction override, fake JSON,
role-play, encoded instructions) sit next to seeded synthetic names, a new
cassette is recorded and committed, and the README reports the replayed
result as an example run with its caveats.
