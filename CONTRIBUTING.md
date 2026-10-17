# Contributing to Hider

Hider is a redaction library, so the one rule that outranks every other one is
about data.

## The rule: no real data, ever

Nothing real enters this repository: no real log bundle, no real secret, no
real email address, name, IP address, phone number, hostname or tenant, and
not an excerpt of one either. That holds for code, tests, fixtures, templates,
cassettes, docs, commit messages and issue text.

- Every fixture is synthetic. Use the made-up companies and people the tests
  already use (Contoso, Fabrikam, Northwind, Litware, Tailspin), the reserved
  `.example` domain, `203.0.113.0/24` and the `555-01xx` phone range.
- Fake secrets must look fake on inspection (`sk-abcdefghijklmnop...`,
  repeated filler runs). If a fixture carries a base64 payload,
  `tests/test_hygiene.py` decodes it and fails unless every word inside is in
  its `ALLOWED_TOKENS` list. Adding a payload means adding its vocabulary there
  on purpose.
- To capture the *structure* of a real log format, follow "Working from real
  bundles safely" in the README: extract placeholder-only templates where the
  real data already lives, review them there, and bring only the templates
  out.
- Runtime output goes to `out/`, which is gitignored, including JSON mappings
  that hold real values. Deployment-specific settings go in the uncommitted
  `hider.local.json` or a site profile pointed at by `HIDER_PROFILE`.

If you find real data in the repository or its history, do not paste it into
an issue. Report the commit and path only.

## Where the data comes from

The eval corpus is not stored in the repository. `hider/generator.py` builds it
at run time from `templates/support_bundle.json` (log line skeletons with typed
placeholders) and the value generators in `hider/entities.py`, using a seeded
`random.Random` (seed `20260820` by default), and records exact ground truth
for every value it plants. `hider/adversarial.py` adds hand-written hostile
placements, all with invented values. `cassettes/tier3-injection-run1.jsonl`
is a recorded tier 3 run over those same synthetic adversarial cases.

## Setup and checks

```sh
make install        # python3 -m venv .venv && pip install -e ".[dev]"
make test           # pytest
make lint           # ruff check
make format         # ruff format, then safe ruff fixes
make check          # lint + format check + tests, what CI runs
make eval           # redaction recall on the synthetic corpus, writes out/
```

Optional extras: `pip install -e ".[ner]"` for the spaCy tier 2 backend,
`pip install -e ".[llm]"` for tier 3. Without the `ner` extra, the spaCy tests
(`tests/test_ner.py` and one eval test) are skipped; everything else runs from a
clean clone with only `.[dev]`, with no network and no API key.

## Layout

| Path | What it is |
|---|---|
| `hider/entities.py` | The contract: the 18 sensitive value types, how each is formed, which tier owns it, and whether it is destroyed or pseudonymised. |
| `hider/recognizers.py` | Tier 1 regex recognizers and their suppression rules. |
| `hider/classifier.py`, `hider/ner.py` | Tier 2 backends: the local token classifier (default) and spaCy NER. |
| `hider/llm_tier.py`, `hider/llm_backend.py` | Optional tier 3 and its backends, including the replay cassette. |
| `hider/pipeline.py` | Tier ordering, span algebra, monotonicity and fail-closed handling. |
| `hider/pseudonym.py` | Shape-preserving pseudonyms and the vault. |
| `hider/profiles.py`, `hider/localcfg.py` | Site profiles and local settings, both uncommitted. |
| `hider/jsonscrub.py`, `hider/csvmerge.py` | JSON export obfuscation and CSV log merging. |
| `hider/proxy.py` | Optional OpenAI-compatible redaction proxy. |
| `hider/webserver.py`, `hider/research.py` | Loopback web UI and the restricted Claude Code bridge. |
| `hider/generator.py`, `hider/adversarial.py`, `hider/evaluate.py`, `hider/report.py` | Synthetic corpus, hostile cases, the eval harness and its HTML report. |
| `templates/` | Placeholder-only log skeletons and the example site profile. |
| `tests/` | Unit and property tests, all synthetic. |

## What a change needs

- Tests for the behaviour, with synthetic values only.
- For a detector change: `make eval` still exits 0 (no unexplained survivor,
  no adversarial surprise, tier 2 above its recall floor). If it moves a
  number quoted in the README, update the README in the same change.
- The invariants hold: a later tier only adds redactions, a failing tier fails
  closed, secrets are destroyed and never stored in the vault.
- `make check` passes.

## Style

- Python 3.11+, `from __future__ import annotations`, type hints on public
  functions, docstrings that say why as well as what.
- Ruff, line length 100. The proxy and web server stay standard library only.
- Plain hyphens in prose and comments, never em or en dashes.
- Every quoted number in the README must come from a command in this
  repository; anything else is labelled as an example run.
