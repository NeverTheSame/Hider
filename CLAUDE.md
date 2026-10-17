# CLAUDE.md

Guidance for AI coding agents (Claude Code and similar) working in this
repository. Humans should read CONTRIBUTING.md; this file is the short version.

## Purpose

Hider is a tiered redaction library: it strips secrets and personal data from
log bundles and JSON exports before they leave the user's environment.
Identifiers become stable, shape-preserving pseudonyms; credentials are
destroyed. It does not train, fine-tune, evaluate, host or serve models.

## Hard rules

- **Never add real secrets or personal data.** All fixtures, templates,
  cassettes and examples must be synthetic: invented names (Contoso, Fabrikam,
  Northwind...), `.example` domains, `203.0.113.0/24`, `555-01xx` phones,
  obviously fake keys. No real employer, customer, product or person names.
- Never read, print or commit anything under `out/`, `hider.local.json` or a
  site profile: they can hold real customer values on the user's machine.
- A base64 fixture payload must decode to words listed in
  `ALLOWED_TOKENS` in `tests/test_hygiene.py`.
- Keep the invariants: later tiers only add redactions (monotonicity), a
  failing tier fails closed, secrets are destroyed and never vaulted.
- No behaviour change hidden inside a refactor, and no README number without a
  command that produces it.

## Commands

```sh
make install     # venv + pip install -e ".[dev]"
make test        # python -m pytest (fast, no network)
make lint        # ruff check .
make format      # ruff format . and safe fixes
make check       # what CI runs
make eval        # redaction recall on the synthetic corpus; non-zero exit on regression
```

Run a single test with `.venv/bin/python -m pytest tests/test_recognizers.py -k jwt`.

## Module map

| Module | Role |
|---|---|
| `entities.py` | Contract for the 18 entity types: shape, owning tier, destroy or pseudonymise. Start here. |
| `recognizers.py` | Tier 1: Presidio pattern recognizers and suppression rules. |
| `classifier.py` | Tier 2 default: small local scikit-learn token classifier, trained on synthetic sentences at startup. |
| `ner.py` | Tier 2 alternate: spaCy NER over the tier 1 residue. |
| `llm_tier.py`, `llm_backend.py` | Optional tier 3 (LLM detection pass) and record/replay cassette backend. |
| `pipeline.py` | Engine: tier order, span merging, monotonicity, fail-closed, decision log. |
| `pseudonym.py` | HMAC pseudonyms and the vault (refuses secrets). |
| `profiles.py` | Site profiles via `HIDER_PROFILE`; may only add patterns; broken profile is a startup error. |
| `localcfg.py` | Uncommitted `hider.local.json`: portal URL, vendor host allow-list. |
| `jsonscrub.py` | JSON obfuscation: key-driven harvesting, span resolution, sweep, leak check. |
| `csvmerge.py` | Merge CSV log parts into one JSON document. |
| `webserver.py` | Loopback-only web UI (stdlib), CSP locked to self. |
| `research.py` | Prompt masking, restricted headless Claude Code run, unmasking. |
| `proxy.py` | Optional OpenAI-compatible redaction proxy (stdlib). |
| `generator.py`, `adversarial.py` | Seeded synthetic corpus and hostile placements. |
| `evaluate.py`, `report.py` | Eval harness and HTML report. |
| `cli.py` | `python -m hider ...` entry points. |

## Conventions

- Python 3.11+, `from __future__ import annotations`, type hints and
  docstrings on public functions. Ruff, line length 100.
- Standard library only in `proxy.py` and `webserver.py`.
- New entity type: add the spec in `entities.py` first, then the recognizer,
  a generator for the eval corpus, an adversarial case if it has a hostile
  placement, and tests. Run `make eval`.
- Prose, comments and commit messages use plain hyphens, never em or en dashes.
- Tasks to pick up are in ROADMAP.md.
