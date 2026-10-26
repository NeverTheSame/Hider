# Contributing and feedback

Thanks for looking at Hider. Two kinds of feedback matter here, and they go to
different places on purpose.

## 1. "The redaction got something wrong on my data"

Use the built-in channel, not an issue. Run the web UI (`python -m hider
serve`), obfuscate your file, and use **Report a mistake** on the results card:

- **Missed** — this should have been hidden and was not;
- **Wrong** — this was hidden and should not have been.

Reports append to `out/feedback.jsonl` on your machine only. A *missed* report
necessarily contains the value that leaked, which is exactly why this file
never leaves your machine and is gitignored. `python -m hider feedback` lists
what has been reported (values hidden by default).

If a report reveals a general gap worth fixing upstream, open a GitHub issue
that describes the **shape** of the miss (entity type, surrounding log
structure, a synthetic example you construct), never the real value. The fix
will land as a recognizer pattern, a classifier training sentence or an
adversarial case — each with its own test, so the gap stays closed.

## 2. "I found a bug / have an idea / have a question about the project"

Open an issue: <https://github.com/NeverTheSame/Hider/issues>

- Reproduce with synthetic data first: `python -m hider generate` writes a
  bundle to `out/bundle`, and every committed number reproduces offline from
  the cassettes in `cassettes/`. **Never paste real log data, mappings,
  vaults or site profiles into an issue.**
- Include the command you ran, the output you got, and the output you
  expected. For eval regressions, attach `out/metrics.json`.

## Pull requests

Before opening one, read `AGENTS.md` — it states the three invariants
(monotonicity, fail closed, secrets destroyed), the no-real-data rule, and the
measurement culture. The short version:

1. `python -m pytest` must pass (the whole suite).
2. `python -m hider eval` must exit zero; if your change touches detection,
   say what the numbers did and why.
3. Changes to tier 3 or utility prompts change `PROMPT_VERSION` and require
   re-recorded cassettes; read any cassette before committing it.
4. New behaviour comes with tests; new gateway behaviour is tested from both
   sides of the boundary.
5. Nothing personal or customer-derived in the diff: no real values, no real
   hostnames or portal URLs, nothing from `out/` or `hider.local.json`.

## Security

If you believe you have found a way for a real value to cross the boundary
(survive redaction, enter a log, reach an upstream), do not open a public
issue with the details. Open an issue saying only that you have a boundary
finding and how to reach you, or use GitHub's private vulnerability reporting
on the repository.
