# Contributing and giving feedback

Feedback about this project arrives in two very different shapes, and they go
to two very different places. The distinction exists because one of them can
carry customer data and the other must never.

## 1. The redaction got something wrong on a real bundle

Use the **"Report a mistake"** form on the results card of the web UI
(`python -m hider serve`), or append to `out/feedback.jsonl` yourself in the
same shape:

```json
{"kind": "missed", "text": "<the value that leaked>", "entity_type": "PERSON_NAME", "note": "in a comment field"}
{"kind": "wrong",  "text": "8.1.0.7", "entity_type": "IPV4", "note": "a build number, not an address"}
```

`python -m hider feedback` lists what has been reported (values hidden unless
you pass `--show-values`).

That file **stays on your machine**. A `missed` report necessarily holds the
real value that leaked, so it is as sensitive as a mapping file and is
gitignored. Do not paste its contents into an issue, a chat, or a commit.

To get the finding into the project, convert it the way the README's
"Working from real bundles safely" section describes:

1. Replace every value in the offending line with a typed placeholder
   (`<<PERSON_NAME>>`, `<<HOSTNAME_FQDN>>`, ...), keeping field names,
   punctuation and ordering.
2. Confirm, where the real bundle legitimately lives, that no live value
   survived in the skeleton.
3. Add the skeleton as an adversarial case in `hider/adversarial.py` (with
   `expect_tier1` and an owner), or as a template line in
   `templates/support_bundle.json`, and open a pull request with the eval
   numbers before and after.

A placeholder skeleton is what an issue or PR may contain. A real line, even a
"harmless" one, is not.

## 2. Everything else

Bugs, questions, design proposals, measurement disagreements, and "I tried to
pick this up and the docs lost me here" all go to
**GitHub issues** on this repository:
https://github.com/NeverTheSame/Hider/issues

Useful things to include:

- The command you ran and its printed summary (`eval`, `utility`, `pytest`
  output is designed to be safe to paste: it carries counts and labels, never
  values).
- Which tier you believe owns the behaviour (see AGENTS.md).
- For eval disagreements, `out/metrics.json` or `out/utility.json` with the
  `verbatim_survivors.detail` and `by_question` sections intact. They carry
  types, positions and lengths, not values.
- Python version, OS, and whether spaCy or a live LLM backend was involved.

Please do not open issues about a leak you can only demonstrate with real
data. Follow section 1 and report the synthetic reproduction instead.

## Pull requests

- Run `python -m pytest` (no network or key needed) and `python -m hider eval`
  and quote the headline numbers before and after in the PR description.
- Any change to detection adds or updates an adversarial case or a test.
- Any change to the tier 3 instruction text changes `PROMPT_VERSION`;
  re-record the affected cassettes and update the README numbers in the same
  PR, or state clearly that the numbers are now stale.
- Any change to a README figure links to the run that produced it.
- Keep the boundary modules (`proxy.py`, `webserver.py`) standard library
  only.
- Read `AGENTS.md` first. It lists the invariants that tests enforce and the
  reasons behind them.

## Security

If you find a way for a real value to cross the boundary (reach an upstream
body, a decision log, a committed file, or a Claude Code workspace), please do
not open a public issue with the details. Open an issue titled "security:
private report requested" with no specifics, and the maintainer will provide a
private channel.

## License

By contributing you agree your contribution is licensed under the MIT license
in `LICENSE`.
