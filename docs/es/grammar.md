# Elasticsearch research: the query grammar, phrase caps, not and any_of

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**Elasticsearch research.** Live Kibana through a closed grammar, a
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
variants of one phrase, which count separately (safe direction).
**`not` and `any_of`** (decided: built, under the same caps as
everything else). `{"not": filter}` compiles to `must_not`,
`{"any_of": [filter, ...]}` (1-50) to `should` with
`minimum_should_match` 1. Both hold **plain filters only, one level
deep, in a query's `filters` only** - nesting, and either form inside a
`filters` aggregation bucket, are refused `bad_filter`. That is all the
two questions they were built for need (`esutility`'s
`except_top_error` and `any_failure_signal`); left out, each a decision
rather than an oversight: none-of as `not(any_of)` (a list of `not`s
says the same), an any_of of nots or of any_ofs, and compound filters in
aggregation buckets (per-bucket counts there already exist, and
`esbridge.field_probe` builds its buckets from a query's filters, so it
now skips a query that uses either form rather than being refused).
**Every rule is the same code path**: `_Compiler.compound_filter` hands
each inner filter to `one_filter` with the *outer position's* name, so
label rules, shown labels, keep literals, the shaped-literal gate, the
per-query distinct-phrase cap and the per-case budget apply inside
exactly as outside, and a refusal inside is the refusal the same filter
gets on its own, code, message and label (pinned per case by
`test_a_refusal_inside_not_or_any_of_is_the_refusal_outside_word_for_word`).
Oracle cases, written first: every one-filter case wrapped once in each
form (`esquery.COMPOUND_TWINS`, generated so the two lists cannot
drift), plus the structural shapes (`COMPOUND_CASES`: nesting both
ways, extra keys, both keys at once, a list under `not`, an empty or
over-long `any_of`, either form in a filters aggregation, and three
phrase floods - one any_of, many nots, and a word list split across both
forms and plain phrases, all `size_cap`).
**They are not a new way to guess, measured** (`run_compound_guess_eval`,
gate `compound_forms_no_new_guesses`): the budget gate's guessing run
(500 batches of 8 candidates, default budget) through five attackers,
each a fresh case on the real `Bridge` playing its best game - the
any_of and none-of attackers split a positive batch with phrases they
already paid for, which is free. Old forms: filters aggregation 145
confirmed for 145 charged at 0.138 requests a guess, one phrase a query
150 for 150 at 4.65. New forms: any_of 145/145 at 1.16, one `not` a
query against a phrase-free base count 150/150 at 3.667, eight `not`s at
once 145/145 at 0.807. (The per-guess request figures for the
zero-returning attackers rose when the empty-result check landed: a
zero-hit filter now pays its explanation's requests too, which makes
guessing dearer, not cheaper.) So no form confirms more than the budget or more
than the old forms reached, none is cheaper per request than the
filters aggregation, every guess costs one phrase, every refusal is
`phrase_budget` with 0 requests and one message shape. And the counts
are derivable from the old forms, shown rather than said: on 18 of those
batches every any_of count equals inclusion-exclusion over a filters
aggregation of the subsets (18/18), every `not` count equals the base
minus the plain phrase count (144/144), for the same 130 phrases
charged either way (252 old-form queries against 162). What they do add
is reach, not information: listing the hits of a complement or a union
in one page, which paging and client-side filtering could already do.
**The zero-hit rule for them** (`esbridge._zero_hit_phrases`,
`_unjudged_phrases`): a page that found nothing makes every phrase of
an `any_of` zero-hit (each alternative found nothing), as a plain phrase
is; a phrase inside a `not` is never zero-hit (zero documents means it
matched everything in scope); and a row that uses either form also logs
`unjudged_phrases` - every negated phrase, and the alternatives of an
any_of of two or more when the page found something - and
`negated_phrases`, both Claude's own words already in `text_queries`.
Rows without either form are written exactly as before.

