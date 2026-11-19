# Elasticsearch research: ordinary words, shown labels, keep fields, the realistic estate

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

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

