# Elasticsearch research: the split tenant and empty results

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**A tenant split between its field and the text.** Every tenant
question in the measure scoped by the tenant field, and its expected
answer was computed from the same field-scoped documents, so a line
like "Quota exceeded for Harbour Ridge" from a component that does not
fill the tenant field was outside every question asked **and the
measure still scored the answer right**. On a real cluster one tenant
was 11,465 documents in the field, 427 in text, 1 in both.
`eseval.split_docs` (own index pattern and map, not in `generate`, all
names invented, positions fixed) is that shape in miniature: 24
field-marked failures on two relay servers, 15 naming the tenant only
in the text from an indexer that fills no tenant field, starting ten
hours before any field-marked one and skewed to the newest day. Asked
**today's way and graded against the full truth**: onset ten hours
late, 2 of 3 servers (the worst one invisible), 3 of 4 days, 1 of 2
error groups, 24 of 39 failures counted - every tenant question wrong.
**The honest ask is the wider scope**, already in the grammar: one
`any_of` of the tenant field `eq` its label and a **phrase made only
of the label** on the text field. The label resolves in the bridge (the
name never leaves it), a document matching both branches is one hit
(bool `should`, never counted twice in one query; summing a
field-scoped and a text-scoped count *would* double the overlap, which
is why the scope is one query), and counting, aggregating and grouping
all work over it: `esutility`'s `text_onset`, `text_servers` (terms),
`text_per_day` (date_histogram) and `text_error_census` (text_groups)
are answered over the wider scope, each row's figures showing the
field-scope-alone answer wrong against the full truth beside it.
**What does not work**, measured or declared: `text_which_tenants` is
blocked (`GAPS["text_names_not_enumerable"]`) - the honest terms query
runs and the documents naming their tenant only in text are in no
bucket, and a group's text shows `<*>` where a name stood (a group
makes no label usable), so tenants named only in text cannot be
listed; each candidate must be asked for by its own label, one wider
scope at a time. A per-tenant breakdown in one query is out too:
compound filters do not go inside a `filters` aggregation (unchanged).
**Where the wider scope is still wrong**, each declared: text whose
words spell the name **in another sense** is inside it -
`text_lookalike` measures this, scored `wrong` on purpose (a week's
count is 40 where 39 are about the tenant; the fortieth is a route
named after the same place, and nothing mechanical can tell the senses
apart); a **one-word tenant** is that miss at its worst, since its
label resolves to a word any message may use in English (and unseeded
it has no label at all - the skip rules' declared miss); a tenant known
under **two fields** (name and full name) is two labels, and the honest
any_of must carry each field with its own label - nothing merges the
spellings; and the phrase matches the text field it names, so a name
only in *another* text field needs that field's phrase in the any_of.
**Cost**: one of the query's `max_phrases` per name (the label-only
phrase), nothing from the per-case budget, and the usual price of a
wider scope - more documents in every count.
**Nothing existing weakens**, pinned
(`test_esquery.py::test_label_only_phrases_count_toward_the_per_query_cap_and_spend_no_budget`,
`test_esutility.py::test_the_wider_scope_weakens_nothing_and_the_log_shows_the_label_not_the_name`):
a label-only phrase still counts toward `max_phrases` (a word list of
labels cannot widen a query), still spends nothing from
`phrase_budget`, still resolves only a **shown** label (`<Org-77>`
inside the any_of refuses `unknown_label` with the usual words), the
decision log carries the phrase as written - the label, under
`labels_used` too, never the value - and es-review does not read a
label-only phrase as a typed guess (`text_phrases_distinct` 0, no
flag). The model is told all of this: esmcp instructions rule 3 and
`es_schema`'s `kinds.identifier` carry the wider scope, its costs and
the one real figure (427 to 1).

**A tenant under two fields** (`text_two_fields`): another component
writes the tenant to `labels.tenant_full_name` in another spelling, with
neither the short field nor the name in the text (six failures in
`eseval.split_docs`, between three and five days back so no other split
question moves). The second spelling is its own value and its own
label: the engineer seeds it (`es-seed`, a human step the row shows),
and the honest ask is one `any_of` carrying **each field with its own
label** plus a phrase of each. Asked with the first label alone the
count is 0 - and that zero is explained, not bare (below): the
short-name field is not filled in that window at all. Nothing merges
the spellings; a tenant known under three fields needs three branches.

**An empty result says what it means.** A filtered query that finds
nothing was a bare `hits_total: 0` to the model, and to the person only
es-smoke ran a check - one `filters` aggregation with `exists` buckets
that **counted every document in the window** per filtered field (30 to
39 seconds on a one-day window against under a second for the query,
not in the seconds the summary reported, each probe its own query row),
and **skipped entirely** for a query using `not` or `any_of`, which is
the honest tenant ask. Measured before the change
(`test_esempty.py`, the `before_` tests, kept): the model's reply to a
zero on a field the index never fills had three keys and nothing about
why; the old check was 1 request of 4 full scans, 48 simulated seconds
on a day and 336 on a week (the stub charges
`eseval.EXISTS_SCAN_SECONDS_PER_DAY`, 12 s per exists scan per
window-day, sized from the measurement - an assumption stated as one);
the wider scope got no check. On a real cluster the level field is
missing from tens of millions of documents a day and the tenant field
from about a third, so "this field is not filled here" is a common
reason for a zero.
Now `Bridge._explain_empty` runs **inside the bridge** on every zero
(every tool, es-smoke, any filter shape) and the output carries
`empty`: per filtered field a status, counts and one `meaning`
sentence; the MCP payload carries it; the decision log row carries
`empty_check` (requests, seconds, `field -> status`, window documents).
**The questions, in an order that stops early**, each one count with
`track_total_hits` capped at `EMPTY_CHECK_CAP` (100): Elasticsearch
stops collecting at the cap, so a present field answers in
milliseconds and an absent one (no postings for it in the window) at
once - no full scan either way. (1) Is the field filled **anywhere in
this index and window**? A field absent from the window explains the
zero alone (`absent_in_window`: "its filter cannot match here, whatever
it says") and the other fields are not asked further. (2) Otherwise, is
it filled on the documents the **other plain filters** leave?
`present`: a real zero for that filter ("check a keep field's spellings
with a terms aggregation; try fewer words in a phrase");
`absent_in_scope`: the filtered fields never meet on one document;
`others_empty`: another filter emptied the result, this field is not
the reason (one count per distinct set of others). Fields inside
`any_of` are checked like plain ones; `not` and `any_of` are left out
of the "other filters" scope. **Remembered between queries**: every
field a page showed non-empty, and every field a check found present,
is remembered per index for `PRESENCE_TTL_S` (an hour) - field names
and times only, shared across a broker's cases - so a later zero skips
its window request; a zero whose fields all came from memory still asks
the window total once, because memory is about the index, not this
window. **Cost**: about one request per filtered field plus one, each
early-terminated: on the before-test's two-filter zero, 3 requests and
0.6 simulated seconds against 1 request and 48-336 before; the
19-field query in `test_esbridge.py` is 19-20 requests. The check's
time is **inside** the query's reported `seconds` and reported apart as
`empty.seconds`; es-smoke's line carries `fields_checked`,
`check_requests` and `check_seconds`, and prints EMPTY (exit 3) for an
absent field as before, OK for a real zero. **Nothing about the value**:
statuses, counts and sentences name fields, a filter's own value never
enters its field's count, and the tests assert the typed value is
absent from the explanation and the log. The model is told how to read
it (esmcp instructions rule 6): an absent field is not a negative
finding. **Still ambiguous**, declared: a `present` field says nothing
about *why* the filter missed (a keep field's other spelling, a phrase
the analyser splits differently, a label for a value with another
spelling in this index all look the same); a field remembered present
may be absent in *this* window (the status says `remembered within the
hour` and the window total is still asked); the "other filters" scope
excludes `not` and `any_of`, so a zero inside a wider scope is
explained against the plain filters only; `exists` counts a document
whose field holds an empty value as filled; and the check does not
distinguish "the field is filled on 1% of documents" from 100% - the
cap is enough to say filled, not how much. **es-review is unchanged**
by design: the check's requests are not query rows, and a typed phrase
whose field turned out absent is still counted as a zero-hit phrase
(explained is not excused; pinned in
`test_an_explained_zero_moves_no_review_signal`). `esbridge.field_probe`
is kept only for the before-tests and `run_smoke` no longer probes.
What the stub does not show: `track_total_hits: 100` against a real
shard still has to find the first hundred matching documents, which
for a rare but present field is a scan until they are found - cheaper
than counting all, not free; the measured 30-39 s was the full count.

