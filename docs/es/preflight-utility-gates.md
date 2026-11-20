# Elasticsearch research: es-preflight, operator utility, es-eval gates

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**One report of what stays readable: es-preflight**
(`hider/espreflight.py`, broker op `preflight`, human-only, read-only,
nothing the model can call or read). Before letting a model session at
real logs someone has to judge what stays readable on that cluster, and
that judgement was spread over the VOCAB line, the READABLE line, the
build log and memory. The report puts it in one place: `HIDDEN` (the
vocabulary line - names per field, covered days, the on-disk file),
then findings, each naming **the declared limit it is, its size in
counts and field names, and what to do about it**, then the designed
channels, then a `VERDICT`.
**Two severities.** `STOP` means a customer name is readable to a model
session on this cluster right now: the vocabulary not serving or stale
(with days and slices left), a field **over the cap** - with its shape:
a count `OVER_CAP_ID_RATIO` (10) or more times the cap is reported
**id-shaped** and the fix offered is the site map (type it as a
`NO_VOCABULARY_TYPES` id, or map it `keep`), never the cap, because a
mistyped id of millions of values was being offered "raise
vocabulary.max" (measured: ~2 and ~4 million against 50k on one real
cluster); a count near the cap reads as a wide name field with the cap
fix - a heuristic, stated as one, 0 requests; a learnable field the map
**omits** (with a live distinct count), a **frozen** field (its range;
names since readable), a **stuck** returning field, and **names inside
longer keep values** found on a sampled page - reported as the
**distinct names** (labels), the field paths with how many sampled
documents carry one, and how many of the sampled documents carry any,
with `_index` called out as the stream itself being named after the
customer. It was the occurrence count summed over paths ("58 to 200
value(s)" on one real cluster for 2 distinct names, moving between
runs because the newest 50 are a sample); the line now leads with the
2 and says the document counts move between runs and the names do not.
`KNOW` means a declared trade with its size: the **skip rules'** counts
by reason (ordinary words, short - readable in text; seed per case),
**readable words** harvested on the sample (labels and fields), and a
withheld sample. The two fixed design lines (the phrase/label/keep
channels with their caps, and a pointer to `hider eval` for the
recognizer- and classifier-level misses, which are the same on every
cluster and deliberately not restated here) print as **`DESIGN`**, not
`KNOW`: they are not findings, and a `VERDICT` saying "1 know" above
three KNOW-prefixed lines made a tester count them by hand. The
`VERDICT` counts findings only and says the DESIGN lines hold on every
cluster.
**Which declared limits became a number, a warning, or were left out**:
numbered - cover days per field, over-cap, omitted (counted live),
frozen ranges, stuck attempts, skip counts, names-in-keep and readable
words on a sample; warning only - a bare name in a keep field tier 1
has no shape for (uncountable without knowing the names), names logged
in the gap between top-ups (the age is on the HIDDEN line); left out -
recognizer/tier-2 corpus misses (cluster-independent, one pointer
line), and the wider-scope query-honesty misses (lookalike senses, the
two-field tenant), which are about answer correctness, not about what
the model can read - the utility measure owns them.
**Cost.** `--no-probes` (and the short form below): **0 requests** -
the vocabulary index, a local apply for the skip counts, the site map.
With probes: one capped `cardinality` per omitted field per index
pattern over the vocabulary window, plus **one newest page per index
pattern** (`PREFLIGHT_SAMPLE` 50 documents over the last day), scrubbed
by a throwaway case exactly as a page would be - only counts, field
paths and labels leave it; the sampled names-in-keep check is a sample,
not a sweep, and says so. On the example map that is 3 requests clean,
15 with four omitted fields. Values print only under `--show-values`,
as es-review asks. The index *pattern* is printed (it is the site map's
own config, as es-smoke prints it) - a stream named after a customer is
therefore visible in the pattern itself, which is exactly the finding.
**Exit codes**: 0 no STOP findings, 1 at least one, 2 could not assess
(no bridge, refused) - never "clean" by silence.
**es-research shows the short form and requires a say-so**: before
opening a case it fetches the 0-request form (STOP lines only; its own
failure never blocks the case - advisory, the broker may predate the
op) and, when STOP findings exist, headless runs are refused
(`code=readable_findings`) unless `--accept-readable`, and interactive
runs ask `continue? [y/N]`. Costs, stated: the flag can become
reflexive on a cluster with a permanent over-cap field - the short form
still prints every time, which is the point; pipelines must add the
flag once, deliberately; and case-open gains one 0-request broker call.
Fixtures, each gap with its number and nothing reported that is not
there (`tests/test_espreflight.py`): over-cap `request.ref ~5500 >
5000` (STOP); the field added late - `BACKFILLING labels.tenant_name …
2 one-day slices left` under a `vocabulary_not_serving` STOP; the
ordinary words - `skip_rules` KNOW `ordinary_word: 2, short: 1`; the
job-named stream - `name_in_keep` STOP, 1 distinct learnt name in
`_index`, `data_stream.dataset`, `data_stream.namespace` (3 of the
newest 3 documents carry one; it was "9 value(s)"), the name only under
`--show-values`; and the split fixture
reports **nothing**: 0 stop, 0 know, the channels still printed.

**Operator utility (measured, not a gate).** Every gate below measures
what the bridge hides or refuses; `esutility` measures whether an
operator can still get answers through it, with no model. One case from
the fixture (the first tenant with a failing `Nightly` job), eleven
scripted investigations of different kinds (onset, servers, jobs, error
text, other tenants, per day, a job named in the ticket, an error census,
everything but the known error, any failure signal, tenant size), each a
fresh `BridgeCase` seeded with the tenant's name only, each expected
answer computed from the raw documents. Scored in **label space**: a
label counts as its value, so an answer is `answered` when it equals the
fixture's with every customer value swapped for this case's label and
nothing else changed; `wrong` otherwise, as `redaction` when unmasking
would make it right (the operator reads the redacted answer, so that is
not a pass) and `differs` when it would not; `blocked` when refused or
when the needed value came back only as a label. A question whose honest
query is not in the grammar is sent in that form and left blocked, with
a cause code from `esutility.GAPS`; never rewritten to fit. **A human
step is shown as a human step**: `named_job` (the engineer knows the
job by its name from the ticket) has the engineer seed the name into
the open case by hand (`Operator.human_seed`, the same `Bridge.seed`
that `es-seed` reaches) and then asks with the label; the row carries
`human_steps` (`es-seed JOB_NAME from the ticket`) and the section's
header counts them, so the answer is not credited to the grammar. It
was blocked `name_not_seeded` before `es-seed` existed. The section
prints keys, statuses, codes and counts only, runs last on its own stub
engine so no other figure moves, and is pinned in
`tests/test_esutility.py`. **What it does not cover:** a script is not
Claude (whether a model finds these queries, or runs out of phrase
budget over a long case, is not measured); the questions are a chosen
set, so "18 of 21 answered, 1 wrong, 2 blocked" (6 of 11 before `not`
and `any_of`, 8 before `text_groups`, whose question now asks with it,
9 of 12 before the sample was spread over the span, 10 of 12 before
the human step, 11 of 12 before the split-tenant questions, whose
`text_lookalike` is wrong **by design**, 15 of 18 before the two-field
tenant, 16 of 19 before the re-spread, whose `tenant_day_census` read
20 of 3,000 documents until the sample followed them, 17 of 20 before
the window pieces, whose `slow_week_census` spent the 300 s limit and
returned nothing) is not a rate of
anything, and the two human steps are scripted
here, not a person deciding whether the name deserves seeding; one tenant over six hours of synthetic
data, so "per day" is one day, and the questions on their own data
(`week_census` on `eseval.burst_world`, the `text_*` seven on
`eseval.split_world`) are one invented shape each; `Bridge.run`
directly, not the MCP tool layer; a vocabulary that always serves (no
building or gap refusals); and nothing on the realistic estate's name
shapes.

**Gates.** `es-eval` runs the fixture end to end and through the real
MCP endpoint; all 37 pass, and a change that cannot keep them passing
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
`compound_forms_no_new_guesses` (`eseval.run_compound_guess_eval`, see
"`not` and `any_of`" above).
`text_groups_no_new_guesses` and `text_groups_page_equivalent` (see
"`text_groups`" above).
Every figure is the same from run to run: the main session picks the
labels its scripted queries use from lists built in sorted order, not
in the order of a set, which follows the process's string hash seed
(`labels_issued` moved between runs before that).
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
hidden, and a cover ten minutes behind serves). `field_added_backfilled`
and `lapsed_decision_serves` (see the per-field section). `catch_up_sliced`
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
`STREAM_*`, `GAP_*`, `ADDED_*` and, last of all, `LAPSE_*` (the last five the only ones in index patterns of
their own, so no other query, build or count pays for them; they hold
no ground truth either - `OVER_CAP_TRUTH` is that gate's own).

