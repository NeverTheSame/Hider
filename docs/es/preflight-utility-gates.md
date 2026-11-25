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
2 and says the document counts move between runs. It also said the
names do not, and that was wrong: on a busy real cluster one pattern
showed 9 distinct names over three runs and none of them in all three,
because the names are read off the same newest 50 documents. The line
now says the names can move too, so one run is not the full list.
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


**A model asked the questions (`hider/esmodel.py`): an observation, not a
figure.** `esutility` asks by code and knows the honest query; nothing
measured whether a model finds the queries, reads `covered_share`,
`order_settled` or a bounded list, or runs out of phrase budget.
`python -m hider.esmodel [--only KEY ...] --max-budget-usd N --out FILE`
asks questions of Claude Code through **the real es-research launch**
(`cli._es_research`, the function `es-research --stub --prompt` runs: the
short preflight, `open_case`, the prompt check and masking,
`esmcp.prepare_launch` / `claude_argv` / `claude_env`, the four tools,
`--max-budget-usd`, `close_case`) on a StubKibana, with no cluster. Only its
surroundings differ from `_es_research_stub`: the fixture is the one each
question's truth comes from, the case directory is kept until the score is
taken, and the unmasked answer es-research prints and saves is discarded
unread.
**The questions** (`esmodel.QUESTIONS`): `servers` and `onset` on the
es-eval utility case (`generate(seed=20261103, docs=600)` - the same base
documents and case tenant as es-eval, without the back catalogue and estate
appended after the RNG stream); `top_servers_month` (a top ten with how
certain the order is) and `distinct_servers_month` on `eseval.fail_docs` at
the busy hour, where one search over the month never finishes, so every
reply is pieced and may be partial or bounded.
**The stub serves a pieced reply over HTTP now**: an engine search past its
limit stays `isRunning` until the session's own deadline deletes it, as on
Kibana (`eseval._NEVER_FINISHES`; before, StubKibana dropped the
connection). Reached only by an engine with `count_wall` or
`group_scan_wall`, which no es-eval StubKibana has, so no gate or figure
moves. The relay world's limit is `esmodel.RELAY_POLL_S` real seconds (the
engine's 300 s is simulated); at 2 s the read's real-time budget ran out
after the newest half every time, so it is 5 s.
**Scoring a free-text answer without a second model**: the prompt names the
*shape of the answer* - one fenced ```answer block of JSON, labels as the
tools show them, null where it cannot answer - and never the query, the
aggregation, the field or the size (pinned:
`test_the_prompts_name_the_answer_shape_never_the_query`). Only that block
is scored, by fixed rules in label space: `answered`, `wrong` (including
claiming more than the reply supports - a lower bound stated as exact, an
order called certain past what is true, a part-window count presented as
the window's), `blocked` (null, or an honest "this covers only part").
A reply without a parseable block is `wrong` (`no_answer_block`).
**What a run records** (`out/`, gitignored, one JSON line per question):
status and cause, the parsed answer block, the masked answer as es-research
saves it, **the expected answer in the case's label space** (a value the
model never saw as `<not shown N>`), the shape of every query (tool, index,
filter fields and ops, aggregation types and fields, refusal code, how a
pieced read was combined - never a phrase's text), es-review's numbers
(queries by tool, refusals by code, phrases used against the budget,
labels issued), es-research's status lines, dollars, seconds, model, Claude
Code version. `esmodel.masked_only` searches every row for every value
behind a label of the case and replaces a row carrying one with a stub row;
none of the run below was withheld, and a separate check found no case
value in the file.
**Observed, 2026-11-20, Claude Code 2.1.330, default model, one ask per
question (top_servers_month twice), $1.50 cap each: 5 of 5 answered,
$0.88 and 3.9 minutes in total** (plus $0.39 and 1.2 minutes on two asks
lost to a harness bug - es-research's `research_dir` stamps a new directory
per call, so the first version read an empty one - not recorded):
- `onset` answered, to the millisecond - **without the honest query**: no
  `min` aggregation; it paged the failures newest first and read the
  oldest. 7 queries, $0.28, 61 s.
- `servers` answered (5 servers, exact counts) with the honest terms on
  `agent.name`, after a terms on `host.name` and four on `job.status`. 8
  queries, $0.22, 44 s.
- `distinct_servers_month` answered 12, whole window: the month read came
  back `covered_share` 0.5 and **the model read it, asked the older half
  itself and added the halves**, saying so; it never used cardinality. 5
  queries, $0.11, 48 s.
- `top_servers_month` answered twice (`order_claims_true`): exact counts,
  first three called certain, the ties named as ties, "no single correct
  top ten". The first read came back `covered_share` 0.5 (2 s limit) and
  then 0.75 (5 s), and **both times the model fetched the missing part and
  added it**. $0.17 / $0.10, 39 / 43 s.
- Every question met 1 or 2 `bad_agg` refusals first (its first
  aggregation each time); the decision log does not record a refused
  query's shape, so which shape is not known - es-review cannot say
  either.
- Phrase budget: 0 or 1 of 150 per case; nowhere near it on questions
  this short.
- The model noted each time that the cluster's "now" (the fixture's clock,
  2026-08-20) is not today - a stub artefact, harmless to the score.
**A bounded list, received and read** (second round, same day, version
and model; `top3_servers_wide` on `esmodel.wide_world`: the 12 relay
servers plus 80 minor ones, more than `max_buckets` 50, so no terms the
grammar accepts returns every key): the month read came back **`bounded`**
(covered 75%; the model fetched the older part itself, exact). The model
read it right: it quoted a `doc_count_max` ("30, at most 32" on four minor
servers), used `order_settled` (the first four in the newer part) and the
most an unlisted server could have, and concluded the top three are exact
and in certain order - true (600, 450, 300). $0.17, 45 s. It was first
scored `wrong` (`claimed_complete_but_is_not`) by a **scorer bug**: the
model wrote `failures_max` equal to `failures` to say exact, and the scorer
took any maximum as a bound; fixed (a maximum equal to the count is exact,
pinned in `tests/test_esmodel.py`) and the recorded row re-scores from the
file to `answered`. The `bad_agg` that opened every case is explained and
fixed (`docs/es/review-and-seed.md`): before 1 refusal and 6 queries on
`servers`, after 0 and 5. This round: 3 asks, **$0.69, 2.3 minutes**.
**Not measured, and why**: a bounded list read where the order is *not*
settled at the top (here the top three were exact); also unmeasured: an `estimated`
text_groups reply (the burst world is not wired in yet), a long case that
nears the phrase budget, other models, and more than one ask per question.
**Can it be reproduced?** The **scoring** can: `esmodel.rescore(row)`
re-scores a row from the file alone (its masked answer against its
recorded label-space truth, no mapping, model or stub; pinned by
`test_a_row_never_carries_a_value_and_rescores_from_the_file_alone`), and
the five rows above re-score to the same statuses (one cause renamed since:
`bounded_read_honestly` claimed a bounded reply that never happened, now
`order_claims_true`). The **run** cannot: the model chooses its queries and
words afresh each time, at a cost, and there is no cassette (the tool calls
go both ways). So "5 of 5" is **an observation of one model on one day,
n=1 per question** - to be reported with its date, model and version, and
never as a figure beside esutility's 18 of 21.
