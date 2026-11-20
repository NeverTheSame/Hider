# Elasticsearch research: the name vocabulary

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**A name in free text with nothing marking it.** "Harbour Nightly
finished", "Tenant Thornbury Estates exceeded its quota": no shape a
rule can read. Two mechanisms cover it.
`elastic._JOB_REF` labels "job \<Title Case run\>" in a text field as
JOB_NAME when the site map declares that type, at the declared cost of
hiding any capitalised run right after the word "job".
Everything else is covered by the cluster's **name vocabulary**: every
value of every field in `vocabulary.fields` becomes a known value under
its own field's rule. Fields of a type in `NO_VOCABULARY_TYPES`
(accounts, ids, machines, numbers), shaped fields and globs are refused
at load. With **no `vocabulary` section the default is every field that
could be listed** (`ElasticConfig.learnable_rules`: non-glob, unshaped,
type outside `NO_VOCABULARY_TYPES`) - exactly the set
`_parse_vocabulary` accepts, so the default can never be something a
site map would be refused for, and a map listing everything it may list
gets the same set as one listing nothing. It was JOB_NAME fields only,
which left tenant, tenant-full and resource names readable at every
site that had not written the section: the common case, and the fields
most likely to hold the customer's name. A map that does list
`vocabulary.fields` keeps exactly its own list, and
`vocabulary_omitted` names what it leaves out, reported by
`vocabulary_report()["omitted"]` and on the `VOCAB` line as `NOT READ
(readable in text)` - field names only. Gate:
`default_map_names_hidden`.
The default set is wide by design, and a site may type an identifier
anything it likes, so it can contain a field that is not a name at all
(a per-request reference). That is what the per-field distinct count
below is for: such a field is counted, left out and reported, rather
than paged to the cap and taking the slice - and the build - down with
it. `NO_VOCABULARY_TYPES` is still the only thing refused at load; the
count is about **width**, not about type.

**The vocabulary is read once per cluster, at sign-in, in one-day
slices, newest first.** Never inside a case, and never from anything
Claude says - the read takes no input from Claude at all, not even a
time bound. Three shapes failed first, and each failure is why a part
of the current one exists: one capped `terms` aggregation over the
retention period refused every case on an estate past the cap; reading
the *case's own window* costs 8-35s per 1,000-value page, so a one-hour
case read 49 hours once a margin was added and every case was refused
again; and reading the whole 30-day range at once costs **31 to 297
seconds a page** (not 8-35), which on 12 name fields of ~10,000 values
is over a hundred pages - hours, against a twenty-minute budget.
So, today:
- `next_vocabulary_slice` hands out one `VOCABULARY_SLICE_S` (a day) at
  a time, newest first and contiguous, until the cover reaches
  `vocabulary.days`. A day-wide page is charged the cheap rate, and
  `VocabularyIndex` saves each slice as soon as it is whole, so a
  restart resumes rather than starting over.
- `VocabularyBuild` reads **one field per request** with an `exists`
  filter on it, `VOCABULARY_PAGE` (1,000) values a page, carrying that
  field's `after_key`. One field at a time because the cost is per
  aggregation: a request carrying every field pays for all of them
  before it can be stopped, logged or resumed. Fields are read
  JOB_NAME-first. The sentence that used to justify that order -
  "a message naming a tenant almost always carries the tenant fields
  on the same document" - **turned out to be wrong on a real cluster**:
  one tenant had 11,465 documents carrying it in the tenant field, 427
  naming it in message text, and **one** document doing both. The read
  order stands on the other half of the argument alone (about three in
  four messages naming a job carry no job field, so job fields teach
  the most per page); what the wrong half had quietly licensed - tenant
  questions scoped by the tenant field alone - is the split-tenant
  section below.
- **Every field is counted before it is paged**, one `cardinality`
  request per field per slice (`VOCABULARY_COUNT_AGG`,
  `precision_threshold` asked for at the cap). Without it, an id-shaped
  field in the default set - a per-request reference with a fresh value
  on nearly every document - was paged to `vocabulary.max` and *then*
  refused: 51 requests, the slice abandoned, retried, abandoned again,
  and **no case ever served**. What the count does next depends on who
  chose the field:
  - **default set** (no `vocabulary.fields` in the map): the field is
    left out, the build carries on, and the decision is saved
    (`VocabularyIndex.note_over_cap`, at once, before the slice is
    whole, so a slice that fails afterwards does not pay again) for
    `VOCABULARY_OVER_CAP_S` (a day), after which it is counted again;
  - **a field the map lists itself**: the slice is refused, as before,
    with a message naming the field and the two ways out (remove it
    from `vocabulary.fields`, or raise `vocabulary.max`). A site that
    named the field asked for it to be read, and reading most of it is
    not that.
  A cardinality count is **approximate**, so `VOCABULARY_PROBE_MARGIN`
  (5%, well above the measured HyperLogLog++ error) decides what "near
  the cap" means - and it is applied **in whichever direction keeps the
  build running**: a default field within the margin is treated as over
  the cap (left out, build carries on), a listed field within it as
  under (paged, with the exact page-time count deciding, because there
  "over the cap" means refusing the slice). The exact page-time check
  stays as the backstop under both, and takes the same two branches.
  The cost of the count is **one cheap request per kept field per
  slice** - on the es-eval fixture 150 of the cover's 312 requests.
- **One step per serve-loop iteration**, not one page:
  `KibanaSession.submit` / `poll_once` / `release` are the three steps
  `search` is made of, and `Broker.pump_vocabulary` does one of them
  per iteration, keeping the search in `Broker._page`. The browser
  belongs to that thread, so a pump that ran a whole page left the
  broker answering nothing for its length - es-login timed out against
  its own broker, and es-logout then read that as "no bridge".
- **The budget is per slice** (`vocabulary.budget_s`, 1200s). One slow
  slice fails alone and is retried after `VOCABULARY_RETRY_S`; the
  slices already saved stay.
- **A case applies what the index holds** (`apply_vocabulary`,
  `Bridge._apply_vocabulary`): local work, no request, once per case
  per cluster. It is refused with `vocabulary_building` only until the
  cover spans `VOCABULARY_SERVE_DAYS` (2) - `ClusterVocabulary.serves` -
  after which cases run while the older slices are still being read.
  State goes `building` -> `extending` -> `ready`, and the `VOCAB` line
  prints the covered range, the age, `NEAR CAP` at 80% and build
  progress.
- **Nothing is learnt from a partial, failed or timed-out read of a
  field that is kept**: an upstream error, a partial or misshapen
  reply, a *listed* field over `vocabulary.max` (50,000) or a slice
  over its budget abandons that slice (`VocabularyBuild.failed`,
  `result()` refuses) and leaves the saved vocabulary exactly as it
  was. A field left out for being over the cap is not a partial read of
  it: whatever it returned is dropped (`_over_cap` pops its values) and
  it is absent from the result, not present and short.
- Logs hold counts, requests, seconds and field names, **never a name**
  (`vocabulary_report`, `VocabularyIndex.report`,
  `vocabulary.log.jsonl`, the `VOCAB` line) - including the `over_cap`
  row, which carries the field name, its distinct count and the cap.
  Every surface that says what the vocabulary holds also says what it
  **left out and why**: `omitted` (the map's own `vocabulary.fields`
  leaves it out) and `over_cap` (counted, too wide to read), on the
  `VOCAB` line as `NOT READ (readable in text)` and `OVER CAP, NOT READ
  (readable in text): field~count>cap`. `esbridge.clock` is what
  the build range and the staleness check read; it is a module global
  because the harnesses' fixtures sit at `eseval.NOW` rather than
  today, and nothing in the live path replaces it.
- Values that are log words, stopwords, letterless, one word under four
  characters, or one word on the shared `ORDINARY_NAME_WORDS` list are
  skipped (`vocabulary_skip`) - a fixed list on purpose, not the system
  dictionary: what is hidden must not depend on the machine.
**Measured cost**, with the stub charging `PAGE_SECONDS` (8-35s a page
over a slice) against `WIDE_PAGE_SECONDS` (31-297s over the whole
range), so a build that stopped slicing fails its budget in the eval
rather than quietly costing hours: on the es-eval fixture (5 fields,
21,751 job names, 30 days) **30 slices, 312 requests and 3,423
simulated seconds for the whole cover**, worst slice 137s of 1200s -
but only **20 requests and 211 seconds, two slices, before the first
case can run**, and 10 requests and 105 seconds for a top-up. Of those
312 requests, **150 are the per-field distinct counts** (`PROBE_SECONDS`,
2s each, an assumption stated as one - the claim about the count is its
request *count*, which is exact); before the count the same cover was
162 requests and 3,123 seconds, which is what the count buys off: a
single id-shaped field in the default set cost 51 requests a slice and
then failed the slice, every slice, for ever. On the
shape that motivated slicing (12 name fields, ~10,000 values each) the
first case is roughly eight minutes after sign-in and the full cover
about two hours, in the background. If a *day's* page costs two minutes
at some site, a slice is 24 minutes, which **exceeds the per-slice
budget**: that site must raise `vocabulary.budget_s` (ceiling 7200) or
list fewer fields. There is no setting at which a cover that size is
free.
**Declared costs and misses of this shape:** the first sign-in takes
minutes before any case can run, and `es-login` waits there showing
progress; **real customer names are written to disk** in
`out/es/vocabulary.json` (0600, gitignored, never in the repo), a
larger on-disk footprint than a case vault because it is every name on
the cluster rather than the ones a case saw; a name **logged only in a
day the cover has not reached, or older than `vocabulary.days` (30), is
not known** - the `VOCAB` line's covered range is where that is
visible; so is one logged in the gap between top-ups, up to
`VOCABULARY_REFRESH_S`; and a failed top-up leaves the bridge serving a
cover that is complete for its range but stale, reported as `stale`
with its age rather than refusing, the same risk the ten-minute refresh
already accepts. **`stale` means overdue, not due**: a cover older
than the refresh interval is `top_up_due` (the top-up runs next, and
reading the first two days at sign-in always takes longer than the
interval, so this is what es-login returns to), and becomes `stale`
only past the interval plus one slice budget, or at once when the
last top-up failed. **Overdue is measured on this bridge's clock**:
`VocabularyIndex.report` used to charge the cover's age alone, so a
bridge restarted a day after the last one said `stale, TOP-UP OVERDUE`
on its first page while the top-up had just started. The broker now
tells the index when it started (`started_at`), which clusters have a
slice in flight (`in_progress`) and whose last slice failed (`failed`),
all runtime-only and never saved; the state is `top_up_due` while a
top-up is running (`topping_up`, the line says `top-up running`) or has
not yet had a slice budget of this bridge's time, and `stale` once it
has, or at once after a failure (with the refusal). `age_s` and the
line's age stay honest - from the end of the cover - and the line says
that names logged since the cover ended are not known until the top-up
finishes. A bare index with no broker (tests, es-eval sessions) keeps
the age-alone rule. Cost: a bridge restarted after a week of downtime
reports `top-up due` for up to twenty minutes while its catch-up slice
runs, and serves cases that whole time with a week of names unknown -
which it also did before, under a word that made it look like a fault.
**Past a bound the gap fails closed.** `ClusterVocabulary.serves`
checked only how many days the cover spans, never how recent its end
is, so a bridge restarted a week after the last one served cases off a
cover a week old: a tenant onboarded in between had never been read and
was plain text in message text. Now a cover whose end is more than
`vocabulary_max_gap` behind now (`VOCABULARY_MAX_GAP_S`, an hour, or one
refresh plus one slice budget if the site's budget makes that longer) is
`catching_up`: **every query of every case** - an open one too - is
refused `vocabulary_building` before any request, with a message giving
the gap in hours, the bound and the range the top-up must read (no
value, nothing about a guess; the code's meaning, "the vocabulary does
not yet cover what a page could carry", is the right one). The VOCAB
line says `CATCHING UP` with the same range, and es-login waits through
it and says what it is waiting for. A constant rather than a site-map
setting because a site that raised it would be choosing to leak; it
scales with `budget_s` so a site that needs long slices is not refused
during an ordinary slow top-up. Within the bound nothing changes: ten
minutes behind serves as before, a failed top-up is `stale` and serves.
**Simple rule, not a time-range one**, because a narrow rule could not be
shown safe. Routes checked: a query with no time range covers all time;
a range ending before the gap still returns documents whose message
names a tenant first logged in the gap (ingest delay, a back-dated
`@timestamp`, a message about a future onboarding), and the vocabulary
is read by `@timestamp`, so such a name was never in any slice; a
`top_hits` under an aggregation and a `filters` bucket reach the same
documents. **The open-case route** was a second leak: a case applied the
cover once and never again, so a top-up never reached it; the bridge
now re-applies (locally, no request) whenever the index holds a newer
cover than the case does. Order: `next_vocabulary_slice` already reads
the newest end first, from the cover's end to now, so the gap is the
first top-up and cases run as soon as it is whole; left as it was.
**Cost** to a user who restarts the bridge every morning: the overnight
gap is hours, so every case is refused for as long as that one top-up
takes - one-day slices from the cover's end to now, each a page per
1,000 values per field at the slice rate; on a cluster where a day's
page is 8-35s that is a minute or two a slice, so an overnight gap is
minutes and a week is about ten. Gate: `gap_fails_closed` on
`eseval.gap_docs` (own index pattern and map, appended last).
**The catch-up is read in slices**, not as one request. It was one read
from the cover's end to now, however wide: after a week down that is
charged the wide-range rate (31-297s a page against 8-35s over a day),
which on the gap fixture is **10 requests, 1,392 simulated seconds and
9 wide pages against a 1,200s budget - refused, retried, refused, for
ever**, with every case refused the whole time. `next_vocabulary_slice`
now hands the gap out **forward from the cover's end**, one
`VOCABULARY_SLICE_S` at a time (the slice size and how one slice is read
are unchanged; a ten-minute top-up is still one short slice): each
slice has its own `budget_s`, is saved by `VocabularyIndex.put` as soon
as it is whole, and a failure or a restart resumes from the cover's new
end. On the same fixture: **7 slices, 35 requests, 433 seconds, worst
slice 75s, 0 wide pages**, and the case is shown with the gap tenant
hidden once the seventh lands. **Why forward, not newest-first**: the
hard rule is that the saved cover never claims a range with a hole in
it, and a forward slice always touches the cover, so `merge` extends one
range. Newest-first would serve cases two slices in - but the recent
slices would not touch the saved cover, so either the saved cover is
dropped (a week's gap on a 30-day cover re-reads 23 days that were
already on disk) or the index holds two ranges with a hole between
them, which is the thing the rule forbids. The cost of forward: cases
wait for the whole gap, seven slices for a week rather than two. `put`
enforces the rule structurally - a slice that does not touch the held
cover **replaces** it (logged as `saved_as: replaced`) rather than
bridging the hole; nothing in the live path produces one, and a test
pins it.
**A slice of the gap that fails** (its budget, an upstream error, a
misshapen reply) behaves as any slice does: the slices before it stay
saved, the cover is unchanged by the failure, the same slice is retried
after `VOCABULARY_RETRY_S` (a minute) from the cover's end, and cases
stay refused while the cover is behind the bound. The VOCAB line and
the refusal say `last attempt failed (<code>), retrying`.
**A cover that has fallen out of `vocabulary.days`** - its end older
than the window - is dropped (`VocabularyIndex.drop_expired`, logged as
`expired` with days and a count), and the build starts as a first build
does: newest day first, cases after `VOCABULARY_SERVE_DAYS`. Reading
forward from it would spend slices on days nobody asks about before any
case could run, and reading from the window's edge would leave a hole.
Cost: the names it held are lost (every day it covers is outside the
window, so none would be re-read), and the first case waits the
first-build time rather than two short slices. A cover that is only
**partly** out of the window is kept whole and read forward: the old
part is extra names, not a hole, and `complete()` is true for it.
**Progress is visible everywhere a user waits**:
`VocabularyIndex.catch_up` gives slices left and total (total counted
from where the cover ended when this bridge first found it behind,
`catch_up_from`, runtime-only), the range being read, and whether that
slice is running, next, or failed and retrying - counts and ranges
only. The VOCAB line prints it under `CATCHING UP` (and beside a running
slice's progress), es-login prints it when it stops waiting, and the
`vocabulary_building` refusal carries it word for word; none of it
depends on anything about a guess, and the numbers are what the broker
does next, not an estimate. Gate: `catch_up_sliced`
(`eseval.run_catch_up_eval`, on `eseval.gap_docs` with `GAP_JOBS` 12,000
job names spread over the seven-day gap, the stub charging the slice
and wide rates): the before and after figures above, the cover one range
from its old start to now, 145 refusals while behind with the
slices-left count 7 first and never increasing, the case shown and the
name hidden after, and no value in the build log.
Anything that scrubs pages outside the bridge (es-eval's `Session`,
tests) must build and apply first: `eseval.build_vocabulary`,
`eseval.learn_vocabulary`.

**The cover is kept per field.** It was one range for the cluster
(`covered_from`/`covered_until`), and `merge` took the widest, so a
field that started being read after a cover existed was claimed for
days it was never read: a site with a 30-day cover of `job.name` adds
`labels.tenant_name` to `vocabulary.fields`, the next sign-in reads
the new field for the ten-minute top-up only, the VOCAB line said
`labels.tenant_name=3/50000 over the last 30d, ready`, and a case about
last week showed a tenant in message text that no slice had read. The
second route was a default-set field left out as over the cap, counted
again a day later, under it, and read from then on with its earlier
days unread. Now `ClusterVocabulary.covers` holds **one range per
field**, the saved file (schema `v2`) writes only those, `merge` and
`VocabularyIndex.put` apply the no-hole rule **per field** (a slice
that does not touch a field's cover replaces that field alone), and
the cluster-level figures (`covered_days`, the line's `every field
over the last Nd`) are what *every* field of the read set covers, with
a field's own days beside its count when they differ. The **read set**
(`VocabularyIndex.read_set`) is the map's vocabulary fields minus the
ones over the cap; `serves` requires every field in it to meet the
first-build rule on its own cover (`VOCABULARY_SERVE_DAYS`, inside the
gap bound), `behind` is any field in it past the bound.
**Backfill**: `plan_vocabulary_slice` computes each field's want by the
one-range rules against its own cover (nothing: the newest day; end
older than the refresh: one slice forward; else one day back), picks
one - fields that do not serve first, then top-ups due, then
extension, and within a class the latest end first - and reads
together the fields that share it. Fields with identical covers always
share a slice, so **an unchanged field set gets exactly the slices and
request counts it had**. A field lacking cover is read on slices of its
own, newest first; the fields that already have cover are not re-read.
A forward slice carries every field whose cover ends before it, so one
top-up realigns a backfilled field with the rest: that is those
fields' next top-up brought forward, not an extra read. **Cost of a
backfill**: that field's first build - a count and a page per 1,000
values per slice over `vocabulary.days` slices - and nothing else;
cases are refused until the field has two recent days (as for a first
build) and run while its older days are read. Visible everywhere a
user waits: the VOCAB line, es-login and the `vocabulary_building`
refusal carry `BACKFILLING <field> covers Nd, K one-day slices left
before it serves and M to the full cover, reading A to B (running |
next | last attempt failed)` - field names, counts and ranges, nothing
about a query (`VocabularyIndex.backfill`, `esbridge._backfill_note`).
**A field that leaves the set** (taken out of `vocabulary.fields`, or
counted over the cap after being read) **keeps its names**: they are
still applied under the field's own identifier rule (hiding a name
already read is the safe direction), its cover stops growing, nothing
waits for it, and it expires with its cover after `vocabulary.days`
like any other. Reported as `frozen` (field -> its range) in
`VocabularyIndex.report` and `EsScrubber.vocabulary_report`, and on the
line as `NOT READ NOW (names read before still hidden): field A to B`.
Cost: a site that removed a field to make its words readable keeps
seeing them hidden until that cover expires (or the file is deleted),
and the protection is partial and shrinking, which is why the range
is printed. A field whose rule is gone from the map is not applied. A
returning over-cap field is read **forward from its own cover** before
any case runs, like a cluster that was down for the same time; in the
common case that is the top-up every other field is due for by then.
**A file saved before this** (`hider.es-vocabulary.v1`, one range, no
per-field record) **is not trusted**: it may hold a field read for a
few hours and claimed for thirty days, and the file alone cannot say
which. Dropped on load (`VocabularyIndex.untrusted`, logged by the
broker as `untrusted` with field names and counts), the over-cap
decisions kept (dated, they expire on their own), and the next sign-in
pays a **first build**: two slices before the first case, the rest in
the background - on the es-eval fixture 20 requests and 211 simulated
seconds, about eight minutes on the motivating shape. Keeping the
names without a cover would hide nothing a case could see, since no
case is served until every field is read again.
Gate: `field_added_backfilled` (`eseval.run_added_field_eval`, on
`eseval.added_docs`, 3,000 job names and 1,500 tenant names over 30
days plus a tenant named in text a week ago, in their own index
pattern and maps, appended last of all; the real `Broker` on
`SteppedSearchTransport`). Before (`merge(one_range=True)`, the
measurement switch): the new field claims 30d after a ten-minute
top-up, state `ready`, the week-old tenant readable on a page. After:
read 0.01d, state `building`, **17 refusals, all `vocabulary_building`,
0 requests from the case**, the field named with slices left 2 then 1;
served after **2 slices, 4 requests, 53 simulated seconds**; the whole
backfill **30 slices, 60 requests, 649 simulated seconds, worst slice
37s of 1200s, 0 wide pages, 0 requests on `job.name`**; the name hidden
once its day is read, no value in the build log or on any line. The
declared window of a first build holds for a backfill too: between
serving and the slice that reads its day, the week-old name is
readable, and the per-field range on the line is where that shows.
Unit cases: `test_esbridge.py`
`test_a_field_added_to_an_existing_cover_is_not_claimed_covered_for_days_it_was_not_read`,
and in `test_elastic.py` the frozen field, the over-cap route and the
untrusted v1 file.

**A field back from over the cap is read, not waited for, until it
serves.** Per-field covers opened a hole the one range did not have: a
default-set field counted over the cap is left out for
`VOCABULARY_OVER_CAP_S` (a day), and when the decision lapsed by the
clock alone the field was back in the read set with no cover, so
*every* case was refused until the build happened to count it again -
behind a slow slice, or for as long as a failing recount kept failing,
once a day for an id-like field that is always over. Now the over-cap
record outlives the decision: a field whose decision has lapsed is
counted again (the read set includes it, so the build still re-counts
about once a day and a raised cap or narrowed field is picked up) but
is **returning** (`VocabularyIndex.returning`): cases wait only for the
`wait_set`, the read set minus returning fields. If the recount finds it
still over, it is left out again and nothing was claimed or refused. If
it fits, it is read like a new field - never read: newest day first;
frozen cover: forward from where it froze - and when it serves on its
own cover `settle_over_cap` clears the record (logged `returned`) and
it is waited for like any other field. Its slices rank after the
top-ups of the fields cases wait for, so it cannot push them behind the
gap bound. Both kinds are treated alike on purpose: while over the cap
their values were readable in text, and they stay so - **no worse, not
better** - until the field serves; refusing every case for them would
trade that for an outage. **Cost**: a field that comes back under the
cap leaves its values readable in text for its first two slices (and a
frozen one, names logged since it froze, until its catch-up lands), as
they already were while over. **A field near the cap that flips** over
and under from day to day never takes cases down: over, it is left out
with its cover frozen; under, it is read without being waited for;
over again before it serves, left out again. The 5% margin and the
one-day lifetime are unchanged. A field the map **lists** is unchanged
too: over the cap refuses the slice and no record is made. Visible as
the same `BACKFILLING <field>` note on the VOCAB line, in es-login and
in `report()["backfill"]` with `waited: false`, ending `back from over
the cap, cases do not wait for it and its values stay readable in text
until it serves`; the `vocabulary_building` refusal lists only fields
cases wait for. Gate: `lapsed_decision_serves`
(`eseval.run_lapse_eval` on `eseval.lapse_docs`: an invented
`trace.ref`, 260 values a day against a cap of 200, a map with no
vocabulary section, 10 days, own index pattern and map, appended last
of all; the real `Broker`). Before (`VocabularyIndex.lapsed_waited`,
the measurement switch): at the lapse serving False, **2 refusals, all
`vocabulary_building`, 0 requests from the case**, until the recount.
After: serving True, state `ready`, **0 refusals, 3 cases served**, the
name hidden, the recount **1 request**, the field left out again and
never claimed covered, no value in the log or lines. Two fields
backfilled at once share every slice (identical covers): on the
example fixture **served after 2 slices, 8 requests, 92 simulated
seconds; the whole backfill 30 slices, 120 requests, 1,284 seconds; 0
requests on the field that already had cover**
(`test_two_fields_added_at_once_are_backfilled_together`). Unit cases
in `test_elastic.py`: the lapse itself, a never-read field back under,
a flipping field, a frozen field returning next to a never-read one,
and the ranking after top-ups.

**A returning field that never gets there.** Nothing ended the
returning state if the field's own slices kept failing, and measured
over two simulated hours on the real broker (`_FailingField` in
`test_esbridge.py`) the failure side was: a recount failing upstream
every time, or a page failing every time, served every case but was
retried every 60s **for ever, 60 attempts an hour**, with only
`retrying` on the line; and a field that read one good day and then
failed **took the top-ups of the fields cases wait for down with it** -
once aligned it rode in their forward slice, so their top-up failed,
the state went `stale` then `catching_up`, and 59 of 120 cases were
refused. Now: a returning field **never shares a slice** with a field
cases wait for (`plan_vocabulary_slice`); a slice that read only
returning fields and failed is **charged to them**
(`VocabularyIndex.note_returning_failure`, logged `returning_failed`),
never to the cluster - no `failed`, no `stale`, no 60s pause for the
others; and its next try waits a delay doubling from
`VOCABULARY_RETRY_S` to `VOCABULARY_RETURNING_RETRY_MAX_S` (an hour),
saved in the field's over-cap record with the attempt count and when
it started failing, so a restart keeps the delay. **Retry cost**:
attempts at 0, 1, 3, 7, 15, 31 and 63 minutes, then one an hour - 8 in
the first three hours, 24 a day after; one request each for a failing
recount, two (the count and the first page) for a failing page. A slice
that lands resets the count. **What the user sees**: the field's
`BACKFILLING` note carries `last attempt failed (<code>), N attempts
since A, next try B` (and, with nothing read yet, says its next slice
recounts it and reads its first day); past
`VOCABULARY_RETURNING_STUCK_S` (an hour) of failing it is also
`STUCK, NOT READ (readable in text): field failing since A, N attempts
(<code>), next try B` on the VOCAB line and in es-login, and in
`report()["stuck"]` - field names, counts, codes and times. **Cases
stay served**: the choice was between that and refusing, and a stuck
field's values were readable in text all the time it was over the cap;
refusing would turn an upstream fault on one id-like field into an
outage of every case. Cost: its values stay readable for as long as it
fails, which the STUCK line says; what was protected stays protected -
every field cases wait for is topped up on time (lag never past the
refresh in the measurement), a frozen cover's names stay hidden, and
nothing is claimed for days not read. A restart **mid-read** keeps the
field returning with the day it read, reads the next day behind it,
and serves as before; a restart **with a recount submitted and not
answered** keeps it returning with no cover, its attempt count and its
retry time, and the recount runs again - nothing lost, nothing claimed
twice (both pinned in `test_esbridge.py`). A field the map **lists**
is untouched: over the cap refuses the slice, no record is made, it is
never returning (pinned). An unchanged field set never has a returning
field, so its slices and request counts are as before.

**Older days on slower storage: an extension slice that cannot fit the
budget covers less each time.** Measured on one real cluster: a one-day
slice took about 42 seconds for a recent day and 600-730 seconds for a
day 10 to 20 days old; the slowest took 1,028 of the 1,200-second budget,
and two failed. A failed slice was retried `VOCABULARY_RETRY_S` (60s)
later over **the same range**, with no growing delay, and set the
cluster's `failed`, so a cluster whose recent cover was fine was reported
`stale` (`TOP-UP OVERDUE` on the VOCAB line) and the 60-second hold also
held back its top-ups. One day that could not fit was retried for ever and
the cover never reached `vocabulary.days`.
Shown in the stub first: `StubEngine.aged_seconds` (optional, None by
default, so no other figure moves) charges a vocabulary request by the age
of its range's newest end, scaled by the range's width in days, from
`eseval.AGED_REQUEST_SECONDS` - 14s a request for recent days (a 42s day
slice of a count and two pages), 200-243s at 10-20 days (600-730s), 343s
at 24-25 days (the 1,028s day), 650s from 26 days (over budget by its
second request). **The shape and the width scaling are assumptions** sized
from those points: a half-day is charged half, which is what scanning
fewer documents of the same age gives and what makes a narrower slice
fit. The fixture is `eseval.aged_docs` (own index pattern
`logs-aged-*` and map `eseval.aged_map`, one listed field `job.name`,
1,200 invented job names a day over 30 days, not in `generate`). The
test drives the real `Broker` with `Broker.build_clock` set to the
engine's simulated seconds (None, wall time, in the live path).
Before (`Broker.extend_shrinks = False`, the measurement switch, set by
nothing in the live path), 12 simulated hours
(`test_before_an_old_day_that_cannot_fit_is_retried_whole_for_ever`):
**21 failures, all charged to the cluster, every one over the same
one-day range; the cover stuck at 26.0 days of 30; 42 report readings of
`stale` while the cover served cases; 66 slices, 201 requests.**
After (`test_after_a_failing_old_day_covers_less_each_time_and_the_cover_reaches_the_window`):
**1 failure, charged to the extension; the next try reads half a day and
fits; the cover reaches the whole 30 days; never `stale`, 0 cluster
failures; the cover's end 60s behind at the close; 99 slices, 226
requests.**
The rule (`VocabularyIndex.note_extend_failure`, `note_extend_success`,
`reach`; `Broker._end_slice`; `plan_vocabulary_slice(extend_width=,
extend=)`):
- **Only extension is affected**: a `back` slice whose fields all serve
  already. A first build's slices, a backfill's first two days, forward
  top-ups and catch-up slices, and returning fields are unchanged - each
  still fails and retries as before.
- **Charged to the extension, never the cluster**: no `failed`, no
  `stale`, no 60-second hold on the cluster, so a top-up due right after
  is not delayed by it (it ranks first anyway, as before).
- **Covers less each time**: the next extension slice is half the width
  that failed (24h, 12h, 6h, 3h, 1.5h, then the floor
  `VOCABULARY_EXTEND_MIN_S`, an hour), after `VOCABULARY_RETRY_S`. At the
  floor it cannot shrink, so the delay doubles instead, from 60s to
  `VOCABULARY_EXTEND_RETRY_MAX_S` (an hour): 60s, 2, 4, 8, 16, 32 minutes,
  then one an hour.
- **The width that fitted is kept, not grown back**: older days only get
  slower on that storage, so growing would pay the same failure again.
  The width, attempt count, code, start time, retry time and edge are
  **saved** in `vocabulary.json` under `extend` (widths, counts, a code
  and times; never a value), so a restart does not pay the halvings again.
- **No hole and nothing learnt from a partial read**: an extension slice
  always ends at the cover's start, however narrow, so `merge` extends one
  range; a failed slice is dropped whole, exactly as before.
- **A fast cluster is unchanged**: with no extension failure the width is
  a day and nothing is recorded, so slices and requests are exactly as
  before (`test_a_fast_cluster_gets_the_same_slices_and_requests`, and the
  es-eval figures above).
**What the VOCAB line says** (`esbridge._reach_note`, from
`report()["reach"]`, in es-login and es-smoke): once an extension slice
has failed or been narrowed and the cover is short of `vocabulary.days`,
`COVER REACHES <date> (Nd of 30d)` and why: `older days are slower to
read; the last older slice failed (<code>), N attempts since A, next try B
at <width>h`, or `older days read <width>h at a time (a day did not fit the
budget)`, or, at the floor and still failing, `STOPS THERE - an older
slice of 1h, the narrowest, did not fit vocabulary.budget_s (<code>), N
attempts since A, next try B; names logged only before <date> are not
known`. Nothing once the cover is complete. Pinned:
`test_while_shrinking_the_vocab_line_says_how_far_and_why`,
`test_a_day_that_cannot_fit_even_an_hour_stops_the_cover_and_says_so`
(a transport that fails every request for days 26 back: widths 12h, 6h,
3h, 1.5h, 1h, then the floor; cases served, never stale, the edge never
moves, top-ups within a refresh plus a budget, no value in the line or
the log).
**Costs, declared**: an old day read in pieces costs more requests (each
piece pays its own distinct count, and a page per 1,000 values of its
own), and each failed attempt spends up to one budget of cluster time
(on the measurement, 1,300 simulated seconds) - once per halving, not for
ever; a cover that stops at the floor leaves names logged only before its
edge unknown, which the line says; the narrowed width stays narrowed for
the cluster (saved) even for older days that would have fitted a day,
which only costs requests; a slice in flight still holds the one build
thread for up to a budget, so a top-up waits behind it as before (the
`stale` threshold is a refresh plus a budget, and the measurement stayed
under it); and a first build's or a backfill's own back slice that cannot
fit is **not** narrowed by this rule - it fails and retries as before,
because those are what refuse cases and narrowing them is a separate
decision. Not measured on a real cluster yet: a tester should watch the
VOCAB line through one extension past the slow days.

**Declared cost of the cap, new and the sharper one: a real name field
with more distinct values than `vocabulary.max` is left unread under
the default field set, so its values stay readable in message text.**
Before, such a field took the whole slice down and the failure was
loud - nothing ran, which nobody can miss. Now the build finishes and
the field is simply absent, which is quiet, and **the `VOCAB` line is
the only place a user sees it** (`OVER CAP, NOT READ (readable in
text): field~count>cap`, from `VocabularyIndex.report`'s `over_cap`,
via `Bridge._apply_vocabulary` and `EsScrubber.vocabulary_report`).
Nothing refuses because of it: a case runs, the page looks clean, and
that field's names are English in the text. The ways out are the two
the refusal names - raise `vocabulary.max` (ceiling 200,000; it costs a
page per 1,000 values per slice) or, if the site wants the failure
rather than the silence, list the field in `vocabulary.fields`, which
restores the refusal. A site that does not want the field read at all
should list the others, which is reported as `omitted` and is the same
cost stated at load time.
Two smaller ones: the count is approximate, so a field within 5% of the
cap is left out of the default set even if it would have fitted; and a
field whose cardinality drops below the cap is still skipped until the
decision expires (`VOCABULARY_OVER_CAP_S`, a day).

**Declared miss: a one-word tenant name the skip rules drop stays
readable.** Many real tenants are one word, and a one-word value on
`ORDINARY_NAME_WORDS` or shorter than four characters is never made
vocabulary, because registering it would hide that word from every
message. Of the eight invented one-word names in
`eseval.DEFAULT_MAP_ONE_WORD`, three are dropped (`Archive` and `Vault`
as `ordinary_word`, `Ops` as `short`) and two of those are then
readable in message text; the third happens to be caught by tier 2,
which is luck and not a rule to rely on. A site whose tenants are
called `Archive` or `Vault` gets no vocabulary protection for them and
must seed the name with `--term`. Widening the vocabulary is not the
fix: that is the skip rules' trade, and loosening it erases the word
everywhere.

