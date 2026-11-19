# Elasticsearch research: text_groups

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**`text_groups`: the commonest messages in a scope.** `{"type":
"text_groups", "field": <text field>, "size": n}` (1..`max_buckets`)
returns each group's redacted text and its count. **Grouping happens
after redaction, in the bridge**, never in Elasticsearch: the read
(`esquery.GroupRead`, run by `esquery.read_text_groups` from
`Bridge.run` and `eseval.Session`) samples at most
`elastic.TEXT_GROUP_SAMPLE` (1,000) documents **per request**, with the
whole `_source` a page carries, the scrubber runs its three passes and
the leak check over them exactly as over a page (the page cap lifted to
the sample for this read only), then groups the redacted texts by
`elastic.text_group_key` and checks the groups again.
**The sample is spread over the scope's time span**, not the newest
moment of it. It was the newest 1,000 documents in one request, and on
a wide scope that is the end of the window: "which errors are commonest
this week", answered from the last minute, with nothing but `sampled`
against the total to say so. The fixture's one utility case is smaller
than the sample and could not show it; `esutility`'s `week_census`
question (on `eseval.burst_docs`, a fixture of its own: 1,400 of one
steady error and 200 of another over a week, 1,100 of a third in the
last minute, invented names, own index pattern and map, not appended to
`generate`) scored **wrong: the noisy group alone, 1,000 of 2,700 read,
two of three groups missing**. Now the span is cut into at most
`TEXT_GROUP_STRATA` (50; the site's `max_buckets` if lower) equal
slices - one `date_histogram` with `fixed_interval` span/48 s, aligned
to the epoch as Elasticsearch aligns it, so at most 50 buckets even
across a boundary - and the newest `TEXT_GROUP_SAMPLE // strata` (20;
never more than a page or Elasticsearch's `index.max_inner_result_window`)
documents of each are read as a `top_hits`, **in one request**. A
group's count is its sampled count in each slice scaled by that slice's
documents over its documents read (`elastic.group_estimate`): a slice
read whole counts exactly, and a read in which every slice fits is
`exact`. **Every read starts with a capped count** (`track_total_hits`
at `elastic.TEXT_GROUP_COUNT_CAP`, just past the sample: it only decides
whether the scope fits one page, and Elasticsearch stops counting at the
cap, so it is cheap on any scope; a query with no closed `time_range`
carries it on the `min`/`max` bounds request it already paid, so the
slices cover the documents' span - nothing of either is shown): a scope
that **fits the sample is read whole** as one page, always exact now.
The same question now scores **answered: 3 of 3 groups in the week's
order, 979 of 2,700 read over 49 slices in 2 requests (the count and
the pass), every count within the reply's margin, worst off by 1.3%**
(and, since the margins learnt honesty about time structure, the reply
claims the order settled for none - it underclaims; below).
**The sample is re-spread to where the documents are** when the even
spread misses them. The slices divide the *window*, so a day-wide
question about documents that all sit in one half hour put them in one
slice and read that slice's share: `esutility`'s `tenant_day_census`
(on `eseval.dense_docs`, a fixture of its own: one tenant's 3,000
failures inside one aligned half-hour slice of a day window - 2,400 of
a steady error and 120 of a rarer one over the half hour, 480 of a
third in its last minute - own index pattern and map, invented names)
scored **wrong: one of three groups, 20 of 3,000 read in one slice, the
last minute's error estimated at the whole 3,000 (525% off), the order
settled only for the one group it saw**. Now, when the uniform pass lands less
than its share (`elastic.TEXT_GROUP_RESPREAD_MIN`: a second pass runs
only when it would read at least a quarter more than the first landed,
so a well-spread scope like the burst week pays nothing), **one more
request re-spreads the same sample over the slices' own document
counts** (`esquery._allocate`: every slice up to a fair share, a slice
smaller than its share read whole, deterministic, built from the first
pass's counts alone - nothing typed in a query reaches it), each heavy
slice cut into equal sub-ranges of at most `per_cap`
(`index.max_inner_result_window`, never more than a page) documents,
one sibling `filter` range per sub-range with its own newest-first
`top_hits`, the asked sizes summing to at most the sample, each range
scaled by its own `doc_count`. The same question now scores **answered:
3 of 3 groups in the day's order, 1,000 of 3,000 read in 3 requests
over 10 sub-ranges, every count within the stated margin, the order
settled for the leading group** (the boundary group's margin is widened
by the scatter term below to cover its newest-first bias, so the reply
stops claiming an order it cannot know from this sample).
**How the reply says how far to trust itself**: `exact`; `sampled`,
`total`, `coverage` (sampled/total), `strata` and `strata_read_whole`;
per group `doc_count` (the estimate, or the count when exact),
`sampled_count` (documents actually read in the group) and, when not
exact, `margin` - about 95%, **the larger of two terms**: a
Jeffreys-adjusted binomial with the finite-population correction per
slice (the noise if what was read in a slice stood for the slice; a
group seen in every or in no sampled document still has one), and a
**between-range scatter term** over the partially read ranges
(successive differences of the group's scaled per-range counts),
because the read within a range is newest-first, not random: a group
concentrated in a few partially read ranges owes its estimate to time
structure the sample cannot check, and its margin says so by being
about the size of the swing, while an evenly spread group keeps the
tight binomial one. The cost of that honesty is `order_settled` - the
number of leading groups whose estimate minus margin is above the
next's estimate plus margin (the first unshown group counts as next; a
tie is not settled even when exact) - dropping to what the sample
really supports: the burst week reports settled 0 (from its sample
alone, the burst group could outnumber the steady one; the shown order
is in fact the true one - the reply underclaims, the safe direction),
the dense day settled 1. Also carried: `unbucketed` when documents in
scope have no time field (they are in no slice and never read);
`requests`. The decision log row carries `requests`, `sampled`, `exact`
and `strata`. The `es_schema` text tells Claude to read these before
trusting the counts and the order. **Where it is still wrong**, each
declared: the read **within a slice or sub-range is still
newest-first**, so a burst at the end of one is counted as that whole
range - the re-spread shrinks what one burst can misattribute from the
whole sample to one sub-range's documents (on the dense fixture the
last-minute error shares a 3-minute sub-range with the steady one and
is overcounted by that range's share, 654 against 480, now inside its
scatter-widened margin), and when the whole read is **one** partial
range there is no between-range signal and the margin does not cover
the bias at all (pinned: 20 noisy documents ending a slice of 1,000
are estimated at 1,000, and the margin does not reach the truth);
documents concentrated in a sliver narrower than a sub-range still
read at most `per_cap` of it; a group rarer than about one document
per range's read is missed in that range and under-counted or absent
overall (`sum_other_doc_count` and `groups` say how much is
unaccounted, not what); the scatter term reads legitimate time
variation as uncertainty, so a genuinely bursty group gets a wide
margin even when its estimate happens to be right; on a scope of a
hundred million documents the sample is 0.001% and a group's margin is
at best around ±3% of the total at a 30% share; and relative
ranges (`now-7d`) re-align the slices each call, so
the edge slices' newest twenty move between two calls of the same
question. **Asking the same question again** returns the same sample
(the count, the slices and the allocation are deterministic, the
top_hits the newest of each range - pinned: the same question twice
returns the same groups and counts) and teaches nothing new; shifting the window to walk other
documents reads them as groups at the same cost per request the
newest-1,000 read had, and every one of them is reachable by paging
with a narrower range, so it is reach, not information. **Cost**: two
requests for a scope with a closed range (the capped count, then the
exact page or the sampling pass - one more than before), three when the
sample is re-spread, plus one for `min`/`max` without a closed range;
up to `TEXT_GROUP_MAX_PASSES` + 1 when the window must be read in
pieces (the slow-read section below); each sampling pass is a histogram
or filter set with a heap per range over every matching document of its
piece, the fetch at most 1,000 docs per request.
**The key**: every label, destroyed secret and token
carrying a digit becomes one placeholder, `<*>` - **never a type**,
because a label's type depends on how its value was first labelled (its
own field's rule, tier 1 or tier 2 in text): two job ids in one slot came
back as `<Guid>` and `<Session>`, and on the fixture one tenant slot as
`<Org>` and `<Person>`, which split one message into two groups
(`test_an_id_labelled_by_its_field_and_one_labelled_in_text_are_one_group`
failed before the fix). Every pseudonym shape carries a digit, so
numbers and hidden values share the placeholder for the same reason.
**Except codes**, which stay readable: a value of up to five digits, a
`0x` hex value or an upper-case code (`AADSTS50076`) right after a code
word - `HTTP` (and `HTTP/1.1`), `status`, `status code`, `code`,
`error`, `error code`, `err`, `errno`, `exit`, `exit code`, `hresult`,
`sqlstate`, `ntstatus`, `rc`, with or without `:`/`=` - and a failure
HRESULT/NTSTATUS (`0x8`/`0xC` and seven hex digits) anywhere. Hidden
values are masked first, so a code is never a hidden value
(`status <Org-01>` is `status <*>`). What still merges: a code with no
code word before it (`GET /api/sites 429 in 333 ms`), and every count,
duration, size, version and id. What could split that should not: a
per-request number of five digits or fewer after a code word (`error
48213`), and a count after one (`error 1 of 3`). Measured on the
fixture: the typeless key merged the one real split (worker messages,
34 groups to 33), codes split 18/23/33/13 groups into 20/32/42/14, and
every split is by an HTTP or status code - nothing else is kept. Only the groups leave; the hits are dropped, so
`mark_shown` sees no label and **a group response makes no label
usable**. Two messages that differ only by a hidden value are one
group, and a group is a function of the pages of the same documents:
the gate `text_groups_page_equivalent` (`eseval.run_text_groups_eval`)
pages four scopes at `max_hits` in a second case, groups the texts with
the same key and gets the same groups and counts (exact, in two
requests: the capped count, then the whole scope as one page), with 0
labels made usable and nothing readable in a group that the pages do
not show (the three one-word tenant names the skip rules leave readable
- the declared miss - are readable in both); and on the burst scope
(`eseval._burst_scope`, 2,700 documents paged an hour at a time, 178
pages) every group's text is one the pages show, the order is the
pages' order, no label is made usable, two requests of at most the
sample each, and - reported, not gated - 3 of 3 counts within
the margin. It is the query's only
aggregation, at the top level, with query `size` 0 and no `from`,
`sort` or sub-aggregations; the scope's filters are gated as every
filter is. A placeholder typed into a phrase is refused `bad_value`.
Oracle cases, written first: `esquery.TEXT_GROUP_CASES` (26: wrong
field kinds, unlisted and glob fields, unmasked/include/min-count keys,
over the size cap, nested under terms or a filters aggregation, with
sub-aggregations, beside another aggregation, with hits, `from` or
`sort`, a scope with a literal, an unshown label or a phrase flood, a
placeholder - `<Org>` or `<*>` - typed into a phrase, and the read's
own knobs typed into the spec - `sample`, `strata`, `interval`, `exact`,
`newest` - all `raw_dsl`: nothing in a query shapes how the sample is
read, because the per-request read is the cap that keeps a group read
no wider than paging), the one-filter ones wrapped in `not` and
`any_of` like the others. **Not a cheaper way to guess** (gate
`text_groups_no_new_guesses`, the same guessing run): one phrase a query
with groups 150/150 at 7.32 requests a guess, an any_of whose groups show
which candidate matched 145/145 at 0.50 - exactly the any_of-with-a-page
attacker the forms before it allow (0.39 with a page), and the filters
aggregation's 0.138 is still the cheapest; the capped count in front of
every group read makes the group attackers strictly dearer per guess,
and the typeless key and the readable codes move no figure. **Costs**: the engineer no longer sees which
hidden value is in which message, nor what kind of value sat in a slot
(tenant, id, server and user are all `<*>`; a page of one phrase shows
them), nor numbers other than codes (on the fixture 313 distinct
redacted texts on the pages are 32 groups), and counts over a scope
wider than the sample are estimates, with the reply saying so (`exact`,
`margin`, `order_settled`, above); a leak in any sampled document
withholds the whole reply, as it would that page; one request reads ten
pages' worth, scrubbed with tier 2.
**A read whose pass cannot finish is re-read in newest-first window
pieces, and the reply says exactly what it covers; nothing is refused
on a prediction.** The sampling pass is a full bucketing pass over
every document in scope, and its wall time **cannot be predicted from
a document count** - measured on one real cluster: one day of errors,
about 3 million documents, 52 seconds; three days, about 9.7 million,
**47 seconds**; a week **did not finish within that site's 300 s
search limit** (the default limit is 120 s). The first cut of this rule
refused any scope past a 5-million-document bound, which would have
refused the measured three-day read; the second stopped at the limit
and refused with nothing, so the commonest question - a week of errors
- waited the whole limit and came back empty, with "narrow the scope"
but not how far, and every guess at how far cost another limit. Now the
deadline stands (the session bounds every search at `poll_timeout_s`,
the site's own setting; a search past it is deleted server-side and
nothing is read) and a strata pass that hits it **splits its window in
half and reads the halves newest first**, each piece its own strata
pass and re-spread, each piece's query carrying the piece's own range
clause (so the pass scans the piece, not the whole window - on the
cluster, not only in accounting; the one narrowing the bridge's clock
produces, see `esbridge.clock`). Every piece's kept texts are already
reduced to group keys (`_strata`, idempotent, so `mark_shown` and the
leak check see only group text) and all pieces are combined into
**one** estimate, margins and scatter across every range.
**The waiting is bounded, because unbounded it was an hour**: with no
bound, `TEXT_GROUP_MAX_PASSES` (12) passes could each wait the full
site limit - 3,600 s at the measured 300 s site, pinned as the before
in `test_the_waiting_of_one_question_is_bounded_whatever_the_cluster_does`.
Now (`esquery.read_text_groups`, the bridge passing the site limit and
wall time; the eval its simulated clock): a pass over a width the read
knows nothing about is waited on for the **probe deadline**
(`TEXT_GROUP_PROBE_FLOOR_S`: `max(60 s, limit/5)`), the full limit only
for a width that already finished once in this read or for the **last
allowed attempt** (so a cluster slow at every width still gets one
full-length try); at most `TEXT_GROUP_MAX_TIMEOUTS` (3) timed-out
passes; and the read starts no new pass once
`TEXT_GROUP_READ_BUDGET_LIMITS` (3) limits of waiting are spent. **The
longest one question can take is budget plus one in-flight pass = four
limits: 1,200 s at a 300 s site, 480 s at the default.** The chosen
trade (waiting over requests, by decision): a pass that would have
finished between the probe deadline and the limit is split instead -
more requests, same answer, less waiting - and a probed-out width is
remembered as bad even though the full limit was never tried on it. A
timed-out re-spread keeps its piece's finished first pass; when the
read stops early the reply's `covered`/`covered_share` say **exactly
which newest part of the window the groups describe** (contiguous by
construction: pieces are processed strictly newest first), the total is
`gte`, and only a read that covered nothing is refused `slow_read`
(message: the deadline hit, the narrowest width tried, the waits spent,
what to do).
**The bridge remembers what timed out** (`Bridge.group_spans`, shared
across a broker's cases like `presence`, per index, the narrowest span
that hit the limit, `GROUP_SPAN_TTL_S` an hour, spans and times only):
a later wide question splits past the doomed widths without paying
them, and the pieces it lands on are the same halving tree, so **the
same question asked again returns the same groups and counts**.
Measured on the stub's cluster shape
(`eseval.measured_cluster_scan_wall` + `MEASURED_SEARCH_LIMIT_S`, the
three points and the 300 s limit, an assumption stated as one; pinned
by the week-in-pieces tests in `test_estextgroups.py` and `esutility`'s
`slow_week_census`):
**before, the week spent 300 s and returned nothing; now it answers
whole in about six minutes** - 2 probes pay their 60 s deadline (the
week, then its newest half), four 1.75-day pieces finish, **8 requests,
~355 simulated seconds (835 when every probe paid the full limit),
covered 100%, every count within margin (the narrow pieces read most
slices whole, worst count off under 1%)**; asked again on the same
broker it is **6 requests, ~235 seconds, 0 timeouts, identical
groups**. A cluster slow at every width is refused after 60 + 60 +
300 = 420 s; one whose every pass finishes just under the limit is
stopped by the budget with honest partial coverage, total under four
limits. A window wider than the pass budget covers its newest pieces
and says so (30 days at 1.875-day pieces: 12 passes, `covered_share`
0.6875, total `gte`). **Why several samples per question is still safe**: the
per-request cap is untouched (no request reads more than one sample,
which is what keeps a group read no wider than paging), and the pieces
are exactly the narrower questions the case could already ask one at a
time - the page-equivalence gate pages the same 2,700 documents in 178
requests - so pieces add reach the grammar already had, not
information; every pass is scrubbed and leak-checked as a page, groups
still make no label usable, and a pieced question costs strictly more
requests per phrase, so guessing gets dearer, never cheaper (the guess
gates run without piecing and stand unchanged). **Where the pieced
answer is weaker than one read**, declared: a group's counts join
across pieces but a document counted in one piece was sampled without
knowledge of the others (the estimate is per-range as always - in
practice the narrow pieces sample *better*); partial coverage is
honest but silent about the unread part - a group may be commoner
there, which the es-smoke NOTE and `es_schema` both say; empty pieces
of a too-wide window still spend passes (the budget buys coverage, not
cleverness); the span memory is per index, so a cheap narrow-filtered
wide question splits like an expensive one (more requests, same
answer); after `GROUP_SPAN_TTL_S` the probing is paid again - two 60 s
probes, not spent limits, once per cluster per hour.
**Costs otherwise unchanged**: the refusal's spent phrases are not
refunded; the small fixtures' passes are charged at
`elastic.TEXT_GROUP_SCAN_S_PER_MDOC` (52/3 s per million documents, a
floor sized from the one-day point so the measure never implies the
pass is free - the utility rows carry `scan_seconds`); and a pass that
would have finished just past its deadline is lost as surely as one
that never would (the site's lever is `poll_timeout_s`, which bounds
every search - no group-read knob).
**The one-thread broker lives with a long read.** The broker's thread
owns the browser, so for the length of a search it used to answer
nothing - acceptable at one search of at most the limit, not at a read
of several (the same failure AGENTS already records for the vocabulary
build, which pumps between pages). Now the session's wait between polls
is the broker's **idle hook** (`KibanaSession(idle=...)`,
`Broker._search_idle`): during any search, a **ping is answered** (so
`broker_state`, es-login's health checks and es-logout's "never say no
bridge at a live one" keep working), a **stop is accepted** (it lands
when the search in flight finishes; the socket stays until then, which
is what es-logout watches), and **anything else is told `busy` at
once** - "the bridge is mid-search" - instead of hanging to its own
socket timeout; the browser is never touched from the hook (it stays on
this thread throughout). **The idle hook also pumps one vocabulary step
per poll**, because answering pings was not enough: a model asking wide
questions back to back keeps the thread inside reads for 20-35 minutes
at a time, the top-up only stepped between requests, and the gap rule -
correctly - then refused every case. Measured
(`test_the_vocabulary_top_up_survives_back_to_back_long_reads`, the
`idle_answers` switch again): **before, three back-to-back wide reads
(~84 simulated minutes) left the cover 5,025 s behind the 3,600 s bound
and the fourth question was refused `vocabulary_building`** - the
person sees the usual "ends 1.4h ago, past the 1.0h bound" message, and
refusing is right once the cover is behind, but nothing should let it
fall behind; **after, six reads over almost three simulated hours all
answer and the cover stays about one pass (~295 s) behind**. The cost:
the case's polls and the vocabulary's steps share the one thread, so
each stretches the other slightly, and a vocabulary step between polls
spends wall time the pass's deadline also counts (declared). MCP tool
calls during **another** case's read still wait in the backlog (one
browser, one thread - declared). **The model's own tool call survives
the read, now measured, not assumed**: Claude Code's HTTP MCP client
cuts one tool call at 60 s by default - probed empirically on 2.1.328
with a stub MCP server and a 90 s tool: **with default settings the
call died at 66 s and the model saw "The operation timed out." while
the server was still working; with the bridge's launch settings the
same call returned its result**. So the launch now sizes all three
knobs to the worst read (`esmcp.tool_wait_ms` = `search_wait_s` in ms):
`MCP_TOOL_TIMEOUT` and `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` in
`claude_env` (set only when the operator has not set their own; both
and `MCP_TIMEOUT` are allowlisted through - durations, never data), and
a per-server `timeout` in the generated `mcp.json`, for versions that
honour it per server. Declared remainder: the idle-window knob
(documented default 5 minutes for HTTP, needs Claude Code ≥ 2.1.187) is
set but was probed only to 90 s - a tester should run one es-research
tool call that waits ~6 minutes to cross the idle default once; and a
wide read still **returns late, not incrementally**, which `es_schema`
says, with the four-limit bound and the advice to prefer narrower
ranges when latency matters. **Callers wait as long as the worst read**:
`esbridge.search_wait_s` = (budget + 1) limits + the old 120 s margin -
es-smoke used it to give up at `limit + 120` (420 s at the measured
site) and print "the bridge did not answer" while the bridge was still
reading a 835 s week. Before and after are pinned:
`test_before_a_long_read_left_the_broker_deaf` (no idle hook: a ping
mid-read times out, the bridge looks dead while only reading),
`test_a_ping_is_answered_and_others_told_busy_during_a_long_read` (the
ping answers, others get `busy`, the read's caller still gets the whole
covered answer), and
`test_es_smoke_waits_out_the_longest_group_read` in `test_cli.py`
(`idle_answers` is the measurement switch; nothing in the live path
sets it False).
**What a real cluster needs that
the stub does not show**: a 1,000-hit reply with full `_source` is
megabytes through Kibana (its payload limits apply) and tier 2 over
1,000 texts takes seconds in the bridge; the strata request is a
`date_histogram` with a `top_hits` of 20 per bucket, and the re-spread
a set of sibling `filter` ranges with their own `top_hits`, each of
which makes Elasticsearch bucket every matching document and keep a
heap per bucket per shard - a full pass over the scope with the time
field's doc values, the measured 52/47/never figures above, the fetch
phase still at most 1,000 documents; the async search runs for that
long and the bridge polls it, under the completion ceiling that is now
the slow rule; the capped count stops just past the sample, so it is
cheap on any scope (as with the empty check's capped counts);
`fixed_interval` in seconds (`12600s`) is valid; `top_hits` size must
fit `index.max_inner_result_window` (100 by default, the cap on
`TEXT_GROUP_MAX_PER_STRATUM`); the exact read's `size` 1,000 must still
fit `index.max_result_window` (10,000); the histogram's `doc_count` is
exact in Elasticsearch as in the stub (only `terms` is approximate);
documents whose time field is missing fall in no bucket (`unbucketed`);
the `min`/`max` bounds request is cheap (doc values, no fetch); and an
exact count over a large scope would still need Elasticsearch to group
first, which is the one thing this design refuses to do
(`categorize_text` groups before redaction, so a hidden name would
split groups). A uniformly random sample (`random_score`, or the
`random_sampler` aggregation) would be unbiased within a slice where
newest-first is not, and was not chosen because a different sample on
every call would make re-asking a way to read new documents each time,
and `random_score` over the whole scope costs a full scoring pass.
Identifier fields take labels only. Every forbidden shape (wildcard,
prefix, range, sort, terms include, scripts, raw DSL, literals,
wrong-type labels) is an `esquery.ORACLE_CASES` entry and must be
refused with its declared code. **Add the case before the rule**, as
with `adversarial.CASES`.

