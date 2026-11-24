# Elasticsearch research: browser session, es-login, es-smoke, broker, MCP server

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**The session lives in one browser, in one process.** Only `esbridge`
opens a connection, and only from the broker's Chrome. The SSO cookie
never leaves it and never reaches disk: Kibana's `sid` is a session
cookie that dies with the browser, so one long-lived broker holds the
sign-in (`es-login` starts it, `es-smoke` talks to it over a 0600
socket), and its Chrome context is off the record because a persistent
profile flushes even session cookies to its cookie database. An expired
Kibana session is a 200 login page, not a 401, so every reply goes
through `KibanaSession.parse_reply` first. A hit names its data-stream
backing index (`.ds-<stream>-<date>-<gen>`), which `index_allowed`
checks by stream. A backing index mounted from a snapshot carries
`partial-` (frozen tier) or `restored-` (cold tier) in front of the
same name and is checked by the same stream; on one real cluster every
page older than about five days came from `partial-` indices and was
refused `bad_index` before this. Shrunken, downsampled and
failure-store indices stay refused. A `bad_index` refusal is explained
to the person, never to the model: the decision-log row, es-smoke
(`INDICES` line) and es-review carry each refused index name as a
*shape* with the number of hits on the page that had it
(`elastic.index_shape`: Elasticsearch's own prefixes as written, every
other run of letters as `L`, of digits as `9`; at most five shapes and
one count of the rest). No letter of a name survives, in any script:
the rule was ASCII-only at first, and a name written in another
alphabet came out whole; what is then neither a letter, a digit nor
ASCII punctuation becomes `?`. Only refused names are counted - an
allowed and a refused name can share a shape - and hits are read
wherever the reply carries them, under an aggregation too (a group
read is refused there), never from a document's own content. The
refusal a model receives stays the same code and message.
The stub enforces the same rules (cookie sessions, an
IdP that refuses headless and fetches).
**es-login waits for a healthy bridge however long its slices take.**
`cli._wait_for_vocabulary` waited a fixed thirty minutes and then
exited 1 with a refusal message. On a cluster where a day's slice takes
about nine minutes, a long weekend's catch-up is three slices, one
retry pushed it past thirty, and es-login gave up while the bridge was
healthy and minutes from done: to the person, a failure. Now the wait
has **no ceiling by default** and ends on one of four things: the
cover serves cases (exit 0, as before); the bridge reports a failure or
stops answering (exit 1); the bridge **stalls** - its progress key
(state, requests sent, field being read, slices left, retry attempts,
notes) unchanged for one slice budget plus `_STALL_GRACE_S` (120s),
which is a bridge that answers ping and does nothing, not a slow one
(exit 1, `stalled_s` in the state, "stuck, not slow" on screen); or a
ceiling the person set with `--max-wait SECONDS` (exit **3**: "the
bridge is healthy and still reading; this is not a failure", with the
same words for a build that is still catching up or backfilling when
the wait ends). 3 rather than 1 so a script can tell "come back later"
from "broken". Cost: with no ceiling, es-login on a bridge whose slices
are legitimately slow sits there for as long as they take, printing
progress; Ctrl-C leaves the bridge reading. **Progress lines are per
change, not per request**: a line prints when something coarse moves
(state, a field done, a slice landed, a retry, an over-cap decision) or
every `_PROGRESS_HEARTBEAT_S` (60s), where it used to print every time
the line's text changed - which was every request. And
`esbridge._backfill_note` says one sentence per **state**, not per
field: a first build has every field at the same point, and ten
identical sentences on every line (a real site saw them more than a
thousand times) buried what mattered; `BACKFILLING 10 fields (a, b, …)
each cover 0d, 2 one-day slices left before they serve …`, while a
single field keeps exactly the sentence it had (pinned). **What was set
aside is said on screen**: the broker keeps per-cluster `notes`
(`Broker._note`, in `vocabulary_progress`), one sentence each, printed
once by es-login as `NOTE`: an older one-range file set aside (how many
names over how many fields, its range, why it cannot be trusted, and
that a full first build runs with two slices before the first case),
and a cover dropped for ending outside `vocabulary.days`. Field names,
counts and days; never a name. Before this the file was logged as
`untrusted` in `vocabulary.log.jsonl` and nothing on the screen said
why a full first build was running. Tests in `test_esbridge.py`: the
wait over ninety simulated minutes of progress (not given up, a line
per change, the note once), the stall and the ceiling, the exit codes,
the broker's note, the grouped sentence.

**es-smoke runs any query the grammar accepts** (`--query JSON`,
`@file`, or `-` for stdin), because a person could otherwise only run
what a handful of flags build - no `text_groups`, no `not` or `any_of`,
no nested aggregation - against a real cluster without starting a
model. The query is sent **as written** through exactly the path every
query takes (`Broker._run` → `Bridge.run`: compile, vocabulary gate,
compile again, phrase spend, probe, scrub, decision log); the only
thing filled in is `index`, from `--index` or the first configured
pattern, as the flags do. Nothing in the CLI validates it: a bad query
is the grammar's refusal with its code. `--query` is not combined with
the query-building flags (`SystemExit`). **The summary stays safe to
copy into a report**: the `OK` line carries, for each aggregation the
query named, its type, field and bucket count (`srv:terms(agent.name)
buckets=5 other_docs=16`, `n:cardinality(job.id) value=28`), and for
`text_groups` `groups=shown/found read=sampled/total requests=N
strata=K exact=yes|no order_settled=S/shown other_docs=…` (plus
`covered=NN%` when the read stopped before the whole window), with a
`NOTE` saying how far the reply says to trust it (exact: every
document read; estimated: documents read of how many, over how many
time ranges and what share of the scope - a share under 1% keeps two
significant digits and says how rare a read document is (`0.0015% of
the scope, 1 document in 67,347 read`), where 980 of 66 million used
to print `0.0%` - the largest margin, how many leading groups
the order is settled for, the two declared misses; partial coverage:
which newest part of the window the groups describe and that a group
may be commoner in the unread part) and one for
`unbucketed`; the filters print as ops and field names only (`filters:
eq=1 not=1 any_of=1(2) fields=job.status,message,log.level`). **Never a
key, a group's text or a value**: those print with `--show` only, as
the page does, and `--show-readable-names` is unchanged. Zero hits on a
query with `not` or `any_of` skip the field probe, as before
(`field_probe` returns None for them). The stub path (`--stub`) takes
`--query` too. Tests: `test_print_smoke_summarises_a_grammar_query_as_counts_and_shows_texts_only_on_request`,
`test_es_smoke_cli_takes_a_grammar_query_through_the_same_checks`.

Clients must tell a busy broker from a dead one: `broker_state` returns
`running`/`busy`/`absent` (a failed connect is absent, a timeout with
the socket file still there is busy), `cli._wait_for_vocabulary` treats
a refusal as "ask again" while ping still answers, and `es-logout`
retries for a minute and never says "no bridge" while the socket
exists - saying it at a live broker leaves the process holding the
Kibana session, which is the opposite of what es-logout is for.

**The MCP server runs inside the broker** (`esmcp`), because the
broker's thread owns the browser: per-case bearer token, loopback,
`Host` checked, no CORS. Its four tools (`es_schema`, `es_search`,
`es_count`, `es_aggregate`) take grammar keys only. **Never add a tool
that seeds a value, signs in or unmasks**: a value-to-label tool would
let Claude mint a label for a guess and confirm it with a count. Claude
Code is launched with an allowlisted environment (`esmcp.claude_env`) -
a variable it needs goes on the allowlist, and nothing goes on a
denylist. The prompt is gated too (`esmcp.prompt_findings`), headless
before launch and interactive as a `UserPromptSubmit` hook whose
command ends in `|| exit 2`, so a broken check blocks.

## An empty index pattern is an empty answer

Every malformed reply is a refusal, and a reply without the aggregations
the query planned used to count as one. On a real cluster an index pattern
with no document in the window answered a plain count with 0 hits, and a
terms aggregation on the same pattern with `malformed`: Elasticsearch
leaves the `aggregations` key out when nothing matched an index, so
"nothing there" read as "the bridge is broken", and the explanation every
zero gets was never reached.

So a reply with exactly zero hits (`total` 0 with relation `eq`, no hit
rows) and no `aggregations` key gets its planned aggregations filled in
empty by `elastic._empty_aggs`: an empty bucket list, a zero count, no
value for a min, max, avg or sum. They then go through the same harvest,
rewrite, sweep and leak check as any reply. Nothing else changed: a reply
with a hit, a lower-bound total, no total or a non-zero total that lacks
its planned aggregations is still refused `malformed`.

