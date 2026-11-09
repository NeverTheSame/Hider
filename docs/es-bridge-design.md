# Design: live Elasticsearch research through Hider

Status: offline core built and measured (`hider/elastic.py`, `hider/esquery.py`,
`hider/eseval.py`, `python -m hider es-eval`); session layer built and
tested against the stub Kibana (`hider/esbridge.py`, `python -m hider
es-smoke`, `es-login`); MCP server built inside the broker and tested
against the stub and one live Claude Code run on it (`hider/esmcp.py`,
`python -m hider es-research`). Companion to `pilot-plan.md`.

## Decisions taken

| Question | Decision |
|---|---|
| Claude Code's own API traffic through the gateway as a second sweep | Not now. Recorded as a later phase below. |
| Tier 3 on text fields | Off for the pilot. |
| Minimum word length on phrase queries | No. `match_phrase` on `message` is the main tool. Guess confirmation by hit count is accepted: every text query is logged with its labels, counted in the eval (`text_queries`) and declared. |
| Server names | Keep role and region: `ctr-amer-042` becomes `ctr-amer-s01`, through a `shape` regex and `label` format on the identifier field. |
| Index and field names | Site-specific, in `hider.local.json` under `elastic` (object or path), or `HIDER_ELASTIC`. The repo ships `templates/elastic.example.json` with invented names only. |
| Auth | No API keys. The bridge drives the installed Chrome through Playwright in an **off-the-record context**, signed in to Kibana only, one browser for all four clusters, kept alive by a long-lived broker process because Kibana's session cookie dies with the browser. Queries are in-page `fetch` calls from a tab parked on each Kibana origin, so the SSO cookie never leaves the browser, and off the record it never reaches disk (a persistent profile flushes even session cookies to its cookie database). The analyst's everyday profile is never opened by the bridge. |
| Kibana | 9.4 on all clusters. Required headers: `kbn-xsrf`, `x-elastic-internal-origin: Kibana`, `Content-Type` and `Accept: application/json`. Poll every 1.5 s, 2 minute timeout, `DELETE` the search when done. |
| Expired session | Kibana does not 401. It redirects, sometimes via the identity provider, to a `/login` page served with 200. Any such reply is `session_expired`; a visible window (`es-login`) is how the human signs back in, silently when Entra remembers the device. |

## The question

Let Claude Code investigate a support case over the live Elasticsearch
logs, searching and aggregating as it goes, while every customer value it
sees is a pseudonym, and while it can still narrow a search to one customer
it only knows as `<Tenant-01>`.

Constraints, restated as properties a test can hold:

1. Elastic credentials never reach Claude Code's process, its environment,
   its working directory, or any tool it can call.
2. Fail closed. A response that cannot be shown clean is replaced by a
   refusal. Nothing is ever mapped to "no findings".
3. The mapping never leaves the machine. Unmasking is a local dictionary
   lookup, done by the human's UI, never by a tool Claude can reach.
4. No real data in the repo or in any session transcript. Index names, field
   names and naming conventions live in `hider.local.json` or the site
   profile. Tests and evals run against synthetic Elasticsearch responses.

## Why not a headless browser

The starting idea was Claude Code driving Kibana headlessly. It fails every
constraint at once, so it is worth writing down why before moving on.

- The browser session cookie *is* the Elastic credential, and it sits inside
  the process Claude controls. Constraint 1 is gone on day one.
- Kibana is a full admin surface. Discover is one tab away from Dev Tools,
  which is raw `_search`, and from Stack Management, which lists real users.
  There is no allowlist to enforce because the browser speaks DOM, not
  queries.
- A rendered page has no field semantics. The only scrubber that can run on
  a DOM dump is tier 1 regex over text, which is exactly the tier the README
  says cannot catch free-text names on its own. Screenshots cannot be
  scrubbed at all.
- "Refusal" has no shape. When a page is partly dirty there is nothing to
  hand back except a blank page, and nothing to log but the URL.
- `--restricted` and a browser tool are incompatible by construction. The
  bridge's whole safety story in `research.py` is the tool list.

Keep the browser for the human. Claude gets a narrow tool instead.

## Architecture

Three processes on the workstation, one trust boundary between the first
two.

```
 human ──┐
         │  loopback web UI (existing hider serve, :8790)
         ▼
 ┌────────────────────────────────────────────┐   ES creds, mapping, vault,
 │  hider ES bridge  (127.0.0.1, MCP over HTTP)│   decision log all live here
 │  - query compiler  (labels → real values)   │
 │  - response scrubber (real values → labels) │ ──────► Elasticsearch
 │  - leak check, degraded check, refusals     │
 └────────────────────────────────────────────┘
         ▲  one MCP tool surface, per-session bearer token
         │
 ┌────────────────────────────────────────────┐
 │  Claude Code  --restricted --strict-mcp-config
 │  tools: the bridge's MCP tools only         │   no Bash, no Read, no
 │  cwd: empty temp dir, env: scrubbed         │   WebFetch, no other MCP
 └────────────────────────────────────────────┘
```

### The bridge process

A new module, working name `hider/esbridge.py`, standard library only like
`proxy.py` and `webserver.py`. It is started by the human before the Claude
session, reads the Elastic endpoint and credential from the environment or
keychain at that moment, and listens on loopback. Claude Code is launched by
the existing bridge code with `--mcp-config` naming only this server and a
random per-session token, and with `--strict-mcp-config` so no user-level
MCP server leaks in. The bridge refuses any request without the token and
any connection not from loopback.

Running the bridge as its own process rather than a stdio MCP child is the
point: a stdio server is spawned *by* Claude Code and inherits whatever
Claude Code's environment holds. Constraint 1 wants the credential in a
process Claude Code did not start.

### The site configuration

Everything that names the estate goes in `hider.local.json` under one new
key, validated by `localcfg` the way the existing keys are, malformed is a
startup error. The repo ships only `templates/es.example.json`.

```json
"elastic": {
  "indices":      ["logs-app-*", "logs-gateway-*"],
  "fields": {
    "@timestamp":        {"kind": "keep"},
    "event.outcome":     {"kind": "keep"},
    "http.response.status_code": {"kind": "keep"},
    "tenant.name":       {"kind": "identifier", "type": "ORG_NAME"},
    "tenant.id":         {"kind": "identifier", "type": "TENANT_ID"},
    "user.email":        {"kind": "identifier", "type": "UPN_EMAIL"},
    "host.name":         {"kind": "identifier", "type": "HOSTNAME_FQDN"},
    "message":           {"kind": "text"},
    "error.stack_trace": {"kind": "text"}
  },
  "max_hits": 50,
  "max_text_chars": 20000
}
```

Three kinds, and the default for a field that is not listed is a fourth:

| kind | On the way out (response) | On the way in (query) |
|---|---|---|
| `keep` | passed through | filter, range, sort, aggregate freely |
| `identifier` | value → stable label via the session vault, typed | exact match on a *label* only; never a literal, never a pattern |
| `text` | tier 1 + tier 2 pipeline, then the known-value sweep | match on words that pass the outbound gate |
| unlisted | **dropped**, server side, via `_source.includes` | refused |

A `keep` field is a declaration. Numbers and enums are the obvious members.
A numeric account number is an `identifier`, and the pilot's Phase 1 review
of real-shaped bundles is where that gets decided, exactly as for the
profile.

### The query surface

Claude never writes Query DSL. It calls tools whose parameters are a closed
grammar, and the bridge compiles them. That is where the oracle attacks are
stopped (see failures below), and it is why the tool list is short:

- `es_schema()` returns the allowlisted indices and fields with their kinds.
  Claude needs field names to work; constraint 4 only keeps them out of the
  repo, not out of the session.
- `es_search(index, time_range, filters, text_query, size, sort, cursor)`.
  `filters` is a list of `{field, op, value}` where `op` is `eq`, `in`,
  `exists`, or `range` and `range` is allowed on `keep` fields only. A value
  for an `identifier` field must be a label the vault knows. `sort` is
  allowed on `keep` fields only. `cursor` is an opaque token held by the
  bridge, so the `search_after` values never cross.
- `es_count(...)` with the same filters.
- `es_aggregate(index, time_range, filters, group_by, metric, interval)`.
  `group_by` is one or two fields, `keep` or `identifier`; buckets on an
  `identifier` field come back keyed by label, ordered by count, with the
  real key never serialised. Metrics are count, cardinality, min, max, avg,
  sum, percentiles, date histogram.

Compiled queries are `bool` filters, `match` on `text` fields with
`operator: and`, `terms` aggregations with `size` capped, `_source.includes`
set to the allowlist. Nothing else is ever generated: no `query_string`, no
`wildcard`, `prefix`, `regexp`, `fuzzy`, `more_like_this`, scripts, runtime
mappings, `highlight`, `top_hits`, `_sql`, `_eql`, `_msearch`, `_mget`.

### The two gates, both local

**Outbound gate, before Elasticsearch is contacted.** Every literal in a
tool call is checked exactly as `research.mask_prompt` checks a prompt
today: if it matches a mapped value, a term, or a tier 1 shape (email, GUID,
IP, hostname, token), the call is refused. Labels are resolved to real
values only for `identifier` fields with a matching type, so `<Tenant-01>`
cannot be used to filter `user.email`. An unknown label is a refusal, not a
guess.

**Inbound gate, before Claude sees anything.** The scrubber is
`jsonscrub.JsonScrubber` with its key classification replaced by the field
map and its vault replaced by the session vault, run over the `_source`
projection and the aggregation buckets. Then the three checks the bridge
already applies to a file run, in order:

1. a degraded tier anywhere → refuse the whole response;
2. the leak check (every mapped value, any length, word boundaries) → a hit
   refuses the whole response, never a partial page;
3. an Elasticsearch error → a fixed, short error class to Claude, never the
   body, because ES errors echo the query and sometimes the document.

A refusal is a tool error with a stable message like "response withheld:
redaction degraded" and a decision-log row. It carries no value and no
count.

### Sessions, the vault, and seeding the case

A case is a session. The session vault is a `pseudonym.EntityVault`
persisted to `out/es/<case>.vault.json`, gitignored, so `<Tenant-01>` means
the same thing on every call and across restarts. It is scoped per case so a
label from last week's JSON run cannot be confused with this week's.

The human seeds it. "The case is about Contoso" is typed into the local web
UI, which registers the name in the session vault and shows the label back.
The prompt Claude receives already says `<Tenant-01>`. This is the existing
terms mechanism in `research.py`, pointed at a vault instead of a file. No
real value is ever typed into Claude.

Unmasking is unchanged: `research.unmask` over Claude's answer, in the web
UI, with unknown labels reported. The bridge exposes no unmask tool. There
is no tool for it to expose.

### What is reused

| Need | Existing piece |
|---|---|
| Field-aware labelling, parts of names, leak check | `jsonscrub.JsonScrubber`, `leak_check` |
| Stable typed labels, shaped labels, destroyed secrets | `pseudonym.EntityVault`, `entities.py` |
| Outbound literal check | `research.mask_prompt`, `prompt_leaks` |
| Refusal type, decision log, rotation, metrics | `proxy.Refused`, `_record`, `GatewayMetrics` |
| Known-value sweep | `proxy.RedactionGateway.sweep` |
| Launch and restrict Claude Code, workspace, unmask | `research.claude_command`, `ask`, `unmask` |
| Site config with startup validation | `localcfg`, `profiles` |

New: the MCP transport, the query compiler, the field-map scrubber adapter,
a synthetic ES response generator, and a stub ES server for tests.

## Failures I expect

Ordered by how much they worry me.

1. **The enumeration oracle.** Hit counts leak values without any value
   crossing. `wildcard tenant.name: "c*"` then `"co*"` recovers a name letter
   by letter; `range` on an identifier field does a binary search; sorting
   by an identifier reveals alphabetical order between labels; a `terms`
   aggregation with `include` regex does the same for a whole index. This is
   why the grammar is closed and why `identifier` fields take labels and
   exact matches only. Residual: Claude can still *confirm a guess* by
   matching a word in a `text` field and reading a non-zero count. The
   outbound gate catches guesses that are already mapped or shaped; it
   cannot catch an unmapped plain word. Logged, measured, and declared.
2. **Unlisted fields.** A new field appears in the index. Default deny
   drops it, which is correct and will be noticed as a utility loss, not a
   leak. The failure mode to avoid is the opposite default, which is why the
   projection is server side and tested.
3. **A credential-shaped value in a `text` field reaches tier 2 and gets
   vaulted** instead of destroyed. The AGENTS known gap applies unchanged.
   The pipeline test, not a recognizer test, is the one to write.
4. **Correlation loss across fields.** `user.name` as `Anna Lind` and
   `message` as `anna.lind@...` get labels of different types. The register-
   parts logic in jsonscrub narrows this; it will not close it. A utility
   loss, not a leak.
5. **Tier 2 over stack traces.** .NET namespaces read as organisations is a
   known gap. On a 50-hit page of exceptions this is many false labels and a
   slower response. Measured by the utility metric and the latency figure.
6. **Identifiers hiding in `keep`-looking places.** `_id`, `_index`,
   `_routing`, and index names that are per tenant. `_id` and `_routing`
   default to identifier. Index names are allowlisted patterns; a per-tenant
   index naming scheme is a site-profile decision to label them too.
7. **Numeric identifiers.** An account number as a JSON number survives
   unless its field is declared `identifier`. The leak check compares numbers
   as strings, as jsonscrub already does, so a declared one is caught; an
   undeclared one in a `keep` field is the human's Phase 1 mistake. The
   field-coverage figure below exists to make that mistake visible.
8. **Cursor leakage.** `search_after` values are sort keys. Opaque bridge-
   held cursors, and sort on `keep` fields only.
9. **Session mix-ups.** Two cases open at once, one vault. Per-case vaults
   and the case name in every label-bearing page of the UI.
10. **Latency under one lock.** The bridge serialises redaction like the
    gateway. One Claude session is fine. The `max_hits` and
    `max_text_chars` caps exist to keep a tool call under a few seconds with
    tier 2 warm.
11. **The transport.** An MCP server is a new attack surface on loopback.
    Token required, loopback only, no CORS, same posture as the web UI.

## How we measure it

Every number comes from `pytest`, a new `python -m hider es-eval`, or a
committed cassette of synthetic responses. None of it touches a live
cluster.

**Fixtures.** Extend `generator.py` with an Elasticsearch shape: the same
typed placeholders and the same RNG discipline, emitted as `hits.hits`,
aggregation buckets, and a `_mapping`. A stub ES server in tests answers the
compiled queries from these fixtures and records what it was asked. The
example field map in `templates/` uses invented field names; the real one
never leaves `hider.local.json`.

| Figure | What it answers | Gate |
|---|---|---|
| Response leak rate | Did any seeded value reach Claude, over N synthetic pages, with refusals counted separately | 0 |
| Refusal rate on clean traffic | How often fail-closed fires when nothing is wrong | reported, target low single digits |
| Field coverage | Share of fields in the synthetic mapping that are classified, and how many are default-denied | reported per site, so blind spots are visible |
| Label round trip | Query with `<Tenant-01>`, bridge sends the real value, response shows `<Tenant-01>` again, same ordinal across N calls | 100% |
| Oracle cases | One adversarial case per forbidden shape: wildcard, prefix, regexp, fuzzy, range on identifier, sort on identifier, terms include, script, runtime field, highlight, raw DSL, mapped literal, shaped literal, label of the wrong type, unknown label, `_source` outside the allowlist | every case refused |
| Credential isolation | The argv and env handed to Claude Code contain no ES variable; the tool list is the MCP tools only; the bridge rejects non-loopback and no-token requests | pass |
| Error opacity | Every ES error class maps to a fixed string; a synthetic ES error with a seeded value in its body never reaches Claude | pass |
| Decision log hygiene | Rows hold field names, ops, labels, counts and timings, never a value; `test_hygiene` extended | pass |
| Latency | p50 and p95 per tool call at `max_hits`, tier 2 warm | reported; sets the caps |
| Task utility | Fixed synthetic case scenarios, scored raw against through-the-bridge, same method as `hider utility`: answer correctness, labels quoted intact, unknown-label count, tool calls, cost | delta within the utility floor already in the README |

The utility run needs a key once and is recorded to a cassette holding
synthetic data only, hashes where a value is secret-shaped, read before
commit. The same cassette constraint from AGENTS applies: changing a
template reshuffles the generator and invalidates it.

## What is built (offline core)

| Piece | Where | Measured by |
|---|---|---|
| Site map: kinds, shapes, caps, startup validation | `elastic.py` (`parse`, `load`, `active`) | `tests/test_elastic.py` |
| Session scrubber for async-search responses: hits, `_source` and `fields` by path, bucket keys, `top_hits`, `filters`, metrics; drop-by-default; degraded and leak refusals; error bodies to a class | `elastic.EsScrubber.scrub_response` | `test_elastic.py`, `es-eval` |
| Case vault and seeding (`seed`), save/restore under `out/es/` | `EsScrubber.seed`, `save_session`, `load_session` | `test_elastic.py` |
| Closed grammar, compiler, outbound gate, label resolution | `esquery.py` (`compile_query`) | `tests/test_esquery.py` |
| Adversarial query cases, 38, each with its refusal code | `esquery.ORACLE_CASES` | parametrised test plus `es-eval` |
| Synthetic documents in the three index shapes, with ground truth | `eseval.generate`, `templates/elastic_fixtures.json` | `tests/test_eseval.py` |
| Stub Elasticsearch engine for the grammar; stub Kibana speaking the async protocol with required headers and a cookie | `eseval.StubEngine`, `eseval.StubKibana` | `test_eseval.py` |
| The numbers: leak rate, refusals, clean-traffic refusals, round trip, oracle, coverage, text queries, latency | `eseval.run_eval`, `python -m hider es-eval` | writes `out/es-eval.json` |

Figures from `python -m hider es-eval` on the example map (620 synthetic
documents: 600 generated and 20 fixed ones for unmarked job and customer
names; 120
queries, tier 2 on) are in the session notes and reproduced by the command;
the gates are zero leaks, zero degraded pages, every oracle case refused
with its declared code, every label round trip passing, a fresh case's
first page clean for every unmarked job and customer name (no word of
the name readable), and the two deliberately
planted unlisted fields never shown.

One change outside the new modules: `jsonscrub._phone` no longer labels a
run of eight or more consecutive digits as a phone number unless it starts
with `+`. The fixtures showed `Report-02 (4190469244 bytes)` becoming a
phone label. A formatted number never has eight digits in a row and an
unformatted one is already a declared miss. Eval before and after: unchanged.

## Built: the session layer (`hider/esbridge.py`)

| Piece | What it does | Tested by |
|---|---|---|
| `BrowserTransport` | Playwright, `launch()` plus an off-the-record `new_context()`, `channel="chrome"`, pipe transport (no debug port). One tab per cluster parked on `/app/home`; every request is an in-page `fetch` with the four headers. A tab that lands off the Kibana host or on `/login` is `session_expired`. `login()` navigates the tab and waits; it keeps the browser open, because the session cookie dies with it. | `test_browser_login_keeps_the_session_and_it_dies_with_the_browser`, `test_browser_headless_sso_never_completes` (skip without Playwright and Chrome) |
| `Broker`, `BrokerClient` | The long-lived process that owns the browser. `es-login` starts it detached and asks it to sign in; `es-smoke` sends a grammar query over a Unix socket (0600, in the bridge's 0700 directory) and gets the scrubbed report back. Compile, Kibana and scrub all run inside it, so no raw reply crosses the socket. Stops on `es-logout`, on the analyst closing its window, or after 8 hours idle; any exception is a `bridge_error` refusal with no detail. No broker is `session_expired`. | `test_one_login_lasts_across_many_smoke_runs`, the CLI test, the fail-closed tests |
| `prepare_profile_dir` | Creates the bridge's own directory with a marker file, mode 700; it holds the broker socket. Refuses a stock Chrome profile root and any existing non-empty directory without the marker. | `test_profile_dir_is_dedicated` |
| `UrllibTransport` | Plain HTTP with a cookie, for the stub only. The CLI refuses to use it against a configured cluster. | the rest of `test_esbridge.py` |
| `KibanaSession.parse_reply` | The gate every reply passes: off-host redirect, `/login`, HTML that mentions login, other HTML, non-JSON, non-object, 401/403 each have a code; the body never enters the refusal message. | parametrised test, ten shapes |
| `KibanaSession.search` | Submit, poll on `isRunning`, timeout to `incomplete`, `DELETE` in `finally`. Error bodies pass through to the scrubber, which classes them. | `test_search_submits_polls_and_releases`, `test_poll_timeout_is_incomplete_and_the_search_is_deleted`, the mid-flight expiry test |
| `Bridge.run` | cluster lookup, compile, probe (`/internal/security/me`, body discarded), search, scrub, one lock, decision-log row. The function the MCP tool will call. | the bridge tests, including six concurrent calls |
| Decision log | `hider.es-bridge.v1`: cluster, index, size, time range, filter fields and ops, agg shape, labels used, text phrases as written, hit counts, refusal code, seconds. | `..._the_log_holds_no_values` checks every planted value against the log |
| Stub Kibana additions | Sessions are `sid` cookies with no expiry, issued by an IdP at `/login` that completes only for a headed top-level navigation (never headless, never a `fetch`); without one, a 302 to `/login` and a 200 HTML login page. Hits name data-stream backing indices (`.ds-logs-app-default-2026.08.20-000001`). `slow=True` never finishes, `DELETE` is recorded. `eseval.SimBrowser` keeps Chrome's cookie lifetime rules for tests that cannot run Chrome. | `eseval.StubKibana`, the lifecycle tests |

Site configuration gained two keys, both in the example with invented
values: `clusters` (name to Kibana origin; plain `http` only on loopback)
and `profile_dir` (the bridge's own directory). `poll_timeout_s` (default
120, at most 600) caps how long one async search may poll; the ceiling is
there because the bridge is serialised and a polling search blocks every
other call. `max_phrases` (default 8, at most 16, 0 turns text queries off)
caps the distinct phrases in one query, filters and aggregations at any
depth together; over it is `size_cap` with the count and the cap, never
the phrases. A phrase repeated across buckets, or differing only in case
or spacing, counts once. The zero-hit check reuses only the query's own
filters, so it never goes over the cap of a query that was allowed, and
it splits its buckets across queries when `max_buckets` needs it.

Smoke commands, in the order to run them:

```sh
.venv/bin/pip install -r requirements-es.txt          # playwright; uses the installed Chrome
python -m hider es-smoke --stub --no-browser         # grammar + scrubber + protocol, no Chrome
python -m hider es-smoke --stub                      # the same through real Chrome on a throwaway profile
python -m hider es-smoke --stub --expired            # the stub serves the SSO login page: expect REFUSED session_expired
python -m hider es-login --cluster emea              # starts the bridge; headed window, sign in, it minimises
python -m hider es-smoke --cluster emea --term "<the customer>" --phrase "<a phrase>" --log out/es/smoke.jsonl
python -m hider es-logout                            # stops the bridge; every session ends with its browser
```

`es-login` once per cluster per bridge; every `es-smoke` after that runs
in the bridge. The first sign-in of each bridge is the full IdP flow,
because the off-the-record context remembers nothing; re-signing in after
Kibana expires a session, inside the same bridge, is the quick one. The
`es-smoke` line is the one against a real cluster. It prints one `OK` or
`REFUSED` line with counts and a refusal code, never a page; add `--show`
to print the scrubbed page (labels only) once the counts look right. The
real site map comes from `HIDER_ELASTIC` or `hider.local.json`.

The window defaults to the last hour; `--since` and `--until` take the
grammar's times (`now-7d`, `now-1d/d`, ISO). `--count-by FIELD` adds a
terms aggregation and `--interval 1d` splits it by a date histogram on the
time field (alone, `--interval` is a histogram of the matching lines):

```sh
python -m hider es-smoke --stub --no-browser --since now-6h --count-by agent.name --interval 1h
python -m hider es-smoke --cluster emea --phrase "<a phrase>" --since now-7d --count-by agent.name --interval 1d
```

The `OK` line then carries bucket counts and per-bucket doc counts, never a
key; `--show` prints the keys, which are labels on identifier fields
(`ctr-amer-s01`, region kept by the field's shape). These values go
through `esquery` unchanged, so a field outside the site map, a text field,
an interval outside the grammar, a `--buckets` over `max_buckets` or a
time that is not date math gives a `REFUSED` line with the grammar's code.

`--phrase` is repeatable and every filter is ANDed: `--phrase "returned
HTTP" --phrase 429`. It searches the first text field in the site map
unless `--phrase-field` names another, and the summary names the field
(`phrase_field=message phrases=2`). `--eq FIELD=VALUE` is repeatable; an
identifier field takes a label this run has issued, so seed it first with
`--term TYPE=VALUE` (`--term SERVER_NAME=<the server>`), which gives the
same label on every run with the same terms. A zero-hit filtered query is
followed by one check query: per filtered field, how many documents the
other filters leave and how many of those have the field. A field with
nothing to search makes the run `EMPTY` with exit code 3, naming the
field; a zero over a field that holds documents stays `OK`. With
`--count-by`, the summary adds `count_error_bound`
(`doc_count_error_upper_bound`) and `docs_with_field`, and a `NOTE` when
bucket counts plus `other_docs` do not equal `hits_total`, saying whether
documents lack the field, hold several values, or the counts are
approximate.

A histogram that would return more than `max_buckets` buckets is refused
by the grammar before anything is sent (`size_cap`, naming the count and an
interval that fits). `esquery` resolves both `time_range` bounds the way
Elasticsearch does (UTC, calendar months, `gt`/`lte` rounding up, a bare
date on `lte` meaning its last millisecond) and counts the buckets between
them exactly. When one side is `now` and the other an ISO date, the `now`
side uses this machine's clock widened by five minutes, so the count stays
an upper bound. When both sides are `now`, one clock reading serves both,
as Kibana uses one. A histogram whose window cannot be computed is refused
as `unbounded_histogram`: a `time_range` missing its start or its end, or a
histogram on a field other than the time field. The scrubber's bucket cap
stays as the backstop, for example when Kibana's clock sits across a bucket
edge from this one.

Known limits of this layer, by design for now: Playwright's sync API is
single-threaded, so calls are serialised under one lock (parallel tabs
need the async API); the probe adds one round trip per call; shard
failures in a complete response are not yet a refusal.

## Built: the MCP server (`hider/esmcp.py`)

The architecture section above predates the broker, and three things in it
changed when the MCP server was built on top of it:

- **Where it runs.** Inside the broker, not a process of its own: the
  broker owns the Chrome that holds the only Kibana session, and
  Playwright's sync API belongs to its thread, so every tool call runs
  there. One `selectors` loop serves both listeners: the private socket
  (`es-login`, `es-smoke`, `es-research`) and MCP Streamable HTTP on
  `127.0.0.1`, ephemeral port, JSON replies, no event stream, one request
  per connection.
- **What there is to isolate.** No Elastic credential exists any more, so
  "the argv and env contain no ES variable" becomes: the environment is an
  allowlist (`esmcp.claude_env`: `HOME`, `PATH`, locale, proxies with
  loopback forced into `NO_PROXY`, `ANTHROPIC_*`, `CLAUDE_CODE_*`), so
  `HIDER_ELASTIC`, `HIDER_VAULT_KEY` or an exported cookie are absent by
  default, and nothing Claude Code can reach can open the broker's socket.
- **Tool parameters.** The tools carry the grammar as `esquery` has it now,
  not the signatures in "The query surface": a `cluster`, `phrase` filters
  instead of `text_query`, `aggs` as the grammar's object, and `from`
  instead of `cursor` (cursors are still a later phase).

| Piece | What it does | Tested by |
|---|---|---|
| Transport guards (risk 11) | Loopback peer; `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding); a non-loopback `Origin` is refused; no `Access-Control-*` header on any reply; bearer token for an open case, checked before the path; JSON only, declared length capped before the body is read. Nothing about a case is said before the token matches. | `test_requests_without_a_live_token_or_from_a_page_are_refused`, `test_the_listener_is_loopback_only` |
| Cases | `open_case` on the private socket loads or creates `out/es/<case>/` (0700, files 0600), seeds the human's terms, mints a token. Reopening a case kills the earlier token (one session per case); `close_case` and stopping the bridge kill it too. Saved after every tool call, so labels survive a restart. Two cases, two vaults. | `test_closing_or_reopening_a_case_kills_its_token`, `test_a_case_keeps_its_labels_across_a_bridge_restart`, `test_two_cases_have_two_vaults` |
| Tools | `es_schema` (site map, caps, the case's labels and types), `es_search`, `es_count`, `es_aggregate`, schemas filled in from the site map. Each passes only its own grammar keys to `Bridge.run`; anything else (`terms`, `log`, raw DSL) is `bad_request`. There is no seeding, login, stop or unmask tool: a tool that turned a value into a label would let a guessed value be minted and then confirmed by a count. | `test_a_session_investigates_with_labels_and_never_sees_a_value`, the parametrised refusal test, `test_protocol_edges` |
| Refusals | A tool error `refused (<code>): <message>` with the refusal's own message; any other exception is `bridge_error`, fixed text. | `test_a_real_value_typed_by_claude_is_refused_and_not_echoed`, `test_a_failing_transport_is_bridge_error_with_nothing_in_it` |
| Decision log | The case's `decisions.jsonl`; rows gain `tool`. | `test_the_decision_log_names_the_tool_and_holds_no_values` |
| Launch (credential isolation row) | `es-research`: `claude --restricted --strict-mcp-config --mcp-config <file> --tools "" --allowedTools mcp__hider-es__…`, cwd an empty temp dir, the token only in a 0600 config file in a separate 0700 dir (never on argv), all removed afterwards. The prompt is masked against the case mapping before it is sent; the answer is unmasked locally, shaped server labels included. | `test_the_environment_is_an_allowlist`, `test_argv_names_only_the_bridge_tools_and_holds_no_secret`, `test_es_research_runs_claude_with_the_tools_only_and_unmasks_locally` (a stand-in `claude` that is itself an MCP client) |

```sh
python -m hider es-research --stub --case demo --term "Contoso Group" --prompt "..."   # synthetic
python -m hider es-login --cluster emea
python -m hider es-research --case <case> --term "<the customer>"                       # interactive
python -m hider es-research --case <case> --prompt "<question>" --model haiku         # headless
python -m hider unmask answer.md --mapping out/es/<case>/session.json
```

Added after the first version:

- **The prompt gate** (`esmcp.prompt_findings`). The prompt is the one input
  that skips the grammar. Headless, values the case holds are masked, then
  anything tier 1 or a site shape still calls an identifier is refused
  (`prompt_identifier`), whatever `--yes` says. The check runs on the
  prompt with the case's whole values taken out, before term-word masking,
  because masking `com` inside an address hid the address from tier 1.
  Interactive, the same check is a `UserPromptSubmit` hook passed with
  `--settings` (which `--restricted` honours; checked against Claude Code
  2.1.319: blocked with 0 turns and no cost). Exit code 2 blocks and shows
  stderr to the human only; the command ends in `|| exit 2`, so a crash
  blocks too. The hook also refuses values the case holds, naming their
  labels, because it cannot rewrite the prompt. Labels the case issued and
  the generic label shapes (reserved namespaces) are taken out first.
  Tested by the prompt-gate tests in `test_esmcp.py`.
- **es-eval's MCP section** (`eseval.run_mcp_eval`, gates `mcp_*`). The
  same fixture through the real endpoint. The case is seeded with the
  three labels the oracle cases are written against. The 38 oracle cases
  go through the tools (5 raw-DSL shapes stop at the tool layer as
  `bad_request`). Then 13 hostile transport requests, which must not reach
  Kibana, the decision log, the launch and the prompt gate. The leak this
  section found on its first run - a job name present only in
  `job.status_message` on the first page of a fresh case, which
  harvest-then-sweep can never see because the referenced job's field is on
  some other document - is closed by `elastic._JOB_REF`: at a site whose
  map declares `JOB_NAME` an identifier, a title-case run after the word
  "job" in a text field is labelled with the same label the name gets as a
  field value. Log-vocabulary runs ("Job Failed") are left alone. Every
  gate passes, `mcp_no_leaks` included.
- **Job names with no marker** ("Harbour Nightly finished with warnings").
  The fixture had none, so the gate passed while the shape leaked:
  `eseval.UNMARKED_JOBS` adds five, each message on a worker document with
  no job field and the job's record on an application document, appended
  after the RNG stream. A fresh case's first page is checked offline
  (`fresh_case_no_leaks`) and through MCP (a second case, `mcp_no_leaks`,
  `mcp_fresh_case_shown`); both failed (3 of 5 leaking) before the fix.
  The fix reads the names from the cluster: `Bridge.run` drives an
  `elastic.VocabularyFetch` (one `composite` aggregation per field in
  `vocabulary.fields`, all configured indices, `ignore_unavailable`)
  before a case's first page per cluster and every ten minutes after, and
  every value becomes a known value under its field's rule. Logged as
  counts per field against the cap, plus requests and seconds. An
  unreadable, capped or over-budget read refuses the page and learns
  nothing.
- **A cluster with more names than one aggregation carries.** The first
  version read the last `vocabulary.days` in one capped `terms`
  aggregation. A full bucket list is indistinguishable from a truncated
  one, so a field at the cap had to refuse - and an estate with tens of
  thousands of job names is at the cap on every case, for ever, after a
  wide and slow first read. `eseval.BULK_JOBS` puts 12,000 invented job
  names in the fixture, all older than any case window, which reproduced
  exactly that: every es-eval query refused with `vocabulary`. The fix is
  two things, neither sufficient alone: the read covers the window of the
  query being served widened by `vocabulary.margin_days`, so an hour-wide
  case reads an hour and not a month; and it pages with `composite`
  `after_key` (`VOCABULARY_PAGE` per field per request), so a wide window
  is still readable rather than refused. The ceiling (`vocabulary.max`,
  counted across the whole read) and a wall-clock budget
  (`vocabulary.budget_s`, because the read holds the bridge's one lock)
  keep "fail closed" intact, and `commit()` is the only thing that learns,
  so a refusal on page nine leaves the session untouched. `WINDOW_CASE_*`
  is the fixture shape it exists for: a one-hour case whose message names
  a job whose own record is outside that hour but inside the margin
  (`window_case_shown`, `wide_case_read_whole`). The window is the query's
  own resolved bounds (`Compiled.window`) and nothing else from Claude.
- **Tenant, resource and site names with no marker** (`eseval.UNMARKED_NAMES`):
  the same shape for the other name fields, each message on a document
  whose own fields hold a different tenant. Before the fix they failed
  only once the fresh-case pages were also checked word by word
  (`eseval.name_part_leaks`): tier 2 hid part of a name ("Tenant <Org-01>
  Estates"), which the whole-value check counts as clean. Fixed by listing
  the fields under `vocabulary.fields`; ordinary one-word names are kept
  out by `ORDINARY_NAME_WORDS`.
- **The same names at a site with no `vocabulary` section.** Listing the
  fields fixed the example map, not the default, which stayed JOB_NAME
  only - so a site that had not written the section (the common case) had
  its tenant, tenant-full and resource names readable in message text.
  `eseval.DEFAULT_MAP_*` reproduces it: the example map with the section
  deleted, a one-hour case, "Quota warning for Thornbury Estates, resource
  vault07 near capacity" with both fields on documents outside the hour.
  Before: five of nine tenant names and all nine resources readable.
  After: no resource and no name except the ones the skip rules drop. The
  default is now `ElasticConfig.learnable_rules`, exactly the set the
  loader accepts, so it cannot be something a map would be refused for;
  the cost is zero extra requests, since every field rides one search.
  `vocabulary_omitted` and `es-smoke`'s `NOT READ` make a shorter list a
  visible choice. Declared miss: a one-word tenant name on
  `ORDINARY_NAME_WORDS` or under four characters (`Archive`, `Vault`,
  `Ops`) is still skipped and stays readable - seed it with `--term`.
- **A sensitive value in a keep field.** A real level field held a
  SharePoint personal-site URL among its `info`/`Warning`/`ERR` spellings,
  once a day. A keep field passed through unchanged by declaration, and the
  value reaches Claude two ways: in a hit, and as a bucket key when the
  field's values are aggregated (which the instructions tell Claude to do
  before filtering). `EsScrubber._keep_value` now runs tier 1 and the
  known-value sweep (never tier 2) over every string keep value, in hit
  leaves and bucket keys; a match is replaced as a text field would replace
  it, the bucket stays one bucket under its rewritten key, and an ordinary
  value comes back byte-for-byte. Time-shaped strings skip the pass and a
  cache makes repeated values one detection. Gates: `keep_leak_closed`
  (the invented URL, leaking both ways before) and `keep_values_readable`
  (nine level/outcome spellings unchanged and still filterable).
- **Old cases and log words.** `EsScrubber.load_session` no longer makes a
  value of only `pipeline.LOG_VOCABULARY` words a known value. The label
  stays in the mapping, so old answers unmask; the vocabulary-only value
  is also left out of prompt masking.

Known limits of this layer: one call at a time (a polling search holds
every other call, and `es-login` holds the tools while the human signs
in); keep-field values are never normalised, so `es_schema` and the
instructions tell Claude to aggregate a keep field's actual spellings
(err/Error/ERROR) before an exact filter and to use `in` across them,
guidance the model can still ignore; the refusal codes reach the model, so
`known_value` confirms that a
word Claude typed is a value this case has pseudonymised, a narrower
form of the declared text-query channel; and the zero-hit field check
`es-smoke` runs is not done for the tools (Claude can ask `es_count` with
`exists` itself).

## Superseded: the SSO proposal as written before the decisions

The live side has to make one request shape work on four clusters, each
behind its own corporate SSO session held by a headless Chrome profile:

```
POST {kibana}/internal/search/ese            headers: kbn-xsrf: true,
                                                       x-elastic-internal-origin: Kibana,
                                                       content-type: application/json
body: {"params": {"index": ..., "body": ...}}   (what esquery compiles)
-> {"id", "isRunning": true, ...}  then  POST .../ese/{id} until isRunning is false
-> DELETE .../ese/{id} to release the async search
```

Three ways to own the session, and a recommendation.

**A. Extract the cookie from the Chrome profile and speak HTTP directly.**
The bridge reads the `sid` cookie from the profile's cookie store and uses
`urllib`. Simple HTTP, fully testable against the stub Kibana. Against: the
cookie store is encrypted with the OS keychain key and the format changes;
the extracted cookie is a bearer credential sitting in bridge memory and,
if persisted, in a file; expiry is detected only by a 401 after the fact.
This is cookie theft done to yourself, and the thing it steals is exactly
what constraint 1 wants kept in one place.

**B. Keep the cookie in the browser; the bridge drives the browser.** The
bridge launches one headless Chrome per cluster on its persistent profile
and sends requests *through* the browser, so the cookie never leaves
Chrome's jar. Two ways to do that:

- B1, Playwright as an optional extra (`requirements-es.txt`, the same
  pattern as `requirements-llm.txt`): `launch_persistent_context` per
  cluster, then `context.request.post(...)`, which sends with the context's
  cookies and no page script. Playwright talks to Chrome over a pipe, not a
  TCP port, so no other process on the machine can reach the browser.
- B2, raw Chrome DevTools Protocol over `--remote-debugging-pipe` with the
  standard library only. No dependency, but a websocket-less CDP client and
  a `fetch` evaluated in the Kibana page: a few hundred lines that will
  break on Chrome's schedule, not ours.

**Recommendation: B1.** The credential stays where it already is, the bridge
process holds no secret of its own, the pipe transport closes the local
network path, and the stub Kibana in `eseval` already demands the cookie so
the HTTP half is testable without a cluster. The cost is one heavy optional
dependency that the core never imports.

Whichever is chosen, the same rules:

- **Cluster names are site configuration.** `elastic.clusters` in
  `hider.local.json`: name, Kibana URL, profile directory (outside the
  repo, mode 700). Claude picks a cluster by name; the names are not in the
  repo but are visible in the session, like field names.
- **Session check before every call, refusal on failure.** A cheap
  authenticated request first (`/internal/security/me`). A 401, or a
  redirect to the identity provider, is `Refused("session_expired")` to
  Claude and a prompt in the local web UI for the human to sign in again,
  in a headed window the human drives. Claude never sees the identity
  provider and cannot trigger a login.
- **The response path is the one already built.** The envelope goes to
  `EsScrubber.scrub_response`; `isRunning`, `isPartial`, `timed_out`, an
  error body, and a poll timeout are all refusals. Nothing is shown from a
  response that is not complete and clean.
- **The bridge is started by the human, not spawned by Claude Code.** As in
  the architecture section: a stdio MCP child inherits Claude Code's
  environment; this process must not.
- **Decision log per call**: cluster, index, field names, ops, labels, hit
  count, bucket count, refusal code, timings. The text phrase as written,
  with labels. Never a value.

Expected failures to design for, in order: SSO expiry mid-investigation
(four sessions expire on four clocks); an MFA step the headless profile
cannot complete (headed re-login, human present); a Kibana upgrade that
starts demanding `kbn-version`; the async search id expiring under a slow
poll; a cluster returning `isPartial: false` with failed shards (refused
today by the shard check being absent, which is a gap to close: add
`_shards.failed > 0` to the refusals); and a profile directory that ends up
in a synced folder.

Questions before building this part:

1. Playwright as an optional extra (B1), or no new dependency and raw CDP
   (B2)? If there is already a Chrome automation stack in use for the
   headless profile, which one?
2. Which Kibana version, and does the endpoint there require `kbn-version`
   or `kbn-build-number` headers?
3. Is a headed re-login window popping up on the workstation acceptable
   when a session expires, and does the SSO need MFA on each login?
4. Where should the four profile directories live, and are they already
   created by the current headless setup?

## Later phases

- **Second sweep through the gateway.** Route Claude Code's own API traffic
  through `hider proxy` sharing the case vault, so a value that slipped the
  bridge is caught by the known-value sweep. Needs an Anthropic-shaped
  upstream in the gateway, the scope question the pilot plan flags.
- **Shard failures as refusals.** `_shards.failed > 0` in a complete
  response should be `incomplete`.
- **Parallel tabs.** Playwright's async API, one tab per in-flight call.
- **Cursor pagination.** `from` is capped at 1,000 today; opaque bridge-held
  `search_after` cursors if deeper pages are ever needed.
- **Parallel sessions.** One lock, as the gateway. Fine for one analyst.
