# Design: live Elasticsearch research through Hider

Status: offline core built and measured (`hider/elastic.py`, `hider/esquery.py`,
`hider/eseval.py`, `python -m hider es-eval`); session layer built and
tested against the stub Kibana (`hider/esbridge.py`, `python -m hider
es-smoke`, `es-login`). No MCP server yet. Companion to `pilot-plan.md`.

## Decisions taken

| Question | Decision |
|---|---|
| Claude Code's own API traffic through the gateway as a second sweep | Not now. Recorded as a later phase below. |
| Tier 3 on text fields | Off for the pilot. |
| Minimum word length on phrase queries | No. `match_phrase` on `message` is the main tool. Guess confirmation by hit count is accepted: every text query is logged with its labels, counted in the eval (`text_queries`) and declared. |
| Server names | Keep role and region: `ctr-amer-042` becomes `ctr-amer-s01`, through a `shape` regex and `label` format on the identifier field. |
| Index and field names | Site-specific, in `hider.local.json` under `elastic` (object or path), or `HIDER_ELASTIC`. The repo ships `templates/elastic.example.json` with invented names only. |
| Auth | No API keys. The bridge drives the installed Chrome through Playwright on its **own dedicated profile**, signed in to Kibana only, one profile for all four clusters. Queries are in-page `fetch` calls from a tab parked on each Kibana origin, so the SSO cookie never leaves the browser. The analyst's everyday profile is never opened by the bridge. |
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
| Adversarial query cases, 35, each with its refusal code | `esquery.ORACLE_CASES` | parametrised test plus `es-eval` |
| Synthetic documents in the three index shapes, with ground truth | `eseval.generate`, `templates/elastic_fixtures.json` | `tests/test_eseval.py` |
| Stub Elasticsearch engine for the grammar; stub Kibana speaking the async protocol with required headers and a cookie | `eseval.StubEngine`, `eseval.StubKibana` | `test_eseval.py` |
| The numbers: leak rate, refusals, clean-traffic refusals, round trip, oracle, coverage, text queries, latency | `eseval.run_eval`, `python -m hider es-eval` | writes `out/es-eval.json` |

Figures from `python -m hider es-eval` on the example map (600 synthetic
documents, 120 queries, tier 2 on) are in the session notes and reproduced
by the command; the gates are zero leaks, zero degraded pages, every oracle
case refused with its declared code, every label round trip passing, and
the two deliberately planted unlisted fields never shown.

One change outside the new modules: `jsonscrub._phone` no longer labels a
run of eight or more consecutive digits as a phone number unless it starts
with `+`. The fixtures showed `Report-02 (4190469244 bytes)` becoming a
phone label. A formatted number never has eight digits in a row and an
unformatted one is already a declared miss. Eval before and after: unchanged.

## Built: the session layer (`hider/esbridge.py`)

| Piece | What it does | Tested by |
|---|---|---|
| `BrowserTransport` | Playwright, `launch_persistent_context` on `profile_dir`, `channel="chrome"`, pipe transport (no debug port). One tab per cluster parked on `/app/home`; every request is an in-page `fetch` with the four headers. A tab that lands off the Kibana host or on `/login` is `session_expired`. `login()` reopens the same profile headed and waits for the human. | `test_browser_transport_runs_the_whole_path_and_sees_the_login_page` (skips without Playwright and Chrome) |
| `prepare_profile_dir` | Creates the dedicated profile with a marker file, mode 700. Refuses a stock Chrome profile root and any existing non-empty directory without the marker. | `test_profile_dir_is_dedicated` |
| `UrllibTransport` | Plain HTTP with a cookie, for the stub only. The CLI refuses to use it against a configured cluster. | the rest of `test_esbridge.py` |
| `KibanaSession.parse_reply` | The gate every reply passes: off-host redirect, `/login`, HTML that mentions login, other HTML, non-JSON, non-object, 401/403 each have a code; the body never enters the refusal message. | parametrised test, ten shapes |
| `KibanaSession.search` | Submit, poll on `isRunning`, timeout to `incomplete`, `DELETE` in `finally`. Error bodies pass through to the scrubber, which classes them. | `test_search_submits_polls_and_releases`, `test_poll_timeout_is_incomplete_and_the_search_is_deleted`, the mid-flight expiry test |
| `Bridge.run` | cluster lookup, compile, probe (`/internal/security/me`, body discarded), search, scrub, one lock, decision-log row. The function the MCP tool will call. | the bridge tests, including six concurrent calls |
| Decision log | `hider.es-bridge.v1`: cluster, index, size, time range, filter fields and ops, agg shape, labels used, text phrases as written, hit counts, refusal code, seconds. | `..._the_log_holds_no_values` checks every planted value against the log |
| Stub Kibana additions | `signed_in=False` serves a 302 to `/login` and a 200 HTML login page, `slow=True` never finishes, `DELETE` is recorded, `/app/home` and `/internal/security/me` exist. | `eseval.StubKibana` |

Site configuration gained two keys, both in the example with invented
values: `clusters` (name to Kibana origin; plain `http` only on loopback)
and `profile_dir`.

Smoke commands, in the order to run them:

```sh
.venv/bin/pip install -r requirements-es.txt          # playwright; uses the installed Chrome
python -m hider es-smoke --stub --no-browser         # grammar + scrubber + protocol, no Chrome
python -m hider es-smoke --stub                      # the same through real Chrome on a throwaway profile
python -m hider es-smoke --stub --expired            # the stub serves the SSO login page: expect REFUSED session_expired
python -m hider es-login --cluster emea              # once per cluster: headed window, sign in, closes itself
python -m hider es-smoke --cluster emea --term "<the customer>" --phrase "<a phrase>" --log out/es/smoke.jsonl
```

The last line is the one against a real cluster. It prints one `OK` or
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

Known limits of this layer, by design for now: Playwright's sync API is
single-threaded, so calls are serialised under one lock (parallel tabs
need the async API); the probe adds one round trip per call; shard
failures in a complete response are not yet a refusal.

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
- **The MCP server.** Loopback, per-session token, `es_schema`, `es_search`,
  `es_count`, `es_aggregate` over `Bridge.run`; started by the human.
- **Cursor pagination.** `from` is capped at 1,000 today; opaque bridge-held
  `search_after` cursors if deeper pages are ever needed.
- **Parallel sessions.** One lock, as the gateway. Fine for one analyst.
