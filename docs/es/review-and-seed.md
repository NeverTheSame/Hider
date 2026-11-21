# Elasticsearch research: es-review and es-seed

Moved verbatim from `AGENTS.md` (only the indentation changed). `AGENTS.md` keeps the rules a change must not break; this file keeps the history, measurements, declared misses and reasoning behind them.

**A case can be read back** (`es-review --case NAME`, `hider/esreview.py`)
from its decision log and saved session, because the log recorded a
great deal per query and nothing read it: after a session nobody could
tell an investigation from a case spent probing without reading the
JSONL. The command is **human-only** (no MCP tool, nothing the
es-research session can call or read), **read-only** (it writes
nothing), prints **counts, labels, codes, field names and Claude's own
typed phrases** by default and the values behind labels only under
`--show-values` (the same explicit ask as es-smoke's
`--show-readable-names`), reports a missing or unreadable log as **no
review** with a non-zero exit and never as a clean case, and reviews a
log written before it existed with each gap marked `not recorded`.
It shows the numbers (queries by tool, pages shown, hits, refusals by
code, labels and keep values the case ended up able to use from
`session.json` or the log's running totals, labels issued) and the
phrase spend against the budget, then five signals, each with its
evidence and a note on what an innocent case looks like; the
thresholds sit together at the top of the module:
- `label_guessing`: 3+ `unknown_label` refusals, or a run of 3+
  consecutive label numbers among the labels typed (innocent: 0-2, a
  typo or a label off an older page);
- `zero_hit_phrases`: 5+ name-shaped phrases (one to three capitalised
  words, no digits) that found nothing, or 20+ phrases with half
  finding nothing (innocent: a handful of lower-case error fragments
  while narrowing). A phrase a row cannot judge (`unjudged_phrases`) is
  neither found nor zero-hit there; it is found once any row finds it.
  A name-shaped phrase only ever used inside `not` counts toward the 5,
  because guessing through `not` is exactly that test (base count minus
  negated count) and an honest exclusion is an error fragment, not a
  name. Cost: a case excluding five capitalised names by phrase is
  flagged; excluding a tenant by its label on its field is not a phrase
  and is not counted;
- `phrase_budget_pressure`: any `phrase_budget` refusal, or 80% of the
  budget spent (innocent: tens of phrases and no refusal);
- `wide_collection`: one **aggregation** that made 20+ labels or keep
  values usable - pages of hits are not counted, since a page of
  events carries a handful of labels per event and reading events is
  the job (innocent: a terms over servers or levels, about ten keys);
- `literal_probing`: 3+ `known_value`/`literal_identifier`/
  `shaped_literal` refusals, with the fields (innocent: 0-1, a value
  typed back before it was shown, then corrected to the label);
- `mid_case_seeding`: names the engineer added while the session ran
  (the `event: seed` rows below), flagged at 3+ in one case, or when
  any such label's first use found nothing - a guess turned into a
  label by hand and confirmed by a zero (innocent: none, or one or two
  names from the ticket or the customer's reply, each then used and
  found). The `SEEDED` line lists every one: label, type, after which
  query, whether the case already held a label for the value, and what
  its first use found; never the value.
Three fields were added to the decision log for it, all counts or
Claude's own words: `new_labels`/`new_keep_values` (how many a page made
usable) with the running totals `labels_usable`/`keep_values_usable`,
and `zero_hit_phrases` (the typed phrases whose filter or `filters`
bucket matched nothing - already in `text_queries`, so the log holds
nothing it did not). Gate: `review_flags_guessing` - the guessing run
from `phrase_budget_holds` is flagged (`zero_hit_phrases` and
`phrase_budget_pressure`), an ordinary investigation on the fixture
(page by tenant label, servers and levels aggregated, a server label
off that page used next, two error fragments searched, a histogram) is
not and has no refusal, a case directory with no log is `missing` with
no verdict, and the default output of both carries no planted value.
Declared limits: the signals read the shape of what Claude typed, not
its intent, so a long and clumsy investigation can trip
`zero_hit_phrases` and a case about many tenants can trip
`wide_collection` - the innocent note under each flag is there to be
read; and a bridge not restarted since this change writes none of the
new fields, which the review then marks rather than infers.

**A name can be added to an open case without ending its session**
(`es-seed --case c1 --term "JOB_NAME=…"`, broker op `seed_case`,
`Bridge.seed`, `CaseBook.seed`). Before: a human could turn a name
into a label only by opening the case, and `CaseBook.open` on a case
already open closed the earlier session first - its token stopped
working at once, so the Claude conversation was lost - while the
reopened case kept its shown labels and every earlier seed on disk but
told Claude (es_schema `case.seeded`) about the **latest opening's
terms alone**, and nothing in the decision log recorded the reopen or
the seed. So when the customer replied halfway through with a second
job, the engineer chose between losing the conversation and not asking
about the job. Now `es-seed` reaches the running broker over its 0600
socket by the case's **name** (no token, no tool: Claude Code has no
shell, no files and no socket, and `es_seed` is not a tool - a
value-to-label step Claude could trigger would let it confirm a guess
with a count), the value is labelled, seeded and marked shown, the
session and its token are untouched, and the human gets the label and
its type to hand to Claude. **How Claude learns**: its next tool result
carries `seeded_since_last_call` (label and type, once), `es_schema`
lists every seed with its type under `case.seeds` (the reopen list is
complete now too), and the esmcp instructions (rule 9) tell it what the
step is and never to ask for one. The value reaches Claude nowhere, and
no log: the decision log gets an `event: seed` row with the label, the
type, `known_before` (the case already held a label for the value - from
the cluster vocabulary, a page or an earlier seed), `already_seeded`,
`queries_before` and `seeded_total`; `es-seed` prints the same and a
reminder, and `vocabulary.log.jsonl`, the VOCAB line and every reply
stay as they were. A case holds at most `esbridge._MAX_SEEDS` (40)
seeded names over its life (cost: a longer case opens a new one).
**Misuse, thought through before building.** Claude *can* use the
human as its value-to-label step by asking "please seed Northwind":
the human types the name, hands over the label, and a count confirms
the guess outside the phrase budget. What closes it is not a rule in
the bridge but visibility and the instruction: every seed is the
engineer's logged step, `es-review` lists each one with what its label
then found, flags the pattern (`mid_case_seeding`, above), and `es-seed`
itself says that a name Claude asked for is a guess it could not make
itself. **A name the cluster knows looks different to Claude from one
it does not**, and this is declared rather than closed: a known value
keeps the label it already has (a number minted when the vocabulary
was applied or when a page showed it), while a new value gets the
next number, which Claude can read against the numbers it has seen on
pages. Closing it would mean minting labels out of order, which is a
change to label numbering, not made. What it leaks is one bit per name
the human chose to type - "has the cluster labelled this value" - and
the human is told the same bit (`already labelled in this case` / `new
to this case`) before handing over the label, so the human knows
exactly what Claude can infer and the review shows it (`known_before`).
A seed before the case's first query is always "new" (the vocabulary
is applied at the first query), so an opening seed tells Claude
nothing. **Not touched**: the query grammar (a seeded label is a label
like any other), the phrase budget (a seed is not a phrase; charging
it would change what the budget means), the vocabulary, tier 2 and
the scrubbing rules. Tests: `test_esmcp.py` (the op through the real
broker: token kept, label in the next result and in `es_schema`, no
`es_seed` tool, no value in any byte Claude received or in the log,
`no_case` for a case not open, the CLI, the reopen list),
`test_esbridge.py::test_a_mid_case_seed_is_logged_as_a_label_never_a_value_and_capped`,
`test_esreview.py`. The review eval's ordinary investigation now seeds
one name mid-case (the customer naming a job), which es-review
reports and does not flag, gated in `review_flags_guessing`.


**A refused query is logged as its shape** (`esbridge._refused_shape`,
row key `refused_shape`; es-review prints one `REFUSED <code>: <shape>`
line per refusal and `numbers.refused_shapes`). The log used to keep only
the code of a query the grammar refused before `_describe` could run, so
when the model run (`esmodel`) showed a `bad_agg` as the first aggregation
of every case, neither a person nor es-review could say what was tried.
**What counts as shape when the grammar did not understand the query**:
only closed vocabularies are written - a field name or the index only if
the site map lists it (else `<unlisted>`), a filter op or aggregation type
only if the grammar knows it (else `<other>`, or `<missing>` when the key is
absent), key names only if they are the grammar's own or on the fixed
`_DSL_WORDS` list of Elasticsearch DSL words; Elasticsearch's own
`{"terms": {...}}` form is shown under `dsl` with its inner keys and field.
Everything the model chose freely - aggregation and filter-bucket names,
values, phrases, labels, an invented key - is **counted** (`other_keys`),
never written. Nesting is followed to the grammar's depth; lists to 50.
Pinned by `tests/test_esrefused.py`: an Elasticsearch-style aggregation
named `contoso_servers` with a phrase and an invented key logs `type:
<missing>`, `dsl.terms.keys: [field, size]`, `other_keys: 1`,
`field: agent.name`, and none of the name, the phrase or the key; an
unlisted index, an invented type and an unlisted field log as `<unlisted>`
/ `<other>`; an accepted query logs no `refused_shape`.
**What could still leak through it**, declared: which listed fields, ops,
types and DSL words the model tried, and how many other keys and list
entries a query had - nothing it typed as free text. A site that lists a
field named after a customer has a customer name in its site map already,
and that name appears here as it does in every accepted row.
**What it found**: the model's first aggregation in every case was
Elasticsearch's form - `{"<name>": {"terms": {"field": ..., "size": ...}}}`,
`type` missing - because the tool schema described each type as `terms
{field, size, aggs}`, which reads as Elasticsearch's. Fixed in the wording,
not the grammar: the `es_aggregate` schema now opens with one example in the
grammar's form and says the Elasticsearch form is refused; the `bad_agg`
refusal for a spec with no `type` and an aggregation word as a key gives the
grammar's form with the example. Still refused, never translated - oracle
case `dsl-form-aggregation` (`bad_agg`). Measured with the model on the same
question (`servers`): **before, 1 `bad_agg` and 6 queries; after, 0
refusals and 5 queries**, answered both times.
