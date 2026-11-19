"""The operator-utility measure: scripted investigations through the real bridge."""

from __future__ import annotations

import dataclasses
import json
from collections import Counter

import pytest

from hider import elastic, eseval, esutility

CFG = dataclasses.replace(elastic.load(elastic.EXAMPLE),
                          clusters=(elastic.Cluster("stub", "https://kibana-stub.example.net"),))

#: what each grammar or site-map gap is refused with when the honest query
#: is sent unbent - the list the measure exists to produce
BLOCKED = {
    "tenant_size": ("label_only", None),
    # the honest query runs; the documents naming their tenant only in text
    # are in no bucket of a terms aggregation, and a group shows <*> where a
    # name stood, so tenants named only in text cannot be listed
    "text_which_tenants": ("text_names_not_enumerable", None),
}


@pytest.fixture(scope="module")
def world():
    # the first 600 documents are the ones es-eval generates
    fx = eseval.generate(docs=600)
    engine = eseval.StubEngine(fx, CFG.indices)
    vocab, _ = eseval.build_vocabulary(CFG, engine)
    return fx, engine, vocab


@pytest.fixture(scope="module")
def report(world):
    fx, _engine, vocab = world
    return esutility.run_utility_eval(CFG, fx, vocab, tier2="none")


def test_the_case_is_picked_from_the_fixture_not_written_by_hand(world):
    fx, _e, _v = world
    cs = esutility.pick_case(fx)
    assert cs is not None and esutility.NIGHTLY in cs.job
    assert cs.job in [j[0] for j in cs.tenant.jobs]
    assert cs.failed and all(d.source["labels"]["tenant_name"] == cs.tenant.name
                             and d.source["job"]["status"] == esutility.FAILED for d in cs.failed)
    assert any(d.source["job"]["name"] == cs.job for d in cs.failed)
    # the first tenant in fixture order with a failing Nightly job
    first = next(t for t in fx.tenants
                 if any(d.index == esutility.INDEX
                        and d.source.get("labels", {}).get("tenant_name") == t.name
                        and "Nightly" in d.source.get("job", {}).get("name", "")
                        and d.source["job"].get("status") == "Failed" for d in fx.docs))
    assert cs.tenant is first
    # every status message of a failure maps to exactly one template
    assert all(cs.template(d.source["job"]["status_message"]) is not None for d in cs.all_failed)


def test_every_question_is_scored_and_every_block_names_its_cause(report):
    rows = report["questions"]
    assert len(rows) >= 6 and len({r["kind"] for r in rows}) >= 6
    assert all(r["status"] in esutility.STATUSES for r in rows)
    assert sum(report["counts"].values()) == len(rows)
    for r in rows:
        if r["status"] == "blocked":
            assert r["cause"] in esutility.GAPS or r["refused"] == r["cause"], r
        assert r["queries"] >= 1


def test_the_measured_result_and_the_list_of_what_is_missing(report):
    rows = {r["key"]: r for r in report["questions"]}
    assert {k: (r["cause"], r["refused"]) for k, r in rows.items()
            if r["status"] == "blocked"} == BLOCKED
    assert {k for k, r in rows.items() if r["status"] == "answered"} == \
        {"onset", "servers", "which_jobs", "error_text", "other_tenants", "per_day",
         # the honest queries of these two did not change: the grammar did
         "except_top_error", "any_failure_signal",
         # and this one's honest query is text_groups now
         "error_census",
         # the engineer seeds the job name from the ticket by hand (es-seed),
         # one human step shown as such, then Claude asks with the label
         "named_job",
         # and this one's scope is wider than the sample and its commonest
         # error is not among the newest documents: wrong (the noisy group
         # alone, two of three groups missing) when the sample was the
         # newest documents, answered since the sample is spread over the
         # scope's time span
         "week_census",
         # one tenant's day, all of it in one half hour: wrong (one slice's
         # 20 documents, one of three groups, 525% off) when the sample was
         # spread evenly over the asked-about day, answered since the
         # re-spread puts the sample where the documents are
         "tenant_day_census",
         # the tenant split between its field and the text: asked over the
         # wider scope (any_of of the field eq the label and a text phrase
         # made only of the label), where the field scope alone is wrong
         # against the full truth - the figures on each row show both
         "text_onset", "text_servers", "text_per_day", "text_error_census",
         # a tenant under two fields: the second spelling is seeded by the
         # engineer (a human step) and carried as its own branch
         "text_two_fields"}
    # the one deliberate wrong: the name's words in another sense are inside
    # the wider scope, and nothing mechanical can tell the senses apart
    assert {k for k, r in rows.items() if r["status"] == "wrong"} == {"text_lookalike"}
    assert rows["text_lookalike"]["cause"] == "differs"
    assert rows["text_lookalike"]["figures"]["same_words_another_sense"] == 1
    for k in ("text_onset", "text_servers", "text_per_day", "text_error_census"):
        fs = rows[k]["figures"]
        assert fs["field_scope_against_full_truth"] == "wrong", k
        assert fs["field_scope_items"] is None or fs["field_scope_items"] <= fs["full_truth_items"]
    assert report["counts"]["wrong"] == 1
    assert rows["named_job"]["human_steps"] == ["es-seed JOB_NAME from the ticket"]
    assert rows["named_job"]["requests"] == rows["named_job"]["queries"] == 1
    assert rows["text_two_fields"]["human_steps"] == ["es-seed ORG_NAME the full name from the ticket"]
    tf = rows["text_two_fields"]["figures"]
    assert tf["one_field_scope"] == 0 and tf["both_fields"] == 6
    # the zero with one label was explained, not bare: in that window the
    # short-name field is not filled at all (only the full-name field is),
    # which is exactly what sends the engineer to the second field
    assert tf["zero_explained"]["labels.tenant_name"] == "absent_in_window"
    assert set(tf["zero_explained"].values()) <= {"present", "absent_in_scope", "others_empty",
                                                  "present_in_window", "absent_in_window"}
    assert tf["check_requests"] >= 1
    assert report["human_steps"] == 2
    assert all(r["human_steps"] == [] for k, r in rows.items()
               if k not in ("named_job", "text_two_fields"))
    f = rows["week_census"]["figures"]
    assert f["total"] > f["sampled"] and f["requests"] == 2 and not f["exact"]
    assert f["missing"] == 0 and f["within_margin"] == f["groups"] == 3
    assert f["max_error_pct"] < 5
    # the burst group is concentrated in one slice, so its honest margin is
    # about its own size and the reply claims the order settled for none -
    # it underclaims (the order it shows is in fact the true one)
    assert f["order_settled"] == 0
    # the simulated cost of the sampling pass, at the measured 52 s / 3M rate
    assert f["scan_seconds"] > 0
    f = rows["tenant_day_census"]["figures"]
    # the whole sample lands inside the half hour: the day answered from
    # 1,000 of 3,000 documents in three requests, every count inside the
    # stated margin (the boundary group's margin is widened by the scatter
    # term to cover its newest-first bias), the order settled for the
    # leading group only - where the even spread saw one group from 20
    # documents and put the whole 3,000 on it
    assert (f["total"], f["sampled"], f["requests"]) == (3000, 1000, 3)
    assert f["missing"] == 0 and f["groups"] == 3 and not f["exact"]
    assert f["within_margin"] == 3 and f["order_settled"] == 1
    assert f["max_error_pct"] < 40
    assert f["scan_seconds"] > 0
    # the refused query (the last one a question asks) reaches nothing;
    # the steps before it, e.g. reading the page that names the error to
    # exclude, each make one request
    for k, (_cause, code) in BLOCKED.items():
        if code is not None:
            assert rows[k]["requests"] == rows[k]["queries"] - 1, k


def test_the_same_result_with_tier_2_on(world):
    fx, _e, vocab = world
    u = esutility.run_utility_eval(CFG, fx, vocab, tier2="classifier")
    assert u["counts"] == {"answered": 17, "wrong": 1, "blocked": 2}


def test_the_grader_tells_redaction_from_a_wrong_answer(world):
    fx, engine, vocab = world
    cs = esutility.pick_case(fx)
    op = esutility.Operator(CFG, engine, vocab, cs.tenant.name, tier2="none")
    try:
        g = esutility._error_text(op, cs)
        assert esutility.grade(op, g) == ("answered", None)
        # a word that is not a customer value, hidden behind a label: the
        # unmasked answer is right, what the operator reads is not
        word = next(w for w in ("scheduled", "completed", "failed", "Health", "Scheduler")
                    if any(w in m for m in g.got))
        label = op.scrubber.seed(word)
        over = Counter({m.replace(word, label): n for m, n in g.got.items()})
        assert esutility.grade(op, dataclasses.replace(g, got=over)) == ("wrong", "redaction")
        # a count off is wrong whatever the labels say
        off = Counter(g.got)
        off[next(iter(off))] += 1
        assert esutility.grade(op, dataclasses.replace(g, got=off)) == ("wrong", "differs")
        # a value the question needs, returned only as its label, does not count
        lbl = op.label_of(cs.tenant.name)
        assert esutility.grade(op, esutility.Graded("x", "x", lbl, needs_value=True)) == \
            ("blocked", "label_only")
    finally:
        op.close()


def test_the_operator_reads_only_what_the_bridge_returned():
    page = "Job <Job-02> (<Guid-07>) scheduled on ctr-amer-s01, 14 sites enqueued"
    assert esutility.shape(page) == "Job <> (<>) scheduled on # # sites enqueued"
    assert esutility.search_phrase(page) == "scheduled on"
    assert esutility.search_phrase("<Org-01> <Guid-02> 12") is None


def test_the_section_carries_counts_and_codes_never_a_value(world, report):
    fx, _e, _v = world
    lines = esutility.format_lines(report)
    assert lines[0].startswith("-- operator utility")
    blob = ("\n".join(lines) + json.dumps(report)).lower()
    values = set(fx.truth) | {t.name for t in fx.tenants} | {j[0] for t in fx.tenants
                                                             for j in t.jobs}
    values |= set(eseval.BURST_TENANTS) | set(eseval.BURST_JOBS)
    values |= {eseval.DENSE_TENANT, eseval.DENSE_OTHER, eseval.DENSE_JOB}
    values |= {eseval.SPLIT_TENANT, eseval.SPLIT_OTHER, eseval.SPLIT_THIRD,
               eseval.SPLIT_FULL_NAME, "relay-07", "relay-08", "indexer-03"}
    assert not [v for v in values if any(c.isalpha() for c in v) and v.lower() in blob]
    for key in esutility.GAPS:
        assert key == key.lower() and " " not in key


def test_the_wider_scope_weakens_nothing_and_the_log_shows_the_label_not_the_name():
    """One any_of of the tenant field eq its label and a text phrase made
    only of the label: counts one of the query's max_phrases, spends
    nothing from the per-case budget, resolves only a shown label, never
    double counts a document matching both branches, and the decision log
    and es-review see the label, never the value."""
    from hider import esquery, esreview

    cfg, fx, engine, vocab = eseval.split_world()
    op = esutility.Operator(cfg, engine, vocab, eseval.SPLIT_TENANT, tier2="none")
    try:
        wider = esutility._wider(op)
        out = op.ask(esutility._split_q(op, wider))
        # the full truth, each matching document once (the field-marked
        # documents also name the tenant in text and still count once)
        in_window = [d for d in eseval.split_truth()
                     if eseval._parse_time(d.source["@timestamp"])
                     >= eseval._parse_time("now-3d")]
        assert out["hits"]["total"]["value"] == len(in_window) == 39
        # budget: a phrase made only of the label is free; the per-query
        # width still charges it one of max_phrases
        rep = op.scrubber.phrase_report()
        assert rep["phrases_used"] == 0
        c = esquery.compile_query(esutility._split_q(op, wider), cfg, op.scrubber)
        assert len(c.new_phrases) == 0 and c.text_queries == [op.tenant]
        # an unshown label in the same shape refuses as any label rule does
        with pytest.raises(esutility.Blocked) as e:
            op.ask(esutility._split_q(op, {"any_of": [
                {"field": "labels.tenant_name", "op": "eq", "value": op.tenant},
                {"field": "job.status_message", "op": "phrase", "value": "<Org-77>"}]}))
        assert e.value.code == "unknown_label"
        # the log carries the phrase as written (the label) and never the name
        log = (op.case.directory / "decisions.jsonl").read_text()
        rows = [json.loads(x) for x in log.splitlines() if "vocabulary" not in x]
        assert rows[0]["text_queries"] == [op.tenant] and op.tenant in rows[0]["labels_used"]
        assert eseval.SPLIT_TENANT not in log and "Welland" not in log
        # es-review does not read the label-only phrase as a typed guess
        op.case.save()
        r = esreview.review(op.case.directory)
        assert r["numbers"]["text_phrases_distinct"] == 0
        assert not any(s["flagged"] for s in r["signals"]), r["signals"]
        blob = json.dumps(r)
        assert eseval.SPLIT_TENANT not in blob and "Welland" not in blob
    finally:
        op.close()
