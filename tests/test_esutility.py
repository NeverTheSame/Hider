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
         "week_census"}
    assert report["counts"]["wrong"] == 0
    assert rows["named_job"]["human_steps"] == ["es-seed JOB_NAME from the ticket"]
    assert rows["named_job"]["requests"] == rows["named_job"]["queries"] == 1
    assert report["human_steps"] == 1
    assert all(r["human_steps"] == [] for k, r in rows.items() if k != "named_job")
    f = rows["week_census"]["figures"]
    assert f["total"] > f["sampled"] and f["requests"] == 1 and not f["exact"]
    assert f["missing"] == 0 and f["within_margin"] == f["groups"] == 3 == f["order_settled"]
    assert f["max_error_pct"] < 5
    # the refused query (the last one a question asks) reaches nothing;
    # the steps before it, e.g. reading the page that names the error to
    # exclude, each make one request
    for k, (_cause, code) in BLOCKED.items():
        if code is not None:
            assert rows[k]["requests"] == rows[k]["queries"] - 1, k


def test_the_same_result_with_tier_2_on(world):
    fx, _e, vocab = world
    u = esutility.run_utility_eval(CFG, fx, vocab, tier2="classifier")
    assert u["counts"] == {"answered": 11, "wrong": 0, "blocked": 1}


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
    assert not [v for v in values if any(c.isalpha() for c in v) and v.lower() in blob]
    for key in esutility.GAPS:
        assert key == key.lower() and " " not in key
