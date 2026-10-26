"""The utility harness: questions from ground truth, raw vs redacted scoring."""

from __future__ import annotations

import json
import re

import pytest

from hider import generator, utility

CORPUS = generator.generate(lines=300, seed=20260820, clean_lines=0)


def test_excerpt_is_entity_bearing_lines_with_rebased_truth():
    ex = utility.build_excerpt(CORPUS, 20)
    assert len(ex.lines) == 20
    for o in ex.occurrences:
        assert ex.lines[o.line_no][o.start:o.end] == o.value


def test_questions_follow_from_truth():
    ex = utility.build_excerpt(CORPUS, 40)
    qs = utility.build_questions(ex)
    assert qs, "no questions could be built"
    kinds = {q.kind for q in qs}
    assert {"count", "value"} <= kinds
    for q in qs:
        if q.kind == "count":
            assert isinstance(q.truth, int) and q.truth >= 1
        if q.kind == "value":
            assert q.truth in ex.text
        if q.kind == "list":
            assert all(v in ex.text for v in q.truth)
        for v in q.carries:
            assert v in q.text


@pytest.mark.parametrize("kind,truth,answer,ok", [
    ("count", 3, 3, True), ("count", 3, "3", True), ("count", 3, "three", False),
    ("value", "a@b.example", " `a@b.example` ", True), ("value", "x", ["x"], True),
    ("value", "x", "y", False),
    ("list", ["a", "b"], ["b", "a"], True), ("list", ["a", "b"], "a, b", True),
    ("list", ["a", "b"], ["a"], False),
])
def test_scoring(kind, truth, answer, ok):
    assert utility.score(kind, truth, answer)[0] is ok


def test_parse_answer_is_strict():
    assert utility.parse_answer('{"answer": 4}') == 4
    assert utility.parse_answer('```json\n{"answer": "x"}\n```') == "x"
    with pytest.raises(utility.UtilityParseError):
        utility.parse_answer("4")
    with pytest.raises(utility.UtilityParseError):
        utility.parse_answer('{"result": 4}')


class Constant:
    name = "constant"

    def __init__(self, answer):
        self.answer = answer
        self.prompts: list[str] = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        return json.dumps({"answer": self.answer})


class CountOracle(Constant):
    """Answers counting questions by actually counting in the data it was
    given, so it is right on both sides regardless of redaction."""

    name = "oracle"

    def complete(self, prompt):
        self.prompts.append(prompt)
        data = prompt.split("<<<DATA\n", 1)[1].split("\nDATA>>>", 1)[0]
        q = prompt.rsplit("Question: ", 1)[1]
        m = re.search(r"appear: (.*?) \?", q)
        if m:
            needle = m.group(1)
            return json.dumps({"answer": sum(1 for l in data.splitlines() if needle in l)})
        return json.dumps({"answer": 0})


def test_redacted_prompts_never_carry_a_seeded_value():
    b = Constant(0)
    rep = utility.run(b, lines=300, excerpt_lines=30, tier2=None)
    assert rep.prompt_leaks == 0
    ex = utility.build_excerpt(CORPUS, 30)
    seeded = {o.value for o in ex.occurrences if len(o.value) >= 8}
    redacted_prompts = b.prompts[1::2]  # raw, redacted, raw, redacted ...
    assert redacted_prompts
    for p in redacted_prompts:
        for v in seeded:
            assert v not in p


def test_same_wrong_answer_on_both_sides_gives_zero_delta():
    rep = utility.run(Constant("nonsense"), lines=300, excerpt_lines=30, tier2=None)
    assert rep.n > 0
    assert rep.raw_accuracy == rep.redacted_accuracy
    assert rep.delta == 0.0 and not rep.below_floor
    d = rep.to_dict()
    assert d["questions"] == rep.n and d["backend"]["name"] == "constant"
    assert "prompt_version" in d


def test_a_value_question_is_scored_after_detokenisation():
    rep = utility.run(CountOracle(0), lines=300, excerpt_lines=30, tier2=None)
    by_id = {q.qid: q for q in rep.questions}
    counts = [q for q in by_id.values() if q.qid.startswith("lines-mentioning-")]
    assert counts
    # The oracle counts the pseudonym on the redacted side and the real value
    # on the raw side; stable pseudonyms make both right.
    for q in counts:
        assert q.raw_correct, q.qid
        assert q.redacted_correct, (q.qid, q.redacted_error, q.redacted_answer)


def test_display_question_hides_the_carried_value():
    assert utility._display("On how many lines does this x appear: SECRET ?", "X") == \
        "On how many lines does this x appear: <value> ?"
