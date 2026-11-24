"""Tier 2, the trained classifier: generalisation, tokenisation, the pipeline slot.

The property that matters most here is not "does it work on the sentences it
was trained on" - a lookup table would pass that - but "does it work on names
it never saw", since the eval corpus is seeded from a vocabulary the training
data deliberately never touches.
"""

from __future__ import annotations

import pytest

from hider import classifier, pipeline, pseudonym


def test_training_vocabulary_is_disjoint_from_the_eval_vocabulary():
    from hider import entities

    train_words = {w.lower() for w in classifier._TRAIN_FIRST}
    train_words |= {w.lower() for w in classifier._TRAIN_LAST}
    train_words |= {w.lower() for w in classifier._TRAIN_ORG_WORDS}
    eval_words = {w.lower() for w in entities._FIRST}
    eval_words |= {w.lower() for w in entities._LAST}
    eval_words |= {w.lower() for w in entities._ORG_WORDS}
    assert train_words.isdisjoint(eval_words)


def test_generalises_to_names_never_seen_in_training():
    clf = classifier.get_trained()
    text = "Escalated to Anna Novak from Contoso Holdings this morning."
    spans = classifier.predict_spans(clf, text)
    found = {(text[s:e], t) for s, e, t, _ in spans}
    assert ("Anna Novak", "PERSON") in found
    assert ("Contoso Holdings", "ORGANIZATION") in found


def test_unseen_short_capitalised_suffix_is_part_of_the_organisation():
    """Regression: every tier 2 miss in one eval run was a two-letter legal
    suffix ("AG") that the old grammar, with only title-case suffixes, had
    never produced. The eval's suffixes are still not in the training set, so
    this has to come from shape: a short all-caps token after a capitalised
    head in organisation context continues the organisation."""
    clf = classifier.get_trained()
    assert "AG" not in classifier._TRAIN_ORG_SUFFIX
    text = "Escalation note: Fabrikam AG is asking for an ETA on the restore."
    found = {(text[s:e], t) for s, e, t, _ in classifier.predict_spans(clf, text)}
    assert found == {("Fabrikam AG", "ORGANIZATION")}


def test_organisation_without_a_person_nearby_is_still_found():
    clf = classifier.get_trained()
    text = "Waiting on Litware Group for the change approval."
    found = {(text[s:e], t) for s, e, t, _ in classifier.predict_spans(clf, text)}
    assert ("Litware Group", "ORGANIZATION") in found


@pytest.mark.parametrize("text", [
    "The Scheduler API returned an ETA of 5 minutes.",
    "Checked the VPN for the Transport module; DNS is fine.",
    "Session SLA and Queue MFA are both healthy.",
])
def test_acronyms_after_a_capitalised_word_are_not_an_organisation(text):
    """The widened suffix grammar must not turn 'capitals after a title-case
    word' into a signal on its own, or component names followed by a unit or
    protocol get redacted and the engineer stops using the tool."""
    clf = classifier.get_trained()
    assert classifier.predict_spans(clf, text) == []


def test_training_grammar_keeps_the_eval_suffixes_out():
    """The suffix list is where train and eval are allowed to share generic
    words, but the grammar itself must not draw the eval corpus's suffixes:
    that would be training on the answer. 'Holdings' is the one pre-existing
    overlap, named in the module docstring."""
    from hider import entities
    overlap = set(classifier._TRAIN_ORG_SUFFIX) & set(entities._ORG_SUFFIX)
    assert overlap <= {"Holdings"}


def test_hard_negatives_are_not_flagged():
    clf = classifier.get_trained()
    text = "The Session module logged a Warning in the Transport queue."
    spans = classifier.predict_spans(clf, text)
    assert spans == []


def test_training_is_deterministic_for_a_fixed_seed():
    a = classifier.train(seed=1, n_sentences=50)
    b = classifier.train(seed=1, n_sentences=50)
    text = "Spoke to Mateo Berg at Meridian Systems."
    assert classifier.predict_spans(a, text) == classifier.predict_spans(b, text)


def test_get_trained_is_process_cached():
    a = classifier.get_trained(seed=999)
    b = classifier.get_trained(seed=999)
    assert a is b


def test_tokenizer_offsets_round_trip():
    text = "Wkr-amer-prx117, Anna's note: done."
    for tok in classifier.tokenize(text):
        assert text[tok.start:tok.end] == tok.text


# ---------------------------------------------------------------------------
# In the pipeline
# ---------------------------------------------------------------------------


def test_managed_ner_tier_bills_against_the_residue_only():
    line = ("session a41f77c2-9be1-4c33-8f0e-1122aabbccdd on wkr-amer-prx117 "
            "note: spoke with Anna Novak today")
    p = pipeline.Pipeline(
        [pipeline.RegexTier(), pipeline.ManagedNerTier()],
        vault=pseudonym.EntityVault(key=b"k"),
    )
    p.redact(line)
    offered = p.stats.tiers["tier2"].chars_offered
    assert 0 < offered < len(line)


def test_monotonic_with_tier1():
    line = "Anna Novak at anna.novak@contoso.com on wkr-emea-rg124"
    only1 = pipeline.Pipeline(
        [pipeline.RegexTier()], vault=pseudonym.EntityVault(key=b"k")
    ).detect(line)[0]
    both = pipeline.Pipeline(
        [pipeline.RegexTier(), pipeline.ManagedNerTier()],
        vault=pseudonym.EntityVault(key=b"k"),
    ).detect(line)[0]

    def cov(spans):
        out = set()
        for s in spans:
            out.update(range(s.start, s.end))
        return out

    assert cov(only1) <= cov(both)


def test_fail_closed_when_the_classifier_errors(monkeypatch):
    tier = pipeline.ManagedNerTier()

    def boom(clf, text):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(classifier, "predict_spans", boom)
    p = pipeline.Pipeline(
        [pipeline.RegexTier(), tier], vault=pseudonym.EntityVault(key=b"k")
    )
    r = p.redact("session a41f77c2-9be1-4c33-8f0e-1122aabbccdd and Anna Novak")
    assert r.degraded is True
    assert p.stats.tiers["tier2"].errors == 1
    # Tier 1 coverage survives the tier 2 failure.
    assert "a41f77c2-9be1-4c33-8f0e-1122aabbccdd" not in r.text


# ---------------------------------------------------------------------------
# The notes grammar: markdown lines (headings, table rows, labels, list items)
# ---------------------------------------------------------------------------

_NOTES_LISTS = ("_NOTE_PHRASE_WORDS", "_NOTE_FEATURE_WORDS", "_NOTE_COLUMN_WORDS",
                "_NOTE_STATUS_WORDS", "_NOTE_PERSON_LABELS", "_NOTE_ORG_LABELS")
_NOTES_FEATURES = {"line.heading", "token.in_pipes", "token.in_bold", "phrase.before_colon"}


def _claimed(clf, text):
    return {(text[s:e], t) for s, e, t, _ in classifier.predict_spans(clf, text)}


def test_the_notes_vocabulary_is_disjoint_from_the_eval_and_the_name_vocabulary():
    from hider import entities

    names = {w.lower() for w in classifier._TRAIN_FIRST + classifier._TRAIN_LAST}
    names |= {w.lower() for w in classifier._TRAIN_ORG_WORDS}
    eval_words = {w.lower() for w in entities._FIRST + entities._LAST + entities._ORG_WORDS}
    for lst in _NOTES_LISTS:
        words = {w.lower() for w in getattr(classifier, lst)}
        assert words, lst
        assert words.isdisjoint(eval_words), lst
        assert words.isdisjoint(names), lst


def test_logs_training_examples_are_what_a_call_without_the_argument_makes():
    plain = classifier.training_examples(7, 60)
    assert classifier.training_examples(7, 60, notes=False) == plain
    assert not any(_NOTES_FEATURES & set(f) for f in plain[0])


def test_notes_training_is_the_same_log_lines_then_note_lines():
    feats, labels = classifier.training_examples(7, 60)
    nfeats, nlabels = classifier.training_examples(7, 60, notes=True)
    assert nlabels[:len(labels)] == labels and len(nlabels) > len(labels)
    assert [f["word.lower"] for f in nfeats[:len(feats)]] == [f["word.lower"] for f in feats]
    assert all(_NOTES_FEATURES <= set(f) for f in nfeats)
    drop = lambda f: {k: v for k, v in f.items() if k not in _NOTES_FEATURES}
    assert [drop(f) for f in nfeats[:len(feats)]] == feats


def test_the_structure_features_read_the_line():
    toks = classifier.tokenize("## Capacity Planning")
    f = classifier.featurize(toks, "## Capacity Planning", notes=True)
    assert all(x["line.heading"] for x in f)
    text = "| **Owner:** Anna | open |"
    f = {t.text: x for t, x in zip(classifier.tokenize(text),
                                   classifier.featurize(classifier.tokenize(text), text, notes=True))}
    assert f["Owner"]["token.in_bold"] and f["Owner"]["phrase.before_colon"]
    assert f["Owner"]["token.in_pipes"] and not f["Anna"]["token.in_bold"]
    assert not f["Anna"]["phrase.before_colon"] and f["open"]["token.in_pipes"]
    assert not any(x["line.heading"] for x in f.values())


def test_the_default_features_are_unchanged():
    toks = classifier.tokenize("Spoke to Mateo Berg at Meridian Systems.")
    assert classifier.featurize(toks) == classifier.featurize(toks, notes=False)
    assert not any(_NOTES_FEATURES & set(f) for f in classifier.featurize(toks))


@pytest.fixture(scope="module")
def _notes_clf():
    return classifier.get_trained(notes=True)


@pytest.mark.parametrize("line", [
    "## Capacity Planning",
    "### Retention Review",
    "| Ticket | Region | Reviewer |",
    "| Component | Severity | Reference | Comment |",
    "**Open Questions:**",
    "**Impact**:",
])
def test_with_notes_a_heading_a_table_header_and_a_bold_label_are_not_claimed(_notes_clf, line):
    assert _claimed(_notes_clf, line) == set()


@pytest.mark.parametrize("line, name", [
    ("| Anna Novak | open | 3 | retry |", "Anna Novak"),
    ("| 4 | Lena Moreau | closed | pending |", "Lena Moreau"),
    ("Owner: Diego Ferreira", "Diego Ferreira"),
    ("**Contact:** Priya Iyer", "Priya Iyer"),
    ("- Marek Petrov confirmed the restore completed.", "Marek Petrov"),
    ("Escalated the ticket to Sofia Tanaka this morning.", "Sofia Tanaka"),
])
def test_with_notes_a_person_in_a_cell_after_a_label_a_list_item_or_a_sentence_is_claimed(
        _notes_clf, line, name):
    assert (name, "PERSON") in _claimed(_notes_clf, line)


def test_with_notes_an_organisation_after_a_label_or_in_a_cell_is_claimed(_notes_clf):
    assert ("Contoso Holdings", "ORGANIZATION") in _claimed(
        _notes_clf, "**Customer:** Contoso Holdings")
    assert ("Fabrikam Group", "ORGANIZATION") in _claimed(
        _notes_clf, "| Fabrikam Group | open | 2 |")


def test_notes_training_is_deterministic_and_the_default_model_is_not_the_notes_model():
    a = classifier.train(seed=1, n_sentences=50, notes=True)
    b = classifier.train(seed=1, n_sentences=50, notes=True)
    text = "| Anna Novak | open |"
    assert classifier.predict_spans(a, text) == classifier.predict_spans(b, text)
    assert a.notes and not classifier.get_trained().notes
    assert classifier.get_trained(notes=True) is classifier.get_trained(notes=True)
    assert classifier.get_trained(notes=True) is not classifier.get_trained()
