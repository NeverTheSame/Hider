"""Tier 2, the trained classifier: generalisation, tokenisation, the pipeline slot.

The property that matters most here is not "does it work on the sentences it
was trained on" - a lookup table would pass that - but "does it work on names
it never saw", since the eval corpus is seeded from a vocabulary the training
data deliberately never touches.
"""

from __future__ import annotations

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
