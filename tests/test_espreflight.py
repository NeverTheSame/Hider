"""es-preflight: what stays readable on a cluster, in one report, measured
on the fixtures that already carry the known gaps. Each gap appears with
its number; nothing is reported that is not there; no value leaves the
report unless asked."""

from __future__ import annotations

import dataclasses
import json

import pytest

from hider import elastic, eseval, espreflight

NOW = eseval.NOW.timestamp()


def _world(cfg, docs, indices, build_cfg=None):
    fx = eseval.Fixture(docs, [], [])
    engine = eseval.StubEngine(fx, indices)
    index = elastic.VocabularyIndex(None)
    vocab, _b = eseval.build_vocabulary(build_cfg or cfg, engine)
    index.put("stub", vocab)
    sess = eseval.EngineSession(engine)
    return engine, index, (lambda body: sess.search(None, body))


def _by_id(r, fid):
    return [f for f in r["findings"] if f["id"] == fid]


def test_an_over_cap_field_is_a_stop_with_its_count():
    cfg = eseval.over_cap_map(listed=False)
    fx = eseval.Fixture(eseval.over_cap_docs(), [], [])
    engine = eseval.StubEngine(fx, (eseval.OVER_CAP_INDEX,))
    index = elastic.VocabularyIndex(None)
    index.note_over_cap("stub", eseval.OVER_CAP_FIELD, 5500, NOW)
    kept = dataclasses.replace(cfg, vocabulary_fields=("labels.tenant_name", "job.name"))
    vocab, _b = eseval.build_vocabulary(kept, engine)
    index.put("stub", vocab)
    sess = eseval.EngineSession(engine)
    r = espreflight.gather(cfg, "stub", index, lambda b: sess.search(None, b), now=NOW)
    (f,) = _by_id(r, "over_cap")
    assert f["severity"] == "stop" and f["field"] == eseval.OVER_CAP_FIELD and f["count"] == 5500
    # 1.1x the cap reads as a wide name field, with the cap fix
    assert "~5500 distinct values, 1.1x the cap 5000" in f["size"]
    assert f["shape"] == "name" and "raise vocabulary.max" in f["fix"]
    assert r["stops"] == 1
    text = "\n".join(espreflight.format_report({"stub": r}, cfg))
    assert "STOP " in text and "request.ref ~5500" in text and "VERDICT  1 stop" in text
    assert eseval.OVER_CAP_TENANT not in text and eseval.OVER_CAP_JOB not in text
    # millions against a 50k-style cap is an id in a mistyped field: the fix
    # offered is the site map, never the cap
    index.note_over_cap("stub", "request.ref2", 2_000_000, NOW)
    r2 = espreflight.gather(cfg, "stub", index, lambda b: sess.search(None, b), now=NOW)
    (fid,) = [x for x in _by_id(r2, "over_cap") if x["field"] == "request.ref2"]
    assert fid["shape"] == "id" and "about 400x the cap 5000" in fid["size"]
    assert "id-shaped" in fid["size"]
    assert "fix the site map, not the cap" in fid["fix"] and "NO_VOCABULARY_TYPES" in fid["fix"]


def test_a_field_added_late_is_a_stop_with_its_slices_left():
    cfg = eseval.added_map(tenant=True)
    job_only = dataclasses.replace(cfg, vocabulary_fields=("job.name",))
    _e, index, search = _world(cfg, eseval.added_docs(), (eseval.ADDED_INDEX,),
                               build_cfg=job_only)
    r = espreflight.gather(cfg, "stub", index, search, now=NOW)
    (f,) = _by_id(r, "vocabulary_not_serving")
    assert f["severity"] == "stop" and "0.0d of 30d" in f["size"]
    text = "\n".join(espreflight.format_report({"stub": r}, cfg))
    assert "BACKFILLING labels.tenant_name" in text and "2 one-day slices left" in text
    assert eseval.ADDED_TENANT not in text


def test_skip_rules_are_a_know_with_their_counts_and_an_omitted_field_a_stop_with_its_width():
    cfg = dataclasses.replace(elastic.load(elastic.EXAMPLE),
                              clusters=(elastic.Cluster("stub", "https://x.example.net"),))
    fx = eseval.generate(docs=300)
    engine = eseval.StubEngine(fx, cfg.indices)
    index = elastic.VocabularyIndex(None)
    vocab, _b = eseval.build_vocabulary(cfg, engine)
    index.put("stub", vocab)
    sess = eseval.EngineSession(engine)
    search = lambda body: sess.search(None, body)
    r = espreflight.gather(cfg, "stub", index, search, now=NOW)
    (f,) = _by_id(r, "skip_rules")
    assert f["severity"] == "know" and f["counts"] == {"ordinary_word": 2, "short": 1}
    assert "seed" in f["fix"] and _by_id(r, "omitted") == [] and r["stops"] == 0
    # a map that lists job.name alone: every other learnable field is
    # omitted, a stop each, with a live distinct count
    listed = dataclasses.replace(cfg, vocabulary_fields=("job.name",))
    vocab2, _b = eseval.build_vocabulary(listed, engine)
    index2 = elastic.VocabularyIndex(None)
    index2.put("stub", vocab2)
    r = espreflight.gather(listed, "stub", index2, search, now=NOW)
    om = {f["field"]: f["count"] for f in _by_id(r, "omitted")}
    assert set(om) == {"labels.tenant_name", "labels.tenant_full_name",
                       "labels.resource_name", "labels.site_name"}
    assert om["labels.tenant_name"] == 25 and all(isinstance(n, int) for n in om.values())
    assert all(f["severity"] == "stop" for f in _by_id(r, "omitted"))
    # probes off: the field is still a stop, not counted, and 0 requests
    r = espreflight.gather(listed, "stub", index2, None, now=NOW)
    assert r["requests"] == 0 and "not counted: probes off" in _by_id(r, "omitted")[0]["size"]


def test_a_stream_named_after_a_job_is_a_stop_with_fields_and_counts_never_the_name():
    cfg = eseval.stream_name_map()
    _e, index, search = _world(cfg, eseval.stream_name_docs(), (eseval.STREAM_INDEX,))
    r = espreflight.gather(cfg, "stub", index, search, now=NOW)
    (f,) = _by_id(r, "name_in_keep")
    assert f["severity"] == "stop" and f["sampled"] == 3
    # what a person decides on: the distinct names (here 1), not the 9
    # path-occurrences the sample happened to repeat them in
    assert f["names"] == 1 and f["documents"] == 3
    assert f["fields"] == {"_index": 3, "data_stream.dataset": 3, "data_stream.namespace": 3}
    assert "1 distinct learnt name(s)" in f["size"] and "identifier" in f["fix"]
    assert "a sample, so the document counts move between runs" in f["size"]
    assert "hit's own index name" in f["size"]       # _index is named apart
    # the index *pattern* is site-map config the person wrote and es-smoke
    # already prints; with it stripped, the name appears nowhere - not as a
    # value, not in a backing index, not behind a label
    blob = (json.dumps(r) + "\n".join(espreflight.format_report({"stub": r}, cfg))) \
        .replace(eseval.STREAM_INDEX, "")
    assert eseval.STREAM_JOB not in blob and "harborsync" not in blob
    # the name only under show_values, resolved as written
    rv = espreflight.gather(cfg, "stub", index, search, now=NOW, show_values=True)
    assert _by_id(rv, "name_in_keep")[0]["values"] == [eseval.STREAM_JOB]


def test_a_clean_cluster_reports_nothing_and_the_channels_still_print():
    cfg = eseval.split_map()
    _e, index, search = _world(cfg, eseval.split_docs(), (eseval.SPLIT_INDEX,))
    r = espreflight.gather(cfg, "stub", index, search, now=NOW)
    assert r["findings"] == [] and r["stops"] == 0 and r["knows"] == 0
    text = "\n".join(espreflight.format_report({"stub": r}, cfg))
    assert "VERDICT  0 stop, 0 know findings: nothing readable to report" in text
    assert "by design, every cluster" in text and "150 distinct text phrases" in text
    assert "STOP " not in text
    lines, stops = espreflight.short_form({"stub": r})
    assert lines == [] and stops == 0


def test_the_short_form_carries_the_stops_and_es_research_requires_a_say_so(monkeypatch,
                                                                            capsys, tmp_path):
    from hider import cli, esbridge

    cfg = eseval.over_cap_map(listed=False)
    index = elastic.VocabularyIndex(None)
    index.note_over_cap("stub", eseval.OVER_CAP_FIELD, 5500, NOW)
    r = espreflight.gather(cfg, "stub", index, None, now=NOW)
    lines, stops = espreflight.short_form({"stub": r})
    # two stops: the over-cap field, and a vocabulary with no cover at all
    assert stops == 2
    assert any(l.startswith("READABLE on stub: over_cap: request.ref ~5500") for l in lines)
    assert "es-preflight" in lines[-1]

    # es-research headless: refused without the flag, the short form printed
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": "https://kibana-stub.example.net"}}
    raw["profile_dir"] = str(tmp_path / "p")

    class Client:
        def call(self, op, **kw):
            assert op == "preflight" and kw.get("probes") is False
            return {"preflight": {"stub": r}}

    args = type("A", (), {"case": "c1", "term": [], "tier2": "none", "prompt": "q",
                          "yes": True, "accept_readable": False, "model": None,
                          "max_budget_usd": None, "timeout": 60})()
    rc = cli._es_research(args, Client(), tmp_path, elastic.load(elastic.EXAMPLE))
    cap = capsys.readouterr()
    assert rc == 2 and "code=readable_findings" in cap.out
    assert "READABLE on stub: over_cap" in cap.err and "--accept-readable" in cap.out
    assert eseval.OVER_CAP_TENANT not in cap.out + cap.err


def test_the_cli_refuses_without_a_bridge(capsys):
    import json as _json
    import shutil
    import tempfile
    from pathlib import Path

    from hider import cli, elastic as _elastic

    short = Path(tempfile.mkdtemp(prefix="hp-", dir="/tmp"))
    try:
        raw = _json.loads(_elastic.EXAMPLE.read_text())
        raw["clusters"] = {"stub": {"kibana": "https://kibana-stub.example.net"}}
        raw["profile_dir"] = str(short / "nowhere")
        path = short / "elastic.json"
        path.write_text(_json.dumps(raw))
        assert cli.main(["es-preflight", "--config", str(path)]) == 2
        assert "code=session_expired" in capsys.readouterr().out
    finally:
        shutil.rmtree(short, ignore_errors=True)


def test_the_broker_op_is_read_only_and_answers_with_and_without_probes(tmp_path):
    """The op through a real Broker: probes=False reads only what the
    bridge holds (0 requests); probes=True runs the counts and the sample
    through the broker's own session. Field names and counts, no value."""
    from hider import esbridge

    cfg = eseval.stream_name_map()
    engine = eseval.StubEngine(eseval.Fixture(eseval.stream_name_docs(), [], []),
                               (eseval.STREAM_INDEX,))
    saved = esbridge.clock
    esbridge.clock = lambda: NOW
    try:
        broker = esbridge.Broker(cfg, lambda: eseval.SteppedSearchTransport(engine),
                                 poll_interval=0.0, sessions_dir=tmp_path)
        vocab, _b = eseval.build_vocabulary(cfg, engine)
        broker.vocabulary.put("stub", vocab)
        before = len(engine.requests)
        reply = broker.handle({"schema": esbridge.BROKER_SCHEMA, "op": "preflight",
                               "probes": False})
        assert reply["ok"] and len(engine.requests) == before
        assert reply["preflight"]["stub"]["findings"] == []   # probes off: nothing sampled
        reply = broker.handle({"schema": esbridge.BROKER_SCHEMA, "op": "preflight",
                               "cluster": "stub"})
        r = reply["preflight"]["stub"]
        assert r["requests"] >= 1 and [f["id"] for f in r["findings"]] == ["name_in_keep"]
        blob = json.dumps(reply).replace(eseval.STREAM_INDEX, "")
        assert eseval.STREAM_JOB not in blob and "harborsync" not in blob
        bad = broker.handle({"schema": esbridge.BROKER_SCHEMA, "op": "preflight",
                             "cluster": "nope"})
        assert not bad.get("ok") and bad.get("code") == "bad_cluster"
    finally:
        esbridge.clock = saved


def test_a_stream_word_the_site_map_lists_as_readable_is_a_know_line_not_a_stop():
    """The job-named stream again, with the name declared a system word:
    the STOP goes, and a KNOW line says a name was let through, as a count
    and a field; the word only under show_values."""
    cfg = eseval.stream_name_map()
    listed = dataclasses.replace(cfg, vocabulary_readable=frozenset({eseval.STREAM_JOB.casefold()}))
    _e, index, search = _world(cfg, eseval.stream_name_docs(), (eseval.STREAM_INDEX,))
    r = espreflight.gather(listed, "stub", index, search, now=NOW)
    assert not _by_id(r, "name_in_keep") and r["stops"] == 0
    (f,) = _by_id(r, "site_words")
    assert f["severity"] == "know" and f["field"] == "job.name" and f["count"] == 1
    assert "words" not in f
    assert _by_id(r, "skip_rules")[0]["counts"].get("site_word") == 1
    blob = (json.dumps(r) + "\n".join(espreflight.format_report({"stub": r}, listed))) \
        .replace(eseval.STREAM_INDEX, "")
    assert eseval.STREAM_JOB not in blob and "harborsync" not in blob
    rv = espreflight.gather(listed, "stub", index, search, now=NOW, show_values=True)
    assert _by_id(rv, "site_words")[0]["words"] == [eseval.STREAM_JOB]
    # unlisted, the stop is where it was
    assert _by_id(espreflight.gather(cfg, "stub", index, search, now=NOW), "name_in_keep")


def test_a_readable_word_that_is_a_customers_whole_name_is_a_stop():
    cfg = eseval.over_cap_map(listed=False)
    kept = dataclasses.replace(cfg, vocabulary_fields=("labels.tenant_name", "job.name"))
    fx = eseval.Fixture(eseval.over_cap_docs(), [], [])
    engine = eseval.StubEngine(fx, (eseval.OVER_CAP_INDEX,))
    index = elastic.VocabularyIndex(None)
    vocab, _b = eseval.build_vocabulary(kept, engine)
    index.put("stub", vocab)
    tenant = next(v for v in vocab.fields["labels.tenant_name"]
                  if elastic.EsScrubber.vocabulary_skip(v) is None)
    listed = dataclasses.replace(kept, vocabulary_readable=frozenset({" ".join(tenant.split()).casefold()}))
    r = espreflight.gather(listed, "stub", index, None, now=NOW)
    (f,) = _by_id(r, "site_words")
    assert f["severity"] == "stop" and f["field"] == "labels.tenant_name" and f["count"] == 1
    assert "customer" in f["limit"] and tenant not in json.dumps(r)
