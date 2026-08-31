"""Site profiles: additive only, and loudly broken rather than quietly absent."""

from __future__ import annotations

import json

import pytest

from hider import pipeline, profiles, pseudonym, recognizers

GOOD = {
    "name": "test-site",
    "patterns": {
        "WORKER_POD_ID": [r"\bzz-[a-z]{3,6}-(?:prx|rg)\d{1,4}\b"],
        "SERVICE_INSTANCE_ID": [{"regex": r"\bzz-svc-[a-z]{2,8}-\d{1,4}\b", "score": 0.95}],
    },
}


def write(tmp_path, obj, name="site.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj) if isinstance(obj, dict) else obj, encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _clear_cache():
    profiles.active.cache_clear()
    yield
    profiles.active.cache_clear()


def test_profile_adds_coverage_the_builtins_do_not_have(tmp_path):
    line = "[Agent] Agent zz-emea-prx42 claimed the session"
    assert not any(r.entity_type == "WORKER_POD_ID"
                   for r in recognizers.analyze(line, recognizers.all_recognizers()))
    prof = profiles.load(write(tmp_path, GOOD))
    regs = recognizers.all_recognizers(profile=prof)
    hits = [r for r in recognizers.analyze(line, regs) if r.entity_type == "WORKER_POD_ID"]
    assert hits and line[hits[0].start:hits[0].end] == "zz-emea-prx42"


def test_a_profile_cannot_remove_a_builtin(tmp_path):
    """Additive only: whatever the built-ins caught, they still catch."""
    line = ("session 6cafd2ac-dd19-d991-291a-8d565940996d for anna@contoso.com "
            "on zz-emea-prx42")
    base = {(r.start, r.end) for r in recognizers.analyze(line, recognizers.all_recognizers())}
    prof = profiles.load(write(tmp_path, GOOD))
    withp = {(r.start, r.end)
             for r in recognizers.analyze(line, recognizers.all_recognizers(profile=prof))}
    assert base <= withp
    assert withp > base


def test_profile_is_picked_up_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(profiles.ENV_PROFILE, str(write(tmp_path, GOOD)))
    profiles.active.cache_clear()
    p = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    out = p.redact("[Agent] Agent zz-emea-prx42 heartbeat").text
    assert "zz-emea-prx42" not in out


def test_the_eval_baseline_ignores_any_local_profile(tmp_path, monkeypatch):
    """Committed numbers must reproduce on a machine that has a profile set."""
    monkeypatch.setenv(profiles.ENV_PROFILE, str(write(tmp_path, GOOD)))
    profiles.active.cache_clear()
    tier = pipeline.RegexTier(use_active_profile=False)
    line = "[Agent] Agent zz-emea-prx42 heartbeat"
    assert not [s for s in tier.detect(line, [(0, len(line))])
                if s.entity_type == "WORKER_POD_ID"]


@pytest.mark.parametrize("bad,fragment", [
    ({"name": "x", "patterns": {"NOPE": ["a"]}}, "unknown entity label"),
    ({"name": "x", "patterns": {"WORKER_POD_ID": ["("]}}, "does not compile"),
    ({"name": "x", "patterns": {}}, "non-empty object"),
    ({"name": "x", "patterns": {"WORKER_POD_ID": []}}, "non-empty list"),
    ({"name": "x", "patterns": {"WORKER_POD_ID": [{"regex": "a", "score": 9}]}}, "outside"),
    ({"name": "x", "patterns": {"WORKER_POD_ID": [{"nope": "a"}]}}, "must be a regex"),
])
def test_a_broken_profile_raises_rather_than_loading_less_protection(tmp_path, bad, fragment):
    with pytest.raises(profiles.ProfileError) as e:
        profiles.load(write(tmp_path, bad))
    assert fragment in str(e.value)


def test_missing_and_malformed_files_raise(tmp_path):
    with pytest.raises(profiles.ProfileError):
        profiles.load(tmp_path / "does-not-exist.json")
    with pytest.raises(profiles.ProfileError):
        profiles.load(write(tmp_path, "{not json", name="broken.json"))


def test_the_shipped_example_profile_is_valid():
    """The file people copy must itself load."""
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "templates" / "profile.example.json"
    prof = profiles.load(example)
    assert prof.pattern_count >= 3


def test_the_example_profile_uses_only_the_invented_namespace():
    """Stated positively on purpose.

    A denylist of real prefixes would have to spell those prefixes out in a
    public repository, which is the leak it is trying to prevent. So the
    assertion is the other way round: every pattern in the shipped example must
    live under the invented ``acme`` namespace, and anything else fails.
    """
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "templates" / "profile.example.json"
    prof = profiles.load(example)
    for label, items in prof.patterns.items():
        for regex, _score in items:
            assert "acme" in regex, f"{label} pattern is outside the example namespace"
