"""Repository hygiene: what a public checkout is allowed to contain.

This file exists because the same mistake happened twice. Fixtures carry
base64 payloads, a plain-text search for a forbidden string cannot see inside
one, and a JWT fixture therefore kept a real-world service name in the
repository through a sanitisation pass and a code review.

The assertions are positive rather than a denylist. A denylist of strings that
must not appear would have to spell those strings out here, in the public
repository, which is the leak it is meant to prevent.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Files whose fixture content is committed and therefore reviewable.
SCANNED = (
    list((ROOT / "hider").glob("*.py"))
    + list((ROOT / "tests").glob("*.py"))
    + list((ROOT / "templates").glob("*.json"))
    + list((ROOT / "cassettes").glob("*.jsonl"))
)

BLOB = re.compile(r"[A-Za-z0-9_-]{16,}={0,2}")

#: Every token a decoded fixture payload is allowed to contain. Adding a
#: payload means adding its vocabulary here, deliberately and in review, which
#: is the point: a payload nobody can describe has no business being committed.
ALLOWED_TOKENS = {
    "alg", "typ", "HS256", "JWT", "sub", "iat", "svc", "abc", "001",
    "1755000000", "anna", "novak", "contosocorp", "com", "acme", "example",
    "sDfGhJkLMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCd",
    "CWDfnkLxVsHtbJPwGrNmXyZcAsDfgHjkL",
    # Truncated variants of the two filler runs above, as they appear in the
    # shorter recognizer fixtures.
    "sDfGhJkLMnOpQrStUvWx", "CWDfnkLxVsHtbJPwGrNm",
    # The canonical RFC 7519 example subject, and the deliberately meaningless
    # opaque bearer value used to prove position alone is enough to redact.
    "1234567890", "hello", "world", "opaque", "token",
    # The HTTP Basic fixture. Basic auth is base64 of "user:password", which
    # is the entire reason it has to be destroyed rather than passed through,
    # so the fixture has to decode to something that looks like a credential.
    # Both halves are invented and say so.
    "svcacct", "Hunter2ExampleNotReal",
}

WORD = re.compile(r"[A-Za-z0-9]+")


def _decodable(text: str) -> list[tuple[str, str]]:
    out = []
    for m in set(BLOB.findall(text)):
        try:
            decoded = base64.urlsafe_b64decode(m + "=" * (-len(m) % 4)).decode("utf-8")
        except Exception:
            continue
        # Only treat it as a real payload if it decodes to readable text.
        if decoded and all(31 < ord(c) < 127 or c in "\n\t" for c in decoded):
            out.append((m, decoded))
    return out


@pytest.mark.parametrize("path", SCANNED, ids=[str(p.relative_to(ROOT)) for p in SCANNED])
def test_every_base64_fixture_payload_decodes_to_declared_vocabulary(path):
    for blob, decoded in _decodable(path.read_text(errors="replace")):
        unknown = {w for w in WORD.findall(decoded) if w not in ALLOWED_TOKENS}
        assert not unknown, (
            f"{path.relative_to(ROOT)} contains a base64 payload decoding to "
            f"undeclared content {sorted(unknown)!r}. If this is intended, add the "
            f"tokens to ALLOWED_TOKENS in this file so the decision is reviewable."
        )


# ---------------------------------------------------------------------------
# Push-protection-shaped credentials. GitHub blocked a push because invented
# Slack tokens in the fixtures had exactly the vendor's shape. The fixtures
# are now assembled at import time (hider.adversarial.DEAD_TOKENS); this check
# keeps the committed text clean for every vendor format a recognizer covers,
# and proves the patterns bite by running them over the runtime values.
# ---------------------------------------------------------------------------

#: What a secret scanner keys on: the vendor prefix plus the documented exact
#: length, or the documented structure. Written to match what GitHub push
#: protection flags for these providers, not what hider.recognizers matches
#: (the recognizer uses length floors on purpose; a scanner uses exact shapes).
SCANNER_PATTERNS = {
    "github classic/oauth/app/refresh token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "github fine-grained token": re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b"),
    "aws access key id": re.compile(
        r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA|ABIA|ACCA)[A-Z0-9]{16}\b", re.IGNORECASE),
    "google api key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack token": re.compile(r"\bxox[abeprs]-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,34}\b"),
    "entra client secret": re.compile(r"\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b"),
}


def _scanner_hits(text: str) -> list[tuple[str, str]]:
    hits = []
    for name, rx in SCANNER_PATTERNS.items():
        for m in rx.finditer(text):
            hits.append((name, m.group(0)[:12] + "..."))
    return hits


@pytest.mark.parametrize("path", SCANNED, ids=[str(p.relative_to(ROOT)) for p in SCANNED])
def test_no_committed_file_contains_a_scanner_shaped_credential(path):
    text = path.read_text(errors="replace")
    hits = _scanner_hits(text)
    # inside base64 payloads too, the blind spot this file exists for
    for _, decoded in _decodable(text):
        hits += _scanner_hits(decoded)
    assert not hits, (
        f"{path.relative_to(ROOT)} contains a credential-shaped string {hits}; GitHub push "
        f"protection will reject it. Build the value at runtime from pieces "
        f"(hider.adversarial.DEAD_TOKENS) instead of writing it out."
    )


def test_scanner_patterns_flag_the_runtime_fixtures():
    """The other half: the dead tokens really have the vendor shapes, so the
    recognizer tests test the real thing and the check above is not vacuous."""
    from hider.adversarial import DEAD_TOKENS

    expected = {
        "github_classic": "github classic/oauth/app/refresh token",
        "github_oauth": "github classic/oauth/app/refresh token",
        "github_fine": "github fine-grained token",
        "aws_long_term": "aws access key id", "aws_temporary": "aws access key id",
        "aws_lowercased": "aws access key id",
        "google": "google api key", "slack_bot": "slack token", "slack_user": "slack token",
        "entra": "entra client secret",
    }
    assert set(expected) == set(DEAD_TOKENS)
    for key, pattern in expected.items():
        assert SCANNER_PATTERNS[pattern].search(DEAD_TOKENS[key]), key
    # and the recognizer catches every one of them, destroyed not vaulted
    from hider import pipeline
    pipe = pipeline.Pipeline()
    for key, value in DEAD_TOKENS.items():
        r = pipe.redact(f"token {value} seen")
        assert value not in r.text and "<REDACTED:API_KEY>" in r.text, key
        assert not any(value == e["value"] for e in pipe.vault.entries.values()), key


def test_no_profile_file_is_committed():
    """A filled-in site profile describes an estate and must stay local."""
    for name in ("profile.json", "site.json"):
        assert not (ROOT / name).exists()
    committed = [p.name for p in ROOT.rglob("*.profile.json")
                 if ".venv" not in str(p) and "out" not in p.parts]
    assert committed == []


def test_the_example_profile_is_the_only_profile_in_templates():
    files = sorted(p.name for p in (ROOT / "templates").glob("*profile*"))
    assert files == ["profile.example.json"]
