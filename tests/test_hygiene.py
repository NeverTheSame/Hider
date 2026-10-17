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
    "alg",
    "typ",
    "HS256",
    "JWT",
    "sub",
    "iat",
    "svc",
    "abc",
    "001",
    "1755000000",
    "anna",
    "novak",
    "contosocorp",
    "com",
    "acme",
    "example",
    "sDfGhJkLMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCd",
    "CWDfnkLxVsHtbJPwGrNmXyZcAsDfgHjkL",
    # Truncated variants of the two filler runs above, as they appear in the
    # shorter recognizer fixtures.
    "sDfGhJkLMnOpQrStUvWx",
    "CWDfnkLxVsHtbJPwGrNm",
    # The canonical RFC 7519 example subject, and the deliberately meaningless
    # opaque bearer value used to prove position alone is enough to redact.
    "1234567890",
    "hello",
    "world",
    "opaque",
    "token",
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
    for _blob, decoded in _decodable(path.read_text(errors="replace")):
        unknown = {w for w in WORD.findall(decoded) if w not in ALLOWED_TOKENS}
        assert not unknown, (
            f"{path.relative_to(ROOT)} contains a base64 payload decoding to "
            f"undeclared content {sorted(unknown)!r}. If this is intended, add the "
            f"tokens to ALLOWED_TOKENS in this file so the decision is reviewable."
        )


def test_no_profile_file_is_committed():
    """A filled-in site profile describes an estate and must stay local."""
    for name in ("profile.json", "site.json"):
        assert not (ROOT / name).exists()
    committed = [
        p.name
        for p in ROOT.rglob("*.profile.json")
        if ".venv" not in str(p) and "out" not in p.parts
    ]
    assert committed == []


def test_the_example_profile_is_the_only_profile_in_templates():
    files = sorted(p.name for p in (ROOT / "templates").glob("*profile*"))
    assert files == ["profile.example.json"]
