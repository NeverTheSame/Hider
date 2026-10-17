"""Per-recognizer tests, written from the entity spec.

Each case is a value in the kind of context it actually appears in, because a
recognizer that only works on a bare token is not useful: real log lines wrap
values in punctuation, quotes and paths.
"""

from __future__ import annotations

import pytest

from hider import recognizers as R

REGS = R.all_recognizers()


def types_in(line: str) -> set[str]:
    return {r.entity_type for r in R.analyze(line, REGS)}


def covered(line: str, value: str) -> bool:
    """True when every character of ``value`` sits inside some detected span."""
    start = line.index(value)
    want = set(range(start, start + len(value)))
    got: set[int] = set()
    for r in R.analyze(line, REGS):
        got.update(range(r.start, r.end))
    return want <= got


CASES = [
    ("SESSION_GUID", "[Session] Backup session a41f77c2-9be1-4c33-8f0e-1122aabbccdd started",
     "a41f77c2-9be1-4c33-8f0e-1122aabbccdd"),
    ("SESSION_GUID", 'session={a41f77c2-9be1-4c33-8f0e-1122aabbccdd} braced',
     "a41f77c2-9be1-4c33-8f0e-1122aabbccdd"),
    ("SESSION_GUID", "session=a41f77c29be14c338f0e1122aabbccdd n-format",
     "a41f77c29be14c338f0e1122aabbccdd"),
    ("WORKER_POD_ID", "[Agent] Agent wkr-amer-prx117 heartbeat received", "wkr-amer-prx117"),
    ("WORKER_POD_ID", '{"pod":"wkr-emea-rg124","msg":"claim"}', "wkr-emea-rg124"),
    ("SERVICE_INSTANCE_ID", "Handled by service instance svc-prod-cus-001", "svc-prod-cus-001"),
    ("UPN_EMAIL", "Processing mailbox anna.novak@contosocorp.com (id x)", "anna.novak@contosocorp.com"),
    ("UPN_EMAIL", "GET /users/anna.novak@contosocorp.com/mailFolders returned 429",
     "anna.novak@contosocorp.com"),
    ("UPN_EMAIL", "bounce for priya.vargas+alerts@tailspin.technology today",
     "priya.vargas+alerts@tailspin.technology"),
    ("SITE_URL", "target https://contoso.sharepoint.com/sites/Finance now",
     "https://contoso.sharepoint.com/sites/Finance"),
    ("IP_ADDRESS", "[Net] peer 10.20.30.40 reset the connection", "10.20.30.40"),
    ("IP_ADDRESS", "registered on fe80:0000:0000:0000:0202:b3ff:fe1e:8329 ok",
     "fe80:0000:0000:0000:0202:b3ff:fe1e:8329"),
    ("WINDOWS_USER_PATH", r"[Cache] path C:\Users\anna.novak\AppData\Local\BackupAgent is full",
     r"C:\Users\anna.novak\AppData\Local\BackupAgent"),
    ("HOSTNAME_FQDN", "[Repo] endpoint app01.contosocorp.internal reachable",
     "app01.contosocorp.internal"),
    ("SUPPORT_CASE_NUMBER", "Escalation on case 07551234 with dev", "07551234"),
    ("JWT", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
     "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    ("PRESIGNED_URL", "[Transport] Uploading to https://stor9f2c1a8b3d.blob.core.windows.net/"
                      "repo/chunk881.bin?sv=2024-11-04&sp=racwdl&sig=Q1dEZm5rTHhWc0h0YkpQd0dyTm0%3D",
     "https://stor9f2c1a8b3d.blob.core.windows.net/repo/chunk881.bin"
     "?sv=2024-11-04&sp=racwdl&sig=Q1dEZm5rTHhWc0h0YkpQd0dyTm0%3D"),
    ("CONNECTION_STRING", 'store: DefaultEndpointsProtocol=https;AccountName=stor3a9f1c2b7d;'
                          'AccountKey=c0RmR2hKa0xNbk9wUXJTdFV2V3g==;EndpointSuffix=core.windows.net',
     "DefaultEndpointsProtocol=https;AccountName=stor3a9f1c2b7d;"
     "AccountKey=c0RmR2hKa0xNbk9wUXJTdFV2V3g==;EndpointSuffix=core.windows.net"),
    ("API_KEY", '"ClientSecret": "sk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"',
     "sk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"),
]


@pytest.mark.parametrize("entity_type,line,value", CASES,
                         ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_recognizer_covers_value(entity_type, line, value):
    assert covered(line, value), f"{entity_type} not fully covered in: {line[:70]}"


@pytest.mark.parametrize("entity_type,line,value", CASES,
                         ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_recognizer_reports_expected_label(entity_type, line, value):
    assert entity_type in types_in(line)


# ---------------------------------------------------------------------------
# Suppression. These are the rules that remove protection, so they get the
# most explicit tests in the suite.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "[Service] Build 8.1.0.7, .NET runtime initialised in 16 ms",
    "[Service] Product version 12.3.1.44 loaded",
    "[Agent] agent 8.0.0.101 connected",
])
def test_version_numbers_are_not_addresses(line):
    assert "IP_ADDRESS" not in types_in(line)


def test_real_address_survives_a_nearby_version_word():
    line = "[Net] Build 8.1.0.7 talking to peer 10.20.30.40 now"
    assert covered(line, "10.20.30.40")


def test_public_microsoft_endpoint_is_not_customer_data():
    line = "[Api] Connected to outlook.office365.com as anna@contoso.com"
    assert covered(line, "anna@contoso.com")
    assert not covered(line, "outlook.office365.com")


def test_case_number_needs_context():
    """Eight digits alone must not be redacted, or item counts vanish."""
    assert "SUPPORT_CASE_NUMBER" not in types_in("[Stats] 07551234 items processed")
    assert "SUPPORT_CASE_NUMBER" in types_in("[Note] see case 07551234 for detail")


def test_custom_registry_adds_to_stock_presidio():
    """The baseline the eval compares against really is weaker."""
    line = ("[Session] session a41f77c2-9be1-4c33-8f0e-1122aabbccdd on wkr-amer-prx117 "
            "for site https://contoso.sharepoint.com/sites/Finance")
    stock = {r.entity_type for r in R.analyze(line, R.builtins())}
    full = types_in(line)
    assert full - stock
    assert stock <= full


# ---------------------------------------------------------------------------
# Bearer credentials in every shape a wrapped log line produces.
#
# Regression: the three-part JWT pattern never matched a token whose signature
# had been split onto the next line, so the head stayed in the clear, reached
# the residue, and with tier 3 enabled was sent to the model provider. The
# adversarial case that covered this had an owner note asserting the head "is
# destroyed", which it was not. Every shape below now destroys.
# ---------------------------------------------------------------------------

JWT_HEAD = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYWJjLTAwMSJ9"
JWT_SIG = ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


@pytest.mark.parametrize("line,value", [
    (f"[Auth] Authorization: Bearer {JWT_HEAD}{JWT_SIG}", JWT_HEAD + JWT_SIG),
    (f"[Auth] Authorization: Bearer {JWT_HEAD}", JWT_HEAD),
    (f"[Auth] token={JWT_HEAD} refreshed", JWT_HEAD),
    ("[Auth] Authorization: Bearer aGVsbG8td29ybGQtb3BhcXVlLXRva2Vu",
     "aGVsbG8td29ybGQtb3BhcXVlLXRva2Vu"),
    (f"    {JWT_SIG}", JWT_SIG),
])
def test_every_bearer_credential_shape_is_found(line, value):
    assert covered(line, value)
    assert "JWT" in types_in(line)


def test_a_split_credential_leaves_nothing_in_the_residue():
    """The property that actually matters: no fragment survives to a later tier."""
    from hider import pipeline, pseudonym
    wrapped = f"[Auth] Authorization: Bearer {JWT_HEAD} \\\n    {JWT_SIG}"
    p = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    for line in wrapped.split("\n"):
        spans, _ = p.detect(line)
        residue = "".join(line[s:e] for s, e in pipeline.residue_segments(len(line), spans))
        assert "eyJ" not in residue
        assert "dozjgNry" not in residue


def test_the_word_bearer_alone_is_not_a_credential():
    assert "JWT" not in types_in("[Auth] Bearer token refresh scheduled in 30 ms")


# ---------------------------------------------------------------------------
# GUID subtyping. Label only, never the span.
# ---------------------------------------------------------------------------

GUID_A = "6cafd2ac-dd19-d991-291a-8d565940996d"


@pytest.mark.parametrize("line,expected", [
    (f"[Restore] Execution session {GUID_A} started", "SESSION_GUID"),
    (f"[Tenant] tenant {GUID_A} quota 91% used", "TENANT_ID"),
    (f"[Tenant] tenant id {GUID_A} quota", "TENANT_ID"),
    (f"[Restore] source collection {GUID_A} exported", "OBJECT_GUID"),
    (f"[Dump] Reading {GUID_A} from disk", "GUID"),
])
def test_a_guid_is_typed_from_the_words_around_it(line, expected):
    labels = {r.entity_type for r in R.analyze(line, REGS) if line[r.start:r.end] == GUID_A}
    assert labels == {expected}


def test_subtyping_never_changes_the_span():
    for line in (f"session {GUID_A} x", f"tenant {GUID_A} x", f"Reading {GUID_A} x"):
        hits = [r for r in R.analyze(line, REGS) if "GUID" in r.entity_type or "TENANT" in r.entity_type]
        assert [(h.start, h.end) for h in hits] == [(line.index(GUID_A),
                                                     line.index(GUID_A) + len(GUID_A))]
