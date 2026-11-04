"""Per-recognizer tests, written from the entity spec.

Each case is a value in the kind of context it actually appears in, because a
recognizer that only works on a bare token is not useful: real log lines wrap
values in punctuation, quotes and paths.
"""

from __future__ import annotations

import pytest

from hider import recognizers as R
from hider.adversarial import DEAD_TOKENS as T

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
    ("IP_ADDRESS", "[Net] peer 010.020.030.040 reset the connection", "010.020.030.040"),
    ("IP_ADDRESS", "[Net] connected to 192.168.001.010:443 ok", "192.168.001.010"),
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
    ("WINDOWS_USER_PATH", "[Cache] path C:/Users/anna.novak/AppData/Local/BackupAgent is full",
     "C:/Users/anna.novak/AppData/Local/BackupAgent"),
    ("WINDOWS_USER_PATH", "[Cache] staging C:\\Users\\anna.novak/AppData/Local\\BackupAgent done",
     "C:\\Users\\anna.novak/AppData/Local\\BackupAgent"),
]


# ---------------------------------------------------------------------------
# Vendor credentials. Every value is shape-valid and value-dead, and built at
# import time (hider.adversarial.DEAD_TOKENS) so no committed file contains a
# string a secret scanner would flag; tests/test_hygiene.py enforces that.
# ---------------------------------------------------------------------------

VENDOR_CASES = [
    ("github classic PAT",
     f"[Connector] github auth failed for {T['github_classic']} at 401", T["github_classic"]),
    ("github OAuth token",
     f"[Connector] refreshing {T['github_oauth']} now", T["github_oauth"]),
    ("github fine-grained PAT",
     f"[Connector] token={T['github_fine']} expired", T["github_fine"]),
    ("aws long-term access key id",
     f"[S3] InvalidAccessKeyId for {T['aws_long_term']} on upload", T["aws_long_term"]),
    ("aws temporary access key id",
     f"[S3] assumed role issued {T['aws_temporary']} valid 1h", T["aws_temporary"]),
    ("google api key",
     f'[Config] {{"gcp":"{T["google"]}"}}', T["google"]),
    ("slack bot token",
     f'[Config] {{"slack":"{T["slack_bot"]}"}}', T["slack_bot"]),
    ("slack user token",
     f"[Connector] {T['slack_user']} revoked", T["slack_user"]),
    ("entra client secret",
     f"[Auth] client secret {T['entra']} expires in 7 days", T["entra"]),
]


@pytest.mark.parametrize("name,line,value", VENDOR_CASES, ids=[c[0] for c in VENDOR_CASES])
def test_vendor_credential_is_found(name, line, value):
    assert covered(line, value), f"{name} not fully covered"
    assert "API_KEY" in types_in(line)


@pytest.mark.parametrize("name,line,value", VENDOR_CASES, ids=[c[0] for c in VENDOR_CASES])
def test_vendor_credential_is_destroyed_never_vaulted(name, line, value):
    """The whole point of the type: these must not reach the vault.

    A pseudonym is reversible by design, so vaulting a live credential would
    store the exact thing this layer exists to remove. ``EntityVault`` refuses,
    and ``pipeline`` routes the type to destruction instead.
    """
    from hider import entities, pipeline, pseudonym

    assert "API_KEY" in entities.SECRET_TYPES
    assert pipeline._is_secret("API_KEY")
    with pytest.raises(ValueError):
        pseudonym.EntityVault(key=b"k").pseudonym("API_KEY", value)


@pytest.mark.parametrize("name,line,value", VENDOR_CASES, ids=[c[0] for c in VENDOR_CASES])
def test_vendor_credential_leaves_nothing_in_the_residue(name, line, value):
    """No fragment may survive to a paid tier, which is where it would leave the machine."""
    from hider import pipeline, pseudonym

    p = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    spans, _ = p.detect(line)
    residue = "".join(line[s:e] for s, e in pipeline.residue_segments(len(line), spans))
    assert value not in residue
    # The distinctive body, not just the prefix, has to be gone.
    assert value[-18:] not in residue


def test_lower_cased_aws_key_id_is_still_caught():
    """Opposite call from the pod-id rule, and deliberately so.

    A down-cased key id is still a credential. Destroying a token that merely
    looked like one costs a line of triage detail; missing one leaks a live
    AWS credential, so this rule errs toward destroying.
    """
    assert "API_KEY" in types_in(f"[S3] using profile key {T['aws_lowercased']}")


@pytest.mark.parametrize("line", [
    "[Scheduler] Policy 'Nightly' bound to service svc-prod-cus-001, next run in 40 ms",
    "[Stats] processed 48123 items in 9124 ms across 12 shards",
    "[Repo] endpoint app01.contosocorp.internal reachable in 12 ms",
    "[Note] The engineer asked whether the agpa report covers that account.",
    "[Build] github_actions runner v2.311.0 started",
])
def test_vendor_credential_rules_do_not_fire_on_ordinary_lines(line):
    """Prefix rules are cheap; a prefix rule that over-matches is not."""
    assert "API_KEY" not in types_in(line)


# ---------------------------------------------------------------------------
# Credentials that were being VAULTED rather than destroyed.
#
# This group is the worst failure mode the system has: a pseudonymising tier
# claims a credential, so the secret stays in the text under a label AND is
# written to the vault under a reversible mapping. A plain miss leaks once; a
# vault entry leaks and persists. Each case below was observed doing that.
# Every literal is invented.
# ---------------------------------------------------------------------------

URL_USERINFO = "[Feed] pull from https://svcacct:Hunter2Example@repo.contoso.internal/api/v1/pull failed"
AWS_SECRET_LINE = "[Cfg] aws_secret_access_key=wJalrXUtnFEMIexampleKEYnotrealbPxRfiCYEXAMPLEKEY loaded"
BASIC_LINE = "[Auth] Authorization: Basic c3ZjYWNjdDpIdW50ZXIyRXhhbXBsZU5vdFJlYWw="
COOKIE_LINE = "[Http] Cookie: session_id=abc123exampleonlynotarealcookievalue0000; theme=dark"
SET_COOKIE_LINE = ("[Http] Set-Cookie: auth_token=ExampleOnlyNotARealTokenValue000000; "
                   "HttpOnly; Secure; SameSite=Lax")
PEM_BODY_LINE = "MIIEowIBAAKCAQEAxEXAMPLEONLYnotarealprivatekeymaterial0000000000"

VAULTED_CASES = [
    ("url userinfo password", URL_USERINFO, "svcacct:Hunter2Example"),
    ("aws secret access key", AWS_SECRET_LINE,
     "wJalrXUtnFEMIexampleKEYnotrealbPxRfiCYEXAMPLEKEY"),
    ("http basic credentials", BASIC_LINE, "c3ZjYWNjdDpIdW50ZXIyRXhhbXBsZU5vdFJlYWw="),
    ("cookie value", COOKIE_LINE, "abc123exampleonlynotarealcookievalue0000"),
    ("set-cookie value", SET_COOKIE_LINE, "ExampleOnlyNotARealTokenValue000000"),
    ("pem private key body line", PEM_BODY_LINE, PEM_BODY_LINE),
]


@pytest.mark.parametrize("name,line,value", VAULTED_CASES, ids=[c[0] for c in VAULTED_CASES])
def test_credential_is_found_and_typed_as_a_secret(name, line, value):
    from hider import pipeline

    assert covered(line, value), f"{name} not fully covered"
    claimed = {r.entity_type for r in R.analyze(line, REGS)
               if r.start < line.index(value) + len(value) and line.index(value) < r.end}
    assert any(pipeline._is_secret(t) for t in claimed), (
        f"{name} is claimed only as {claimed}, none of which is destroyed")


@pytest.mark.parametrize("name,line,value", VAULTED_CASES, ids=[c[0] for c in VAULTED_CASES])
def test_credential_is_destroyed_and_never_reaches_the_vault(name, line, value):
    """The property that actually failed in the field.

    Running the whole pipeline, not just the recognizers: the bug was that a
    *later* tier claimed what tier 1 had left, so a recognizer-level assertion
    would have passed while the vault still filled up with secrets.
    """
    from hider import pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    p = pipeline.Pipeline(vault=vault)
    out = p.redact(line)

    assert value not in out.text, f"{name} survived redaction"
    stored = [e["value"] for e in vault.entries.values()]
    assert value not in stored, f"{name} was written to the vault"
    # Not even a substantial fragment of it, under any label.
    for entry in stored:
        assert value[:16] not in entry and value[-16:] not in entry, \
            f"{name} fragment vaulted as {entry!r}"


def test_url_userinfo_destroys_the_username_too_and_keeps_the_host():
    """The service account name identifies as surely as the password authenticates.

    The host is deliberately still redacted-but-recoverable rather than
    destroyed, because "which endpoint was this" has to stay answerable.
    """
    from hider import pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(vault=vault).redact(URL_USERINFO)
    assert "svcacct" not in out.text
    assert "Hunter2Example" not in out.text
    assert "repo.contoso.internal" not in out.text
    assert "repo.contoso.internal" in [e["value"] for e in vault.entries.values()]


def test_cookie_attributes_survive_but_values_do_not():
    """Destroying the structure as well would make the line not worth keeping."""
    from hider import pipeline, pseudonym

    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(SET_COOKIE_LINE)
    assert "auth_token" in out.text
    assert "HttpOnly" in out.text and "Secure" in out.text and "SameSite" in out.text
    assert "ExampleOnlyNotARealTokenValue000000" not in out.text


def test_pem_markers_survive_so_the_removal_is_visible():
    from hider import pipeline, pseudonym

    block = ("-----BEGIN RSA PRIVATE KEY-----\n"
             f"{PEM_BODY_LINE}\n"
             "-----END RSA PRIVATE KEY-----")
    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(block)
    assert "BEGIN RSA PRIVATE KEY" in out.text
    assert "END RSA PRIVATE KEY" in out.text
    assert PEM_BODY_LINE not in out.text


def test_every_cookie_value_is_destroyed_not_just_the_session_one():
    """Deliberate over-destruction, stated rather than discovered.

    Cookie names are not a reliable signal: a session token is spelled
    ``session_id``, ``sid``, ``s``, ``_sess`` or anything else the framework
    chose, so a rule that only destroyed values with credential-looking names
    would miss the ones that matter. Every value goes, the names and
    attributes stay, and a harmless ``theme=dark`` is collateral the line can
    afford.
    """
    from hider import pipeline, pseudonym

    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(
        "[Http] Cookie: theme=dark; lang=en")
    assert "theme" in out.text and "lang" in out.text
    assert "dark" not in out.text and "=en" not in out.text


@pytest.mark.parametrize("line", [
    "[Feed] polling https://host:8443?token=a@b.example now",
    "[Feed] polling https://cdn.example.com/a/b?x=1 every 30 s",
    "[Note] The session cookie policy was reviewed with the customer.",
    "[Cfg] secret_access_key rotation is scheduled for Tuesday",
    "[Api] GET https://graph.microsoft.com/v1.0/users/anna.novak@contosocorp.com/messages",
    "[Repo] endpoint app01.contosocorp.internal reachable in 12 ms",
    "[Stats] processed 48123 items in 9124 ms across 12 shards",
])
def test_credential_rules_do_not_fire_on_ordinary_lines(line):
    """These rules claim whole values, so an over-match is expensive."""
    from hider import recognizers

    only_new = [recognizers.url_userinfo(), recognizers.http_credential_header(),
                recognizers.CookieHeaderRecognizer(), recognizers.AwsSecretKeyRecognizer(),
                recognizers.PrivateKeyBlockRecognizer()]
    found = [r for r in R.analyze(line, only_new)]
    assert not found, f"over-matched: {[line[r.start:r.end] for r in found]}"


def test_a_plain_address_is_still_pseudonymised_not_destroyed():
    """The userinfo rule must not swallow ordinary addresses next to a colon."""
    from hider import pipeline, pseudonym

    line = "[Mail] Notified anna.novak@contosocorp.com at 09:02 about the retry"
    vault = pseudonym.EntityVault(key=b"k")
    pipeline.Pipeline(vault=vault).redact(line)
    assert "anna.novak@contosocorp.com" in [e["value"] for e in vault.entries.values()]


# ---------------------------------------------------------------------------
# Windows and Microsoft identifiers. These identify a customer, so they are
# PSEUDONYMISED, never destroyed: correlation across lines is the point.
# Each one lives one step away from something that must survive - a well-known
# SID, a commit hash, a byte count - so the survival tests are as load-bearing
# as the catch tests.
# ---------------------------------------------------------------------------

MS_ID_CASES = [
    ("domain logon", "[Auth] Logon failure for FABRIKAM\\anna.novak from wks041",
     "FABRIKAM\\anna.novak", "DOMAIN_LOGON"),
    ("domain logon with dollar machine account",
     "[Auth] computer account FABRIKAM\\WKS041$ authenticated",
     "FABRIKAM\\WKS041$", "DOMAIN_LOGON"),
    ("domain sid",
     "[Auth] token for SID S-1-5-21-3623811015-3361044348-30300820-1013 issued",
     "S-1-5-21-3623811015-3361044348-30300820-1013", "WINDOWS_SID"),
    ("azure ad sid",
     "[Auth] cloud principal S-1-12-1-1234567890-1234567890-1234567890-1234567890 mapped",
     "S-1-12-1-1234567890-1234567890-1234567890-1234567890", "WINDOWS_SID"),
    ("certificate thumbprint",
     "[Cert] app-only auth with thumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 ok",
     "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", "CERT_THUMBPRINT"),
    ("onmicrosoft tenant domain",
     "[Dir] Tenant contosocorp.onmicrosoft.com verified",
     "contosocorp.onmicrosoft.com", "TENANT_DOMAIN"),
    ("onmicrosoft mail domain",
     "[Dir] initial domain contosocorp.mail.onmicrosoft.com set",
     "contosocorp.mail.onmicrosoft.com", "TENANT_DOMAIN"),
    ("support tracking id",
     "[Sup] Microsoft support trackingID#2609150040004419 opened",
     "2609150040004419", "SUPPORT_CASE_NUMBER"),
    ("formatted phone international",
     "[Note] Called the admin at +1 425 555 0147 and left a message",
     "+1 425 555 0147", "PHONE_NUMBER"),
    ("formatted phone dashed",
     "[Note] Callback requested on 425-555-0183 after 5pm",
     "425-555-0183", "PHONE_NUMBER"),
]


@pytest.mark.parametrize("name,line,value,label", MS_ID_CASES,
                         ids=[c[0] for c in MS_ID_CASES])
def test_ms_identifier_is_found_with_its_own_label(name, line, value, label):
    assert covered(line, value), f"{name} not fully covered"
    assert label in types_in(line)


@pytest.mark.parametrize("name,line,value,label", MS_ID_CASES,
                         ids=[c[0] for c in MS_ID_CASES])
def test_ms_identifier_is_pseudonymised_and_reversible(name, line, value, label):
    """The opposite contract from the credential group: these go INTO the vault.

    An identifier destroyed is correlation lost; the engineer must be able to
    detokenise the model's answer back to the real value.
    """
    from hider import pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(vault=vault).redact(line)
    assert value not in out.text, f"{name} survived"
    assert value in [e["value"] for e in vault.entries.values()], \
        f"{name} was not vaulted, so it is not reversible"


WELL_KNOWN_LINES = [
    "[Svc] Service runs as NT AUTHORITY\\SYSTEM, group BUILTIN\\Administrators",
    "[Svc] worker runs as NT SERVICE\\MSSQLSERVER on the default instance",
    "[Auth] added to group SID S-1-5-32-544 (well known)",
    "[Auth] LocalSystem is S-1-5-18, Everyone is S-1-1-0",
    "[Reg] value under SOFTWARE\\Policies updated",
    "[Reg] HKLM\\SYSTEM hive loaded read-only",
    "[Git] deployed commit 9fceb02d0ae598e95dc970b74767f19372d61af8 to prod",
    "[Svc] build 10.0.26100.1 loaded in 9124 ms",
    "[Stats] transferred 4255550147 bytes in 9124 ms across 12 shards",
]


@pytest.mark.parametrize("line", WELL_KNOWN_LINES)
def test_well_known_windows_constants_survive_whole(line):
    """Well-known SIDs, principals, commit hashes, versions and counts are the
    same for every customer or carry no identity; redacting them is the
    over-redaction that makes engineers stop using the tool."""
    from hider import pipeline, pseudonym

    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(line)
    assert out.text == line, f"over-redacted: {out.text!r}"


def test_domain_sid_pseudonym_keeps_the_rid_azure_sid_keeps_nothing():
    """RID 500 means 'the built-in Administrator' and a bare RID without its
    domain identifies nobody, so it stays. An Azure AD SID is the user's
    objectId in four dwords, so every dword goes."""
    from hider import pseudonym

    v = pseudonym.EntityVault(key=b"k")
    dom = v.pseudonym("WINDOWS_SID", "S-1-5-21-3623811015-3361044348-30300820-500")
    assert dom.endswith("-500") and "3623811015" not in dom
    cloud = v.pseudonym("WINDOWS_SID", "S-1-12-1-1234567890-1234567890-1234567890-1234567890")
    assert cloud.startswith("S-1-12-1-") and "1234567890" not in cloud


def test_tenant_domain_correlates_with_upn_and_site_url():
    """contoso.onmicrosoft.com, anna@contoso.com and the contoso SharePoint
    site must all map to the same tenant ordinal, or cross-line reasoning about
    one tenant silently becomes reasoning about three."""
    from hider import pseudonym

    v = pseudonym.EntityVault(key=b"k")
    upn = v.pseudonym("UPN_EMAIL", "anna.novak@contosocorp.com")
    dom = v.pseudonym("TENANT_DOMAIN", "contosocorp.onmicrosoft.com")
    assert upn.split("@")[1].split(".")[0] == dom.split(".")[0].replace("tenant-", "tenant-")
    assert dom.split(".")[0] == "tenant-" + upn.split("@tenant-")[1].split(".")[0]


def test_an_unformatted_digit_run_is_never_a_phone():
    """The declared gap, pinned: 'call 4255550147' is missed on purpose,
    because the same rule that caught it would redact byte counts."""
    from hider import recognizers

    reg = [recognizers.FormattedPhoneRecognizer()]
    assert R.analyze("[Note] call 4255550147 when the restore completes", reg) == []
    assert R.analyze("[Stats] case 07551234 closed after 8301 MB", reg) == []


def test_commit_hash_without_thumbprint_context_is_not_claimed():
    from hider import recognizers

    reg = [recognizers.CertThumbprintRecognizer()]
    assert R.analyze("deployed commit 9fceb02d0ae598e95dc970b74767f19372d61af8", reg) == []
    assert len(R.analyze("thumbprint 9fceb02d0ae598e95dc970b74767f19372d61af8", reg)) == 1


# ---------------------------------------------------------------------------
# The dotted-chain suppression: namespaces out, one-dot organisations in.
# Structural on purpose - a three-label floor rather than a vocabulary of
# namespace roots, because a vocabulary rots and a shape does not.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line,label", [
    ("[Worker] caught System.Net.Http.HttpRequestException after 30 ms", "HttpRequestException"),
    ("[Boot] loaded Microsoft.Extensions.Logging.Abstractions v8.0.0", "Abstractions"),
    ("[Worker] System.Collections.Generic.KeyNotFoundException at depth 4", "Collections"),
    ("[Boot] resolved Newtonsoft.Json.Serialization.DefaultContractResolver", "DefaultContractResolver"),
])
def test_namespace_labels_are_not_vaulted_as_organisations(line, label):
    """187 false spans over 145 of 1,000 clean lines before this rule, each one
    writing a .NET type name into the vault under ORG_NAME."""
    from hider import cli, pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(cli._build_tiers("classifier"), vault=vault).redact(line)
    assert out.text == line, f"namespace redacted: {out.text!r}"
    assert label not in [e["value"] for e in vault.entries.values()]


def test_one_dot_organisations_are_still_claimed():
    """The floor is three labels precisely so this keeps working. Tier 2 catches
    these only in part today (see the dotted-org head-leak gap); the property
    pinned here is that the suppression does not take the catch away."""
    from hider import cli, pipeline, pseudonym

    p = pipeline.Pipeline(cli._build_tiers("classifier"), vault=pseudonym.EntityVault(key=b"k"))
    for line in ["Contract held by Tailspin.Industries since March",
                 "Escalated to Acme.Holdings for review",
                 "Invoice from Fabrikam.Group received"]:
        assert p.redact(line).text != line, f"org lost to the namespace rule: {line!r}"


def test_dotted_chain_floor_is_structural_not_a_vocabulary():
    """A namespace nobody put on a list is still a namespace."""
    from hider import pipeline

    ns = "Contoso.Backup.Agent.RetryHandler"
    line = f"[Worker] {ns} gave up"
    assert pipeline.in_dotted_chain(line, line.index("RetryHandler"),
                                   line.index("RetryHandler") + len("RetryHandler"))
    org = "Wood.Partners"
    line2 = f"Escalated to {org} for review"
    assert not pipeline.in_dotted_chain(line2, line2.index("Partners"),
                                        line2.index("Partners") + len("Partners"))


def test_a_space_ends_the_chain():
    """"Wood.Partners Ltd" is a two-label chain, not a three-label namespace."""
    from hider import pipeline

    line = "Escalated to Wood.Partners Ltd for review"
    start = line.index("Partners Ltd")
    assert not pipeline.in_dotted_chain(line, start, start + len("Partners Ltd"))


def test_declared_misses_of_the_dotted_chain_floor():
    """Both sides of the floor, pinned so a future change has to face them.

    Two labels is below the floor and still vaults; three labels is above it
    and suppresses an organisation. Both are documented adversarial cases.
    """
    from hider import cli, pipeline, pseudonym

    p = pipeline.Pipeline(cli._build_tiers("classifier"), vault=pseudonym.EntityVault(key=b"k"))
    two = "[Worker] threw Newtonsoft.JsonSerializationException at depth 3"
    assert p.redact(two).text != two, "declared miss changed; update the adversarial case"
    three = "Escalated to Wood.Partners.Group for review"
    assert p.redact(three).text == three, "declared miss changed; update the adversarial case"


def test_backslash_suppression_is_tier2_wide_not_principal_specific():
    """The rule is 'a token straight after a backslash is structure, not
    prose', so it must hold for any capitalised token there, not only the
    well-known principals."""
    from hider import pipeline, pseudonym

    line = "[Reg] exporting WORKGROUP\\Contoso settings for review"
    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(line)
    # The whole logon is tier 1's (WORKGROUP is not well-known); the point is
    # that tier 2 must not have claimed the bare word "Contoso" on its own.
    spans2 = [s for s in out.spans if s.tier == "tier2"]
    assert not spans2, f"tier 2 claimed {spans2}"


# ---------------------------------------------------------------------------
# URLs, paths and Azure resources: identifiers, pseudonymised and reversible.
# The fences matter as much as the catches: vendor hosts stay readable, and
# the space-tolerant URL tail must never swallow prose.
# ---------------------------------------------------------------------------

SPACE_URL = ("[Restore] target https://contosocorp.sharepoint.com/sites/Finance/"
             "Shared Documents/Q3 support plans.xlsx restored")
PERSONAL_PATH = "[Sync] item /personal/anna_novak_contosocorp_com/Documents/Reviews queued"
KV_URL = ("[KV] fetching https://fabrikam-prod-kv.vault.azure.net/secrets/"
          "sql-conn-primary/9f2c1a8b3d7e4f60 took 41 ms")
EXCH_ITEM = ("AAMkADY2YmZhNjdkLTM4MWEtNGUzMi1hYmMwLWZlODc5MzE1NDc1MABGAAAAAAB3"
             "EXAMPLEONLYnotreal0000AAA=")
EXCH_FOLDER = "AQMkADY2YmZhNjdkEXAMPLEONLYfolder0000000000="

URL_PATH_CASES = [
    ("space in document path", SPACE_URL,
     "https://contosocorp.sharepoint.com/sites/Finance/Shared Documents/Q3 support plans.xlsx",
     "SITE_URL"),
    ("onedrive personal identity segment", PERSONAL_PATH,
     "anna_novak_contosocorp_com", "ONEDRIVE_ACCOUNT"),
    ("key vault url", KV_URL,
     "https://fabrikam-prod-kv.vault.azure.net/secrets/sql-conn-primary/9f2c1a8b3d7e4f60",
     "AZURE_KEY_VAULT"),
    ("bare key vault host", "[KV] endpoint fabrikam-prod-kv.vault.azure.net reachable",
     "fabrikam-prod-kv.vault.azure.net", "AZURE_KEY_VAULT"),
    ("exchange item id", f"[Mail] moved item {EXCH_ITEM} ok", EXCH_ITEM, "EXCHANGE_ITEM_ID"),
    ("exchange folder id", f"[Mail] into folder {EXCH_FOLDER} ok", EXCH_FOLDER, "EXCHANGE_ITEM_ID"),
]


@pytest.mark.parametrize("name,line,value,label", URL_PATH_CASES,
                         ids=[c[0] for c in URL_PATH_CASES])
def test_url_path_identifier_is_found(name, line, value, label):
    assert covered(line, value), f"{name} not fully covered"
    assert label in types_in(line)


@pytest.mark.parametrize("name,line,value,label", URL_PATH_CASES,
                         ids=[c[0] for c in URL_PATH_CASES])
def test_url_path_identifier_is_pseudonymised_and_reversible(name, line, value, label):
    from hider import pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(vault=vault).redact(line)
    assert value not in out.text, f"{name} survived"
    assert value in [e["value"] for e in vault.entries.values()], \
        f"{name} not vaulted, so not reversible"


def test_space_tail_never_swallows_prose_after_a_url():
    """The two fences: a path separator in the tail, and a document extension.

    Prose after a URL has neither ("... is 91% full") or only the extension
    ("... from archive backup.zip" has no slash), so it survives whole.
    """
    from hider import pipeline, pseudonym

    p = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    out = p.redact("[Restore] https://contosocorp.sharepoint.com/sites/Finance is 91% full")
    assert out.text.endswith("is 91% full")
    out = p.redact("[Restore] https://contosocorp.sharepoint.com/sites/Finance from archive backup.zip")
    assert out.text.endswith("from archive backup.zip")


def test_space_tail_final_segment_gap_is_the_declared_one():
    """A space-separated file name in the FINAL segment has no further slash,
    so only its first word is covered. Pinned so the gap stays declared."""
    line = "[Restore] https://contosocorp.sharepoint.com/sites/Finance/Q3 plans.xlsx restored"
    assert covered(line, "https://contosocorp.sharepoint.com/sites/Finance/Q3")
    assert not covered(line, "https://contosocorp.sharepoint.com/sites/Finance/Q3 plans.xlsx")


def test_vendor_hosts_stay_readable():
    """graph.microsoft.com and login.microsoftonline.com are the same for
    every customer; an engineer must still see which endpoint was involved."""
    from hider import pipeline, pseudonym

    p = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k"))
    for line in [
        "[Rest] GET https://graph.microsoft.com/v1.0/me/messages returned 200",
        "[Auth] token from login.microsoftonline.com for the app ok",
        "[Api] endpoint outlook.office365.com reachable",
    ]:
        out = p.redact(line)
        assert out.text == line, f"vendor host redacted: {out.text!r}"


def test_exchange_id_alone_on_a_line_is_destroyed_not_leaked():
    """The declared trade from the adversarial case: the bare-base64-line rule
    wins and destroys. Correlation lost, nothing leaked, nothing vaulted."""
    from hider import pipeline, pseudonym

    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(vault=vault).redact(EXCH_ITEM)
    assert EXCH_ITEM not in out.text
    assert EXCH_ITEM not in [e["value"] for e in vault.entries.values()]


def test_onedrive_pseudonym_keeps_the_path_structure():
    from hider import pipeline, pseudonym

    out = pipeline.Pipeline(vault=pseudonym.EntityVault(key=b"k")).redact(PERSONAL_PATH)
    assert "/personal/user-01/Documents/Reviews" in out.text
    assert "anna" not in out.text


def test_two_secrets_from_one_vault_stay_colocated():
    from hider import pseudonym

    v = pseudonym.EntityVault(key=b"k")
    a = v.pseudonym("AZURE_KEY_VAULT", "https://fabrikam-prod-kv.vault.azure.net/secrets/sql-conn/1")
    b = v.pseudonym("AZURE_KEY_VAULT", "https://fabrikam-prod-kv.vault.azure.net/secrets/smtp-pass/2")
    assert a != b
    assert a.split("/secrets/")[0] == b.split("/secrets/")[0], \
        "same vault must map to the same vault pseudonym"


# ---------------------------------------------------------------------------
# Customer domains in the open namespace: allowlist-of-vendors, fail toward
# redaction, firing in prose as well as host positions. The lookalikes that
# must survive carry as much weight as the catches, and the same lookalikes
# sit in the generated clean corpus so the false-redaction figure measures
# them on every eval run.
# ---------------------------------------------------------------------------

CUSTOMER_DOMAIN_CASES = [
    ("host position", "[Backup] repository backup.fabrikamedu.org unreachable",
     "backup.fabrikamedu.org"),
    ("bare registrable domain in prose",
     "Mail for fabrikamedu.org is routed through the proxy.", "fabrikamedu.org"),
    ("ccTLD second-level suffix",
     "[Net] peer sql01.ops.woodgrove-trading.co.uk registered",
     "sql01.ops.woodgrove-trading.co.uk"),
    ("customer tenant on a vendor suffix",
     "[Chat] notified contoso-workspace.slack.com channel", "contoso-workspace.slack.com"),
]


@pytest.mark.parametrize("name,line,value", CUSTOMER_DOMAIN_CASES,
                         ids=[c[0] for c in CUSTOMER_DOMAIN_CASES])
def test_customer_domain_is_found_and_reversible(name, line, value):
    from hider import pipeline, pseudonym

    assert covered(line, value), f"{name} not fully covered"
    vault = pseudonym.EntityVault(key=b"k")
    out = pipeline.Pipeline(vault=vault).redact(line)
    assert value not in out.text
    assert value in [e["value"] for e in vault.entries.values()]


@pytest.mark.parametrize("line", [
    "   at Backup.Proxy.SessionWorker.Run() in /src/SessionWorker.cs:line 214",
    "[Worker] caught System.Net.Sockets.SocketException after 30 ms",
    "[Rotate] archived backup.log and metrics.csv, wrote summary.xlsx",
    "[Deploy] running main.py and helper.ps1 from the tools folder",
    "The retry fired twice.then the queue drained, no action needed.",
    "[Pkg] verified installer.msi and agent.tar.gz checksums",
    "[Auth] token endpoint login.microsoftonline.com responded in 41 ms",
    "[Rest] docs at learn.microsoft.com and graph.microsoft.com reachable",
])
def test_customer_domain_lookalikes_survive(line):
    """Namespaces, file names, missing-space typos and vendor hosts: the four
    shapes most likely to masquerade as a customer domain, pinned here and
    seeded in the clean corpus so the eval measures them forever."""
    from hider import recognizers

    found = R.analyze(line, [recognizers.CustomerDomainRecognizer()])
    assert not found, f"over-matched: {[line[r.start:r.end] for r in found]}"


def test_vendor_pair_model_not_bare_suffix():
    """api.slack.com is the vendor; contoso.slack.com is a customer. And the
    label-aligned suffix check closes the old notmicrosoft.com hole."""
    from hider import vendors

    assert vendors.is_vendor_host("api.slack.com")
    assert vendors.is_vendor_host("graph.microsoft.com")
    assert vendors.is_vendor_host("login.microsoftonline.com")
    assert not vendors.is_vendor_host("contoso-workspace.slack.com")
    assert not vendors.is_vendor_host("evil.notmicrosoft.com")
    assert not vendors.is_vendor_host("slack.com")  # bare suffix decides nothing


def test_customer_domain_pseudonym_keeps_the_tld():
    from hider import pseudonym

    v = pseudonym.EntityVault(key=b"k")
    org = v.pseudonym("CUSTOMER_DOMAIN", "backup.fabrikamedu.org")
    assert org.endswith(".example.org") and "fabrikamedu" not in org
    uk = v.pseudonym("CUSTOMER_DOMAIN", "sql01.ops.woodgrove-trading.co.uk")
    assert uk.endswith(".example.co.uk") and "woodgrove" not in uk


def test_customer_domain_correlates_with_upn_tenant():
    """backup.fabrikamedu.org and anna@fabrikamedu.org are one tenant."""
    from hider import pseudonym

    v = pseudonym.EntityVault(key=b"k")
    upn = v.pseudonym("UPN_EMAIL", "anna.novak@fabrikamedu.org")
    host = v.pseudonym("CUSTOMER_DOMAIN", "backup.fabrikamedu.org")
    upn_tenant = upn.split("@")[1].split(".")[0]
    host_tenant = [p for p in host.split(".") if p.startswith("tenant-")][0]
    assert upn_tenant == host_tenant


def test_jsonscrub_and_recognizers_share_one_vendor_judgement():
    """The point of hider.vendors: the two paths cannot drift."""
    from hider import jsonscrub, recognizers, vendors

    assert jsonscrub._FILE_EXT is recognizers.FILE_EXT
    assert jsonscrub._vendors is vendors


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


# ---------------------------------------------------------------------------
# Zero-padded IPv4. Was a documented tier 1 gap: Presidio's regex matched the
# quad and its validator then rejected it, because Python's ipaddress refuses
# leading zeros. A narrow recognizer now covers the padded shape only.
# ---------------------------------------------------------------------------

def test_zero_padded_ipv4_is_the_custom_set_not_stock():
    """Stock Presidio still drops it, so the eval's baseline is still stock."""
    line = "[Net] peer 010.020.030.040 reset the connection"
    assert "IP_ADDRESS" not in {r.entity_type for r in R.analyze(line, R.builtins())}
    assert covered(line, "010.020.030.040")


def test_zero_padded_recognizer_leaves_plain_quads_to_stock():
    reg = [R.zero_padded_ipv4()]
    assert R.analyze("peer 10.20.30.40 reset", reg) == []
    assert len(R.analyze("peer 10.20.030.40 reset", reg)) == 1


@pytest.mark.parametrize("line", [
    "[Service] Build 8.01.0.7 loaded",
    "[Agent] agent 08.0.0.101 connected",
])
def test_zero_padded_version_numbers_are_not_addresses(line):
    assert "IP_ADDRESS" not in types_in(line)


@pytest.mark.parametrize("line", [
    "[Stats] 01.02.2026 completed 300 items",
    "[Net] peer 010.020.030.0400 odd",
    "[Net] peer 010.020.030.256 out of range",
])
def test_zero_padded_pattern_does_not_over_match(line):
    assert "IP_ADDRESS" not in types_in(line)


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
    for i, line in enumerate(wrapped.split("\n")):
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
