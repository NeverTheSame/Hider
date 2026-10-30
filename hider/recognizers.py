"""Tier 1 detection: Presidio pattern recognizers, including custom domain ones.

Written against the contract in ``entities.py``, not derived from it. The
patterns here describe how a value is FOUND in arbitrary text, which is a
different problem from how a value is FORMED: a formation rule can assume clean
context, a detection rule cannot.

Tier 1 runs standalone, with no NLP engine. Presidio's ``PatternRecognizer``
supports that directly (``nlp_artifacts=None``), which matters for two reasons:
the sync proxy path has a latency budget of tens of milliseconds, and tier 1 is
the cost gate that must clear the bulk of shaped tokens before any paid tier is
consulted.
"""

from __future__ import annotations

import re

from . import entities, profiles
from presidio_analyzer import (
    LocalRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)
from presidio_analyzer.predefined_recognizers import (
    EmailRecognizer,
    IpRecognizer,
)

TIER1 = "tier1"

# ---------------------------------------------------------------------------
# Custom domain recognizers
# ---------------------------------------------------------------------------

_GUID_CORE = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def upn_email() -> PatternRecognizer:
    """User principal names, including inside URL paths.

    Presidio's stock EmailRecognizer misses these. Its local-part character
    class allows a forward slash, so on ``GET /users/anna.novak@contoso.com/
    mailFolders`` it matches from ``/users/`` onward, and its tldextract-based
    validation then rejects the over-long match and drops the result entirely.
    A UPN inside a Graph URL is one of the most common ways a mailbox owner
    appears in a service log, so that is not an acceptable gap. This recognizer
    uses a tighter local part and no external validation.

    The stock recognizer is kept alongside it: where it does fire it fires at
    higher confidence, and overlap resolution keeps whichever span is safest.
    """
    return PatternRecognizer(
        supported_entity="UPN_EMAIL",
        name="UpnEmailRecognizer",
        patterns=[
            Pattern(
                name="upn",
                regex=(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"
                       r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})"
                       r"(?:\.[A-Za-z0-9-]{1,63})+"),
                score=0.85,
            ),
        ],
        context=["user", "mailbox", "upn", "owner", "recipient"],
    )


def any_guid() -> PatternRecognizer:
    """Any GUID: session, tenant, mailbox and site-collection ids share a shape.

    A detector cannot honestly separate them from the token alone, so one label
    covers all three and the scoring treats that as a correct typed catch. The
    context words below let Presidio raise confidence when the surrounding text
    names the kind of id, without pretending to relabel it.
    """
    return PatternRecognizer(
        supported_entity="GUID",
        name="GuidRecognizer",
        patterns=[
            Pattern(name="guid-braced", regex=r"\{" + _GUID_CORE + r"\}", score=0.9),
            Pattern(name="guid", regex=_GUID_CORE, score=0.85),
            # No dashes: some components log GUIDs in "N" format.
            Pattern(name="guid-n", regex=r"\b[0-9a-fA-F]{32}\b", score=0.5),
        ],
        context=["session", "tenant", "mailbox", "site", "job", "id", "guid"],
    )


def worker_pod_id() -> PatternRecognizer:
    """Worker proxy pods and agents, e.g. wkr-amer-prx117, wkr-emea-rg124."""
    return PatternRecognizer(
        supported_entity="WORKER_POD_ID",
        name="WorkerPodIdRecognizer",
        patterns=[
            Pattern(
                name="pod",
                # Region list stays open on purpose: a new region must not
                # silently become a detection gap.
                regex=r"\bwkr-[a-z]{3,6}-(?:prx|rg|node)\d{1,4}\b",
                score=0.9,
            ),
        ],
        context=["pod", "proxy", "worker", "agent"],
    )


def service_instance_id() -> PatternRecognizer:
    """Service instances, e.g. svc-prod-cus-001."""
    return PatternRecognizer(
        supported_entity="SERVICE_INSTANCE_ID",
        name="ServiceInstanceIdRecognizer",
        patterns=[
            Pattern(name="svc", regex=r"\bsvc-[a-z]{3,6}-[a-z]{2,8}-\d{1,4}\b", score=0.9),
        ],
        context=["service", "instance", "svc"],
    )


def tenant_site_url() -> PatternRecognizer:
    """URLs on SaaS hosts whose subdomain is the customer's tenant name.

    The subdomain is the sensitive part, and the path is often nearly as bad: a
    site called ``Legal`` or ``HR-Records`` tells the reader what the customer
    was doing. Both go.

    The host list comes from the entity spec rather than being hard-coded here,
    so adding a vendor is a one-line change in one place.
    """
    hosts = "|".join(h.replace(".", r"\.") for h in entities.TENANT_SITE_HOSTS)
    return PatternRecognizer(
        supported_entity="SITE_URL",
        name="TenantSiteRecognizer",
        patterns=[
            Pattern(
                name="tenant-site",
                regex=rf"https?://[A-Za-z0-9-]{{1,63}}(?:-my)?\.(?:{hosts})"
                      rf"(?:/[^\s\"'<>,;)\]]*)?",
                score=0.9,
            ),
            # Bare host with no scheme still identifies the tenant.
            Pattern(name="tenant-host",
                    regex=rf"\b[A-Za-z0-9-]{{1,63}}\.(?:{hosts})\b", score=0.8),
        ],
        context=["site", "tenant", "workspace", "target"],
    )


def presigned_url() -> PatternRecognizer:
    """Pre-signed storage URL. A live credential, so it is destroyed."""
    return PatternRecognizer(
        supported_entity="PRESIGNED_URL",
        name="PresignedUrlRecognizer",
        patterns=[
            Pattern(
                name="sas",
                regex=(r"https?://[A-Za-z0-9.-]+\.(?:blob|file|queue|table|dfs)"
                       r"\.core\.windows\.net/[^\s\"'<>]*[?&]s(?:ig|v)=[^\s\"'<>]+"),
                score=0.95,
            ),
            # A signature parameter alone is enough: the grant is the secret.
            Pattern(name="sas-sig", regex=r"[?&]sig=[A-Za-z0-9%+/_-]{20,}={0,2}", score=0.8),
        ],
        context=["sas", "signature", "blob", "upload"],
    )


def connection_string() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="CONNECTION_STRING",
        name="ConnectionStringRecognizer",
        patterns=[
            Pattern(
                name="conn",
                regex=(r"(?:DefaultEndpointsProtocol|AccountName|AccountKey|"
                       r"SharedAccessSignature|Server|Data Source|Password|Pwd)"
                       r"=[^\s\"']*(?:;[^\s\"';]+)*"),
                score=0.9,
            ),
            Pattern(name="accountkey", regex=r"AccountKey=[A-Za-z0-9+/=_-]{20,}", score=0.95),
        ],
        context=["connection", "storage", "account"],
    )


def jwt() -> PatternRecognizer:
    """Bearer credentials, including the fragments a three-part pattern misses.

    A JWT that has been wrapped, truncated or split across lines is still a
    credential, and the naive ``a.b.c`` pattern does not match any of those
    forms. Three patterns instead of one:

    * the full compact serialisation, header.payload.signature;
    * a two-segment head, header.payload with the signature elsewhere, which is
      what a wrapped log line leaves behind and which still carries the claims;
    * whatever follows ``Bearer``, whatever shape it is, because the position
      is the evidence: a token in an Authorization header is a credential even
      when it is not a JWT at all.

    A continuation fragment on its own line is handled by
    ``ContinuationFragmentRecognizer``, which needs line anchoring the pattern
    engine here cannot express.
    """
    return PatternRecognizer(
        supported_entity="JWT",
        name="JwtRecognizer",
        patterns=[
            Pattern(
                name="jwt",
                regex=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                score=0.95,
            ),
            # Header.payload with no signature: a split or truncated token.
            Pattern(
                name="jwt-head",
                regex=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                score=0.9,
            ),
            # Anything presented as a bearer credential. Fixed-width lookbehind
            # keeps the span on the credential and off the word "Bearer".
            Pattern(
                name="bearer-value",
                regex=r"(?<=[Bb]earer )[A-Za-z0-9._~+/=-]{10,}",
                score=0.9,
            ),
        ],
        context=["bearer", "authorization", "token"],
    )


class ContinuationFragmentRecognizer(LocalRecognizer):
    """A base64url fragment alone on a line, the tail of a split credential.

    Log lines get wrapped by editors, ticket systems and mail clients. The tail
    of a split token has no internal structure to match: it is just a long
    base64url run, usually opened by the dot that used to join it to its
    payload. Anchoring to the line is what makes it safe to match at all, and
    line anchoring is what Presidio's pattern engine cannot express here.
    """

    FRAGMENT = re.compile(r"(?m)^[ \t]*(\.[A-Za-z0-9_-]{20,})[ \t]*$")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["JWT"],
            name="ContinuationFragmentRecognizer",
            context=["bearer", "authorization", "token", "continued"],
        )
        self.supported_entity = "JWT"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        return [
            RecognizerResult(entity_type=self.supported_entity, start=m.start(1),
                             end=m.end(1), score=0.85, analysis_explanation=None)
            for m in self.FRAGMENT.finditer(text)
        ]


def api_key() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="API_KEY",
        name="ApiKeyRecognizer",
        patterns=[
            Pattern(name="prefixed", regex=r"\b(?:sk|ak|vk|pk)-[A-Za-z0-9_-]{20,}\b", score=0.9),
        ],
        context=["key", "secret", "clientsecret", "apikey"],
    )


def windows_user_path() -> PatternRecognizer:
    """Profile paths carry an account name inside the path."""
    return PatternRecognizer(
        supported_entity="WINDOWS_USER_PATH",
        name="WindowsUserPathRecognizer",
        patterns=[
            Pattern(
                name="profile",
                regex=r"[A-Za-z]:\\Users\\[^\\\s\"'<>|]+(?:\\[^\s\"'<>|]*)*",
                score=0.85,
            ),
            Pattern(name="unc-home", regex=r"\\\\[A-Za-z0-9.-]+\\users?\$?\\[^\s\"'<>|]+", score=0.8),
        ],
        context=["path", "cache", "export", "profile"],
    )


def hostname_fqdn() -> PatternRecognizer:
    """Internal hostnames. Narrow on purpose: broad FQDN matching over-redacts.

    Shared API endpoints of the SaaS providers a service talks to carry no
    customer information, and destroying them costs real triage value, so they
    are excluded rather than matched and forgiven.
    """
    return PatternRecognizer(
        supported_entity="HOSTNAME_FQDN",
        name="InternalHostnameRecognizer",
        patterns=[
            Pattern(
                name="internal-tld",
                regex=r"\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9-]{1,63})*"
                      r"\.(?:internal|local|lan|corp|intra|ad)\b",
                score=0.85,
            ),
        ],
        context=["host", "endpoint", "server", "repository"],
    )


_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"


def zero_padded_ipv4() -> PatternRecognizer:
    """IPv4 with zero-padded octets, as some loggers emit (``010.020.030.040``).

    Presidio's stock ``IpRecognizer`` regex matches these, then throws the
    match away: its validator runs ``ipaddress.ip_interface`` and Python
    rejects leading zeros as ambiguous octal. This recognizer only fires when
    at least one octet is padded, so plain dotted quads stay the stock
    recognizer's job and the eval's stock baseline stays stock. It emits the
    same ``IP_ADDRESS`` label, so the version-number suppression and the
    IPv4/IPv6 pseudonym split apply to it unchanged.
    """
    return PatternRecognizer(
        supported_entity="IP_ADDRESS",
        name="ZeroPaddedIpv4Recognizer",
        patterns=[
            Pattern(
                name="ipv4-zero-padded",
                regex=r"\b(?=[\d.]*\b0\d)" + _IPV4_OCTET + r"(?:\." + _IPV4_OCTET + r"){3}\b",
                score=0.6,
            ),
        ],
        context=["ip", "ipv4", "peer", "address"],
    )


class SupportCaseRecognizer(LocalRecognizer):
    """Eight-digit case number.

    The shape alone is far too weak to redact on: eight digits also spell item
    counts and byte offsets, and redacting those would gut the bundle. So this
    recognizer only fires when a case-referencing word precedes the digits, and
    it reports a span covering the digits alone, not the surrounding phrase.
    Presidio's pattern engine cannot express that (Python ``re`` has no
    variable-length lookbehind and no ``\\K``), so the span is narrowed here.
    """

    PHRASE = re.compile(
        r"(?i)\b(?:case|ticket|sr|incident)\s*(?:number|no\.?|#)?\s*:?\s*(\d{8})\b"
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["SUPPORT_CASE_NUMBER"],
            name="SupportCaseRecognizer",
            context=["case", "ticket", "support", "escalation"],
        )
        self.supported_entity = "SUPPORT_CASE_NUMBER"

    def load(self) -> None:  # required by EntityRecognizer, nothing to load
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        return [
            RecognizerResult(
                entity_type=self.supported_entity,
                start=m.start(1),
                end=m.end(1),
                score=0.7,
                analysis_explanation=None,
            )
            for m in self.PHRASE.finditer(text)
        ]


#: Presidio built-ins reused verbatim. Reuse over reimplementation: these two
#: are pattern-based and run without an NLP engine, exactly like the custom set.
def builtins() -> list[PatternRecognizer]:
    return [EmailRecognizer(), IpRecognizer()]


def custom() -> list[LocalRecognizer]:
    return [
        upn_email(),
        any_guid(),
        worker_pod_id(),
        service_instance_id(),
        tenant_site_url(),
        presigned_url(),
        connection_string(),
        jwt(),
        api_key(),
        windows_user_path(),
        hostname_fqdn(),
        zero_padded_ipv4(),
        SupportCaseRecognizer(),
        ContinuationFragmentRecognizer(),
    ]


def profile_recognizers(profile: profiles.SiteProfile | None) -> list[LocalRecognizer]:
    """Recognizers built from a site profile's patterns.

    These are additive only: they join the registry alongside the built-ins and
    are subject to the same overlap resolution, so a profile can widen coverage
    and can never narrow it.
    """
    if profile is None:
        return []
    out: list[LocalRecognizer] = []
    for label, items in sorted(profile.patterns.items()):
        out.append(
            PatternRecognizer(
                supported_entity=label,
                name=f"Profile[{profile.name}]:{label}",
                patterns=[
                    Pattern(name=f"profile-{label.lower()}-{i}", regex=regex, score=score)
                    for i, (regex, score) in enumerate(items)
                ],
            )
        )
    return out


def all_recognizers(
    *,
    include_builtins: bool = True,
    profile: profiles.SiteProfile | None = None,
    use_active_profile: bool = True,
) -> list[LocalRecognizer]:
    """The tier 1 registry.

    ``include_builtins=False`` gives the custom-only registry, which the eval
    harness uses to measure what the domain-specific recognizers add over stock
    Presidio patterns.

    A site profile is picked up from ``HIDER_PROFILE`` automatically. That is
    deliberate: a control you have to remember to enable is a control that gets
    forgotten on the busy day. Pass ``use_active_profile=False`` to measure the
    repository's own baseline behaviour without it, which is what the eval does
    so its committed numbers stay reproducible on any machine.
    """
    regs: list[LocalRecognizer] = list(custom())
    if include_builtins:
        regs = builtins() + regs
    if profile is None and use_active_profile:
        profile = profiles.active()
    regs = regs + profile_recognizers(profile)
    return regs


def analyze(text: str, recognizers: list[LocalRecognizer]) -> list[RecognizerResult]:
    """Run every recognizer over one string, no NLP engine involved."""
    out: list[RecognizerResult] = []
    for rec in recognizers:
        # A broken recognizer must not silently drop coverage, so nothing is
        # caught here. The pipeline decides what a tier failure means.
        out.extend(rec.analyze(text, entities=rec.supported_entities, nlp_artifacts=None))
    return refine(text, suppress(text, out))

# ---------------------------------------------------------------------------
# Suppression: the precision half of the job
# ---------------------------------------------------------------------------

#: Words that, immediately before a dotted-quad, mean it is a version number
#: rather than an address. Stock IP matching flags "Build 8.1.0.7", and an
#: engineer who finds their build numbers redacted stops using the tool. That
#: is the failure mode this list exists to prevent.
_VERSION_CONTEXT = re.compile(
    r"(?i)\b(?:build|version|ver|rev|assembly|release|schema|sdk|runtime|"
    r"framework|agent|product)\b[\s:=v#]*$"
)

#: Shared provider endpoints. They identify the SaaS vendor, not a customer,
#: and destroying them costs real triage value for no privacy gain. Note the
#: contrast with TENANT_SITE_HOSTS: there the subdomain IS the customer, here
#: the whole host is the same for every customer on earth.
_PUBLIC_HOSTS = re.compile(
    r"(?i)\b(?:outlook\.office365\.com|outlook\.office\.com|graph\.microsoft\.com|"
    r"login\.microsoftonline\.com|login\.windows\.net|management\.azure\.com|"
    r"api\.slack\.com|www\.googleapis\.com|sts\.amazonaws\.com|api\.github\.com)\b"
)


#: What a GUID is, when the surrounding text says so. Every GUID is the same
#: 36 characters, so a detector cannot type one from the token alone. It can
#: read the word in front of it, and that is worth doing: a pseudonym that
#: calls a tenant id "Session-02" invites a model to reason about two sessions
#: where there is one session and one tenant.
_GUID_KINDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(?:tenant|directory|organisation|organization|customer)\b"
                r"(?:\W{0,4}(?:id|guid|uuid)\b)?\W{0,14}$"), "TENANT_ID"),
    (re.compile(r"(?i)\b(?:session|job|run|execution|task|activity)\b"
                r"(?:\W{0,4}(?:id|guid|uuid)\b)?\W{0,14}$"), "SESSION_GUID"),
    (re.compile(r"(?i)\b(?:mailbox|item|object|site|collection|folder|user|drive)\b"
                r"(?:\W{0,4}(?:id|guid|uuid)\b)?\W{0,14}$"), "OBJECT_GUID"),
)


def refine(text: str, results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Relabel a bare GUID when its context names what kind of id it is.

    Only the label changes, never the span, so this cannot alter coverage in
    either direction. An unrecognised context leaves the generic ``GUID``
    label, which is the honest answer rather than a guess: the pseudonym for it
    reads ``<Guid-07>`` and asserts nothing.
    """
    out: list[RecognizerResult] = []
    for r in results:
        if r.entity_type != "GUID":
            out.append(r)
            continue
        before = text[max(0, r.start - 48):r.start]
        label = "GUID"
        for rx, kind in _GUID_KINDS:
            if rx.search(before):
                label = kind
                break
        out.append(
            RecognizerResult(entity_type=label, start=r.start, end=r.end,
                             score=r.score, analysis_explanation=r.analysis_explanation)
        )
    return out


def suppress(text: str, results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Drop matches that context shows to be harmless.

    Every rule here is a deliberate, named exception, not a confidence tweak.
    Suppression is the one place in the engine that removes protection, so it
    is kept small, explicit, and covered by its own tests.
    """
    kept: list[RecognizerResult] = []
    for r in results:
        value = text[r.start:r.end]
        if r.entity_type == "IP_ADDRESS" and ":" not in value:
            if _VERSION_CONTEXT.search(text[max(0, r.start - 40):r.start]):
                continue
        if r.entity_type in {"HOSTNAME_FQDN", "SITE_URL", "URL"}:
            if _PUBLIC_HOSTS.fullmatch(value):
                continue
        kept.append(r)
    return kept

