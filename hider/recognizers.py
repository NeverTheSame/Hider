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

from . import entities
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
    return PatternRecognizer(
        supported_entity="JWT",
        name="JwtRecognizer",
        patterns=[
            Pattern(
                name="jwt",
                regex=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                score=0.95,
            ),
        ],
        context=["bearer", "authorization", "token"],
    )


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
        SupportCaseRecognizer(),
    ]


def all_recognizers(*, include_builtins: bool = True) -> list[LocalRecognizer]:
    """The tier 1 registry.

    ``include_builtins=False`` gives the custom-only registry, which the eval
    harness uses to measure what the domain-specific recognizers add over stock
    Presidio patterns.
    """
    regs: list[LocalRecognizer] = list(custom())
    if include_builtins:
        regs = builtins() + regs
    return regs


def analyze(text: str, recognizers: list[LocalRecognizer]) -> list[RecognizerResult]:
    """Run every recognizer over one string, no NLP engine involved."""
    out: list[RecognizerResult] = []
    for rec in recognizers:
        # A broken recognizer must not silently drop coverage, so nothing is
        # caught here. The pipeline decides what a tier failure means.
        out.extend(rec.analyze(text, entities=rec.supported_entities, nlp_artifacts=None))
    return suppress(text, out)

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

