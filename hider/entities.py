"""Entity specification for Hider.

This module is the CONTRACT. It is written FIRST, from public
documentation, public knowledge-base article shapes and the sanitize-at-source
templates in ``templates/``. It describes how a sensitive value is FORMED, so the generator
can synthesise realistic examples.

It deliberately does NOT describe how a value is FOUND. Detection patterns live
in ``recognizers.py`` and were written against this document, not copied from
it. That separation is what keeps the recall numbers from being circular: the
generator and the recognizers are two implementations of one spec, the way two
teams working from one interface contract would be.

Known limitation, stated openly in the writeup: one person wrote both sides, so
independence is procedural rather than organisational. The adversarial corpus in
``adversarial.py`` exists to attack that weakness directly.
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Handling classes
# ---------------------------------------------------------------------------

#: Value carries meaning across lines. Replace with a stable pseudonym so
#: correlation survives and the triage answer stays useful. Reversible via the
#: entity vault for the authorised engineer.
PSEUDONYMISE = "pseudonymise"

#: Value is a live credential. Destroy irreversibly. Never vaulted, never
#: reversible, because holding it is itself the risk.
DESTROY = "destroy"


# ---------------------------------------------------------------------------
# Detection tiers (which layer is EXPECTED to own this entity type)
# ---------------------------------------------------------------------------

TIER_SHAPED = "tier1-shaped"  # deterministic pattern, regex owns it
TIER_FREETEXT = "tier2-freetext"  # needs NER, no reliable shape
TIER_CONTEXTUAL = "tier3-contextual"  # disclosure depends on surrounding meaning


@dataclass(frozen=True)
class EntitySpec:
    """How one class of sensitive value is formed."""

    name: str
    handling: str
    expected_tier: str
    source: str
    description: str
    generate: Callable[[random.Random], str]
    #: Detector labels that count as a correctly TYPED catch. Several distinct
    #: entity types share one shape on the wire (every GUID looks alike), so a
    #: detector honestly cannot always tell them apart. Typed recall is scored
    #: against this set; span recall ignores the label entirely.
    detected_as: frozenset[str] = field(default_factory=frozenset)
    #: Pseudonym label prefix, e.g. "Pod" -> "Pod-A".
    label_prefix: str = "Entity"


# ---------------------------------------------------------------------------
# Value generators
# ---------------------------------------------------------------------------

_HEX = "0123456789abcdef"
_REGIONS = ["emea", "amer", "apj"]
_AZ_REGIONS = ["westeu", "eastus", "eastau", "northeu", "cus"]
_FIRST = [
    "anna",
    "marek",
    "priya",
    "tomas",
    "hanna",
    "yusuf",
    "lena",
    "diego",
    "ingrid",
    "noah",
    "sofia",
    "kenji",
    "aisha",
    "pavel",
    "clara",
]
_LAST = [
    "novak",
    "lindqvist",
    "iyer",
    "moreau",
    "okafor",
    "vargas",
    "haddad",
    "petrov",
    "schmitt",
    "delacroix",
    "tanaka",
    "olsen",
    "ferreira",
]
_ORG_WORDS = [
    "Northwind",
    "Contoso",
    "Fabrikam",
    "Litware",
    "Adventure",
    "Tailspin",
    "Woodgrove",
    "Proseware",
]
_ORG_SUFFIX = ["Holdings", "Group", "Partners", "Industries", "Advisory", "AG"]


def _hexs(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_HEX) for _ in range(n))


def _guid(rng: random.Random) -> str:
    return "-".join(_hexs(rng, n) for n in (8, 4, 4, 4, 12))


def _tenant_slug(rng: random.Random) -> str:
    return rng.choice(_ORG_WORDS).lower() + rng.choice(["", "corp", "grp", str(rng.randint(2, 89))])


def _upn(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}@{_tenant_slug(rng)}.com"


def _person(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST).capitalize()} {rng.choice(_LAST).capitalize()}"


def _org(rng: random.Random) -> str:
    return f"{rng.choice(_ORG_WORDS)} {rng.choice(_ORG_SUFFIX)}"


def _pod_id(rng: random.Random) -> str:
    # Region-scoped worker naming, the shape most multi-tenant services use for
    # their pods and agents, e.g. wkr-amer-prx117, wkr-emea-rg124.
    kind = rng.choice(["prx", "rg", "node"])
    return f"wkr-{rng.choice(_REGIONS)}-{kind}{rng.randint(1, 399):02d}"


def _service_id(rng: random.Random) -> str:
    # e.g. svc-prod-cus-001
    return f"svc-{rng.choice(['prod', 'stage'])}-{rng.choice(_AZ_REGIONS)}-{rng.randint(1, 40):03d}"


#: SaaS hosts whose subdomain is the customer's tenant name. The list is
#: deliberately multi-vendor: the pattern being defended against is structural,
#: not specific to any one product, and a redaction layer that only knows one
#: vendor's URL shape is a redaction layer with a hole in it.
TENANT_SITE_HOSTS = ("sharepoint.com", "atlassian.net", "zendesk.com", "slack.com")

_SITE_PATHS = {
    "sharepoint.com": "/sites/",
    "atlassian.net": "/wiki/spaces/",
    "zendesk.com": "/agent/tickets/",
    "slack.com": "/archives/",
}


def _site_url(rng: random.Random) -> str:
    host = rng.choice(TENANT_SITE_HOSTS)
    leaf = rng.choice(["Finance", "HR-Records", "Legal", "ProjectPhoenix", "Audit"])
    return (
        f"https://{_tenant_slug(rng)}.{host}{_SITE_PATHS[host]}{leaf}"
        f"{rng.choice(['', str(rng.randint(2, 9))])}"
    )


def _ipv4(rng: random.Random) -> str:
    return f"{rng.choice([10, 172, 192])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _ipv6(rng: random.Random) -> str:
    return ":".join(_hexs(rng, 4) for _ in range(8))


def _win_user_path(rng: random.Random) -> str:
    user = f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}"
    tail = rng.choice(
        [
            "AppData\\Local\\BackupAgent\\cache",
            "Documents\\Exports",
            "AppData\\Roaming\\BackupAgent",
        ]
    )
    return f"C:\\Users\\{user}\\{tail}"


def _fqdn(rng: random.Random) -> str:
    host = f"{rng.choice(['app', 'sql', 'prx', 'dc'])}{rng.randint(1, 40):02d}"
    return f"{host}.{_tenant_slug(rng)}.internal"


def _case_number(rng: random.Random) -> str:
    return f"{rng.randint(7000000, 8999999):08d}"


def _b64(rng: random.Random, n: int) -> str:
    alpha = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alpha) for _ in range(n))


def _jwt(rng: random.Random) -> str:
    return f"eyJ{_b64(rng, 30)}.eyJ{_b64(rng, 64)}.{_b64(rng, 43)}"


def _sas_url(rng: random.Random) -> str:
    acct = f"stor{_hexs(rng, 10)}"
    return (
        f"https://{acct}.blob.core.windows.net/repo/chunk{rng.randint(1, 9999)}.bin"
        f"?sv=2024-11-04&ss=b&srt=sco&sp=racwdl&se=2026-12-31T23:59:59Z"
        f"&st=2026-01-01T00:00:00Z&spr=https&sig={_b64(rng, 43)}%3D"
    )


def _conn_string(rng: random.Random) -> str:
    acct = f"stor{_hexs(rng, 10)}"
    return (
        f"DefaultEndpointsProtocol=https;AccountName={acct};"
        f"AccountKey={_b64(rng, 86)}==;EndpointSuffix=core.windows.net"
    )


def _api_key(rng: random.Random) -> str:
    return f"{rng.choice(['sk', 'ak', 'vk'])}-{_b64(rng, 40)}"


# ---------------------------------------------------------------------------
# The specification
# ---------------------------------------------------------------------------

#: A bare GUID carries the generic label. ``recognizers.refine`` upgrades it to
#: a specific type when the surrounding text names one, so each type accepts
#: the generic label plus its own, and nothing else. A tenant id relabelled
#: SESSION_GUID is a typing error and is counted as one.
_GUID_LABELS = frozenset({"GUID"})

SPECS: tuple[EntitySpec, ...] = (
    EntitySpec(
        name="SESSION_GUID",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="backup and restore session identifiers as written in service logs",
        description="Backup or restore session id. Correlates lines across a bundle, so it must stay stable after redaction.",
        generate=_guid,
        detected_as=_GUID_LABELS | {"SESSION_GUID"},
        label_prefix="Session",
    ),
    EntitySpec(
        name="TENANT_ID",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="cloud identity provider tenant identifier, public format",
        description="Tenant id of the customer directory. Same shape as any other GUID on the wire.",
        generate=_guid,
        detected_as=_GUID_LABELS | {"TENANT_ID"},
        label_prefix="Tenant",
    ),
    EntitySpec(
        name="OBJECT_GUID",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="per-object identifiers in SaaS APIs, mailboxes and document collections",
        description="Identifier of one backed-up object.",
        generate=_guid,
        detected_as=_GUID_LABELS,
        label_prefix="Mailbox",
    ),
    EntitySpec(
        name="UPN_EMAIL",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="RFC 5322 addr-spec, cloud user principal names",
        description="User principal name or mailbox address. Directly identifies a person.",
        generate=_upn,
        detected_as=frozenset({"EMAIL_ADDRESS", "UPN_EMAIL"}),
        label_prefix="User",
    ),
    EntitySpec(
        name="POD_ID",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="region-scoped worker pod and agent naming, e.g. wkr-amer-prx117",
        description="Worker proxy pod. Reveals region and internal topology.",
        generate=_pod_id,
        detected_as=frozenset({"WORKER_POD_ID"}),
        label_prefix="Pod",
    ),
    EntitySpec(
        name="SERVICE_INSTANCE_ID",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="service instance naming, e.g. svc-prod-cus-001",
        description="Service instance serving a set of tenants.",
        generate=_service_id,
        detected_as=frozenset({"SERVICE_INSTANCE_ID"}),
        label_prefix="Service",
    ),
    EntitySpec(
        name="SITE_URL",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="public URL format of SaaS collaboration hosts, where the subdomain is the customer tenant",
        description="Collaboration site URL. Leaks both the customer tenant name and the business purpose of the site.",
        generate=_site_url,
        detected_as=frozenset({"SITE_URL", "URL"}),
        label_prefix="Site",
    ),
    EntitySpec(
        name="IPV4",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="dotted-quad, standard",
        description="Host address from a customer or internal network.",
        generate=_ipv4,
        detected_as=frozenset({"IP_ADDRESS"}),
        label_prefix="Host4",
    ),
    EntitySpec(
        name="IPV6",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="RFC 4291 full form",
        description="IPv6 host address.",
        generate=_ipv6,
        detected_as=frozenset({"IP_ADDRESS"}),
        label_prefix="Host6",
    ),
    EntitySpec(
        name="WINDOWS_USER_PATH",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="Windows profile path layout",
        description="Filesystem path containing an account name.",
        generate=_win_user_path,
        detected_as=frozenset({"WINDOWS_USER_PATH"}),
        label_prefix="Path",
    ),
    EntitySpec(
        name="HOSTNAME_FQDN",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="internal DNS naming in on-prem deployments",
        description="Internal hostname. Reveals customer naming conventions.",
        generate=_fqdn,
        detected_as=frozenset({"HOSTNAME_FQDN"}),
        label_prefix="Node",
    ),
    EntitySpec(
        name="SUPPORT_CASE_NUMBER",
        handling=PSEUDONYMISE,
        expected_tier=TIER_SHAPED,
        source="support ticket numbering, eight digits",
        description="Support case number. Internal reference that links a log excerpt back to a named account.",
        generate=_case_number,
        detected_as=frozenset({"SUPPORT_CASE_NUMBER"}),
        label_prefix="Case",
    ),
    # ---- true secrets: destroyed, never vaulted ----
    EntitySpec(
        name="JWT",
        handling=DESTROY,
        expected_tier=TIER_SHAPED,
        source="RFC 7519 compact serialisation",
        description="Bearer token. Live credential, so it is destroyed rather than pseudonymised.",
        generate=_jwt,
        detected_as=frozenset({"JWT"}),
        label_prefix="Jwt",
    ),
    EntitySpec(
        name="PRESIGNED_URL",
        handling=DESTROY,
        expected_tier=TIER_SHAPED,
        source="pre-signed object-storage URL query formats",
        description="Pre-signed storage URL granting direct data access to anyone holding it.",
        generate=_sas_url,
        detected_as=frozenset({"PRESIGNED_URL"}),
        label_prefix="Presigned",
    ),
    EntitySpec(
        name="CONNECTION_STRING",
        handling=DESTROY,
        expected_tier=TIER_SHAPED,
        source="object-storage connection string formats",
        description="Account key embedded in a connection string.",
        generate=_conn_string,
        detected_as=frozenset({"CONNECTION_STRING"}),
        label_prefix="Conn",
    ),
    EntitySpec(
        name="API_KEY",
        handling=DESTROY,
        expected_tier=TIER_SHAPED,
        source="common provider key prefixes",
        description="API or client key.",
        generate=_api_key,
        detected_as=frozenset({"API_KEY"}),
        label_prefix="Key",
    ),
    # ---- free text: tier 1 is EXPECTED to miss these ----
    EntitySpec(
        name="PERSON_NAME",
        handling=PSEUDONYMISE,
        expected_tier=TIER_FREETEXT,
        source="engineer and end-user names written into notes and error text",
        description="A person's name in prose. No shape to match, so this is the managed-NER case.",
        generate=_person,
        detected_as=frozenset({"PERSON"}),
        label_prefix="Person",
    ),
    EntitySpec(
        name="ORG_NAME",
        handling=PSEUDONYMISE,
        expected_tier=TIER_FREETEXT,
        source="customer company names in operator notes",
        description="Customer organisation name in prose.",
        generate=_org,
        detected_as=frozenset({"ORGANIZATION"}),
        label_prefix="Org",
    ),
)

BY_NAME: dict[str, EntitySpec] = {s.name: s for s in SPECS}

SECRET_TYPES: frozenset[str] = frozenset(s.name for s in SPECS if s.handling == DESTROY)


def spec(name: str) -> EntitySpec:
    """The spec for an entity type by name; raises KeyError listing the known types."""
    try:
        return BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown entity type {name!r}; known: {sorted(BY_NAME)}") from None
