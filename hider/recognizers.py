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

from . import entities, paths, profiles, vendors
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
    # Unencoded spaces in document paths ("/Shared Documents/Q3 support
    # plans.xlsx") used to stop the match at the first space and leak the file
    # name. The space-tolerant tail is fenced twice so it can never swallow
    # prose after a URL: it must contain a path separator (a continuation of a
    # path has one; " from archive backup.zip" does not), and it must end in a
    # document extension. The declared remainder: a space-separated file name
    # in the final segment with no further slash still leaks its tail.
    space_tail = (r"(?:(?:[ ][\w.%()&-]{1,40})*[ ]?/[^\"'<>\n]{0,80}?"
                  r"\.(?:xlsx|xls|docx|doc|pptx|ppt|pdf|csv|msg|eml|one|vsdx|txt|rtf|zip)\b)?")
    return PatternRecognizer(
        supported_entity="SITE_URL",
        name="TenantSiteRecognizer",
        patterns=[
            Pattern(
                name="tenant-site",
                regex=rf"https?://[A-Za-z0-9-]{{1,63}}(?:-my)?\.(?:{hosts})"
                      rf"(?:/[^\s\"'<>,;)\]]*)?{space_tail}",
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


#: Authorities on the left of a backslash that name Windows itself, not a
#: customer. ``NT AUTHORITY\SYSTEM`` is the same string on every machine on
#: earth; redacting it destroys triage value and protects nobody. Registry
#: hives and the common all-caps path roots are here for the same reason:
#: they look exactly like a NETBIOS domain and never are one.
_WELL_KNOWN_AUTHORITIES = frozenset({
    "NT", "AUTHORITY", "BUILTIN", "SERVICE", "SYSTEM", "SELF", "EVERYONE",
    "HKLM", "HKCU", "HKCR", "HKU", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT", "HKEY_USERS", "SOFTWARE", "IIS", "APPPOOL",
    "TEMP", "TMP", "WINDIR", "WINDOWS", "PUBLIC", "DEFAULT", "USERS",
})


class DomainLogonRecognizer(LocalRecognizer):
    """``DOMAIN\\user`` logons, the on-prem spelling of a person.

    The shape is two tokens around a backslash, which is also the shape of a
    registry path, a well-known principal and an all-caps directory pair, so
    the pattern alone is not enough. Three guards carry the precision:

    * the authority must be all-caps, which is how NETBIOS domains are written
      and how prose is not;
    * the character before it must not be ``\\``, ``:`` or a word character,
      which excludes every segment inside a longer path (``D:\\BACKUP\\x``);
    * the authority must not be a well-known one, so ``NT AUTHORITY\\SYSTEM``
      and ``BUILTIN\\Administrators`` survive verbatim - they are structure,
      not customer data, and an engineer needs to see them.

    A denylist cannot be complete, which is acceptable in this direction: an
    unlisted authority means a well-known principal gets pseudonymised, not
    that a customer logon leaks.
    """

    # The account tail must end on an alphanumeric or the $ of a machine
    # account (WKS041$); ending on . or - would swallow sentence punctuation.
    LOGON = re.compile(
        r"(?<![\w\\:.\-])([A-Z][A-Z0-9-]{1,14})\\"
        r"([A-Za-z](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?\$?)(?![\w$\\])"
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["DOMAIN_LOGON"],
            name="DomainLogonRecognizer",
            context=["logon", "user", "account", "domain"],
        )
        self.supported_entity = "DOMAIN_LOGON"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        out: list[RecognizerResult] = []
        for m in self.LOGON.finditer(text):
            if m.group(1) in _WELL_KNOWN_AUTHORITIES:
                continue
            out.append(RecognizerResult(
                entity_type=self.supported_entity, start=m.start(),
                end=m.end(), score=0.85, analysis_explanation=None))
        return out


def windows_sid() -> PatternRecognizer:
    """Domain and Azure AD SIDs, and deliberately nothing else.

    Only ``S-1-5-21-…`` (a domain plus its accounts) and ``S-1-12-1-…`` (an
    Azure AD identity projected into Windows) carry customer identity. The
    well-known SIDs - ``S-1-5-18``, ``S-1-5-32-544``, ``S-1-1-0`` - are
    constants shared by every Windows installation, and redacting them is pure
    loss, so the pattern requires the domain-form subauthorities and cannot
    match the short well-known forms.
    """
    return PatternRecognizer(
        supported_entity="WINDOWS_SID",
        name="WindowsSidRecognizer",
        patterns=[
            Pattern(
                name="domain-sid",
                regex=r"\bS-1-(?:5-21|12-1)-\d{1,10}-\d{1,10}-\d{1,10}(?:-\d{1,10})?\b",
                score=0.9,
            ),
        ],
        context=["sid", "account", "token", "group"],
    )


class CertThumbprintRecognizer(LocalRecognizer):
    """Certificate thumbprints, which are 40 hex characters - and so is every
    git commit hash.

    The shape is worthless on its own: redacting bare 40-hex would eat every
    deploy line in the bundle. The gate is the word that names it, same
    approach as the support-case rule, and the span is narrowed to the digits
    so the word "thumbprint" itself survives to say what was removed. Python's
    ``re`` has no variable-length lookbehind, hence a recognizer rather than a
    pattern.
    """

    PHRASE = re.compile(
        r"(?i)\b(?:thumbprint|cert(?:ificate)?\s*hash)\b\W{0,24}([0-9A-Fa-f]{40})\b"
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["CERT_THUMBPRINT"],
            name="CertThumbprintRecognizer",
            context=["certificate", "thumbprint", "auth", "app"],
        )
        self.supported_entity = "CERT_THUMBPRINT"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        return [
            RecognizerResult(entity_type=self.supported_entity, start=m.start(1),
                             end=m.end(1), score=0.9, analysis_explanation=None)
            for m in self.PHRASE.finditer(text)
        ]


def onmicrosoft_tenant_domain() -> PatternRecognizer:
    """``*.onmicrosoft.com`` domains: the subdomain IS the customer tenant.

    ``jsonscrub`` already caught these in JSON exports; plain log text did
    not. Not added to ``entities.TENANT_SITE_HOSTS`` because the generator
    reads that constant, and widening generation reshuffles the corpus and
    invalidates the committed utility cassette. Same idea, separate rule.
    """
    return PatternRecognizer(
        supported_entity="TENANT_DOMAIN",
        name="OnmicrosoftTenantRecognizer",
        patterns=[
            Pattern(
                name="onmicrosoft",
                regex=r"\b[A-Za-z0-9][A-Za-z0-9-]{0,62}\.(?:mail\.)?onmicrosoft\.com\b",
                score=0.9,
            ),
        ],
        context=["tenant", "domain", "directory", "verified"],
    )


class FormattedPhoneRecognizer(LocalRecognizer):
    """Phone numbers in free text, via the ``phonenumbers`` library - gated on
    the number actually being written like one.

    The library alone is not safe here, in both directions. At every leniency
    level it claims ``4255550147`` in "transferred 4255550147 bytes" and even
    the eight-digit support-case shape ``07551234``; and it reads the head of
    every bracketed log timestamp, ``[21.08.2026 09``, as a formatted European
    number - measured at 96 of 1,000 clean lines redacted, which would have
    gutted the bundle. The gate that kills all of it is the writing system
    phones actually use: a kept match consists of digits plus ``+ - ( )`` and
    spaces only, and is not a pure digit run. Dots, colons and brackets mean a
    timestamp, a version or log structure, never a phone.

    The declared cost: an unformatted phone number in a note
    ("call 4255550147") and a dotted European spelling ("0043.1.5125.0") are
    missed, documented gaps rather than silent ones, because the alternatives
    redact byte counts and timestamps and the engineer stops trusting the
    output.
    """

    _PHONE_CHARS = frozenset("0123456789 -()+")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["PHONE_NUMBER"],
            name="FormattedPhoneRecognizer",
            context=["phone", "call", "callback", "contact", "mobile"],
        )
        self.supported_entity = "PHONE_NUMBER"
        from presidio_analyzer.predefined_recognizers import PhoneRecognizer
        self._inner = PhoneRecognizer()

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        out: list[RecognizerResult] = []
        for r in self._inner.analyze(text, ["PHONE_NUMBER"], nlp_artifacts=nlp_artifacts):
            value = text[r.start:r.end]
            if value.isdigit() or not set(value) <= self._PHONE_CHARS:
                continue  # a count, a timestamp or log structure, not a phone
            out.append(RecognizerResult(
                entity_type=self.supported_entity, start=r.start, end=r.end,
                score=min(r.score, 0.85), analysis_explanation=None))
        return out


#: Dotted tokens that are files, not hosts. Shared with jsonscrub (one list,
#: one judgement). The two-letter source extensions (py, js, ts, rs, md, sh,
#: ps, go, rb, cs, db) shadow the matching country TLDs on purpose: in a log
#: bundle "main.py" outnumbers Paraguayan domains by orders of magnitude, and
#: the loss is declared rather than discovered.
FILE_EXT = frozenset({
    "log", "txt", "json", "xml", "dll", "exe", "zip", "csv", "config", "html",
    "htm", "pdf", "png", "jpg", "gz", "db", "md", "ps", "cs", "js", "py", "sh",
    "ts", "rs", "go", "rb", "yml", "yaml", "ini", "bak", "tmp", "evtx", "etl",
    "xlsx", "xls", "docx", "doc", "pptx", "ppt", "msg", "eml", "one", "vsdx",
    "rtf", "jpeg", "bmp", "gif", "svg", "ico", "tar", "bz2", "7z", "rar",
    "dat", "dmp", "pcap", "reg", "ps1", "psm1", "bat", "cmd", "vbs", "msi",
    "cab", "jar", "war", "class", "pyc", "whl", "toml", "lock", "sql", "pem",
    "crt", "cer", "key", "pfx", "der", "jsonl", "parquet", "php", "aspx",
    "jsp", "css", "map", "wasm", "so", "dylib", "pdb", "cpp", "hpp",
})

#: Public TLDs the customer-domain rule will claim under. Deliberately an
#: allowlist: an open [a-z]{2,24} tail also matches "service.then" when a note
#: drops the space after a sentence. An exotic TLD outside this list is a
#: declared miss, and a site profile can add a pattern for it.
_PUBLIC_TLDS = frozenset((
    "com net org io co edu gov mil info biz dev app cloud tech online site "
    "store blog news media email group team live global world "
    "uk de fr nl be it es pt se no dk fi pl cz sk at ch ie au nz ca us mx br "
    "ar cl jp cn kr in sg hk tw th my id ph vn ru ua tr il ae sa za eg ng ke "
    "gr hu ro bg hr si ee lv lt lu is mt cy eu asia"
).split())

#: Multi-part public suffixes: in "contoso.co.uk" the organisation is
#: "contoso", not "co". Only the common second-level forms are handled.
_SECOND_LEVEL = frozenset({"co", "com", "org", "net", "ac", "gov", "edu"})


class CustomerDomainRecognizer(LocalRecognizer):
    """Any public FQDN that is not a known vendor service is a customer host.

    This closes the "backup.fabrikamedu.org" gap: a host outside the internal
    suffix list used to pass untouched because no rule owned the open
    namespace. The rule fails toward redaction - an unknown host is a customer
    host until the vendor list (repo core plus hider.local.json) says
    otherwise - and it fires in prose as well as in host positions, because an
    operator note names the customer's estate as readily as a Host: header.

    The fences, each with a test and a measured false-redaction cost of zero:

    * last label must be a listed public TLD (kills "service.then" typos);
    * last label must not be a file extension ("backup.log", "report.xlsx");
    * no mixed-case label ("Backup.Proxy.SessionWorker" is a namespace);
    * not inside a longer dotted chain ("system.net" inside
      "system.net.sockets" is a namespace segment, blocked by the lookahead);
    * not an email domain (the @ lookbehind leaves those to the UPN rule);
    * hosts other rules own are skipped: vendor services, internal TLDs,
      onmicrosoft and key-vault and tenant-site hosts.
    """

    FQDN = re.compile(
        r"(?<![\w@.-])"
        r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"
        r"(?![\w-])(?!\.[A-Za-z0-9])"
    )

    #: Suffixes owned by a more specific rule; claiming them here would only
    #: fight that rule in overlap resolution.
    OWNED = ("onmicrosoft.com", "vault.azure.net", ".internal", ".local",
             ".lan", ".corp", ".intra", ".ad") + entities.TENANT_SITE_HOSTS

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["CUSTOMER_DOMAIN"],
            name="CustomerDomainRecognizer",
            context=["host", "domain", "server", "endpoint", "repository"],
        )
        self.supported_entity = "CUSTOMER_DOMAIN"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        out: list[RecognizerResult] = []
        for m in self.FQDN.finditer(text):
            host = m.group(1)
            labels = host.split(".")
            if labels[-1].lower() not in _PUBLIC_TLDS:
                continue
            if labels[-1].lower() in FILE_EXT:
                continue
            if any(lb != lb.lower() and lb != lb.upper() for lb in labels):
                continue  # TitleCase label: a namespace, not a host
            low = host.lower()
            if low.endswith(self.OWNED) or vendors.is_vendor_host(low):
                continue
            out.append(RecognizerResult(
                entity_type=self.supported_entity, start=m.start(1),
                end=m.end(1), score=0.75, analysis_explanation=None))
        return out


def onedrive_personal_account() -> PatternRecognizer:
    """The identity segment of a OneDrive ``/personal/`` path.

    OneDrive flattens the owner's UPN into the path - dots and the @ become
    underscores, so ``anna.novak@contoso.com`` travels as
    ``/personal/anna_novak_contoso_com/...`` even when the host has been
    stripped from the log line. The segment is the person; the rest of the
    path keeps its structure, which keeps "which folder failed" answerable.

    The flattening is not invertible (an underscore in the original local part
    is indistinguishable from a flattened dot), so this pseudonym cannot share
    the owner's UPN vault entry; it gets its own user ordinal. Customer
    folders and file names deeper in the path are CustomerPathRecognizer's.
    """
    return PatternRecognizer(
        supported_entity="ONEDRIVE_ACCOUNT",
        name="OneDrivePersonalRecognizer",
        patterns=[
            Pattern(
                name="personal-segment",
                # Fixed-width lookbehind keeps the span on the identity
                # segment, so "/personal/" itself survives as structure.
                regex=r"(?<=/personal/)[A-Za-z0-9][A-Za-z0-9_-]{4,128}(?=/|\b)",
                score=0.9,
            ),
        ],
        context=["personal", "onedrive", "site", "path"],
    )


def azure_key_vault() -> PatternRecognizer:
    """Key vault URLs: the vault name is the customer, the secret name is the
    purpose, and both go.

    Only names travel in these URLs - the secret *value* never appears, which
    is why this is pseudonymised rather than destroyed: "the job read
    sql-conn-primary from the same vault twice" is exactly the correlation an
    engineer needs, and the vault can give it back. Not added to
    ``entities.TENANT_SITE_HOSTS`` for the usual reason: the generator reads
    that constant and widening it invalidates the committed utility cassette.
    """
    return PatternRecognizer(
        supported_entity="AZURE_KEY_VAULT",
        name="AzureKeyVaultRecognizer",
        patterns=[
            Pattern(
                name="kv-url",
                regex=(r"(?:https?://)?[A-Za-z0-9-]{3,24}\.vault\.azure\.net"
                       r"(?:/[^\s\"'<>,;)\]]*)?"),
                score=0.9,
            ),
        ],
        context=["vault", "secret", "key", "certificate"],
    )


def exchange_item_id() -> PatternRecognizer:
    """Exchange item and folder ids, the ``AAMkAD…`` base64 runs.

    They encode mailbox and store identity and correlate every operation on
    one item, so they are pseudonymised, not destroyed. The constant prefix is
    the gate: EWS and Graph both stamp it, and a random base64 run opening
    with it does not occur. Tier 2 used to half-claim these as organisation
    names, which vaulted fragments of the id under the wrong type and left the
    head in the clear.

    Declared trade, owned by the adversarial case: an id alone on a wrapped
    line is also a bare 40+ character base64 line, which the credential rules
    destroy. Overlap resolution prefers the destroying span, so correlation is
    lost but nothing leaks.
    """
    return PatternRecognizer(
        supported_entity="EXCHANGE_ITEM_ID",
        name="ExchangeItemIdRecognizer",
        patterns=[
            Pattern(
                name="exchange-id",
                regex=r"\bA[AQ]MkA[DG][A-Za-z0-9+/=_-]{30,}",
                score=0.9,
            ),
        ],
        context=["item", "folder", "mailbox", "message"],
    )


def url_userinfo() -> PatternRecognizer:
    """Credentials in a URL's userinfo, ``scheme://user:password@host``.

    This one was not merely missed, it was actively mishandled. The UPN rule
    matches ``password@host`` as an address, so the password was pseudonymised
    into the vault as if it were a user, and the username in front of the
    colon was left in the clear. A vaulted credential is strictly worse than a
    missed one: the secret is still in the text and is now also on disk under
    a reversible mapping.

    The span covers the whole ``user:password@``, because the service account
    name identifies as surely as the password authenticates. ``pipeline.resolve``
    prefers this span over the overlapping address span, since a secret outranks
    an identifier. The host is left to the hostname and site rules, which is
    what keeps "which endpoint was this" answerable after redaction.
    """
    return PatternRecognizer(
        supported_entity="API_KEY",
        name="UrlUserinfoRecognizer",
        patterns=[
            Pattern(
                name="userinfo",
                # Fixed-width lookbehind keeps the span off the scheme. The
                # character classes exclude the delimiters that end an
                # authority (/ ? # &): without them, an ordinary URL whose
                # query string happens to contain an @, as in
                # "https://host:8443?token=a@b.com", matched from the host
                # onward and the host was destroyed.
                regex=r"(?<=://)[^/\s:@?#&]{1,64}:[^/\s@?#&]{1,128}@",
                score=0.95,
            ),
        ],
        context=["url", "endpoint", "feed", "credential"],
    )


def http_credential_header() -> PatternRecognizer:
    """Credentials carried in HTTP headers other than a bearer token.

    ``Basic`` is not obfuscation, it is base64 of ``user:password``, and a
    session cookie is a bearer credential in every sense that matters: anyone
    holding it is the user until it expires. Both went upstream untouched
    before this rule existed.

    Cookie values are handled by ``CookieHeaderRecognizer`` rather than here,
    because keeping the attribute names while destroying only the values needs
    per-pair spans that the pattern engine cannot express.
    """
    return PatternRecognizer(
        supported_entity="API_KEY",
        name="HttpCredentialHeaderRecognizer",
        patterns=[
            # Fixed-width lookbehind; Presidio matches case-insensitively.
            Pattern(name="basic-auth",
                    regex=r"(?<=Basic )[A-Za-z0-9+/=_-]{8,}", score=0.95),
            # Other schemes that carry a credential rather than a challenge.
            Pattern(name="ntlm-negotiate",
                    regex=r"(?<=Negotiate )[A-Za-z0-9+/=]{16,}", score=0.9),
            Pattern(name="apikey-header",
                    regex=r"(?<=X-Api-Key: )[^\s\"']{8,}", score=0.9),
        ],
        context=["authorization", "header", "credential", "auth"],
    )


#: Cookie attribute names, which are structure rather than secret. Keeping
#: them is what lets an engineer still see that a cookie was Secure and
#: SameSite=Lax after the value itself has been destroyed.
_COOKIE_ATTRS = frozenset({
    "expires", "max-age", "domain", "path", "secure", "httponly", "samesite",
    "version", "comment", "priority", "partitioned",
})


class CookieHeaderRecognizer(LocalRecognizer):
    """Values inside a ``Cookie`` or ``Set-Cookie`` header.

    A session cookie authenticates, so it is destroyed, not pseudonymised.
    Before this existed, tier 2 claimed parts of cookie values as organisation
    names: the value was half-leaked and half-written to the vault.

    Only the value half of each ``name=value`` pair is claimed, and attribute
    pairs are skipped entirely. Cookie names and attributes are the part that
    makes the line worth keeping ("the auth cookie was present, Secure, and
    scoped to /api"), and they are not the part that authenticates. Expressing
    "the value of each pair, except these names" needs per-pair offsets, which
    is why this is a recognizer rather than a pattern.
    """

    HEADER = re.compile(r"(?i)\b(?:Set-)?Cookie\s*:[ \t]*")
    PAIR = re.compile(r"([A-Za-z0-9_.-]+)[ \t]*=[ \t]*([^;,\r\n]*)")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["API_KEY"],
            name="CookieHeaderRecognizer",
            context=["cookie", "session", "header"],
        )
        self.supported_entity = "API_KEY"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        out: list[RecognizerResult] = []
        for header in self.HEADER.finditer(text):
            # One header runs to the end of its line and no further.
            line_end = text.find("\n", header.end())
            stop = len(text) if line_end == -1 else line_end
            for pair in self.PAIR.finditer(text, header.end(), stop):
                name, value = pair.group(1), pair.group(2).strip()
                if name.lower() in _COOKIE_ATTRS or not value:
                    continue
                start = pair.start(2) + (len(pair.group(2)) - len(pair.group(2).lstrip()))
                out.append(RecognizerResult(
                    entity_type=self.supported_entity, start=start,
                    end=start + len(value), score=0.9, analysis_explanation=None))
        return out


class AwsSecretKeyRecognizer(LocalRecognizer):
    """The AWS secret access key, which has no shape of its own.

    Forty base64 characters is also a hash, a chunk id and half a certificate,
    so the value cannot be matched on shape without redacting the bundle to
    confetti. The key *name* beside it is the evidence, and it is a strong one:
    nobody writes ``aws_secret_access_key =`` next to something harmless.

    Reported as the value alone, not the whole assignment, so the key name
    survives and the line still says what was removed. Python has no
    variable-length lookbehind, which is why the span is narrowed here rather
    than in a pattern.
    """

    PHRASE = re.compile(
        r"(?i)\b(?:aws[_-]?)?secret[_-]?access[_-]?key\b[ \t]*[:=][ \t]*"
        r"[\"']?([A-Za-z0-9/+=]{20,})"
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["API_KEY"],
            name="AwsSecretKeyRecognizer",
            context=["aws", "secret", "credentials", "profile"],
        )
        self.supported_entity = "API_KEY"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        return [
            RecognizerResult(entity_type=self.supported_entity, start=m.start(1),
                             end=m.end(1), score=0.95, analysis_explanation=None)
            for m in self.PHRASE.finditer(text)
        ]


class PrivateKeyBlockRecognizer(LocalRecognizer):
    """PEM private key material, whole block or one body line at a time.

    Two matching modes because the engine sees text both ways. The proxy and
    the JSON scrubber hand over a whole message, where the BEGIN/END markers
    bracket the body and the block can be matched outright. The CLI and the
    eval walk a bundle line by line, where a body line is a bare base64 run
    with no context whatsoever - and that is exactly the line that was being
    vaulted as an organisation name.

    So a base64-only line is claimed on its own, anchored to the line and
    floored at 40 characters. That floor is the whole precision argument: a
    line consisting of nothing but a long unbroken base64 run is key material,
    a chunk digest or a token, and none of those belong upstream. The false-
    redaction measurement on the clean corpus is what keeps this honest.

    The BEGIN and END markers are deliberately not claimed. They carry no key
    material, and leaving them tells the engineer a key was removed here.
    """

    BLOCK = re.compile(
        r"(?s)(?<=-----)\n?(.*?)(?=-----END[A-Z ]*PRIVATE KEY-----)"
    )
    MARKER = re.compile(r"(?i)-----BEGIN[A-Z ]*PRIVATE KEY-----")
    BODY_LINE = re.compile(r"(?m)^[ \t]*([A-Za-z0-9+/]{40,}={0,2})[ \t]*$")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["API_KEY"],
            name="PrivateKeyBlockRecognizer",
            context=["private", "key", "pem", "certificate"],
        )
        self.supported_entity = "API_KEY"

    def load(self) -> None:
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        if entities and self.supported_entity not in entities:
            return []
        out: list[RecognizerResult] = []
        # Whole block, when the markers are both present in this text.
        for marker in self.MARKER.finditer(text):
            body = self.BLOCK.search(text, marker.end() - 5)
            if body and body.group(1).strip():
                out.append(RecognizerResult(
                    entity_type=self.supported_entity, start=body.start(1),
                    end=body.end(1), score=0.95, analysis_explanation=None))
        # Bare base64 body lines, which is how a line-by-line walk sees them.
        for m in self.BODY_LINE.finditer(text):
            out.append(RecognizerResult(
                entity_type=self.supported_entity, start=m.start(1),
                end=m.end(1), score=0.85, analysis_explanation=None))
        return out


def vendor_credential() -> PatternRecognizer:
    """Vendor-issued credentials that announce themselves with an issuer prefix.

    These are the cheapest true positives in the whole system and the most
    expensive misses. Each vendor deliberately stamps a constant prefix on its
    tokens precisely so that scanners can find them, so the pattern needs no
    context word and carries a high score: nothing else in a support bundle is
    spelled ``ghp_`` followed by thirty-six base62 characters.

    Lengths are lower bounds rather than exact, because a bundle contains
    truncated and elided tokens ("ghp_abc...") far more often than pristine
    ones, and a shortened credential is still a credential prefix worth
    destroying. The floors are set high enough that no English word reaches
    them.

    These are reported as ``API_KEY`` rather than as a type of their own. The
    handling class is identical - every one of them authenticates on its own,
    so every one is destroyed, never vaulted - and a detector has no reason to
    tell a GitHub PAT from a Slack token. ``entities.VENDOR_KEY_FORMATS``
    documents the formats these patterns were written against.
    """
    return PatternRecognizer(
        supported_entity="API_KEY",
        name="VendorCredentialRecognizer",
        patterns=[
            # GitHub fine-grained PAT: github_pat_ + 22 + _ + 59 base62.
            Pattern(name="github-pat-fine",
                    regex=r"\bgithub_pat_[A-Za-z0-9_]{20,}", score=0.95),
            # GitHub classic PAT and its siblings: user, OAuth, user-to-server,
            # server-to-server and refresh tokens all share the shape.
            Pattern(name="github-pat-classic",
                    regex=r"\bgh[pousr]_[A-Za-z0-9]{20,}", score=0.95),
            # AWS access key id: a resource-type prefix plus 16 characters.
            # Presidio matches case-insensitively by default and that default
            # is kept here, unlike the pod-id rule: a down-cased key id is
            # still a key id, and the asymmetry is stark. Destroying a
            # 20-character token that merely looked like one costs a line of
            # triage detail; missing one puts a live AWS credential in a
            # provider's request log.
            Pattern(name="aws-access-key-id",
                    regex=r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA|ABIA|ACCA)"
                          r"[A-Z0-9]{16}\b",
                    score=0.95),
            # Google API key: AIza + 35 base64url characters.
            Pattern(name="google-api-key",
                    regex=r"\bAIza[A-Za-z0-9_-]{30,}", score=0.95),
            # Slack bot, user, app, refresh, session and export tokens.
            Pattern(name="slack-token",
                    regex=r"\bxox[abeprs]-[A-Za-z0-9-]{10,}", score=0.95),
            # Azure Entra application client secret. There is no constant
            # prefix to key on, so the rule is the structure the format does
            # guarantee: a short head, a tilde, and a long unbroken secret
            # body. Thirty characters after a tilde with no whitespace is not
            # something prose produces.
            Pattern(name="entra-client-secret",
                    regex=r"\b[A-Za-z0-9._-]{2,8}~[A-Za-z0-9._-]{30,}", score=0.85),
        ],
        context=["key", "secret", "token", "credential", "apikey", "authorization"],
    )


def windows_user_path() -> PatternRecognizer:
    """Profile paths carry an account name inside the path.

    The separator is a character class, not a literal backslash, because the
    forward-slash spelling of a Windows path is not an exotic case: .NET's
    ``Path`` APIs accept it, Python and PowerShell emit it, and anything that
    round-trips a path through JSON or a URL tends to produce it. A rule that
    only knew ``C:\\Users\\`` let ``C:/Users/anna.novak/...`` through with the
    account name intact, which was this project's one deliberately open tier 1
    gap. Mixed separators within one path match too, since string concatenation
    across layers produces exactly that.
    """
    sep = r"[\\/]"
    return PatternRecognizer(
        supported_entity="WINDOWS_USER_PATH",
        name="WindowsUserPathRecognizer",
        patterns=[
            Pattern(
                name="profile",
                regex=rf"[A-Za-z]:{sep}Users{sep}[^\\/\s\"'<>|]+(?:{sep}[^\s\"'<>|]*)*",
                score=0.85,
            ),
            # UNC stays backslash-only. A forward-slash "//host/users/..." is
            # indistinguishable from the tail of an ordinary URL, and widening
            # it would swallow every Graph call of the form
            # https://graph.microsoft.com/users/<upn> as a filesystem path.
            Pattern(name="unc-home", regex=r"\\\\[A-Za-z0-9.-]+\\users?\$?\\[^\s\"'<>|]+", score=0.8),
        ],
        context=["path", "cache", "export", "profile"],
    )


#: Extensions the path rule reads as a file's extension (the rest of a dotted
#: final segment is part of the name).
_ARTIFACT_EXT = frozenset({
    "log", "etl", "evtx", "dmp", "json", "jsonl", "xml", "config", "ini", "yml", "yaml",
    "toml", "lock", "tmp", "dat", "db", "sqlite", "reg", "cab", "pem", "crt", "cer",
    "pfx", "trace", "out", "err",
})
_PATH_EXT = (FILE_EXT | paths.CODE_EXT | paths.BINARY_EXT | paths.DOCUMENT_EXT
             | _ARTIFACT_EXT | {"gz", "tar", "bz2", "xz", "tgz"})
_PATH_WORD = r"[^\s\\/\"<>|*?:\x00-\x1f]+"
#: A word of a file name: a path word that may also hold a colon, as long as
#: no separator follows it (a colon before a separator is a drive or a URL
#: scheme, and ends the name).
_NAME_WORD = r"(?:[^\s\\/\"<>|*?:\x00-\x1f]|:(?![\\/]))+"
#: What joins the words of one name: a run of spaces, including the
#: non-breaking and narrow spaces Office and macOS write. Tabs and line breaks
#: are field and record separators in a log, never part of a name.
_NAME_GAP = r"[ \u00a0\u2007\u202f]+"
#: How many words after the first an unquoted last segment is searched for
#: its extension. Past this the title-case fallback applies (a declared miss,
#: adversarial path-file-name-over-sixteen-words): the further the search
#: runs, the more prose after a folder path it swallows up to the next file
#: mentioned on the line.
_MAX_NAME_WORDS = 16
#: Endings that are a host's, not a file's, when the extension is not known.
_NOT_EXT = frozenset({"local", "lan", "corp", "internal", "intra", "home", "localdomain"})
_UNKNOWN_EXT = re.compile(r"(?![vV]\d+$)(?:[a-z][a-z0-9]{1,5}|[A-Z][A-Z0-9]{1,5})")
_HTTP_METHOD = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+$")
_QUOTES = {'"': '"', "'": "'", "\u2018": "\u2019", "\u201c": "\u201d", "`": "`"}
_LOG_WORDS = None


def _has_gap(name: str) -> bool:
    """True when a path segment holds more than one word."""
    return any(c.isspace() for c in name)


class CustomerPathRecognizer(LocalRecognizer):
    """Customer folder and file names inside file paths in free text.

    Each customer segment gets its own stable label, so one file can be
    followed through a bundle and two files in one folder visibly share it;
    separators, structural folder names (:mod:`hider.paths`), version
    segments and the file extension stay readable:

        /Sites/Finance/Shared Documents/Harbor Ridge Project (HRP)/Budget.docx
        /Sites/<Folder-01>/Shared Documents/<Folder-02>/<File-01>.docx

    A path starts at a root: a drive (``C:\\`` or ``C:/``), a UNC server
    (``\\\\server\\share``), ``~/``, a leading slash after whitespace, a quote
    or a bracket, or a library name (``Shared Documents/``). Folder names may
    hold spaces (runs of them, non-breaking ones too) when a separator closes
    them. The last segment is a file name and is labelled whole or not at
    all, never with a folder label over its first words. Quoted, it runs to
    the closing quote. Unquoted, it runs over up to sixteen more words (colons,
    commas, codes and amounts included) to the first word with a known
    extension, else to the last with an unknown one (``.xlsl``: the whole
    segment, extension included, is the label). With no extension in reach,
    it runs as far as the following words are title-case or all-caps; a
    lower-case or log-vocabulary word ends it.

    What stays readable, each a named fence with a test:

    * a path to a source file or a program binary (stack traces, installs);
    * a path under a system root (``/usr``, ``/var``, ``C:\\Windows``,
      ``Program Files``) or through a hidden folder (``~/.cache/<app>``): its
      folders, though a document name under one is labelled;
    * a leading-slash path that is an API route: after an HTTP method, under
      an API root, or with nothing in it that a document path has (an
      extension, a space, a capital, a library root); and one segment alone
      (``/MIR``) is a switch, not a path;
    * Windows profile paths and ``\\\\server\\users\\`` homes, which
      ``windows_user_path`` owns; URLs, whose host other rules own.

    The labels are new detector labels (``PATH_SEGMENT``, ``FILE_NAME``,
    ``PATH_ACCOUNT``) borrowed by the ``WINDOWS_USER_PATH`` spec, and the UNC
    server is ``HOSTNAME_FQDN``.
    """

    _START = re.compile(
        r"(?P<drive>(?<![A-Za-z0-9_])[A-Za-z]:(?=[\\/]))"
        r"|(?P<unc>(?<![\\\w])\\\\(?=[A-Za-z0-9]))"
        r"|(?P<tilde>(?<![\w~/\\])~(?=[\\/]))"
        r"|(?P<slash>(?:^|(?<=[\s\"'(\[=,;\u2018\u201c`]))(?=/[^\s/\\]))"
        r"|(?P<anchor>(?<![\w\\/.%-])(?:" + "|".join(re.escape(a) for a in paths.RELATIVE_ANCHORS)
        + r")(?=[\\/]))"
    )
    _SEP = re.compile(r"[\\/]+")
    _INTERIOR = re.compile(_PATH_WORD + r"(?:" + _NAME_GAP + _PATH_WORD + r"){0,9}(?=[\\/])")
    # Inside quotes the quote delimits the name, so a colon is part of it; a
    # colon right before a separator is still a drive or a scheme.
    _QUOTED_SEG = re.compile(r"(?:[^\\/\"<>|*?:\x00-\x1f]|:(?![\\/]))+?(?=[\\/]|$)")
    _WORD = re.compile(_PATH_WORD)
    _NAME_WORD = re.compile(_NAME_WORD)
    _GAP = re.compile(_NAME_GAP)
    _HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
    _IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["PATH_SEGMENT", "FILE_NAME", "PATH_ACCOUNT", "HOSTNAME_FQDN"],
            name="CustomerPathRecognizer",
            context=["path", "file", "folder", "share", "export", "restore"],
        )

    def load(self) -> None:
        return None

    # -- parsing -------------------------------------------------------------

    @staticmethod
    def _ext(seg: str) -> str:
        stem, dot, ext = seg.rpartition(".")
        return ext.lower() if dot and stem and ext.lower() in _PATH_EXT else ""

    @staticmethod
    def _unknown_ext(seg: str) -> bool:
        """True when ``seg`` ends in something shaped like an extension that is
        on no list (``.xlsl``): two to six letters and digits after a single
        dot, one case throughout. A second dot, a public TLD or an ``@`` makes
        it a host or an address, not a file."""
        stem, dot, ext = seg.rpartition(".")
        if not dot or not stem or stem.endswith(".") or "." in stem or "@" in stem:
            return False
        if ext.lower() in _PATH_EXT:
            return False
        e = ext.casefold()
        return bool(_UNKNOWN_EXT.fullmatch(ext)) and e not in _PUBLIC_TLDS \
            and e not in _SECOND_LEVEL and e not in _NOT_EXT

    @staticmethod
    def _strip_tail(text: str, a: int, b: int) -> int:
        """End of a last segment without the sentence punctuation after it."""
        while b > a and text[b - 1] in ".,;:!?\"\u201d":
            b -= 1
        for opener, closer in ("()", "[]", "{}"):
            while b > a and text[b - 1] == closer and \
                    text[a:b].count(closer) > text[a:b].count(opener):
                b -= 1
        return b

    def _continue_title(self, text: str, a: int, b: int, lim: int) -> int:
        """Extend an unquoted last folder over title-case and all-caps words."""
        global _LOG_WORDS
        if _LOG_WORDS is None:
            from . import pipeline
            _LOG_WORDS = pipeline.LOG_VOCABULARY
        if not (text[a].isupper() or text[a].isdigit()):
            return b
        end = b
        pos = b
        while pos < lim:
            gap = self._GAP.match(text, pos, lim)
            if not gap:
                break
            m = self._WORD.match(text, gap.end(), lim)
            if not m:
                break
            word = m.group(0)
            core = word.rstrip(".,;!?")
            if core in {"-", "\u2013", "&"}:
                pos = m.end()  # joins two capitalised words, only kept if one follows
                continue
            letters = core.lstrip("(")
            if not letters or not (letters[0].isupper() or letters[0].isdigit()) \
                    or letters.casefold().strip("()") in _LOG_WORDS:
                break
            end = m.start() + len(core)
            if core != word:
                break  # "Trust," ends the name and the sentence goes on
            pos = m.end()
        return end

    def _file_end(self, text: str, a: int, lim: int) -> int | None:
        """End of an unquoted file name that starts at ``a``, or None.

        The name runs over words joined by space runs (NBSP included) to the
        first word with a known extension, else to the last word with an
        unknown one, within :data:`_MAX_NAME_WORDS` words. Words may hold a
        colon, a comma, ``$`` and anything else a file name can, so
        "Alpine Trust: 09-16-22 with staff IDs.xlsx" is one name. It stops at
        a line break, a tab, a separator or a quote, which no unquoted name
        crosses. When it errs it errs long: prose between a folder path and a
        file mentioned later on the line is hidden with the name."""
        pos = a
        unknown: int | None = None
        for i in range(_MAX_NAME_WORDS + 1):
            if i:
                gap = self._GAP.match(text, pos, lim)
                if not gap:
                    break
                pos = gap.end()
            w = self._NAME_WORD.match(text, pos, lim)
            if not w:
                break
            end = self._strip_tail(text, w.start(), w.end())
            word = text[w.start():end]
            if self._ext(word):
                return end
            if self._unknown_ext(word):
                unknown = end
            pos = w.end()
        return unknown

    def _segments(self, text: str, pos: int, lim: int, quoted: bool) -> list[tuple[int, int, bool]]:
        """(start, end, is_last) of each segment after the root, separators skipped."""
        segs: list[tuple[int, int, bool]] = []
        while pos < lim:
            sep = self._SEP.match(text, pos, lim)
            if not sep:
                break
            pos = sep.end()
            if quoted:
                m = self._QUOTED_SEG.match(text, pos, lim)
                if not m or not m.group(0).strip():
                    break
                a, b = m.start(), m.start() + len(m.group(0).rstrip())
                last = m.end() >= lim
                segs.append((a, b, last))
                pos = m.end()
                if last:
                    break
                continue
            m = self._INTERIOR.match(text, pos, lim)
            if m:
                segs.append((m.start(), m.end(), False))
                pos = m.end()
                continue
            tok = self._WORD.match(text, pos, lim)
            if not tok:
                break
            a = pos
            b = self._strip_tail(text, a, tok.end())
            if b <= a:
                break
            if not self._ext(text[a:b]):
                end = self._file_end(text, a, lim)
                b = end if end is not None else self._continue_title(text, a, b, lim)
            segs.append((a, b, True))
            break
        return segs

    # -- deciding ------------------------------------------------------------

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        out: list[RecognizerResult] = []
        taken = 0
        for m in self._START.finditer(text):
            if m.start() < taken:
                continue  # inside a path already read
            kind = m.lastgroup
            start = m.start()
            q = text[start - 1] if start > 0 else ""
            lim = len(text)
            quoted = False
            if q in _QUOTES:
                close = text.find(_QUOTES[q], m.end(), min(len(text), m.end() + 400))
                nl = text.find("\n", m.end(), close if close > 0 else len(text))
                if close > 0 and nl < 0:
                    lim, quoted = close, True
            spans: list[tuple[int, int, str]] = []
            pos = m.end()
            if kind == "unc":
                host = self._HOST.match(text, m.end(), lim)
                if not host:
                    continue
                pos = host.end()
                if not self._IP.match(host.group(0)):
                    spans.append((host.start(), host.end(), "HOSTNAME_FQDN"))
            segs = self._segments(text, pos, lim, quoted)
            if not segs:
                continue
            taken = segs[-1][1]
            found = self._decide(text, kind, start, segs, spans)
            for a, b, etype in found:
                out.append(RecognizerResult(entity_type=etype, start=a, end=b, score=0.7,
                                            analysis_explanation=None))
        return [r for r in out if not entities or r.entity_type in entities]

    def _decide(self, text: str, kind: str, start: int, segs: list, spans: list) -> list:
        names = [text[a:b] for a, b, _ in segs]
        last_a, last_b, is_last = segs[-1]
        ext = self._ext(names[-1]) if is_last else ""
        if ext in paths.CODE_EXT or ext in paths.BINARY_EXT:
            return []  # a source file or a program: readable whole
        # An extension on no list (.xlsl): the whole segment is the label,
        # extension included, since nothing says the "extension" is not part
        # of the name.
        unknown = is_last and not ext and self._unknown_ext(names[-1])
        spaced = is_last and (_has_gap(names[-1]) or "%20" in names[-1])
        evidence = names
        if spaced and ext and ext not in paths.DOCUMENT_EXT:
            # "/jobs/run/status answered 200, see agent.log": a spaced last
            # segment found by reading on to an artifact's extension is not
            # evidence of a document path; judge the route by its first word.
            evidence = names[:-1] + [names[-1].split()[0]]
        first = paths.norm(names[0])
        mode = "customer"
        account = None
        if kind == "drive":
            if first == "users":
                return []  # windows_user_path owns profile paths
            if first in paths.WINDOWS_SYSTEM_ROOTS:
                mode = "system"
        elif kind == "unc":
            if first in {"users", "user", "users$"}:
                return []  # the unc-home pattern owns it
        elif kind == "slash":
            if _HTTP_METHOD.search(text[max(0, start - 10):start]) or paths.is_api_root(names[0]):
                return []
            if first in paths.POSIX_SYSTEM_ROOTS:
                mode = "system"
            elif len(segs) < 2:
                return []  # /MIR, /s: a switch, not a path
            elif first in paths.PROFILE_ROOTS:
                account = 1
            elif not ((ext and evidence is names) or unknown or first in paths.LIBRARY_ROOTS
                      or any(_has_gap(n) or "%20" in n or paths.is_structural(n) or n[:1].isupper()
                             for n in evidence)):
                return []  # lower-case and nothing a document path has: an API route
        if any(n.startswith(".") and n.strip(".") for n, (_, _, last) in zip(names, segs)
               if not last):
            mode = "system"  # ~/.cache/<app>, /srv/x/.git/...: application state
        found = list(spans)
        for i, ((a, b, last), name) in enumerate(zip(segs, names)):
            # The last segment is a file name and is labelled whole or not at
            # all: never a folder label over its first words.
            if last and unknown:
                if (mode == "system" and not spaced) or paths.is_structural(name) \
                        or paths.is_version(name):
                    continue
                found.append((a, b, "FILE_NAME"))
                continue
            if last and ext:
                stem_end = b - len(ext) - 1
                stem = text[a:stem_end]
                if mode == "system" and ext not in paths.DOCUMENT_EXT:
                    continue
                if (ext in _ARTIFACT_EXT and not spaced) or paths.is_structural(stem) \
                        or paths.is_version(stem):
                    continue  # agent.log, setup.json: application artifacts keep their names
                found.append((a, stem_end, "FILE_NAME"))
                continue
            if mode == "system":
                continue
            if account is not None and i == account:
                found.append((a, b, "PATH_ACCOUNT"))
                continue
            if i == 0 and kind == "slash" and first in paths.PROFILE_ROOTS:
                continue
            if paths.is_structural(name) or paths.is_version(name):
                continue
            found.append((a, b, "PATH_SEGMENT"))
        return found


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

    #: Microsoft support tracking ids: longer digit runs after the word that
    #: names them, written ``trackingID#2609150040004419`` in confirmation
    #: mails and pasted into notes verbatim. Same context-gating argument as
    #: the eight-digit form: the digits alone are indistinguishable from a
    #: large count, the label in front of them is not.
    TRACKING = re.compile(r"(?i)\btracking\s*id\b\s*(?:number|no\.?)?\s*[:#]?\s*(\d{12,19})\b")

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
            for rx in (self.PHRASE, self.TRACKING)
            for m in rx.finditer(text)
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
        vendor_credential(),
        DomainLogonRecognizer(),
        CustomerDomainRecognizer(),
        onedrive_personal_account(),
        azure_key_vault(),
        exchange_item_id(),
        windows_sid(),
        CertThumbprintRecognizer(),
        onmicrosoft_tenant_domain(),
        FormattedPhoneRecognizer(),
        url_userinfo(),
        http_credential_header(),
        CookieHeaderRecognizer(),
        AwsSecretKeyRecognizer(),
        PrivateKeyBlockRecognizer(),
        windows_user_path(),
        CustomerPathRecognizer(),
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

#: Shared provider endpoints identify the SaaS vendor, not a customer, and
#: destroying them costs real triage value for no privacy gain. The judgement
#: of which hosts those are lives in hider.vendors, shared with the JSON
#: scrubber, so the two paths cannot drift. Note the contrast with
#: TENANT_SITE_HOSTS: there the subdomain IS the customer, here the whole host
#: is the same for every customer on earth.


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
    # Inside a path, "BOARD\BUDGET" is two all-caps folders, not a logon: the
    # logon match would win overlap resolution on length and leave the rest
    # of the folder name ("HRP" in "\HRP BOARD\") readable.
    path_spans = [(r.start, r.end) for r in results
                  if r.entity_type in {"PATH_SEGMENT", "FILE_NAME", "PATH_ACCOUNT"}]
    for r in results:
        value = text[r.start:r.end]
        if r.entity_type == "DOMAIN_LOGON" and any(
                r.start < b and a < r.end for a, b in path_spans):
            continue
        if r.entity_type == "IP_ADDRESS" and ":" not in value:
            if _VERSION_CONTEXT.search(text[max(0, r.start - 40):r.start]):
                continue
        if r.entity_type in {"HOSTNAME_FQDN", "SITE_URL", "URL", "CUSTOMER_DOMAIN"}:
            if vendors.is_vendor_host(value):
                continue
        kept.append(r)
    return kept

