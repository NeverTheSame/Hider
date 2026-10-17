"""Obfuscate a JSON document of customer data, fully offline.

Hider's tiers were built for log lines. A customer JSON export (a support
case, a contact record, a tenant dump) carries most of its PII in *fields*,
where the key says what the value is and the value has no shape to match:
``"account": "Northwind Holdings"`` will never trip a regex. So this layer runs
in four passes:

1. **Harvest.** Walk the document and take every scalar sitting under a
   sensitive key (name, email, account, phone, id, number, ...), or under an
   object hanging off one (reference fields such as ``assigned_to ->
   display_value``). Each value gets a stable label. Person names also register
   their parts, so "Hi Anna," in a comment maps to the same family of labels.
2. **Rewrite.** Sensitive-key values are replaced whole. Every other string is
   first scrubbed of harvested values wherever they occur, then run through the
   Hider pipeline (tier 1 regex, tier 2 local classifier) for what was not
   harvested: emails, GUIDs, IPs, hosts, tokens and free-text names.
3. **Sweep.** A second pass over every string with everything learned in pass
   2, so a value first seen late in the document is also gone from the strings
   that came before it.
4. **Leak check.** Every original value is searched for in the output. The
   result reports how many survived (by label, never by value).

No tier 3, no network. The mapping (label -> original) is the sensitive half
and is returned separately so it can stay on this machine.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

from . import evaluate, localcfg, pipeline, pseudonym

# ---------------------------------------------------------------------------
# Key classification
# ---------------------------------------------------------------------------

_PERSON_WORDS = {
    "name",
    "firstname",
    "lastname",
    "fullname",
    "displayname",
    "givenname",
    "surname",
    "middlename",
    "nickname",
    "contact",
    "caller",
    "requester",
    "requestor",
    "requested",
    "opened",
    "assigned",
    "assignee",
    "owner",
    "user",
    "username",
    "login",
    "author",
    "creator",
    "engineer",
    "manager",
    "tam",
    "sender",
    "recipient",
    "employee",
    "agent",
    "approver",
    "reporter",
    "watcher",
    "member",
    "person",
    "signer",
    "submitter",
    "attendee",
    "participant",
    "commenter",
    "resolver",
    "closer",
    "updater",
    "modifier",
}
_WHOLE_KEY_PERSON = {"to", "cc", "bcc", "from", "replyto", "by", "who"}
_ORG_WORDS = {
    "account",
    "company",
    "organization",
    "organisation",
    "org",
    "tenant",
    "customer",
    "client",
    "vendor",
    "partner",
    "reseller",
    "employer",
    "business",
    "enterprise",
    "firm",
}
_EMAIL_WORDS = {"email", "mail", "upn", "emailaddress"}
_PHONE_WORDS = {"phone", "mobile", "tel", "telephone", "fax", "cell", "msisdn"}
_ADDRESS_WORDS = {
    "address",
    "street",
    "city",
    "zip",
    "zipcode",
    "postal",
    "postcode",
    "country",
    "province",
    "county",
    "location",
    "building",
    "floor",
}
_NET_WORDS = {
    "ip",
    "ipaddress",
    "host",
    "hostname",
    "fqdn",
    "server",
    "machine",
    "computer",
    "device",
    "domain",
    "mac",
    "dns",
    "endpoint",
}
_LINK_WORDS = {"url", "uri", "link", "href", "site", "path", "web", "website"}
_ID_WORDS = {
    "id",
    "ids",
    "sysid",
    "guid",
    "uuid",
    "number",
    "num",
    "no",
    "nr",
    "case",
    "ticket",
    "serial",
    "license",
    "licence",
    "contract",
    "subscription",
    "invoice",
    "reference",
    "ref",
    "correlation",
    "session",
    "sn",
    "key",
    "sid",
    "oid",
    "objectid",
    "tenantid",
    "vat",
    "tax",
    "iban",
    "swift",
    "passport",
    "ssn",
}
_DESCRIPTOR_SUFFIX = {
    "status",
    "state",
    "type",
    "kind",
    "count",
    "total",
    "time",
    "date",
    "start",
    "end",
    "duration",
    "size",
    "rate",
    "percent",
    "version",
    "mode",
    "level",
    "result",
    "utc",
    "at",
    "on",
    "flag",
    "enabled",
}
_SECRET_WORDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "authorization",
    "auth",
    "cookie",
    "privatekey",
    "accesskey",
    "sas",
    "signature",
}

#: Values that are never worth mapping even under a sensitive key, and that
#: must never be substituted into free text (they are ordinary words).
_STOPWORDS = {
    "",
    "system",
    "admin",
    "administrator",
    "guest",
    "none",
    "null",
    "unknown",
    "support",
    "true",
    "false",
    "yes",
    "no",
    "n/a",
    "na",
    "default",
    "user",
    "test",
    "service",
    "other",
    "customer",
    "internal",
    "external",
    "new",
    "open",
    "closed",
    "the",
    "and",
    "for",
    "mr",
    "mrs",
    "ms",
    "dr",
    "team",
}

_LEGAL_SUFFIX = re.compile(
    r"[\s,]+(?:inc|llc|llp|ltd|limited|gmbh|ag|sa|sas|bv|nv|plc|corp|corporation|"
    r"co|company|group|holdings|s\.?a\.?|s\.?r\.?l\.?|oy|ab|as|kk|pty)\.?$",
    re.IGNORECASE,
)


def _words(key: str) -> list[str]:
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return [w for w in re.split(r"[^A-Za-z0-9]+", key.lower()) if w]


def classify_key(key: str) -> str | None:
    """Return the entity type a key implies, or None if it is not sensitive."""
    words = _words(key)
    if not words:
        return None
    joined = "".join(words)
    ws = set(words) | {joined}
    if ws & _SECRET_WORDS:
        return "SECRET"
    if words[-1] in _DESCRIPTOR_SUFFIX:
        return None  # session_status, account_type, case_state: describe, not identify
    if ws & _EMAIL_WORDS:
        return "UPN_EMAIL"
    if ws & _PHONE_WORDS:
        return "PHONE"
    if ws & {"ip", "ipaddress"}:
        return "IPV4"
    if ws & (_NET_WORDS - {"ip", "ipaddress"}):
        return "HOSTNAME_FQDN"
    if ws & _ADDRESS_WORDS:
        return "ADDRESS"
    if ws & _LINK_WORDS:
        return "LINK"
    # "account_id", "user_id", "case_number": an identifier beats the noun.
    if ws & _ID_WORDS and words[-1] in _ID_WORDS:
        return "ID:" + "_".join(words).upper()
    if words[-1] == "by" or joined in _WHOLE_KEY_PERSON or ws & _PERSON_WORDS:
        if "name" in ws and not ws & (_PERSON_WORDS - {"name"}) and len(words) > 1:
            # policy_name, job_name, file_name: free-form, may embed a customer.
            return "NAME:" + "_".join(words).upper()
        return "PERSON_NAME"
    if ws & _ORG_WORDS:
        return "ORG_NAME"
    if ws & _ID_WORDS:
        return "ID:" + "_".join(words).upper()
    return None


# ---------------------------------------------------------------------------
# The scrubber
# ---------------------------------------------------------------------------

_SHORT = 160  # an inherited value longer than this is free text, not a field
_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?.*)?$")
_ID_SHAPE = re.compile(
    r"^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+)$",
    re.IGNORECASE,
)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}")
_PHONE = re.compile(r"(?<![\w+])\+?\d[\d\s().-]{7,}\d(?!\w)")
_TOKEN = re.compile(r"[A-Za-z0-9]+")
_WORD = re.compile(r"[A-Za-z0-9_]+")
#: A field name, not data: left untouched. Keys with an @, a dot-host or a long
#: digit run still go through the scrubber.
#: Every shape a label can take, so the sweep never rewrites inside one.
_LABEL_RE = re.compile(
    r"<[A-Za-z_]+-\d+>|<REDACTED:[A-Z_0-9]+>|user-\d+@tenant-\d+\.example"
    r"|https://tenant-\d+\.[\w.-]*?\.example/spaces/Space-\d+|node-\d+\.tenant\.example"
    r"|tenant-\d+\.example|203\.0\.113\.\d+|\bpod-\d+\b|2001:db8::[0-9a-f]+"
)
#: Server-relative SharePoint paths carry the site name with no host around it.
_SP_PATH = re.compile(r"(?i)/(?:sites|teams|personal|lists)/([^/\s\"'<>?#&|,;]+)")
#: Tenant hosts, including the underscore and mixed-case forms the generic
#: hostname rule refuses.
_TENANT_HOST = re.compile(
    r"(?i)(?<![\w.-])[\w-]+(?:\.[\w-]+)*\.(?:onmicrosoft|sharepoint)\.com(?![\w-])"
)
_PLAIN_KEY = re.compile(r"^(?!.*\d{4})[A-Za-z_][A-Za-z0-9_ ()/-]{0,63}$")
_COMMON: set[str] | None = None


def _common_words() -> set[str]:
    """Lowercase entries of the system word list (macOS /usr/share/dict/words)."""
    global _COMMON
    if _COMMON is None:
        try:
            with open("/usr/share/dict/words", encoding="utf-8") as fh:
                _COMMON = {w.strip() for w in fh if w.strip() and w.strip().islower()}
        except OSError:
            _COMMON = set()
    return _COMMON


def _is_common(word: str) -> bool:
    """Dictionary word, allowing the inflections the word list leaves out."""
    words = _common_words()
    w = word.strip(".,;:!?()\"'")
    cands = {w}
    if w.endswith("s"):
        cands.add(w[:-1])
    if w.endswith("es"):
        cands.add(w[:-2])
    if w.endswith("ies"):
        cands.add(w[:-3] + "y")
    if w.endswith("ed"):
        cands.update({w[:-2], w[:-1]})
    if w.endswith("ing"):
        cands.update({w[:-3], w[:-3] + "e"})
    return any(c in words for c in cands)


_BOUND_L = r"(?<![A-Za-z0-9])"
_BOUND_R = r"(?![A-Za-z0-9])"


def _norm(v: str) -> str:
    return " ".join(v.split()).casefold()


_GREETING = re.compile(
    r"^(?:(?:hi|hello|hey|dear|thanks|thank\s+you|regards|kind\s+regards|best|cheers|"
    r"mr|mrs|ms|dr)\b[\s,.:]*)+",
    re.IGNORECASE,
)
_NAME_TYPES = {"PERSON", "PERSON_NAME", "ORGANIZATION", "ORG_NAME"}


#: Words that make up Microsoft 365, HTTP and backup log templates. The tier 2
#: classifier was trained on prose and reads "Too Many Requests" or
#: "Site Pages" as a name; masking those destroys the signal being triaged.
_LOG_VOCAB = {
    "too",
    "many",
    "request",
    "requests",
    "access",
    "denied",
    "display",
    "name",
    "language",
    "master",
    "site",
    "sites",
    "page",
    "pages",
    "list",
    "lists",
    "library",
    "document",
    "documents",
    "folder",
    "item",
    "items",
    "error",
    "warning",
    "forbidden",
    "not",
    "found",
    "internal",
    "server",
    "service",
    "unavailable",
    "bad",
    "gateway",
    "timeout",
    "unauthorized",
    "conflict",
    "throttled",
    "throttling",
    "retry",
    "after",
    "processing",
    "backup",
    "restore",
    "job",
    "session",
    "policy",
    "object",
    "sharepoint",
    "onedrive",
    "teams",
    "exchange",
    "mailbox",
    "user",
    "group",
    "web",
    "app",
    "catalog",
    "style",
    "form",
    "forms",
    "templates",
    "template",
    "workflow",
    "history",
    "tasks",
    "calendar",
    "contacts",
    "announcements",
    "links",
    "discussion",
    "survey",
    "picture",
    "assets",
    "shared",
    "microsoft",
    "graph",
    "office",
    "owners",
    "members",
    "visitors",
    "gallery",
    "solution",
    "theme",
    "composed",
    "looks",
    "content",
    "type",
    "types",
    "field",
    "fields",
    "view",
    "views",
    "version",
    "versions",
    "attachment",
    "attachments",
    "permission",
    "permissions",
    "role",
    "roles",
    "file",
    "files",
    "upload",
    "download",
    "success",
    "failed",
    "failure",
    "skipped",
    "completed",
    "running",
    "stopped",
}


def _is_noise(text: str) -> bool:
    """A classifier "name" that is really log vocabulary or a code identifier."""
    words = re.findall(r"[A-Za-z]+", text)
    if not words:
        return True
    if len(words) == 1:
        w = words[0]
        if _is_common(w.casefold()) or w.casefold() in _LOG_VOCAB:
            return True
        # SiteAssetsLibrary, SPWebPartManager: code identifiers, not names
        return len(re.findall(r"[A-Z]", w)) >= 3 and any(c.islower() for c in w)
    low = [w.casefold() for w in words]
    return all(_is_common(w) or w in _LOG_VOCAB for w in low) and any(w in _LOG_VOCAB for w in low)


def _trim_name(s: pipeline.Span, line: str) -> pipeline.Span | None:
    """Drop greetings and punctuation the classifier glued onto a name or a
    URL, and classifier hits that are log vocabulary rather than names."""
    text = line[s.start : s.end]
    if s.entity_type in ("SITE_URL", "URL"):
        # "...sites/x: 429" - sentence punctuation is not part of the URL
        end = s.start + len(text.rstrip(".,:;!?'\")"))
        return replace(s, end=end) if end > s.start else None
    if s.entity_type not in _NAME_TYPES:
        return s
    lead = _GREETING.match(text)
    start = s.start + (lead.end() if lead else 0)
    end = s.start + len(text.rstrip(" ,.:;!?"))
    if end - start < 2:
        return None
    if s.tier == "tier2" and _is_noise(line[start:end]):
        return None
    return replace(s, start=start, end=end)


#: Shared hosts of the platforms a case talks about. They identify a vendor,
#: not the customer, and keeping them keeps the text readable.
#: Your own vendor's hosts come from hider.local.json, never from the repo.
_VENDOR_SUFFIXES = (
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office365.com",
    "windows.net",
    "azure.com",
    *localcfg.settings().get("vendor_suffixes", []),
)
_VENDOR_HOSTS = {
    "www",
    "graph",
    "login",
    "outlook",
    "management",
    "portal",
    "api",
    "docs",
    "learn",
    "support",
    "admin",
    *localcfg.settings().get("vendor_hosts", []),
}
_FILE_EXT = {
    "log",
    "txt",
    "json",
    "xml",
    "dll",
    "exe",
    "zip",
    "csv",
    "config",
    "html",
    "htm",
    "pdf",
    "png",
    "jpg",
    "gz",
    "db",
    "md",
    "ps",
    "cs",
    "js",
    "py",
    "sh",
    "ts",
    "rs",
    "go",
    "rb",
    "yml",
    "yaml",
    "ini",
    "bak",
    "tmp",
    "evtx",
    "etl",
}
_FQDN = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}"
    r"[A-Za-z]{2,24}(?![\w-])"
)


def _fqdn_spans(line: str) -> list[pipeline.Span]:
    """Hostnames with three or more labels, beyond Hider's internal-TLD rule."""
    out = []
    for m in _FQDN.finditer(line):
        host = m.group(0)
        labels = host.split(".")
        if labels[-1].lower() in _FILE_EXT:
            continue
        if any(lb != lb.lower() and lb != lb.upper() for lb in labels):
            continue  # Vendor.Product.Proxy is a namespace, not a host
        low = host.lower()
        if low.endswith(_VENDOR_SUFFIXES) and labels[0].lower() in _VENDOR_HOSTS:
            continue
        out.append(pipeline.Span(m.start(), m.end(), "HOSTNAME_FQDN", 0.9, "jsonhost"))
    return out


@dataclass
class Result:
    """The obfuscated document, the label -> original mapping, and run statistics."""

    output: Any
    mapping: dict[str, str]
    stats: dict[str, Any] = field(default_factory=dict)


class JsonScrubber:
    """One obfuscation run over one JSON document.

    Holds the vault and the known-value index, so a value gets the same label
    everywhere it appears in the document. Use a fresh instance per document.
    """

    def __init__(self, tier2: str = "classifier", terms: list[str] | None = None) -> None:
        self.terms = [t.strip() for t in (terms or []) if t and t.strip()]
        self._prefixes: list[str] = []
        tiers: list[pipeline.Tier] = [pipeline.RegexTier()]
        if tier2 != "none":
            tiers.append(evaluate.build_tier2(tier2))
        self.vault = pseudonym.EntityVault()
        self.pipe = pipeline.Pipeline(tiers, vault=self.vault)
        #: normalised original -> label, first sighting wins across all types
        self.known: dict[str, str] = {}
        #: label -> original, the mapping handed back to the user
        self.mapping: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.secrets_destroyed = 0
        self.degraded = 0
        #: first alnum token of a known value -> [(value, token offset)], so
        #: matching known values in text is one dict lookup per word instead
        #: of a regex alternation that has to be recompiled as values arrive
        self._index: dict[str, list[tuple[str, int]]] = {}
        #: log bundles repeat the same line many times; detection is pure
        self._detect_cache: dict[tuple[str, bool], tuple[list, bool]] = {}

    # -- labelling ---------------------------------------------------------

    def _label(self, etype: str, value: str) -> str:
        n = _norm(value)
        if n in self.known:
            return self.known[n]
        if (
            etype in {"PERSON_NAME", "ORG_NAME", "UPN_EMAIL"} or etype.startswith("NAME:")
        ) and _ID_SHAPE.match(value.strip()):
            etype = "ID:ID"  # a reference field's sys_id is an id, not a name
        if etype in {"UPN_EMAIL", "IPV4", "HOSTNAME_FQDN", "PERSON_NAME", "ORG_NAME"}:
            vtype = etype
            if etype == "UPN_EMAIL" and "@" not in value:
                vtype = "PERSON_NAME"
            if etype == "IPV4" and ":" in value:
                vtype = "IPV6"
            label = self.vault.pseudonym(vtype, value)
        else:
            prefix = etype.split(":", 1)[-1]
            vtype = prefix
            label = self.vault.pseudonym(prefix, value)
        self._remember(value, label, vtype)
        return label

    def _remember(
        self, value: str, label: str, etype: str, *, index: bool = True, force: bool = False
    ) -> None:
        n = _norm(value)
        if n in self.known or value in self.mapping:
            return  # already mapped, or it is one of our own labels
        self.known[n] = label
        self.mapping.setdefault(label, value)
        self.counts[etype] = self.counts.get(etype, 0) + 1
        if (
            force
            or index
            and n not in _STOPWORDS
            and (len(n) >= 4 or (len(n) >= 3 and not n.isdigit()))
        ):
            toks = list(_TOKEN.finditer(n))
            if toks:
                # Index under the least-shared token, so a word every URL has
                # ("https", "sharepoint") never becomes a bucket of thousands.
                tok = min(
                    toks, key=lambda t: (len(self._index.get(t.group(0), ())), -len(t.group(0)))
                )
                self._index.setdefault(tok.group(0), []).append((n, tok.start()))

    def _register_parts(self, etype: str, value: str, label: str) -> None:
        """Register sub-values that commonly appear on their own in free text."""
        if etype == "PERSON_NAME":
            parts = re.split(r"[\s,]+", value.strip())
            if len(parts) > 1:
                for p in parts:
                    p = p.strip(".()")
                    if len(p) >= 3 and p.casefold() not in _STOPWORDS and not p.isdigit():
                        self._label("PERSON_NAME", p)
        elif etype == "ORG_NAME":
            core = _LEGAL_SUFFIX.sub("", value.strip())
            if core != value.strip() and len(core) >= 3:
                self._label("ORG_NAME", core)
        elif etype == "UPN_EMAIL" and "@" in value:
            local, _, domain = value.partition("@")
            domain = domain.strip().lower()
            if domain and domain.count(".") >= 1:
                n = self.vault.ordinal_for("_TENANT_DOMAIN", domain.split(".")[0])
                self._remember(domain, f"tenant-{n:02d}.example", "EMAIL_DOMAIN")
            # john.smith@ -> "john smith" is how it shows up in prose
            name = re.sub(r"[._-]+", " ", local).strip()
            if " " in name:
                self._label("PERSON_NAME", name)

    # -- pass 1: harvest ---------------------------------------------------

    def _mappable(self, v: Any) -> bool:
        if isinstance(v, bool) or v is None:
            return False
        if isinstance(v, (int, float)):
            return True
        if not isinstance(v, str):
            return False
        s = v.strip()
        return bool(s) and s.casefold() not in _STOPWORDS and not _DATE_LIKE.match(s)

    def _harvest(self, node: Any, inherited: str | None) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                own = classify_key(str(k))
                self._harvest_value(v, own, inherited)
        elif isinstance(node, list):
            for v in node:
                self._harvest_value(v, None, inherited)

    def _harvest_value(self, v: Any, own: str | None, inherited: str | None) -> None:
        etype = own or inherited
        if isinstance(v, (dict, list)):
            self._harvest(v, etype)
            return
        if etype is None or etype == "SECRET" or not self._mappable(v):
            return
        s = str(v)
        if own is None and (len(s) > _SHORT or "\n" in s):
            return  # free text hanging off a sensitive parent: pass 2 handles it
        if own is not None and (len(s) > _SHORT or "\n" in s) and etype not in {"ADDRESS"}:
            return  # e.g. "customer_comments": scrubbed as text, not erased whole
        label = self._label(etype, s)
        self._register_parts(etype, s, label)

    # -- pass 2/3: rewrite -------------------------------------------------

    def _find_known(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping (start, end, value) hits of known values, longest first."""
        if not self._index and not self._prefixes:
            return []
        hits = []
        guard = [(m.start(), m.end()) for m in _LABEL_RE.finditer(text)]
        for m in _WORD.finditer(text) if self._prefixes else ():
            w = m.group(0).casefold()
            if any(w.startswith(p) for p in self._prefixes) and not any(
                m.start() < ge and gs < m.end() for gs, ge in guard
            ):
                if w not in self.known:
                    self._remember(
                        m.group(0), self.vault.pseudonym("ORG_NAME", m.group(0)), "TERM", force=True
                    )
                hits.append((m.start(), m.end(), w))
        for tok in _TOKEN.finditer(text):
            for v, off in self._index.get(tok.group(0).casefold(), ()):
                a = tok.start() - off
                b = a + len(v)
                if a < 0 or b > len(text):
                    continue
                if a > 0 and text[a - 1].isascii() and text[a - 1].isalnum():
                    continue
                if b < len(text) and text[b].isascii() and text[b].isalnum():
                    continue
                if any(a < ge and gs < b for gs, ge in guard):
                    continue  # inside a label we already placed
                if " ".join(text[a:b].split()).casefold() == v:
                    hits.append((a, b, v))
        hits.sort(key=lambda h: (-(h[1] - h[0]), h[0]))
        kept: list[tuple[int, int, str]] = []
        for h in hits:
            if all(h[1] <= k[0] or k[1] <= h[0] for k in kept):
                kept.append(h)
        return sorted(kept)

    def _substitute(self, text: str) -> str:
        hits = self._find_known(text)
        if not hits:
            return text
        buf, cur = [], 0
        for a, b, v in hits:
            buf.append(text[cur:a])
            buf.append(self.known[v])
            cur = b
        buf.append(text[cur:])
        return "".join(buf)

    def _detect(self, line: str, shaped_only: bool) -> tuple[list, bool]:
        key = (line, shaped_only)
        hit = self._detect_cache.get(key)
        if hit is not None:
            return hit
        found, degraded = self.pipe.detect(line)
        if shaped_only:
            found = [s for s in found if s.tier == "tier1"]
        found = [t for t in (_trim_name(s, line) for s in found) if t is not None]
        found += _fqdn_spans(line)
        found += [
            pipeline.Span(m.start(1), m.end(1), "SITE_NAME", 0.95, "jsonsp")
            for m in _SP_PATH.finditer(line)
            if not _LABEL_RE.fullmatch(m.group(1))
        ]
        found += [
            pipeline.Span(m.start(), m.end(), "TENANT_DOMAIN", 0.95, "jsonsp")
            for m in _TENANT_HOST.finditer(line)
        ]
        if len(self._detect_cache) < 500_000:
            self._detect_cache[key] = (found, degraded)
        return found, degraded

    def _scrub_text(self, text: str, *, shaped_only: bool = False) -> str:
        """Known values and Hider's spans, resolved together on the original text."""
        out_lines = []
        for line in text.split("\n"):
            if not line.strip():
                out_lines.append(line)
                continue
            spans = [
                pipeline.Span(a, b, "KNOWN", 1.0, "known") for a, b, _ in self._find_known(line)
            ]
            found, degraded = self._detect(line, shaped_only)
            self.degraded += int(degraded)
            spans = pipeline.resolve(spans + found)
            buf, cur = [], 0
            for s in spans:
                original = line[s.start : s.end]
                buf.append(line[cur : s.start])
                if s.entity_type == "KNOWN":
                    buf.append(self.known[" ".join(original.split()).casefold()])
                elif pipeline._is_secret(s.entity_type):
                    buf.append(pseudonym.destroyed_marker(s.entity_type, original))
                    self.secrets_destroyed += 1
                elif original in self.mapping:
                    buf.append(original)  # already one of our labels
                else:
                    label = self.known.get(_norm(original)) or self.vault.pseudonym(
                        s.entity_type, original
                    )
                    # A lone dictionary word the classifier called a name
                    # ("Records", "Server") is masked here but not spread
                    # through the document, or every "server" would go.
                    common = s.tier == "tier2" and all(
                        _is_common(w) for w in original.casefold().split()
                    )
                    self._remember(
                        original,
                        label,
                        pseudonym._canonical_type(s.entity_type, original),
                        index=not common,
                    )
                    if s.entity_type in {"EMAIL_ADDRESS", "UPN_EMAIL"}:
                        self._register_parts("UPN_EMAIL", original, label)
                    buf.append(label)
                cur = s.end
            buf.append(line[cur:])
            line = _PHONE.sub(lambda m: self._phone(m.group(0)), "".join(buf))
            out_lines.append(line)
        return "\n".join(out_lines)

    def _phone(self, raw: str) -> str:
        digits = re.sub(r"\D", "", raw)
        # Dates, versions and byte counts also look like digit runs.
        if len(digits) < 9 or len(digits) > 15 or _TIMESTAMP.search(raw):
            return raw
        if re.fullmatch(r"\d+", raw.strip()) and not raw.strip().startswith(("+", "0")):
            return raw  # a bare integer is a count, not a number to dial
        if re.fullmatch(r"[\d.]+", raw.strip()):
            return raw  # 12.3456789, 10.0.17763.1234: decimals and versions
        return self._label("PHONE", raw.strip())

    def _rewrite(self, node: Any, inherited: str | None, sweep: bool) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                own = classify_key(str(k))
                nk = k if _PLAIN_KEY.match(str(k)) else self._scrub_text(str(k), shaped_only=True)
                out[nk] = self._rewrite_value(v, own, inherited, sweep)
            return out
        if isinstance(node, list):
            return [self._rewrite_value(v, None, inherited, sweep) for v in node]
        return node

    def _rewrite_value(self, v: Any, own: str | None, inherited: str | None, sweep: bool) -> Any:
        etype = own or inherited
        if isinstance(v, (dict, list)):
            return self._rewrite(v, etype, sweep)
        if etype == "SECRET" and isinstance(v, str) and v.strip():
            self.secrets_destroyed += 1
            return "<REDACTED:SECRET>"
        if isinstance(v, str) and v in self.mapping:
            return v  # already a label
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            if etype is not None and etype != "SECRET":
                return self.known.get(_norm(str(v)), self._label(etype, str(v)))
            return v
        if not isinstance(v, str):
            return v
        n = _norm(v)
        if n in self.known and n not in _STOPWORDS:
            return self.known[n]
        if sweep:
            return self._substitute(v)
        return self._scrub_text(v)

    # -- entry point -------------------------------------------------------

    def run(self, doc: Any) -> Result:
        """Obfuscate ``doc`` and return the result.

        Registers the user's terms, harvests values under sensitive keys, rewrites
        the document, sweeps it once more for anything that slipped past, and runs
        the leak check. The input document is not modified.
        """
        for t in self.terms:
            # User-named terms ("ACME") are hidden whatever their length;
            # "acme*" hides any word that starts with it.
            if t.endswith("*") and len(t) > 2:
                self._prefixes.append(t[:-1].casefold())
            elif _norm(t) not in self.known:
                self._remember(t, self.vault.pseudonym("ORG_NAME", t), "TERM", force=True)
        self._harvest_value(doc, None, None)
        out = self._rewrite_value(doc, None, None, sweep=False)
        out = self._rewrite_value(out, None, None, sweep=True)
        leaks = self.leak_check(out)
        stats = {
            "mapped_values": len(self.mapping),
            "by_type": dict(sorted(self.counts.items(), key=lambda kv: -kv[1])),
            "secrets_destroyed": self.secrets_destroyed,
            "degraded_lines": self.degraded,
            "leaks": leaks,
        }
        return Result(out, dict(self.mapping), stats)

    def leak_check(self, out: Any) -> list[str]:
        """Labels whose original value still appears in the output text."""
        leaked: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if not _PLAIN_KEY.match(str(k)):
                        walk(k)  # plain field names are kept on purpose
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
            elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
                for _, _, v in self._find_known(str(node)):
                    if len(v) >= 4:
                        leaked.add(self.known[v])

        walk(out)
        return sorted(leaked)


def scrub(doc: Any, tier2: str = "classifier", terms: list[str] | None = None) -> Result:
    """Obfuscate a parsed JSON document with a fresh scrubber; see ``JsonScrubber.run``."""
    return JsonScrubber(tier2=tier2, terms=terms).run(doc)


def parse(text: str) -> tuple[Any, bool]:
    """Parse JSON, or JSON Lines as a fallback. Returns (doc, was_jsonl)."""
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        return rows, True
