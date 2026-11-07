"""Consistent pseudonyms and the entity vault.

Two properties matter and they pull against each other.

*Utility.* A bundle whose identifiers have been replaced with ``***`` is
useless for triage: you can no longer tell that line 4000 and line 91000 talk
about the same session. So every value maps to a stable, readable pseudonym,
and the pseudonym keeps the shape of what it replaced (an address stays an
address, a site URL stays a site URL) so downstream parsers and the model both
still see well-formed input.

*Reversibility, but only for identifiers.* The engineer needs to turn the
model's answer back into real values, so identifier mappings are kept in a
vault. Live credentials are a different class: holding a JWT or a SAS URL is
itself the risk, so those are destroyed and never enter the vault. That
distinction is enforced by the entity spec, not by the caller.

The mapping key is ``HMAC(vault_key, entity_type + normalised_value)``. The
value never appears in the label, labels are assigned in first-seen order per
type, and the reverse mapping lives only in the vault. In a deployed setting the
vault key is a Key Vault secret and the vault store is per-engagement; the local
JSON file here stands in for that.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from . import entities, paths

ENV_KEY = "HIDER_VAULT_KEY"

#: Common second-level public suffixes, so "contoso.co.uk" pseudonymises the
#: organisation ("contoso"), not "co".
_SECOND_LEVEL_SUFFIX = frozenset({"co", "com", "org", "net", "ac", "gov", "edu"})

#: The ``\Users\`` or ``/Users/`` segment of a Windows profile path, capturing
#: the separator so the pseudonym can be written in the same style.
_USERS_SEGMENT = re.compile(r"([\\/])Users[\\/]", re.IGNORECASE)


def _split_first_path_segment(tail: str) -> tuple[str, str, str]:
    """Split ``account\\rest`` (or ``account/rest``) into its three parts.

    Returns the account segment, the separator that followed it (empty when
    the account is the whole tail) and everything after it.
    """
    m = re.search(r"[\\/]", tail)
    if not m:
        return tail, "", ""
    return tail[:m.start()], m.group(0), tail[m.end():]


#: Path labels key on the name as :func:`hider.paths.norm` reads it, so one
#: file keeps one label however a log layer spelled it: case, ``%20`` for a
#: space, a non-breaking space, a doubled space, a typographic apostrophe.
_PATH_LABEL_TYPES = frozenset({"PATH_SEGMENT", "FILE_NAME", "PATH_ACCOUNT"})


def _digest(key: bytes, entity_type: str, value: str) -> str:
    if entity_type in _PATH_LABEL_TYPES:
        value = paths.norm(value)
    msg = f"{entity_type}\x1f{value.strip().casefold()}".encode()
    return hmac.new(key, msg, sha256).hexdigest()


@dataclass
class EntityVault:
    """Deterministic value -> pseudonym mapping, with the reverse direction."""

    key: bytes = field(default_factory=lambda: _load_key())
    #: digest -> {"type", "label", "value"}
    entries: dict[str, dict[str, str]] = field(default_factory=dict)
    #: label -> original value, the de-tokenisation direction
    by_label: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    # -- labelling ---------------------------------------------------------

    def _next_ordinal(self, entity_type: str) -> int:
        n = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = n
        return n

    def _shape(self, entity_type: str, value: str, ordinal: int) -> str:
        """Build a pseudonym that keeps the shape of what it replaces."""
        spec = entities.BY_NAME.get(entity_type)
        prefix = spec.label_prefix if spec else entity_type.title()

        if entity_type == "UPN_EMAIL" and "@" in value:
            _, _, domain = value.partition("@")
            tenant = self.ordinal_for("_TENANT_DOMAIN", domain.split(".")[0])
            return f"user-{ordinal:02d}@tenant-{tenant:02d}.example"
        if entity_type in {"SITE_URL", "URL"}:
            host = value.split("//", 1)[-1].split("/", 1)[0]
            sub, _, rest = host.partition(".")
            tenant = self.ordinal_for("_TENANT_DOMAIN", sub)
            # The vendor half of the host is kept, under a reserved TLD. Which
            # SaaS a line is about is useful for triage and is not customer
            # data: that host is identical for every tenant on the platform.
            # The subdomain, which IS the customer, is what gets replaced.
            vendor = rest.rsplit(".", 1)[0] if "." in rest else (rest or "site")
            return f"https://tenant-{tenant:02d}.{vendor}.example/spaces/Space-{ordinal:02d}"
        if entity_type in {"IPV4", "IPV6", "IP_ADDRESS"}:
            if ":" in value:
                return f"2001:db8::{ordinal:x}"
            # TEST-NET-3, reserved for documentation, so it can never route.
            return f"203.0.113.{ordinal % 254 + 1}"
        if entity_type == "WINDOWS_USER_PATH":
            # Either separator, and whichever one the original used is the one
            # the pseudonym uses, so a forward-slash path stays recognisable as
            # the thing it replaced. Splitting on backslash alone used to drop
            # the whole tail of a forward-slash path: no leak, but the part of
            # the path that carries the triage value ("AppData/Local/...")
            # disappeared along with the account name.
            m = _USERS_SEGMENT.search(value)
            sep = m.group(1) if m else "\\"
            tail = value[m.end():] if m else value
            _account, found_sep, rest = _split_first_path_segment(tail)
            suffix = f"{found_sep}{rest}" if found_sep else ""
            return f"C:{sep}Users{sep}user-{ordinal:02d}{suffix}"
        if entity_type == "HOSTNAME_FQDN":
            return f"node-{ordinal:02d}.tenant.example"
        if entity_type == "DOMAIN_LOGON":
            domain, _, _user = value.partition("\\")
            d = self.ordinal_for("_LOGON_DOMAIN", domain.lower())
            return f"DOMAIN{d:02d}\\user-{ordinal:02d}"
        if entity_type == "WINDOWS_SID":
            parts = value.split("-")
            # Domain form S-1-5-21-a-b-c(-rid): the subauthority triple is the
            # directory and goes; the RID is kept, because RID 500 meaning
            # "the built-in Administrator" is triage signal and a bare RID
            # without its domain identifies nobody. The Azure AD form
            # S-1-12-1-a-b-c-d is the user's objectId split into four dwords,
            # so every dword goes: keeping even one leaks a quarter of it.
            if value.startswith("S-1-5-21-") and len(parts) == 8:
                return f"S-1-5-21-0-0-{ordinal}-{parts[7]}"
            prefix = "-".join(parts[:4])
            return f"{prefix}-0-0-0-{ordinal}" if len(parts) > 7 else f"{prefix}-0-0-{ordinal}"
        if entity_type == "CERT_THUMBPRINT":
            return f"{ordinal:040x}"
        if entity_type == "TENANT_DOMAIN":
            # Shares the _TENANT_DOMAIN ordinal space with UPN domains and
            # site URLs, so contoso.onmicrosoft.com, contoso.sharepoint.com
            # and anna@contoso.com all point at the same tenant pseudonym and
            # cross-line correlation survives.
            # Under .example, not .com: tenant-01.onmicrosoft.com could be a
            # real tenant, and a pseudonym must never collide with a real
            # value. Same reasoning as the SITE_URL shape above.
            t = self.ordinal_for("_TENANT_DOMAIN", value.split(".")[0])
            tail = ".mail.onmicrosoft.example" if ".mail." in value else ".onmicrosoft.example"
            return f"tenant-{t:02d}{tail}"
        if entity_type == "CUSTOMER_DOMAIN":
            # The TLD is kept so triage can still read "a .org host" / "a .de
            # host"; everything registrable goes. "example" sits between the
            # tenant label and the TLD so the pseudonym cannot collide with a
            # real domain. The org label shares the _TENANT_DOMAIN ordinal
            # space, so backup.fabrikamedu.org correlates with
            # anna@fabrikamedu.org and fabrikamedu.onmicrosoft.com.
            labels = value.lower().strip(".").split(".")
            if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL_SUFFIX:
                suffix, org, subs = ".".join(labels[-2:]), labels[-3], labels[:-3]
            else:
                suffix, org, subs = labels[-1], labels[-2], labels[:-2]
            t = self.ordinal_for("_TENANT_DOMAIN", org)
            base = f"tenant-{t:02d}.example.{suffix}"
            return f"host-{ordinal:02d}.{base}" if subs else base
        if entity_type == "ONEDRIVE_ACCOUNT":
            # Its own ordinal, not the owner's UPN entry: the underscore
            # flattening is not invertible, and a guessed join would silently
            # merge two different users.
            return f"user-{ordinal:02d}"
        if entity_type == "AZURE_KEY_VAULT":
            # Vault name and secret name get separate ordinals so two secrets
            # from one vault stay visibly co-located. Under .example so the
            # pseudonym can never be a real vault host.
            host = value.split("//", 1)[-1].split("/", 1)[0]
            v = self.ordinal_for("_KEY_VAULT", host.split(".")[0].lower())
            base = f"https://vault-{v:02d}.vault.azure.example"
            if "/" in value.split("//", 1)[-1]:
                kind = "secrets" if "/secrets/" in value else "keys" if "/keys/" in value \
                    else "certificates" if "/certificates/" in value else "objects"
                return f"{base}/{kind}/secret-{ordinal:02d}"
            return base if value.startswith("http") else f"vault-{v:02d}.vault.azure.example"
        if entity_type == "PATH_SEGMENT":
            # One label per customer folder, so two files in one folder visibly
            # share it; the separators and structure around it stay as written.
            return f"<Folder-{ordinal:02d}>"
        if entity_type == "FILE_NAME":
            # The stem only: the extension stays outside the span, so
            # "<File-03>.xlsx" still says what kind of file failed.
            return f"<File-{ordinal:02d}>"
        if entity_type == "PATH_ACCOUNT":
            # The account in /home/<account>; its own ordinal space, like the
            # OneDrive segment, since nothing ties it to a UPN reliably.
            return f"user-{ordinal:02d}"
        if entity_type == "EXCHANGE_ITEM_ID":
            return f"<ExchangeId-{ordinal:02d}>"
        if entity_type == "PHONE_NUMBER":
            # 555-01xx is reserved for fiction, so the pseudonym can never be
            # a real subscriber's number.
            return f"+1-555-01{ordinal % 100:02d}"
        if entity_type in {"POD_ID", "WORKER_POD_ID"}:
            return f"pod-{ordinal:02d}"
        return f"<{prefix}-{ordinal:02d}>"

    def ordinal_for(self, entity_type: str, value: str) -> int:
        """Stable ordinal for a value, used for sub-parts such as a domain."""
        d = _digest(self.key, entity_type, value)
        existing = self.entries.get(d)
        if existing:
            return int(existing["label"])
        n = self._next_ordinal(entity_type)
        self.entries[d] = {"type": entity_type, "label": str(n), "value": value}
        return n

    # -- public API --------------------------------------------------------

    def pseudonym(self, entity_type: str, value: str) -> str:
        """Return the stable pseudonym for ``value``, minting one if needed.

        Raises for secret types: those must be destroyed, and routing one
        through the vault would store the credential we are trying to remove.
        """
        canonical = _canonical_type(entity_type, value)
        if canonical in entities.SECRET_TYPES:
            raise ValueError(
                f"{canonical} is a secret; it must be destroyed, not vaulted"
            )
        d = _digest(self.key, _identity_type(canonical), value)
        hit = self.entries.get(d)
        if hit:
            return hit["label"]
        label = self._shape(canonical, value, self._next_ordinal(canonical))
        self.entries[d] = {"type": canonical, "label": label, "value": value}
        self.by_label[label] = value
        return label

    def detokenize(self, text: str) -> str:
        """Turn pseudonyms in a model response back into real values.

        One left-to-right, non-overlapping scan over every form at once:
        bracketed labels and their bare spellings (models routinely drop the
        angle brackets when they quote a token back, so ``<Session-01>`` comes
        home as ``Session-01``). Where two forms match at the same position
        the longest wins, so a short label cannot clip a longer one.

        It used to be a sequence of whole-string ``str.replace`` calls,
        longest label first, and that order is wrong in two ways this is not.
        Two pseudonyms written back to back let a longer label match across
        their boundary and take characters from both: ``203.0.113.2`` twice
        with no separator came back as ``10.20.30.2103.0.113.2``, because
        ``203.0.113.21`` matched astride the join. And a restored value was
        itself rescanned by every later replace, so a real value that happened
        to contain a shorter label's text was corrupted after being restored
        correctly.

        Back-to-back labels make the parse genuinely ambiguous (the text above
        also *starts with* the complete label ``203.0.113.22``), so greedy
        longest-at-position is not enough either: it would take label 22 and
        strand ``03.0.113.2``. The rule that resolves every such case in the
        measured pair matrix is: of all ways to segment the text into labels
        and plain text, take the one that restores the most label characters,
        and where two parses tie, the longer label at the earlier position
        wins. That keeps the documented behaviour for a standalone ambiguous
        token - ``203.0.113.22`` alone is label 22, not label 2 plus a stray
        digit - because the longer single match covers more characters.
        Matched spans are consumed, never rescanned.
        """
        forms = dict(self.by_label)
        for label, value in self.by_label.items():
            if label.startswith("<") and label.endswith(">"):
                forms.setdefault(label[1:-1], value)
        if not forms:
            return text
        lengths = sorted({len(f) for f in forms}, reverse=True)
        n = len(text)
        # best[i]: most label characters restorable in text[i:]; one entry per
        # position, O(len(text) * distinct label lengths), no recursion.
        best = [0] * (n + 1)
        for i in range(n - 1, -1, -1):
            best[i] = best[i + 1]
            for l in lengths:
                if i + l <= n and text[i:i + l] in forms:
                    best[i] = max(best[i], l + best[i + l])
        out: list[str] = []
        i = 0
        while i < n:
            taken = False
            if best[i] > best[i + 1]:
                for l in lengths:  # longest first: ties go to the longer label
                    if i + l <= n and text[i:i + l] in forms                             and l + best[i + l] == best[i]:
                        out.append(forms[text[i:i + l]])
                        i += l
                        taken = True
                        break
            if not taken:
                out.append(text[i])
                i += 1
        return "".join(out)

    # -- persistence -------------------------------------------------------

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(
                {
                    "note": "Stands in for a Key Vault backed store. Holds real "
                            "values, so it is the sensitive half of the system "
                            "and never leaves the engagement boundary.",
                    "entries": self.entries,
                    "counters": self._counters,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path, key: bytes | None = None) -> "EntityVault":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        v = cls(key=key or _load_key(), entries=raw["entries"], _counters=raw["counters"])
        v.by_label = {
            e["label"]: e["value"] for e in raw["entries"].values()
            if not e["type"].startswith("_")
        }
        return v

    @property
    def size(self) -> int:
        return sum(1 for e in self.entries.values() if not e["type"].startswith("_"))


#: Every GUID subtype shares one identity space in the vault.
#:
#: ``recognizers.refine`` types a GUID from the words around it, so the same
#: value can arrive as TENANT_ID on one line and as a bare GUID on the next,
#: where the sentence did not happen to say what it was. Keying the vault on
#: the subtype would then mint two labels for one value and destroy exactly the
#: cross-line correlation the pseudonyms exist to preserve. The digest is taken
#: over the family; the label keeps the prefix of the first sighting, so a
#: value's pseudonym never changes once it has been issued.
_GUID_FAMILY = frozenset({"GUID", "SESSION_GUID", "TENANT_ID", "OBJECT_GUID"})


def _identity_type(canonical: str) -> str:
    return "GUID_FAMILY" if canonical in _GUID_FAMILY else canonical


def _canonical_type(entity_type: str, value: str = "") -> str:
    """Map a detector label back to a spec entity type where they differ.

    Several spec types share one detector label, because the detector genuinely
    cannot tell them apart from the token alone. Where the value settles it, as
    with IPv4 against IPv6, the value decides; otherwise the shared label maps
    to one representative type and the pseudonym prefix reflects that. This is
    a labelling convenience only: handling class (pseudonymise or destroy) is
    identical across every type that shares a label.
    """
    if entity_type in entities.BY_NAME:
        return entity_type
    if entity_type == "IP_ADDRESS":
        return "IPV6" if ":" in value else "IPV4"
    return {
        "EMAIL_ADDRESS": "UPN_EMAIL",
        "WORKER_POD_ID": "POD_ID",
        "SERVICE_INSTANCE_ID": "SERVICE_INSTANCE_ID",
        "IP_ADDRESS": "IPV4",
        "PERSON": "PERSON_NAME",
        "ORGANIZATION": "ORG_NAME",
        "URL": "SITE_URL",
    }.get(entity_type, entity_type)


def _load_key() -> bytes:
    env = os.environ.get(ENV_KEY)
    if env:
        return env.encode()
    # Ephemeral key: pseudonyms stay consistent within the process, and nothing
    # persists by accident. A deployment reads this from Key Vault.
    return secrets.token_bytes(32)


def destroyed_marker(entity_type: str, value: str = "") -> str:
    return f"<REDACTED:{_canonical_type(entity_type, value)}>"
