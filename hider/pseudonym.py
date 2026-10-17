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
import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from . import entities

ENV_KEY = "HIDER_VAULT_KEY"


def _digest(key: bytes, entity_type: str, value: str) -> str:
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
            tail = value.split("\\Users\\", 1)[-1]
            _, _, rest = tail.partition("\\")
            suffix = f"\\{rest}" if rest else ""
            return f"C:\\Users\\user-{ordinal:02d}{suffix}"
        if entity_type == "HOSTNAME_FQDN":
            return f"node-{ordinal:02d}.tenant.example"
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

        Labels are matched in their bracketed form first, then bare. Models
        routinely drop the angle brackets when they quote a token back at you,
        so ``<Session-01>`` comes home as ``Session-01``; matching only the
        exact form left those un-restored, which looks like the vault failing
        when it is the model reformatting. Longest first, so a short label
        cannot clip a longer one.
        """
        for label in sorted(self.by_label, key=len, reverse=True):
            text = text.replace(label, self.by_label[label])
        bare = {
            label[1:-1]: value for label, value in self.by_label.items()
            if label.startswith("<") and label.endswith(">")
        }
        for label in sorted(bare, key=len, reverse=True):
            text = text.replace(label, bare[label])
        return text

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
    def load(cls, path: str | Path, key: bytes | None = None) -> EntityVault:
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
