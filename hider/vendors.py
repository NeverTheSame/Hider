"""The one vendor-host list, shared by every path that must leave them readable.

A vendor host (``graph.microsoft.com``, ``api.slack.com``) is identical for
every customer on earth; redacting it costs triage value and protects nobody.
A customer host is anything else. Three places used to hold their own version
of that judgement - the JSON scrubber's suffix/host pair, the recognizers'
public-host suppression, and nothing at all for plain logs - and this module
replaces all of them so the judgement cannot drift.

The model is a pair test, not a bare suffix test, because several vendor
suffixes carry the customer in the first label: ``contoso.slack.com`` is a
customer, ``api.slack.com`` is the vendor. A host is a vendor host only when
its suffix is a known vendor suffix AND its first label is a known
vendor-service label.

The repo list is deliberately conservative core infrastructure. Site-specific
additions come from ``hider.local.json`` (``vendor_suffixes``,
``vendor_hosts``) via :mod:`hider.localcfg`, never from the repo, so an
employer's own estate is never committed.
"""

from __future__ import annotations

from . import localcfg

#: Registrable suffixes operated by platform vendors. Being here does NOT make
#: a host readable by itself - see the pair test in :func:`is_vendor_host`.
VENDOR_SUFFIXES: tuple[str, ...] = (
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "windows.net", "azure.com",
    "slack.com", "googleapis.com", "google.com",
    "amazonaws.com", "github.com", "atlassian.com", "zendesk.com",
    *localcfg.settings().get("vendor_suffixes", []),
)

#: First labels that name a vendor service rather than a tenant.
VENDOR_HOSTS: frozenset[str] = frozenset({
    "www", "graph", "login", "outlook", "management", "portal", "api",
    "docs", "learn", "support", "admin", "sts", "status", "developer",
    *localcfg.settings().get("vendor_hosts", []),
})


def is_vendor_host(host: str) -> bool:
    """True when ``host`` names a shared vendor service, not a customer.

    The suffix match is label-aligned (``notmicrosoft.com`` is not a match for
    ``microsoft.com``), and a bare suffix with no service label in front of it
    is NOT a vendor host: deciding what ``slack.com`` alone means is the
    caller's problem, and failing toward redaction is the right default.
    """
    low = host.strip().strip(".").lower()
    labels = low.split(".")
    if len(labels) < 3:
        return False
    first, rest = labels[0], ".".join(labels[1:])
    # Label-aligned suffix match: "notmicrosoft.com" must not pass for
    # "microsoft.com". The old jsonscrub check used a plain endswith and had
    # exactly that hole.
    suffix_ok = any(rest == s or rest.endswith("." + s) for s in _SUFFIXES)
    return suffix_ok and first in VENDOR_HOSTS


_SUFFIXES = tuple(s.lower().lstrip(".") for s in VENDOR_SUFFIXES)
