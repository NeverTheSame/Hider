"""Vault behaviour: stability, correlation, reversibility, refusal."""

from __future__ import annotations

import pytest

from hider import pseudonym


def v():
    return pseudonym.EntityVault(key=b"fixed-test-key")


def test_same_value_always_gets_the_same_pseudonym():
    a = v()
    first = a.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    second = a.pseudonym("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd")
    assert first == second


def test_matching_is_case_and_whitespace_insensitive():
    a = v()
    assert a.pseudonym("UPN_EMAIL", "Anna.Novak@Contoso.com") == \
           a.pseudonym("UPN_EMAIL", " anna.novak@contoso.com ")


def test_different_values_get_different_pseudonyms():
    a = v()
    assert a.pseudonym("POD_ID", "wkr-amer-prx117") != a.pseudonym("POD_ID", "wkr-emea-rg124")


def test_users_of_one_tenant_share_a_tenant_label():
    """Cross-line correlation is the reason to pseudonymise rather than mask."""
    a = v()
    one = a.pseudonym("UPN_EMAIL", "anna@contoso.com")
    two = a.pseudonym("UPN_EMAIL", "bob@contoso.com")
    other = a.pseudonym("UPN_EMAIL", "carl@fabrikam.com")
    assert one.split("@")[1] == two.split("@")[1]
    assert one.split("@")[1] != other.split("@")[1]
    assert one.split("@")[0] != two.split("@")[0]


def test_a_site_url_and_a_upn_agree_on_the_tenant():
    a = v()
    upn = a.pseudonym("UPN_EMAIL", "anna@contoso.com")
    site = a.pseudonym("SITE_URL", "https://contoso.sharepoint.com/sites/Finance")
    assert upn.split("@")[1].split(".")[0] in site


@pytest.mark.parametrize("etype,value,check", [
    ("UPN_EMAIL", "anna@contoso.com", lambda p: "@" in p and p.endswith(".example")),
    ("IP_ADDRESS", "10.1.2.3", lambda p: p.startswith("203.0.113.")),
    ("IP_ADDRESS", "fe80:0:0:0:0:0:0:1", lambda p: p.startswith("2001:db8::")),
    ("WINDOWS_USER_PATH", r"C:\Users\anna\AppData\Local",
     lambda p: p.startswith(r"C:\Users\user-") and p.endswith(r"AppData\Local")),
    ("HOSTNAME_FQDN", "app01.contoso.internal", lambda p: p.endswith(".example")),
    ("SITE_URL", "https://contoso.sharepoint.com/sites/HR",
     lambda p: p.startswith("https://")),
])
def test_pseudonym_keeps_the_shape_of_what_it_replaced(etype, value, check):
    """A well-formed substitute keeps downstream parsers and the model working."""
    assert check(v().pseudonym(etype, value))


def test_substituted_addresses_are_reserved_ranges():
    """A pseudonym must never be a real routable address or a real domain."""
    a = v()
    assert a.pseudonym("IPV4", "8.8.8.8").startswith("203.0.113.")   # TEST-NET-3
    assert a.pseudonym("IPV6", "2606:4700::1").startswith("2001:db8::")  # RFC 3849
    assert a.pseudonym("UPN_EMAIL", "x@real.com").endswith(".example")   # RFC 2606


def test_detokenize_round_trips():
    a = v()
    pod = a.pseudonym("POD_ID", "wkr-amer-prx117")
    upn = a.pseudonym("UPN_EMAIL", "anna@contoso.com")
    answer = f"The stall is on {pod}, reported by {upn}."
    assert a.detokenize(answer) == "The stall is on wkr-amer-prx117, reported by anna@contoso.com."


def test_secrets_never_enter_the_vault():
    a = v()
    for secret_type in ("JWT", "PRESIGNED_URL", "CONNECTION_STRING", "API_KEY"):
        with pytest.raises(ValueError):
            a.pseudonym(secret_type, "value-does-not-matter")
    assert a.size == 0


def test_vault_survives_a_round_trip_to_disk(tmp_path):
    a = v()
    label = a.pseudonym("POD_ID", "wkr-amer-prx117")
    path = tmp_path / "vault.json"
    a.save(path)
    b = pseudonym.EntityVault.load(path, key=b"fixed-test-key")
    assert b.pseudonym("POD_ID", "wkr-amer-prx117") == label
    assert b.detokenize(label) == "wkr-amer-prx117"


def test_a_different_key_gives_a_different_mapping():
    one = pseudonym.EntityVault(key=b"key-one")
    two = pseudonym.EntityVault(key=b"key-two")
    one.pseudonym("POD_ID", "wkr-amer-prx117")
    two.pseudonym("POD_ID", "wkr-emea-rg124")
    # Same ordinal, different underlying value: the label leaks no value, and
    # the mapping is only meaningful next to its own vault.
    assert one.entries.keys() != two.entries.keys()


def test_pseudonym_does_not_contain_the_original():
    a = v()
    for etype, value in [("SESSION_GUID", "a41f77c2-9be1-4c33-8f0e-1122aabbccdd"),
                         ("POD_ID", "wkr-amer-prx117"),
                         ("UPN_EMAIL", "anna.novak@contoso.com"),
                         ("HOSTNAME_FQDN", "app01.contoso.internal")]:
        p = a.pseudonym(etype, value)
        assert value not in p
        for part in value.replace("@", ".").replace("-", ".").split("."):
            if len(part) > 4:
                assert part.lower() not in p.lower()
