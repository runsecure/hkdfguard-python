"""DistinguishedName: a configured subject against a certificate's, whole and ignoring case."""

from __future__ import annotations

import pytest
from certificate_test_support import ec_key, name_of, self_signed
from cryptography import x509
from cryptography.x509.oid import NameOID
from hkdfguard.options.certificate import DistinguishedName


def matches(configured: str, name: x509.Name) -> bool:
    return DistinguishedName.parse(configured).matches(DistinguishedName.of(name))


def test_a_subject_matches_the_certificates_whole_subject_ignoring_case() -> None:
    certificate = self_signed(ec_key(), "CN=api.example.com, O=Contoso")
    name = certificate.subject
    assert matches("CN=api.example.com, O=Contoso", name)
    assert matches("cn=API.Example.COM;o=contoso", name)
    assert matches("  CN = api.example.com ,O=Contoso  ", name)
    assert matches("2.5.4.3=api.example.com, OID.2.5.4.10=Contoso", name)
    # Never a substring, never another order, never part of the name.
    assert not matches("CN=api", name)
    assert not matches("CN=api.example.com", name)
    assert not matches("O=Contoso, CN=api.example.com", name)
    assert not matches("CN=api.example.com, O=Contoso, C=US", name)
    assert not matches("CN=api.example.com, OU=Contoso", name)


def test_the_value_is_compared_decoded_whatever_its_string_type() -> None:
    printable = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api", x509.name._ASN1Type.PrintableString)])
    bmp = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "API", x509.name._ASN1Type.BMPString)])
    utf8 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ápi")])
    assert matches("CN=api", printable)
    assert matches("CN=api", bmp)
    assert matches("CN=ápi", utf8)
    assert not matches("CN=api", utf8)


def test_case_is_ignored_character_for_character() -> None:
    assert matches("CN=STRASSE", name_of("CN=strasse"))
    assert not matches("CN=STRASSE", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "straße")]))


def test_a_subject_value_may_be_quoted_or_escaped() -> None:
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Contoso, Ltd"), x509.NameAttribute(NameOID.COMMON_NAME, 'a "b" +c')])
    assert matches('CN="a ""b"" +c", O="Contoso, Ltd"', name)
    assert matches('CN=a \\"b\\" \\+c, O=Contoso\\, Ltd', name)
    assert matches("CN=a \\22b\\22 \\2Bc, O=Contoso\\2C Ltd", name)
    assert matches("CN=caf\\C3\\A9", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "café")]))
    # An escaped trailing space is kept; an unescaped one isn't.
    assert matches("CN=a\\ ", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a ")]))
    assert matches("CN=a   ", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")]))


def test_a_multi_valued_relative_name_matches_its_attributes_in_any_order() -> None:
    name = x509.Name([x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "a"),
                                                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "b")])])
    assert matches("CN=a + OU=b", name)
    assert matches("OU=b+CN=a", name)
    assert not matches("CN=a, OU=b", name)
    assert not matches("CN=a + OU=b + O=c", name)


@pytest.mark.parametrize("text", ["", "CN", "api.example.com", "ZZ=x", "CN=a, ", 'CN="a', 'CN="a" b', "CN=a\\", "1=x", "OID.x.y=z", "2.5.-4=x"])
def test_what_isnt_a_distinguished_name_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        DistinguishedName.parse(text)


def test_a_name_is_rendered_as_dotnet_renders_it() -> None:
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Contoso, Ltd"),
                      x509.NameAttribute(x509.ObjectIdentifier("1.2.3.4"), "x"), x509.NameAttribute(NameOID.COMMON_NAME, " padded ")])
    assert str(DistinguishedName.of(name)) == 'CN=" padded ", OID.1.2.3.4=x, O="Contoso, Ltd", C=US'
    assert repr(DistinguishedName.parse("CN=a+O=b")) == "DistinguishedName('CN=a + O=b')"
