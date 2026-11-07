"""The PKCS#12 and encrypted PKCS#8 reader against files other tools wrote, in testdata (the Go
port's fixtures):

    openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
    openssl pkcs12 -export -in rsa.crt -inkey rsa.key -out openssl-aes.pfx -passout file:pw.txt     # PBES2 AES-256, SHA-256 MAC
    openssl pkcs12 -export ... -out openssl-3des.pfx -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
    openssl pkcs12 -export -in ec.crt -inkey ec.key -out openssl-ec.pfx -passout file:pw.txt
    openssl pkcs12 -export ... -out openssl-nopass.pfx -passout pass: -keypbe NONE -certpbe NONE
    openssl pkcs12 -export ... -out openssl-rc2.pfx -passout file:pw.txt -legacy                    # RC2-40 certificates
    openssl pkcs12 -export ... -out openssl-plainkey.pfx -passout file:pw.txt -keypbe NONE -certpbe NONE  # a MAC, the key in the clear
    openssl pkcs8 -topk8 -in rsa.key -out rsa-encrypted.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 100000 -passout file:pw.txt
    openssl pkcs8 -topk8 -in ec.key -out ec-encrypted.key -v2 aes-128-cbc -passout file:pw.txt

and, from openssl-aes.pfx, by .NET 10 on Windows 11: dotnet-default.pfx (3DES, SHA-1 MAC, as Windows
writes), dotnet-nopassword.pfx, dotnet-aes.pfx (PBES2 AES-256 SHA-256) and dotnet-encrypted.key."""

from __future__ import annotations

import base64
import hashlib

import pytest
from certificate_test_support import PASSWORD, ec_key, fixture, fixture_certificate, rsa_key, self_signed
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, PrivateFormat, pkcs12
from hkdfguard.options.certificate import InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError, _der, _files, _pbe, _pkcs12


def password(text: str = PASSWORD) -> bytearray:
    return bytearray(text.encode("utf-8"))


@pytest.mark.parametrize(("file", "secret", "certificate"), [
    ("openssl-aes.pfx", PASSWORD, "rsa.crt"),
    ("openssl-3des.pfx", PASSWORD, "rsa.crt"),
    ("openssl-ec.pfx", PASSWORD, "ec.crt"),
    ("openssl-nopass.pfx", None, "rsa.crt"),
    ("dotnet-default.pfx", PASSWORD, "rsa.crt"),
    ("dotnet-aes.pfx", PASSWORD, "rsa.crt"),
    ("dotnet-nopassword.pfx", None, "rsa.crt"),
])
def test_other_tools_pkcs12_files_are_read(file: str, secret: str | None, certificate: str) -> None:
    expected = fixture_certificate(certificate)
    contents = _pkcs12.decode(fixture(file).read_bytes(), None if secret is None else password(secret))
    try:
        assert contents.certificates == [expected]
        assert len(contents.keys) == 1
        assert _files.private_key_of(contents.keys[0]).public_key() == expected.public_key()
    finally:
        keys = list(contents.keys)
        contents.wipe()
    assert all(not any(key) for key in keys), "the keys aren't wiped"
    if secret is not None:
        with pytest.raises(WrongPasswordError):
            _pkcs12.decode(fixture(file).read_bytes(), password("wrong"))


@pytest.mark.parametrize(("file", "certificate"), [("rsa-encrypted.key", "rsa.crt"), ("ec-encrypted.key", "ec.crt"),
                                                   ("dotnet-encrypted.key", "rsa.crt")])
def test_other_tools_encrypted_pkcs8_keys_are_read(file: str, certificate: str) -> None:
    data = bytearray(fixture(file).read_bytes())
    key = _files.decrypt_pem_key(data, password(), file)
    assert _files.private_key_of(key).public_key() == fixture_certificate(certificate).public_key()
    with pytest.raises(WrongPasswordError):
        _files.decrypt_pem_key(data, password("wrong"), file)


def _without_mac(data: bytes) -> bytes:
    """The PFX ``data`` with its MacData left out: version and contents only, as ``-nomac`` writes it."""
    pfx = _der.sequence(_der.read(data), "A PKCS#12 file", 3, 3)
    body = bytes(pfx[0].encoding) + bytes(pfx[1].encoding)
    length = len(body)
    header = bytes([0x30, length]) if length < 0x80 else bytes([0x30, 0x80 | ((length.bit_length() + 7) // 8)]) + length.to_bytes(
        (length.bit_length() + 7) // 8, "big")
    return header + body


@pytest.mark.parametrize("file", ["openssl-aes.pfx", "openssl-nopass.pfx", "openssl-plainkey.pfx"])
def test_a_file_without_a_mac_is_refused_when_a_password_is_given(file: str) -> None:
    # The MAC is what proves the password: without one, a wrong password wouldn't be noticed for a key
    # in the clear, and an encrypted key's padding could be probed.
    data = _without_mac(fixture(file).read_bytes())
    for given in (password(), password("wrong")):
        with pytest.raises(InvalidCertificateFileError, match="has no integrity check"):
            _pkcs12.decode(data, given)


def test_a_file_without_a_mac_or_a_password_is_still_read_without_one() -> None:
    contents = _pkcs12.decode(_without_mac(fixture("openssl-nopass.pfx").read_bytes()), None)
    try:
        assert contents.certificates == [fixture_certificate("rsa.crt")]
        assert len(contents.keys) == 1
    finally:
        contents.wipe()


def test_a_key_in_the_clear_is_refused_when_a_password_is_given() -> None:
    # The MAC verifies, but the key it covers isn't encrypted: refused, as a plain PEM key is.
    with pytest.raises(InvalidCertificateFileError, match="holds its key in the clear"):
        _pkcs12.decode(fixture("openssl-plainkey.pfx").read_bytes(), password())
    with pytest.raises(WrongPasswordError):
        _pkcs12.decode(fixture("openssl-plainkey.pfx").read_bytes(), password("wrong"))


def test_every_failed_decryption_says_the_same() -> None:
    # Bad padding and a plaintext that isn't a key read alike, so neither can be told from the other.
    not_a_key = _pbe.encrypt_pkcs8(bytearray(b"padded correctly, but no key"), password())
    for data, given in ((not_a_key, password()), (not_a_key, password("wrong"))):
        with pytest.raises(WrongPasswordError) as error:
            _pkcs12.decrypt_pkcs8(data, given, _pbe.IterationBudget())
        assert str(error.value) == _pbe.WRONG_PASSWORD


def version_9(certificate: x509.Certificate) -> bytes:
    """``certificate``'s DER claiming X.509 version 9 - which ``cryptography`` refuses with
    ``InvalidVersion``, not a ``ValueError`` - its signature no longer matching."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    v3 = b"\xa0\x03\x02\x01\x02"  # [0] EXPLICIT INTEGER 2: version 3
    assert der.count(v3) == 1
    return der.replace(v3, b"\xa0\x03\x02\x01\x09")


def test_a_certificate_with_an_unknown_version_is_an_invalid_file() -> None:
    bad = version_9(fixture_certificate("rsa.crt"))
    with pytest.raises(x509.InvalidVersion):
        x509.load_der_x509_certificate(bad)
    with pytest.raises(InvalidCertificateFileError, match="isn't a PEM or DER certificate"):
        _files.parse_certificates(bytearray(bad), "bad.cer")
    pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bad) + b"-----END CERTIFICATE-----\n"
    with pytest.raises(InvalidCertificateFileError, match="isn't one"):
        _files.parse_certificates(bytearray(pem), "bad.pem")


def test_a_legacy_rc2_file_is_refused_saying_how_to_re_export_it() -> None:
    with pytest.raises(UnsupportedCertificateError, match="re-export it with AES"):
        _pkcs12.decode(fixture("openssl-rc2.pfx").read_bytes(), password())


def test_a_legacy_encrypted_pem_key_is_refused() -> None:
    legacy = bytearray(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00000000000000000000000000000000\n\n"
                       b"AAAA\n-----END RSA PRIVATE KEY-----\n")
    with pytest.raises(UnsupportedCertificateError, match="openssl pkcs8 -topk8"):
        _files.decrypt_pem_key(legacy, password(), "legacy.key")
    with pytest.raises(InvalidCertificateFileError):
        _files.decrypt_pem_key(bytearray(b"no key here"), password(), "none.key")


def test_what_isnt_a_pkcs12_file_is_refused() -> None:
    for data in (b"", b"\x30\x03\x02\x01", b"not a pfx at all", fixture("rsa.crt").read_bytes()):
        with pytest.raises(InvalidCertificateFileError):
            _pkcs12.decode(data, password())


def _to_ber(element: _der.Element) -> bytes:
    """``element`` re-encoded as NSS writes BER: every constructed element with an indefinite length,
    and every OCTET STRING longer than 16 bytes split into a constructed one of 16-byte segments."""
    if element.constructed:
        return bytes([element.tag, 0x80]) + b"".join(_to_ber(child) for child in element.children()) + b"\x00\x00"
    if element.tag == _der.OCTET_STRING and len(element.contents) > 16:
        data = bytes(element.contents)
        segments = b"".join(_der.encode(_der.OCTET_STRING, data[i:i + 16]) for i in range(0, len(data), 16))
        return bytes([0x24, 0x80]) + segments + b"\x00\x00"
    return bytes(element.encoding)


def test_a_ber_pfx_is_read_as_its_der_is() -> None:
    # Only the outer PFX and its unencrypted contents are rewritten: the MAC covers the authenticated
    # safe's bytes, so it is recomputed over the BER, as a tool writing BER computes it.
    original = pkcs12.serialize_key_and_certificates(b"x", rsa_key(), None, None, serialization.NoEncryption())
    pfx = _der.sequence(_der.read(original), "pfx")
    content_info = _der.sequence(pfx[1], "authSafe")
    auth_safe = _der.octets(content_info[1].children()[0], "authSafe data")
    ber_safe = _to_ber(_der.read(auth_safe))
    ber = (bytes([0x30, 0x80]) + bytes(pfx[0].encoding)
           + bytes([0x30, 0x80]) + bytes(content_info[0].encoding) + bytes([0xA0, 0x80])
           + _to_ber(_der.read(_der.encode(_der.OCTET_STRING, ber_safe))) + b"\x00\x00" + b"\x00\x00" + b"\x00\x00")
    contents = _pkcs12.decode(ber, None)
    assert len(contents.certificates) == 0
    assert len(contents.keys) == 1
    assert _files.private_key_of(contents.keys[0]).public_key() == rsa_key().public_key()


def test_files_cryptography_writes_are_read_with_every_encryption() -> None:
    certificate = self_signed(ec_key())
    for encryption in (BestAvailableEncryption(PASSWORD.encode()),
                       PrivateFormat.PKCS12.encryption_builder().kdf_rounds(5000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                       .hmac_hash(hashes.SHA1()).build(PASSWORD.encode()),
                       PrivateFormat.PKCS12.encryption_builder().kdf_rounds(5000).key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
                       .hmac_hash(hashes.SHA512()).build(PASSWORD.encode())):
        data = pkcs12.serialize_key_and_certificates(b"tls", ec_key(), certificate, None, encryption)
        contents = _pkcs12.decode(data, password())
        assert contents.certificates == [certificate]
        assert _files.private_key_of(contents.keys[0]).public_key() == ec_key().public_key()


def test_pbkdf2_and_the_reencryption_are_what_others_read() -> None:
    # The throwaway re-encryption is ordinary encrypted PKCS#8, which cryptography (OpenSSL) reads back.
    info = bytearray(rsa_key().private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for iterations in (1, 2048):
        encrypted = _pbe.encrypt_pkcs8(info, password(), iterations)
        loaded = serialization.load_der_private_key(encrypted, PASSWORD.encode())
        assert loaded.public_key() == rsa_key().public_key()
        assert _pkcs12.decrypt_pkcs8(encrypted, password(), _pbe.IterationBudget()) == info


def test_the_bmp_password_is_big_endian_utf16_with_a_terminator() -> None:
    assert _pbe.bmp_password(None) == bytearray(b"\x00\x00")
    assert _pbe.bmp_password(bytearray()) == bytearray()
    for text in ("a", "pässwörd", "€", "𝄞 clef"):
        assert _pbe.bmp_password(bytearray(text.encode("utf-8"))) == bytearray(text.encode("utf-16-be") + b"\x00\x00")
    for bad in (b"\xff", b"\xc3", b"\xed\xa0\x80", b"\xc0\xaf"):
        with pytest.raises(WrongPasswordError):
            _pbe.bmp_password(bytearray(bad))


def test_the_pkcs12_kdf_is_rfc_7292s() -> None:
    # RFC 7292 B.2 written out once more, plainly, for a SHA-1 key of 24 bytes (two digests).
    bmp, salt, iterations = _pbe.bmp_password(password()), b"saltsalt", 3
    v, u = 64, 20

    def fill(data: bytes) -> bytes:
        return bytes(data[i % len(data)] for i in range(v * ((len(data) + v - 1) // v)))

    i = bytearray(fill(salt) + fill(bytes(bmp)))
    out = b""
    while len(out) < 24:
        a = hashlib.sha1(bytes([1]) * v + bytes(i)).digest()
        for _ in range(iterations - 1):
            a = hashlib.sha1(a).digest()
        out += a
        b = int.from_bytes(bytes(a[k % u] for k in range(v)), "big")
        for block in range(0, len(i), v):
            value = (int.from_bytes(i[block:block + v], "big") + b + 1) % (1 << (8 * v))
            i[block:block + v] = value.to_bytes(v, "big")
    assert _pbe.pkcs12_kdf("sha1", bmp, salt, iterations, 1, 24) == bytearray(out[:24])


def test_an_iteration_count_is_bounded() -> None:
    budget = _pbe.IterationBudget()
    for bad in (0, -1, _pbe.MAX_ITERATIONS + 1):
        with pytest.raises(InvalidCertificateFileError):
            budget.spend(bad)
    for _ in range(4):
        budget.spend(_pbe.MAX_ITERATIONS)
    with pytest.raises(InvalidCertificateFileError):
        budget.spend(1)


def test_a_derivation_is_charged_per_hash_block() -> None:
    # PKCS#12's own KDF runs the iterations once per 20 bytes it makes: a 3DES key and its IV are three
    # runs, so a file can't buy three times the work the budget allows by using it.
    budget = _pbe.IterationBudget()
    budget.spend(_pbe.MAX_ITERATIONS, 3)
    assert budget.spent == 3 * _pbe.MAX_ITERATIONS
    with pytest.raises(InvalidCertificateFileError):
        budget.spend(_pbe.MAX_ITERATIONS // 3 + 1, 3)
    budget.spend(_pbe.MAX_ITERATIONS)


def test_the_der_reader_refuses_what_isnt_der() -> None:
    for data in (b"\x30", b"\x30\x05\x02\x01", b"\x04\x80\x00\x00", b"\x30\x80\x02\x01\x01", b"\x30\x85\xff\xff\xff\xff\xff",
                 b"\x02\x01\x01\x00"):
        with pytest.raises(_der.DerError):
            _der.read(data)
    assert _der.oid(_der.read(_der.encode_oid("1.2.840.113549.1.12.10.1.2"))) == "1.2.840.113549.1.12.10.1.2"
    assert _der.integer(_der.read(_der.encode_integer(600000)), "n") == 600000
