"""A minimal PKCS#12 (RFC 7292) reader, as the Go port's: password-integrity MACs with
HMAC-SHA-1/224/256/384/512; unencrypted and password-encrypted contents; key bags, shrouded key bags,
certificate bags and nested safe contents. Encryption is PBES2 (AES-CBC or 3DES-CBC under PBKDF2) or
PKCS#12's own 3DES; legacy RC2 and RC4, public-key (enveloped) contents and the PBMAC1 MAC are
refused. Every private key comes out as its PKCS#8 PrivateKeyInfo in a ``bytearray`` the caller
wipes; every buffer that held the password or the plaintext on the way is wiped here.

Written here rather than taken from ``cryptography``'s ``pkcs12.load_key_and_certificates``, which
copies the password into a buffer its bindings free without zeroing, accepts legacy RC2 and RC4
files, and returns a key that can only be re-encrypted under an immutable ``bytes`` password."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hmac as crypto_hmac
from hkdfguard.options.certificate import _der, _pbe
from hkdfguard.options.certificate._der import DerError, Element
from hkdfguard.options.certificate._errors import InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError

_DATA: Final = "1.2.840.113549.1.7.1"
_ENCRYPTED_DATA: Final = "1.2.840.113549.1.7.6"
_KEY_BAG: Final = "1.2.840.113549.1.12.10.1.1"
_SHROUDED_KEY_BAG: Final = "1.2.840.113549.1.12.10.1.2"
_CERT_BAG: Final = "1.2.840.113549.1.12.10.1.3"
_SAFE_CONTENTS_BAG: Final = "1.2.840.113549.1.12.10.1.6"
_X509_CERTIFICATE: Final = "1.2.840.113549.1.9.22.1"
_MAX_SAFE_DEPTH: Final = 4


@dataclass
class Pkcs12Contents:
    """What a PKCS#12 file holds: its certificates, in file order, and its private keys, each a PKCS#8
    PrivateKeyInfo, DER, in a buffer :meth:`wipe` zeroes."""

    certificates: list[x509.Certificate] = field(default_factory=list)
    keys: list[bytearray] = field(default_factory=list)

    def wipe(self) -> None:
        _pbe.wipe(*self.keys)
        self.keys.clear()


def decode(data: bytes | bytearray, password: bytearray | None) -> Pkcs12Contents:
    """Reads a PKCS#12 file with a UTF-8 password - ``None`` for a file without one, which is tried as
    both the empty password and no password, as tools write either.

    Given a password, the file must be protected by it, as an encrypted PEM key must: it must carry
    the integrity MAC - the only thing that proves the password, and without which its encrypted
    contents could be probed for their padding - and every key outside encrypted contents must be in
    a shrouded (password-encrypted) bag. A file that isn't is refused, so a configuration naming a
    password never silently loads a key held in the clear.

    :raises WrongPasswordError: the file's MAC doesn't verify, or its contents don't decrypt
    :raises InvalidCertificateFileError: it isn't a PKCS#12 file, or a password was given and the file
        has no MAC or holds a key in the clear
    :raises UnsupportedCertificateError: legacy RC2/RC4, PBMAC1, or public-key (enveloped) contents
    """
    try:
        pfx = _der.sequence(_der.read(data), "A PKCS#12 file", 2, 3)
        if _der.integer(pfx[0], "The PKCS#12 version") != 3:
            raise UnsupportedCertificateError("Only PKCS#12 version 3 files are supported.")
        auth_type, auth_content = _content_info(pfx[1])
        if auth_type != _DATA or auth_content is None:
            raise UnsupportedCertificateError(f"A PKCS#12 file signed with a public key ({auth_type}) isn't supported.")
        auth_safe = _der.octets(auth_content, "The PKCS#12 contents")
    except DerError as error:
        raise InvalidCertificateFileError(f"Not a PKCS#12 file: {error}") from None

    try:
        budget = _pbe.IterationBudget()
        protected = bool(password)
        # The passwords to try: the one given; for none, the empty BMPString (00 00) and no bytes at all.
        candidates: list[bytearray | None] = [password] if password else [None, bytearray()]
        if len(pfx) == 3:
            candidates = [_verify_mac(pfx[2], auth_safe, candidates, budget)]
        elif protected:
            raise InvalidCertificateFileError(_UNPROTECTED.format(what="has no integrity check (MAC) to prove the password by"))

        failure: WrongPasswordError | None = None
        for candidate in candidates:
            try:
                return _read_authenticated_safe(auth_safe, candidate, budget, protected)
            except WrongPasswordError as wrong:
                failure = wrong
        assert failure is not None
        raise failure
    finally:
        # Unencrypted contents - certificates, and a key in the clear - are in it.
        _pbe.wipe(auth_safe)


_UNPROTECTED: Final = ("The PKCS#12 file {what}, but File.PasswordSecretName names a password for it; re-export it protected by that "
                       "password, or leave PasswordSecretName unset and set AllowUnprotectedPrivateKey.")


def _content_info(element: Element) -> tuple[str, Element | None]:
    items = _der.sequence(element, "A ContentInfo", 1, 2)
    if len(items) == 1:
        return _der.oid(items[0]), None
    content = items[1].expect(_der.CONTEXT_0, "A ContentInfo's content").children()
    if len(content) != 1:
        raise DerError("A ContentInfo's content isn't one element.")
    return _der.oid(items[0]), content[0]


def _verify_mac(mac_data: Element, auth_safe: bytearray, candidates: list[bytearray | None], budget: _pbe.IterationBudget) -> bytearray | None:
    """The candidate password the file's integrity MAC verifies under."""
    try:
        items = _der.sequence(mac_data, "The PKCS#12 MAC", 2, 3)
        digest_info = _der.sequence(items[0], "The MAC's digest", 2, 2)
        algorithm, _ = _der.algorithm(digest_info[0], "The MAC algorithm")
        expected = bytes(_der.octets(digest_info[1], "The MAC"))
        salt = bytes(_der.octets(items[1], "The MAC salt"))
        iterations = _der.integer(items[2], "The MAC iteration count") if len(items) == 3 else 1
    except DerError as error:
        raise InvalidCertificateFileError(f"The PKCS#12 MAC is malformed: {error}") from None
    if algorithm == _pbe.PBMAC1:
        raise UnsupportedCertificateError("The PKCS#12 file's PBMAC1 integrity check isn't supported.")
    if algorithm not in _pbe.DIGESTS:
        raise UnsupportedCertificateError(f"The PKCS#12 MAC algorithm {algorithm} isn't supported.")
    name, hash_algorithm = _pbe.DIGESTS[algorithm]
    for candidate in candidates:
        budget.spend(iterations)
        bmp = _pbe.bmp_password(candidate)
        key = bytearray()
        try:
            key = _pbe.pkcs12_kdf(name, bmp, salt, iterations, _pbe.PKCS12_MAC_ID, hash_algorithm().digest_size)
            mac = crypto_hmac.HMAC(key, hash_algorithm())
            mac.update(auth_safe)
            if hmac.compare_digest(mac.finalize(), expected):
                return candidate
        finally:
            _pbe.wipe(bmp, key)
    raise WrongPasswordError("The PKCS#12 file's integrity check fails: the password is wrong, or the file is corrupt.")


def _read_authenticated_safe(auth_safe: bytearray, password: bytearray | None, budget: _pbe.IterationBudget, protected: bool) -> Pkcs12Contents:
    contents = Pkcs12Contents()
    try:
        try:
            infos = _der.sequence(_der.read(auth_safe), "The PKCS#12 authenticated safe")
        except DerError as error:
            raise InvalidCertificateFileError(f"The PKCS#12 authenticated safe is malformed: {error}") from None
        for info in infos:
            try:
                content_type, content = _content_info(info)
                if content is None:
                    raise DerError("A safe has no content.")
            except DerError as error:
                raise InvalidCertificateFileError(f"The PKCS#12 contents are malformed: {error}") from None
            if content_type == _DATA:
                try:
                    safe = _der.octets(content, "PKCS#12 data")
                except DerError as error:
                    raise InvalidCertificateFileError(f"The PKCS#12 data is malformed: {error}") from None
                try:
                    _read_safe_contents(contents, safe, password, budget, 0, clear_keys_allowed=not protected)
                finally:
                    _pbe.wipe(safe)
            elif content_type == _ENCRYPTED_DATA:
                algorithm, ciphertext = _encrypted_data(content)
                plaintext = _pbe.decrypt(algorithm, password, ciphertext, budget)
                try:
                    # Encrypted under the password, so a key bag in it is protected by it too.
                    _read_safe_contents(contents, plaintext, password, budget, 0, clear_keys_allowed=True)
                except InvalidCertificateFileError as error:
                    # Contents that decrypted to nonsense were decrypted with the wrong password.
                    raise WrongPasswordError(f"The password doesn't decrypt the file's contents ({error}).") from None
                finally:
                    _pbe.wipe(plaintext)
            else:
                raise UnsupportedCertificateError(f"PKCS#12 contents of type {content_type} (public-key encrypted) aren't supported.")
        return contents
    except BaseException:
        contents.wipe()
        raise


def _encrypted_data(content: Element) -> tuple[Element, bytearray]:
    try:
        items = _der.sequence(content, "PKCS#12 encrypted data", 2, 3)
        info = _der.sequence(items[1], "The encrypted content info", 2, 3)
        if len(info) != 3:
            raise DerError("The encrypted content is missing.")
        return info[1], _der.octets(info[2], "The encrypted content", tag=0x80)
    except DerError as error:
        raise InvalidCertificateFileError(f"The PKCS#12 encrypted data is malformed: {error}") from None


def _read_safe_contents(contents: Pkcs12Contents, safe: bytearray | memoryview, password: bytearray | None, budget: _pbe.IterationBudget,
                        depth: int, *, clear_keys_allowed: bool) -> None:
    if depth > _MAX_SAFE_DEPTH:
        raise InvalidCertificateFileError("The PKCS#12 safe contents are nested too deep.")
    try:
        bags = _der.sequence(_der.read(safe), "PKCS#12 safe contents")
    except DerError as error:
        raise InvalidCertificateFileError(f"The PKCS#12 safe contents are malformed: {error}") from None
    for bag in bags:
        try:
            items = _der.sequence(bag, "A PKCS#12 bag", 2, 3)
            bag_type = _der.oid(items[0])
            values = items[1].expect(_der.CONTEXT_0, "A bag's value").children()
            if len(values) != 1:
                raise DerError("A bag's value isn't one element.")
            value = values[0]
        except DerError as error:
            raise InvalidCertificateFileError(f"A PKCS#12 bag is malformed: {error}") from None

        if bag_type == _CERT_BAG:
            certificate = _certificate(value)
            if certificate is not None:
                contents.certificates.append(certificate)
        elif bag_type == _KEY_BAG:
            if not clear_keys_allowed:
                raise InvalidCertificateFileError(_UNPROTECTED.format(what="holds its key in the clear"))
            contents.keys.append(bytearray(value.encoding))
        elif bag_type == _SHROUDED_KEY_BAG:
            contents.keys.append(decrypt_pkcs8(value.encoding, password, budget))
        elif bag_type == _SAFE_CONTENTS_BAG:
            _read_safe_contents(contents, value.encoding, password, budget, depth + 1, clear_keys_allowed=clear_keys_allowed)
        # CRL and secret bags hold nothing a certificate needs.


def _certificate(value: Element) -> x509.Certificate | None:
    try:
        items = _der.sequence(value, "A certificate bag", 2, 2)
        if _der.oid(items[0]) != _X509_CERTIFICATE:
            return None  # an SDSI certificate, say
        inner = items[1].expect(_der.CONTEXT_0, "A certificate bag's value").children()
        if len(inner) != 1:
            raise DerError("A certificate bag's value isn't one element.")
        der = bytes(_der.octets(inner[0], "A certificate"))
    except DerError as error:
        raise InvalidCertificateFileError(f"A PKCS#12 certificate bag is malformed: {error}") from None
    try:
        return x509.load_der_x509_certificate(der)
    except (ValueError, x509.InvalidVersion) as error:  # InvalidVersion isn't a ValueError
        raise InvalidCertificateFileError(f"A PKCS#12 certificate isn't one: {error}") from None


def decrypt_pkcs8(encrypted: bytes | bytearray | memoryview, password: bytearray | None, budget: _pbe.IterationBudget) -> bytearray:
    """Decrypts an EncryptedPrivateKeyInfo with a UTF-8 password: its PrivateKeyInfo, in a new buffer
    the caller wipes.

    :raises WrongPasswordError: the password doesn't decrypt it to a key
    """
    try:
        items = _der.sequence(_der.read(encrypted), "An encrypted private key", 2, 2)
        ciphertext = _der.octets(items[1], "The encrypted key")
    except DerError as error:
        raise InvalidCertificateFileError(f"An encrypted private key is malformed: {error}") from None
    plaintext = _pbe.decrypt(items[0], password, ciphertext, budget)
    try:
        key = _der.sequence(_der.read(plaintext), "A private key", 3)
        _der.integer(key[0], "A private key's version")
    except DerError:
        # A key that decrypted to nonsense was decrypted with the wrong password. The same message as
        # bad padding, so the two can't be told apart.
        _pbe.wipe(plaintext)
        raise WrongPasswordError(_pbe.WRONG_PASSWORD) from None
    return plaintext
