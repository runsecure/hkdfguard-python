"""The macOS keychains, through ctypes and the Security framework, loaded by their absolute system
paths: CurrentUser is the login keychain and LocalMachine the System keychain, and the search is
restricted to that one keychain. A certificate with its private key is an identity
(kSecClassIdentity); its key stays in the keychain, and every signature is a SecKeyCreateSignature
call and every decryption a SecKeyCreateDecryptedData call. Only My - the keychain itself - is a
store here, as in the Go port.

Not run by this repository's own tests on a Mac yet: HKDFGUARD_TEST_MACOS_KEYCHAIN=1 runs the
keychain round trip there. Imported only on macOS."""

from __future__ import annotations

import ctypes
import functools
import os
import threading
import warnings
from ctypes import POINTER, byref, c_char_p, c_int32, c_long, c_uint32, c_void_p
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.utils import CryptographyDeprecationWarning
from hkdfguard.abstractions import ObjectClosedError
from hkdfguard.options.certificate._errors import CertificateError, NoPrivateKeyError, UnsupportedCertificateError
from hkdfguard.options.certificate._keys import OsKey, RsaDecryption, RsaSignature
from hkdfguard.options.certificate._options import StoreLocation, StoreName

_CORE_FOUNDATION: Final = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_SECURITY: Final = "/System/Library/Frameworks/Security.framework/Security"
_SYSTEM_KEYCHAIN: Final = "/Library/Keychains/System.keychain"
_ERR_SEC_ITEM_NOT_FOUND: Final = -25300
_ERR_SEC_NO_SUCH_KEYCHAIN: Final = -25294
_K_CF_STRING_ENCODING_UTF8: Final = 0x08000100
_SIGN: Final = 0  # kSecKeyOperationTypeSign
_DECRYPT: Final = 3  # kSecKeyOperationTypeDecrypt

_RSA_PKCS1: Final = {"sha1": "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1", "sha224": "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224",
                     "sha256": "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256", "sha384": "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384",
                     "sha512": "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512"}
_RSA_PSS: Final = {"sha1": "kSecKeyAlgorithmRSASignatureDigestPSSSHA1", "sha224": "kSecKeyAlgorithmRSASignatureDigestPSSSHA224",
                   "sha256": "kSecKeyAlgorithmRSASignatureDigestPSSSHA256", "sha384": "kSecKeyAlgorithmRSASignatureDigestPSSSHA384",
                   "sha512": "kSecKeyAlgorithmRSASignatureDigestPSSSHA512"}
_ECDSA: Final = {"sha1": "kSecKeyAlgorithmECDSASignatureDigestX962SHA1", "sha224": "kSecKeyAlgorithmECDSASignatureDigestX962SHA224",
                 "sha256": "kSecKeyAlgorithmECDSASignatureDigestX962SHA256", "sha384": "kSecKeyAlgorithmECDSASignatureDigestX962SHA384",
                 "sha512": "kSecKeyAlgorithmECDSASignatureDigestX962SHA512"}
_RSA_OAEP: Final = {"sha1": "kSecKeyAlgorithmRSAEncryptionOAEPSHA1", "sha224": "kSecKeyAlgorithmRSAEncryptionOAEPSHA224",
                    "sha256": "kSecKeyAlgorithmRSAEncryptionOAEPSHA256", "sha384": "kSecKeyAlgorithmRSAEncryptionOAEPSHA384",
                    "sha512": "kSecKeyAlgorithmRSAEncryptionOAEPSHA512"}


class _Frameworks:
    """CoreFoundation and Security, with the signatures of the calls made."""

    def __init__(self) -> None:
        core = ctypes.CDLL(_CORE_FOUNDATION)
        security = ctypes.CDLL(_SECURITY)
        self.core, self.security = core, security
        core.CFRelease.argtypes = [c_void_p]
        core.CFRetain.argtypes = [c_void_p]
        core.CFRetain.restype = c_void_p
        core.CFGetTypeID.argtypes = [c_void_p]
        core.CFGetTypeID.restype = ctypes.c_ulong
        core.CFArrayGetTypeID.restype = ctypes.c_ulong
        core.CFArrayCreate.argtypes = [c_void_p, POINTER(c_void_p), c_long, c_void_p]
        core.CFArrayCreate.restype = c_void_p
        core.CFArrayGetCount.argtypes = [c_void_p]
        core.CFArrayGetCount.restype = c_long
        core.CFArrayGetValueAtIndex.argtypes = [c_void_p, c_long]
        core.CFArrayGetValueAtIndex.restype = c_void_p
        core.CFDictionaryCreate.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_void_p), c_long, c_void_p, c_void_p]
        core.CFDictionaryCreate.restype = c_void_p
        core.CFDataCreate.argtypes = [c_void_p, c_char_p, c_long]
        core.CFDataCreate.restype = c_void_p
        core.CFDataGetBytePtr.argtypes = [c_void_p]
        core.CFDataGetBytePtr.restype = c_void_p
        core.CFDataGetLength.argtypes = [c_void_p]
        core.CFDataGetLength.restype = c_long
        core.CFErrorGetCode.argtypes = [c_void_p]
        core.CFErrorGetCode.restype = c_long
        core.CFErrorCopyDescription.argtypes = [c_void_p]
        core.CFErrorCopyDescription.restype = c_void_p
        core.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
        core.CFStringGetCString.restype = ctypes.c_bool
        security.SecKeychainOpen.argtypes = [c_char_p, POINTER(c_void_p)]
        security.SecKeychainOpen.restype = c_int32
        security.SecKeychainGetStatus.argtypes = [c_void_p, POINTER(c_uint32)]
        security.SecKeychainGetStatus.restype = c_int32
        security.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]
        security.SecItemCopyMatching.restype = c_int32
        security.SecIdentityCopyCertificate.argtypes = [c_void_p, POINTER(c_void_p)]
        security.SecIdentityCopyCertificate.restype = c_int32
        security.SecIdentityCopyPrivateKey.argtypes = [c_void_p, POINTER(c_void_p)]
        security.SecIdentityCopyPrivateKey.restype = c_int32
        security.SecCertificateCopyData.argtypes = [c_void_p]
        security.SecCertificateCopyData.restype = c_void_p
        security.SecKeyIsAlgorithmSupported.argtypes = [c_void_p, c_long, c_void_p]
        security.SecKeyIsAlgorithmSupported.restype = ctypes.c_bool
        security.SecKeyCreateSignature.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]
        security.SecKeyCreateSignature.restype = c_void_p
        security.SecKeyCreateDecryptedData.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]
        security.SecKeyCreateDecryptedData.restype = c_void_p
        security.SecCopyErrorMessageString.argtypes = [c_int32, c_void_p]
        security.SecCopyErrorMessageString.restype = c_void_p

    def constant(self, library: Any, name: str) -> int:
        """The value of a global CFTypeRef constant (kSecClass, kSecKeyAlgorithm..., kCFBooleanTrue)."""
        value = c_void_p.in_dll(library, name).value
        if not value:
            raise UnsupportedCertificateError(f"The Security framework has no {name}.")
        return value

    def address(self, library: Any, name: str) -> int:
        """The address of a global structure (kCFTypeArrayCallBacks...)."""
        return ctypes.addressof(ctypes.c_char.in_dll(library, name))

    def release(self, reference: int | None) -> None:
        if reference:
            self.core.CFRelease(reference)

    def data_bytes(self, data: int) -> bytes:
        return ctypes.string_at(self.core.CFDataGetBytePtr(data), self.core.CFDataGetLength(data))

    def status_message(self, status: int) -> str:
        text = self.security.SecCopyErrorMessageString(status, None)
        message = self._string(text) if text else ""
        self.release(text)
        return f"OSStatus {status}: {message}" if message else f"OSStatus {status}"

    def error_message(self, error: int | None) -> str:
        if not error:
            return "unknown error"
        code = self.core.CFErrorGetCode(error)
        description = self.core.CFErrorCopyDescription(error)
        text = self._string(description) if description else ""
        self.release(description)
        return f"{code}: {text}"

    def _string(self, reference: int) -> str:
        buffer = ctypes.create_string_buffer(512)
        if not self.core.CFStringGetCString(reference, buffer, len(buffer), _K_CF_STRING_ENCODING_UTF8):
            return ""
        return buffer.value.decode("utf-8", "replace")


@functools.cache
def _frameworks() -> _Frameworks:
    return _Frameworks()


def _login_keychain() -> str:
    """The login keychain of the effective user, from the account database, never ``$HOME``."""
    import pwd  # noqa: PLC0415 - Unix only

    home = pwd.getpwuid(os.geteuid()).pw_dir  # type: ignore[attr-defined,unused-ignore]
    return os.path.join(home, "Library", "Keychains", "login.keychain-db")


def read_store(location: StoreLocation, name: StoreName) -> list[KeychainCertificate]:  # noqa: PLR0912 - one keychain, both item classes
    """The identities and certificates of the keychain ``location`` names. Only My is a store on
    macOS; a keychain that doesn't exist reads as empty."""
    if name != StoreName.MY:
        raise UnsupportedCertificateError(f"Only the My store - the keychain itself - can be read on macOS, not {name}.")
    path = _login_keychain() if location == StoreLocation.CURRENT_USER else _SYSTEM_KEYCHAIN
    cf = _frameworks()
    keychain = c_void_p()
    status = cf.security.SecKeychainOpen(path.encode("utf-8"), byref(keychain))
    if status != 0:
        raise CertificateError(f"Opening the keychain {path} failed: {cf.status_message(status)}.")
    try:
        keychain_status = c_uint32()
        status = cf.security.SecKeychainGetStatus(keychain, byref(keychain_status))
        if status == _ERR_SEC_NO_SUCH_KEYCHAIN:
            return []
        if status != 0:
            raise CertificateError(f"Opening the keychain {path} failed: {cf.status_message(status)}.")
        found: list[KeychainCertificate] = []
        try:
            # Identities first - certificates with their keys - then every certificate that isn't one.
            for identities in (True, False):
                for item in _copy_items(cf, keychain.value or 0, identities, path):
                    try:
                        der = _certificate_data(cf, item, identities)
                        with warnings.catch_warnings():  # a keychain holds what others put there
                            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                            certificate = x509.load_der_x509_certificate(der) if der else None
                    except (ValueError, x509.InvalidVersion):  # InvalidVersion isn't a ValueError
                        certificate = None
                    if certificate is None or (not identities and any(c.der == der for c in found)):
                        cf.release(item)
                        continue
                    if identities:
                        found.append(KeychainCertificate(item, certificate, der))
                    else:
                        cf.release(item)
                        found.append(KeychainCertificate(None, certificate, der))
        except BaseException:
            for entry in found:
                entry.close()
            raise
        return found
    finally:
        cf.release(keychain.value)


def _copy_items(cf: _Frameworks, keychain: int, identities: bool, path: str) -> list[int]:
    """Every item of the class in that keychain alone, each retained: the caller releases them."""
    search = (c_void_p * 1)(keychain)
    search_list = cf.core.CFArrayCreate(None, search, 1, cf.address(cf.core, "kCFTypeArrayCallBacks"))
    if not search_list:
        raise CertificateError("CFArrayCreate failed.")
    try:
        security = cf.security
        item_class = cf.constant(security, "kSecClassIdentity" if identities else "kSecClassCertificate")
        keys = (c_void_p * 4)(cf.constant(security, "kSecClass"), cf.constant(security, "kSecMatchSearchList"),
                              cf.constant(security, "kSecMatchLimit"), cf.constant(security, "kSecReturnRef"))
        values = (c_void_p * 4)(item_class, search_list, cf.constant(security, "kSecMatchLimitAll"), cf.constant(cf.core, "kCFBooleanTrue"))
        query = cf.core.CFDictionaryCreate(None, keys, values, 4, cf.address(cf.core, "kCFTypeDictionaryKeyCallBacks"),
                                           cf.address(cf.core, "kCFTypeDictionaryValueCallBacks"))
    finally:
        cf.release(search_list)
    if not query:
        raise CertificateError("CFDictionaryCreate failed.")
    result = c_void_p()
    try:
        status = security.SecItemCopyMatching(query, byref(result))
    finally:
        cf.release(query)
    if status == _ERR_SEC_ITEM_NOT_FOUND:
        return []
    if status != 0:
        raise CertificateError(f"Searching the keychain {path} failed: {cf.status_message(status)}.")
    try:
        if cf.core.CFGetTypeID(result) != cf.core.CFArrayGetTypeID():
            raise CertificateError(f"Searching the keychain {path} gave something other than a list.")
        items = []
        for index in range(cf.core.CFArrayGetCount(result)):
            item = cf.core.CFArrayGetValueAtIndex(result, index)
            if item:
                items.append(cf.core.CFRetain(item))
        return items
    finally:
        cf.release(result.value)


def _certificate_data(cf: _Frameworks, item: int, identity: bool) -> bytes:
    certificate = c_void_p(item)
    if identity:
        certificate = c_void_p()
        if cf.security.SecIdentityCopyCertificate(item, byref(certificate)) != 0:
            return b""
    try:
        data = cf.security.SecCertificateCopyData(certificate)
        if not data:
            return b""
        try:
            return cf.data_bytes(data)
        finally:
            cf.release(data)
    finally:
        if identity:
            cf.release(certificate.value)


class KeychainCertificate:
    """One certificate from a keychain: an identity, holding its reference until closed, or a
    certificate alone."""

    def __init__(self, identity: int | None, certificate: x509.Certificate, der: bytes) -> None:
        self._lock = threading.Lock()
        self._identity = identity
        self.certificate = certificate
        self.der = der
        self.has_private_key = identity is not None

    def close(self) -> None:
        with self._lock:
            _frameworks().release(self._identity)
            self._identity = None

    def open_private_key(self) -> OsKey:
        with self._lock:
            if self._identity is None:
                raise NoPrivateKeyError("The keychain holds no private key for it.")
            cf = _frameworks()
            key = c_void_p()
            status = cf.security.SecIdentityCopyPrivateKey(self._identity, byref(key))
            if status != 0 or not key.value:
                raise NoPrivateKeyError(f"The keychain won't give its private key: {cf.status_message(status)}.")
        public_key = self.certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            cf.release(key.value)
            raise UnsupportedCertificateError("The certificate's key isn't RSA or ECDSA.")
        return KeychainKey(key.value, public_key)


class KeychainKey:
    """A SecKeyRef in the keychain."""

    def __init__(self, reference: int, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> None:
        self._reference: int | None = reference
        self.public_key = public_key

    def close(self) -> None:
        _frameworks().release(self._reference)
        self._reference = None

    def sign_digest(self, digest: bytes, algorithm: hashes.HashAlgorithm, scheme: RsaSignature | None) -> bytes:
        if isinstance(self.public_key, ec.EllipticCurvePublicKey):
            if scheme is not None:
                raise TypeError("An ECDSA key signs with no padding.")
            table = _ECDSA  # X9.62 signatures are DER already
        elif scheme is None:
            raise TypeError("An RSA key signs with padding.PKCS1v15() or padding.PSS(...).")
        elif scheme.scheme == "pss":
            # The Security framework's PSS salt is always the hash's length.
            if scheme.salt_length != algorithm.digest_size:
                raise UnsupportedCertificateError("A keychain key signs PSS only with a salt the hash's length (PSS.DIGEST_LENGTH).")
            table = _RSA_PSS
        else:
            table = _RSA_PKCS1
        return bytes(self._call(table, algorithm, digest, _SIGN, sign=True))

    def decrypt(self, ciphertext: bytes, scheme: RsaDecryption) -> bytearray:
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise UnsupportedCertificateError("Only an RSA key decrypts.")
        if scheme.scheme == "oaep":
            if scheme.label:
                raise UnsupportedCertificateError("A keychain key decrypts OAEP only with an empty label.")
            assert scheme.hash is not None
            return self._call(_RSA_OAEP, scheme.hash, ciphertext, _DECRYPT, sign=False)
        return self._call({"": "kSecKeyAlgorithmRSAEncryptionPKCS1"}, None, ciphertext, _DECRYPT, sign=False)

    def _call(self, table: dict[str, str], algorithm: hashes.HashAlgorithm | None, data: bytes, operation: int, *, sign: bool) -> bytearray:
        if self._reference is None:
            raise ObjectClosedError("The certificate has been closed.")
        name = table.get(algorithm.name if algorithm is not None else "")
        if name is None:
            raise UnsupportedCertificateError(f"A keychain key can't use {algorithm.name if algorithm else 'this'} here.")
        cf = _frameworks()
        sec_algorithm = cf.constant(cf.security, name)
        if not cf.security.SecKeyIsAlgorithmSupported(self._reference, operation, sec_algorithm):
            raise UnsupportedCertificateError(f"The keychain key doesn't support {name}.")
        data_ref = cf.core.CFDataCreate(None, data, len(data))
        if not data_ref:
            raise CertificateError("CFDataCreate failed.")
        error = c_void_p()
        try:
            create = cf.security.SecKeyCreateSignature if sign else cf.security.SecKeyCreateDecryptedData
            result = create(self._reference, sec_algorithm, data_ref, byref(error))
        finally:
            cf.release(data_ref)
        if not result:
            message = cf.error_message(error.value)
            cf.release(error.value)
            raise CertificateError(f"{'SecKeyCreateSignature' if sign else 'SecKeyCreateDecryptedData'} failed: {message}.")
        try:
            length = cf.core.CFDataGetLength(result)
            pointer = cf.core.CFDataGetBytePtr(result)
            out = bytearray(length)
            ctypes.memmove((ctypes.c_char * length).from_buffer(out), pointer, length)
            if not sign:
                ctypes.memset(pointer, 0, length)  # the decrypted copy the framework made for this call alone
            return out
        finally:
            cf.release(result)
