"""The Windows certificate store, through ctypes: crypt32 opens a system store read-only and only
if it exists and enumerates its certificates, and a chosen one's private key is acquired through CNG
alone - CryptAcquireCertificatePrivateKey with CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG and
CRYPT_ACQUIRE_SILENT_FLAG - as an NCrypt key handle every signature (NCryptSignHash) and decryption
(NCryptDecrypt) goes through. The key is never exported. A key only a legacy CryptoAPI provider holds,
or one that would need a dialog to open, is refused. Imported only on Windows, where it binds
crypt32.dll and ncrypt.dll from System32 on first use."""

from __future__ import annotations

import ctypes
import functools
import threading
import warnings
from ctypes import POINTER, Structure, byref, c_int, c_long, c_uint32, c_void_p, c_wchar_p
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.utils import CryptographyDeprecationWarning
from hkdfguard.abstractions import ObjectClosedError
from hkdfguard.options.certificate import _win32
from hkdfguard.options.certificate._errors import CertificateError, NoPrivateKeyError, UnsupportedCertificateError
from hkdfguard.options.certificate._keys import OsKey, RsaDecryption, RsaSignature
from hkdfguard.options.certificate._options import StoreLocation, StoreName

_CERT_STORE_PROV_SYSTEM_W: Final = 10
_CERT_STORE_READONLY_FLAG: Final = 0x00008000
_CERT_STORE_OPEN_EXISTING_FLAG: Final = 0x00004000
_CERT_SYSTEM_STORE_CURRENT_USER: Final = 1 << 16
_CERT_SYSTEM_STORE_LOCAL_MACHINE: Final = 2 << 16
_CRYPT_E_NOT_FOUND: Final = 0x80092004

# The certificate context properties that say the store holds a certificate's private key, as .NET's
# HasPrivateKey reads them: its key provider's name and container, a key handle already acquired, or
# a CNG key handle.
_CERT_KEY_PROV_INFO_PROP_ID: Final = 2
_CERT_KEY_CONTEXT_PROP_ID: Final = 5
_CERT_NCRYPT_KEY_HANDLE_PROP_ID: Final = 78

_CRYPT_ACQUIRE_SILENT_FLAG: Final = 0x00000040
_CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG: Final = 0x00040000
_CERT_NCRYPT_KEY_SPEC: Final = 0xFFFFFFFF

_BCRYPT_PAD_PKCS1: Final = 0x00000002
_BCRYPT_PAD_OAEP: Final = 0x00000004
_BCRYPT_PAD_PSS: Final = 0x00000008
_NCRYPT_SILENT_FLAG: Final = 0x00000040

# The system store each StoreName opens, as .NET maps them.
_STORE_NAMES: Final = {StoreName.CERTIFICATE_AUTHORITY: "CA"}

_CNG_HASHES: Final = {"sha1": "SHA1", "sha256": "SHA256", "sha384": "SHA384", "sha512": "SHA512"}


class _CertContext(Structure):
    _fields_ = [("dwCertEncodingType", c_uint32), ("pbCertEncoded", POINTER(ctypes.c_ubyte)), ("cbCertEncoded", c_uint32),
                ("pCertInfo", c_void_p), ("hCertStore", c_void_p)]


class _Pkcs1PaddingInfo(Structure):
    _fields_ = [("pszAlgId", c_wchar_p)]


class _PssPaddingInfo(Structure):
    _fields_ = [("pszAlgId", c_wchar_p), ("cbSalt", c_uint32)]


class _OaepPaddingInfo(Structure):
    _fields_ = [("pszAlgId", c_wchar_p), ("pbLabel", c_void_p), ("cbLabel", c_uint32)]


@functools.cache
def _crypt32() -> Any:
    crypt32 = _win32.system32("crypt32.dll")
    crypt32.CertOpenStore.argtypes = [c_void_p, c_uint32, c_void_p, c_uint32, c_void_p]
    crypt32.CertOpenStore.restype = c_void_p
    crypt32.CertCloseStore.argtypes = [c_void_p, c_uint32]
    crypt32.CertCloseStore.restype = c_int
    crypt32.CertEnumCertificatesInStore.argtypes = [c_void_p, c_void_p]
    crypt32.CertEnumCertificatesInStore.restype = POINTER(_CertContext)
    crypt32.CertDuplicateCertificateContext.argtypes = [c_void_p]
    crypt32.CertDuplicateCertificateContext.restype = c_void_p
    crypt32.CertFreeCertificateContext.argtypes = [c_void_p]
    crypt32.CertFreeCertificateContext.restype = c_int
    crypt32.CertGetCertificateContextProperty.argtypes = [c_void_p, c_uint32, c_void_p, POINTER(c_uint32)]
    crypt32.CertGetCertificateContextProperty.restype = c_int
    crypt32.CryptAcquireCertificatePrivateKey.argtypes = [c_void_p, c_uint32, c_void_p, POINTER(c_void_p), POINTER(c_uint32), POINTER(c_int)]
    crypt32.CryptAcquireCertificatePrivateKey.restype = c_int
    return crypt32


@functools.cache
def _ncrypt() -> Any:
    ncrypt = _win32.system32("ncrypt.dll")
    ncrypt.NCryptSignHash.argtypes = [c_void_p, c_void_p, c_void_p, c_uint32, c_void_p, c_uint32, POINTER(c_uint32), c_uint32]
    ncrypt.NCryptSignHash.restype = c_long
    ncrypt.NCryptDecrypt.argtypes = [c_void_p, c_void_p, c_uint32, c_void_p, c_void_p, c_uint32, POINTER(c_uint32), c_uint32]
    ncrypt.NCryptDecrypt.restype = c_long
    ncrypt.NCryptFreeObject.argtypes = [c_void_p]
    ncrypt.NCryptFreeObject.restype = c_long
    return ncrypt


def windows_store_name(name: StoreName) -> str:
    """The system store a StoreName opens: its own name, but CertificateAuthority, which is "CA"."""
    return _STORE_NAMES.get(name, str(name))


def read_store(location: StoreLocation, name: StoreName) -> list[WindowsCertificate]:
    """Every certificate in the system store ``name`` at ``location``, read-only. A store that doesn't
    exist, or can't be opened, reads as empty, as .NET's does."""
    crypt32 = _crypt32()
    flags = _CERT_STORE_READONLY_FLAG | _CERT_STORE_OPEN_EXISTING_FLAG
    flags |= _CERT_SYSTEM_STORE_CURRENT_USER if location == StoreLocation.CURRENT_USER else _CERT_SYSTEM_STORE_LOCAL_MACHINE
    store_name = ctypes.create_unicode_buffer(windows_store_name(name))
    store = crypt32.CertOpenStore(_CERT_STORE_PROV_SYSTEM_W, 0, None, flags, ctypes.cast(store_name, c_void_p))
    if not store:
        return []
    found: list[WindowsCertificate] = []
    context = None
    try:
        while True:
            # Frees the previous context, and gives the next, or NULL - CRYPT_E_NOT_FOUND - after the last.
            context = crypt32.CertEnumCertificatesInStore(store, context)
            if not context:
                error = _win32.last_error() & 0xFFFFFFFF
                if error not in (_CRYPT_E_NOT_FOUND, 0):
                    raise CertificateError(f"Reading the {location} {name} certificate store failed with error 0x{error:08X}.")
                return found
            entry = context.contents
            der = ctypes.string_at(entry.pbCertEncoded, entry.cbCertEncoded)
            try:
                with warnings.catch_warnings():
                    # A store holds what others put there - a negative serial number, say: not this loader's to warn about.
                    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                    certificate = x509.load_der_x509_certificate(der)
            except ValueError:
                continue  # a certificate that can't be parsed can't be the one named
            duplicate = crypt32.CertDuplicateCertificateContext(ctypes.cast(context, c_void_p))
            has_key = any(_has_property(crypt32, duplicate, prop)
                          for prop in (_CERT_KEY_PROV_INFO_PROP_ID, _CERT_KEY_CONTEXT_PROP_ID, _CERT_NCRYPT_KEY_HANDLE_PROP_ID))
            found.append(WindowsCertificate(duplicate, certificate, der, has_key))
    except BaseException:
        if context:
            crypt32.CertFreeCertificateContext(ctypes.cast(context, c_void_p))  # the one enumeration was on
        for entry_certificate in found:
            entry_certificate.close()
        raise
    finally:
        # Each certificate kept is a duplicated context, which holds the store open until it is freed.
        crypt32.CertCloseStore(store, 0)


def _has_property(crypt32: Any, context: int, prop: int) -> bool:
    size = c_uint32(0)
    return bool(crypt32.CertGetCertificateContextProperty(context, prop, None, byref(size)))


class WindowsCertificate:
    """One certificate from a Windows store, holding its context until closed."""

    def __init__(self, context: int, certificate: x509.Certificate, der: bytes, has_key: bool) -> None:
        self._lock = threading.Lock()
        self._context: int | None = context
        self.certificate = certificate
        self.der = der
        self.has_private_key = has_key

    def close(self) -> None:
        with self._lock:
            if self._context is not None:
                _crypt32().CertFreeCertificateContext(self._context)
                self._context = None

    def open_private_key(self) -> OsKey:
        """The certificate's private key as a CNG key handle, acquired silently.

        :raises NoPrivateKeyError: CNG can't open it (or only with a dialog)
        :raises UnsupportedCertificateError: it isn't a CNG key, or isn't RSA or ECDSA
        """
        with self._lock:
            if self._context is None:
                raise ObjectClosedError("The certificate has been closed.")
            handle = c_void_p()
            key_spec = c_uint32()
            caller_free = c_int()
            if not _crypt32().CryptAcquireCertificatePrivateKey(self._context, _CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | _CRYPT_ACQUIRE_SILENT_FLAG, None,
                                                                byref(handle), byref(key_spec), byref(caller_free)):
                error = _win32.last_error() & 0xFFFFFFFF
                raise NoPrivateKeyError(f"Its private key can't be opened through CNG, silently (error 0x{error:08X}): a key only a legacy "
                                        "CryptoAPI provider holds must be re-imported into a CNG key storage provider, and one that needs "
                                        "a dialog can't be used by a service.")
        if key_spec.value != _CERT_NCRYPT_KEY_SPEC:
            # Not an NCrypt key, despite the flag: a CryptoAPI provider handle, which this never uses.
            if caller_free.value and handle.value:
                advapi32 = _win32.system32("advapi32.dll")
                advapi32.CryptReleaseContext.argtypes = [c_void_p, c_uint32]
                advapi32.CryptReleaseContext(handle, 0)
            raise UnsupportedCertificateError("Its private key isn't a CNG key: re-import it into a CNG key storage provider.")
        key = NCryptKey(handle.value or 0, bool(caller_free.value), self.certificate.public_key())
        if not isinstance(key.public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            key.close()
            raise UnsupportedCertificateError("The certificate's key isn't RSA or ECDSA.")
        return key


class NCryptKey:
    """A CNG key, held by its NCrypt handle: every signature is an NCryptSignHash call and every
    decryption an NCryptDecrypt call, so the key never enters the process."""

    def __init__(self, handle: int, owned: bool, public_key: object) -> None:
        self._handle = handle
        self._owned = owned  # whether the handle is this key's to free, not the certificate context's
        self.public_key = public_key

    def close(self) -> None:
        if self._owned and self._handle:
            _ncrypt().NCryptFreeObject(self._handle)
        self._handle = 0

    def sign_digest(self, digest: bytes, algorithm: hashes.HashAlgorithm, scheme: RsaSignature | None) -> bytes:
        public_key = self.public_key
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if scheme is not None:
                raise TypeError("An ECDSA key signs with no padding.")
            size = (public_key.curve.key_size + 7) // 8
            p1363 = self._sign(None, digest, 0, 2 * size)
            if len(p1363) != 2 * size:
                raise CertificateError(f"NCryptSignHash gave a {len(p1363)}-byte ECDSA signature, not {2 * size}.")
            # CNG gives r||s (IEEE P1363); X.509 and cryptography take SEQUENCE { r INTEGER, s INTEGER }.
            return encode_dss_signature(int.from_bytes(p1363[:size], "big"), int.from_bytes(p1363[size:], "big"))
        if not isinstance(public_key, rsa.RSAPublicKey) or scheme is None:
            raise TypeError("An RSA key signs with padding.PKCS1v15() or padding.PSS(...).")
        name = _cng_hash(algorithm)
        size = (public_key.key_size + 7) // 8
        if scheme.scheme == "pss":
            pss = _PssPaddingInfo(name, scheme.salt_length)
            return self._sign(ctypes.addressof(pss), digest, _BCRYPT_PAD_PSS, size)
        pkcs1 = _Pkcs1PaddingInfo(name)
        return self._sign(ctypes.addressof(pkcs1), digest, _BCRYPT_PAD_PKCS1, size)

    def _sign(self, padding_info: int | None, digest: bytes, flags: int, size: int) -> bytes:
        if not self._handle:
            raise ObjectClosedError("The certificate has been closed.")
        if not digest:
            raise ValueError("The digest is empty.")
        signature = ctypes.create_string_buffer(size)
        written = c_uint32()
        status = _ncrypt().NCryptSignHash(self._handle, padding_info, digest, len(digest), signature, size, byref(written),
                                          flags | _NCRYPT_SILENT_FLAG) & 0xFFFFFFFF
        if status:
            raise CertificateError(f"NCryptSignHash failed with status 0x{status:08X}.")
        return signature.raw[:written.value]

    def decrypt(self, ciphertext: bytes, scheme: RsaDecryption) -> bytearray:
        public_key = self.public_key
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise UnsupportedCertificateError("Only an RSA key decrypts.")
        if not self._handle:
            raise ObjectClosedError("The certificate has been closed.")
        if not ciphertext:
            raise ValueError("The ciphertext is empty.")
        size = (public_key.key_size + 7) // 8
        label = ctypes.create_string_buffer(scheme.label, len(scheme.label)) if scheme.label else None
        if scheme.scheme == "oaep":
            assert scheme.hash is not None
            oaep = _OaepPaddingInfo(_cng_hash(scheme.hash), ctypes.cast(label, c_void_p) if label is not None else None, len(scheme.label))
            info: int | None = ctypes.addressof(oaep)
            flags = _BCRYPT_PAD_OAEP
        else:
            info, flags = None, _BCRYPT_PAD_PKCS1
        out = bytearray(size)
        target = (ctypes.c_ubyte * size).from_buffer(out)
        written = c_uint32()
        try:
            status = _ncrypt().NCryptDecrypt(self._handle, ciphertext, len(ciphertext), info, target, size, byref(written),
                                             flags | _NCRYPT_SILENT_FLAG) & 0xFFFFFFFF
            if status:
                raise CertificateError(f"NCryptDecrypt failed with status 0x{status:08X}.")
            plaintext = bytearray(written.value)
            plaintext[:] = memoryview(out)[:written.value]
            return plaintext
        finally:
            del target
            out[:] = bytes(size)


def _cng_hash(algorithm: hashes.HashAlgorithm) -> str:
    name = _CNG_HASHES.get(algorithm.name)
    if name is None:
        raise UnsupportedCertificateError(f"A CNG key can't sign or decrypt with {algorithm.name}: use SHA-1, SHA-256, SHA-384 or SHA-512.")
    return name
