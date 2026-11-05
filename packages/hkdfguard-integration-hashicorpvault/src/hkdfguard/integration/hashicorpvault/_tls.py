"""Which certificates a Vault integration trusts Vault's to be signed by, and which it presents."""

from __future__ import annotations

import contextlib
import os
import secrets
import ssl
import tempfile
from collections.abc import Buffer
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from hkdfguard.abstractions import ArrayUtility, CryptographicError, DataProtector

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

PASSWORD_PURPOSE: Final = "HkdfGuard.Integration.HashiCorpVault.KeyStorePassword"  # noqa: S105 - a purpose, not a password
"""The purpose of the protector a key store's password is protected by:
``key_ring.create_protector(PASSWORD_PURPOSE)``."""

# The first four bytes of a JKS and a JCEKS key store, neither of which Python can read.
_JAVA_KEY_STORE_MAGIC: Final = (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce")
_MAX_CHAIN_LENGTH: Final = 10

_OID_DATA: Final = bytes.fromhex("2a864886f70d010701")  # 1.2.840.113549.1.7.1
_OID_KEY_BAG: Final = bytes.fromhex("2a864886f70d010c0a0101")  # 1.2.840.113549.1.12.10.1.1
_OID_SHROUDED_KEY_BAG: Final = bytes.fromhex("2a864886f70d010c0a0102")  # 1.2.840.113549.1.12.10.1.2
_OID_FRIENDLY_NAME: Final = bytes.fromhex("2a864886f70d010914")  # 1.2.840.113549.1.9.20


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultTlsOptions:
    """Which certificates a Vault client - or the HashiCorp Vault transit key wrapper or secret cache
    - trusts Vault's to be signed by, and which it presents for the cert auth method or a Vault
    requiring mutual TLS: the Python counterpart of the .NET and Java ``VaultTlsOptions``. All unset,
    the system's trust store decides. Immutable; files are read by :meth:`create_ssl_context`, when
    the integration is created.

    Certificates are PEM ("CERTIFICATE" blocks). A client key is a PEM "PRIVATE KEY" (PKCS#8), "RSA
    PRIVATE KEY" (PKCS#1) or "EC PRIVATE KEY" (SEC1) - unencrypted, as vault-client-go reads it.

    Either can instead come from a password-protected PKCS#12 key store: a trust store
    (:attr:`trust_store_file`) in place of the PEM CA certificates, a client key store
    (:attr:`client_key_store_file`) in place of the PEM client certificate and key. JKS and JCEKS
    stores are refused - Python can't read them; convert one with ``keytool -importkeystore
    -deststoretype PKCS12``. A store's password is held only protected, by a protector on the key ring
    (``key_ring.create_protector(PASSWORD_PURPOSE)``, set as :attr:`password_protector`): it is
    decrypted into a bytearray only while the store is read, and zeroed at once.

    Python's ``ssl`` module loads a client key only from a file. The key - from PEM or a key store -
    is therefore written, PEM-encrypted under a random one-time password held only in memory, to a
    temporary file only the current user can read, loaded, and deleted before
    :meth:`create_ssl_context` returns. The file never holds the key in the clear, and the one-time
    password never leaves the process.
    """

    server_certificate_file: str | os.PathLike[str] | None = None
    """A PEM file of the CA certificates Vault's certificate must chain to (VAULT_CACERT), in place
    of the system's trust store."""

    server_certificate_pem: Buffer | None = None
    """:attr:`server_certificate_file`'s content, in memory (VAULT_CACERT_BYTES)."""

    server_certificate_directory: str | os.PathLike[str] | None = None
    """A directory of PEM files of CA certificates (VAULT_CAPATH); every regular file is read."""

    client_certificate_file: str | os.PathLike[str] | None = None
    """A PEM file of the certificate, and any intermediates, presented to Vault (VAULT_CLIENT_CERT)."""

    client_certificate_pem: Buffer | None = None
    """:attr:`client_certificate_file`'s content, in memory."""

    client_certificate_key_file: str | os.PathLike[str] | None = None
    """A PEM file of the client certificate's private key (VAULT_CLIENT_KEY), unencrypted."""

    client_certificate_key_pem: Buffer | None = field(default=None, repr=False)
    """:attr:`client_certificate_key_file`'s content, in memory. The caller owns the buffer: zero it
    once the integration is created."""

    server_name: str | None = None
    """The name Vault's certificate must be issued to, and sent as SNI, in place of the address's
    host (VAULT_TLS_SERVER_NAME)."""

    insecure_skip_verify: bool = False
    """Trusts any certificate Vault presents (VAULT_SKIP_VERIFY). For development only: anyone on the
    network path can then read every token and secret."""

    trust_store_file: str | os.PathLike[str] | None = None
    """A PKCS#12 store of the CA certificates Vault's certificate must chain to, in place of the PEM
    ones. Needs :attr:`trust_store_password`."""

    trust_store_password: str | None = field(default=None, repr=False)
    """:attr:`trust_store_file`'s password, protected: :meth:`protect_password`."""

    client_key_store_file: str | os.PathLike[str] | None = None
    """A PKCS#12 store of the private key and certificate chain presented to Vault, in place of the
    PEM ones. Needs :attr:`client_key_store_password`."""

    client_key_store_password: str | None = field(default=None, repr=False)
    """:attr:`client_key_store_file`'s password, protected: :meth:`protect_password`. It unlocks the
    key too, as PKCS#12 requires."""

    client_key_store_alias: str | None = None
    """The friendly name (alias) of the key in :attr:`client_key_store_file` to present, ignoring
    case as Java's PKCS#12 key store does; ``None`` when the store holds only one private key."""

    password_protector: DataProtector | None = None
    """The protector the key store passwords were protected by:
    ``key_ring.create_protector(PASSWORD_PURPOSE)``."""

    PASSWORD_PURPOSE = PASSWORD_PURPOSE

    @staticmethod
    def protect_password(password_protector: DataProtector, password: str) -> str:
        """Protects a key store's password with ``password_protector`` - a protector on the key ring,
        ``key_ring.create_protector(PASSWORD_PURPOSE)`` - for :attr:`trust_store_password` or
        :attr:`client_key_store_password`. ``password`` is a ``str``, which Python can't erase: read it
        once, here, and keep no other reference to it.

        :raises TypeError: ``password_protector`` or ``password`` is ``None``
        :raises ValueError: ``password`` is empty
        """
        if password_protector is None:
            raise TypeError("password_protector must not be None.")
        if password is None:
            raise TypeError("password must not be None.")
        if not isinstance(password, str):
            raise TypeError("password must be a str.")
        if not password:
            raise ValueError("A key store password can't be empty.")
        return password_protector.encrypt(password)

    @property
    def is_empty(self) -> bool:
        """Whether nothing is set, so the system's defaults decide."""
        return (self.server_certificate_file is None and _is_empty(self.server_certificate_pem) and self.server_certificate_directory is None
                and self.client_certificate_file is None and _is_empty(self.client_certificate_pem)
                and self.client_certificate_key_file is None and _is_empty(self.client_certificate_key_pem)
                and self.server_name is None and not self.insecure_skip_verify
                and self.trust_store_file is None and self.client_key_store_file is None)

    def create_ssl_context(self) -> ssl.SSLContext:
        """An SSLContext trusting and presenting what these options say: TLS 1.2 or later, verifying
        Vault's certificate and host name unless :attr:`insecure_skip_verify`. A connection made with
        it must send :attr:`server_name`, when set, as its ``server_hostname``.

        :raises TypeError: an option is of the wrong type
        :raises ValueError: a certificate, key or key store can't be read; a client certificate has no
            key or a key no certificate; a key store has no password, or one
            :attr:`password_protector` didn't protect; a key store is JKS, or is combined with the PEM
            it replaces; or a client key store holds no key, or several and no alias names one
        """
        self._check_types()
        roots = None if self.insecure_skip_verify else self._server_certificates()
        if roots is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)  # NOSONAR - verifies unless insecure_skip_verify
        else:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata="".join(_pem(c) for c in roots))  # NOSONAR - verifies
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.insecure_skip_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # NOSONAR - VAULT_SKIP_VERIFY, an explicit opt-in for development

        client = self._client_key()
        if client is not None:
            _load_client_key(context, *client)
        return context

    def _check_types(self) -> None:
        for name in ("server_certificate_file", "server_certificate_directory", "client_certificate_file", "client_certificate_key_file",
                     "trust_store_file", "client_key_store_file"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str | os.PathLike):
                raise TypeError(f"{name} must be a path.")
        for name in ("server_certificate_pem", "client_certificate_pem", "client_certificate_key_pem"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, str) or not isinstance(value, Buffer)):
                raise TypeError(f"{name} must be a bytes-like object.")
        for name in ("server_name", "trust_store_password", "client_key_store_password", "client_key_store_alias"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be a str.")
        if not isinstance(self.insecure_skip_verify, bool):
            raise TypeError("insecure_skip_verify must be a bool.")
        if self.password_protector is not None and not isinstance(self.password_protector, DataProtector):
            raise TypeError("password_protector must be a DataProtector.")

    def _server_certificates(self) -> list[x509.Certificate] | None:
        if self.trust_store_file is not None:
            if self.server_certificate_file is not None or not _is_empty(self.server_certificate_pem) or self.server_certificate_directory is not None:
                raise ValueError("A trust store and PEM CA certificates can't be given together.")
            return self._trust_store_certificates()

        roots: list[x509.Certificate] = []
        if self.server_certificate_file is not None:
            _import_certificates(roots, _read(self.server_certificate_file), str(self.server_certificate_file))
        elif not _is_empty(self.server_certificate_pem):
            _import_certificates(roots, bytes(memoryview(self.server_certificate_pem).cast("B")), "server_certificate_pem")  # type: ignore[arg-type]
        elif self.server_certificate_directory is not None:
            directory = Path(self.server_certificate_directory)
            try:
                files = sorted(f for f in directory.iterdir() if f.is_file())
            except OSError as error:
                raise ValueError(f"Could not list the CA certificates in {directory}: {error}") from error
            for file in files:
                _import_certificates(roots, _read(file), str(file))
        else:
            return None
        return roots

    def _trust_store_certificates(self) -> list[x509.Certificate]:
        assert self.trust_store_file is not None
        store = self._load_key_store(self.trust_store_file, self.trust_store_password, "trust store")
        if store.key is not None:
            raise ValueError(f"The trust store {self.trust_store_file} holds a private key: give a store of CA certificates only.")
        roots = [c.certificate for c in store.additional_certs]
        if store.cert is not None:
            roots.append(store.cert.certificate)
        if not roots:
            raise ValueError(f"The trust store {self.trust_store_file} holds no trusted certificate.")
        return roots

    def _client_key(self) -> tuple[PrivateKeyTypes, list[x509.Certificate]] | None:
        has_certificate = self.client_certificate_file is not None or not _is_empty(self.client_certificate_pem)
        has_key = self.client_certificate_key_file is not None or not _is_empty(self.client_certificate_key_pem)
        if self.client_key_store_file is not None and (has_certificate or has_key):
            raise ValueError("A client key store and a PEM client certificate or key can't be given together.")
        if has_certificate != has_key:
            raise ValueError("A client certificate and its key must be given together.")
        if self.client_key_store_file is not None:
            return self._client_key_from_store(self.client_key_store_file)
        if not has_certificate:
            return None
        return self._client_key_from_pem()

    def _client_key_from_pem(self) -> tuple[PrivateKeyTypes, list[x509.Certificate]]:
        certificate_pem = _read(self.client_certificate_file) if self.client_certificate_file is not None else _bytes(self.client_certificate_pem)
        key_pem = bytearray(_read(self.client_certificate_key_file)) if self.client_certificate_key_file is not None else None
        try:
            try:
                chain = x509.load_pem_x509_certificates(certificate_pem)
            except ValueError as error:
                raise ValueError(f"Could not read the client certificate and key: the certificate PEM holds no certificate ({error}).") from None
            source = key_pem if key_pem is not None else memoryview(self.client_certificate_key_pem).cast("B")  # type: ignore[arg-type]
            try:
                key = serialization.load_pem_private_key(source, password=None)
            except TypeError:
                raise ValueError("Could not read the client certificate and key: the key is encrypted; give it unencrypted, "
                                 "as vault-client-go reads it.") from None
            except (ValueError, UnsupportedAlgorithm):
                # Not chained: the parser's message could quote the key.
                raise ValueError("Could not read the client certificate and key: the key PEM holds no private key that is RSA, EC or EdDSA.") from None
            return key, chain
        finally:
            ArrayUtility.zero_memory(key_pem)

    def _client_key_from_store(self, file: str | os.PathLike[str]) -> tuple[PrivateKeyTypes, list[x509.Certificate]]:
        # The store's private key: the one named client_key_store_alias, or its only one.
        store, bags, password = self._load_key_store_keeping_password(file, self.client_key_store_password, "client key store")
        try:
            if store.key is None or store.cert is None:
                raise ValueError(f"The client key store {file} holds no private key.")
            certificates = [store.cert.certificate, *(c.certificate for c in store.additional_certs)]
            alias = self.client_key_store_alias
            if bags is not None and len(bags) > 1:
                if alias is None:
                    raise ValueError(f"The client key store {file} holds more than one private key: name the one to present with client_key_store_alias.")
                named = [bag for bag in bags if bag[0] is not None and bag[0].casefold() == alias.casefold()]
                if not named:
                    raise ValueError(f"The client key store {file} holds no private key named '{alias}'.")
                key = _decrypt_key_bag(named[0], password, file)
                leaf = _certificate_for(key, certificates, file)
            else:
                name = store.cert.friendly_name.decode("utf-8", "replace") if store.cert.friendly_name is not None else None
                if alias is not None and (name is None or name.casefold() != alias.casefold()):
                    raise ValueError(f"The client key store {file} holds no private key named '{alias}'.")
                key = store.key
                leaf = store.cert.certificate
            return key, _chain(leaf, certificates)
        finally:
            ArrayUtility.zero_memory(password)

    def _load_key_store(self, file: str | os.PathLike[str], protected_password: str | None, what: str) -> pkcs12.PKCS12KeyAndCertificates:
        store, _, password = self._load_key_store_keeping_password(file, protected_password, what)
        ArrayUtility.zero_memory(password)
        return store

    def _load_key_store_keeping_password(self, file: str | os.PathLike[str], protected_password: str | None,
                                         what: str) -> tuple[pkcs12.PKCS12KeyAndCertificates, list[_KeyBag] | None, bytearray]:
        # Reads file, unlocked with the password protected_password holds, and returns it, its key
        # bags, and the password in a bytearray the caller zeroes.
        if not protected_password:
            raise ValueError(f"The {what} {file} needs its password, protected: VaultTlsOptions.protect_password.")
        if self.password_protector is None:
            raise ValueError(f"The {what}'s password needs the protector that protected it: set password_protector.")
        data = _read(file)
        if data[:4] in _JAVA_KEY_STORE_MAGIC:
            raise ValueError(f"The {what} {file} is a JKS or JCEKS key store, which Python can't read: convert it to PKCS#12 "
                             "(keytool -importkeystore -deststoretype PKCS12).")

        password = self._decrypt_password(protected_password, what)
        try:
            try:
                store = pkcs12.load_pkcs12(data, password)  # type: ignore[arg-type]  # a bytearray, so it can be zeroed; cryptography reads any buffer
            except ValueError as error:
                # A wrong password is reported as a ValueError too.
                raise ValueError(f"Could not read the {what} {file}: {error}") from None
            return store, _key_bags(data), password
        except BaseException:
            ArrayUtility.zero_memory(password)
            raise

    def _decrypt_password(self, protected_password: str, what: str) -> bytearray:
        # The password protected_password holds, in a bytearray exactly its length that the caller
        # zeroes. The protector's exceptions aren't chained: a parser handed an unprotected password
        # could quote it.
        assert self.password_protector is not None
        decrypted: bytearray | None = None
        length = -1
        try:
            max_length = self.password_protector.get_max_decrypted_length(protected_password)
            if max_length >= 0:
                decrypted = bytearray(max_length)
                length = self.password_protector.decrypt(protected_password, decrypted)
        except (ValueError, LookupError, CryptographicError):
            length = -1
        try:
            if decrypted is None or length < 0:
                raise _not_protected(what)
            return bytearray(memoryview(decrypted)[:length])
        finally:
            ArrayUtility.zero_memory(decrypted)


# (friendly name, bag type, the bag's DER value: an EncryptedPrivateKeyInfo or a PrivateKeyInfo)
type _KeyBag = tuple[str | None, bytes, bytes]


def _key_bags(data: bytes) -> list[_KeyBag] | None:
    """The private key bags of a PKCS#12 store, in its unencrypted contents - where Java, OpenSSL and
    .NET put them - with their friendly names; ``None`` if the store isn't DER that can be walked.
    cryptography's reader returns only the first key, so this is how a store of several is seen."""
    try:
        pfx = _Der(data).sequence()
        pfx.integer()
        auth_safe = pfx.sequence()
        if auth_safe.oid() != _OID_DATA:
            return None
        safes = _Der(auth_safe.explicit(0).octet_string()).sequence()
        bags: list[_KeyBag] = []
        while not safes.done:
            info = safes.sequence()
            if info.oid() != _OID_DATA:
                continue  # encrypted contents: certificates, as these stores put them
            contents = _Der(info.explicit(0).octet_string()).sequence()
            while not contents.done:
                bag = contents.sequence()
                bag_type = bag.oid()
                value = bag.explicit(0).raw()
                if bag_type not in {_OID_KEY_BAG, _OID_SHROUDED_KEY_BAG}:
                    continue
                name = None
                if not bag.done:
                    attributes = bag.set()
                    while not attributes.done:
                        attribute = attributes.sequence()
                        if attribute.oid() == _OID_FRIENDLY_NAME:
                            name = attribute.set().bmp_string()
                bags.append((name, bag_type, value))
        return bags
    except ValueError:
        return None


class _Der:
    """Just enough of a DER reader to walk a PKCS#12 store's bags."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def done(self) -> bool:
        return self._position >= len(self._data)

    def _next(self, tag: int | None = None) -> tuple[int, int, int]:
        # The next element's tag, and where its contents start and end; moves past it.
        data, position = self._data, self._position
        if position + 2 > len(data):
            raise ValueError("truncated")
        actual = data[position]
        length = data[position + 1]
        position += 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4 or position + count > len(data):
                raise ValueError("not DER")
            length = int.from_bytes(data[position:position + count])
            position += count
        if position + length > len(data) or (tag is not None and actual != tag):
            raise ValueError("not DER")
        self._position = position + length
        return actual, position, position + length

    def _contents(self, tag: int) -> bytes:
        _, start, end = self._next(tag)
        return self._data[start:end]

    def sequence(self) -> _Der:
        return _Der(self._contents(0x30))

    def set(self) -> _Der:
        return _Der(self._contents(0x31))

    def explicit(self, number: int) -> _Der:
        return _Der(self._contents(0xA0 | number))

    def integer(self) -> bytes:
        return self._contents(0x02)

    def oid(self) -> bytes:
        return self._contents(0x06)

    def octet_string(self) -> bytes:
        return self._contents(0x04)

    def bmp_string(self) -> str:
        return self._contents(0x1E).decode("utf-16-be")

    def raw(self) -> bytes:
        # The next element, tag and length included.
        start = self._position
        self._next()
        return self._data[start:self._position]


def _decrypt_key_bag(bag: _KeyBag, password: bytearray, file: str | os.PathLike[str]) -> PrivateKeyTypes:
    _, bag_type, value = bag
    try:
        return serialization.load_der_private_key(value, password if bag_type == _OID_SHROUDED_KEY_BAG else None)  # type: ignore[arg-type]  # as in load_pkcs12
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError(f"Could not read the private key named '{bag[0]}' in the client key store {file}: its encryption isn't one "
                         "Python reads (PBES2 is); re-export the store, or give a store holding only that key.") from None


def _certificate_for(key: PrivateKeyTypes, certificates: list[x509.Certificate], file: str | os.PathLike[str]) -> x509.Certificate:
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for certificate in certificates:
        if certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public:
            return certificate
    raise ValueError(f"The client key store {file} holds no certificate for the key it names.")


def _chain(leaf: x509.Certificate, certificates: list[x509.Certificate]) -> list[x509.Certificate]:
    # leaf, then each issuer the store holds, up to (not including) a self-signed root.
    chain = [leaf]
    while len(chain) < _MAX_CHAIN_LENGTH and chain[-1].issuer != chain[-1].subject:
        issuer = next((c for c in certificates if c.subject == chain[-1].issuer and c not in chain), None)
        if issuer is None or issuer.issuer == issuer.subject:
            break
        chain.append(issuer)
    return chain


def _load_client_key(context: ssl.SSLContext, key: PrivateKeyTypes, chain: list[x509.Certificate]) -> None:
    # ssl loads a key only from a file: written PEM-encrypted under a one-time password that never
    # leaves this process, to a file only this user can read, and deleted once loaded.
    one_time = secrets.token_urlsafe(32).encode("ascii")
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(one_time))
    descriptor, path = tempfile.mkstemp(prefix="hkdfguard-vault-", suffix=".pem")
    try:
        with os.fdopen(descriptor, "wb") as file:
            for certificate in chain:
                file.write(certificate.public_bytes(serialization.Encoding.PEM))
            file.write(pem)
        try:
            context.load_cert_chain(path, password=lambda: one_time)
        except ssl.SSLError as error:
            raise ValueError(f"Could not use the client certificate and key: {error}") from None
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)


def _import_certificates(roots: list[x509.Certificate], pem: bytes, source: str) -> None:
    if b"-----BEGIN CERTIFICATE-----" not in pem:
        raise ValueError(f"{source} holds no PEM-encoded certificate.")
    try:
        roots.extend(x509.load_pem_x509_certificates(pem))
    except ValueError as error:
        raise ValueError(f"Could not read the CA certificate(s) in {source}: {error}") from error


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _read(file: str | os.PathLike[str]) -> bytes:
    try:
        return Path(file).read_bytes()
    except OSError as error:
        raise ValueError(f"Could not read {file}: {error}") from error


def _bytes(data: Buffer | None) -> bytes:
    return b"" if data is None else bytes(memoryview(data).cast("B"))


def _is_empty(data: Buffer | None) -> bool:
    return data is None or len(memoryview(data)) == 0


def _not_protected(what: str) -> ValueError:
    return ValueError(f"The {what}'s password isn't protected by password_protector: hand over VaultTlsOptions.protect_password's result, "
                      "never the password itself.")



def check_tls_options(ssl_context: object, tls: object) -> None:
    """Refuses an ``ssl_context`` or ``tls`` of the wrong type, or both together: each says how to
    connect, so one would silently override the other.

    :raises TypeError: ``ssl_context`` isn't an ``ssl.SSLContext`` or ``tls`` a :class:`VaultTlsOptions`
    :raises ValueError: both are given
    """
    if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext.")
    if tls is not None and not isinstance(tls, VaultTlsOptions):
        raise TypeError("tls must be VaultTlsOptions.")
    if ssl_context is not None and tls is not None:
        raise ValueError("ssl_context and tls can't be given together: set the TLS settings with one or the other.")
