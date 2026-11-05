"""OpenSSL 3 providers for Python's own ``ssl`` module, on Linux.

``ssl.SSLContext.load_cert_chain`` reads its key file through ``PEM_read_bio_PrivateKey_ex``, which
in OpenSSL 3 decodes through every loaded provider's decoders: a ``TSS2 PRIVATE KEY`` through
tpm2-openssl's, a ``PKCS#11 PROVIDER URI`` through pkcs11-provider's - and the key it gives is the
provider's, so every TLS signature is the TPM's or the token's, and the key never enters the process.
The provider must be loaded into the libcrypto ``ssl`` itself uses: this finds that library among the
process's mappings (``/proc/self/maps``), checks it is the version ``ssl`` reports, and calls its
``OSSL_PROVIDER_load`` - also loading ``default`` first when it isn't yet, since an explicit load
would otherwise stop it loading on its own. A Python whose ``ssl`` has OpenSSL built in (as
python-build-standalone's does) has no such library to load a provider into, and is refused."""

from __future__ import annotations

import base64
import ctypes
import functools
import os
import ssl
import threading
from typing import Any, Final

from hkdfguard.options.certificate import _der
from hkdfguard.options.certificate._errors import UnsupportedCertificateError

PKCS11_URI_LABEL: Final = "PKCS#11 PROVIDER URI"
_PKCS11_URI_DESCRIPTION: Final = b"PKCS#11 Provider URI v1.0"
_VISIBLE_STRING: Final = 0x1A

_lock = threading.Lock()
_loaded: dict[str, int] = {}  # never unloaded: keys and contexts made through a provider keep using it


def _maps() -> list[str]:
    try:
        with open("/proc/self/maps", encoding="utf-8", errors="replace") as maps:
            return maps.read().splitlines()
    except OSError:
        return []


@functools.cache
def _libcrypto() -> Any:
    """The libcrypto ``ssl`` is linked against: the one mapped into the process whose version is
    ``ssl.OPENSSL_VERSION_NUMBER``."""
    paths = sorted({line.split(None, 5)[5] for line in _maps() if len(line.split(None, 5)) == 6 and "/libcrypto.so" in line.split(None, 5)[5]})
    candidates = []
    for path in paths:
        if not os.path.isabs(path) or not os.path.exists(path):
            continue
        library = ctypes.CDLL(path, mode=getattr(os, "RTLD_NOW", 2) | getattr(os, "RTLD_NOLOAD", 0))  # only one already loaded
        library.OpenSSL_version_num.restype = ctypes.c_ulong
        if library.OpenSSL_version_num() == ssl.OPENSSL_VERSION_NUMBER:
            candidates.append(library)
    if len(candidates) != 1:
        raise UnsupportedCertificateError(
            f"This Python's ssl module ({ssl.OPENSSL_VERSION}) doesn't use a shared libcrypto an OpenSSL provider can be loaded into"
            + (" (it has OpenSSL built in, as python-build-standalone builds do)" if not candidates else "")
            + ": use a Python linked against the system's OpenSSL 3, such as the distribution's own python3.")
    library = candidates[0]
    library.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.OSSL_PROVIDER_load.restype = ctypes.c_void_p
    library.OSSL_PROVIDER_available.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.OSSL_PROVIDER_available.restype = ctypes.c_int
    library.ERR_get_error.restype = ctypes.c_ulong
    library.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]
    return library


def ensure_loaded(provider: str) -> None:
    """Loads ``provider`` into the default library context of ``ssl``'s libcrypto, if it isn't loaded.

    :raises UnsupportedCertificateError: this Python's ``ssl`` can't host a provider, or the provider
        can't be loaded (not installed, or its module fails to initialize)
    """
    if ssl.OPENSSL_VERSION_INFO[0] < 3:
        raise UnsupportedCertificateError(f"OpenSSL providers need OpenSSL 3; this Python's ssl module has {ssl.OPENSSL_VERSION}.")
    with _lock:
        if provider in _loaded:
            return
        library = _libcrypto()
        for name in ("default", provider):
            if name in _loaded or (name == "default" and library.OSSL_PROVIDER_available(None, name.encode())):
                continue
            handle = library.OSSL_PROVIDER_load(None, name.encode())
            if not handle:
                raise UnsupportedCertificateError(f"The OpenSSL provider '{name}' can't be loaded: {_errors(library)}. Is it installed "
                                                  f"(for {provider}: the {'tpm2-openssl' if provider == 'tpm2' else provider} package)?")
            _loaded[name] = handle


def _errors(library: Any) -> str:
    messages = []
    while code := library.ERR_get_error():
        buffer = ctypes.create_string_buffer(256)
        library.ERR_error_string_n(code, buffer, len(buffer))
        messages.append(buffer.value.decode("utf-8", "replace"))
    return "; ".join(messages) or "no error reported"


def pkcs11_uri_pem(uri: str) -> bytes:
    """A ``pkcs11:`` URI as pkcs11-provider's decoder takes it from a key file: a ``PKCS#11 PROVIDER
    URI`` PEM, ``SEQUENCE { desc VisibleString, uri UTF8String }``. The URI names the key; it holds
    no secret unless it carries a ``pin-value``, which belongs in the provider's configuration."""
    body = _der.encode(_VISIBLE_STRING, _PKCS11_URI_DESCRIPTION) + _der.encode(_der.UTF8_STRING, uri.encode("utf-8"))
    encoded = base64.encodebytes(_der.encode(_der.SEQUENCE, body)).decode("ascii")
    return f"-----BEGIN {PKCS11_URI_LABEL}-----\n{encoded}-----END {PKCS11_URI_LABEL}-----\n".encode("ascii")
