"""Password-based encryption for PKCS#12 files and encrypted PKCS#8 keys: PBES2 (PBKDF2 with
HMAC-SHA-1/2, AES-CBC or 3DES-CBC) both ways, and PKCS#12's own 3DES key derivation to decrypt.

The password is always a ``bytearray``, never a ``str``. PBES2 derives its key with
``cryptography``'s ``PBKDF2HMAC.derive_into`` straight into a ``bytearray``, and decrypts and
encrypts with ``update_into`` into ``bytearray``s, so the password, the derived key and the
plaintext are all in buffers this module wipes. PKCS#12's own key derivation (RFC 7292 B.2), used by
Windows' default 3DES export and every integrity MAC, is hashed here with ``hashlib``, whose digests
are immutable ``bytes``: those intermediate values can't be wiped, and are left to the allocator."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Final

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hkdfguard.abstractions import ArrayUtility
from hkdfguard.options.certificate import _der
from hkdfguard.options.certificate._der import DerError, Element
from hkdfguard.options.certificate._errors import InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError

# The most iterations one key derivation may ask for, and a whole file all of its derivations: a file
# can't make loading it take minutes. Generous beside what tools write (OpenSSL 2048, Windows
# 2000-10000, .NET's PBES2 default 100000 and its loader's 600000 cap). As the Go port.
MAX_ITERATIONS: Final = 1_000_000
MAX_TOTAL_ITERATIONS: Final = 4_000_000

PBES2: Final = "1.2.840.113549.1.5.13"
PBKDF2: Final = "1.2.840.113549.1.5.12"
PBMAC1: Final = "1.2.840.113549.1.5.14"
HMAC_SHA1: Final = "1.2.840.113549.2.7"
HMAC_SHA256: Final = "1.2.840.113549.2.9"
AES256_CBC: Final = "2.16.840.1.101.3.4.1.42"
_PBE_SHA_3DES: Final = "1.2.840.113549.1.12.1.3"
_PBE_SHA_2DES: Final = "1.2.840.113549.1.12.1.4"
_LEGACY: Final = {
    "1.2.840.113549.1.12.1.1": "RC4-128",
    "1.2.840.113549.1.12.1.2": "RC4-40",
    "1.2.840.113549.1.12.1.5": "RC2-128",
    "1.2.840.113549.1.12.1.6": "RC2-40",
}

_PRFS: Final[dict[str, Callable[[], hashes.HashAlgorithm]]] = {
    HMAC_SHA1: hashes.SHA1,
    "1.2.840.113549.2.8": hashes.SHA224,
    HMAC_SHA256: hashes.SHA256,
    "1.2.840.113549.2.10": hashes.SHA384,
    "1.2.840.113549.2.11": hashes.SHA512,
}
# The digests a PKCS#12 MAC names, by OID: hashlib's name, for the key derivation, and cryptography's hash.
DIGESTS: Final[dict[str, tuple[str, Callable[[], hashes.HashAlgorithm]]]] = {
    "1.3.14.3.2.26": ("sha1", hashes.SHA1),
    "2.16.840.1.101.3.4.2.4": ("sha224", hashes.SHA224),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashes.SHA256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashes.SHA384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashes.SHA512),
}
type _CipherFactory = Callable[[bytearray], BlockCipherAlgorithm]


def _triple_des(key: bytearray) -> BlockCipherAlgorithm:
    return TripleDES(key)  # type: ignore[arg-type]  # it takes any buffer, as AES does


def _aes(key: bytearray) -> BlockCipherAlgorithm:
    return algorithms.AES(key)


_CIPHERS: Final[dict[str, tuple[int, _CipherFactory]]] = {
    "2.16.840.1.101.3.4.1.2": (16, _aes),
    "2.16.840.1.101.3.4.1.22": (24, _aes),
    AES256_CBC: (32, _aes),
    "1.2.840.113549.3.7": (24, _triple_des),
}

PKCS12_KEY_ID: Final = 1
PKCS12_IV_ID: Final = 2
PKCS12_MAC_ID: Final = 3


class IterationBudget:
    """The key-derivation iterations one file has spent."""

    def __init__(self) -> None:
        self.spent = 0

    def spend(self, iterations: int) -> None:
        if iterations < 1 or iterations > MAX_ITERATIONS or self.spent + iterations > MAX_TOTAL_ITERATIONS:
            raise InvalidCertificateFileError("An iteration count in the file is out of range.")
        self.spent += iterations


def wipe(*buffers: bytearray | None) -> None:
    for buffer in buffers:
        ArrayUtility.zero_memory(buffer)


def bmp_password(password: bytearray | None) -> bytearray:  # noqa: PLR0912 - UTF-8 decoding, byte by byte
    """A UTF-8 password as PKCS#12's key derivation takes it: a BMPString - big-endian UTF-16 - with a
    two-byte terminator, decoded byte by byte, never through a ``str``. ``None`` is the empty
    password, the terminator alone; an empty ``bytearray`` is no password at all, no bytes - the two
    ways tools write a file without one. A new buffer the caller wipes.

    :raises WrongPasswordError: the password isn't UTF-8
    """
    if password is not None and len(password) == 0:
        return bytearray()
    source = password if password is not None else bytearray()
    out = bytearray(4 * len(source) + 2)  # sized once, never grown
    written = 0
    i = 0
    try:
        while i < len(source):
            lead = source[i]
            if lead < 0x80:
                code, size = lead, 1
            elif 0xC2 <= lead <= 0xDF:
                code, size = lead & 0x1F, 2
            elif 0xE0 <= lead <= 0xEF:
                code, size = lead & 0x0F, 3
            elif 0xF0 <= lead <= 0xF4:
                code, size = lead & 0x07, 4
            else:
                raise WrongPasswordError("The password isn't UTF-8.")
            if i + size > len(source):
                raise WrongPasswordError("The password isn't UTF-8.")
            for k in range(1, size):
                octet = source[i + k]
                if octet & 0xC0 != 0x80:
                    raise WrongPasswordError("The password isn't UTF-8.")
                code = (code << 6) | (octet & 0x3F)
            if (size == 3 and (code < 0x800 or 0xD800 <= code <= 0xDFFF)) or (size == 4 and not 0x10000 <= code <= 0x10FFFF):
                raise WrongPasswordError("The password isn't UTF-8.")
            if code > 0xFFFF:
                code -= 0x10000
                high, low = 0xD800 | (code >> 10), 0xDC00 | (code & 0x3FF)
                out[written:written + 4] = bytes((high >> 8, high & 0xFF, low >> 8, low & 0xFF))
                written += 4
            else:
                out[written] = code >> 8
                out[written + 1] = code & 0xFF
                written += 2
            i += size
            code = 0
        out[written:written + 2] = b"\x00\x00"
        written += 2
        result = bytearray(written)
        result[:] = memoryview(out)[:written]
        return result
    finally:
        wipe(out)


def pkcs12_kdf(digest: str, password: bytearray, salt: bytes, iterations: int, purpose: int, size: int) -> bytearray:  # noqa: PLR0917 - RFC 7292's own parameters
    """RFC 7292 B.2: ``size`` bytes for ``purpose`` from a BMPString password and a salt. A new buffer
    the caller wipes; the hash's own digests along the way are immutable ``bytes``."""
    u = hashlib.new(digest).digest_size
    v = hashlib.new(digest).block_size

    def fill(data: bytes | bytearray) -> bytearray:
        if not data:
            return bytearray()
        out = bytearray(v * ((len(data) + v - 1) // v))
        for index in range(len(out)):
            out[index] = data[index % len(data)]
        return out

    d = bytes([purpose]) * v
    s = fill(salt)
    p = fill(password)
    i = bytearray(len(s) + len(p))
    i[:len(s)] = s
    i[len(s):] = p
    wipe(p)
    out = bytearray(((size + u - 1) // u) * u)
    b = bytearray(v)
    written = 0
    try:
        while written < size:
            h = hashlib.new(digest)
            h.update(d)
            h.update(i)
            a = h.digest()
            for _ in range(iterations - 1):
                a = hashlib.new(digest, a).digest()
            out[written:written + u] = a
            written += u
            if written >= size:
                break
            for j in range(v):
                b[j] = a[j % u]
            # Each v-byte block of I becomes (I_j + B + 1) mod 2^(8v).
            for block in range(0, len(i), v):
                carry = 1
                for k in range(v - 1, -1, -1):
                    total = i[block + k] + b[k] + carry
                    i[block + k] = total & 0xFF
                    carry = total >> 8
        result = bytearray(size)
        result[:] = memoryview(out)[:size]
        return result
    finally:
        wipe(i, out, b)


def decrypt(algorithm: Element, password: bytearray | None, ciphertext: bytearray | memoryview, budget: IterationBudget) -> bytearray:
    """Decrypts ``ciphertext`` under a password-based encryption algorithm: PBES2 (PBKDF2 with
    HMAC-SHA-1/224/256/384/512, and AES-128/192/256-CBC or 3DES-CBC), or PKCS#12's
    pbeWithSHAAnd3-KeyTripleDES-CBC or 2-KeyTripleDES. ``password`` is UTF-8: PBES2 uses it as it is,
    as OpenSSL and .NET do, and PKCS#12's own PBE as a BMPString. The plaintext is a new buffer the
    caller wipes. A wrong password shows as bad padding: :class:`WrongPasswordError`.

    :raises UnsupportedCertificateError: legacy RC2 or RC4, or an algorithm this doesn't know
    """
    try:
        name, parameters = _der.algorithm(algorithm, "An encryption algorithm")
        key: bytearray | None = None
        iv: bytes | bytearray = b""
        try:
            if name == PBES2:
                key, iv, cipher = _pbes2_key(parameters, password, budget)
            elif name in (_PBE_SHA_3DES, _PBE_SHA_2DES):
                salt, iterations = _pkcs12_pbe_parameters(parameters)
                budget.spend(iterations)
                bmp = bmp_password(password)
                try:
                    key = pkcs12_kdf("sha1", bmp, salt, iterations, PKCS12_KEY_ID, 24 if name == _PBE_SHA_3DES else 16)
                    iv = pkcs12_kdf("sha1", bmp, salt, iterations, PKCS12_IV_ID, 8)
                finally:
                    wipe(bmp)
                cipher = _triple_des  # a 16-byte key is two-key 3DES, K1 K2 K1
            elif name in _LEGACY:
                raise UnsupportedCertificateError(
                    f"The file is encrypted with legacy {_LEGACY[name]} ({name}), which is refused: re-export it with AES - for instance "
                    "with 'openssl pkcs12 -export' without -legacy, or .NET's ExportPkcs12 with Pkcs12ExportPbeParameters.Pbes2Aes256Sha256.")
            else:
                raise UnsupportedCertificateError(f"The encryption algorithm {name} isn't supported.")
            return _cbc_decrypt(cipher(key), iv, ciphertext)
        finally:
            wipe(key, iv if isinstance(iv, bytearray) else None)
    except DerError as error:
        raise InvalidCertificateFileError(f"The file's encryption parameters are malformed: {error}") from None


def _pkcs12_pbe_parameters(parameters: Element | None) -> tuple[bytes, int]:
    if parameters is None:
        raise DerError("PKCS#12 PBE parameters are missing.")
    items = _der.sequence(parameters, "PKCS#12 PBE parameters", 2, 2)
    return bytes(_der.octets(items[0], "A salt")), _der.integer(items[1], "An iteration count")


def _pbes2_key(parameters: Element | None, password: bytearray | None, budget: IterationBudget) -> tuple[bytearray, bytes, _CipherFactory]:
    if parameters is None:
        raise DerError("PBES2 parameters are missing.")
    kdf, scheme = _der.sequence(parameters, "PBES2 parameters", 2, 2)
    kdf_name, kdf_parameters = _der.algorithm(kdf, "A key derivation")
    if kdf_name != PBKDF2:
        raise UnsupportedCertificateError(f"The PBES2 key derivation {kdf_name} isn't supported.")
    if kdf_parameters is None:
        raise DerError("PBKDF2 parameters are missing.")
    items = _der.sequence(kdf_parameters, "PBKDF2 parameters", 2, 4)
    salt = bytes(_der.octets(items[0], "A PBKDF2 salt"))
    iterations = _der.integer(items[1], "A PBKDF2 iteration count")
    rest = items[2:]
    key_length = None
    if rest and rest[0].tag == _der.INTEGER:
        key_length = _der.integer(rest[0], "A PBKDF2 key length")
        rest = rest[1:]
    prf: Callable[[], hashes.HashAlgorithm] = hashes.SHA1
    if rest:
        prf_name, _ = _der.algorithm(rest[0], "A PBKDF2 PRF")
        if prf_name not in _PRFS:
            raise UnsupportedCertificateError(f"The PBKDF2 PRF {prf_name} isn't supported.")
        prf = _PRFS[prf_name]
    budget.spend(iterations)

    cipher_name, iv_element = _der.algorithm(scheme, "A PBES2 cipher")
    if cipher_name not in _CIPHERS:
        raise UnsupportedCertificateError(f"The PBES2 cipher {cipher_name} isn't supported.")
    length, cipher = _CIPHERS[cipher_name]
    if key_length is not None and key_length != length:
        raise DerError("PBKDF2's key length doesn't fit its cipher.")
    if iv_element is None:
        raise DerError("The cipher's IV is missing.")
    iv = bytes(_der.octets(iv_element, "An IV"))

    key = bytearray(length)
    PBKDF2HMAC(prf(), length, salt, iterations).derive_into(password if password is not None else bytearray(), key)
    return key, iv, cipher


def _cbc_decrypt(cipher: BlockCipherAlgorithm, iv: bytes | bytearray, ciphertext: bytearray | memoryview) -> bytearray:
    block = cipher.block_size // 8
    if len(ciphertext) == 0 or len(ciphertext) % block or len(iv) != block:
        raise InvalidCertificateFileError("The encrypted data isn't whole cipher blocks.")
    decryptor = Cipher(cipher, modes.CBC(bytes(iv))).decryptor()
    out = bytearray(len(ciphertext) + block - 1)
    try:
        written = decryptor.update_into(ciphertext, out)
        decryptor.finalize()
        # PKCS#7 padding, checked whole.
        padding = out[written - 1] if written else 0
        if not 1 <= padding <= block or written < padding or any(out[k] != padding for k in range(written - padding, written)):
            raise WrongPasswordError("The password doesn't decrypt the file's key or contents.")
        plaintext = bytearray(written - padding)
        plaintext[:] = memoryview(out)[:written - padding]
        return plaintext
    finally:
        wipe(out)


def encrypt_pkcs8(private_key_info: bytearray, password: bytearray, iterations: int = 1) -> bytes:
    """``private_key_info`` - a PKCS#8 PrivateKeyInfo - as an EncryptedPrivateKeyInfo, DER, under
    PBES2: PBKDF2-HMAC-SHA-256 and AES-256-CBC, the way ``openssl pkcs8 -topk8 -v2 aes-256-cbc``
    writes it. The result is ciphertext and parameters only; every buffer holding the key, the
    padded plaintext or the derived key is wiped. ``iterations`` can be 1 for a random throwaway
    password of 32 bytes, which no iteration count would strengthen."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = bytearray(32)
    padded = bytearray(len(private_key_info) + 16 - len(private_key_info) % 16)
    ciphertext = bytearray(len(padded) + 15)
    try:
        PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive_into(password, key)
        padded[:len(private_key_info)] = private_key_info
        pad = len(padded) - len(private_key_info)
        padded[len(private_key_info):] = bytes([pad]) * pad
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        written = encryptor.update_into(padded, ciphertext)
        encryptor.finalize()
        encrypted = bytes(ciphertext[:written])
    finally:
        wipe(key, padded)

    seq = _der.SEQUENCE
    prf = _der.encode(seq, _der.encode_oid(HMAC_SHA256) + _der.encode(_der.NULL, b""))
    kdf_parameters = _der.encode(seq, _der.encode(_der.OCTET_STRING, salt) + _der.encode_integer(iterations) + _der.encode_integer(32) + prf)
    kdf = _der.encode(seq, _der.encode_oid(PBKDF2) + kdf_parameters)
    scheme = _der.encode(seq, _der.encode_oid(AES256_CBC) + _der.encode(_der.OCTET_STRING, iv))
    algorithm = _der.encode(seq, _der.encode_oid(PBES2) + _der.encode(seq, kdf + scheme))
    return _der.encode(seq, algorithm + _der.encode(_der.OCTET_STRING, encrypted))
