"""Distinguished names, decoded: parsed from configuration, read from a certificate, compared whole
ignoring case, and rendered as .NET and Windows render them."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509

# The attribute keywords a configured subject may use, as Windows' CertStrToName and .NET accept
# them, upper-cased; and the one each type is written with.
_KEYWORDS: dict[str, str] = {
    "CN": "2.5.4.3",
    "SN": "2.5.4.4",
    "SERIALNUMBER": "2.5.4.5",
    "C": "2.5.4.6",
    "L": "2.5.4.7",
    "S": "2.5.4.8",
    "ST": "2.5.4.8",
    "STREET": "2.5.4.9",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "T": "2.5.4.12",
    "TITLE": "2.5.4.12",
    "DESCRIPTION": "2.5.4.13",
    "POSTALCODE": "2.5.4.17",
    "G": "2.5.4.42",
    "GN": "2.5.4.42",
    "GIVENNAME": "2.5.4.42",
    "I": "2.5.4.43",
    "INITIALS": "2.5.4.43",
    "DNQUALIFIER": "2.5.4.46",
    "DC": "0.9.2342.19200300.100.1.25",
    "UID": "0.9.2342.19200300.100.1.1",
    "E": "1.2.840.113549.1.9.1",
    "EMAIL": "1.2.840.113549.1.9.1",
    "EMAILADDRESS": "1.2.840.113549.1.9.1",
    "UNSTRUCTUREDNAME": "1.2.840.113549.1.9.2",
    "UNSTRUCTUREDADDRESS": "1.2.840.113549.1.9.8",
}
_NAMES: dict[str, str] = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S",
    "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T", "2.5.4.13": "DESCRIPTION", "2.5.4.17": "PostalCode",
    "2.5.4.42": "G", "2.5.4.43": "I", "2.5.4.46": "DNQualifier", "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "E", "1.2.840.113549.1.9.2": "unstructuredName",
}
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class _Attribute:
    oid: str
    value: str | bytes  # bytes for a value that isn't a string type, which no configured value matches

    def matches(self, other: _Attribute) -> bool:
        if self.oid != other.oid:
            return False
        if isinstance(self.value, str) and isinstance(other.value, str):
            return _fold(self.value) == _fold(other.value)
        return self.value == other.value


def _fold(text: str) -> str:
    # Ignoring case as .NET's OrdinalIgnoreCase does: character by character, one for one, so "ß"
    # doesn't become "SS".
    return "".join(upper if len(upper := c.upper()) == 1 else c for c in text)


class DistinguishedName:
    """A distinguished name: its relative distinguished names in the order it is written - most
    specific first, ``"CN=api.example.com, O=Contoso"`` - each one or more attributes. A
    certificate's subject is encoded the other way round, so it is reversed as it is read, as .NET's
    ``X500DistinguishedName.Name`` and Windows render it."""

    __slots__ = ("_rdns",)

    def __init__(self, rdns: list[list[_Attribute]]) -> None:
        self._rdns = rdns

    @classmethod
    def parse(cls, text: str) -> DistinguishedName:
        """Parses a distinguished name as configuration writes it: ``"CN=api.example.com, O=Contoso"``.
        Relative names are separated by ``,`` or ``;``, attributes within one by ``+``; a type is a
        keyword (CN, O, OU, L, S, C, E, DC, ...) or a dotted OID, optionally ``OID.``-prefixed; a value
        may be double-quoted, and ``\\`` escapes the next character or two hex digits. Space around
        types and values is ignored.

        :raises ValueError: ``text`` isn't a distinguished name
        """
        rdns: list[list[_Attribute]] = []
        current: list[_Attribute] = []
        rest = text
        while True:
            attribute, rest, separator = _parse_attribute(rest)
            current.append(attribute)
            if separator != "+":
                rdns.append(current)
                current = []
            if separator == "":
                return cls(rdns)

    @classmethod
    def of(cls, name: x509.Name) -> DistinguishedName:
        """A certificate's subject (or issuer), most specific relative name first."""
        rdns: list[list[_Attribute]] = []
        for rdn in reversed(name.rdns):
            rdns.append([_Attribute(attribute.oid.dotted_string, attribute.value) for attribute in rdn])
        return cls(rdns)

    def matches(self, other: DistinguishedName) -> bool:
        """Whether the two are the same name: the same relative names in the same order, each with the
        same attributes - in any order within it, as a SET OF is - each value compared decoded and
        ignoring case. Never a substring: ``"CN=api"`` doesn't match ``"CN=api.example.com"``."""
        if len(self._rdns) != len(other._rdns):
            return False
        for mine, theirs in zip(self._rdns, other._rdns, strict=True):
            if len(mine) != len(theirs):
                return False
            unmatched = list(theirs)
            for attribute in mine:
                match = next((index for index, candidate in enumerate(unmatched) if attribute.matches(candidate)), None)
                if match is None:
                    return False
                del unmatched[match]
        return True

    def __str__(self) -> str:
        """The name as .NET and Windows render it: ``"CN=api.example.com, O=Contoso"``, a value quoted
        when it holds a separator, a quote or surrounding space."""
        parts = []
        for rdn in self._rdns:
            parts.append(" + ".join(f"{_NAMES.get(a.oid, 'OID.' + a.oid)}={_quote(a.value)}" for a in rdn))
        return ", ".join(parts)

    def __repr__(self) -> str:
        return f"DistinguishedName({str(self)!r})"


def describe(name: x509.Name) -> str:
    """A certificate's subject as messages name it."""
    return str(DistinguishedName.of(name))


def _quote(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return "#" + value.hex().upper()
    if value != value.strip() or any(c in value for c in ',;+="\\<>#\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def _parse_attribute(text: str) -> tuple[_Attribute, str, str]:  # noqa: PLR0912 - one value, every escape and quote
    """One ``type=value`` from the start of ``text``: the attribute, what follows its separator, and
    the separator (``,`` ``;`` ``+``), or ``""`` at the end."""
    equals = text.find("=")
    if equals < 0:
        raise ValueError("Not a distinguished name: an attribute has no '='.")
    oid = _attribute_type(text[:equals].strip())

    rest = text[equals + 1:].lstrip(" ")
    quoted = rest.startswith('"')
    value: list[str] = []
    # trailing is the length of value up to its last non-space, unescaped character: unquoted
    # values lose trailing spaces, but not escaped ones.
    trailing = 0
    i = 1 if quoted else 0
    while i < len(rest):
        c = rest[i]
        if c == "\\":
            if i + 1 >= len(rest):
                raise ValueError("Not a distinguished name: it ends in an escape.")
            if i + 2 < len(rest) and rest[i + 1] in _HEX and rest[i + 2] in _HEX:
                value.append(_hex_escape(rest, i))
                i += 2
            else:
                value.append(rest[i + 1])
                i += 1
            trailing = len(value)
        elif quoted and c == '"':
            if i + 1 < len(rest) and rest[i + 1] == '"':  # "" is a quote, as Windows writes one
                value.append('"')
                i += 2
                trailing = len(value)
                continue
            after = rest[i + 1:].lstrip(" ")
            if after == "":
                return _Attribute(oid, _join(value)), "", ""
            if after[0] not in ",;+":
                raise ValueError("Not a distinguished name: text follows a quoted value.")
            return _Attribute(oid, _join(value)), after[1:], after[0]
        elif not quoted and c in ",;+":
            return _Attribute(oid, _join(value[:trailing])), rest[i + 1:], c
        else:
            value.append(c)
            if c != " " or quoted:
                trailing = len(value)
        i += 1
    if quoted:
        raise ValueError("Not a distinguished name: a quoted value has no closing quote.")
    return _Attribute(oid, _join(value[:trailing])), "", ""


def _hex_escape(text: str, index: int) -> str:
    # \XX is one byte; a run of them is UTF-8, so it is collected as bytes and decoded on joining.
    return "\x00" + text[index + 1:index + 3]


def _join(parts: list[str]) -> str:
    # Hex escapes are carried as "\0XX" and decoded together, as UTF-8 (Latin-1 for bytes that
    # aren't), so "\C3\A9" is "é".
    out: list[str] = []
    pending = bytearray()
    for part in parts:
        if len(part) == 3 and part[0] == "\x00":
            pending.append(int(part[1:], 16))
            continue
        if pending:
            out.append(_decode(pending))
            pending.clear()
        out.append(part)
    if pending:
        out.append(_decode(pending))
    return "".join(out)


def _decode(data: bytearray) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _attribute_type(keyword: str) -> str:
    oid = _KEYWORDS.get(keyword.upper())
    if oid is not None:
        return oid
    dotted = keyword[4:] if len(keyword) > 4 and keyword[:4].upper() == "OID." else keyword
    parts = dotted.split(".")
    if len(parts) < 2 or not all(part.isascii() and part.isdigit() for part in parts):
        raise ValueError(f"Not a distinguished name: '{keyword}' isn't an attribute type.")
    return ".".join(str(int(part)) for part in parts)
