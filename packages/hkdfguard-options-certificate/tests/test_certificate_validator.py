"""CertificateOptionsValidator and CertificateOptions.from_mapping: .NET's rules and configuration keys."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hkdfguard.options import OptionsValidationError
from hkdfguard.options.certificate import (
    CertificateFileFormat,
    CertificateFileOptions,
    CertificateOptions,
    CertificateOptionsValidationError,
    CertificateOptionsValidator,
    CertificateStoreOptions,
    LinuxOpenSslProviderOptions,
    StoreLocation,
    StoreName,
)

ABSOLUTE = os.path.abspath("tls.pfx")
CERTIFICATE = os.path.abspath("tls.crt")
KEY = os.path.abspath("tls.key")


def store(subject: str | None = "CN=api.example.com", **kwargs: object) -> CertificateStoreOptions:
    return CertificateStoreOptions(subject=subject, **kwargs)  # type: ignore[arg-type]


def valid(platform: str, options: CertificateOptions) -> list[str]:
    return CertificateOptionsValidator(platform).validate(options)


@pytest.mark.parametrize(("platform", "options"), [
    ("windows", CertificateOptions(windows=store())),
    ("macos", CertificateOptions(mac_os=store())),
    ("linux", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri="pkcs11:token=t;object=k", certificate_file=CERTIFICATE))),
    ("linux", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri=KEY, certificate_file=CERTIFICATE))),
    ("windows", CertificateOptions(file=CertificateFileOptions(path=ABSOLUTE, password_secret_name="pw"))),
    ("freebsd", CertificateOptions(file=CertificateFileOptions(path=ABSOLUTE, password_secret_name="pw"))),
])
def test_each_source_is_valid_on_its_own_platform(platform: str, options: CertificateOptions) -> None:
    assert valid(platform, options) == []


@pytest.mark.parametrize(("source", "options", "platform"), [
    ("Windows", CertificateOptions(windows=store()), "linux"),
    ("MacOS", CertificateOptions(mac_os=store()), "windows"),
    ("Linux", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri=KEY, certificate_file=CERTIFICATE)), "macos"),
])
def test_a_native_source_is_refused_on_another_platform(source: str, options: CertificateOptions, platform: str) -> None:
    failures = valid(platform, options)
    describe = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}[platform]
    assert failures == [f"The {source} certificate source can only be used on {source}; this is {describe}."]


def test_an_unknown_platform_is_named_as_it_is() -> None:
    assert valid("freebsd14", CertificateOptions(windows=store())) == [
        "The Windows certificate source can only be used on Windows; this is freebsd14."]


def test_no_source_or_more_than_one_is_refused() -> None:
    assert valid("windows", CertificateOptions()) == ["One certificate source is required: Windows, MacOS, Linux or File."]
    failures = valid("windows", CertificateOptions(windows=store(), file=CertificateFileOptions(path=ABSOLUTE, password_secret_name="pw")))
    assert failures == ["Only one certificate source can be set, but Windows, File are."]


@pytest.mark.parametrize("subject", ["CN=api.example.com, O=Contoso", "CN=a+OU=b; O=c", 'CN="a, b"', "OID.2.5.4.3=x", "2.5.4.3=x", "E=a@b.c"])
def test_a_store_takes_a_subject_distinguished_name(subject: str) -> None:
    assert valid("windows", CertificateOptions(windows=store(subject))) == []


@pytest.mark.parametrize("subject", [None, "", "  "])
def test_a_store_needs_a_subject(subject: str | None) -> None:
    assert valid("windows", CertificateOptions(windows=store(subject))) == [
        'Windows.Subject is required: the certificate\'s subject distinguished name, e.g. "CN=api.example.com".']


@pytest.mark.parametrize("subject", ["api.example.com", "XX=api", 'CN="unclosed', 'CN="a" b', "CN=a\\"])
def test_a_store_needs_a_subject_that_is_a_distinguished_name(subject: str) -> None:
    assert valid("windows", CertificateOptions(windows=store(subject))) == [
        f"Windows.Subject must be a distinguished name, e.g. \"CN=api.example.com, O=Contoso\", not '{subject}'."]


def test_a_store_needs_a_location_and_name_that_are_ones() -> None:
    failures = valid("windows", CertificateOptions(windows=store(store_location="Elsewhere", store_name="Nowhere")))
    assert failures == ["Windows.StoreLocation must be CurrentUser or LocalMachine, not Elsewhere.",
                        "Windows.StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not Nowhere."]


def test_macos_reads_only_the_my_store() -> None:
    assert valid("macos", CertificateOptions(mac_os=store(store_name=StoreName.ROOT))) == [
        "MacOS.StoreName must be My - the keychain itself, the only store this port reads on macOS - not Root."]
    assert valid("windows", CertificateOptions(windows=store(store_name=StoreName.ROOT))) == []


@pytest.mark.parametrize("provider", ["tpm2", "pkcs11", "my-provider_2"])
def test_a_linux_provider_may_hold_hyphens_and_underscores(provider: str) -> None:
    options = CertificateOptions(linux=LinuxOpenSslProviderOptions(provider=provider, key_uri=KEY, certificate_file=CERTIFICATE))
    assert valid("linux", options) == []


@pytest.mark.parametrize("provider", ["", "tpm 2", "tpm2;rm", "prövider"])
def test_a_linux_provider_must_be_a_providers_name(provider: str) -> None:
    options = CertificateOptions(linux=LinuxOpenSslProviderOptions(provider=provider, key_uri=KEY, certificate_file=CERTIFICATE))
    assert valid("linux", options) == [f"Linux.Provider must be an OpenSSL provider's name - \"tpm2\" or \"pkcs11\" - not '{provider}'."]


def test_a_linux_key_is_required_only_with_a_private_key() -> None:
    no_key = LinuxOpenSslProviderOptions(certificate_file=CERTIFICATE)
    assert valid("linux", CertificateOptions(linux=no_key)) == [
        'Linux.KeyUri is required: the key as the provider names it, e.g. "pkcs11:token=...;object=...".']
    assert valid("linux", CertificateOptions(linux=no_key, require_private_key=False)) == []


def test_a_tpm_handle_or_a_relative_key_is_refused_on_linux_as_ssl_reads_only_a_key_file() -> None:
    handle = valid("linux", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri="handle:0x81000001", certificate_file=CERTIFICATE)))
    assert len(handle) == 1
    assert "persistent TPM handle" in handle[0]
    assert "TSS2 PRIVATE KEY" in handle[0]
    relative = valid("linux", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri="key.pem", certificate_file=CERTIFICATE)))
    assert relative == ["Linux.KeyUri must be a \"pkcs11:\" URI or the absolute path of a key file the provider decodes (a TSS2 PRIVATE KEY "
                        "PEM, for tpm2), not 'key.pem'."]
    file_uri = CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri="file:" + KEY, certificate_file=CERTIFICATE))
    assert valid("linux", file_uri) == []
    # Elsewhere the platform failure says enough.
    assert len(valid("windows", CertificateOptions(linux=LinuxOpenSslProviderOptions(key_uri="handle:1", certificate_file=CERTIFICATE)))) == 1


@pytest.mark.parametrize(("path", "failure"), [
    (None, "File.Path is required."),
    ("  ", "File.Path is required."),
    ("tls.pfx", "File.Path must be an absolute path, not 'tls.pfx'."),
])
def test_a_file_path_must_be_absolute(path: str | None, failure: str) -> None:
    assert valid("windows", CertificateOptions(file=CertificateFileOptions(path=path, password_secret_name="pw"))) == [failure]
    linux = CertificateOptions(linux=LinuxOpenSslProviderOptions(certificate_file=path), require_private_key=False)
    assert valid("linux", linux) == [failure.replace("File.Path", "Linux.CertificateFile")]


def test_a_pem_file_needs_a_key_path_only_with_a_private_key() -> None:
    pem = CertificateFileOptions(path=CERTIFICATE, format=CertificateFileFormat.PEM, password_secret_name="pw")
    assert valid("windows", CertificateOptions(file=pem)) == ["File.KeyPath is required."]
    pem.key_path = "tls.key"
    assert valid("windows", CertificateOptions(file=pem)) == ["File.KeyPath must be an absolute path, not 'tls.key'."]
    pem.key_path = None
    pem.password_secret_name = None
    assert valid("windows", CertificateOptions(file=pem, require_private_key=False)) == []


def test_a_file_format_must_be_one() -> None:
    options = CertificateOptions(file=CertificateFileOptions(path=ABSOLUTE, format="Der", password_secret_name="pw"))
    assert valid("windows", options) == ["File.Format must be Pkcs12 or Pem, not Der."]


def test_a_key_file_needs_a_password_unless_an_unprotected_key_is_allowed() -> None:
    file = CertificateFileOptions(path=ABSOLUTE)
    assert valid("windows", CertificateOptions(file=file)) == [
        "File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. "
        "Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only."]
    assert valid("windows", CertificateOptions(file=file, require_private_key=False)) == []
    file.allow_unprotected_private_key = True
    assert valid("windows", CertificateOptions(file=file)) == []


def test_an_empty_password_secret_name_is_refused() -> None:
    options = CertificateOptions(file=CertificateFileOptions(path=ABSOLUTE, password_secret_name=" "), require_private_key=False)
    assert valid("windows", options) == [
        "File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset."]


def test_every_failure_is_reported_at_once_and_the_error_names_the_options() -> None:
    options = CertificateOptions(windows=store(None, store_location="x"), file=CertificateFileOptions(path="rel"))
    failures = valid("linux", options)
    assert len(failures) == 6
    with pytest.raises(CertificateOptionsValidationError) as raised:
        CertificateOptionsValidator("linux").require_valid(options, "tls")
    assert raised.value.failures == tuple(failures)
    assert raised.value.name == "tls"
    assert str(raised.value).startswith("The certificate options 'tls' are invalid: Only one certificate source")
    assert isinstance(raised.value, OptionsValidationError)  # caught where key ring options' failures are
    assert isinstance(raised.value, ValueError)


def test_the_validator_judges_the_running_platform_and_refuses_what_isnt_options() -> None:
    assert CertificateOptionsValidator().platform in ("windows", "macos", "linux") or CertificateOptionsValidator().platform
    with pytest.raises(TypeError):
        CertificateOptionsValidator().validate(None)  # type: ignore[arg-type]
    file = CertificateOptions(file=CertificateFileOptions(path=ABSOLUTE, password_secret_name="pw"))
    assert file.validate() == []
    assert file.require_valid() is file
    with pytest.raises(CertificateOptionsValidationError):
        CertificateOptions().require_valid()


def test_the_documented_shapes_bind_from_configuration() -> None:
    sections = json.loads("""{
        "Windows": { "Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } } },
        "MacOS": { "Certificate": { "MacOS": { "StoreLocation": "currentuser", "Subject": "CN=api.example.com" } } },
        "Linux": { "Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=t", "CertificateFile": "/etc/myapp/tls.crt" } } },
        "File": { "Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" }, "RequirePrivateKey": "false" } },
        "Numbers": { "Certificate": { "Windows": { "StoreLocation": 1, "StoreName": "6", "Subject": "CN=a" } } },
        "Pem": { "Certificate": { "file": { "path": "/c.pem", "format": "PEM", "key_path": "/k.pem", "allow_unprotected_private_key": true } } }
    }""")
    windows = CertificateOptions.from_mapping(sections["Windows"]["Certificate"])
    assert windows == CertificateOptions(windows=CertificateStoreOptions(StoreLocation.LOCAL_MACHINE, StoreName.MY, "CN=api.example.com"))
    mac = CertificateOptions.from_mapping(sections["MacOS"]["Certificate"])
    assert mac.mac_os == CertificateStoreOptions(StoreLocation.CURRENT_USER, StoreName.MY, "CN=api.example.com")
    linux = CertificateOptions.from_mapping(sections["Linux"]["Certificate"])
    assert linux.linux == LinuxOpenSslProviderOptions("pkcs11", "pkcs11:token=t", "/etc/myapp/tls.crt")
    file = CertificateOptions.from_mapping(sections["File"]["Certificate"])
    assert file.file == CertificateFileOptions(path="/etc/myapp/tls.pfx", password_secret_name="tls-pfx-password")
    assert file.require_private_key is False
    numbers = CertificateOptions.from_mapping(sections["Numbers"]["Certificate"])
    assert numbers.windows == CertificateStoreOptions(StoreLocation.CURRENT_USER, StoreName.ROOT, "CN=a")
    pem = CertificateOptions.from_mapping(sections["Pem"]["Certificate"])
    assert pem.file == CertificateFileOptions(path="/c.pem", format=CertificateFileFormat.PEM, key_path="/k.pem", allow_unprotected_private_key=True)


def test_configuration_that_isnt_options_is_refused_and_an_unknown_enum_is_kept_for_the_validator() -> None:
    with pytest.raises(ValueError, match="unknown key 'Thumbprint'"):
        CertificateOptions.from_mapping({"Windows": {"Thumbprint": "AB"}})
    with pytest.raises(ValueError, match="more than once"):
        CertificateOptions.from_mapping({"MacOS": {}, "mac_os": {}})
    with pytest.raises(TypeError):
        CertificateOptions.from_mapping({"File": "tls.pfx"})
    with pytest.raises(ValueError, match="true or false"):
        CertificateOptions.from_mapping({"RequirePrivateKey": "maybe"})
    odd = CertificateOptions.from_mapping({"Windows": {"StoreLocation": "Elsewhere", "StoreName": 42, "Subject": "CN=a"}})
    assert odd.windows is not None
    assert (odd.windows.store_location, odd.windows.store_name) == ("Elsewhere", "42")
    assert len(CertificateOptionsValidator("windows").validate(odd)) == 2


def test_the_defaults_are_the_safe_ones() -> None:
    options = CertificateOptions()
    assert options.require_private_key is True
    assert CertificateStoreOptions() == CertificateStoreOptions(StoreLocation.LOCAL_MACHINE, StoreName.MY, None)
    assert LinuxOpenSslProviderOptions().provider == "tpm2"
    file = CertificateFileOptions()
    assert (file.format, file.allow_unprotected_private_key) == (CertificateFileFormat.PKCS12, False)
    assert CertificateOptions.from_mapping({}).require_private_key is True
    path = Path(ABSOLUTE)
    assert path.is_absolute()
