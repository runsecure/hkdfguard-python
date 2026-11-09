"""Key ring settings as plain data: :class:`HkdfGuardOptions` reads them from a configuration
section, validates them, and applies them onto a :class:`~hkdfguard.dataencryptionkey.KeyRingBuilder`."""

from pkgutil import extend_path

# hkdfguard-options-certificate installs a subpackage of hkdfguard.options
# (hkdfguard.options.certificate). Installed wheels share one directory, but editable installs keep
# each distribution's src separate, so every one of them is searched.
__path__ = extend_path(__path__, __name__)

from hkdfguard.options._options import HkdfGuardOptions, KeyFileOptions, OptionsValidationError

__all__ = ["HkdfGuardOptions", "KeyFileOptions", "OptionsValidationError"]
