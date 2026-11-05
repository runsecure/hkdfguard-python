"""A protected read-only cache over one JSON file holding every secret, already encrypted - the file a
pipeline's ``SecretPipelineWriter.write_json_secrets`` writes: read through TrustedFile on the first
lookup, every value authenticated under its name, and kept still encrypted."""

from hkdfguard.cache.jsonsecretsfile._cache import JsonSecretsFileReadOnlyCache

__all__ = ["JsonSecretsFileReadOnlyCache"]
