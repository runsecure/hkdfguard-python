# hkdfguard-cache-awssecretsmanager

A protected read-only cache over AWS Secrets Manager, through botocore: each secret is read on its first lookup, taken out of the response before botocore can make it a str, encrypted under the key ring's current key and cached only as ciphertext.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache-awssecretsmanager
```

```python
import boto3
from hkdfguard.cache.awssecretsmanager import AwsSecretsManagerSecretCache

client = boto3.client("secretsmanager")  # the application creates, configures and owns the client
secrets = AwsSecretsManagerSecretCache(client, ring)

buffer = bytearray(256)
written = secrets.decrypt("prod/Db-Password", buffer)       # 0 if the secret doesn't exist
written = secrets.decrypt("prod/app#api-credential-21", buffer)  # one key of a key/value secret
```

Nothing is fetched up front: the first `decrypt` or `find_max_decrypted_length` for a name calls
`GetSecretValue` for that one secret's `AWSCURRENT` version, encrypts it under the ring's current key
bound to its name, and caches only the ciphertext; later lookups never call AWS. The cache never
lists secrets, so the principal needs only `secretsmanager:GetSecretValue` on the secrets it reads
(plus `kms:Decrypt` on a customer managed key that encrypts them). A cached value isn't refreshed: a
new secret version is picked up by a new cache.

- **Names** match exactly, as Secrets Manager's do: `prod/Db` and `prod/db` are two secrets.
  Anything but 1-512 ASCII letters, digits and `/_+=.@-` - such as the configuration path
  `ConnectionStrings:Admin`, or an ARN - returns 0 without a call, so look secrets up by name, and
  the cache can go last in a `ProtectedCacheCollection` behind other sources.
- **Values.** A `SecretString` is cached as its UTF-8 bytes and a `SecretBinary` as its bytes. A
  `SecretString` holding a JSON object - a key/value secret, as the console stores one - is also
  cached member by member, as `name#key`, from the same single call; a `SecretBinary` is never split.
- **Failures.** A secret that doesn't exist (`ResourceNotFoundException`) or is empty returns 0 and
  is looked up again next time. Anything else - access denied, a secret scheduled for deletion, a
  decryption failure, AWS unreachable, no credentials - raises botocore's exception (`ClientError`,
  or the client's modeled subclass, or a `BotoCoreError`), and a response body that can't be trusted
  as Secrets Manager's raises `InvalidSecretDataError`.
- **Async.** botocore is synchronous: `decrypt` blocks the calling thread, and `decrypt_async` and
  `find_max_decrypted_length_async` run the call in a worker thread, so they don't block the event
  loop. Concurrent lookups of one uncached secret share one call.

**A secret never becomes a `str`.** The cache registers one handler on the client's event system,
`before-parse.secrets-manager.GetSecretValue`, ahead of any registered before it. For the cache's own
calls only - tracked per thread with a `ContextVar`, so the application's calls on the same client,
and the cache's concurrent calls from other threads, are each left with their own response - it
takes `SecretString` or `SecretBinary` out of a successful response's body with `SecretJsonBody`,
and hands botocore's parser the body with both replaced by `""`. The parsed response, botocore's
debug log of the body, and every later handler hold nothing secret; every bytearray of HkdfGuard's
that held the value is zeroed. Out of reach: botocore reads the whole body into an immutable `bytes`
before any hook runs (from urllib3's own `bytes` chunks), and that copy lives until it is collected.
It is held only by botocore's response object for the length of the call, but a `response-received`
or `after-call` handler the application registers on the client sees it, as does botocore's history
recorder if something enables it.

The client is the application's: create it with `boto3.client("secretsmanager")` or
`botocore.session.get_session().create_client("secretsmanager")` (either is a botocore client), keep
it for as long as anything uses the cache, and close it. The cache never closes it, and changes
nothing on it but registering that handler, once however many caches share the client. A client
whose responses never reach the endpoint - a `botocore.stub.Stubber`, say - is refused with
`RuntimeError` rather than read, since its value would already be a `str`.

Each fetch is a `hkdfguard.cache.populate` span counted as `success`, `not_found` or `error`; with
sensitive logging on, the secret's name (never a value) is logged, and a failed fetch is logged as an
error. See `hkdfguard-cache`'s `RemoteSecretCache` for the rest of the caching behaviour.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
and [Run the AWS Secrets Manager cache integration tests](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/run-aws-secrets-manager-cache-integration-tests.md)
to try it against a secret of your own.

Licensed under the Mozilla Public License 2.0.
