# Run the HashiCorp Vault cache integration tests

`test_hashicorpvault_integration.py` in `hkdfguard-cache-hashicorpvault` reads a real secret from a
real HashiCorp Vault through `HashiCorpVaultSecretCache`. This page starts a dev Vault in Docker (or
points the tests at one you already have), stores a test secret, creates a token that can only read
it, and runs the tests from the command line and the IDE.

The other tests of the distribution serve a fake Vault from `http.server` on 127.0.0.1 and run
without any of this. The integration tests are reported as **skipped**, never passed, until a
secret is configured.

They check that:

- `decrypt` and `decrypt_async` reveal the configured `path#key`;
- when you give the expected JSON, every key of the secret reads back as `path#key` with exactly
  that value, synchronously and asynchronously, and `path#no-such-key` returns 0;
- a secret that doesn't exist returns 0 rather than raising.

The tests only read: they never list, write or delete a secret.

## What you need

- [Docker](https://docs.docker.com/get-docker/), for the dev Vault, or any Vault 1.x with a KV
  version 2 engine mounted at `secret`.
- [uv](https://docs.astral.sh/uv/). `uv sync` installs Python 3.12 or later and the test tools into
  the workspace's `.venv`. The cache itself needs no HTTP library.

## 1. Start a dev Vault

A dev server keeps everything in memory, is unsealed, and mounts KV version 2 at `secret`: what the
tests expect. Never use one for real secrets. Give it a root token of your own rather than a fixed
one, and publish it on loopback only. If port 8200 is taken (another Vault, say), pick another host
port, such as `-p 127.0.0.1:18200:8200`, and use it in every address below.

In Git Bash, macOS or Linux:

```bash
export VAULT_ROOT_TOKEN=$(openssl rand -hex 16)
docker run --rm -d --name hkdfguard-vault --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID="$VAULT_ROOT_TOKEN" -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  -p 127.0.0.1:8200:8200 hashicorp/vault:1.20
```

In PowerShell:

```powershell
$env:VAULT_ROOT_TOKEN = [guid]::NewGuid().ToString("N")
docker run --rm -d --name hkdfguard-vault --cap-add=IPC_LOCK `
  -e VAULT_DEV_ROOT_TOKEN_ID=$env:VAULT_ROOT_TOKEN -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 `
  -p 127.0.0.1:8200:8200 hashicorp/vault:1.20
```

The dev server listens on plain http, which the cache allows only on a loopback address such as
`http://127.0.0.1:8200`. To test over TLS as well, add `-dev-tls -dev-tls-cert-dir=/vault/tls` after
the image name (`hashicorp/vault:1.20 server -dev -dev-tls -dev-tls-cert-dir=/vault/tls`), copy the
CA out with `docker cp hkdfguard-vault:/vault/tls/vault-ca.pem .`, and use
`https://127.0.0.1:8200` with `HKDFGUARD_TEST_VAULT_CACERT` in step 4.

## 2. Store a test secret

Run the Vault CLI inside the container, as root:

```bash
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" hkdfguard-vault \
  vault kv put secret/hkdfguard/test value=s3cret port=5432
```

In PowerShell, write `$env:VAULT_ROOT_TOKEN` for `"$VAULT_ROOT_TOKEN"` (here and in step 3). With
`-dev-tls`, use `VAULT_ADDR=https://127.0.0.1:8200` and add `-e VAULT_CACERT=/vault/tls/vault-ca.pem`.

`vault kv put` stores every value as a string, so this secret holds `{"value":"s3cret","port":"5432"}`.
To store numbers or booleans too, put a JSON file: `vault kv put secret/hkdfguard/test @secret.json`.

## 3. Create a token that can only read

Don't run the tests with the root token. Write a policy that can read the secrets under
`hkdfguard/` - the test of a missing secret reads `hkdfguard/missing-<random>`, which Vault answers
with 403 rather than 404 unless the token may read there - and create a short-lived token with it:

```bash
docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" hkdfguard-vault \
  vault policy write hkdfguard-test - <<'EOF'
path "secret/data/hkdfguard/*" {
  capabilities = ["read"]
}
EOF
export HKDFGUARD_TEST_VAULT_TOKEN=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" \
  hkdfguard-vault vault token create -policy=hkdfguard-test -ttl=8h -field=token)
```

In PowerShell, pipe the policy in and capture the token:

```powershell
'path "secret/data/hkdfguard/*" { capabilities = ["read"] }' |
  docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$env:VAULT_ROOT_TOKEN hkdfguard-vault vault policy write hkdfguard-test -
$env:HKDFGUARD_TEST_VAULT_TOKEN = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$env:VAULT_ROOT_TOKEN `
  hkdfguard-vault vault token create -policy=hkdfguard-test -ttl=8h -field=token
```

KV version 2 reads go to `secret/data/...`, so that is the path the policy names; `list` isn't
needed. Against your own Vault, ask its administrator for a token with this policy instead.

> **Security:** the token goes in the environment of the shell you run the tests from, and nowhere
> else. Never put it in `vault.test.properties`, `pyproject.toml`, a `.env` file in the repository,
> or an IDE run configuration that is committed, and don't echo it.

## 4. Point the tests at the secret

The tests read these variables - the same ones the .NET and Java integration tests read - in the
pytest process:

| Variable | Value | |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_SECRET_NAME` | `hkdfguard/test#value` | the secret's path in the engine and a key it holds; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_ADDR` | `http://127.0.0.1:8200` | Vault's address; `https://127.0.0.1:8200` if unset |
| `HKDFGUARD_TEST_VAULT_TOKEN` | the token from step 3 | environment only |
| `HKDFGUARD_TEST_VAULT_CACERT` | `vault-ca.pem` | only for a server certificate the system doesn't trust; then it is the only CA trusted |
| `HKDFGUARD_TEST_VAULT_SECRET_JSON` | `{"value":"s3cret","port":"5432"}` | optional: the keys the secret is expected to hold; environment only |

The secret's name, the address and the CA certificate can also go in `vault.test.properties` at the
repository root - the same file hkdfguard-java reads, ignored by git - so they needn't be set for
every command:

```properties
HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200
```

The environment wins over the file. The token and the expected JSON hold secrets, so they are read
from the environment only.

With `HKDFGUARD_TEST_VAULT_SECRET_JSON` set, each key of the object is read as
`hkdfguard/test#<key>` (the path being the secret name's, without its key) and compared with its
value: a string as its text, a number, `true` or `false` as its JSON text, as the cache caches them;
`null`, objects and arrays are skipped. A mismatch names the key, never either value.

## 5. Run the tests

From the repository root, in Git Bash, macOS or Linux, with the token from step 3 still in the
environment:

```bash
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \
HKDFGUARD_TEST_VAULT_SECRET_JSON='{"value":"s3cret","port":"5432"}' \
uv run --locked pytest packages/hkdfguard-cache-hashicorpvault
```

In PowerShell:

```powershell
$env:HKDFGUARD_TEST_VAULT_ADDR = "http://127.0.0.1:8200"
$env:HKDFGUARD_TEST_VAULT_SECRET_NAME = "hkdfguard/test#value"
$env:HKDFGUARD_TEST_VAULT_SECRET_JSON = '{"value":"s3cret","port":"5432"}'
uv run --locked pytest packages/hkdfguard-cache-hashicorpvault
Remove-Item Env:HKDFGUARD_TEST_VAULT_ADDR, Env:HKDFGUARD_TEST_VAULT_SECRET_NAME, Env:HKDFGUARD_TEST_VAULT_SECRET_JSON, Env:HKDFGUARD_TEST_VAULT_TOKEN
```

To run just the integration tests, name the file:
`uv run --locked pytest packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py -v`.

Every test in the file should pass with none skipped:

```text
packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py::test_decrypt_reveals_the_secret PASSED
packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py::test_decrypt_async_reveals_the_secret PASSED
packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py::test_decrypt_reveals_every_key_the_secret_holds PASSED
packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py::test_decrypt_async_reveals_every_key_the_secret_holds PASSED
packages/hkdfguard-cache-hashicorpvault/tests/test_hashicorpvault_integration.py::test_decrypt_of_a_secret_that_does_not_exist_returns_zero PASSED
```

Without `HKDFGUARD_TEST_VAULT_SECRET_JSON`, the two tests of every key are skipped and the other
three run.

In **PyCharm**, add the variables under **Environment variables** in the pytest run configuration
for `test_hashicorpvault_integration.py`, keeping the configuration out of version control (or put
the non-secret ones in `vault.test.properties` and only the token in the configuration). In **VS
Code** with the Python extension, put them in a `.env` file outside the repository and point
`python.envFile` at it in your user settings, not the workspace's.

On a CI runner, start Vault as a service container, store the secret and create the token in an
earlier step, and pass the token to the test step through the job's environment, masked.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 5 tests skipped | `HKDFGUARD_TEST_VAULT_SECRET_NAME` isn't set in the pytest process or `vault.test.properties` | Set it in the same command, the file, or the IDE's run configuration |
| `Failed: Set HKDFGUARD_TEST_VAULT_TOKEN in the environment` | The token isn't in the pytest process's environment | Step 3, in the same shell; it is never read from the file |
| `VaultRequestError: ... HTTP 403: permission denied` | The token has expired, or its policy doesn't cover the path | Step 3: the policy names `secret/data/hkdfguard/*`; create a new token |
| `VaultRequestError: ... HTTP 404: no handler for route` | No KV version 2 engine is mounted at `secret` | Use a dev server, or `vault secrets enable -path=secret kv-v2` |
| `ConnectionRefusedError` after a few seconds | Nothing listens at the address | `docker ps`; check the host port in `-p` and in `HKDFGUARD_TEST_VAULT_ADDR` |
| `ValueError: Vault's address ... must be https` | An http address that isn't loopback | Use `127.0.0.1` or `localhost`, or https |
| `ssl.SSLCertVerificationError` | Vault's certificate isn't trusted, or doesn't name the host | Set `HKDFGUARD_TEST_VAULT_CACERT`; connect by a name the certificate holds |
| `assert False` naming `path#key` | The secret doesn't hold the expected JSON's value under that key | Compare `vault kv get secret/hkdfguard/test` with `HKDFGUARD_TEST_VAULT_SECRET_JSON` |

## When you're done

```bash
docker stop hkdfguard-vault
unset HKDFGUARD_TEST_VAULT_TOKEN VAULT_ROOT_TOKEN
```

The container was started with `--rm`, and a dev server keeps nothing on disk, so stopping it
deletes the secret, the policy and every token. In PowerShell, remove the variables with
`Remove-Item Env:HKDFGUARD_TEST_VAULT_TOKEN, Env:VAULT_ROOT_TOKEN`. Against your own Vault, revoke
the token with `vault token revoke -self` (as that token) when you no longer need it.
