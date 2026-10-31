# Run the HashiCorp Vault transit integration tests

`test_hashicorpvault_transit_integration.py` in `hkdfguard-keywrapping-hashicorpvault` makes real
calls to a Vault transit secrets engine through `HashiCorpVaultTransitKeyWrapper`. This page runs a
Vault dev server in Docker, provisions two transit keys and a token that may use only them, and runs
the tests from the command line and the IDE.

The other tests in the distribution use a fake transit engine, served from `http.server` on
127.0.0.1 and called through the wrapper's real `http.client`, and run without any of this. The
integration tests are reported as **skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generate_and_wrap` produces a wrapped DEK that reveals to 32 non-zero bytes, both generated in
  Vault (no context) and generated locally and encrypted (with one);
- a DEK wrapped under one context is refused under another, and under none;
- a DEK wrapped under one key is refused by another;
- a tampered wrapped DEK, and an invalid token, are refused;
- a crypto provider can generate and reveal its DEK through the wrapper.

The tests never create, rotate, read or delete a key.

If you already run hkdfguard-dotnet's transit integration tests, you have a server, keys and a
token: skip to [step 3](#3-point-the-tests-at-the-key) and use the same values.

## What you need

- [Docker](https://docs.docker.com/get-docker/).
- Git Bash (on Windows) or any bash with `curl`, for the provisioning script.
- [uv](https://docs.astral.sh/uv/), and this repository synced (`uv sync`). The wrapper itself needs
  no HTTP library.

## 1. Start a Vault dev server

A dev server keeps everything in memory and is unsealed. Never use one for real keys. Give it a root
token of your own rather than a fixed one, and publish it on loopback only. If port 8200 is taken
(another Vault, say), pick another host port, such as `-p 127.0.0.1:18200:8200`, and use it in every
address below.

In Git Bash, macOS or Linux:

```bash
export VAULT_ROOT_TOKEN=$(openssl rand -hex 16)
docker run --rm -d --name hkdfguard-vault --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID="$VAULT_ROOT_TOKEN" -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

In PowerShell:

```powershell
$env:VAULT_ROOT_TOKEN = [guid]::NewGuid().ToString("N")
docker run --rm -d --name hkdfguard-vault --cap-add=IPC_LOCK `
  -e VAULT_DEV_ROOT_TOKEN_ID=$env:VAULT_ROOT_TOKEN -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 `
  -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

The dev server listens on plain http, which the wrapper allows only on a loopback address such as
`http://127.0.0.1:8200`. It takes a few seconds to start; `curl http://127.0.0.1:8200/v1/sys/health`
answers once it has. A restarted container starts empty, so repeat step 2 after every restart.

> The Vault cache's integration tests (`hkdfguard-cache-hashicorpvault`) can use the same server;
> they read the same `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` and
> `HKDFGUARD_TEST_VAULT_CACERT`, but need a token that can read their KV secret. See
> [Run the HashiCorp Vault cache integration tests](run-hashicorp-vault-cache-integration-tests.md).

## 2. Provision the keys and a token

From the repository root, in Git Bash, macOS or Linux:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN="$VAULT_ROOT_TOKEN" scripts/provision-vault-transit-test-key.sh
```

In PowerShell, run it through Git Bash: `bash scripts/provision-vault-transit-test-key.sh`, with
`$env:VAULT_ADDR` and `$env:VAULT_TOKEN` set first.

The script uses the root token only to provision. It:

1. enables a transit engine at `transit` if nothing is mounted there;
2. creates two `aes256-gcm96` keys, `hkdfguard-test` and `hkdfguard-test-other`;
3. writes the policy `hkdfguard-transit-test`, granting `update` (not `create`) on `encrypt`,
   `decrypt` and `datakey/wrapped` for those two keys only;
4. creates a 24-hour token with only that policy, and prints it.

So the tests run with what a real application would get, not root: they can't create a key by
naming one that doesn't exist, list keys, or touch anything else. Re-running the script is safe; it
keeps the keys and prints a new token. It is the same script as hkdfguard-dotnet's.

Point the script only at a dev server. If yours was started with `-dev-tls`, set `VAULT_CACERT` to
its CA first, and use https below.

> **Security:** the printed token goes in the environment of the shell you run the tests from, and
> nowhere else. Never put it in `vault.test.properties`, `pyproject.toml`, a `.env` file in the
> repository, or an IDE run configuration that is committed, and don't echo it.

## 3. Point the tests at the key

The tests read these variables - the same ones the .NET integration tests read - in the pytest
process:

| Variable | Needed | Meaning |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` | Yes | The transit key to wrap under, `hkdfguard-test`; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_TOKEN` | Yes | The token the script printed; environment only |
| `HKDFGUARD_TEST_VAULT_ADDR` | No | Vault's address; default `http://127.0.0.1:8200` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` | No | A second key, `hkdfguard-test-other`, for the cross-key test; that test is skipped without it |
| `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` | No | The transit mount; default `transit` |
| `HKDFGUARD_TEST_VAULT_CACERT` | No | The path of a CA to trust, for a server started with TLS; then it is the only CA trusted |

Everything but the token can also go in `vault.test.properties` at the repository root, next to
`uv.lock` - the file the Vault cache's integration tests read - so it needn't be set for every
command:

```properties
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200
HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other
```

- **The token is never read from the file.** It is a credential; set it in the environment.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

## 4. Run the tests

From the repository root, in Git Bash, macOS or Linux, with the token from step 2:

```bash
export HKDFGUARD_TEST_VAULT_TOKEN=<token the script printed>
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test \
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
uv run --locked pytest packages/hkdfguard-keywrapping-hashicorpvault
```

In PowerShell:

```powershell
$env:HKDFGUARD_TEST_VAULT_TOKEN = "<token the script printed>"
$env:HKDFGUARD_TEST_VAULT_ADDR = "http://127.0.0.1:8200"
$env:HKDFGUARD_TEST_VAULT_TRANSIT_KEY = "hkdfguard-test"
$env:HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY = "hkdfguard-test-other"
uv run --locked pytest packages/hkdfguard-keywrapping-hashicorpvault
Remove-Item Env:HKDFGUARD_TEST_VAULT_TOKEN, Env:HKDFGUARD_TEST_VAULT_ADDR, Env:HKDFGUARD_TEST_VAULT_TRANSIT_KEY, Env:HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY
```

To run just the integration tests, name the file:
`uv run --locked pytest packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py -v -rs`.

Every test in the file should pass with none skipped:

```text
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_wrap_then_unwrap_round_trips_a_32_byte_dek PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_generate_and_wrap_in_vault_produces_a_wrapped_dek_that_reveals PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_generate_and_wrap_with_a_context_produces_a_wrapped_dek_that_reveals PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_unwrap_under_another_context_or_none_is_refused PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_unwrap_when_tampered_is_refused PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_unwrap_under_another_key_is_refused PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_an_invalid_token_is_refused_with_403 PASSED
packages/hkdfguard-keywrapping-hashicorpvault/tests/test_hashicorpvault_transit_integration.py::test_a_crypto_provider_generates_and_reveals_its_dek_through_vault PASSED
```

In **PyCharm** and **VS Code**, the tests find `vault.test.properties` too: they look in the nearest
directory above the test file that holds `uv.lock`, whatever the working directory. Put the token in
the pytest run configuration's environment variables (PyCharm), or in a `.env` file outside the
repository that your user settings' `python.envFile` points at (VS Code), keeping either out of
version control.

On a CI runner, start the same container as a service, run the provisioning script with the root
token you gave it (`-e VAULT_DEV_ROOT_TOKEN_ID=...`), and pass the printed token to the test step
through the job's environment, masked.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 8 tests skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` isn't set in the pytest process or `vault.test.properties` | Step 3: the file must be in the repository root, next to `uv.lock` |
| 1 test skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` isn't set | Set it to `hkdfguard-test-other` |
| `Failed: Set HKDFGUARD_TEST_VAULT_TOKEN in the environment` | The token isn't in the pytest process's environment | Step 4, in the same shell; it is never read from the file |
| `403 Forbidden` ... `permission denied` | The token expired (24 hours), or the container restarted and the token is gone | Step 2 again |
| `400 Bad Request` ... `encryption key not found` | The container restarted and the keys are gone, or the key name is wrong | Step 2 again |
| `no answer within`, or `Connection refused` / `actively refused it` | The container isn't running, isn't on the port in the address, or is still starting | `docker ps`; check the host port in `-p` and in `HKDFGUARD_TEST_VAULT_ADDR` |
| `curl: (52) Empty reply from server` from the script | The server is still starting | Wait a few seconds and run it again |
| `must be https` | The address isn't loopback and isn't https | Use `127.0.0.1`, or https with `HKDFGUARD_TEST_VAULT_CACERT` |
| `ssl.SSLCertVerificationError` | Vault's certificate isn't trusted, or doesn't name the host | Set `HKDFGUARD_TEST_VAULT_CACERT`; connect by a name the certificate holds |

## When you're done

```bash
docker stop hkdfguard-vault
unset HKDFGUARD_TEST_VAULT_TOKEN VAULT_ROOT_TOKEN
```

The container was started with `--rm`, and a dev server keeps nothing on disk, so stopping it
deletes the keys, the policy and every token. In PowerShell, remove the variables with
`Remove-Item Env:HKDFGUARD_TEST_VAULT_TOKEN, Env:VAULT_ROOT_TOKEN`.
