# Run the Azure Key Vault integration tests

`test_azurekeyvault_integration.py` in `hkdfguard-keywrapping-azurekeyvault` makes real calls to
Azure Key Vault through `AzureKeyVaultKeyWrapper`. This page sets up a test vault with the two keys
the wrapper needs, and runs the tests from the command line and the IDE.

The other tests in the package use an in-process fake vault, or the Azure SDK's own client over a
stubbed HTTP transport, and run without any of this. The integration tests are reported as
**skipped**, never passed, until both keys are configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generate_and_wrap` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a wrapped DEK made under one context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change or delete a key.

If you already run hkdfguard-dotnet's or hkdfguard-java's Azure Key Vault integration tests, you
have a vault, both keys and access: skip to [step 5](#5-fill-in-azuretestproperties) and use the
same two identifiers.

## What you need

- An Azure subscription. A free account works; a test run is about 20 Key Vault operations, a
  fraction of a cent, and software-protected keys have no monthly fee.
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli).
- [uv](https://docs.astral.sh/uv/), and this repository synced (`uv sync`), which installs
  `azure-identity` for the tests.

## 1. Sign in

```bash
az login
az account show --query "{subscription:name, tenant:tenantId, user:user.name}" -o table
```

If the subscription isn't the one you want, run `az account set --subscription "<name or id>"`.

## 2. Create a test vault

Use a vault only for tests, never one that protects real data. Vault names are globally unique:
3 to 24 letters, digits and hyphens.

```bash
rg=hkdfguard-test-rg
vault=<key vault name>
loc=eastus2

az group create --name $rg --location $loc
az keyvault create --name $vault --resource-group $rg --location $loc \
  --enable-rbac-authorization true --retention-days 7
```

Purge protection is left off so the test vault can be deleted completely afterwards. A vault that
protects real data should have it on; see
[Wrap keys with Azure Key Vault](use-azure-key-vault.md#1-create-the-keys).

## 3. Give yourself access

Creating keys and running the tests both need Key Vault's crypto operations. Assign yourself
**Key Vault Crypto Officer** on the test vault:

```bash
me=$(az ad signed-in-user show --query id -o tsv)
vaultId=$(az keyvault show --name $vault --query id -o tsv)

az role assignment create --assignee $me --role "Key Vault Crypto Officer" --scope $vaultId
```

A role assignment takes a minute or two to apply.

> **Security:** Crypto Officer includes `sign`, which is fine for your own test identity on a test
> vault. A deployed application must never have `sign` on the signing key; see the role table in
> [Wrap keys with Azure Key Vault](use-azure-key-vault.md#2-grant-each-identity-only-what-it-calls).

## 4. Create the two keys

An RSA key to wrap, and an EC P-256 key to sign, each allowed only its own two operations:

```bash
az keyvault key create --vault-name $vault --name hkdfguard-test-wrap --kty RSA --size 2048 --ops wrapKey unwrapKey
az keyvault key create --vault-name $vault --name hkdfguard-test-sign --kty EC --curve P-256 --ops sign verify
```

If either fails with `Forbidden`, the role from step 3 hasn't applied yet; wait a minute and run it
again.

Check the identifiers before running the tests:

```bash
az keyvault key show --id "https://$vault.vault.azure.net/keys/hkdfguard-test-wrap" --query "key.kty" -o tsv
az keyvault key show --id "https://$vault.vault.azure.net/keys/hkdfguard-test-sign" --query "key.crv" -o tsv
```

The first must print `RSA`, the second `P-256`.

## 5. Fill in azure.test.properties

The tests read the two key identifiers as `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID` and
`HKDFGUARD_TEST_AZURE_SIGN_KEY_ID`. Rather than set them for every command, create
`azure.test.properties` in the repository root, next to `uv.lock` - this repository's counterpart
of hkdfguard-dotnet's `azure.runsettings`, and the same file hkdfguard-java reads:

```properties
# The RSA key that wraps DEKs: its key identifier without a version.
HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-wrap

# The EC P-256 key that signs wrapped DEKs: its key identifier without a version.
HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-sign
```

Replace `<key vault name>`, brackets included, with the name from step 2. If you already have an
`azure.runsettings` for hkdfguard-dotnet or an `azure.test.properties` for hkdfguard-java, use the
same two identifiers, or copy the Java file as it is.

- **Leave the version off.** The wrapper then uses each key's current version, as it would in
  production.
- **No credentials go in the file.** `DefaultAzureCredential` signs in with your `az login`.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

## 6. Run the tests

From the repository root:

```bash
uv run --locked pytest packages/hkdfguard-keywrapping-azurekeyvault
```

Without the file, set both variables for the one command instead, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://$vault.vault.azure.net/keys/hkdfguard-test-wrap \
HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://$vault.vault.azure.net/keys/hkdfguard-test-sign \
uv run --locked pytest packages/hkdfguard-keywrapping-azurekeyvault
```

To run just the integration tests, name the file:
`uv run --locked pytest packages/hkdfguard-keywrapping-azurekeyvault/tests/test_azurekeyvault_integration.py -v -rs`.

Every test in the file should pass with none skipped:

```text
packages/hkdfguard-keywrapping-azurekeyvault/tests/test_azurekeyvault_integration.py::test_wrap_then_unwrap_round_trips_a_32_byte_dek PASSED
packages/hkdfguard-keywrapping-azurekeyvault/tests/test_azurekeyvault_integration.py::test_generate_and_wrap_produces_a_wrapped_dek_that_reveals PASSED
packages/hkdfguard-keywrapping-azurekeyvault/tests/test_azurekeyvault_integration.py::test_unwrap_under_another_context_is_refused PASSED
packages/hkdfguard-keywrapping-azurekeyvault/tests/test_azurekeyvault_integration.py::test_unwrap_when_tampered_is_refused PASSED
```

In **PyCharm** and **VS Code**, the tests find `azure.test.properties` too: they look in the nearest
directory above the test file that holds `uv.lock`, whatever the working directory. Either way,
`DefaultAzureCredential` may sign in with the IDE's Azure account before `az login`'s: sign it into
the same account.

On a CI runner, set the two variables in the job and sign in with a federated identity (for
example GitHub's OIDC provider and `azure/login`) rather than storing a client secret.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 4 tests skipped | Neither `azure.test.properties` nor the environment names both keys | Step 5: the file must be in the repository root, next to `uv.lock` |
| `... isn't a key identifier` | A placeholder is still in the file or a variable | Step 5 |
| `Forbidden (HTTP 403)` or `ForbiddenByRbac` | The role assignment hasn't applied, or is on another vault | Wait; check with `az role assignment list --assignee $me --scope $vaultId -o table` |
| `KeyNotFound (HTTP 404)` | A vault or key name is wrong | Step 4's check commands |
| `DefaultAzureCredential failed to retrieve a token`, or a tenant error | `DefaultAzureCredential` found no sign-in, or picked an account in another tenant | `az login` again, or set `AZURE_TENANT_ID` for the command |
| `The signing key must be an EC P-256 key` | The two identifiers are swapped, or the signing key is another curve | Step 4's check commands |

## When you're done

Delete the resource group, then purge the vault so its name can be reused:

```bash
az group delete --name $rg --yes
az keyvault purge --name $vault --location $loc
```

Until it's purged, a deleted vault is kept for its 7-day retention period, at no cost.
