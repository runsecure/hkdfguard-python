# Run the Azure Key Vault secret cache integration tests

`test_azurekeyvault_secret_cache_integration.py` in `hkdfguard-cache-azurekeyvault` makes real
calls to Azure Key Vault through `AzureKeyVaultSecretCache`. This page sets up a test vault with a
secret for it to read, and runs the tests from the command line and the IDE.

The other tests in the package use the Azure SDK's own `SecretClient` over a stubbed HTTP transport,
and run without any of this. The integration tests are reported as **skipped**, never passed, until a
secret is configured.

With only the secret named, they check that:

- `decrypt` and `decrypt_async` reveal the secret (something non-empty);
- a secret that doesn't exist returns 0.

Name the JSON object the secret holds as well, and they also check that:

- the whole value is that object (compared as JSON, so whitespace doesn't matter);
- every member reads back as `name#key` - a string as its text, a number, `true` or `false` as its
  JSON text - and `name#no-such-key` returns 0, through `decrypt` and `decrypt_async`;
- optionally, each member is also a secret of its own, named by its key, holding the same value,
  and reads back under its name in upper case too (Key Vault ignores case).

The tests never list, create, change or delete a secret.

If you already run hkdfguard-dotnet's or hkdfguard-java's Azure Key Vault secret cache integration
tests, you have a vault, a secret and access: skip to
[step 5](#5-fill-in-azuretestproperties) and use the same values.

## What you need

- An Azure subscription. A free account works; a test run is a handful of Key Vault operations, a
  fraction of a cent.
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

Use a vault only for tests, never one that holds real secrets. Vault names are globally unique: 3
to 24 letters, digits and hyphens. The key wrapping tests' vault
([Run the Azure Key Vault integration tests](run-azure-key-vault-integration-tests.md)) can hold the
test secret too.

```bash
rg=hkdfguard-test-rg
vault=<key vault name>
loc=eastus2

az group create --name $rg --location $loc
az keyvault create --name $vault --resource-group $rg --location $loc \
  --enable-rbac-authorization true --retention-days 7
```

## 3. Give yourself access

Creating the secrets needs **Key Vault Secrets Officer**; reading them, which is all the tests do,
needs only **Key Vault Secrets User** - the role a deployed application should have:

```bash
me=$(az ad signed-in-user show --query id -o tsv)
vaultId=$(az keyvault show --name $vault --query id -o tsv)

az role assignment create --assignee $me --role "Key Vault Secrets Officer" --scope $vaultId
```

A role assignment takes a minute or two to apply.

## 4. Create the secrets

One secret holding a JSON object, as a key/value secret does:

```bash
az keyvault secret set --vault-name $vault --name hkdfguard-test-login \
  --value '{"username":"app","password":"not-a-real-password","port":5432}'
```

For the separate-secrets check, also store each member as a secret of its own, named by its key
(a key is then also a Key Vault secret name: letters, digits and hyphens only):

```bash
az keyvault secret set --vault-name $vault --name username --value app
az keyvault secret set --vault-name $vault --name password --value not-a-real-password
az keyvault secret set --vault-name $vault --name port --value 5432
```

If a command fails with `Forbidden`, the role from step 3 hasn't applied yet; wait a minute and run
it again.

## 5. Fill in azure.test.properties

The tests read three settings:

| Setting | Holds | Without it |
|---|---|---|
| `HKDFGUARD_TEST_AZURE_SECRET_ID` | The secret's identifier, without a version: `https://<vault>.vault.azure.net/secrets/<name>` | Every test is skipped |
| `HKDFGUARD_TEST_AZURE_SECRET_JSON` | The JSON object the secret holds | The content checks are skipped |
| `HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS` | `true` when the vault also holds each member as a secret named by its key | The separate-secrets check is skipped |

Rather than set them for every command, add them to `azure.test.properties` in the repository root,
next to `uv.lock` - the same file the key wrapping integration tests and hkdfguard-java read:

```properties
# The secret the secret cache reads: its identifier without a version.
HKDFGUARD_TEST_AZURE_SECRET_ID=https://<key vault name>.vault.azure.net/secrets/hkdfguard-test-login

# Optional: the JSON object that secret holds, to check its contents.
HKDFGUARD_TEST_AZURE_SECRET_JSON={"username":"app","password":"not-a-real-password","port":5432}

# Optional: true when each member above is also a secret of its own, named by its key.
HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true
```

Replace `<key vault name>`, brackets included, with the name from step 2.

- **Leave the version off.** The cache reads the secret's current version, as it would in production.
- **Use a test value.** The expected JSON is the secret's value in plain text: never put a real
  secret in the file.
- **No credentials go in the file.** `DefaultAzureCredential` signs in with your `az login`.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins**, even when it is set to empty: set one for a
  single command, or on a CI runner, to override the file - or set it empty to skip those tests
  without editing the file.

## 6. Run the tests

From the repository root:

```bash
uv run --locked pytest packages/hkdfguard-cache-azurekeyvault
```

Without the file, set the variables for the one command instead, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_AZURE_SECRET_ID=https://$vault.vault.azure.net/secrets/hkdfguard-test-login \
HKDFGUARD_TEST_AZURE_SECRET_JSON='{"username":"app","password":"not-a-real-password","port":5432}' \
HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true \
uv run --locked pytest packages/hkdfguard-cache-azurekeyvault
```

To run just the integration tests, name the file:
`uv run --locked pytest packages/hkdfguard-cache-azurekeyvault/tests/test_azurekeyvault_secret_cache_integration.py -v -rs`.

With all three settings, every test in the file should pass with none skipped:

```text
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_reveals_the_secret PASSED
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_async_reveals_the_secret PASSED
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_reveals_the_expected_whole_value PASSED
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_reveals_every_key_the_secret_holds PASSED
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_async_reveals_every_key_the_secret_holds_and_the_whole_value PASSED
...test_azurekeyvault_secret_cache_integration.py::test_each_key_is_also_a_secret_of_its_own_holding_the_same_value PASSED
...test_azurekeyvault_secret_cache_integration.py::test_decrypt_of_a_secret_that_does_not_exist_returns_zero PASSED
```

In **PyCharm** and **VS Code**, the tests find `azure.test.properties` too: they look in the nearest
directory above the test file that holds `uv.lock`, whatever the working directory. Either way,
`DefaultAzureCredential` may sign in with the IDE's Azure account before `az login`'s: sign it into
the same account.

On a CI runner, set the variables in the job and sign in with a federated identity (for example
GitHub's OIDC provider and `azure/login`) rather than storing a client secret.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 7 tests skipped | Neither `azure.test.properties` nor the environment names the secret, or an empty environment variable overrides the file | Step 5: the file must be in the repository root, next to `uv.lock` |
| `... isn't a secret identifier without a version` | A placeholder is still in the file or a variable, or the identifier has a version or names a key | Step 5 |
| `... isn't a JSON object` | `HKDFGUARD_TEST_AZURE_SECRET_JSON` is an array, a string, or not JSON | Step 5; in a shell, quote it with single quotes |
| `HttpResponseError` with status 403 (`Forbidden`, `ForbiddenByRbac`) | The role assignment hasn't applied, or is on another vault | Wait; check with `az role assignment list --assignee $me --scope $vaultId -o table` |
| `Nothing is stored under '<name>'` for the secret itself | The secret doesn't exist (a 404 reads as missing), or its value is empty | `az keyvault secret show --id <identifier>` |
| `Nothing is stored under '<name>#<key>'` | The secret doesn't hold that member, or the member is null, an object or an array | Compare the secret's value with the expected JSON |
| A separate-secrets failure | A member isn't stored as a secret of its own, or holds another value | Step 4 |
| `DefaultAzureCredential failed to retrieve a token`, or a tenant error | `DefaultAzureCredential` found no sign-in, or picked an account in another tenant | `az login` again, or set `AZURE_TENANT_ID` for the command |

## When you're done

Delete the resource group, then purge the vault so its name can be reused:

```bash
az group delete --name $rg --yes
az keyvault purge --name $vault --location $loc
```

Until it's purged, a deleted vault is kept for its 7-day retention period, at no cost.
