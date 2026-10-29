#!/usr/bin/env bash
#
# Provisions the transit keys the HashiCorp Vault transit integration tests use, on a throwaway
# Vault dev server (vault server -dev, e.g. in Docker), and prints a token that may use only them.
#
# Run it with the dev server's root token, which it uses only to provision:
#
#   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh
#
# It:
#
#   1. enables a transit secrets engine at "transit" if nothing is mounted there;
#   2. creates two aes256-gcm96 keys, hkdfguard-test and hkdfguard-test-other (the second is only
#      ever asked to unwrap what the first wrapped, and must refuse);
#   3. writes the policy hkdfguard-transit-test, granting update - not create - on encrypt,
#      decrypt and datakey/wrapped for those two keys and nothing else, so a test can't create a
#      key by naming one that doesn't exist;
#   4. creates a token with only that policy (24 hours, renewable) and prints it.
#
# Re-running it is safe: existing keys and the mount are kept, the policy is rewritten and a new
# token is printed. A dev server keeps everything in memory, so run it again after the container
# restarts. Point it only at a dev server: never at a Vault that holds anything real.
#
# Set VAULT_CACERT to the dev server's CA if it was started with TLS (-dev-tls).
#
# Then run the tests (see docs/how-to/run-hashicorp-vault-transit-integration-tests.md):
#
#   HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=<printed token> \
#   HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test \
#   uv run pytest packages/hkdfguard-keywrapping-hashicorpvault

set -euo pipefail

: "${VAULT_ADDR:?Set VAULT_ADDR to the dev server, e.g. http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?Set VAULT_TOKEN to the root token of the dev server}"

MOUNT=transit
KEYS=(hkdfguard-test hkdfguard-test-other)
POLICY=hkdfguard-transit-test

curl_args=(--silent --show-error --fail-with-body -H "X-Vault-Token: ${VAULT_TOKEN}" -H "X-Vault-Request: true")
if [[ -n "${VAULT_CACERT:-}" ]]; then
    curl_args+=(--cacert "${VAULT_CACERT}")
fi

vault() {
    local method=$1 path=$2 body=${3:-}
    if [[ -n "${body}" ]]; then
        curl "${curl_args[@]}" -X "${method}" "${VAULT_ADDR%/}/v1/${path}" -d "${body}"
    else
        curl "${curl_args[@]}" -X "${method}" "${VAULT_ADDR%/}/v1/${path}"
    fi
}

if vault GET "sys/mounts" | grep -q "\"${MOUNT}/\""; then
    echo "transit engine already mounted at ${MOUNT}/" >&2
else
    vault POST "sys/mounts/${MOUNT}" '{"type":"transit"}' >/dev/null
    echo "mounted a transit engine at ${MOUNT}/" >&2
fi

for key in "${KEYS[@]}"; do
    # Creating a key that exists leaves it as it is.
    vault POST "${MOUNT}/keys/${key}" '{"type":"aes256-gcm96"}' >/dev/null
    echo "key ${MOUNT}/keys/${key} ready" >&2
done

# One HCL rule per line, then as a JSON string: quotes escaped, each line ended with \n.
rules=""
for key in "${KEYS[@]}"; do
    for op in encrypt decrypt datakey/wrapped; do
        rules+="path '${MOUNT}/${op}/${key}' { capabilities = ['update'] }"$'\n'
    done
done
rules_json=$(printf '%s' "${rules}" | tr "'" '"' | sed 's/"/\\"/g' | awk '{ printf "%s\\n", $0 }')
vault PUT "sys/policies/acl/${POLICY}" "{\"policy\":\"${rules_json}\"}" >/dev/null
echo "policy ${POLICY} written" >&2

response=$(vault POST "auth/token/create" "{\"policies\":[\"${POLICY}\"],\"no_default_policy\":true,\"ttl\":\"24h\",\"renewable\":true,\"display_name\":\"hkdfguard-transit-test\"}")
token=$(printf '%s' "${response}" | sed -E 's/.*"client_token":"([^"]+)".*/\1/')
echo "token with only ${POLICY}, valid 24 hours:" >&2
printf '%s\n' "${token}"
