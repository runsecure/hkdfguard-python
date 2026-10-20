#!/usr/bin/env bash
#
# Provisions the TPM-backed KEKs the native integration tests use on Linux.
#
# The libhkdfguard1 package installs no policy and no TPM derivation secret, so on a fresh host
# every wrap fails with "no KEK is provisioned" (-17). This script, run once with sudo from the
# account that runs the tests:
#
#   1. checks the installed hkdfguard packages against dpkg's checksums, and that the test
#      account can open the TPM (it must be in the tss group);
#   2. creates /etc/hkdfguard/tpm.derivation-secret (32 random bytes, root:<test user's group>,
#      0440) if there isn't one - an existing secret is never replaced, because that would change
#      every TPM KEK on this host;
#   3. writes /etc/hkdfguard/policy.toml requiring the TPM, the derivation secret, and a pinned
#      TPM Name for the test service (the provisioning allowlist), learning the Name from the
#      TPM itself through hkdfguard, run as the test user;
#   4. runs "hkdfguard provision" for the service, as the test user, to confirm.
#
# It refuses to overwrite a policy it didn't write. Re-running it is safe: it re-learns the same
# Name (the KEK is derived on demand from the TPM's seed and the secret) and rewrites its own
# policy. It never wraps a DEK and never touches a key file.
#
# Then run the native tests from the repository root:
#
#   HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
#   uv run pytest
#
# The tests' cross-service isolation checks unwrap under a service that is never provisioned. To
# run them against a second real KEK instead, provision one yourself and name it in
# HKDFGUARD_TEST_SERVICE_OTHER.
#
# Every HkdfGuard port's copy of this script (.NET, Go, Java, Node, Python) writes the same
# policy under its own marker, and each accepts the others', so one host can run every port's
# native tests.
#
# Usage:
#   sudo scripts/provision-linux-test-key.sh            # provision
#   sudo scripts/provision-linux-test-key.sh --remove   # remove the policy this script wrote
#
# --remove leaves the derivation secret in place and says how to delete it: deleting it makes
# every DEK wrapped on this host's TPM unrecoverable.

set -euo pipefail

readonly SERVICE="com.hkdfguard.integration.test.221"
readonly TOOL="/usr/bin/hkdfguard"
readonly TPM_DEVICE="/dev/tpmrm0"
readonly ETC_DIR="/etc/hkdfguard"
readonly POLICY="${ETC_DIR}/policy.toml"
readonly SECRET="${ETC_DIR}/tpm.derivation-secret"
readonly MARKER="# Written by hkdfguard-python scripts/provision-linux-test-key.sh - test hosts only."
# Every port's copy of this script writes the same policy under its own marker; any of them
# counts as ours.
readonly KNOWN_MARKERS=(
    "# Written by hkdfguard-dotnet scripts/provision-linux-test-key.sh - test hosts only."
    "# Written by hkdfguard-go keywrapping/nativev1/scripts/provision-linux-test-key.sh - test hosts only."
    "# Written by hkdfguard-java scripts/provision-linux-test-key.sh - test hosts only."
    "# Written by hkdfguard-node packages/keywrapping-native-v1/scripts/provision-linux-test-key.sh - test hosts only."
    "# Written by hkdfguard-python scripts/provision-linux-test-key.sh - test hosts only."
)

die() { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[[ ${EUID} -eq 0 ]] || die "run this with sudo, from the account that runs the tests: sudo $0 $*"

remove=false
case "${1-}" in
    "") ;;
    --remove) remove=true ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument '$1' (expected --remove or nothing)" ;;
esac

policy_is_ours() {
    [[ -f ${POLICY} ]] || return 1
    local first marker
    first="$(head -n 1 "${POLICY}")"
    for marker in "${KNOWN_MARKERS[@]}"; do
        [[ ${first} == "${marker}" ]] && return 0
    done
    return 1
}

if ${remove}; then
    if [[ ! -e ${POLICY} ]]; then
        note "no ${POLICY}; nothing to remove"
    elif policy_is_ours; then
        rm -f -- "${POLICY}"
        note "removed ${POLICY}"
    else
        die "${POLICY} was not written by this script; leaving it alone"
    fi
    if [[ -e ${SECRET} ]]; then
        note "left ${SECRET} in place. Deleting it makes every DEK wrapped on this host's TPM unrecoverable; if that is what you want: sudo rm ${SECRET}"
    fi
    exit 0
fi

# The tests' account: whoever invoked sudo. Root itself is refused, because the tests must prove an
# ordinary account can reach the TPM and read the secret.
TEST_USER="${SUDO_USER-}"
[[ -n ${TEST_USER} && ${TEST_USER} != root ]] || die "run this through sudo from the (non-root) account that runs the tests"
TEST_GROUP="$(id -gn -- "${TEST_USER}")"

# --- Preflight ---------------------------------------------------------------------------------

[[ -x ${TOOL} ]] || die "${TOOL} is not installed; install the hkdfguard and libhkdfguard1 packages first"

# The tool runs below and the library reads the policy written here, so make sure both are the
# files the packages installed. dpkg --verify prints nothing when every checksum matches.
if command -v dpkg >/dev/null; then
    changed="$(dpkg --verify hkdfguard libhkdfguard1 2>&1 || true)"
    [[ -z ${changed} ]] || die "the installed hkdfguard packages don't match their checksums:"$'\n'"${changed}"
fi

[[ -c ${TPM_DEVICE} ]] || die "${TPM_DEVICE} is not present; this host has no usable TPM 2.0 resource manager"
id -nG -- "${TEST_USER}" | tr ' ' '\n' | grep -qx tss \
    || die "${TEST_USER} is not in the tss group, so it can't open ${TPM_DEVICE}: sudo usermod -aG tss ${TEST_USER}, then sign out and in"

if [[ -e ${POLICY} ]] && ! policy_is_ours; then
    die "${POLICY} already exists and was not written by this script; refusing to replace an operator's policy"
fi

# --- Derivation secret -------------------------------------------------------------------------

install -d -m 0755 -o root -g root "${ETC_DIR}"

if [[ -e ${SECRET} ]]; then
    read -r owner mode < <(stat -c '%U %a' -- "${SECRET}")
    [[ ${owner} == root && ${mode} =~ ^[46][04]0$ && ! -L ${SECRET} ]] \
        || die "${SECRET} exists but is not root-owned with mode 0400/0440/0600/0640 (it is ${owner} ${mode}); fix it by hand - replacing it would change every TPM KEK"
    note "keeping the existing ${SECRET}"
else
    tmp="$(mktemp "${ETC_DIR}/.tpm.derivation-secret.XXXXXX")"
    head -c 32 /dev/urandom > "${tmp}"
    chown "root:${TEST_GROUP}" "${tmp}"
    chmod 0440 "${tmp}"
    mv -- "${tmp}" "${SECRET}"
    note "created ${SECRET} (root:${TEST_GROUP}, 0440). Back it up if you will keep wrapped keys: without it no TPM re-derives them."
fi

# --- Policy ------------------------------------------------------------------------------------

# Written beside the destination and renamed over it, so the library never reads a partial file.
write_policy() {
    local tmp
    tmp="$(mktemp "${ETC_DIR}/.policy.toml.XXXXXX")"
    {
        echo "${MARKER}"
        cat <<'EOF'
# The native integration tests' KEKs live on this host's TPM and nowhere else.

[selection]
mode = "require"
provider = "tpm2"

[tpm]
require_derivation_secret = true
require_pinned_names = true

[tpm.pinned_names]
EOF
        local pin
        for pin in "$@"; do echo "${pin}"; done
    } > "${tmp}"
    chown root:root "${tmp}"
    chmod 0644 "${tmp}"
    mv -- "${tmp}" "${POLICY}"
}

provision_as_test_user() {
    sudo -u "${TEST_USER}" -- "${TOOL}" provision --service-name "$1" 2>&1
}

# With the allowlist on and nothing pinned, provision fails and prints the Name this TPM derives
# for the service - through the production derivation, derivation secret included.
learn_name() {
    local output name
    output="$(provision_as_test_user "$1" || true)"
    name="$(grep -oE '"000b[0-9a-f]{64}"' <<<"${output}" | head -n 1 | tr -d '"')"
    [[ -n ${name} ]] || die "could not learn the TPM Name for $1; hkdfguard said:"$'\n'"${output}"
    echo "${name}"
}

write_policy
note "learning the test service's TPM Name (this takes about a second)"
service_name="$(learn_name "${SERVICE}")"

write_policy "\"${SERVICE}\" = \"${service_name}\""
if command -v python3 >/dev/null; then
    python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "${POLICY}" \
        || die "${POLICY} is not valid TOML"
fi
note "wrote ${POLICY}"

# --- Confirm -----------------------------------------------------------------------------------

output="$(provision_as_test_user "${SERVICE}")" \
    || die "provision failed for ${SERVICE} as ${TEST_USER}:"$'\n'"${output}"
note "${SERVICE}: provisioned on the TPM"

cat <<EOF

Done. Run the native integration tests as ${TEST_USER}, from the hkdfguard-python repository root:

  HKDFGUARD_TEST_SERVICE=${SERVICE} \\
  uv run pytest
EOF
