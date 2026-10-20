<#
.SYNOPSIS
    Provisions the KEK the native integration tests use on Windows.

.DESCRIPTION
    Runs the installed HkdfGuard command-line tool's (hkdfguard.exe) "provision" command for the test service name, which creates
    a machine-wide KEK for it in the Platform Crypto Provider (TPM), or re-verifies it if it already
    exists. Safe to run repeatedly. It never wraps a DEK and never touches a key file.

    Must run from an elevated PowerShell: creating a machine-wide KEK requires administrator rights.

    Before running the tool, the script checks that it is the signed HkdfGuard tool from the fixed
    install location - the same publisher, pinned root and Artifact Signing profile the library's
    own loader requires - so an elevated session never runs an impostor.

    Once provisioned, the native tests in hkdfguard-keywrapping-v1 and hkdfguard-dataencryptionkey run
    automatically on this machine instead of being reported as skipped:

        uv run pytest

.PARAMETER ServiceName
    The service whose KEK to provision. Defaults to the name the tests use.

.PARAMETER Remove
    Retires (deletes) the test KEK instead of provisioning it, and the legacy test KEK
    com.hkdfguard.native.windows.test too if this machine still has it. Each KEK is deleted only
    after "hkdfguard status" reports its fingerprint, which "hkdfguard retire" must match; a key
    status reports as corrupt is retired with --corrupt. Asks before deleting each one (pass
    -Confirm:$false to skip the prompt, or -WhatIf to see what would be deleted).

.PARAMETER KeepLegacyKey
    Leaves the legacy test KEK com.hkdfguard.native.windows.test in place. By default a provisioning
    run retires it, after asking: every HkdfGuard port now shares com.hkdfguard.integration.test.221,
    so the old one is no longer used.

.EXAMPLE
    # From an elevated PowerShell at the repository root:
    ./scripts/provision-windows-test-key.ps1
.EXAMPLE
    # Remove this machine's test KEKs - the current one and, if present, the legacy one:
    ./provision-windows-test-key.ps1 -Remove

.EXAMPLE
    # Provision without retiring the legacy test KEK:
    ./provision-windows-test-key.ps1 -KeepLegacyKey
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^(?!\.)(?!.*\.\.)[A-Za-z0-9.]{1,128}$')]
    [string] $ServiceName = 'com.hkdfguard.integration.test.221',

    [switch] $Remove,

    [switch] $KeepLegacyKey
)

# The per-platform test KEK every port used before they shared com.hkdfguard.integration.test.221.
$LegacyServiceName = 'com.hkdfguard.native.windows.test'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The same publisher, root and Artifact Signing profile WindowsNativeLibraryLoader requires of
# HkdfGuard.dll (EXPECTED_PUBLISHER, EXPECTED_ROOT_SHA256, EXPECTED_PROFILE_EKU). Only the root is
# pinned: Artifact Signing reissues the leaf every few days and rotates its intermediates.
$ExpectedPublisher = 'CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US'
$ExpectedRootSha256 = '5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270'
$ExpectedProfileEku = '1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563'
$CodeSigningEku = '1.3.6.1.5.5.7.3.3'

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'This script provisions a Windows KEK and must run on Windows.'
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Creating a machine-wide KEK requires an elevated process. Re-run this script from an elevated PowerShell ("Run as administrator").'
}

# The known-folder location, not the ProgramFiles environment variable, which any process can change.
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$tool = Join-Path $programFiles 'HkdfGuard\v1\hkdfguard.exe'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
    throw "The HkdfGuard command-line tool (hkdfguard.exe) is not installed at '$tool'. Install the HkdfGuard native package first."
}

$signature = Get-AuthenticodeSignature -LiteralPath $tool
if ($signature.Status -ne 'Valid') {
    throw "'$tool' does not carry a valid Authenticode signature (status: $($signature.Status)). Refusing to run it elevated."
}
if ($signature.SignerCertificate.Subject -ne $ExpectedPublisher) {
    throw "'$tool' is signed by '$($signature.SignerCertificate.Subject)', not the HkdfGuard publisher. Refusing to run it elevated."
}

# Get-AuthenticodeSignature has checked the chain is trusted, but any trusted root could issue that
# subject. Rebuild the chain offline from the certificates embedded in the signature to see which
# root it ends at. Expiry is ignored: the leaf lives only days, and the signature's timestamp,
# already verified above, is what keeps it valid.
$embedded = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$embedded.Import($tool)
$chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $policy = $chain.ChainPolicy
    $policy.RevocationMode = 'NoCheck'
    $policy.VerificationFlags = 'IgnoreNotTimeValid'
    $policy.ExtraStore.AddRange($embedded)
    if ($policy.PSObject.Properties['DisableCertificateDownloads']) {
        $policy.DisableCertificateDownloads = $true # not in Windows PowerShell's .NET Framework
    }
    if (-not $chain.Build($signature.SignerCertificate)) {
        throw "'$tool' has no complete, trusted certificate chain ($(($chain.ChainStatus | ForEach-Object Status) -join ', ')). Refusing to run it elevated."
    }
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $rootSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($root.RawData)) -replace '-', ''
}
finally {
    $chain.Dispose()
}
if ($rootSha256 -ne $ExpectedRootSha256) {
    throw "'$tool' chains to '$($root.Subject)' (SHA-256 $rootSha256), not the Artifact Signing root HkdfGuard is signed under. Refusing to run it elevated."
}

$ekus = @($signature.SignerCertificate.EnhancedKeyUsageList | ForEach-Object ObjectId)
if ($ekus -cnotcontains $CodeSigningEku -or $ekus -cnotcontains $ExpectedProfileEku) {
    throw "'$tool' is not signed for code signing under HkdfGuard's Artifact Signing profile (EKUs: $($ekus -join ', ')). Refusing to run it elevated."
}

# What "hkdfguard status" reports for a service: State is present, absent, corrupt or unusable,
# and Fingerprint the 64 hex characters retire needs (when the KEK has one). Read-only.
function Get-KekStatus([string] $Service) {
    $output = @(& $tool status --service-name $Service 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) {
        throw "hkdfguard status could not tell whether '$Service' has a KEK (exit code $LASTEXITCODE):`n$($output -join "`n")"
    }
    $state = ($output | Where-Object { $_ -match '^kek:\s*(\S+)' } | Select-Object -First 1) -replace '^kek:\s*', ''
    $fingerprint = ($output | Where-Object { $_ -match '^fingerprint:\s*[0-9a-fA-F]{64}\s*$' } | Select-Object -First 1) -replace '^fingerprint:\s*', ''
    if (-not $state) {
        throw "Could not read the KEK state for '$Service' from hkdfguard status:`n$($output -join "`n")"
    }
    [pscustomobject]@{ State = $state.Trim(); Fingerprint = "$fingerprint".Trim(); Output = $output }
}

# Retires a service's KEK after checking which key it is, asking first (ShouldProcess). Returns
# whether a KEK was deleted.
function Remove-TestKek([string] $Service) {
    $status = Get-KekStatus $Service
    switch ($status.State) {
        'absent' {
            Write-Host "Service '$Service' has no KEK; nothing to remove."
            return $false
        }
        'corrupt' {
            $arguments = @('retire', '--service-name', $Service, '--corrupt')
            $what = "the corrupt key under '$Service'"
        }
        default {
            if ($status.Fingerprint -notmatch '^[0-9a-fA-F]{64}$') {
                throw "hkdfguard status reported '$Service' as $($status.State) without a fingerprint; retire it by hand:`n$($status.Output -join "`n")"
            }
            $arguments = @('retire', '--service-name', $Service, '--fingerprint', $status.Fingerprint)
            $what = "the KEK for '$Service' (fingerprint $($status.Fingerprint))"
        }
    }

    if (-not $PSCmdlet.ShouldProcess($what, 'Retire (permanently delete)')) {
        return $false
    }
    & $tool @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "hkdfguard retire failed for '$Service' with exit code $LASTEXITCODE. If both key stores hold a key for it, run hkdfguard status and retire it by hand with --provider tpm or --provider software."
    }
    Write-Host "Retired $what."
    return $true
}

if ($Remove) {
    $null = Remove-TestKek $ServiceName
    if ($ServiceName -ne $LegacyServiceName) {
        $null = Remove-TestKek $LegacyServiceName
    }
    return
}

Write-Host "Provisioning the KEK for service '$ServiceName'..."
& $tool provision --service-name $ServiceName
if ($LASTEXITCODE -ne 0) {
    throw "hkdfguard provision failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host "Service '$ServiceName' is provisioned. The native integration tests now run on this machine:"
Write-Host '    uv run pytest'

# Every port now shares one test KEK; retire the per-platform one an earlier version of this script
# provisioned, unless asked to keep it. Nothing is said when it isn't there.
if (-not $KeepLegacyKey -and $ServiceName -ne $LegacyServiceName -and (Get-KekStatus $LegacyServiceName).State -ne 'absent') {
    Write-Host ''
    Write-Host "This machine still has the legacy test KEK '$LegacyServiceName', which no test uses any more."
    $null = Remove-TestKek $LegacyServiceName
}
