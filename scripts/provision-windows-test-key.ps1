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

.EXAMPLE
    # From an elevated PowerShell at the repository root:
    ./scripts/provision-windows-test-key.ps1
#>
[CmdletBinding()]
param(
    [ValidatePattern('^(?!\.)(?!.*\.\.)[A-Za-z0-9.]{1,128}$')]
    [string] $ServiceName = 'com.hkdfguard.native.windows.test'
)

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

Write-Host "Provisioning the KEK for service '$ServiceName'..."
& $tool provision --service-name $ServiceName
if ($LASTEXITCODE -ne 0) {
    throw "hkdfguard provision failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host "Service '$ServiceName' is provisioned. The native integration tests now run on this machine:"
Write-Host '    uv run pytest'
