# make_test_cert.ps1 -- create (once) the sandbox driver test-signing cert and
# sign SandboxGuard.sys with it.
#
# Test-signing model: self-signed code-signing cert in the host's
# LocalMachine stores; the SAME cert is exported (.cer) and imported in the
# guest's Root + TrustedPublisher stores by the spike script, and the guest
# runs with `bcdedit /set testsigning on` (disposable VM).
#
# Usage:  powershell -File guardian\make_test_cert.ps1            # create + sign
#         powershell -File guardian\make_test_cert.ps1 -SignOnly  # just re-sign

param([switch]$SignOnly)

$ErrorActionPreference = "Stop"
$root   = Split-Path -Parent $PSScriptRoot
$sys    = Join-Path $PSScriptRoot "out\x64\Release\SandboxGuard.sys"
$cerOut = Join-Path $PSScriptRoot "out\SandboxGuardTest.cer"
$certSubject = "CN=SandboxGuard Test Cert"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

if (-not (Test-Path $signtool)) { throw "signtool not found: $signtool" }
if (-not (Test-Path $sys)) { throw "driver not built: $sys (run build_guardian.ps1 first)" }

$cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
$storeScope = "LocalMachine"
if (-not $cert) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
    if ($cert) { $storeScope = "CurrentUser" }
}
if (-not $cert) {
    if ($SignOnly) { throw "cert '$certSubject' not found and -SignOnly given" }
    # Prefer LocalMachine (needs admin); fall back to CurrentUser so the
    # signing pipeline works from a non-elevated shell too. Only the public
    # .cer crosses into the guest, so the host store scope is not security-
    # relevant for the spike.
    try {
        Write-Host "[cert] creating self-signed code-signing cert '$certSubject' in LocalMachine\My"
        $cert = New-SelfSignedCertificate -Type Custom -Subject $certSubject `
            -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
            -FriendlyName "SandboxGuard Test Cert" `
            -CertStoreLocation Cert:\LocalMachine\My `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") `
            -NotAfter (Get-Date).AddYears(5) -ErrorAction Stop
    } catch {
        Write-Host "[cert] LocalMachine not writable (non-elevated shell) -> CurrentUser\My"
        $cert = New-SelfSignedCertificate -Type Custom -Subject $certSubject `
            -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
            -FriendlyName "SandboxGuard Test Cert" `
            -CertStoreLocation Cert:\CurrentUser\My `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") `
            -NotAfter (Get-Date).AddYears(5)
        $storeScope = "CurrentUser"
    }
} else {
    Write-Host "[cert] reusing existing '$certSubject' (thumbprint $($cert.Thumbprint), $storeScope)"
}

# Export the public cert for guest-side import (Root + TrustedPublisher).
Export-Certificate -Cert $cert -FilePath $cerOut -Force | Out-Null
Write-Host "[cert] exported public cert -> $cerOut"

Write-Host "[sign] signing $sys (sha256, store $storeScope)..."
$storeArgs = @()
if ($storeScope -eq "LocalMachine") { $storeArgs = @("/sm") }
& $signtool sign /fd sha256 /sha1 $cert.Thumbprint /s My @storeArgs /v $sys
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
# NOTE: `signtool verify` against a self-signed root reports "untrusted root"
# on the host -- expected. Trust is established guest-side (cert import into
# Root + TrustedPublisher + testsigning on), which is what the spike tests.
Write-Host "[sign] OK (host 'untrusted root' on verify is expected for a self-signed test cert)"
