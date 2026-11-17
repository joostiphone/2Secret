<#
.SYNOPSIS
  Builds and signs 2Secret's Windows identity package
  (crates/app/windows/identity/2Secret-identity.msix), which a passkey
  provider for Windows 11 needs (crates/app/src/windows_passkeys.rs).

.DESCRIPTION
  The package holds only crates/app/windows/identity/AppxManifest.xml. It must
  be signed with a certificate whose subject is exactly the manifest's
  Publisher, and Windows installs it only when it trusts that certificate:
  one from a certification authority Windows trusts for everyone, or a test
  certificate this PC trusts (-NewTestCertificate). Needs the Windows SDK
  (MakeAppx.exe, SignTool.exe), as on GitHub's windows-latest runners.

.EXAMPLE
  # A test certificate for this PC (and for the WINDOWS_IDENTITY_CERTIFICATE secret):
  scripts\windows-identity-package.ps1 -NewTestCertificate -Password 'choose-one'

.EXAMPLE
  scripts\windows-identity-package.ps1 -Certificate cert.pfx -Password 'its-password'
#>
param(
  [string]$Certificate,
  [string]$Password,
  [string]$TimestampUrl,
  [switch]$NewTestCertificate
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$identity = Join-Path $root 'crates\app\windows\identity'
$manifestPath = Join-Path $identity 'AppxManifest.xml'
$exeManifestPath = Join-Path $root 'crates\app\windows\2Secret.exe.manifest'
$output = Join-Path $identity '2Secret-identity.msix'

[xml]$manifest = Get-Content -Raw $manifestPath
[xml]$exeManifest = Get-Content -Raw $exeManifestPath
$publisher = $manifest.Package.Identity.Publisher
$msix = $exeManifest.assembly.msix
if ($msix.publisher -ne $publisher -or $msix.packageName -ne $manifest.Package.Identity.Name -or
    $msix.applicationId -ne $manifest.Package.Applications.Application.Id) {
  throw "2Secret.exe.manifest and AppxManifest.xml name different identities"
}

if ($NewTestCertificate) {
  if (-not $Password) { throw '-Password is needed for the .pfx file' }
  # As in https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing
  $cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -Subject $publisher `
    -FriendlyName '2Secret identity package (test)' -CertStoreLocation 'Cert:\CurrentUser\My' `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}') -NotAfter (Get-Date).AddYears(3)
  $secure = ConvertTo-SecureString -String $Password -Force -AsPlainText
  $pfx = Join-Path $identity '2Secret-test.pfx'
  $cer = Join-Path $identity '2Secret-test.cer'
  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null
  Export-Certificate -Cert $cert -FilePath $cer | Out-Null
  # This PC trusts packages signed with it (only this user).
  Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
  Write-Host "Test certificate: $pfx (keep it private) and $cer (trusted on this PC)."
  Write-Host "For the WINDOWS_IDENTITY_CERTIFICATE secret: [Convert]::ToBase64String([IO.File]::ReadAllBytes('$pfx'))"
  $Certificate = $pfx
}

if (-not $Certificate) { throw '-Certificate (a .pfx file) or -NewTestCertificate is needed' }
$loaded = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Certificate, $Password)
if ($loaded.Subject -ne $publisher) {
  throw "The certificate's subject is '$($loaded.Subject)', but the package's Publisher is '$publisher'. Change Publisher in AppxManifest.xml and publisher in 2Secret.exe.manifest to the subject."
}

# The newest Windows SDK tools for this machine.
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
function Find-Tool($name) {
  # Versioned folders only: MakeAppx before SDK 10.0.19041 does not know uap10.
  $tool = Get-ChildItem -Path $kits -Filter $name -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq $arch -and $_.Directory.Parent.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1
  if (-not $tool) { throw "$name not found under $kits (install the Windows SDK)" }
  $tool.FullName
}
$makeAppx = Find-Tool 'makeappx.exe'
$signTool = Find-Tool 'signtool.exe'

# Only the manifest: the logos and the program are at the external location.
$staging = Join-Path ([IO.Path]::GetTempPath()) ('2secret-identity-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $staging | Out-Null
Copy-Item $manifestPath (Join-Path $staging 'AppxManifest.xml')
try {
  # /nv: the files the manifest names are not in the package.
  & $makeAppx pack /o /nv /d $staging /p $output
  if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed ($LASTEXITCODE)" }
} finally {
  Remove-Item -Recurse -Force $staging
}
$signArgs = @('sign', '/fd', 'SHA256', '/f', $Certificate)
if ($Password) { $signArgs += @('/p', $Password) }
if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
& $signTool @signArgs $output
if ($LASTEXITCODE -ne 0) { throw "SignTool failed ($LASTEXITCODE)" }
Write-Host "Signed: $output"
