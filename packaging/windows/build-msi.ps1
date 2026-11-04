<#
.SYNOPSIS
    Builds the AEGIS X MSI on a Windows host with the WiX toolset.

.DESCRIPTION
    HONEST STATUS — READ FIRST:
    * This script CANNOT run on Linux: WiX is Windows-only. It runs
      on the operator's Windows PC from the repo root.
    * It produces an UNSIGNED MSI. Signing is a separate, pending
      operator step that needs a code-signing certificate the
      operator owns. This script never signs, never invents a
      certificate, and prints an explicit UNSIGNED warning at the
      end. Do not ship the unsigned MSI as a release.
    * The .wxs source was validated as well-formed XML on Linux, but
      that is NOT a WiX schema check. A successful `wix build` here
      is the real validation — if it fails, fix the .wxs, do not
      work around it.
    * Before treating any MSI as verified: tools/windows/
      verify-service.ps1 must pass on a real host (the service loop
      has never run under the SCM), and the MSI install/uninstall
      cycle itself must be tested there, including confirming no
      AEGIS WFP sublayer remains after uninstall
      (tools/windows/cleanup-m4.ps1 + `aegis-win diag`).

    Steps:
      1. Checks cargo + the WiX v4/v5 CLI (`wix`).
      2. cargo build --release for aegis-win + aegis-service.
      3. wix build (x64) -> packaging/windows/aegis-x.msi.
      4. Prints the MSI size + SHA-256 for the release record, and
         the UNSIGNED warning + the signtool command for the
         operator's own certificate.

.PARAMETER RepoRoot
    Path to the aegis-x repository root. Defaults to the parent of
    the parent of this script
    (packaging/windows -> aegis-x).
#>
param(
    [string]$RepoRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
)

$ErrorActionPreference = 'Stop'

Set-Location $RepoRoot
$BinaryDir = Join-Path $RepoRoot 'target\release'
$WxsFile = Join-Path $RepoRoot 'packaging\windows\aegis-x.wxs'
$MsiFile = Join-Path $RepoRoot 'packaging\windows\aegis-x.msi'

# --- 1. Prerequisites -------------------------------------------------------
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error @'
Rust is not installed. Install it first, then re-run this script:
  1. Download rustup from https://rustup.rs/ and run rustup-init.exe
  2. Close and reopen PowerShell, then: cargo --version
'@
    exit 1
}
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Error @'
The WiX Toolset v4/v5 CLI (`wix`) was not found. Install it first, then re-run:
  Option A (dotnet tool):  dotnet tool install --global wix
  Option B (installer):    https://wixtoolset.org/ -> download the WiX v4/v5 release
  (WiX v3 candle.exe/light.exe are NOT used by this script; the .wxs is v4/v5 source.)
'@
    exit 1
}
if (-not (Test-Path $WxsFile)) {
    Write-Error "WiX source not found: $WxsFile"
    exit 1
}

# --- 2. Release build ---------------------------------------------------------
Write-Host ''
Write-Host '== Building release binaries =='
cargo build --release -p aegis-windows --bin aegis-win --bin aegis-service
if ($LASTEXITCODE -ne 0) { throw 'cargo build --release failed.' }
foreach ($bin in @('aegis-win.exe', 'aegis-service.exe')) {
    if (-not (Test-Path (Join-Path $BinaryDir $bin))) {
        throw "Expected binary not found after build: $(Join-Path $BinaryDir $bin)"
    }
}

# --- 3. WiX build ---------------------------------------------------------------
Write-Host ''
Write-Host '== Building MSI (WiX v4/v5, x64) =='
# Bind paths are absolute so resolution does not depend on the
# caller's working directory.
wix build $WxsFile -arch x64 `
    -d BinaryDir=$BinaryDir `
    -d RepoRoot=$RepoRoot `
    -o $MsiFile
if ($LASTEXITCODE -ne 0) { throw 'wix build failed — fix the .wxs source (see its header notes).' }
if (-not (Test-Path $MsiFile)) { throw 'wix build reported success but no MSI was produced.' }

# --- 4. Release record + UNSIGNED warning ----------------------------------------
$hash = (Get-FileHash $MsiFile -Algorithm SHA256).Hash
$size = (Get-Item $MsiFile).Length
Write-Host ''
Write-Host "MSI built: $MsiFile"
Write-Host "  size:   $size bytes"
Write-Host "  SHA256: $hash"
Write-Host ''
Write-Host 'WARNING: this MSI is UNSIGNED. Signing needs a code-signing'
Write-Host 'certificate the operator owns — it is a pending user step,'
Write-Host 'not something this script does. Do not ship it as a release'
Write-Host 'until it is signed. Example (with YOUR certificate):'
Write-Host '  signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 aegis-x.msi'
