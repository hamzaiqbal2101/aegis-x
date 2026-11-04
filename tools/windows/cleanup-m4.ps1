<#
.SYNOPSIS
    Removes all AEGIS X filters and the provider from WFP (standalone cleanup).

.DESCRIPTION
    Run from an Administrator PowerShell. Builds aegis-win if needed, then
    runs `aegis-win uninstall`, which deletes the AEGIS sublayer (all its
    filters go with it) and then the provider. Safe to run when nothing is
    installed (the deletes are ignored).
#>
param(
    [string]$RepoRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an Administrator PowerShell.'
    exit 1
}

Set-Location $RepoRoot
$exe = Join-Path $RepoRoot 'target\debug\aegis-win.exe'
if (-not (Test-Path $exe)) {
    Write-Host 'Building aegis-win first...'
    cargo build -p aegis-windows --bin aegis-win
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
}

& $exe uninstall
if ($LASTEXITCODE -eq 0) {
    Write-Host 'AEGIS filters and provider removed from WFP.'
} else {
    throw 'aegis-win uninstall failed.'
}
