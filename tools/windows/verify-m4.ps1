<#
.SYNOPSIS
    Verifies AEGIS X Milestone 4 (Windows WFP adapter) on a real Windows host.

.DESCRIPTION
    SAFETY FIRST — read before running:
    * Run this in a Windows VM first if you have one. On a main PC it is
      still narrow-scope: the test policy has default_action "allow"
      (all normal traffic untouched) and blocks exactly ONE port
      (TCP 18081). Nothing else is filtered.
    * The script ALWAYS uninstalls the test policy at the end
      (try/finally), even if a test fails.
    * WFP loopback traffic (127.0.0.1) is EXEMPT from ALE filtering, so
      the test uses the machine's LAN IP (non-loopback). If the local-IP
      path ever bypasses ALE on your build, use a second machine or VM
      on the same LAN as the client instead.

    Steps:
      1. Checks Administrator rights and a Rust toolchain.
      2. cargo build (THIS is the compile check for engine.rs) + unit tests.
      3. Installs the test policy via aegis-win.
      4. Proves enforcement: 18081 blocked, 18080 + 18082 reachable.
      5. Uninstalls everything and prints PASS/FAIL.

.PARAMETER RepoRoot
    Path to the aegis-x repository root. Defaults to the parent of the
    parent of this script (tools/windows -> aegis-x).

.PARAMETER Force
    Skip the confirmation prompt.
#>
param(
    [string]$RepoRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# --- 1. Administrator check -------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an Administrator PowerShell (right-click PowerShell -> Run as administrator).'
    exit 1
}

# --- 2. Rust toolchain ------------------------------------------------------
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error @'
Rust is not installed. Install it first, then re-run this script:
  1. Download rustup from https://rustup.rs/ and run rustup-init.exe
  2. Close and reopen PowerShell, then: cargo --version
'@
    exit 1
}

# --- 3. Confirmation --------------------------------------------------------
if (-not $Force) {
    Write-Host ''
    Write-Host 'This installs a NARROW test policy into the live Windows Filtering Platform:'
    Write-Host '  - default_action: allow (all normal traffic untouched)'
    Write-Host '  - one block rule: TCP port 18081 only'
    Write-Host '  - the policy is removed at the end, even on failure'
    Write-Host ''
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Aborted. Nothing was changed.'; exit 0 }
}

Set-Location $RepoRoot
$exe = Join-Path $RepoRoot 'target\debug\aegis-win.exe'

try {
    # --- 4. Compile check + unit tests --------------------------------------
    Write-Host ''
    Write-Host '== Building (this is the compile check for engine.rs) =='
    cargo build -p aegis-windows --bin aegis-win
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed — fix the compiler errors in crates/aegis-windows/src/engine.rs first.' }

    Write-Host ''
    Write-Host '== Unit tests (translation model) =='
    cargo test -p aegis-windows
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed.' }

    # --- 5. LAN IP (non-loopback; loopback is exempt from ALE) --------------
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object InterfaceMetric | Select-Object -First 1
    if (-not $route) { throw 'No default IPv4 route found.' }
    $lanIp = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1).IPAddress
    if (-not $lanIp) { throw 'No usable LAN IPv4 address found.' }
    Write-Host ''
    Write-Host "== Test target: LAN IP $lanIp (loopback is exempt from WFP ALE) =="

    # --- 6. Test policy: default allow, block exactly one port --------------
    $policy = @'
{
  "version": 1,
  "name": "aegis-m4-test",
  "default_action": "allow",
  "rules": [
    { "id": "block-test-port", "priority": 10, "action": "deny",
      "protocol": "tcp", "dst_port": 18081 }
  ]
}
'@
    $policyFile = Join-Path $env:TEMP 'aegis-m4-test-policy.json'
    # Write BOM-LESS UTF-8: Windows PowerShell 5.1's Set-Content
    # -Encoding utf8 writes a BOM, and serde_json rejects a BOM with
    # "expected value at line 1 column 1" (this exact failure stopped
    # the first real-host M4 run on Nov 3, 2026). WriteAllText with
    # UTF8Encoding($false) is BOM-less on both PS 5.1 and PS 7.
    [System.IO.File]::WriteAllText(
        $policyFile, $policy,
        (New-Object System.Text.UTF8Encoding $false))

    # --- 6b. Diagnostics (read-only: what already holds these keys) -------
    # Print-only: a diag failure must not stop the run; the install step
    # below reports the real failure if the engine is unreachable.
    Write-Host ''
    Write-Host '== Diagnostics (read-only: what already holds these keys) =='
    & $exe diag

    Write-Host ''
    Write-Host '== Installing test policy =='
    & $exe install --policy $policyFile
    if ($LASTEXITCODE -ne 0) { throw 'aegis-win install failed.' }

    # --- 7. Enforcement probes ----------------------------------------------
    function Test-Port {
        param([int]$Port, [bool]$Listener)
        $job = $null
        if ($Listener) {
            $job = Start-Job -ScriptBlock {
                param($ip, $port)
                $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($ip), $port)
                $l.Start()
                try { $c = $l.AcceptTcpClient(); $c.Close() } catch { }
                $l.Stop()
            } -ArgumentList $lanIp, $Port
            Start-Sleep -Seconds 1
        }
        try {
            $r = Test-NetConnection -ComputerName $lanIp -Port $Port -WarningAction SilentlyContinue
            return $r.TcpTestSucceeded
        } finally {
            if ($job) { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue }
        }
    }

    # NOTE: with default_action "allow", the 18080/18082 probes prove
    # non-interference (unlisted traffic untouched). The 18081 probe is
    # the real enforcement proof (a rule stopped real traffic). Proving
    # an explicit ALLOW rule needs a default-deny policy, which belongs
    # in a VM, not on a main PC — see README.md.
    Write-Host ''
    Write-Host '== Probes (expect: 18080 reachable, 18081 blocked, 18082 reachable) =='
    $ok80 = Test-Port -Port 18080 -Listener $true
    $blocked81 = -not (Test-Port -Port 18081 -Listener $true)
    $ok82 = Test-Port -Port 18082 -Listener $true
    Write-Host "  port 18080 (unlisted, default allow): reachable = $ok80"
    Write-Host "  port 18081 (blocked by rule):        blocked   = $blocked81"
    Write-Host "  port 18082 (unlisted, default allow): reachable = $ok82"

    if ($ok80 -and $blocked81 -and $ok82) {
        Write-Host ''
        Write-Host 'M4 WINDOWS ENFORCEMENT: PASS — a real WFP block stopped real traffic.'
    } else {
        Write-Host ''
        Write-Host 'M4 WINDOWS ENFORCEMENT: FAIL — see the probe results above.'
        Write-Host 'If 18081 was reachable, the local-IP path may bypass ALE on this build;'
        Write-Host 'retry with a second machine/VM on the LAN as the client before concluding.'
    }
}
finally {
    # --- 8. Always clean up --------------------------------------------------
    Write-Host ''
    Write-Host '== Removing test policy (always runs) =='
    if (Test-Path $exe) {
        & $exe uninstall
        if ($LASTEXITCODE -ne 0) { Write-Warning 'aegis-win uninstall reported an error — re-run cleanup-m4.ps1.' }
    } else {
        Write-Warning 'aegis-win.exe not found; nothing to uninstall (build must have failed before install).'
    }
}
