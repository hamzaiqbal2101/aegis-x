<#
.SYNOPSIS
    Verifies the AEGIS X Windows service loop on a real Windows host.

.DESCRIPTION
    SAFETY FIRST — read before running:
    * Run this in a Windows VM first if you have one. On a main PC it is
      still narrow-scope: the test policies have default_action "allow"
      (all normal traffic untouched) and block exactly ONE port at a
      time (TCP 18081, then TCP 18083 for the reload check). Nothing
      else is filtered.
    * The script ALWAYS stops and deletes the test service and removes
      the test policy at the end (try/finally), even if a test fails.
      The service's own stop handler also uninstalls WFP filters, and
      the finally block runs `aegis-win uninstall` as belt and braces.
    * WFP loopback traffic (127.0.0.1) is EXEMPT from ALE filtering, so
      the test uses the machine's LAN IP (non-loopback), exactly like
      verify-m4.ps1. If the local-IP path ever bypasses ALE on your
      build, use a second machine or VM on the same LAN as the client
      instead.
    * This is the FIRST-EVER run of the service binary: it was only
      compile-checked via the cross-target check before. A build
      failure here is expected to be possible (WINDOWS-BUILD-CHECK
      spots in aegis-service.rs) — fix the compiler errors first.

    What it proves, in order:
      1. aegis-service.exe links and the SCM accepts it (sc.exe create
         + start succeed; service reports RUNNING).
      2. The service applies the policy file on start: service.log
         shows "initial policy installed" and the 18081 block is live.
      3. The service process stays alive (Get-Process + RUNNING state
         re-checked after the probes).
      4. The file-watch loop works: rewriting the policy file to block
         18083 instead makes the service log "policy reinstalled",
         after which 18083 is blocked and 18081 is reachable again.
      5. Stop removes the filters: after sc.exe stop, the policy is
         gone (aegis-win uninstall in finally guarantees this even if
         the service's own stop handler fails).

    The service reads its policy from %ProgramData%\AEGIS X\policy.json
    by default (see aegis-service.rs: policy_path). This script writes
    the test policy there and removes it in the finally block, so a
    later service start never picks up test policy by accident. The
    service log (%ProgramData%\AEGIS X\service.log) is LEFT in place
    on purpose for diagnosis; its path is printed at the end.

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

$ServiceName = 'AEGIS X'
$PolicyDir = Join-Path $env:ProgramData 'AEGIS X'
$PolicyFile = Join-Path $PolicyDir 'policy.json'
$ServiceLog = Join-Path $PolicyDir 'service.log'
$ServiceCreated = $false

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

# --- 3. Refuse if a service with this name already exists -------------------
# Deleting someone else's existing service silently would be wrong; the
# operator removes it first (sc.exe delete "AEGIS X") and re-runs.
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Error "A service named '$ServiceName' already exists. Remove it first (sc.exe delete `"$ServiceName`") and re-run this script. Nothing was changed."
    exit 1
}

# --- 4. Confirmation --------------------------------------------------------
if (-not $Force) {
    Write-Host ''
    Write-Host 'This installs the AEGIS X Windows service with a NARROW test policy:'
    Write-Host '  - default_action: allow (all normal traffic untouched)'
    Write-Host '  - one block rule at a time: TCP port 18081, then TCP 18083'
    Write-Host '  - the service and the policy are removed at the end, even on failure'
    Write-Host ''
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Aborted. Nothing was changed.'; exit 0 }
}

Set-Location $RepoRoot
$svcExe = Join-Path $RepoRoot 'target\debug\aegis-service.exe'
$winExe = Join-Path $RepoRoot 'target\debug\aegis-win.exe'

function Test-Port {
    param([string]$Ip, [int]$Port, [bool]$Listener)
    $job = $null
    if ($Listener) {
        $job = Start-Job -ScriptBlock {
            param($ip, $port)
            $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($ip), $port)
            $l.Start()
            try { $c = $l.AcceptTcpClient(); $c.Close() } catch { }
            $l.Stop()
        } -ArgumentList $Ip, $Port
        Start-Sleep -Seconds 1
    }
    try {
        $r = Test-NetConnection -ComputerName $Ip -Port $Port -WarningAction SilentlyContinue
        return $r.TcpTestSucceeded
    } finally {
        if ($job) { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue }
    }
}

function Wait-LogLine {
    param([string]$Pattern, [int]$TimeoutSecs = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $ServiceLog) -and (Select-String -Path $ServiceLog -Pattern $Pattern -Quiet)) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Write-TestPolicy {
    param([int]$BlockPort)
    $policy = @"
{
  "version": 1,
  "name": "aegis-service-test",
  "default_action": "allow",
  "rules": [
    { "id": "block-test-port", "priority": 10, "action": "deny",
      "protocol": "tcp", "dst_port": $BlockPort }
  ]
}
"@
    # BOM-LESS UTF-8, same reason as verify-m4.ps1: PowerShell 5.1
    # Set-Content -Encoding utf8 writes a BOM that serde_json rejects.
    [System.IO.File]::WriteAllText(
        $PolicyFile, $policy,
        (New-Object System.Text.UTF8Encoding $false))
}

try {
    # --- 5. Build (first native link of aegis-service) -----------------------
    Write-Host ''
    Write-Host '== Building (first native link of aegis-service) =='
    cargo build -p aegis-windows --bin aegis-service --bin aegis-win
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed — fix the compiler errors in crates/aegis-windows/src/bin/aegis-service.rs first (see its WINDOWS-BUILD-CHECK notes).' }

    # --- 6. LAN IP (non-loopback; loopback is exempt from ALE) --------------
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object InterfaceMetric | Select-Object -First 1
    if (-not $route) { throw 'No default IPv4 route found.' }
    $lanIp = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1).IPAddress
    if (-not $lanIp) { throw 'No usable LAN IPv4 address found.' }
    Write-Host ''
    Write-Host "== Test target: LAN IP $lanIp (loopback is exempt from WFP ALE) =="

    # --- 7. Write test policy v1 (block 18081) and create + start service ----
    New-Item -ItemType Directory -Force -Path $PolicyDir | Out-Null
    Write-TestPolicy -BlockPort 18081
    Write-Host ''
    Write-Host '== Installing + starting the AEGIS X service =='
    # NOTE: sc.exe syntax requires a space after each "key=" token.
    sc.exe create $ServiceName binPath= "`"$svcExe`"" start= demand DisplayName= $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed.' }
    $ServiceCreated = $true
    sc.exe start $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'sc.exe start failed — see the service log below.' }

    $running = $false
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $running = $true; break }
        Start-Sleep -Seconds 1
    }
    Write-Host "  service state RUNNING: $running"
    if (-not $running) {
        if (Test-Path $ServiceLog) { Get-Content $ServiceLog -Tail 20 }
        throw 'Service did not reach RUNNING within 60s.'
    }

    # --- 8. Service applied the policy on start ------------------------------
    $installed = Wait-LogLine -Pattern 'initial policy installed' -TimeoutSecs 30
    Write-Host "  service.log shows 'initial policy installed': $installed"
    if (-not $installed) {
        if (Test-Path $ServiceLog) { Get-Content $ServiceLog -Tail 20 }
        throw 'Service log does not show the initial policy install.'
    }

    Write-Host ''
    Write-Host '== Probes v1 (expect: 18080 reachable, 18081 blocked, 18082 reachable) =='
    $ok80 = Test-Port -Ip $lanIp -Port 18080 -Listener $true
    $blocked81 = -not (Test-Port -Ip $lanIp -Port 18081 -Listener $true)
    $ok82 = Test-Port -Ip $lanIp -Port 18082 -Listener $true
    Write-Host "  port 18080 (unlisted, default allow): reachable = $ok80"
    Write-Host "  port 18081 (blocked by rule):        blocked   = $blocked81"
    Write-Host "  port 18082 (unlisted, default allow): reachable = $ok82"
    $probesV1 = $ok80 -and $blocked81 -and $ok82

    # --- 9. Service process stays alive ---------------------------------------
    $procAlive = [bool](Get-Process -Name 'aegis-service' -ErrorAction SilentlyContinue)
    $stillRunning = ((Get-Service -Name $ServiceName).Status -eq 'Running')
    Write-Host ''
    Write-Host "  service process alive: $procAlive; service still RUNNING: $stillRunning"
    $aliveOk = $procAlive -and $stillRunning

    # --- 10. File-watch reload: rewrite policy to block 18083 -----------------
    Write-Host ''
    Write-Host '== Policy-change reload (expect: 18083 blocked, 18081 reachable again) =='
    Write-TestPolicy -BlockPort 18083
    $reinstalled = Wait-LogLine -Pattern 'policy reinstalled' -TimeoutSecs 30
    Write-Host "  service.log shows 'policy reinstalled': $reinstalled"
    $blocked83 = $false
    $ok81Again = $false
    if ($reinstalled) {
        $blocked83 = -not (Test-Port -Ip $lanIp -Port 18083 -Listener $true)
        $ok81Again = Test-Port -Ip $lanIp -Port 18081 -Listener $true
        Write-Host "  port 18083 (blocked by new rule): blocked   = $blocked83"
        Write-Host "  port 18081 (no longer blocked):   reachable = $ok81Again"
    }
    $reloadOk = $reinstalled -and $blocked83 -and $ok81Again

    Write-Host ''
    if ($probesV1 -and $aliveOk -and $reloadOk) {
        Write-Host 'SERVICE VERIFICATION: PASS — service installs, enforces, stays alive, and reloads on policy change.'
    } else {
        Write-Host 'SERVICE VERIFICATION: FAIL — see the section results above.'
        Write-Host "  probes v1: $probesV1; process alive: $aliveOk; reload: $reloadOk"
    }
}
finally {
    # --- 11. Always clean up ---------------------------------------------------
    Write-Host ''
    Write-Host '== Removing service + test policy (always runs) =='
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            sc.exe stop $ServiceName | Out-Null
            # Wait briefly for STOPPED; do not fail the cleanup if it lags.
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $deadline) {
                $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $s -or $s.Status -eq 'Stopped') { break }
                Start-Sleep -Seconds 1
            }
        }
        sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning 'sc.exe delete reported an error — remove the service manually.' }
    } elseif ($ServiceCreated) {
        Write-Warning 'Service record not found during cleanup; attempting delete anyway.'
        sc.exe delete $ServiceName | Out-Null
    }
    # Belt and braces: the service's stop handler uninstalls WFP filters,
    # but if the service crashed, filters may remain — remove them here.
    if (Test-Path $winExe) {
        & $winExe uninstall
        if ($LASTEXITCODE -ne 0) { Write-Warning 'aegis-win uninstall reported an error — re-run cleanup-m4.ps1.' }
    }
    # Never leave test policy behind for a later service start to pick up.
    if (Test-Path $PolicyFile) { Remove-Item $PolicyFile -Force }
    Write-Host "  service log kept for diagnosis at: $ServiceLog"
}
