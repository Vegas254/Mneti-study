#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent — Update Applier (helper process)
.DESCRIPTION
    Launched (detached, hidden) by the running agent's background updater
    the moment a downloaded update has been verified (size + SHA-256 both
    match the announced values) and staged to disk. This script's only job:

      1. Wait for the OLD agent process (by PID) to actually exit — the
         agent requests its own graceful shutdown right after launching
         this helper, so this is normally a few seconds at most.
      2. Back up the current agent script, then atomically replace it with
         the verified, staged update.
      3. Restart the Mneti Task Scheduler task so the new code starts
         running immediately.
      4. Clean up the staging marker and exit.

    This script deliberately does almost nothing else. All the "is this
    update actually legitimate/complete/correct" work already happened in
    the agent's background updater (start-Mneti.ps1) BEFORE it ever staged
    a file or launched this helper — by the time this script runs, the
    file at -Pending has already passed HMAC-authenticated broadcast
    validation, a full TCP download, a size check, and a SHA-256 check.
    This script does not re-verify any of that; it only performs the
    file swap + restart, which is the one operation the OLD agent process
    can't safely do to itself while still running.

.NOTES
    If the old process never exits within -TimeoutSec, this script aborts
    WITHOUT touching the target file — the running (old) agent is left
    completely alone rather than risk swapping files out from under a
    process that's still using them.
#>

param(
    [Parameter(Mandatory = $true)][int]$WaitPid,
    [Parameter(Mandatory = $true)][string]$Pending,
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$TaskName   = 'MnetiAgent',
    [int]   $TimeoutSec = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$LOG_FILE = 'C:\ProgramData\Locator\agent.log'
$logLock  = New-Object System.Threading.Mutex($false, 'MnetiLogMutex')

function Write-UpdaterLog {
    param([string]$Level, [string]$Message)
    $line = "{0} [{1}] [UPDATER] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    try {
        if ($logLock.WaitOne(500)) {
            Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8 -Force
        }
    } catch {} finally { try { $logLock.ReleaseMutex() } catch {} }
}

Write-UpdaterLog 'INFO' "Updater helper started - waiting for PID $WaitPid to exit (timeout ${TimeoutSec}s)"

# ── Step 1: wait for the old agent process to actually exit ──────────────────
$deadline = [DateTime]::Now.AddSeconds($TimeoutSec)
$exited   = $false
while ([DateTime]::Now -lt $deadline) {
    $proc = Get-Process -Id $WaitPid -ErrorAction SilentlyContinue
    if (-not $proc) { $exited = $true; break }
    Start-Sleep -Milliseconds 500
}

if (-not $exited) {
    Write-UpdaterLog 'ERROR' "PID $WaitPid did not exit within ${TimeoutSec}s - aborting update, target left untouched"
    exit 1
}

# Small extra grace period so the OS fully releases any file handles.
Start-Sleep -Milliseconds 750

# ── Step 2: verify the staged file is still there ─────────────────────────────
if (-not (Test-Path $Pending)) {
    Write-UpdaterLog 'ERROR' "Staged update file missing at $Pending - aborting, nothing to apply"
    exit 1
}

# ── Step 3: back up current target, then atomically swap in the update ───────
$updateDir = Split-Path $Pending -Parent

# Preserve a copy of the verified payload BEFORE it's moved into place, plus
# a small relay marker (FIX 14). If this device is hotspotting other Mneti
# agents, the NEW agent process reads this marker on its very first startup
# (Invoke-PendingUpdateRelay) and daisy-chains this exact same update into
# those subnets - so devices behind a hotspot never need to reach the
# dashboard directly to get updated. Purely additive: if anything here
# fails, it only disables the daisy-chain step, never the update itself.
try {
    $srcMarkerPath = Join-Path $updateDir 'pending.json'
    if (Test-Path $srcMarkerPath) {
        $srcMarker = Get-Content $srcMarkerPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($srcMarker.origin_sender_ip -and $srcMarker.sha256 -and $srcMarker.file_size) {
            Copy-Item -Path $Pending -Destination (Join-Path $updateDir 'relay_payload.ps1') -Force
            $relayMarker = [ordered]@{
                update_version   = $srcMarker.update_version
                transfer_id      = $srcMarker.transfer_id
                sha256           = $srcMarker.sha256
                file_size        = $srcMarker.file_size
                origin_sender_ip = $srcMarker.origin_sender_ip
                staged_at        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            $relayMarker | ConvertTo-Json -Compress | Set-Content -Path (Join-Path $updateDir 'relay_marker.json') -Encoding UTF8 -Force
            Write-UpdaterLog 'INFO' "Staged relay payload/marker for daisy-chain to hotspotted devices (v$($srcMarker.update_version))"
        } else {
            Write-UpdaterLog 'WARN' "pending.json missing relay fields - daisy-chain relay will be skipped for this update"
        }
    }
} catch {
    Write-UpdaterLog 'WARN' "Could not stage relay payload/marker (daisy-chain relay will be skipped): $_"
}

try {
    if (Test-Path $Target) {
        Copy-Item -Path $Target -Destination "$Target.bak" -Force
        Write-UpdaterLog 'INFO' "Backed up current agent to $Target.bak"
    }
    Move-Item -Path $Pending -Destination $Target -Force
    Write-UpdaterLog 'INFO' "Applied update: $Pending -> $Target"
} catch {
    Write-UpdaterLog 'ERROR' "Failed to apply update ($_) - attempting to restart agent with whatever is currently at $Target"
}

# ── Step 4: clean up the marker ───────────────────────────────────────────────
try {
    $markerPath = Join-Path $updateDir 'pending.json'
    Remove-Item -Path $markerPath -Force -ErrorAction SilentlyContinue
} catch {}

# ── Step 5: restart the agent, verify it actually came up, retry, and roll
#            back to the previous backup if it never does ────────────────────
# Starting the scheduled task "succeeding" only proves Windows launched a
# process - it says nothing about whether the new script is actually valid
# and made it through its own startup (e.g. a syntax error, or something
# that throws before the socket bind). Test-AgentStarted confirms the new
# process actually reached "Bound to UDP :5000" in the log, which can only
# happen after Get-AgentConfig, Assert-SingleInstance, etc. all succeeded.
function Test-AgentStarted {
    param([datetime]$SinceLocal, [int]$TimeoutSec = 15)
    $deadline = [DateTime]::Now.AddSeconds($TimeoutSec)
    while ([DateTime]::Now -lt $deadline) {
        try {
            if (Test-Path $LOG_FILE) {
                $tail = Get-Content -Path $LOG_FILE -Tail 60 -ErrorAction SilentlyContinue
                foreach ($line in $tail) {
                    if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[INFO\].*Bound to UDP :5000') {
                        try {
                            $ts = [DateTime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
                            if ($ts -ge $SinceLocal) { return $true }
                        } catch {}
                    }
                }
            }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Invoke-AgentStart {
    param([string]$TaskName, [string]$Target)
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            Start-ScheduledTask -TaskName $TaskName
        } else {
            $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $args  = "-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Target`""
            Start-Process -FilePath $psExe -ArgumentList $args -WindowStyle Hidden | Out-Null
        }
        return $true
    } catch {
        Write-UpdaterLog 'WARN' "Launch attempt failed: $_"
        return $false
    }
}

$maxRetries = 3
$started    = $false

for ($attempt = 1; $attempt -le $maxRetries -and -not $started; $attempt++) {
    Write-UpdaterLog 'INFO' "Restart attempt $attempt of $maxRetries (task '$TaskName')"
    $attemptTime = Get-Date
    Invoke-AgentStart -TaskName $TaskName -Target $Target | Out-Null

    $started = Test-AgentStarted -SinceLocal $attemptTime -TimeoutSec 15
    if ($started) {
        Write-UpdaterLog 'INFO' "New agent version confirmed running (attempt $attempt)"
    } else {
        Write-UpdaterLog 'WARN' "Attempt $attempt did not come up cleanly - clearing any half-started process before retrying"
        try {
            Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -and $_.CommandLine -match 'start-Mneti\.ps1' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch {}
        Start-Sleep -Seconds 1
    }
}

if (-not $started) {
    Write-UpdaterLog 'ERROR' "New version failed to start cleanly after $maxRetries attempts - rolling back to previous backup"

    # A failed update should never daisy-chain itself to other devices.
    Remove-Item -Path (Join-Path $updateDir 'relay_marker.json')  -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $updateDir 'relay_payload.ps1') -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path "$Target.bak")) {
        Write-UpdaterLog 'ERROR' "No backup found at $Target.bak - cannot roll back, manual intervention required"
        exit 1
    }

    try {
        Copy-Item -Path "$Target.bak" -Destination $Target -Force
        Write-UpdaterLog 'INFO' "Reverted $Target to previous working backup"
    } catch {
        Write-UpdaterLog 'ERROR' "Rollback copy failed: $_ - manual intervention required"
        exit 1
    }

    $rollbackAttemptTime = Get-Date
    Invoke-AgentStart -TaskName $TaskName -Target $Target | Out-Null
    $rolledBack = Test-AgentStarted -SinceLocal $rollbackAttemptTime -TimeoutSec 15

    if ($rolledBack) {
        Write-UpdaterLog 'INFO' "Rollback successful - previous working version is running again"
    } else {
        Write-UpdaterLog 'ERROR' "Rollback restart did not confirm a clean start either - manual intervention required"
    }
    exit 1
}

Write-UpdaterLog 'INFO' 'Update applied and verified successfully, updater helper exiting'
exit 0