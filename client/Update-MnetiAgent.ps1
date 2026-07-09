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
    $markerPath = Join-Path (Split-Path $Pending -Parent) 'pending.json'
    Remove-Item -Path $markerPath -Force -ErrorAction SilentlyContinue
} catch {}

# ── Step 5: restart the agent ─────────────────────────────────────────────────
# Prefer the Task Scheduler task the agent was installed under (matches
# Install-MnetiService.ps1), since that's how it's meant to be running
# persistently. Fall back to a direct hidden launch if the task is missing
# for some reason (e.g. someone ran start-Mneti.ps1 manually).
try {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Start-ScheduledTask -TaskName $TaskName
        Write-UpdaterLog 'INFO' "Restarted agent via Task Scheduler task '$TaskName'"
    } else {
        $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $args  = "-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Target`""
        Start-Process -FilePath $psExe -ArgumentList $args -WindowStyle Hidden | Out-Null
        Write-UpdaterLog 'WARN' "Task '$TaskName' not found - launched agent directly instead"
    }
} catch {
    Write-UpdaterLog 'ERROR' "Failed to restart agent: $_"
    exit 1
}

Write-UpdaterLog 'INFO' 'Update applied successfully, updater helper exiting'
exit 0