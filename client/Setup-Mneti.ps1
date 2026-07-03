#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent — First-Time Setup Wizard
.DESCRIPTION
    Prompts the IT technician (or end user) for the physical location
    of this computer and the shared secret token, then writes
    C:\ProgramData\Locator\config.json with restricted ACLs.
    Run once during installation — re-run to update location details.
.NOTES
    Must be run as Administrator so it can write to ProgramData and
    apply NTFS ACLs that restrict the config to SYSTEM + Administrators.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Paths ─────────────────────────────────────────────────────────────────────
$CONFIG_DIR  = 'C:\ProgramData\Locator'
$CONFIG_FILE = Join-Path $CONFIG_DIR 'config.json'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ''
    Write-Host ('=' * 58) -ForegroundColor Cyan
    Write-Host '   Mneti Agent — Location Setup' -ForegroundColor White
    Write-Host ('=' * 58) -ForegroundColor Cyan
    Write-Host '   Enter the physical location of this computer.'
    Write-Host '   This is stored locally and only sent to the IT server'
    Write-Host '   when an administrator runs a discovery request.'
    Write-Host ('=' * 58) -ForegroundColor Cyan
    Write-Host ''
}

function Read-NonEmpty {
    param(
        [string]$Prompt,
        [string]$Default = '',
        [int]   $MaxLen  = 128,
        [switch]$AllowEmpty
    )
    while ($true) {
        if ($Default) {
            $display = "$Prompt [$Default]"
        } else {
            $display = $Prompt
        }
        $val = Read-Host $display
        $val = $val.Trim()

        if (-not $val -and $Default) { return $Default }

        if ($val.Length -eq 0) {
            if ($AllowEmpty) { return '' }
            Write-Host '  [!] This field is required.' -ForegroundColor Yellow
            continue
        }
        if ($val.Length -gt $MaxLen) {
            Write-Host "  [!] Maximum $MaxLen characters." -ForegroundColor Yellow
            continue
        }
        return $val
    }
}

function Test-ConstantTimeEqual {
    param([string]$A, [string]$B)
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
        $diff = $diff -bor ([int][char]$A[$i] -bxor [int][char]$B[$i])
    }
    return $diff -eq 0
}

function Read-Token {
    param([string]$Default = '')
    while ($true) {
        $prompt = if ($Default) { 'Shared secret token (provided by IT admin) [keep existing]' } `
                  else          { 'Shared secret token (provided by IT admin)' }

        $secure = Read-Host $prompt -AsSecureString
        $plain  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                      [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
        $plain  = $plain.Trim()

        if (-not $plain -and $Default) { return $Default }

        if ($plain.Length -lt 8) {
            Write-Host '  [!] Token must be at least 8 characters.' -ForegroundColor Yellow
            continue
        }

        $secureConfirm = Read-Host '  Confirm shared secret token' -AsSecureString
        $plainConfirm  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                             [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureConfirm))
        $plainConfirm  = $plainConfirm.Trim()

        if (-not (Test-ConstantTimeEqual $plain $plainConfirm)) {
            Write-Host '  [!] Tokens do not match — please try again.' -ForegroundColor Yellow
            continue
        }

        return $plain
    }
}

function Set-RestrictedAcl {
    param([string]$Path)
    try {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)

        $rights  = [System.Security.AccessControl.FileSystemRights]::FullControl
        $type    = [System.Security.AccessControl.AccessControlType]::Allow
        $inherit = [System.Security.AccessControl.InheritanceFlags]::None
        $prop    = [System.Security.AccessControl.PropagationFlags]::None

        $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminSid  = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemSid, $rights, $inherit, $prop, $type)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminSid, $rights, $inherit, $prop, $type)))

        Set-Acl -Path $Path -AclObject $acl
        Write-Host "  [+] ACLs applied (SYSTEM + Administrators only)" -ForegroundColor Green
    } catch {
        Write-Warning "Could not set ACLs on config file: $($_.Exception.Message)"
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
function Invoke-Setup {
    Write-Banner

    # ── Load existing config as defaults ──────────────────────────────────────
    $existing = @{
        building         = ''
        room             = ''
        token            = ''
        connection_type  = 'Wall Port'
        port             = ''
        additional_ports = @()
        switch_name      = ''
        router_name      = ''
    }

    if (Test-Path $CONFIG_FILE) {
        try {
            $raw    = Get-Content $CONFIG_FILE -Raw -Encoding UTF8
            $parsed = $raw | ConvertFrom-Json
            $existing.building        = $parsed.building
            $existing.room            = $parsed.room
            $existing.token           = $parsed.token
            if ($parsed.connection_type)  { $existing.connection_type = $parsed.connection_type }
            if ($parsed.port)             { $existing.port = $parsed.port }
            if ($parsed.additional_ports) { $existing.additional_ports = @($parsed.additional_ports) }
            if ($parsed.switch_name)      { $existing.switch_name = $parsed.switch_name }
            if ($parsed.router_name)      { $existing.router_name = $parsed.router_name }

            Write-Host "  Existing config found — press Enter to keep current values." -ForegroundColor DarkCyan
            Write-Host ''
        } catch {
            Write-Warning "Existing config.json is unreadable — starting fresh."
        }
    }

    # ── Building / Room ───────────────────────────────────────────────────────
    $buildingStr = Read-NonEmpty -Prompt '  Building name/number' -Default $existing.building -MaxLen 128
    $roomStr     = Read-NonEmpty -Prompt '  Room number/name    ' -Default $existing.room     -MaxLen 64

    # ── Connection type ───────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  Connection type:' -ForegroundColor White
    Write-Host '    1. Wall Port'
    Write-Host '    2. Switch'
    Write-Host '    3. Router'
    Write-Host ''
    $typeChoice = Read-Host "  Select option (1-3) [currently: $($existing.connection_type)]"

    $connType = switch ($typeChoice.Trim()) {
        '1'     { 'Wall Port' }
        '2'     { 'Switch'    }
        '3'     { 'Router'    }
        default { $existing.connection_type }
    }

    # ── Connection-type-specific fields ───────────────────────────────────────
    $portStr    = ''
    $addPorts   = @()
    $switchName = ''
    $routerName = ''

    switch ($connType) {

        'Wall Port' {
            Write-Host ''
            $portStr = Read-NonEmpty `
                -Prompt '  Wall port number/label' `
                -Default $existing.port `
                -MaxLen 32 `
                -AllowEmpty

            $addDefault = if ($existing.additional_ports) {
                              $existing.additional_ports -join ', '
                          } else { '' }
            Write-Host ''
            $addRaw = Read-Host "  Additional wall ports in this room (comma-separated) [$addDefault]"
            if (-not $addRaw -and $addDefault) {
                $addPorts = $existing.additional_ports
            } else {
                $addPorts = $addRaw.Split(',') |
                            ForEach-Object { $_.Trim() } |
                            Where-Object { $_ -ne '' }
            }
        }

        'Switch' {
            Write-Host ''
            Write-Host '  Enter the name/label of the switch this computer is connected to.' -ForegroundColor DarkCyan
            $switchName = Read-NonEmpty `
                -Prompt '  Switch name/label   ' `
                -Default $existing.switch_name `
                -MaxLen 128
        }

        'Router' {
            Write-Host ''
            Write-Host '  Enter the name/label of the router this computer is connected to.' -ForegroundColor DarkCyan
            $routerName = Read-NonEmpty `
                -Prompt '  Router name/label   ' `
                -Default $existing.router_name `
                -MaxLen 128
        }
    }

    # ── Token ─────────────────────────────────────────────────────────────────
    Write-Host ''
    $tokenStr = Read-Token -Default $existing.token

    # ── Summary ───────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host ('─' * 58) -ForegroundColor DarkGray
    Write-Host '  Configuration summary:' -ForegroundColor White
    Write-Host "    Building        : $buildingStr"
    Write-Host "    Room            : $roomStr"
    Write-Host "    Connection type : $connType"

    switch ($connType) {
        'Wall Port' {
            Write-Host "    Wall port       : $(if ($portStr) { $portStr } else { '(none)' })"
            Write-Host "    Additional ports: $(if ($addPorts) { $addPorts -join ', ' } else { '(none)' })"
        }
        'Switch' {
            Write-Host "    Switch name     : $switchName"
        }
        'Router' {
            Write-Host "    Router name     : $routerName"
        }
    }

    Write-Host "    Token           : $('*' * [Math]::Min($tokenStr.Length, 8))... ($($tokenStr.Length) chars)"
    Write-Host ('─' * 58) -ForegroundColor DarkGray
    Write-Host ''

    $confirm = Read-Host '  Save this configuration? [Y/n]'
    if ($confirm -match '^[Nn]') {
        Write-Host '  Setup cancelled.' -ForegroundColor Yellow
        return $false
    }

    # ── Write config ──────────────────────────────────────────────────────────
    if (-not (Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
    }

    $config = [ordered]@{
        building         = $buildingStr
        room             = $roomStr
        connection_type  = $connType
        port             = $portStr
        additional_ports = $addPorts
        switch_name      = $switchName
        router_name      = $routerName
        token            = $tokenStr
    }

    # Atomic write: temp file then rename
    $tmpFile = $CONFIG_FILE + '.tmp'
    $config | ConvertTo-Json -Compress | Set-Content -Path $tmpFile -Encoding UTF8 -Force
    Move-Item -Path $tmpFile -Destination $CONFIG_FILE -Force

    Set-RestrictedAcl -Path $CONFIG_FILE

    Write-Host ''
    Write-Host "  [+] Config saved to $CONFIG_FILE" -ForegroundColor Green
    Write-Host ''
    return $true
}

# ── Entry point ───────────────────────────────────────────────────────────────
if ($MyInvocation.InvocationName -ne '.') {

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host ''
        Write-Host '  [!] This script must be run as Administrator.' -ForegroundColor Red
        Write-Host '      Right-click PowerShell -> Run as Administrator' -ForegroundColor Yellow
        Write-Host ''
        exit 1
    }

    $result = Invoke-Setup
    if (-not $result) { exit 1 }
    exit 0
}