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
    Write-Host '   Mneti Agent - Location Setup' -ForegroundColor White
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
        if ($Default) {
            $prompt = 'Shared secret token (provided by IT admin) [keep existing]'
        } else {
            $prompt = 'Shared secret token (provided by IT admin)'
        }

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
            Write-Host '  [!] Tokens do not match - please try again.' -ForegroundColor Yellow
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
        Write-Host '  [+] ACLs applied (SYSTEM + Administrators only)' -ForegroundColor Green
    } catch {
        Write-Warning "Could not set ACLs on config file: $($_.Exception.Message)"
    }
}

# ── Connection-type input (extracted so no switch-inside-function parser issue) ──
function Read-ConnectionFields {
    param(
        [string]$ConnType,
        [string]$DefaultPort,
        [string[]]$DefaultAddPorts,
        [string]$DefaultSwitchName,
        [string]$DefaultRouterName
    )

    $result = @{
        port             = ''
        additional_ports = @()
        switch_name      = ''
        router_name      = ''
    }

    if ($ConnType -eq 'Wall Port') {
        Write-Host ''
        $result.port = Read-NonEmpty `
            -Prompt '  Wall port number/label' `
            -Default $DefaultPort `
            -MaxLen 32 `
            -AllowEmpty

        $addDefault = ''
        if ($DefaultAddPorts -and $DefaultAddPorts.Count -gt 0) {
            $addDefault = $DefaultAddPorts -join ', '
        }
        Write-Host ''
        $addRaw = Read-Host "  Additional wall ports in this room (comma-separated) [$addDefault]"
        if (-not $addRaw -and $addDefault) {
            $result.additional_ports = $DefaultAddPorts
        } else {
            $result.additional_ports = @(
                $addRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
            )
        }

    } elseif ($ConnType -eq 'Switch') {
        Write-Host ''
        Write-Host '  Enter the name/label of the switch this computer is connected to.' -ForegroundColor DarkCyan
        $result.switch_name = Read-NonEmpty `
            -Prompt '  Switch name/label   ' `
            -Default $DefaultSwitchName `
            -MaxLen 128

    } elseif ($ConnType -eq 'Router') {
        Write-Host ''
        Write-Host '  Enter the name/label of the router this computer is connected to.' -ForegroundColor DarkCyan
        $result.router_name = Read-NonEmpty `
            -Prompt '  Router name/label   ' `
            -Default $DefaultRouterName `
            -MaxLen 128
    }

    return $result
}

function Write-Summary {
    param(
        [string]$BuildingStr,
        [string]$RoomStr,
        [string]$ConnType,
        [string]$PortStr,
        [string[]]$AddPorts,
        [string]$SwitchName,
        [string]$RouterName,
        [string]$TokenStr
    )

    Write-Host ''
    Write-Host ('─' * 58) -ForegroundColor DarkGray
    Write-Host '  Configuration summary:' -ForegroundColor White
    Write-Host "    Building        : $BuildingStr"
    Write-Host "    Room            : $RoomStr"
    Write-Host "    Connection type : $ConnType"

    if ($ConnType -eq 'Wall Port') {
        $portDisplay = if ($PortStr) { $PortStr } else { '(none)' }
        $addDisplay  = if ($AddPorts -and $AddPorts.Count -gt 0) { $AddPorts -join ', ' } else { '(none)' }
        Write-Host "    Wall port       : $portDisplay"
        Write-Host "    Additional ports: $addDisplay"
    } elseif ($ConnType -eq 'Switch') {
        Write-Host "    Switch name     : $SwitchName"
    } elseif ($ConnType -eq 'Router') {
        Write-Host "    Router name     : $RouterName"
    }

    $maskedLen = [Math]::Min($TokenStr.Length, 8)
    $masked    = '*' * $maskedLen
    Write-Host "    Token           : $masked... ($($TokenStr.Length) chars)"
    Write-Host ('─' * 58) -ForegroundColor DarkGray
    Write-Host ''
}

# ── Main ──────────────────────────────────────────────────────────────────────
function Invoke-Setup {
    Write-Banner

    # ── Load existing config as defaults ──────────────────────────────────────
    $existingBuilding    = ''
    $existingRoom        = ''
    $existingToken       = ''
    $existingConnType    = 'Wall Port'
    $existingPort        = ''
    $existingAddPorts    = @()
    $existingSwitchName  = ''
    $existingRouterName  = ''

    if (Test-Path $CONFIG_FILE) {
        try {
            $raw    = Get-Content $CONFIG_FILE -Raw -Encoding UTF8
            $parsed = $raw | ConvertFrom-Json

            $existingBuilding = $parsed.building
            $existingRoom     = $parsed.room
            $existingToken    = $parsed.token

            if ($parsed.connection_type)  { $existingConnType   = $parsed.connection_type }
            if ($parsed.port)             { $existingPort       = $parsed.port }
            if ($parsed.additional_ports) { $existingAddPorts   = @($parsed.additional_ports) }
            if ($parsed.switch_name)      { $existingSwitchName = $parsed.switch_name }
            if ($parsed.router_name)      { $existingRouterName = $parsed.router_name }

            Write-Host '  Existing config found - press Enter to keep current values.' -ForegroundColor DarkCyan
            Write-Host ''
        } catch {
            Write-Warning 'Existing config.json is unreadable - starting fresh.'
        }
    }

    # ── Building / Room ───────────────────────────────────────────────────────
    $buildingStr = Read-NonEmpty -Prompt '  Building name/number' -Default $existingBuilding -MaxLen 128
    $roomStr     = Read-NonEmpty -Prompt '  Room number/name    ' -Default $existingRoom     -MaxLen 64

    # ── Connection type ───────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  Connection type:' -ForegroundColor White
    Write-Host '    1. Wall Port'
    Write-Host '    2. Switch'
    Write-Host '    3. Router'
    Write-Host ''
    $typeChoice = Read-Host "  Select option (1-3) [currently: $existingConnType]"
    $typeChoice = $typeChoice.Trim()

    if ($typeChoice -eq '1') {
        $connType = 'Wall Port'
    } elseif ($typeChoice -eq '2') {
        $connType = 'Switch'
    } elseif ($typeChoice -eq '3') {
        $connType = 'Router'
    } else {
        $connType = $existingConnType
    }

    # ── Connection-type-specific fields ───────────────────────────────────────
    $fields = Read-ConnectionFields `
        -ConnType          $connType `
        -DefaultPort       $existingPort `
        -DefaultAddPorts   $existingAddPorts `
        -DefaultSwitchName $existingSwitchName `
        -DefaultRouterName $existingRouterName

    $portStr    = $fields.port
    $addPorts   = $fields.additional_ports
    $switchName = $fields.switch_name
    $routerName = $fields.router_name

    # ── Token ─────────────────────────────────────────────────────────────────
    Write-Host ''
    $tokenStr = Read-Token -Default $existingToken

    # ── Summary ───────────────────────────────────────────────────────────────
    Write-Summary `
        -BuildingStr $buildingStr `
        -RoomStr     $roomStr `
        -ConnType    $connType `
        -PortStr     $portStr `
        -AddPorts    $addPorts `
        -SwitchName  $switchName `
        -RouterName  $routerName `
        -TokenStr    $tokenStr

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