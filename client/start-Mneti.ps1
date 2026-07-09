#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent - UDP Discovery Listener
.DESCRIPTION
    Lightweight, high-performance event-driven listener. Binds to UDP 5000
    and waits silently. On receiving a valid HMAC-signed discovery broadcast:
      1. Validates HMAC-SHA256 signature
      2. Deduplicates request_id FIRST — before any expensive work
      3. Drops self-loopback packets
      4. Self-reports using the IP on the same subnet as the sender
      5. Relays into subnets NOT on the originating subnet (hotspot/secondary)
      6. Depth tracking prevents relay storms (max depth = 1)
      7. Unmanaged relayed devices inherit relay_host/building/room

.FIXES (this release)
    FIX 7 - Duplicate processing on multi-interface machines
        The dedup check (Test-AlreadySeen) was called after Get-NetworkAdapters,
        which is expensive and caused the same request to be fully processed
        multiple times when both Ethernet and Wi-Fi/hotspot adapters received
        the broadcast. Moved dedup to the very top of Invoke-PacketHandler,
        before any adapter work.

    FIX 8 - Unmanaged relayed devices missing relay metadata
        Invoke-SubnetRelay Step 10 built unmanagedReport with empty
        relay_host/relay_building/relay_room. Those fields now carry the
        relay host's values so the dashboard can identify them correctly.
        connection_type is set to "Hotspot" for these devices.

    FIX 9 - Zombie / stale-config processes
        Task Scheduler's default MultipleInstances policy is IgnoreNew.
        If a prior agent process is still alive (e.g. stuck in the 30s
        relay listener window) when Stop/Start-ScheduledTask is run, the
        old process silently keeps running with its OLD config, and a
        new one never actually starts. This produces the symptom of
        config edits (wall port -> switch -> different switch name)
        never taking effect, or "flip-flopping" between old values,
        because multiple stale processes are all still bound to UDP 5000
        (ReuseAddress = true lets them coexist) and racing to respond.

        Fix: Assert-SingleInstance runs at startup and force-kills any
        other process whose command line matches this script before
        binding the socket.

    FIX 10 - Config never reloaded without a full restart
        $config was read once at startup and never touched again, so
        editing config.json via Setup-Mneti.ps1 required a full
        stop/start of the agent to take effect — and FIX 9's failure
        mode meant that often didn't even work. Update-ConfigIfChanged
        is now polled every $CONFIG_RELOAD_SECS seconds inside the main
        loop and hot-swaps $config in place whenever config.json's
        last-write time changes. No restart needed after Setup-Mneti.ps1.

    FIX 11 - Local IP history logging (NEW)
        The agent now tracks its own IP address(es) using the .NET
        NetworkChange.NetworkAddressChanged event — an OS-level callback,
        not polling. When it fires, Invoke-IpChangeCheck compares the
        current adapter IP set against the last known set and appends any
        NEW ip to a local append-only log
        (C:\ProgramData\Locator\ip_history.jsonl).

        IMPORTANT: this log is 100% local and passive. The agent never
        pushes it anywhere on its own. It is only ever read and reported
        in direct response to a signed "ip_history" broadcast from the
        dashboard (see FIX 12) — exactly like an ordinary targeted
        discovery request, just answered from the local log instead of
        the live adapter state.

    FIX 12 - "ip_history" discovery mode (NEW)
        A new packet mode, "ip_history", lets the dashboard ask "what IP
        did this MAC have at time T" or "give me every IP entry logged
        between T1 and T2" without touching the network at all beyond the
        broadcast + reply — no ARP scan, no relay, no live IP check.
        Invoke-PacketHandler short-circuits into Get-IpHistoryMatches and
        replies once per matching local log entry, then returns before
        reaching the normal managed/relay code path.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Constants ─────────────────────────────────────────────────────────────────
$CONFIG_FILE        = 'C:\ProgramData\Locator\config.json'
$LOG_FILE           = 'C:\ProgramData\Locator\agent.log'
$IP_HISTORY_FILE    = 'C:\ProgramData\Locator\ip_history.jsonl'
$UDP_PORT           = 5000
$RELAY_HTTP_PORT    = 5002
$BUFFER_SIZE        = 4096
$POST_TIMEOUT       = 8
$CACHE_TTL          = 60
$MAX_LOG_BYTES      = 5MB
$MAX_RELAY_DEPTH    = 1
$CONFIG_RELOAD_SECS = 15

# ── Self-update (FIX 13) ────────────────────────────────────────────────────
# Bump this with every release you deploy via "Deploy Update" in the
# dashboard. Agents ignore any announced update_version that is not
# strictly newer than this, so a stale/duplicate broadcast is a no-op.
$AGENT_VERSION       = '1.0.0'
$UPDATE_UDP_PORT     = 5010
$UPDATE_MAGIC        = 'MNETI_UPDATE'
$UPDATE_PROTO_MAX    = 1
$UPDATE_DIR          = 'C:\ProgramData\Locator\update'
$UPDATER_SCRIPT      = 'C:\ProgramData\Locator\Update-MnetiAgent.ps1'
$AGENT_SCRIPT_PATH   = 'C:\ProgramData\Locator\start-Mneti.ps1'
$UPDATE_TASK_NAME    = 'MnetiAgent'
$UPDATE_ID_CACHE_TTL = 300
$UPDATE_CONNECT_JITTER_MS_MAX = 3000

$script:LastConfigWrite = $null
$script:LastKnownIPs    = @()
# Synchronized hashtable — safely shared between the main thread and the
# background runspace that performs the (blocking) update download, so the
# download never stalls the UDP receive loop. See Start-BackgroundUpdate.
$script:UpdateState = [hashtable]::Synchronized(@{ PendingRestart = $false; Message = '' })
$script:SeenUpdateIds = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[string,long]'

# ── Logging ───────────────────────────────────────────────────────────────────
$script:LogLock = New-Object System.Threading.Mutex($false, 'MnetiLogMutex')

function Write-AgentLog {
    param([string]$Level, [string]$Message)
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Write-Host $line
    try {
        if ($script:LogLock.WaitOne(500)) {
            if ((Test-Path $LOG_FILE) -and (Get-Item $LOG_FILE).Length -gt $MAX_LOG_BYTES) {
                Move-Item $LOG_FILE "$LOG_FILE.bak" -Force
            }
            Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8 -Force
        }
    } catch {
    } finally {
        try { $script:LogLock.ReleaseMutex() } catch {}
    }
}

function Write-Info   { param([string]$m) Write-AgentLog 'INFO'  $m }
function Write-Warn   { param([string]$m) Write-AgentLog 'WARN'  $m }
function Write-Err    { param([string]$m) Write-AgentLog 'ERROR' $m }
function Write-Debug2 { param([string]$m) Write-AgentLog 'DEBUG' $m }

# ── Single-instance enforcement (FIX 9) ───────────────────────────────────────
function Assert-SingleInstance {
    $myPid = $PID
    try {
        $stale = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -and
                $_.CommandLine -match 'start-Mneti\.ps1' -and
                $_.ProcessId -ne $myPid
            }
        foreach ($p in $stale) {
            Write-Warn "Killing stale agent process PID $($p.ProcessId) (started $($p.CreationDate)) before starting"
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        if ($stale) {
            Start-Sleep -Milliseconds 750   # let UDP 5000 / relay TCP ports free up
        }
    } catch {
        Write-Warn "Assert-SingleInstance check failed: $_"
    }
}

# ── Config ────────────────────────────────────────────────────────────────────
function Get-AgentConfig {
    if (-not (Test-Path $CONFIG_FILE)) {
        Write-Err "Config file not found: $CONFIG_FILE. Run Setup-Mneti.ps1 first."
        exit 1
    }
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($field in @('building', 'room', 'token')) {
            if (-not $cfg.$field) { Write-Err "Config missing required field: $field"; exit 1 }
        }
        return $cfg
    } catch {
        Write-Err "Failed to parse config.json: $_"; exit 1
    }
}

# ── Config hot-reload (FIX 10) ────────────────────────────────────────────────
function Update-ConfigIfChanged {
    param([ref]$ConfigRef)
    try {
        $item = Get-Item $CONFIG_FILE -ErrorAction Stop
        if ($null -eq $script:LastConfigWrite -or $item.LastWriteTimeUtc -gt $script:LastConfigWrite) {
            $newCfg = Get-Content $CONFIG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
            $missing = @('building', 'room', 'token') | Where-Object { -not $newCfg.$_ }
            if ($missing) {
                Write-Warn "Config reload skipped - missing field(s): $($missing -join ', ')"
                return
            }
            $ConfigRef.Value = $newCfg
            $script:LastConfigWrite = $item.LastWriteTimeUtc
            Write-Info ("Config reloaded: building={0} room={1} conn={2} port={3} switch={4} router={5}" -f `
                $newCfg.building, $newCfg.room, $newCfg.connection_type, $newCfg.port, $newCfg.switch_name, $newCfg.router_name)
        }
    } catch {
        Write-Warn "Config reload check failed: $_"
    }
}

# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
function Get-HmacSha256 {
    param([string]$Secret, [string]$Message)
    $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $msgBytes  = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $hmac      = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key  = $keyBytes
    $hashBytes = $hmac.ComputeHash($msgBytes)
    return ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
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

# ── Dedup cache ───────────────────────────────────────────────────────────────
$script:SeenIds = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[string,long]'

function Test-AlreadySeen {
    param([string]$RequestId)
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (-not $script:SeenIds.TryAdd($RequestId, $now)) { return $true }
    foreach ($key in @($script:SeenIds.Keys)) {
        $ts = 0L
        if ($script:SeenIds.TryGetValue($key, [ref]$ts) -and ($now - $ts) -gt $CACHE_TTL) {
            $script:SeenIds.TryRemove($key, [ref]$ts) | Out-Null
        }
    }
    return $false
}

# ── Subnet arithmetic ─────────────────────────────────────────────────────────
function Get-SubnetInfo {
    param([string]$IP, [int]$PrefixLength)
    $ipBytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
    [array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    if ($PrefixLength -le 0) {
        $mask     = [uint32]0
        $hostMask = [uint32]0xFFFFFFFF
    } elseif ($PrefixLength -ge 32) {
        $mask     = [uint32]0xFFFFFFFF
        $hostMask = [uint32]0
    } else {
        $hostBits = 32 - $PrefixLength
        $hostMask = [uint32]([Math]::Pow(2, $hostBits) - 1)
        $mask     = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, $hostBits))
    }

    $network   = [uint32]($ipInt -band $mask)
    $broadcast = [uint32]($network + $hostMask)

    $bBytes = [BitConverter]::GetBytes($broadcast)
    [array]::Reverse($bBytes)
    $broadcastStr = ([System.Net.IPAddress]$bBytes).ToString()

    return [pscustomobject]@{
        IPInt        = $ipInt
        Network      = $network
        Broadcast    = $broadcast
        BroadcastStr = $broadcastStr
        Mask         = $mask
    }
}

function Test-SameSubnet {
    param([string]$IP1, [string]$IP2, [int]$PrefixLength)
    try {
        $i1 = Get-SubnetInfo -IP $IP1 -PrefixLength $PrefixLength
        $i2 = Get-SubnetInfo -IP $IP2 -PrefixLength $PrefixLength
        return $i1.Network -eq $i2.Network
    } catch { return $false }
}

function Test-IsPrivateIP {
    param([string]$IP)
    return ($IP -like '10.*' -or
            ($IP -like '172.*' -and [int]($IP -split '\.')[1] -ge 16 -and [int]($IP -split '\.')[1] -le 31) -or
            $IP -like '192.168.*')
}

# ── Virtual adapter detection ─────────────────────────────────────────────────
# Allow types: 6 (Ethernet), 71 (IEEE 802.11 wireless incl. hosted network/hotspot)
# Exclude by name only for truly non-routable adapters.
$ALLOWED_INTERFACE_TYPES = @(6, 71)
$VIRTUAL_NAME_PATTERNS   = @('*Bluetooth*', '*isatap*', '*Teredo*', '*vEthernet*', '*WSL*')

function Test-IsVirtualAdapter {
    param([object]$Adapter)
    # Only exclude by name/description – let any adapter with an IP be considered.
    foreach ($p in $VIRTUAL_NAME_PATTERNS) {
        if ($Adapter.Name -like $p -or $Adapter.InterfaceDescription -like $p) { return $true }
    }
    return $false
}
# ── Network helpers ───────────────────────────────────────────────────────────
function Get-NetworkAdapters {
    $adapters = @()
    try {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $adapter = $_
            if (Test-IsVirtualAdapter -Adapter $adapter) {
                Write-Debug2 "Skipping adapter: $($adapter.Name) [type=$($adapter.InterfaceType)]"
                return
            }
            $addrs = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                                      -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($addr in $addrs) {
                $ip = $addr.IPAddress
                if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
                $mac = ($adapter.MacAddress -replace '-', ':').ToUpper()
                $adapters += [pscustomobject]@{
                    Name           = $adapter.Name
                    MAC            = $mac
                    IP             = $ip
                    InterfaceIndex = $adapter.InterfaceIndex
                    PrefixLength   = $addr.PrefixLength
                    InterfaceType  = $adapter.InterfaceType
                }
                Write-Debug2 "Adapter included: $($adapter.Name) IP=$ip/$($addr.PrefixLength) [type=$($adapter.InterfaceType)]"
            }
        }
    } catch { Write-Warn "Adapter enumeration error: $_" }
    return $adapters
}

function Get-AdapterForSender {
    param([object[]]$Adapters, [string]$SenderIP)
    
    # Collect all adapters that are on the same subnet as the sender
    $candidates = @()
    foreach ($a in $Adapters) {
        if (Test-SameSubnet -IP1 $a.IP -IP2 $SenderIP -PrefixLength $a.PrefixLength) {
            $candidates += $a
        } else {
            foreach ($pl in @(22, 23, 24)) {
                if (Test-SameSubnet -IP1 $a.IP -IP2 $SenderIP -PrefixLength $pl) {
                    $candidates += $a
                    break
                }
            }
        }
    }
    
    # Exclude any adapter that has the same IP as the sender (avoid using the virtual gateway)
    $filtered = @($candidates | Where-Object { $_.IP -ne $SenderIP })
    
    # If we have a filtered candidate, return the first one
    if ($filtered.Count -gt 0) {
        return $filtered[0]
    }
    
    # Fallback: if all candidates were excluded, return the first candidate (or first overall)
    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }
    
    # Ultimate fallback: return the first adapter from the full list
    return $Adapters | Select-Object -First 1
}

function Get-RelayNetworks {
    param([string]$SenderIP, [object[]]$Adapters)
    $relayNets = @()
    $seen      = @{}

    foreach ($a in $Adapters) {
        $ip     = $a.IP
        $prefix = $a.PrefixLength

        if (-not (Test-IsPrivateIP -IP $ip)) { continue }

        $onOriginatingSubnet = $false
        foreach ($testPrefix in @($prefix, 22, 23, 24)) {
            if (Test-SameSubnet -IP1 $ip -IP2 $SenderIP -PrefixLength $testPrefix) {
                Write-Info "Skipping originating subnet for relay (/$testPrefix match): $ip/$prefix on $($a.Name)"
                $onOriginatingSubnet = $true
                break
            }
        }
        if ($onOriginatingSubnet) { continue }

        $dedupKey = "$ip/$prefix"
        if ($seen.ContainsKey($dedupKey)) { continue }
        $seen[$dedupKey] = $true

        $si = Get-SubnetInfo -IP $ip -PrefixLength $prefix
        $relayNets += [pscustomobject]@{
            IPAddress   = $ip
            Broadcast   = $si.BroadcastStr
            Prefix      = $prefix
            Interface   = $a.InterfaceIndex
            AdapterName = $a.Name
            SubnetInfo  = $si
        }
        Write-Info "Relay subnet detected: $ip/$prefix (broadcast $($si.BroadcastStr)) on $($a.Name)"
    }
    return $relayNets
}

function Get-LoggedInUser {
    try {
        $session = query user 2>$null | Select-Object -Skip 1 | Where-Object { $_ -match 'Active' }
        if ($session) { return ($session -split '\s+')[1].TrimStart('>') }
    } catch {}
    return $env:USERNAME
}

function Get-MacVendor {
    param([string]$MAC)
    $oui = @{
        '00:50:56'='VMware';  '00:0C:29'='VMware';  '00:15:5D'='Hyper-V'
        '08:00:27'='VirtualBox'; '52:54:00'='QEMU'
        'B8:27:EB'='Raspberry Pi'; 'DC:A6:32'='Raspberry Pi'
        '00:1A:11'='Google';  'A4:C3:F0'='Google'
        'AC:BC:32'='Apple';   '3C:22:FB'='Apple';   '00:17:F2'='Apple'
        '00:1B:21'='Intel';   '14:18:77'='Dell';    'B4:B6:86'='HP'
        '3C:D9:2B'='HP';      '00:23:AE'='Dell';    '18:B4:30'='Nest'
        '18:70:3B'='Huawei';  '40:B0:76'='Huawei';  'E8:CD:2D'='Huawei'
        '00:9A:CD'='Huawei';  'F4:9F:54'='Huawei';  '28:31:52'='Huawei'
        'C8:14:79'='Samsung'; '00:07:AB'='Samsung';  '8C:77:12'='Samsung'
        '00:26:37'='Samsung'; 'A0:75:91'='Samsung';  '78:1F:DB'='Samsung'
        '98:DE:D0'='Xiaomi';  '28:6C:07'='Xiaomi';  '64:09:80'='Xiaomi'
        'AC:C1:EE'='Oppo';    '00:1A:7D'='Realtek'; '00:E0:4C'='Realtek'
        '34:97:F6'='Intel';   '8C:8D:28'='Intel';   'B8:08:CF'='Intel'
        '00:1C:73'='Aruba';   '00:0B:86'='Aruba';   'F4:DB:E6'='TP-Link'
        '50:C7:BF'='TP-Link'; 'C8:D3:A3'='TP-Link'; '00:1D:0F'='TP-Link'
        'CC:40:D0'='Cisco';   '00:1B:54'='Cisco';   '00:16:47'='Cisco'
    }
    if ($MAC.Length -ge 8) {
        $prefix = $MAC.Substring(0, 8).ToUpper()
        if ($oui.ContainsKey($prefix)) { return $oui[$prefix] }
    }
    return ''
}

function Resolve-DeviceHostname {
    param([string]$IP)
    try { return [System.Net.Dns]::GetHostEntry($IP).HostName } catch { return '' }
}

# ── Packet validation ─────────────────────────────────────────────────────────
function Test-Packet {
    param([byte[]]$Bytes, [string]$Token)
    try {
        $json = [System.Text.Encoding]::UTF8.GetString($Bytes)
        if ($json.Length -gt $BUFFER_SIZE) { Write-Warn "Oversized packet - dropped"; return $null }
        $envelope = $json | ConvertFrom-Json
    } catch { Write-Warn "Malformed packet (not JSON) - dropped"; return $null }

    if (-not $envelope.payload -or -not $envelope.sig) {
        Write-Warn "Packet missing payload or sig - dropped"; return $null
    }

    $p = $envelope.payload
    if (-not (Test-ConstantTimeEqual $p.token $Token)) {
        Write-Warn "Token mismatch inside payload - dropped"; return $null
    }

    $relayDepth = if ($null -ne $p.relay_depth) { [int]$p.relay_depth } else { 0 }
    $isPrimary  = if ($null -ne $p.is_primary)  { [bool]$p.is_primary } else { $false }

    # ip_history query fields (FIX 12) — always present in the canonical
    # signed string (blank string when not an ip_history request) so the
    # HMAC covers them and a forged/edited query can't slip through.
    $iphMode  = if ($p.iph_mode)  { [string]$p.iph_mode }  else { '' }
    $iphStart = if ($p.iph_start) { [string]$p.iph_start } else { '' }
    $iphEnd   = if ($p.iph_end)   { [string]$p.iph_end }   else { '' }
    $iphIp    = if ($p.iph_ip)    { [string]$p.iph_ip }    else { '' }

    $payloadJson = '{"request_id":"' + $p.request_id + '","mode":"' + $p.mode + '","target":"' + $p.target + '","token":"' + $p.token + '","callback_url":"' + $p.callback_url + '","timestamp":"' + $p.timestamp + '","relay_depth":' + $relayDepth + ',"is_primary":' + $isPrimary.ToString().ToLower() + ',"iph_mode":"' + $iphMode + '","iph_start":"' + $iphStart + '","iph_end":"' + $iphEnd + '","iph_ip":"' + $iphIp + '"}'
    $expectedSig = Get-HmacSha256 -Secret $Token -Message $payloadJson

    if (-not (Test-ConstantTimeEqual $expectedSig $envelope.sig)) {
        Write-Warn "HMAC mismatch - dropped (possible forgery)"; return $null
    }

    # Attach the parsed ip_history fields onto the returned payload object
    # so Invoke-PacketHandler doesn't need to re-derive defaults.
    $p | Add-Member -NotePropertyName 'iph_mode'  -NotePropertyValue $iphMode  -Force
    $p | Add-Member -NotePropertyName 'iph_start' -NotePropertyValue $iphStart -Force
    $p | Add-Member -NotePropertyName 'iph_end'   -NotePropertyValue $iphEnd   -Force
    $p | Add-Member -NotePropertyName 'iph_ip'    -NotePropertyValue $iphIp    -Force

    return $p
}

# ── Target matching ───────────────────────────────────────────────────────────
function Test-IsTarget {
    param([object[]]$Adapters, [string]$Mode, [string]$Target)
    $Target = $Target.Trim().ToUpper()
    foreach ($a in $Adapters) {
        if ($Mode -eq 'targeted_mac') {
            if (($a.MAC.ToUpper() -replace '-',':') -eq ($Target -replace '-',':')) { return $true }
        } elseif ($Mode -eq 'targeted_ip') {
            if ($a.IP -eq $Target) { return $true }
        }
    }
    return $false
}

# ── HTTP POST ─────────────────────────────────────────────────────────────────
function Send-Report {
    param([string]$CallbackUrl, [hashtable]$Report, [string]$Token, [string]$SourceIP = $null)
    try {
        $body      = $Report | ConvertTo-Json -Compress -Depth 5
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $sig       = Get-HmacSha256 -Secret $Token -Message $body

        $req = [System.Net.HttpWebRequest]::Create($CallbackUrl)
        $req.Method      = 'POST'
        $req.ContentType = 'application/json'
        $req.Timeout     = $POST_TIMEOUT * 1000
        $req.Headers.Add('X-Signature', $sig)

        # Bind to a specific source IP if provided
        if ($SourceIP) {
            $localIP = [System.Net.IPAddress]::Parse($SourceIP)
            $req.ServicePoint.BindIPEndPointDelegate = {
                param($servicePoint, $remoteEndPoint, $retryCount)
                return [System.Net.IPEndPoint]::new($localIP, 0)
            }
            Write-Debug2 "Binding HTTP request to source IP: $SourceIP"
        }

        $stream = $req.GetRequestStream()
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
        $stream.Close()

        $resp   = $req.GetResponse()
        $status = [int]$resp.StatusCode
        $resp.Close()
        Write-Info "Report posted -> $CallbackUrl [HTTP $status] $($Report.hostname) ($($Report.type))"
    } catch {
        Write-Err "Failed to post report to $CallbackUrl : $_"
    }
}

# ── Relay packet builder ──────────────────────────────────────────────────────
function Build-RelayPacket {
    param(
        [object]$OriginalPayload,
        [string]$LocalCallbackUrl,
        [string]$Token,
        [int]   $RelayDepth
    )
    $isPrimary = if ($null -ne $OriginalPayload.is_primary) { [bool]$OriginalPayload.is_primary } else { $false }

    # ip_history requests never reach this function (Invoke-PacketHandler
    # returns before relaying — see FIX 12), so these are always blank in
    # practice for a relayed packet. They're still carried through and
    # signed so the canonical string format matches Test-Packet exactly.
    $iphMode  = if ($OriginalPayload.iph_mode)  { [string]$OriginalPayload.iph_mode }  else { '' }
    $iphStart = if ($OriginalPayload.iph_start) { [string]$OriginalPayload.iph_start } else { '' }
    $iphEnd   = if ($OriginalPayload.iph_end)   { [string]$OriginalPayload.iph_end }   else { '' }
    $iphIp    = if ($OriginalPayload.iph_ip)    { [string]$OriginalPayload.iph_ip }    else { '' }

    $relayPayload = [ordered]@{
        request_id   = $OriginalPayload.request_id
        mode         = $OriginalPayload.mode
        target       = $OriginalPayload.target
        token        = $Token
        callback_url = $LocalCallbackUrl
        timestamp    = $OriginalPayload.timestamp
        relay_depth  = $RelayDepth
        is_primary   = $isPrimary
        iph_mode     = $iphMode
        iph_start    = $iphStart
        iph_end      = $iphEnd
        iph_ip       = $iphIp
    }

    $payloadJson = '{"request_id":"' + $relayPayload.request_id +
                   '","mode":"'         + $relayPayload.mode +
                   '","target":"'       + $relayPayload.target +
                   '","token":"'        + $relayPayload.token +
                   '","callback_url":"' + $relayPayload.callback_url +
                   '","timestamp":"'    + $relayPayload.timestamp +
                   '","relay_depth":'   + $relayPayload.relay_depth +
                   ',"is_primary":'     + $isPrimary.ToString().ToLower() +
                   ',"iph_mode":"'      + $relayPayload.iph_mode +
                   '","iph_start":"'    + $relayPayload.iph_start +
                   '","iph_end":"'      + $relayPayload.iph_end +
                   '","iph_ip":"'       + $relayPayload.iph_ip + '"}'

    $sig      = Get-HmacSha256 -Secret $Token -Message $payloadJson
    $envelope = @{ payload = $relayPayload; sig = $sig }
    return [System.Text.Encoding]::UTF8.GetBytes(($envelope | ConvertTo-Json -Compress -Depth 5))
}

# ── ARP reader ────────────────────────────────────────────────────────────────
function Get-ArpHostsInSubnet {
    param([string]$LocalIP, [int]$PrefixLength, [string]$ExcludeIP)
    $hosts = @{}
    try {
        $si        = Get-SubnetInfo -IP $LocalIP -PrefixLength $PrefixLength
        $arpOutput = arp -a 2>$null
        foreach ($line in $arpOutput) {
            if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+(dynamic|static)') {
                $arpIP  = $Matches[1]
                $arpMac = ($Matches[2].ToUpper() -replace '-', ':')
                if ($arpIP -eq $ExcludeIP) { continue }
                try {
                    $aBytes = ([System.Net.IPAddress]::Parse($arpIP)).GetAddressBytes()
                    [array]::Reverse($aBytes)
                    $aInt = [BitConverter]::ToUInt32($aBytes, 0)
                    if (($aInt -band $si.Mask) -eq $si.Network -and
                         $aInt -ne $si.Broadcast -and $aInt -ne $si.Network) {
                        $hosts[$arpIP] = $arpMac
                    }
                } catch {}
            }
        }
    } catch { Write-Warn "Get-ArpHostsInSubnet error: $_" }
    return $hosts
}

function Add-RelayFirewallRule {
    param([int]$Port)
    $ruleName = "Mneti Relay (TCP $Port)"
    try {
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
                -LocalPort $Port -Action Allow | Out-Null
            Write-Info "Firewall rule added for TCP port $Port"
        }
    } catch {
        Write-Warn "Could not add firewall rule for port $Port : $_"
    }
}

# ── Subnet relay ──────────────────────────────────────────────────────────────
function Invoke-SubnetRelay {
    param(
        [object]$Packet,
        [object]$Config,
        [string]$MyHostname,
        [string]$MyBuilding,
        [string]$MyRoom,
        [object]$RelayNet
    )

    $localIP       = $RelayNet.IPAddress
    $broadcastAddr = $RelayNet.Broadcast
    $prefix        = $RelayNet.Prefix
    $newDepth      = [int]$Packet.relay_depth + 1

    Write-Info "Relaying discovery into $localIP/$prefix via $broadcastAddr"

    # Step 1: Ping sweep to seed ARP cache
    Write-Info "Ping sweep (ARP seed) on $localIP/$prefix ..."
    try {
        $si = Get-SubnetInfo -IP $localIP -PrefixLength $prefix
        for ([uint32]$hostNum = $si.Network + 1; $hostNum -lt $si.Broadcast; $hostNum++) {
            $hBytes = [BitConverter]::GetBytes($hostNum)
            [array]::Reverse($hBytes)
            $targetIP = ([System.Net.IPAddress]$hBytes).ToString()
            if ($targetIP -eq $localIP) { continue }
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $ping.SendAsync($targetIP, 150, $null) | Out-Null
            } catch {}
        }
        Start-Sleep -Milliseconds 800
    } catch { Write-Warn "Ping sweep failed on $localIP/$prefix : $_" }

    # Step 2: Read ARP before listener starts
    $arpHosts = Get-ArpHostsInSubnet -LocalIP $localIP -PrefixLength $prefix -ExcludeIP $localIP
    Write-Info "ARP pre-scan: $(@($arpHosts.Keys).Count) host(s) known on $localIP/$prefix"

    # Step 3: Start relay HTTP listener
    $listener        = $null
    $listenerStarted = $false
    $relayPort       = $null
    $localCallbackUrl = $null

    for ($attempt = 0; $attempt -le 4; $attempt++) {
        try {
            $relayPort = $RELAY_HTTP_PORT + $attempt
            $listener  = New-Object System.Net.HttpListener
            $listener.Prefixes.Add("http://$($localIP):$relayPort/api/report/")
            Add-RelayFirewallRule -Port $relayPort
            $listener.Start()
            $localCallbackUrl = "http://$($localIP):$relayPort/api/report/"
            $listenerStarted  = $true
            Write-Info "Relay HTTP listener started on ${localIP}:$relayPort"
            Write-Info "Callback URL will be: $localCallbackUrl"
            break
        } catch {
            Write-Warn "Relay listener attempt $attempt failed on port $relayPort : $_"
            try { if ($listener) { $listener.Close() } } catch {}
            $listener = $null
        }
    }

    if (-not $listenerStarted) {
        Write-Warn "Failed to start relay listener for subnet $localIP/$prefix"; return
    }

    try {
        # Step 4: Build relay packet
        Write-Info "Building relay packet with callback URL: $localCallbackUrl"
        $packetBytes = Build-RelayPacket `
            -OriginalPayload  $Packet `
            -LocalCallbackUrl $localCallbackUrl `
            -Token            $Config.token `
            -RelayDepth       $newDepth

        # Step 5: Unicast to ARP-known hosts first
        foreach ($arpIP in $arpHosts.Keys) {
            try {
                $udpUnicast = New-Object System.Net.Sockets.UdpClient
                $udpUnicast.EnableBroadcast = $false
                $udpUnicast.Send($packetBytes, $packetBytes.Length, $arpIP, $UDP_PORT) | Out-Null
                $udpUnicast.Close()
                Write-Info "Unicast discovery sent to $arpIP (MAC $($arpHosts[$arpIP]))"
            } catch { Write-Warn "Unicast to $arpIP failed: $_" }
        }

        # Step 6: Subnet broadcast
        try {
            $udpBcast = New-Object System.Net.Sockets.UdpClient
            $udpBcast.EnableBroadcast = $true
            $udpBcast.Send($packetBytes, $packetBytes.Length, $broadcastAddr, $UDP_PORT) | Out-Null
            $udpBcast.Close()
            Write-Info "Rebroadcasting discovery to ${broadcastAddr}:$UDP_PORT (depth $newDepth)"
        } catch { Write-Warn "UDP rebroadcast to $broadcastAddr failed: $_" }

        # Step 7: Collect managed responses (30 s window)
        $managedReports = @()
        $deadline       = [DateTime]::Now.AddSeconds(30)

        while ([DateTime]::Now -lt $deadline) {
            try {
                if (-not $listener.IsListening) { break }
                $asyncResult = $listener.BeginGetContext($null, $null)
                if (-not $asyncResult.AsyncWaitHandle.WaitOne(500)) { continue }

                $ctx    = $listener.EndGetContext($asyncResult)
                $req    = $ctx.Request
                Write-Info "Received relay request from $($req.RemoteEndPoint) to $($req.Url)"
                $res    = $ctx.Response
                $reader = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
                $body   = $reader.ReadToEnd()
                $reader.Close()

                $buf = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                $res.ContentLength64 = $buf.Length
                $res.OutputStream.Write($buf, 0, $buf.Length)
                $res.OutputStream.Close()

                $report       = $body | ConvertFrom-Json
                $clientHmac   = $req.Headers.Get('X-Signature')
                $expectedHmac = Get-HmacSha256 -Secret $Config.token -Message $body

                if ((Test-ConstantTimeEqual $clientHmac $expectedHmac) -and
                    (Test-ConstantTimeEqual $report.token $Config.token)) {
                    $managedReports += $report
                    Write-Info "Managed client responded via relay: $($report.hostname) ($($report.ip))"
                } else {
                    Write-Warn "Invalid signature on relay response - discarded"
                }
            } catch { Write-Warn "Error reading relay response: $_" }
        }

        Write-Info "Relay listener completed. Managed responses: $(@($managedReports).Count)"

        # Step 8: Re-read ARP after window
        $arpHostsFinal = Get-ArpHostsInSubnet -LocalIP $localIP -PrefixLength $prefix -ExcludeIP $localIP
        Write-Info "ARP scan found $(@($arpHostsFinal.Keys).Count) device(s) in $localIP/$prefix"

        # Step 9: Forward managed/relayed reports to Flask server
        $managedMacs = @{}
        foreach ($mr in $managedReports) {
            $mac = $mr.mac.ToUpper() -replace '-', ':'
            $managedMacs[$mac] = $true

            $relayReport = @{
                token          = $Config.token
                request_id     = $Packet.request_id
                hostname       = $mr.hostname
                mac            = $mr.mac
                ip             = $mr.ip
                username       = $mr.username
                building       = $mr.building
                room           = $mr.room
                timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                type           = 'relayed'
                relay_host     = $MyHostname
                relay_building = $MyBuilding
                relay_room     = $MyRoom
                vendor         = $mr.vendor
                connection_type = $mr.connection_type
                port           = $mr.port
                switch_name    = $mr.switch_name
                router_name    = $mr.router_name
            }
            Send-Report -CallbackUrl $Packet.callback_url -Report $relayReport -Token $Config.token -SourceIP $localIP
            Write-Info "POSTing to $CallbackUrl"
        }

        # Step 10: Report ARP-only (unmanaged) devices
        # FIX 8: Populate relay_host/building/room so the dashboard can identify
        # these as hotspot-relayed devices. connection_type is set to "Hotspot".
        foreach ($arpIP in $arpHostsFinal.Keys) {
            $arpMac = $arpHostsFinal[$arpIP]
            if ($managedMacs.ContainsKey($arpMac)) { continue }

            $hostname = Resolve-DeviceHostname -IP $arpIP
            if (-not $hostname) { $hostname = "Unmanaged-$arpIP" }
            $vendor = Get-MacVendor -MAC $arpMac

            Write-Info "Unmanaged device discovered: $arpIP ($arpMac) $vendor"

            $unmanagedReport = @{
                token          = $Config.token
                request_id     = $Packet.request_id
                hostname       = $hostname
                mac            = $arpMac
                ip             = $arpIP
                username       = ''
                building       = $MyBuilding
                room           = $MyRoom
                timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                type           = 'unmanaged'
                relay_host     = $MyHostname
                relay_building = $MyBuilding
                relay_room     = $MyRoom
                vendor         = $vendor
                connection_type = 'Hotspot'
                port           = ''
                switch_name    = ''
                router_name    = ''
            }
            Send-Report -CallbackUrl $Packet.callback_url -Report $unmanagedReport -Token $Config.token -SourceIP $localIP
        }

    } finally {
        if ($listener) {
            try { if ($listener.IsListening) { $listener.Stop() } } catch {}
            try { $listener.Close() } catch {}
            Write-Info "Relay listener cleaned up on ${localIP}:$relayPort"
        }
    }
}

# ── Local IP history (FIX 11 / FIX 12) ────────────────────────────────────────
$script:IpHistoryLock = New-Object System.Threading.Mutex($false, 'MnetiIpHistoryMutex')

function Get-CurrentIPSet {
    try { return @(Get-NetworkAdapters | ForEach-Object { $_.IP } | Sort-Object -Unique) }
    catch { return @() }
}

function Write-IpHistoryEntry {
    <#
    Appends a single IP-observation entry to the local, append-only
    ip_history.jsonl log. This function NEVER sends anything over the
    network — it only writes to disk. The log is read back (and only
    then reported) exclusively inside Get-IpHistoryMatches, in direct
    response to a signed "ip_history" broadcast.
    #>
    param([string]$IP, [string]$MAC)
    $entry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        mac       = $MAC
        ip        = $IP
    }
    try {
        if ($script:IpHistoryLock.WaitOne(500)) {
            Add-Content -Path $IP_HISTORY_FILE -Value ($entry | ConvertTo-Json -Compress) -Encoding UTF8 -Force
        }
    } catch {
    } finally {
        try { $script:IpHistoryLock.ReleaseMutex() } catch {}
    }
}

function Invoke-IpChangeCheck {
    <#
    Called only when the OS NetworkAddressChanged event fires — never
    polled on a timer. Debounces briefly since adapters can flap through
    a transient state (link down -> APIPA -> real IP) within ~1s of the
    event firing, then logs any IP not present in $script:LastKnownIPs.
    #>
    Start-Sleep -Milliseconds 1500
    $adapters   = Get-NetworkAdapters
    $currentIPs = @($adapters | ForEach-Object { $_.IP } | Sort-Object -Unique)
    $added      = $currentIPs | Where-Object { $_ -notin $script:LastKnownIPs }

    foreach ($a in $adapters) {
        if ($a.IP -in $added) {
            Write-Info "IP change detected: $($a.IP) on $($a.Name)"
            Write-IpHistoryEntry -IP $a.IP -MAC $a.MAC
        }
    }
    $script:LastKnownIPs = $currentIPs
}

function Get-IpHistoryMatches {
    <#
    Reads the local ip_history.jsonl log and returns matching entries.
    This is the ONLY place the log is read, and it is only ever called
    from inside Invoke-PacketHandler in direct response to a validated
    "ip_history" broadcast — there is no background/proactive reporting.

    QueryMode 'range': every logged entry with StartUtc <= timestamp <= EndUtc
                        (optionally filtered to a single IP).
    QueryMode 'at'    : the most recent entry at or before EndUtc — i.e.
                        "what IP was active at this moment" (optionally
                        filtered so it only replies if that IP matches).
    #>
    param([string]$QueryMode, [string]$StartUtc, [string]$EndUtc, [string]$FilterIp)
    $out = @()
    if (-not (Test-Path $IP_HISTORY_FILE)) { return $out }

    $all = @()
    foreach ($line in (Get-Content $IP_HISTORY_FILE -ErrorAction SilentlyContinue)) {
        try { $all += ($line | ConvertFrom-Json) } catch {}
    }
    if (@($all).Count -eq 0) { return $out }
    # ISO-8601 'Z' timestamps sort lexically in chronological order.
    $all = @($all | Sort-Object timestamp)

    if ($QueryMode -eq 'range') {
        foreach ($e in $all) {
            if ($e.timestamp -ge $StartUtc -and $e.timestamp -le $EndUtc) {
                if (-not $FilterIp -or $e.ip -eq $FilterIp) { $out += $e }
            }
        }
    } elseif ($QueryMode -eq 'at') {
        $active = $null
        foreach ($e in $all) {
            if ($e.timestamp -le $EndUtc) { $active = $e } else { break }
        }
        if ($active -and (-not $FilterIp -or $active.ip -eq $FilterIp)) { $out += $active }
    }
    return $out
}

# ── Self-update (FIX 13) ───────────────────────────────────────────────────────
#
# Wire protocol (broadcast, UDP port 5010, HMAC-signed with the same shared
# token as discovery packets):
#
#   { "payload": {
#       "magic":          "MNETI_UPDATE",
#       "proto_version":  1,
#       "update_version": "1.1.0",
#       "tcp_port":       5300,
#       "file_size":      88213,
#       "sha256":         "<hex>",
#       "timestamp":      "2026-07-08T10:00:00Z",
#       "transfer_id":    "<uuid>",
#       "token":          "<shared token>"
#     },
#     "sig": "<hmac-sha256 hex of the canonical payload string>" }
#
# Extensibility: proto_version lets future releases add new fields without
# breaking older agents — an agent only understanding proto_version 1 simply
# ignores fields it doesn't recognise as long as the fields it DOES need
# (checked in Test-UpdatePacket) are present. Bump $UPDATE_PROTO_MAX and add
# handling here, not by changing the meaning of existing fields.
#
# Trust model: only a broadcast whose HMAC validates against this agent's
# own config.token is accepted — the same shared secret already used to
# authenticate discovery requests. A device without that token cannot get
# an agent to download or run anything via this mechanism.
#
# Safety model: the download + verification happens entirely in a
# background runspace so it never blocks the discovery listener. Nothing
# about the running agent is touched unless the downloaded file's SIZE and
# SHA-256 both match what was announced. Only then is the new file staged
# and a restart requested — if the TCP connection drops, sizes mismatch, or
# the checksum fails at any point, the currently running agent is left
# completely untouched and keeps operating normally.

function Compare-Version {
    <#
    Simple dotted-version comparer ("1.2.10" vs "1.2.9", etc.) — not full
    semver (no pre-release/build metadata), which is all that's needed for
    "is the announced version newer than what I'm running".
    Returns 1 if A > B, -1 if A < B, 0 if equal (or unparsable).
    #>
    param([string]$A, [string]$B)
    try {
        $partsA = ($A -split '\.') | ForEach-Object { [int]($_ -replace '[^\d]', '') }
        $partsB = ($B -split '\.') | ForEach-Object { [int]($_ -replace '[^\d]', '') }
        $len = [Math]::Max($partsA.Count, $partsB.Count)
        for ($i = 0; $i -lt $len; $i++) {
            $va = if ($i -lt $partsA.Count) { $partsA[$i] } else { 0 }
            $vb = if ($i -lt $partsB.Count) { $partsB[$i] } else { 0 }
            if ($va -gt $vb) { return 1 }
            if ($va -lt $vb) { return -1 }
        }
        return 0
    } catch {
        return 0
    }
}

function Test-UpdatePacket {
    <#
    Parses and HMAC-validates an update-announcement UDP datagram. Returns
    the parsed payload object, or $null if it fails validation (malformed,
    wrong token, bad signature, or missing a required field) — mirrors
    Test-Packet's discipline for ordinary discovery packets.
    #>
    param([byte[]]$Bytes, [string]$Token)
    try {
        $json = [System.Text.Encoding]::UTF8.GetString($Bytes)
        if ($json.Length -gt 2048) { Write-Warn "Oversized update packet - dropped"; return $null }
        $envelope = $json | ConvertFrom-Json
    } catch { Write-Warn "Malformed update packet (not JSON) - dropped"; return $null }

    if (-not $envelope.payload -or -not $envelope.sig) { return $null }
    $p = $envelope.payload

    if ($p.magic -ne $UPDATE_MAGIC) { return $null }
    foreach ($field in @('proto_version','update_version','tcp_port','file_size','sha256','timestamp','transfer_id','token')) {
        if ($null -eq $p.$field -or $p.$field -eq '') {
            Write-Warn "Update packet missing required field '$field' - dropped"; return $null
        }
    }

    if (-not (Test-ConstantTimeEqual ([string]$p.token) $Token)) {
        Write-Warn "Update packet token mismatch - dropped"; return $null
    }

    $canonical = '{"magic":"' + $p.magic + '","proto_version":' + [int]$p.proto_version +
                 ',"update_version":"' + $p.update_version + '","tcp_port":' + [int]$p.tcp_port +
                 ',"file_size":' + [int64]$p.file_size + ',"sha256":"' + $p.sha256 +
                 '","timestamp":"' + $p.timestamp + '","transfer_id":"' + $p.transfer_id +
                 '","token":"' + $p.token + '"}'
    $expectedSig = Get-HmacSha256 -Secret $Token -Message $canonical

    if (-not (Test-ConstantTimeEqual $expectedSig ([string]$envelope.sig))) {
        Write-Warn "Update packet HMAC mismatch - dropped (possible forgery)"; return $null
    }

    return $p
}

function Test-UpdateAlreadySeen {
    <#
    Dedups by transfer_id (not by raw packet), separate from the discovery
    dedup cache. The dashboard re-broadcasts the SAME transfer_id several
    times over the deploy window for reliability against UDP loss — this
    ensures an agent that already started (or finished) a download doesn't
    start a second one for the same deploy.
    #>
    param([string]$TransferId)
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (-not $script:SeenUpdateIds.TryAdd($TransferId, $now)) { return $true }
    foreach ($key in @($script:SeenUpdateIds.Keys)) {
        $ts = 0L
        if ($script:SeenUpdateIds.TryGetValue($key, [ref]$ts) -and ($now - $ts) -gt $UPDATE_ID_CACHE_TTL) {
            $script:SeenUpdateIds.TryRemove($key, [ref]$ts) | Out-Null
        }
    }
    return $false
}

function Start-BackgroundUpdate {
    <#
    Kicks off the (potentially slow) download+verify+handoff sequence on a
    background runspace via [powershell]::Create()/BeginInvoke(), so the
    main UDP receive loop is never blocked waiting on a TCP transfer.

    $script:UpdateState is a synchronized hashtable — the SAME object
    (by reference) is visible to both this background runspace and the
    main thread, so setting PendingRestart there is a safe, simple way for
    the background work to signal "time to restart" back to the main loop,
    the same pattern already used for the NetworkAddressChanged flag.
    #>
    param(
        [string]$HostIp, [int]$Port, [int64]$FileSize, [string]$ExpectedSha256,
        [string]$TransferId, [string]$UpdateVersion, [int]$MyPid
    )

    $scriptBlock = {
        param($HostIp, $Port, $FileSize, $ExpectedSha256, $TransferId, $UpdateVersion,
              $MyPid, $UpdateDir, $UpdaterScript, $TargetPath, $TaskName, $LogFile, $JitterMax, $UpdateState)

        # Self-contained logging (this runspace doesn't share the main
        # script's function definitions, so it uses its own tiny logger
        # writing to the same file, guarded by the same named mutex —
        # named mutexes are OS-wide, so this interleaves safely with the
        # main process's own log writes).
        $logLock = New-Object System.Threading.Mutex($false, 'MnetiLogMutex')
        function Log-U {
            param([string]$m)
            $line = "{0} [UPDATE] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
            try {
                if ($logLock.WaitOne(500)) {
                    Add-Content -Path $LogFile -Value $line -Encoding UTF8 -Force
                }
            } catch {} finally { try { $logLock.ReleaseMutex() } catch {} }
        }

        try {
            if (-not (Test-Path $UpdateDir)) { New-Item -ItemType Directory -Path $UpdateDir -Force | Out-Null }

            # Small random delay so many agents don't all connect to the
            # temporary TCP server in the same instant.
            if ($JitterMax -gt 0) { Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum $JitterMax) }

            Log-U "Starting download of v$UpdateVersion from ${HostIp}:$Port (transfer $TransferId)"

            $tmpPath = Join-Path $UpdateDir "$TransferId.download"
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectResult = $tcp.BeginConnect($HostIp, $Port, $null, $null)
            if (-not $connectResult.AsyncWaitHandle.WaitOne(8000)) {
                Log-U "Connect to ${HostIp}:$Port timed out - aborting, agent untouched"
                try { $tcp.Close() } catch {}
                return
            }
            $tcp.EndConnect($connectResult)

            $stream = $tcp.GetStream()
            $stream.ReadTimeout = 15000   # stall protection

            $fileStream = [System.IO.File]::Create($tmpPath)
            $buffer = New-Object byte[] 65536
            $totalRead = [int64]0
            $ok = $true

            try {
                while ($true) {
                    $n = 0
                    try { $n = $stream.Read($buffer, 0, $buffer.Length) }
                    catch {
                        Log-U "Stream read error/timeout during download - aborting, agent untouched: $_"
                        $ok = $false
                        break
                    }
                    if ($n -le 0) { break }   # server closed connection = EOF
                    $totalRead += $n
                    if ($totalRead -gt $FileSize) {
                        Log-U "Received more bytes than announced ($totalRead > $FileSize) - aborting, agent untouched"
                        $ok = $false
                        break
                    }
                    $fileStream.Write($buffer, 0, $n)
                }
            } finally {
                $fileStream.Close()
                try { $stream.Close() } catch {}
                try { $tcp.Close() } catch {}
            }

            if (-not $ok) {
                Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue
                return
            }

            if ($totalRead -ne $FileSize) {
                Log-U "Size mismatch: got $totalRead bytes, expected $FileSize - discarding download, agent untouched"
                Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue
                return
            }

            # Verify checksum BEFORE touching anything the running agent uses.
            $actualHash = (Get-FileHash -Path $tmpPath -Algorithm SHA256).Hash.ToLower()
            if ($actualHash -ne $ExpectedSha256.ToLower()) {
                Log-U "Checksum mismatch: got $actualHash, expected $ExpectedSha256 - discarding download, agent untouched"
                Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue
                return
            }

            Log-U "Download verified OK (size + SHA-256 match) - staging update"

            $pendingPath = Join-Path $UpdateDir 'pending_agent.ps1'
            Move-Item -Path $tmpPath -Destination $pendingPath -Force

            $marker = [ordered]@{
                update_version = $UpdateVersion
                transfer_id    = $TransferId
                target         = $TargetPath
                staged_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            $marker | ConvertTo-Json -Compress | Set-Content -Path (Join-Path $UpdateDir 'pending.json') -Encoding UTF8 -Force

            # Launch the detached updater helper BEFORE requesting our own
            # shutdown, so it's already waiting on our PID the moment we exit.
            $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $args = "-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$UpdaterScript`" " +
                    "-WaitPid $MyPid -Pending `"$pendingPath`" -Target `"$TargetPath`" -TaskName `"$TaskName`""
            Start-Process -FilePath $psExe -ArgumentList $args -WindowStyle Hidden | Out-Null
            Log-U "Launched updater helper, requesting graceful restart to apply v$UpdateVersion"

            # Signal the main thread — it will finish its current tick,
            # stop cleanly, and exit; the updater helper is already waiting.
            $UpdateState.Message = "Applying update v$UpdateVersion - restarting"
            $UpdateState.PendingRestart = $true

        } catch {
            Log-U "Background update failed unexpectedly (agent untouched): $_"
        }
    }

    $ps = [powershell]::Create()
    [void]$ps.AddScript($scriptBlock).AddArgument($HostIp).AddArgument($Port).AddArgument($FileSize).
        AddArgument($ExpectedSha256).AddArgument($TransferId).AddArgument($UpdateVersion).
        AddArgument($MyPid).AddArgument($UPDATE_DIR).AddArgument($UPDATER_SCRIPT).
        AddArgument($AGENT_SCRIPT_PATH).AddArgument($UPDATE_TASK_NAME).
        AddArgument($LOG_FILE).AddArgument($UPDATE_CONNECT_JITTER_MS_MAX).AddArgument($script:UpdateState)
    # Fire-and-forget: BeginInvoke runs this on a threadpool thread within
    # the same process. We intentionally don't keep/await the handle — the
    # scriptblock signals completion via $script:UpdateState instead.
    [void]$ps.BeginInvoke()
}

function Invoke-UpdatePacket {
    <#
    Entry point called from the main loop whenever data is waiting on the
    update UDP socket. Validates, dedups, checks whether the announced
    version is actually newer, and if so hands off to the background
    downloader — never blocks here. $SenderIP is the source address of the
    UDP datagram itself (from the receive call's remote endpoint) — this is
    the address the agent connects back to for the TCP download, since the
    dashboard has no fixed/static address to hardcode.
    #>
    param([byte[]]$Data, [string]$SenderIP, [object]$Config)

    $payload = Test-UpdatePacket -Bytes $Data -Token $Config.token
    if ($null -eq $payload) { return }

    if ([int]$payload.proto_version -gt $UPDATE_PROTO_MAX) {
        Write-Warn "Update packet proto_version $($payload.proto_version) newer than supported ($UPDATE_PROTO_MAX) - ignoring (agent may need a manual update to understand it)"
        return
    }

    if (Test-UpdateAlreadySeen -TransferId $payload.transfer_id) {
        return   # already downloading/downloaded/rejected this exact deploy
    }

    if ((Compare-Version ([string]$payload.update_version) $AGENT_VERSION) -le 0) {
        Write-Debug2 "Ignoring update announcement v$($payload.update_version) - not newer than running v$AGENT_VERSION"
        return
    }

    Write-Info "Update available: v$($payload.update_version) (current v$AGENT_VERSION) from $SenderIP - starting background download"
    Start-BackgroundUpdate -HostIp $SenderIP -Port ([int]$payload.tcp_port) `
        -FileSize ([int64]$payload.file_size) -ExpectedSha256 ([string]$payload.sha256) `
        -TransferId ([string]$payload.transfer_id) -UpdateVersion ([string]$payload.update_version) `
        -MyPid $PID
}

# ── Main packet handler ───────────────────────────────────────────────────────
function Invoke-PacketHandler {
    param([byte[]]$Data, [string]$SenderIP, [object]$Config)

    # ── FIX 7: Validate and dedup BEFORE any expensive work ──────────────────
    # Parsing and HMAC validation first (cheap crypto, rejects forgeries)
    $payload = Test-Packet -Bytes $Data -Token $Config.token
    if ($null -eq $payload) { return }

    $requestId   = $payload.request_id
    $callbackUrl = $payload.callback_url
    $mode        = $payload.mode

    if (-not $requestId -or -not $callbackUrl) {
        Write-Warn "Packet missing request_id or callback_url - dropped"; return
    }

    # Dedup check immediately after validation — prevents multi-interface
    # machines from processing the same broadcast more than once
    if (Test-AlreadySeen -RequestId $requestId) {
        Write-Debug2 "Duplicate request_id $requestId - ignored"; return
    }

    Write-Info "Received packet with callback_url: $callbackUrl"

    # ── FIX 12: ip_history mode short-circuits everything else ───────────────
    # Answered purely from the local log file — no ARP scan, no relay, no
    # live adapter check beyond what's already in the log.
    if ($mode -eq 'ip_history') {
        Write-Info "IP history query received: qmode=$($payload.iph_mode) id=$requestId from=$SenderIP"
        $matches = Get-IpHistoryMatches -QueryMode $payload.iph_mode -StartUtc $payload.iph_start `
                                        -EndUtc $payload.iph_end -FilterIp $payload.iph_ip
        foreach ($m in $matches) {
            $report = @{
                token           = $Config.token
                request_id      = $requestId
                hostname        = $env:COMPUTERNAME
                mac             = $m.mac
                ip              = $m.ip
                building        = $Config.building
                room            = $Config.room
                timestamp       = $m.timestamp
                type            = 'ip_history'
                connection_type = [string]$Config.connection_type
                port            = [string]$Config.port
                switch_name     = [string]$Config.switch_name
                router_name     = [string]$Config.router_name
            }
            Send-Report -CallbackUrl $callbackUrl -Report $report -Token $Config.token -SourceIP $reportingAdapter.IP -SourceIP $reportingAdapter.IP
        }
        Write-Info "IP history query answered: $(@($matches).Count) match(es)"
        return
    }

    # Now do the expensive adapter enumeration (only once per unique request)
    $target     = $payload.target
    $relayDepth = [int]$payload.relay_depth
    $isPrimary  = if ($null -ne $payload.is_primary) { [bool]$payload.is_primary } else { $false }

    $adapters = Get-NetworkAdapters
    $myIPs    = @($adapters | ForEach-Object { $_.IP })

    #if ($myIPs -contains $SenderIP) {
    #    Write-Debug2 "Dropping self-originated packet from $SenderIP (id=$requestId)"
    #    return
    #}

    Write-Info "Discovery request: mode=$mode depth=$relayDepth id=$requestId from=$SenderIP"

    $myHostname = $env:COMPUTERNAME
    $myBuilding = $Config.building
    $myRoom     = $Config.room

    $reportingAdapter = Get-AdapterForSender -Adapters $adapters -SenderIP $SenderIP
    if ($reportingAdapter) {
        Write-Info "Self-reporting via adapter $($reportingAdapter.Name) IP=$($reportingAdapter.IP)"
    }

    $shouldRespond = $false
    if ($mode -eq 'full') {
        $shouldRespond = $true
    } elseif ($mode -in @('targeted_mac', 'targeted_ip')) {
        $shouldRespond = Test-IsTarget -Adapters $adapters -Mode $mode -Target $target
        if (-not $shouldRespond) { Write-Debug2 "Not the target ($target) - not responding" }
    }

    if ($shouldRespond -and $reportingAdapter) {
        $additionalPorts = @()
        if ($Config.additional_ports) {
            $additionalPorts = @($Config.additional_ports | ForEach-Object { [string]$_ })
        }

        $switchName = if ($Config.switch_name) { [string]$Config.switch_name } else { '' }
        $routerName = if ($Config.router_name) { [string]$Config.router_name } else { '' }

        $report = @{
            token            = $Config.token
            request_id       = $requestId
            hostname         = $myHostname
            mac              = $reportingAdapter.MAC
            ip               = $reportingAdapter.IP
            username         = Get-LoggedInUser
            building         = $myBuilding
            room             = $myRoom
            timestamp        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            type             = 'managed'
            relay_host       = ''
            relay_building   = ''
            relay_room       = ''
            vendor           = Get-MacVendor -MAC $reportingAdapter.MAC
            connection_type  = [string]$Config.connection_type
            port             = [string]$Config.port
            additional_ports = $additionalPorts
            switch_name      = $switchName
            router_name      = $routerName
        }

        Send-Report -CallbackUrl $callbackUrl -Report $report -Token $Config.token
    }

    if ($relayDepth -ge $MAX_RELAY_DEPTH) {
        Write-Warn "Relay depth $relayDepth >= $MAX_RELAY_DEPTH - skipping rebroadcast"; return
    }

    $relayNets = Get-RelayNetworks -SenderIP $SenderIP -Adapters $adapters
    if (@($relayNets).Count -eq 0) {
        Write-Debug2 "No secondary relay subnets detected"; return
    }

    Write-Info "Relaying into $(@($relayNets).Count) secondary subnet(s)"
    foreach ($net in @($relayNets)) {
        Invoke-SubnetRelay -Packet $payload -Config $Config `
                           -MyHostname $myHostname -MyBuilding $myBuilding `
                           -MyRoom $myRoom -RelayNet $net
    }
}

# ── UDP listener loop ─────────────────────────────────────────────────────────
function Start-AgentListener {
    Assert-SingleInstance

    $config = Get-AgentConfig
    try { $script:LastConfigWrite = (Get-Item $CONFIG_FILE).LastWriteTimeUtc } catch {}

    Write-Info "Mneti Agent starting - UDP listener on port $UDP_PORT"
    Write-Info "Version: $AGENT_VERSION | Building: $($config.building) | Room: $($config.room)"
    Write-Info "Token length: $($config.token.Length) chars"

    # ── FIX 11: seed the IP-history baseline ──────────────────────────────────
    # Record current IP(s) once at startup, both as the comparison baseline
    # for Invoke-IpChangeCheck and as a "still on this IP as of boot" entry
    # so a same-day query isn't empty just because nothing changed that day.
    $script:LastKnownIPs = Get-CurrentIPSet
    foreach ($a in (Get-NetworkAdapters)) {
        Write-IpHistoryEntry -IP $a.IP -MAC $a.MAC
    }

    # Register the OS-level, event-driven IP change callback. This never
    # polls — .NET fires this on real network configuration changes.
    $global:MnetiIpChangeFlag = $false
    try {
        Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) `
            -EventName 'NetworkAddressChanged' -SourceIdentifier 'MnetiIPChange' -Action {
                $global:MnetiIpChangeFlag = $true
            } | Out-Null
        Write-Info "Registered NetworkAddressChanged event for IP history tracking"
    } catch {
        Write-Warn "Could not register NetworkAddressChanged event: $_"
    }

    $endpoint  = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $UDP_PORT)
    $udpClient = New-Object System.Net.Sockets.UdpClient

    try {
        $udpClient.Client.SetSocketOption(
            [System.Net.Sockets.SocketOptionLevel]::Socket,
            [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udpClient.Client.Bind($endpoint)
        $udpClient.EnableBroadcast = $true
        Write-Info "Bound to UDP :$UDP_PORT - waiting for broadcasts..."
    } catch {
        Write-Err "Cannot bind to UDP port $UDP_PORT : $_"; exit 1
    }
    $udpClient.Client.ReceiveTimeout = 1000

    # ── FIX 13: second socket for update announcements ────────────────────────
    # Kept separate from the discovery socket/port so the update protocol
    # can evolve independently without any risk of colliding with or
    # complicating the discovery packet format/HMAC canonical string.
    $updateEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $UPDATE_UDP_PORT)
    $updateClient   = New-Object System.Net.Sockets.UdpClient
    try {
        $updateClient.Client.SetSocketOption(
            [System.Net.Sockets.SocketOptionLevel]::Socket,
            [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $updateClient.Client.Bind($updateEndpoint)
        $updateClient.EnableBroadcast = $true
        Write-Info "Bound to UDP :$UPDATE_UDP_PORT - listening for update announcements..."
    } catch {
        Write-Warn "Cannot bind update UDP port $UPDATE_UDP_PORT (self-update disabled this run): $_"
        $updateClient = $null
    }

    $script:Running = $true
    $lastReloadCheck = [DateTime]::Now

    try {
        while ($script:Running) {
            try {
                # FIX 10: poll config.json for changes without needing a restart
                if (([DateTime]::Now - $lastReloadCheck).TotalSeconds -ge $CONFIG_RELOAD_SECS) {
                    Update-ConfigIfChanged -ConfigRef ([ref]$config)
                    $lastReloadCheck = [DateTime]::Now
                }

                # FIX 11: event-driven IP history check (no polling of IP state —
                # only reacts when the OS event above actually fired)
                if ($global:MnetiIpChangeFlag) {
                    $global:MnetiIpChangeFlag = $false
                    Invoke-IpChangeCheck
                }

                # FIX 13: non-blocking poll of the update socket. .Available
                # is a cheap property check, not a blocking call, so this
                # never stalls the discovery loop while idle.
                if ($updateClient -and $updateClient.Available -gt 0) {
                    try {
                        $uRemote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                        $uData   = $updateClient.Receive([ref]$uRemote)
                        Invoke-UpdatePacket -Data $uData -SenderIP $uRemote.Address.ToString() -Config $config
                    } catch { Write-Warn "Error reading update announcement: $_" }
                }

                # FIX 13: the background downloader (if one is in flight)
                # sets this once the update has been verified and staged
                # and the detached updater helper is already waiting on
                # our PID. Break out and shut down cleanly so it can apply
                # the update and restart us.
                if ($script:UpdateState.PendingRestart) {
                    Write-Info $script:UpdateState.Message
                    $script:Running = $false
                    continue
                }

                $remote   = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $data     = $udpClient.Receive([ref]$remote)
                $senderIP = $remote.Address.ToString()

                if ($data.Length -gt $BUFFER_SIZE) {
                    Write-Warn "Oversized packet ($($data.Length) bytes) from $senderIP - dropped"
                    continue
                }

                Invoke-PacketHandler -Data $data -SenderIP $senderIP -Config $config

            } catch [System.Net.Sockets.SocketException] {
                continue
            } catch {
                if ($script:Running) {
                    Write-Err ("UDP receive error:`n" + ($_ | Out-String))
                    Write-Err ("Stack:`n" + $_.ScriptStackTrace)
                }
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier 'MnetiIPChange' -ErrorAction SilentlyContinue
        $udpClient.Close()
        if ($updateClient) { $updateClient.Close() }
        Write-Info "Mneti Agent stopped."
    }
}

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-AgentListener
}