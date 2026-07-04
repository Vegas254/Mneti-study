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
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Constants ─────────────────────────────────────────────────────────────────
$CONFIG_FILE     = 'C:\ProgramData\Locator\config.json'
$LOG_FILE        = 'C:\ProgramData\Locator\agent.log'
$UDP_PORT        = 5000
$RELAY_HTTP_PORT = 5002
$BUFFER_SIZE     = 4096
$POST_TIMEOUT    = 8
$CACHE_TTL       = 60
$MAX_LOG_BYTES   = 5MB
$MAX_RELAY_DEPTH = 1

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
    if ($Adapter.InterfaceType -notin $ALLOWED_INTERFACE_TYPES) { return $true }
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
    foreach ($a in $Adapters) {
        if (Test-SameSubnet -IP1 $a.IP -IP2 $SenderIP -PrefixLength $a.PrefixLength) { return $a }
        foreach ($pl in @(22, 23, 24)) {
            if (Test-SameSubnet -IP1 $a.IP -IP2 $SenderIP -PrefixLength $pl) { return $a }
        }
    }
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

    $payloadJson = '{"request_id":"' + $p.request_id + '","mode":"' + $p.mode + '","target":"' + $p.target + '","token":"' + $p.token + '","callback_url":"' + $p.callback_url + '","timestamp":"' + $p.timestamp + '","relay_depth":' + $relayDepth + ',"is_primary":' + $isPrimary.ToString().ToLower() + '}'
    $expectedSig = Get-HmacSha256 -Secret $Token -Message $payloadJson

    if (-not (Test-ConstantTimeEqual $expectedSig $envelope.sig)) {
        Write-Warn "HMAC mismatch - dropped (possible forgery)"; return $null
    }
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
    param([string]$CallbackUrl, [hashtable]$Report, [string]$Token)
    try {
        $body      = $Report | ConvertTo-Json -Compress -Depth 5
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $sig       = Get-HmacSha256 -Secret $Token -Message $body

        $req             = [System.Net.HttpWebRequest]::Create($CallbackUrl)
        $req.Method      = 'POST'
        $req.ContentType = 'application/json'
        $req.Timeout     = $POST_TIMEOUT * 1000
        $req.Headers.Add('X-Signature', $sig)

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

    $relayPayload = [ordered]@{
        request_id   = $OriginalPayload.request_id
        mode         = $OriginalPayload.mode
        target       = $OriginalPayload.target
        token        = $Token
        callback_url = $LocalCallbackUrl
        timestamp    = $OriginalPayload.timestamp
        relay_depth  = $RelayDepth
        is_primary   = $isPrimary
    }

    $payloadJson = '{"request_id":"' + $relayPayload.request_id +
                   '","mode":"'         + $relayPayload.mode +
                   '","target":"'       + $relayPayload.target +
                   '","token":"'        + $relayPayload.token +
                   '","callback_url":"' + $relayPayload.callback_url +
                   '","timestamp":"'    + $relayPayload.timestamp +
                   '","relay_depth":'   + $relayPayload.relay_depth +
                   ',"is_primary":'     + $isPrimary.ToString().ToLower() + '}'

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
            $listener.Start()
            $localCallbackUrl = "http://$($localIP):$relayPort/api/report"
            $listenerStarted  = $true
            Write-Info "Relay HTTP listener started on ${localIP}:$relayPort"
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
                if (-not $asyncResult.AsyncWaitHandle.WaitOne(250)) { continue }

                $ctx    = $listener.EndGetContext($asyncResult)
                $req    = $ctx.Request
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
            Send-Report -CallbackUrl $Packet.callback_url -Report $relayReport -Token $Config.token
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
            Send-Report -CallbackUrl $Packet.callback_url -Report $unmanagedReport -Token $Config.token
        }

    } finally {
        if ($listener) {
            try { if ($listener.IsListening) { $listener.Stop() } } catch {}
            try { $listener.Close() } catch {}
            Write-Info "Relay listener cleaned up on ${localIP}:$relayPort"
        }
    }
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

    if (-not $requestId -or -not $callbackUrl) {
        Write-Warn "Packet missing request_id or callback_url - dropped"; return
    }

    # Dedup check immediately after validation — prevents multi-interface
    # machines from processing the same broadcast more than once
    if (Test-AlreadySeen -RequestId $requestId) {
        Write-Debug2 "Duplicate request_id $requestId - ignored"; return
    }

    # Now do the expensive adapter enumeration (only once per unique request)
    $mode       = $payload.mode
    $target     = $payload.target
    $relayDepth = [int]$payload.relay_depth
    $isPrimary  = if ($null -ne $payload.is_primary) { [bool]$payload.is_primary } else { $false }

    $adapters = Get-NetworkAdapters
    $myIPs    = @($adapters | ForEach-Object { $_.IP })

    if ($myIPs -contains $SenderIP) {
        Write-Debug2 "Dropping self-originated packet from $SenderIP (id=$requestId)"
        return
    }

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
    $config = Get-AgentConfig

    Write-Info "Mneti Agent starting - UDP listener on port $UDP_PORT"
    Write-Info "Building: $($config.building) | Room: $($config.room)"
    Write-Info "Token length: $($config.token.Length) chars"

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
    $script:Running = $true

    try {
        while ($script:Running) {
            try {
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
        $udpClient.Close()
        Write-Info "Mneti Agent stopped."
    }
}

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-AgentListener
}