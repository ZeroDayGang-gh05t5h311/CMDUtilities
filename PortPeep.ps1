$AllowedPorts = @(22, 53, 80, 443)
$AllowedIPRanges = @(
    "127.0.0.0/8",
    "192.168.1.0/24"
)
$LogFile = "C:\ProgramData\network_monitor.log"
$RateLimitSeconds = 60
$PollInterval = 10
$AlertCache = @{}
$TerminalOutput = $false
$Continuous = $false
foreach ($arg in $args) {
    switch ($arg) {
        "-c" { $Continuous = $true }
        "-o" { $Continuous = $false }
        "--terminal" { $TerminalOutput = $true }
    }
}
function Write-Log {
    param (
        [string]$Level,
        [string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    if ($TerminalOutput) {
        Write-Host $line
    }
}
function Rate-Limited {
    param ([string]$Key)
    $now = Get-Date
    if ($AlertCache.ContainsKey($Key)) {
        $last = $AlertCache[$Key]
        if (($now - $last).TotalSeconds -lt $RateLimitSeconds) {
            return $true
        }
    }
    $AlertCache[$Key] = $now
    return $false
}
function IP-In-Range {
    param (
        [string]$IP,
        [string]$CIDR
    )
    $parts = $CIDR.Split("/")
    $network = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    $maskBits = [int]$parts[1]
    $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    $mask = [uint32]0
    for ($i = 0; $i -lt $maskBits; $i++) {
        $mask = $mask -bor (1 -shl (31 - $i))
    }
    $ipInt = [BitConverter]::ToUInt32($ipBytes[::-1], 0)
    $netInt = [BitConverter]::ToUInt32($network[::-1], 0)
    return (($ipInt -band $mask) -eq ($netInt -band $mask))
}
function Is-IP-Allowed {
    param ([string]$IP)

    foreach ($range in $AllowedIPRanges) {
        if (IP-In-Range $IP $range) {
            return $true
        }
    }
    return $false
}
function Scan-Network {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        $pid = $conn.OwningProcess
        if (-not $remoteIP -or $remoteIP -eq "0.0.0.0") {
            continue
        }
        $alertKeyConn = "conn:$remoteIP:$remotePort"
        if (($AllowedPorts -notcontains $remotePort) -and (-not (Is-IP-Allowed $remoteIP))) {
            if (-not (Rate-Limited $alertKeyConn)) {
                Write-Log "ALERT" "Unusual outbound connection detected"
                Write-Log "ALERT" "Destination: $remoteIP`:$remotePort"
                Write-Log "ALERT" "PID: $pid"
            }
        }
        else {
            Write-Log "OK" "Allowed connection -> $remoteIP`:$remotePort"
        }
        if ($AllowedPorts -notcontains $remotePort) {
            $alertKeyProc = "proc:$pid:$remotePort"
            if (-not (Rate-Limited $alertKeyProc)) {
                try {
                    $proc = Get-Process -Id $pid -ErrorAction Stop
                    Write-Log "ALERT" "Process using non-standard port"
                    Write-Log "ALERT" "Process: $($proc.ProcessName) (PID $pid)"
                    Write-Log "ALERT" "Port: $remotePort"
                }
                catch {
                    Write-Log "ALERT" "Unknown process PID $pid using port $remotePort"
                }
            }
        }
    }
}
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Must be run as Administrator."
    exit 1
}
Write-Log "INFO" "Network monitor started"
if ($Continuous) {
    while ($true) {
        Scan-Network
        Start-Sleep -Seconds $PollInterval
    }
}
else {
    Scan-Network
    Write-Log "INFO" "One-time network scan completed"
}
<#
One-time scan (log only)
powershell -ExecutionPolicy Bypass -File damon.ps1
Continuous mode
powershell -ExecutionPolicy Bypass -File damon.ps1 -c
Continuous + terminal output
powershell -ExecutionPolicy Bypass -File damon.ps1 -c --terminal
Log file location: C:\ProgramData\network_monitor.log
#>
