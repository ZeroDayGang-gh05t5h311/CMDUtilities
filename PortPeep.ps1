<#
.SYNOPSIS
Windows Network Monitor – Equivalent behavioral port of the POSIX version
.DESCRIPTION
Monitors network connections, processes, and performs user audit. Logs results to a file with rotation.
#>
# --- Configuration ---
$LogFile = "C:\Windows\Temp\network_monitor.log"
$LogMaxBytes = 5MB
$LogBackups = 5
$RateLimitSeconds = 60
$DiskSpaceThresholdMB = 1024 # 1GB
$StateDir = "C:\Windows\Temp\network_monitor_state"
$AllowedPorts = @(22,53,80,443)
$AllowedIPv4CIDRs = @("127.0.0.0/8","192.168.1.0/24")
$AllowLoopbackIPv6 = $true
$TerminalOutput = $false
$Continuous = $false
# --- Ensure state directory exists ---
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }
# --- Helper Functions ---
function Get-Timestamp { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function Rotate-Logs {
    if (-not (Test-Path $LogFile)) { return }
    $size = (Get-Item $LogFile).Length
    if ($size -lt $LogMaxBytes) { return }
    for ($i=$LogBackups; $i -gt 1; $i--) {
        $prev = $i - 1
        $prevFile = "$LogFile.$prev"
        if (Test-Path $prevFile) { Move-Item $prevFile "$LogFile.$i" -Force }
    }
    Move-Item $LogFile "$LogFile.1" -Force
}
function Log {
    param($Level, $Message)
    Rotate-Logs
    "$((Get-Timestamp)) - $Level - $Message" | Out-File -FilePath $LogFile -Append -Force
    if ($TerminalOutput) { Write-Host "$Level - $Message" }
}
function Die { param($Message) Log "ERROR" $Message; exit 1 }
function Check-Admin {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator"))) {
        Die "Must be run as administrator."
    }
}
function Check-DiskSpace {
    $drive = (Get-Item $LogFile).PSDrive.Name
    $freeMB = (Get-PSDrive $drive).Free / 1MB
    if ($freeMB -lt $DiskSpaceThresholdMB) { Die "Disk space is low! Stopping the script." }
}
function Rate-Limited {
    param($Key)
    $file = Join-Path $StateDir $Key
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    if (Test-Path $file) {
        $last = Get-Content $file | Out-String
        if (($now - [int]$last) -lt $RateLimitSeconds) { return $true }
    }
    $now | Out-File $file -Force
    return $false
}
function Test-PortAllowed { param($Port) return $AllowedPorts -contains $Port }
function IPv4-InCIDR {
    param($IP, $CIDR)
    $ipbytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    $parts = $CIDR.Split('/')
    $net = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    $maskBits = [int]$parts[1]
    $mask = [System.Net.IPAddress]::Parse(([string]([math]::Pow(2,32)-1) -shl (32-$maskBits))).GetAddressBytes()
    for ($i=0; $i -lt 4; $i++) {
        if (($ipbytes[$i] -band $mask[$i]) -ne ($net[$i] -band $mask[$i])) { return $false }
    }
    return $true
}
function IPv6-IsLoopback {
param($IP)
try {
    $addr = [System.Net.IPAddress]::Parse($IP)
    return $addr.Equals([System.Net.IPAddress]::IPv6Loopback)
}
catch {
    return $false
}
}
function Test-IPAllowed {
param($IP)
if ($AllowLoopbackIPv6 -and (IPv6-IsLoopback $IP)) {
    return $true
}
if ($IP -match ":") {
    return $false
}
foreach ($cidr in $AllowedIPv4CIDRs) {
    if (IPv4-InCIDR $IP $cidr) {
        return $true
    }
}
return $false
}

# --- Network & Process Checks ---
function Process-Connections {
$connections = @()
try {
    $connections += Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Established' }
} catch {}
try {
    $connections += Get-NetUDPEndpoint -ErrorAction SilentlyContinue
} catch {}
foreach ($conn in $connections) {
    if ($conn.PSObject.Properties.Name -contains "RemoteAddress") {
        $ip = $conn.RemoteAddress
        $port = $conn.RemotePort
        $proto = "TCP"
    } else {
        continue
    }
    if ($ip -eq "127.0.0.1" -or $ip -eq "::1") {
        continue
    }
    $key = "conn_${ip}_${port}_${proto}"
    if (-not (Test-PortAllowed $port) -and -not (Test-IPAllowed $ip)) {

        if (Rate-Limited $key) {
            continue
        }
        Log "WARN" "[ALERT] Unusual outbound connection"
        Log "WARN" "Protocol: $proto"
        Log "WARN" "Destination: $ip`:$port"

    } else {

        Log "INFO" "[OK] $proto -> $ip`:$port"

    }
}
}
function Process-Processes {
    $procTCP = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
    foreach ($conn in $procTCP) {
        $port = $conn.LocalPort
        $pid = $conn.OwningProcess
        if (Test-PortAllowed $port) { continue }
        $key = "proc_${pid}_${port}"
        if (Rate-Limited $key) { continue }
        $procName = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName
        Log "WARN" "[ALERT] Process using non-standard port: $procName (PID $pid) Port $port"
    }
}
# --- User Audit ---
function Run-UserAccessAudit {
    Write-Output "=== Windows User & Access Audit ==="
    Write-Output "Timestamp: $(Get-Date)"
    Write-Output "=== Local Users ==="
    Get-LocalUser | Format-Table Name,Enabled,LastLogon
    Write-Output "=== Administrators ==="
    Get-LocalGroupMember Administrators | Format-Table Name,ObjectClass
    Write-Output "=== Currently Logged In Users ==="
    quser 2>$null
    Write-Output "=== Running Services ==="
    Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table Name,DisplayName
    Write-Output "Audit Complete"
}
# --- Run Once ---
function Run-Once {
    Check-DiskSpace
    Process-Connections
    Process-Processes
    # Save audit to log file
    Run-UserAccessAudit | Out-File $LogFile -Append -Force
}
# --- Main ---
Check-Admin
if (-not $TerminalOutput) {
    Write-Host "Network monitor started. Logging to $LogFile"
}

# Determine mode
Param(
    [switch]$Continuous,
    [switch]$Terminal
)
if ($Terminal) { $TerminalOutput = $true }

if ($Continuous) {
    while ($true) {
        Run-Once
        Start-Sleep -Seconds 10
    }
} else {
    Run-Once
    Log "INFO" "One-time network scan completed"
}
