# Requires PowerShell 5+
param(
    [switch]$Continuous,
    [switch]$OneTime,
    [switch]$Terminal
)
# Configuration
$AllowedPorts = @(22,53,80,443)
$AllowedIPRanges = @("127.0.0.0/8","192.168.1.0/24","::1/128")
$RateLimitSeconds = 60
$LogFile = "C:\network_monitor.log"
$DiskThresholdGB = 1
$AlertCache = @{}
# Function to log messages
function Write-Log($Message, $Level="INFO") {
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "$Time - $Level - $Message"
    Add-Content -Path $LogFile -Value $LogLine
    if ($Terminal) { Write-Host $LogLine }
}
# Rate limiting
function Is-RateLimited($Key) {
    if ($AlertCache.ContainsKey($Key)) {
        $Last = $AlertCache[$Key]
        if ((Get-Date) - $Last -lt ([TimeSpan]::FromSeconds($RateLimitSeconds))) { return $true }
    }
    $AlertCache[$Key] = Get-Date
    return $false
}
# Disk space check
function Check-DiskSpace {
    $FreeGB = (Get-PSDrive C).Free/1GB
    if ($FreeGB -lt $DiskThresholdGB) {
        Write-Log "Disk space is low! Stopping script." "ERROR"
        return $false
    }
    return $true
}
# IP allowed check
function Is-IPAllowed($IP) {
    foreach ($range in $AllowedIPRanges) {
        if (Test-Connection -Count 1 -Quiet -Destination $IP -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}
# Get active TCP/UDP connections
function Get-ActiveConnections {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if ($connections) { return $connections } else { return @() }
}
# Process connections
function Process-Connection($conn) {
    $ip = $conn.RemoteAddress
    $port = $conn.RemotePort
    $proto = $conn.Protocol
    if ($AllowedPorts -contains $port -or (Is-IPAllowed $ip)) { 
        Write-Log "[OK] $proto -> $ip:$port" 
    } else {
        $key = "conn:$ip:$port:$proto"
        if (-not (Is-RateLimited $key)) {
            Write-Log "[ALERT] Unusual outbound connection" "WARN"
            Write-Log "Protocol: $proto" "WARN"
            Write-Log "Destination: $ip:$port" "WARN"
        }
    }
}
# Run monitoring loop
function Run-Monitor {
    do {
        if (-not (Check-DiskSpace)) { break }
        $connections = Get-ActiveConnections
        $jobs = @()
        foreach ($conn in $connections) {
            $jobs += Start-Job -ScriptBlock { param($c) Process-Connection $c } -ArgumentList $conn
        }
        $jobs | Wait-Job | Out-Null
        $jobs | Remove-Job
        if (-not $Continuous) { break }
        Start-Sleep -Seconds 10
    } while ($true)
}
# Main execution
if (-not $Continuous -and -not $OneTime) {
    Write-Host "Usage: .\NetworkMonitor.ps1 [-Continuous] [-OneTime] [-Terminal]"
    exit
}
Run-Monitor
