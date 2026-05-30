# AD Audit & Health Framework - Hardened Version
[CmdletBinding()]
param(
    [string]$DomainController,
    [string]$OutputPath = "C:\AD-Audit\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')",
    [int]$InactiveDays = 180,
    [switch]$SkipGPOBackup,
    [switch]$IncludeReplication,
    [switch]$AsJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredModules = @('ActiveDirectory')
$optionalModules = @('GroupPolicy')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Required module missing: $module"
    }
}
Import-Module ActiveDirectory
foreach ($module in $optionalModules) {
    if (Get-Module -ListAvailable -Name $module) {
        Import-Module $module
    }
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$LogFile = Join-Path $OutputPath 'audit.log'

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $entry = [PSCustomObject]@{
        Timestamp = Get-Date
        Level     = $Level
        Message   = $Message
    }
    $line = "{0} [{1}] {2}" -f `
        $entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
        $entry.Level,
        $entry.Message
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Target,
        [string]$Finding,
        [object]$Data = $null
    )
    $Results.Add([PSCustomObject]@{
        Timestamp = Get-Date
        Category  = $Category
        Severity  = $Severity
        Target    = $Target
        Finding   = $Finding
        Data      = $Data
    })
}

Write-Log "Discovering domain controllers..."
$DCs = if ($DomainController) {
    @(Get-ADDomainController -Identity $DomainController)
} else {
    @(Get-ADDomainController -Filter *)
}
Write-Log "Found $($DCs.Count) domain controller(s)."

function Invoke-SecurityAudit {
    Write-Log "Running security audit..."
    try {
        $threshold = (Get-Date).AddDays(-$InactiveDays)
        Get-ADUser -Filter * -Properties LastLogonDate,Enabled |
        Where-Object {
            $_.Enabled -eq $true -and
            $_.LastLogonDate -lt $threshold
        } | ForEach-Object {
            Add-Result `
                -Category 'Security' `
                -Severity 'WARN' `
                -Target $_.SamAccountName `
                -Finding "Inactive for $InactiveDays days" `
                -Data $_
        }

        # Hardened filter syntax for PasswordNeverExpires
        Get-ADUser -Filter "PasswordNeverExpires -eq '$true' -and Enabled -eq '$true'" -Properties PasswordNeverExpires |
        ForEach-Object {
            Add-Result `
                -Category 'Security' `
                -Severity 'WARN' `
                -Target $_.SamAccountName `
                -Finding 'Password never expires' `
                -Data $_
        }

        $groups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
        foreach ($group in $groups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive
                foreach ($member in $members) {
                    Add-Result `
                        -Category 'Privilege' `
                        -Severity 'INFO' `
                        -Target $group `
                        -Finding "$($member.SamAccountName) has privileged membership" `
                        -Data $member
                }
            } catch {
                Add-Result `
                    -Category 'Privilege' `
                    -Severity 'ERROR' `
                    -Target $group `
                    -Finding $_.Exception.Message
            }
        }
    } catch {
        Write-Log $_.Exception.Message 'ERROR'
    }
}
function Invoke-ReplicationAudit {
    Write-Log "Running replication audit..."
    $replicationResults = $DCs | ForEach-Object -Parallel {
        param($dc)
        try {
            Get-ADReplicationPartnerMetadata -Target $dc.HostName |
            Select-Object Server, Partner, LastReplicationAttempt, LastReplicationSuccess, ConsecutiveReplicationFailures
        } catch {
            [PSCustomObject]@{
                Server = $dc.HostName
                Error  = $_.Exception.Message
            }
        }
    } -ArgumentList $_ -ThrottleLimit 5
    foreach ($item in $replicationResults) {
        if ($item.ConsecutiveReplicationFailures -gt 0) {
            Add-Result `
                -Category 'Replication' `
                -Severity 'ERROR' `
                -Target $item.Server `
                -Finding "Replication failures detected" `
                -Data $item
        } else {
            Add-Result `
                -Category 'Replication' `
                -Severity 'INFO' `
                -Target $item.Server `
                -Finding 'Replication healthy' `
                -Data $item
        }
    }
}
function Invoke-GPOAudit {
    if (-not (Get-Module GroupPolicy)) {
        Write-Log "GroupPolicy module unavailable." 'WARN'
        return
    }
    Write-Log "Running GPO audit..."
    $gpos = Get-GPO -All
    foreach ($gpo in $gpos) {
        Add-Result `
            -Category 'GPO' `
            -Severity 'INFO' `
            -Target $gpo.DisplayName `
            -Finding 'GPO discovered' `
            -Data $gpo
    }
    if (-not $SkipGPOBackup) {
        try {
            $backupPath = Join-Path $OutputPath 'GPO-Backup'
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
            Backup-GPO -All -Path $backupPath | Out-Null
            Write-Log "GPO backup completed."
        } catch {
            Write-Log $_.Exception.Message 'ERROR'
        }
    }
}
function Get-HealthScore {
    $critical = ($Results | Where-Object Severity -eq 'ERROR').Count * 10
    $warning = ($Results | Where-Object Severity -eq 'WARN').Count * 2
    $score = 100 - ($critical + $warning)
    return [Math]::Max($score, 0)
}
function Export-Results {
    Write-Log "Exporting results..."
    $Results | Export-Csv (Join-Path $OutputPath 'results.csv') -NoTypeInformation
    if ($AsJson) {
        $Results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath 'results.json')
    }
    $summary = [PSCustomObject]@{
        GeneratedAt       = Get-Date
        Domain            = (Get-ADDomain).DNSRoot
        DomainControllers = $DCs.Count
        Findings          = $Results.Count
        Errors            = ($Results | Where-Object Severity -eq 'ERROR').Count
        Warnings          = ($Results | Where-Object Severity -eq 'WARN').Count
        HealthScore       = Get-HealthScore
    }

    $summary | Format-List | Out-File (Join-Path $OutputPath 'summary.txt')
    $summary
}
# Script Execution
Write-Log "===== AD Audit Started ====="
Invoke-SecurityAudit
if ($IncludeReplication) {
    Invoke-ReplicationAudit
}
Invoke-GPOAudit
$summary = Export-Results

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
$summary | Format-List
