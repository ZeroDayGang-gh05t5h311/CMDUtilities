<#
AD-Audit-Lite
A lightweight Active Directory audit and reporting tool written entirely in native PowerShell and .NET.
No RSAT modules.
No external dependencies.
No PowerShell ActiveDirectory module required.
Designed for:
- Domain-joined Windows workstations
- Restricted environments
- Minimal dependency auditing
- Fast operational reviews
# Features
## Security Auditing
- Inactive user discovery
- Password-never-expires detection
- Privileged group membership enumeration
## Replication Health
- Replication status collection using `repadmin`
- Domain controller discovery using `nltest`
## Reporting
- CSV exports
- JSON exports
- Plain text logging
- Summary generation
## Native-Only Design
Uses:
- ADSI
- LDAP
- .NET `System.DirectoryServices`
- Native Windows commands
No external PowerShell modules required.
# Requirements
- Windows PowerShell 5.1+ or PowerShell 7+
- Domain-joined machine
- Standard domain read permissions
- Native Windows AD tools available:
  - `nltest`
  - `repadmin`
Optional:
- Elevated privileges for some replication checks
---
# Usage
## Basic Run
```powershell
.\Invoke-ADAudit.ps1
```
## Custom Output Directory
```powershell
.\Invoke-ADAudit.ps1 -OutputPath C:\Reports
```
## Custom Inactivity Threshold
```powershell
.\Invoke-ADAudit.ps1 -InactiveDays 90
## JSON Export
```powershell
.\Invoke-ADAudit.ps1 -AsJson
# Output Files
| File | Description |
|------|-------------|
| results.csv | Structured audit findings |
| results.json | JSON export (optional) |
| summary.txt | Audit summary |
| audit.log | Execution log |
# Security Notes
This tool:
- Does NOT modify Active Directory
- Performs read-only operations
- Does NOT require Domain Admin privileges
- Uses LDAP queries against the current domain
# Limitations
Because no RSAT modules are used:
- GPO backup is unavailable
- Some advanced replication metadata is limited
- Fine-grained AD policy analysis is not included
This tool prioritizes:
- portability
- simplicity
- low dependency footprint
# Philosophy
This is intentionally boring software.
The goal is:
- readable code
- operational reliability
- minimal assumptions
- easy debugging during outages
Not:
- "AI agents"
- orchestration hype
- enterprise buzzword inflation
# License
MIT 
READme.md
#>
# Invoke-ADAudit.ps1
[CmdletBinding()]
param(
    [string]$OutputPath = "C:\AD-Audit",
    [int]$InactiveDays = 180,
    [switch]$AsJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$LogFile = Join-Path $OutputPath "audit.log"
function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date), $Message
    $line | Out-File $LogFile -Append
    Write-Host $line
}
$Results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Target,
        [string]$Finding
    )
    $Results.Add([PSCustomObject]@{
        Time     = Get-Date
        Category = $Category
        Severity = $Severity
        Target   = $Target
        Finding  = $Finding
    })
}
Write-Log "Discovering domain..."
$RootDSE = [ADSI]"LDAP://RootDSE"
$DomainDN = $RootDSE.defaultNamingContext
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = "LDAP://$DomainDN"
Write-Log "Checking inactive users..."
$Searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
$Searcher.PageSize = 1000
$Users = $Searcher.FindAll()
$Threshold = (Get-Date).AddDays(-$InactiveDays)
foreach ($user in $Users) {
    try {
        $entry = $user.GetDirectoryEntry()
        $lastLogon = $null
        if ($entry.lastLogonTimestamp.Value) {
            $lastLogon = [DateTime]::FromFileTime(
                [Int64]$entry.lastLogonTimestamp.Value
            )
        }
        $enabled = -not (
            [bool]($entry.userAccountControl.Value -band 0x2)
        )
        if ($enabled -and $lastLogon -lt $Threshold) {
            Add-Result `
                -Category "Security" `
                -Severity "WARN" `
                -Target $entry.sAMAccountName.Value `
                -Finding "Inactive user"
        }
    } catch {
        Write-Log $_.Exception.Message
    }
}
Write-Log "Checking password settings..."
foreach ($user in $Users) {
    try {
        $entry = $user.GetDirectoryEntry()
        $uac = $entry.userAccountControl.Value
        if ($uac -band 0x10000) {
            Add-Result `
                -Category "Security" `
                -Severity "WARN" `
                -Target $entry.sAMAccountName.Value `
                -Finding "Password never expires"
        }
    } catch {
        Write-Log $_.Exception.Message
    }
}
Write-Log "Enumerating privileged groups..."
$Groups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators"
)
foreach ($groupName in $Groups) {
    try {
        $Searcher.Filter = "(&(objectClass=group)(cn=$groupName))"
        $group = $Searcher.FindOne()
        if ($group) {
            $groupEntry = $group.GetDirectoryEntry()
            foreach ($member in $groupEntry.member) {
                Add-Result `
                    -Category "Privilege" `
                    -Severity "INFO" `
                    -Target $groupName `
                    -Finding $member
            }
        }
    } catch {
        Write-Log $_.Exception.Message
    }
}
Write-Log "Checking replication..."
try {
    $repadmin = repadmin /replsummary 2>&1
    foreach ($line in $repadmin) {
        if ($line -match "fails") {
            Add-Result `
                -Category "Replication" `
                -Severity "INFO" `
                -Target "Forest" `
                -Finding $line
        }
    }
} catch {
    Write-Log "repadmin unavailable"
}
Write-Log "Exporting results..."
$CsvPath = Join-Path $OutputPath "results.csv"
$Results | Export-Csv $CsvPath -NoTypeInformation
if ($AsJson) {
    $JsonPath = Join-Path $OutputPath "results.json"
    $Results |
        ConvertTo-Json -Depth 4 |
        Out-File $JsonPath
}
$Summary = @"
AD Audit Summary
================
Generated: $(Get-Date)
Findings: $($Results.Count)
Warnings: $(($Results | Where-Object Severity -eq 'WARN').Count)
Errors:   $(($Results | Where-Object Severity -eq 'ERROR').Count)
"@
$Summary |
    Out-File (Join-Path $OutputPath "summary.txt")
Write-Log "Completed."
