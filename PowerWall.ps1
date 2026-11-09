<#
Windows Firewall Configurator (fwconfig)
A PowerShell-based Windows Firewall configuration utility with AES-256 encrypted activity logging.
fwconfig is designed to simplify inbound firewall configuration on Windows systems. It allows administrators to specify TCP and UDP ports through command-line arguments or a configuration file, applies corresponding Windows Defender Firewall rules, and initializes an encrypted log for recording execution information.

The script is intended for systems that you own or are explicitly authorized to administer.

    IMPORTANT: UNTESTED SOFTWARE

    This script has not been tested on an actual Windows computer because I currently do not have access to a Windows environment.

    Although the implementation is designed for Windows PowerShell 5.1 and uses standard Windows Firewall and .NET cryptography APIs, its behavior has not been verified through real-world execution.

    There may be compatibility issues, unexpected behavior, implementation bugs, or firewall configuration problems that have not yet been identified.

    Use at your own risk. Test in a disposable virtual machine or other controlled Windows environment before deploying it on a production system. Do not rely on this script as your only security control.

Features

    Windows Defender Firewall configuration: Creates inbound firewall rules using PowerShell's built-in NetSecurity cmdlets.
    TCP and UDP support: Allows individual TCP ports through command-line arguments and both TCP and UDP ports through configuration files.
    Configuration file support: Loads multiple firewall rules from a simple text file.
    Encrypted logging: Uses AES-256-CBC encryption with HMAC-SHA256 authentication.
    Password-based key derivation: Derives encryption keys using PBKDF2-HMAC-SHA256 with 100,000 iterations and a randomly generated salt.
    Log decryption: Provides a built-in option to decrypt and display previously generated logs.
    Integrity verification: Authenticates encrypted records before attempting decryption.
    Interactive mode: Provides a menu-driven interface for users who prefer not to use command-line arguments.
    Persistent firewall rules: Creates rules in Windows Firewall's persistent policy store.
    Management port warning: Warns when TCP port 22 or 2222 is not included in the requested rules.

Requirements

    Windows operating system with Windows Defender Firewall.
    Windows PowerShell 5.1 or compatible PowerShell environment.
    Administrator privileges when applying firewall rules.
    .NET cryptography APIs available to the PowerShell runtime.
    Permission to configure Windows Firewall.
    A passphrase for initializing or decrypting encrypted logs.

The script uses the following Windows PowerShell cmdlets:

    Get-NetFirewallRule
    New-NetFirewallRule
    Remove-NetFirewallRule
    Set-NetFirewallProfile

These cmdlets are provided by the Windows NetSecurity module.
Installation

    Save the script as:

    fwconfig.ps1
    Open Windows PowerShell.
    Navigate to the directory containing the script.
    If necessary, configure your PowerShell execution policy according to your organization's security requirements.
    Run the script using one of the examples below.

Administrator privileges are required when applying firewall rules.
Usage

General syntax:

.\fwconfig.ps1 [options] [tcp_port ...]

.\fwconfig.ps1 --decrypt [options]

.\fwconfig.ps1 --help

Command-line options
Option	Description
-c, --config FILE	Load firewall rules from a configuration file.
-l, --log FILE	Specify the encrypted log file.
-d, --decrypt	Decrypt and display an existing log.
-h, --help	Display help information.
Examples

Apply inbound TCP rules for ports 22, 80, and 443:

.\fwconfig.ps1 22 80 443

Load rules from a configuration file:

.\fwconfig.ps1 -c ports.conf

Specify a custom encrypted log file:

.\fwconfig.ps1 -l C:\logs\fw.enc 22 80 443

Decrypt the default log:

.\fwconfig.ps1 --decrypt

Decrypt a custom log:

.\fwconfig.ps1 --decrypt -l C:\logs\fw.enc

Display help:

.\fwconfig.ps1 --help

Configuration File

Configuration files support one firewall rule per line.

The format is:

protocol:port

Supported protocol identifiers are:

    tcp
    udp

Example ports.conf:

# SSH access
tcp:22

# HTTP and HTTPS
tcp:80
tcp:443

# DNS
udp:53

# Custom application
tcp:8080
udp:8080

Blank lines and lines beginning with # are ignored.

Port numbers must be between 0 and 65535.

Invalid configuration lines are skipped with a warning rather than terminating the entire import operation.

Important: Command-line port arguments are interpreted as TCP ports. Use a configuration file when UDP rules are required.
Interactive Mode

Running the script without arguments starts the interactive menu.

The menu provides four options:

    Apply firewall rules interactively.
    Decrypt an encrypted log.
    Display detailed help.
    Exit.

When applying rules interactively, the user can provide TCP ports directly or specify a configuration file.

A custom log path can also be supplied.
Firewall Behavior

When applying rules, the script performs the following operations:

    Checks whether the current PowerShell session has Administrator privileges.
    Imports any requested configuration file.
    Validates the requested port numbers.
    Warns if TCP port 22 or 2222 is not included.
    Requests and confirms a logging passphrase.
    Initializes a new encrypted log file.
    Removes existing firewall rules matching the FW-Port-* display-name pattern.
    Removes existing firewall rules belonging to the FWConfig group.
    Sets the default inbound firewall action to Block for Domain, Private, and Public profiles.
    Sets the default outbound firewall action to Allow for those profiles.
    Attempts to create an explicit inbound loopback rule for 127.0.0.1.
    Creates the requested inbound TCP and UDP allow rules.
    Writes an encrypted execution record.
    Displays a summary of the firewall rules.

Default firewall policy
Persistent rules

Firewall rules are created using Windows Firewall's persistent policy store through New-NetFirewallRule.

They are intended to survive system restarts.
Important Security Considerations
Management access

The script warns when neither TCP port 22 nor TCP port 2222 is included in the requested rules.

These ports are commonly associated with SSH access.

This warning does not guarantee remote administrative access.

For example:

    Windows Remote Desktop commonly uses TCP 3389.
    Windows Remote Management commonly uses TCP 5985 or TCP 5986.
    SSH commonly uses TCP 22.

If you administer the machine remotely, explicitly include the ports and protocols required by your management services before applying firewall changes.

The script does not automatically preserve every existing management rule.

Applying an incorrect firewall configuration can interrupt remote access or lock you out of the machine.

Whenever possible, test locally or maintain an alternative recovery method.
Existing firewall rules

The script removes existing rules matching FW-Port-* and rules belonging to the FWConfig group.

This means it can remove previously configured rules that use those names or groups.

Review existing firewall configurations before running the script.
Administrator privileges

Administrator privileges are required to modify Windows Firewall profiles and create firewall rules.

The script checks for an elevated session before attempting to apply changes.
Passphrase security

The passphrase is requested through PowerShell's secure input prompt.

However, the implementation temporarily converts the SecureString into a regular .NET string for cryptographic operations.

The resulting plaintext string is not explicitly zeroed from memory.

Use a strong, unique passphrase and protect access to the system and log files.
Encrypted Logging

The script implements password-based encryption for its log file.

The cryptographic construction uses:
Component   Algorithm / Value
Encryption  AES-256-CBC
Authentication  HMAC-SHA256
Key derivation  PBKDF2-HMAC-SHA256
PBKDF2 iterations   100,000
Salt size   16 bytes
AES key size    32 bytes
Initialization vector   16 bytes
HMAC size   32 bytes
Padding PKCS7
Plaintext encoding  UTF-8
Encryption process

    A cryptographically secure random 16-byte salt is generated.
    PBKDF2-HMAC-SHA256 derives a 32-byte key from the passphrase and salt.
    AES-256-CBC encrypts each log entry using a newly generated initialization vector.
    HMAC-SHA256 authenticates the initialization vector, ciphertext length, and ciphertext.
    The encrypted record is appended to the log file.

The implementation uses an encrypt-then-MAC construction.
Log file structure

The file begins with a 16-byte salt.

Each subsequent encrypted record contains:

#>

#Requires -Version 5.1
<#
.SYNOPSIS
    Simple host firewall configurator (Windows Firewall) with encrypted log.
    Exact functional port of the prior C++ version.
    For use only on systems you own or are authorized to manage.
#>
$ErrorActionPreference = 'Stop'
# Constants matching the C++ version
$Script:MAX_PORTS = 256
$Script:SALT_SIZE = 16
$Script:KEY_SIZE = 32
$Script:IV_SIZE = 16
$Script:HMAC_SIZE = 32
$Script:MAX_PLAIN = 2048
$Script:PBKDF2_ITERS = 100000
$Script:DEFAULT_LOG = "firewall.log.enc"
$Script:RULE_GROUP = "FWConfig"
function Write-Color {
    param([string]$Text,[ConsoleColor]$Color = 'White',[switch]$NoNewLine)
    if ($NoNewLine) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}
function Show-Help {
    param([string]$Prog)
    Write-Host ""
    Write-Color "╔══════════════════════════════════════════════════════════════╗" Cyan
    Write-Color "║           Windows Firewall Configurator (fwconfig)           ║" Cyan
    Write-Color "╚══════════════════════════════════════════════════════════════╝" Cyan
    Write-Host ""
    Write-Color "DESCRIPTION" Yellow
    Write-Host "  Simple host firewall configurator with AES-256 encrypted logging."
    Write-Host "  For use only on systems you own or are authorized to manage."
    Write-Host ""
    Write-Color "USAGE" Yellow
    Write-Host "  $Prog [options] [tcp_port ...]"
    Write-Host "  $Prog --decrypt [options]"
    Write-Host "  $Prog --help"
    Write-Host ""
    Write-Color "OPTIONS" Yellow
    Write-Host "  -c, --config FILE    Load ports from config file (tcp:22 / udp:53)"
    Write-Host "  -l, --log FILE       Encrypted log file (default: $DEFAULT_LOG)"
    Write-Host "  -d, --decrypt        Decrypt and print the log (prompts for passphrase)"
    Write-Host "  -h, --help           Show this help"
    Write-Host ""
    Write-Color "EXAMPLES" Yellow
    Write-Host "  $Prog 22 80 443"
    Write-Host "  $Prog -c ports.conf"
    Write-Host "  $Prog -l C:\logs\fw.enc 22"
    Write-Host "  $Prog --decrypt"
    Write-Host "  $Prog --decrypt -l mylog.enc"
    Write-Host ""
    Write-Color "CONFIG FILE FORMAT" Yellow
    Write-Host "  One rule per line. Comments start with #."
    Write-Host "    tcp:22"
    Write-Host "    udp:53"
    Write-Host "    tcp:443"
    Write-Host ""
    Write-Color "NOTES" Yellow
    Write-Host "  • Must run as Administrator to apply rules."
    Write-Host "  • Default inbound policy is set to Block."
    Write-Host "  • Always include a management port (TCP 22/2222) or you may lock yourself out."
    Write-Host "  • Rules are persistent (PersistentStore) and survive reboot."
    Write-Host "  • Log: AES-256-CBC + encrypt-then-HMAC-SHA256 (PBKDF2-SHA256, 100k iterations)."
    Write-Host "  • Wrong passphrase or tampering fails cleanly with no partial output."
    Write-Host ""
    Write-Color "INTERACTIVE MODE" Yellow
    Write-Host "  Run with no arguments to enter the interactive menu."
    Write-Host ""
}
function Test-IsValidPort {
    param([int]$Port)
    return ($Port -ge 0 -and $Port -le 65535)
}
function Get-Passphrase {
    param([bool]$Confirm = $false)
    $pass = Read-Host -Prompt "Enter passphrase" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ([string]::IsNullOrEmpty($plain)) {
        Write-Color "Passphrase cannot be empty." Red
        return $null
    }
    if ($Confirm) {
        $pass2 = Read-Host -Prompt "Confirm passphrase" -AsSecureString
        $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2)
        try {
            $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
        }
        if ($plain -ne $plain2) {
            Write-Color "Passphrases do not match." Red
            return $null
        }
    }
    return $plain
}
# Crypto helpers (PBKDF2-HMAC-SHA256, AES-256-CBC, HMAC-SHA256 encrypt-then-MAC)
function Get-DerivedKey {
    param([string]$Passphrase,[byte[]]$Salt)
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Passphrase,$Salt,$PBKDF2_ITERS,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        return $pbkdf2.GetBytes($KEY_SIZE)
    } finally {
        $pbkdf2.Dispose()
    }
}
function Get-HmacSha256 {
    param([byte[]]$Key,[byte[]]$Data)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new()
    try {
        $hmac.Key = $Key
        return $hmac.ComputeHash($Data)
    } finally {
        $hmac.Dispose()
    }
}
function Add-EncryptedLogEntry {
    param([string]$LogPath,[string]$Plaintext,[byte[]]$Key)
    if ([string]::IsNullOrEmpty($Plaintext) -or $Plaintext.Length -ge $MAX_PLAIN) {
        return $false
    }
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key = $Key
        $aes.GenerateIV()
        $iv = $aes.IV
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
        $encryptor = $aes.CreateEncryptor()
        try {
            $cipherBytes = $encryptor.TransformFinalBlock($plainBytes,0,$plainBytes.Length)
        } finally {
            $encryptor.Dispose()
        }
        $clen = [uint32]$cipherBytes.Length
        $clenBytes = [BitConverter]::GetBytes($clen)
        $macInput = New-Object byte[] ($iv.Length + $clenBytes.Length + $cipherBytes.Length)
        [Buffer]::BlockCopy($iv,0,$macInput,0,$iv.Length)
        [Buffer]::BlockCopy($clenBytes,0,$macInput,$iv.Length,$clenBytes.Length)
        [Buffer]::BlockCopy($cipherBytes,0,$macInput,$iv.Length + $clenBytes.Length,$cipherBytes.Length)
        $hmac = Get-HmacSha256 -Key $Key -Data $macInput
        $fs = [System.IO.File]::Open($LogPath,[System.IO.FileMode]::Append,[System.IO.FileAccess]::Write)
        try {
            $fs.Write($iv,0,$IV_SIZE)
            $fs.Write($hmac,0,$HMAC_SIZE)
            $fs.Write($clenBytes,0,4)
            $fs.Write($cipherBytes,0,$cipherBytes.Length)
        } finally {
            $fs.Dispose()
        }
        return $true
    } finally {
        $aes.Dispose()
    }
}
function Write-LogMessage {
    param([string]$LogPath,[string]$Message,[byte[]]$Key)
    $timestr = (Get-Date).ToString("ddd MMM dd HH:mm:ss yyyy")
    $line = "[$timestr] $Message"
    Add-EncryptedLogEntry -LogPath $LogPath -Plaintext $line -Key $Key | Out-Null
}
function Initialize-EncryptedLog {
    param([string]$LogPath,[string]$Passphrase)
    $salt = New-Object byte[] $SALT_SIZE
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($salt)
    } finally {
        $rng.Dispose()
    }
    $key = Get-DerivedKey -Passphrase $Passphrase -Salt $salt
    $fs = [System.IO.File]::Open($LogPath,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write)
    try {
        $fs.Write($salt,0,$SALT_SIZE)
    } finally {
        $fs.Dispose()
    }
    return $key
}
function Invoke-DecryptLog {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) {
        Write-Color "Cannot open $LogPath" Red
        return 1
    }
    $fs = [System.IO.File]::Open($LogPath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read)
    try {
        $salt = New-Object byte[] $SALT_SIZE
        $read = $fs.Read($salt,0,$SALT_SIZE)
        if ($read -ne $SALT_SIZE) {
            Write-Color "Log file too short or missing salt." Red
            return 1
        }
        $pass = Get-Passphrase -Confirm $false
        if (-not $pass) {
            return 1
        }
        $key = Get-DerivedKey -Passphrase $pass -Salt $salt
        Write-Color "--- Decrypted log ($LogPath) ---" Cyan
        $records = 0
        $errors = 0
        while ($fs.Position -lt $fs.Length) {
            $iv = New-Object byte[] $IV_SIZE
            $storedHmac = New-Object byte[] $HMAC_SIZE
            $clenBytes = New-Object byte[] 4
            $n = $fs.Read($iv,0,$IV_SIZE)
            if ($n -eq 0) {
                break
            }
            if ($n -ne $IV_SIZE) {
                Write-Color "Truncated record (IV)." Red
                $errors++
                break
            }
            if ($fs.Read($storedHmac,0,$HMAC_SIZE) -ne $HMAC_SIZE -or
                $fs.Read($clenBytes,0,4) -ne 4) {
                Write-Color "Truncated record header." Red
                $errors++
                break
            }
            $clen = [BitConverter]::ToUInt32($clenBytes,0)
            if ($clen -eq 0 -or $clen -gt ($MAX_PLAIN + 32)) {
                Write-Color "Invalid ciphertext length: $clen" Red
                $errors++
                break
            }
            $ciphertext = New-Object byte[] $clen
            if ($fs.Read($ciphertext,0,$clen) -ne $clen) {
                Write-Color "Truncated ciphertext." Red
                $errors++
                break
            }
            $macInput = New-Object byte[] ($iv.Length + $clenBytes.Length + $ciphertext.Length)
            [Buffer]::BlockCopy($iv,0,$macInput,0,$iv.Length)
            [Buffer]::BlockCopy($clenBytes,0,$macInput,$iv.Length,$clenBytes.Length)
            [Buffer]::BlockCopy($ciphertext,0,$macInput,$iv.Length + $clenBytes.Length,$ciphertext.Length)
            $computed = Get-HmacSha256 -Key $key -Data $macInput
            $hmacMatch = [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($computed,$storedHmac)
            if (-not $hmacMatch) {
                Write-Color "Integrity check failed (wrong passphrase or tampered data)." Red
                $errors++
                break
            }
            $aes = [System.Security.Cryptography.Aes]::Create()
            try {
                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $aes.Key = $key
                $aes.IV = $iv
                $decryptor = $aes.CreateDecryptor()
                try {
                    $plainBytes = $decryptor.TransformFinalBlock($ciphertext,0,$ciphertext.Length)
                    $plaintext = [System.Text.Encoding]::UTF8.GetString($plainBytes)
                    Write-Host $plaintext
                    $records++
                } catch {
                    Write-Color "Decryption failed (corruption)." Red
                    $errors++
                    break
                } finally {
                    $decryptor.Dispose()
                }
            } finally {
                $aes.Dispose()
            }
        }
    } finally {
        $fs.Dispose()
    }
    Write-Color "--- $records record(s)" -NoNewline Cyan
    if ($errors -gt 0) {
        Write-Color ", $errors error(s)" -NoNewline Red
    }
    Write-Host " ---" -ForegroundColor Cyan
    return $(if ($errors) { 1 } else { 0 })
}
function Import-PortConfig {
    param([string]$Filename)
    if (-not (Test-Path $Filename)) {
        Write-Color "Cannot open $Filename" Red
        return $null
    }
    $rules = [System.Collections.Generic.List[object]]::new()
    Get-Content $Filename | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            if ($line -match '^([a-zA-Z]+):(\d+)$') {
                $proto = $Matches[1].ToLower()
                $port = [int]$Matches[2]
                if (Test-IsValidPort $port) {
                    $rules.Add([PSCustomObject]@{
                        Port = $port
                        IsUdp = ($proto -eq "udp")
                    })
                } else {
                    Write-Color "Skipping invalid config line: $_" Yellow
                }
            } else {
                Write-Color "Skipping invalid config line: $_" Yellow
            }
        }
    }
    return ,$rules.ToArray()
}
function Show-InteractiveMenu {
    while ($true) {
        Write-Host ""
        Write-Color "╔════════════════════════════════════════╗" Cyan
        Write-Color "║          Firewall Configurator         ║" Cyan
        Write-Color "╚════════════════════════════════════════╝" Cyan
        Write-Host ""
        Write-Color "  1) Apply firewall rules (interactive)" Green
        Write-Color "  2) Decrypt encrypted log" Green
        Write-Color "  3) Show detailed help" Yellow
        Write-Color "  4) Exit" Red
        Write-Host ""
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" {
                Write-Host ""
                $portInput = Read-Host "Enter TCP ports (space-separated, e.g. 22 80 443) or press Enter to use config file"
                $configPath = $null
                if ([string]::IsNullOrWhiteSpace($portInput)) {
                    $configPath = Read-Host "Config file path"
                }
                $logPath = Read-Host "Log file path (Enter for default: $DEFAULT_LOG)"
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $DEFAULT_LOG
                }
                # Rebuild args for existing logic
                $script:args = @()
                if ($configPath) {
                    $script:args += @("-c",$configPath)
                }
                if ($logPath -ne $DEFAULT_LOG) {
                    $script:args += @("-l",$logPath)
                }
                if ($portInput) {
                    $script:args += $portInput.Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
                }
                return "apply"
            }
            "2" {
                $logPath = Read-Host "Log file path (Enter for default: $DEFAULT_LOG)"
                if ([string]::IsNullOrWhiteSpace($logPath)) {
                    $logPath = $DEFAULT_LOG
                }
                $script:args = @("--decrypt","-l",$logPath)
                return "decrypt"
            }
            "3" {
                Show-Help $MyInvocation.MyCommand.Name
            }
            "4" {
                Write-Color "Goodbye." Cyan
                exit 0
            }
            default {
                Write-Color "Invalid selection. Try again." Yellow
            }
        }
    }
}
# Main
$doDecrypt = $false
$configFile = $null
$logFile = $DEFAULT_LOG
$rules = @()
$interactive = $false
if ($args.Count -eq 0) {
    $interactive = $true
    $action = Show-InteractiveMenu
    if ($action -eq "decrypt") {
        $doDecrypt = $true
    }
}
$i = 0
while ($i -lt $args.Count) {
    $arg = $args[$i]
    switch -Regex ($arg) {
        '^-h$|^--help$' {
            Show-Help $MyInvocation.MyCommand.Name
            exit 0
        }
        '^-d$|^--decrypt$' {
            $doDecrypt = $true
        }
        '^-c$|^--config$' {
            if ($i + 1 -ge $args.Count -or $args[$i+1] -match '^-') {
                Write-Color "Option $arg requires a file path." Red
                Show-Help $MyInvocation.MyCommand.Name
                exit 1
            }
            $configFile = $args[++$i]
        }
        '^-l$|^--log$' {
            if ($i + 1 -ge $args.Count -or $args[$i+1] -match '^-') {
                Write-Color "Option $arg requires a file path." Red
                Show-Help $MyInvocation.MyCommand.Name
                exit 1
            }
            $logFile = $args[++$i]
        }
        default {
            if ($arg -notmatch '^-') {
                $portNum = 0
                if ([int]::TryParse($arg,[ref]$portNum) -and (Test-IsValidPort $portNum)) {
                    if ($rules.Count -lt $MAX_PORTS) {
                        $rules += [PSCustomObject]@{
                            Port = $portNum
                            IsUdp = $false
                        }
                    }
                } else {
                    Write-Color "Unknown or invalid argument: $arg" Red
                    Show-Help $MyInvocation.MyCommand.Name
                    exit 1
                }
            } else {
                Write-Color "Unknown option: $arg" Red
                Show-Help $MyInvocation.MyCommand.Name
                exit 1
            }
        }
    }
    $i++
}
if ($doDecrypt) {
    exit (Invoke-DecryptLog -LogPath $logFile)
}
if ($args.Count -eq 0 -and -not $interactive) {
    Show-Help $MyInvocation.MyCommand.Name
    exit 0
}
# Require Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Color "Must be run as Administrator to apply firewall rules." Red
    exit 1
}
if ($configFile) {
    $loaded = Import-PortConfig -Filename $configFile
    if ($null -eq $loaded) {
        exit 1
    }
    $rules += $loaded
}
if ($rules.Count -eq 0) {
    Write-Color "No valid ports specified." Red
    Show-Help $MyInvocation.MyCommand.Name
    exit 1
}
# Management port warning
$hasMgmt = $false
foreach ($r in $rules) {
    if (-not $r.IsUdp -and ($r.Port -eq 22 -or $r.Port -eq 2222)) {
        $hasMgmt = $true
        break
    }
}
if (-not $hasMgmt) {
    Write-Color "WARNING: no common management port (TCP 22/2222) in the rule set." Yellow
    Write-Color "         You may lock yourself out of remote access." Yellow
}
$pass = Get-Passphrase -Confirm $true
if (-not $pass) {
    exit 1
}
$key = Initialize-EncryptedLog -LogPath $logFile -Passphrase $pass
if (-not $key) {
    Write-Color "Failed to initialize encrypted log." Red
    exit 1
}
Write-Color "Applying firewall rules..." Cyan
$fwOk = $true
$created = 0
try {
    Get-NetFirewallRule -DisplayName "FW-Port-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Group $RULE_GROUP -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    $loopbackName = "FW-Loopback"
    if (-not (Get-NetFirewallRule -DisplayName $loopbackName -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName $loopbackName -Group $RULE_GROUP `
                -Direction Inbound -LocalAddress 127.0.0.1 -Action Allow `
                -ErrorAction Stop | Out-Null
        } catch {
            Write-Color "Could not create explicit loopback rule (usually unnecessary): $_" Yellow
        }
    }
    foreach ($r in $rules) {
        $proto = if ($r.IsUdp) { "UDP" } else { "TCP" }
        $name = "FW-Port-$proto-$($r.Port)"
        try {
            New-NetFirewallRule -DisplayName $name -Group $RULE_GROUP `
                -Direction Inbound -Protocol $proto -LocalPort $r.Port -Action Allow `
                -ErrorAction Stop | Out-Null
            Write-Color "Allowed $proto/$($r.Port)" Green
            $created++
        } catch {
            Write-Color "Failed to create rule for $proto/$($r.Port): $_" Red
            $fwOk = $false
        }
    }
} catch {
    Write-Color "Windows Firewall command failed: $_" Red
    $fwOk = $false
}
if (-not $fwOk) {
    Write-Color "One or more Windows Firewall operations failed." Red
}
Write-LogMessage -LogPath $logFile -Message "Firewall started and rules applied ($created rule(s))" -Key $key
Write-Host ""
Write-Color "Rules applied. Encrypted log: $logFile" Green
Write-Color "Decrypt with: $($MyInvocation.MyCommand.Name) --decrypt -l $logFile" Cyan
if ($fwOk -and $created -gt 0) {
    Get-NetFirewallRule -DisplayName "FW-Port-*" -ErrorAction SilentlyContinue |
        Format-Table DisplayName,Enabled,Direction,Action,Protocol,LocalPort -AutoSize
}
exit $(if ($fwOk) { 0 } else { 1 });
