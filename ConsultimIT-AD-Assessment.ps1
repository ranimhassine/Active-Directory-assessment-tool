#Requires -Version 5.1
<#
.SYNOPSIS
    Consultim-IT Active Directory Security Assessment Tool
.DESCRIPTION
    Comprehensive Active Directory security assessment tool that generates
    a detailed HTML report with statistics, findings, and recommendations.
    Branded for Consultim-IT.
.AUTHOR
    Ranim Hassine - Consultim-IT
.VERSION
    1.0.0
.NOTES
    Requires: ActiveDirectory PowerShell Module (RSAT)
    Run as: Domain Administrator or equivalent
    Compatible with PowerShell 5.1+
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordPolicy,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPrivilegeEscalation,

    [Parameter(Mandatory=$false)]
    [switch]$SkipLateralMovement,

    [Parameter(Mandatory=$false)]
    [switch]$SkipKerberos,

    [Parameter(Mandatory=$false)]
    [switch]$SkipGPO,

    [Parameter(Mandatory=$false)]
    [switch]$SkipDelegation,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ConsultimIT-Reports",

    [Parameter(Mandatory=$false)]
    [string]$ReportTitle = "Active Directory Security Assessment"
)

# Helper: join collection property into comma-separated string (PS 5.1 compatible)
function Get-JoinedNames {
    param([object[]]$Collection, [string]$Property = "SamAccountName")
    if (-not $Collection) { return "" }
    return ($Collection | ForEach-Object { $_.$Property }) -join ', '
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  =====================================================================  " -ForegroundColor Cyan
Write-Host "   CONSULTIM-IT  |  Active Directory Security Assessment Tool v1.0       " -ForegroundColor Cyan
Write-Host "   Author: Ranim Hassine                                                  " -ForegroundColor Cyan
Write-Host "  =====================================================================  " -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# PREREQUISITES CHECK
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[!] ERROR: ActiveDirectory module not found." -ForegroundColor Red
    Write-Host "    Install RSAT: Install-WindowsFeature -Name RSAT-AD-PowerShell" -ForegroundColor Yellow
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "[+] ActiveDirectory module loaded." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$StartTime = Get-Date
$Timestamp = $StartTime.ToString("yyyy-MM-dd_HH-mm-ss")

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN CONTEXT
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[*] Connecting to domain..." -ForegroundColor Yellow

try {
    if ($Domain) {
        $DomainObj = Get-ADDomain -Identity $Domain -ErrorAction Stop
    }
    else {
        $DomainObj = Get-ADDomain -ErrorAction Stop
        $Domain    = $DomainObj.DNSRoot
    }
    $ForestObj = Get-ADForest -ErrorAction Stop
    $DomainDN  = $DomainObj.DistinguishedName
    Write-Host "[+] Connected to domain: $Domain" -ForegroundColor Green
}
catch {
    Write-Host "[!] ERROR connecting to domain: $_" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# FINDINGS COLLECTOR
# ─────────────────────────────────────────────────────────────────────────────
$Findings = New-Object System.Collections.ArrayList
$Stats    = @{}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Title,
        [string]$Description,
        [string]$Impact,
        [string]$Remediation,
        [string]$Details = ""
    )
    [void]$script:Findings.Add(@{
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Impact      = $Impact
        Remediation = $Remediation
        Details     = $Details
    })
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 - DOMAIN STATISTICS
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[*] Collecting domain statistics..." -ForegroundColor Yellow

$AllUsers          = Get-ADUser -Filter * -Properties * -Server $Domain
$EnabledUsers      = $AllUsers | Where-Object { $_.Enabled -eq $true }
$DisabledUsers     = $AllUsers | Where-Object { $_.Enabled -eq $false }
$NeverLogonUsers   = $AllUsers | Where-Object { $_.LastLogonDate -eq $null -and $_.Enabled -eq $true }
$StaleUsers        = $AllUsers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) -and $_.Enabled -eq $true -and $_.LastLogonDate -ne $null }
$PwdNeverExpires   = $AllUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
$PwdNotRequired    = $AllUsers | Where-Object { $_.PasswordNotRequired -eq $true -and $_.Enabled -eq $true }
$ReversiblePwd     = $AllUsers | Where-Object { $_.AllowReversiblePasswordEncryption -eq $true }

$AllComputers      = Get-ADComputer -Filter * -Properties * -Server $Domain
$DomainControllers = Get-ADDomainController -Filter * -Server $Domain
$AllGroups         = Get-ADGroup -Filter * -Properties * -Server $Domain
$PrivGroups        = $AllGroups | Where-Object {
    $_.Name -in @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                  "Account Operators","Backup Operators","Print Operators","Server Operators")
}

$AllGPOs   = Get-GPO -All -Domain $Domain -ErrorAction SilentlyContinue
$GPOCount  = if ($AllGPOs) { @($AllGPOs).Count } else { 0 }

$DomainAdmins      = Get-ADGroupMember -Identity "Domain Admins" -Recursive -Server $Domain -ErrorAction SilentlyContinue
$EnterpriseAdmins  = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -Server $Domain -ErrorAction SilentlyContinue

$Stats["TotalUsers"]        = @($AllUsers).Count
$Stats["EnabledUsers"]      = @($EnabledUsers).Count
$Stats["DisabledUsers"]     = @($DisabledUsers).Count
$Stats["NeverLogon"]        = @($NeverLogonUsers).Count
$Stats["StaleUsers"]        = @($StaleUsers).Count
$Stats["PwdNeverExpires"]   = @($PwdNeverExpires).Count
$Stats["PwdNotRequired"]    = @($PwdNotRequired).Count
$Stats["TotalComputers"]    = @($AllComputers).Count
$Stats["DomainControllers"] = @($DomainControllers).Count
$Stats["TotalGroups"]       = @($AllGroups).Count
$Stats["TotalGPOs"]         = $GPOCount
$Stats["DomainAdmins"]      = if ($DomainAdmins) { @($DomainAdmins).Count } else { 0 }
$Stats["EnterpriseAdmins"]  = if ($EnterpriseAdmins) { @($EnterpriseAdmins).Count } else { 0 }
$Stats["ForestFunctional"]  = $ForestObj.ForestMode.ToString()
$Stats["DomainFunctional"]  = $DomainObj.DomainMode.ToString()

Write-Host "[+] Domain statistics collected." -ForegroundColor Green

# ─── Extended dashboard metrics ───────────────────────────────────────────────

# User health breakdown (for flow chart)
$HealthyUsers      = $AllUsers | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogonDate -ge (Get-Date).AddDays(-90) -and
    $_.PasswordNeverExpires -eq $false -and
    $_.PasswordNotRequired -eq $false
}
$AtRiskUsers       = $AllUsers | Where-Object {
    $_.Enabled -eq $true -and (
        $_.PasswordNeverExpires -eq $true -or
        $_.DoesNotRequirePreAuth -eq $true -or
        ($_.ServicePrincipalNames -and $_.ServicePrincipalNames.Count -gt 0)
    )
}
$InactiveUsers     = $AllUsers | Where-Object {
    $_.Enabled -eq $true -and (
        $_.LastLogonDate -eq $null -or
        $_.LastLogonDate -lt (Get-Date).AddDays(-90)
    )
}

$Stats["HealthyUsers"]     = @($HealthyUsers).Count
$Stats["AtRiskUsers"]      = @($AtRiskUsers).Count
$Stats["InactiveUsers"]    = @($InactiveUsers).Count

# Computer OS breakdown
$WorkstationsWin10  = @($AllComputers | Where-Object { $_.OperatingSystem -like "*Windows 10*" }).Count
$WorkstationsWin11  = @($AllComputers | Where-Object { $_.OperatingSystem -like "*Windows 11*" }).Count
$Servers2016Plus    = @($AllComputers | Where-Object { $_.OperatingSystem -like "*Server 2016*" -or $_.OperatingSystem -like "*Server 2019*" -or $_.OperatingSystem -like "*Server 2022*" }).Count
$LegacyOS           = @($AllComputers | Where-Object { $_.OperatingSystem -like "*XP*" -or $_.OperatingSystem -like "*Vista*" -or $_.OperatingSystem -like "*2003*" -or $_.OperatingSystem -like "*2008*" -or $_.OperatingSystem -like "*Windows 7*" -or $_.OperatingSystem -like "*Windows 8*" }).Count
$OtherOS            = @($AllComputers).Count - $WorkstationsWin10 - $WorkstationsWin11 - $Servers2016Plus - $LegacyOS
if ($OtherOS -lt 0) { $OtherOS = 0 }

$Stats["Win10"]      = $WorkstationsWin10
$Stats["Win11"]      = $WorkstationsWin11
$Stats["Server2016"] = $Servers2016Plus
$Stats["LegacyOS"]   = $LegacyOS
$Stats["OtherOS"]    = $OtherOS

# Stale computers
$StaleComputers = @($AllComputers | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogonDate -ne $null -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-90)
}).Count
$Stats["StaleComputers"] = $StaleComputers

# Password policy score sub-metrics
$PwdPolicyScore = 100
try {
    $pp = Get-ADDefaultDomainPasswordPolicy -Server $Domain
    if ($pp.MinPasswordLength -lt 14)        { $PwdPolicyScore -= 20 }
    if ($pp.LockoutThreshold -eq 0)          { $PwdPolicyScore -= 25 }
    if ($pp.PasswordHistoryCount -lt 10)     { $PwdPolicyScore -= 15 }
    if (-not $pp.ComplexityEnabled)          { $PwdPolicyScore -= 20 }
    if ($pp.MaxPasswordAge.Days -eq 0)       { $PwdPolicyScore -= 10 }
    if ($pp.MaxPasswordAge.Days -gt 365)     { $PwdPolicyScore -= 5  }
} catch {}
if ($PwdPolicyScore -lt 0) { $PwdPolicyScore = 0 }

# Privilege score
$PrivScore = 100
if ($CriticalCount -gt 0) { $PrivScore -= ($CriticalCount * 15) }
if ($HighCount -gt 0)     { $PrivScore -= ($HighCount * 7)      }
if ($PrivScore -lt 0) { $PrivScore = 0 }

# Account hygiene score
$HygieneScore = 100
$TotalEnabled = $Stats["EnabledUsers"]
if ($TotalEnabled -gt 0) {
    $staleRatio   = [math]::Round(($Stats["StaleUsers"]      / $TotalEnabled) * 100)
    $pneRatio     = [math]::Round(($Stats["PwdNeverExpires"] / $TotalEnabled) * 100)
    $pnrRatio     = [math]::Round(($Stats["PwdNotRequired"]  / $TotalEnabled) * 100)
    $neverRatio   = [math]::Round(($Stats["NeverLogon"]      / $TotalEnabled) * 100)
    $HygieneScore -= [math]::Min(30, $staleRatio)
    $HygieneScore -= [math]::Min(25, $pneRatio * 2)
    $HygieneScore -= [math]::Min(30, $pnrRatio * 5)
    $HygieneScore -= [math]::Min(15, $neverRatio)
}
if ($HygieneScore -lt 0) { $HygieneScore = 0 }

# Overall Secure Score (weighted average)
$SecureScore = [math]::Round(($PwdPolicyScore * 0.30) + ($PrivScore * 0.40) + ($HygieneScore * 0.30))
if ($SecureScore -lt 0)   { $SecureScore = 0   }
if ($SecureScore -gt 100) { $SecureScore = 100 }

$SecureScoreGrade = if     ($SecureScore -ge 80) { "A" }
                    elseif ($SecureScore -ge 65) { "B" }
                    elseif ($SecureScore -ge 50) { "C" }
                    elseif ($SecureScore -ge 35) { "D" }
                    else                         { "F" }

$SecureScoreColor = if     ($SecureScore -ge 80) { "#27ae60" }
                    elseif ($SecureScore -ge 65) { "#f39c12" }
                    elseif ($SecureScore -ge 50) { "#e67e22" }
                    else                         { "#c0392b" }

# Findings per category (for bar chart)
$FindingsByCategory = @{}
foreach ($f in $Findings) {
    if (-not $FindingsByCategory.ContainsKey($f.Category)) { $FindingsByCategory[$f.Category] = 0 }
    $FindingsByCategory[$f.Category]++
}

# Build JS data arrays for charts
$catLabels  = ($FindingsByCategory.Keys  | ForEach-Object { "'$_'" })  -join ','
$catValues  = ($FindingsByCategory.Keys  | ForEach-Object { $FindingsByCategory[$_] }) -join ','

# User health percentages for donut
$UH_Total   = $Stats["TotalUsers"]
if ($UH_Total -eq 0) { $UH_Total = 1 }
$UH_Healthy  = [math]::Round(($Stats["HealthyUsers"] / $UH_Total) * 100)
$UH_AtRisk   = [math]::Round(($Stats["AtRiskUsers"]  / $UH_Total) * 100)
$UH_Inactive = [math]::Round(($Stats["InactiveUsers"]/ $UH_Total) * 100)
$UH_Disabled = [math]::Round(($Stats["DisabledUsers"]/ $UH_Total) * 100)

# Computer health percentages
$PC_Total = [math]::Max($Stats["TotalComputers"], 1)
$PC_Win11  = [math]::Round(($Stats["Win11"]      / $PC_Total) * 100)
$PC_Win10  = [math]::Round(($Stats["Win10"]      / $PC_Total) * 100)
$PC_Srv    = [math]::Round(($Stats["Server2016"] / $PC_Total) * 100)
$PC_Legacy = [math]::Round(($Stats["LegacyOS"]   / $PC_Total) * 100)
$PC_Other  = [math]::Max(0, 100 - $PC_Win11 - $PC_Win10 - $PC_Srv - $PC_Legacy)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 - PASSWORD POLICY
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipPasswordPolicy) {
    Write-Host "[*] Analyzing password policies..." -ForegroundColor Yellow

    $DefaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Domain

    if ($DefaultPwdPolicy.MinPasswordLength -lt 12) {
        Add-Finding -Category "Password Policy" -Severity "High" `
            -Title "Weak Minimum Password Length" `
            -Description "Domain minimum password length is set to $($DefaultPwdPolicy.MinPasswordLength) characters (recommended: 14+)." `
            -Impact "Short passwords are significantly more vulnerable to brute-force and dictionary attacks." `
            -Remediation "Increase minimum password length to at least 14 characters via Default Domain Policy." `
            -Details "Current: $($DefaultPwdPolicy.MinPasswordLength) chars | Recommended: 14+"
    }

    if ($DefaultPwdPolicy.LockoutThreshold -eq 0) {
        Add-Finding -Category "Password Policy" -Severity "High" `
            -Title "Account Lockout Policy Disabled" `
            -Description "Account lockout threshold is 0 - accounts are never locked after failed attempts." `
            -Impact "Allows unlimited brute-force password attempts against any account." `
            -Remediation "Set lockout threshold to 5-10 attempts; configure lockout duration of at least 15 minutes." `
            -Details "Threshold: 0 (disabled)"
    }

    if ($DefaultPwdPolicy.PasswordHistoryCount -lt 10) {
        Add-Finding -Category "Password Policy" -Severity "Medium" `
            -Title "Insufficient Password History" `
            -Description "Password history is set to $($DefaultPwdPolicy.PasswordHistoryCount). Users can reuse old passwords too quickly." `
            -Impact "Users can cycle through a small set of passwords, defeating the purpose of password rotation." `
            -Remediation "Set password history to at least 24 to prevent password reuse." `
            -Details "Current history count: $($DefaultPwdPolicy.PasswordHistoryCount)"
    }

    if ($DefaultPwdPolicy.MaxPasswordAge.Days -eq 0 -or $DefaultPwdPolicy.MaxPasswordAge.Days -gt 365) {
        Add-Finding -Category "Password Policy" -Severity "Medium" `
            -Title "Password Expiration Not Configured Properly" `
            -Description "Password maximum age is $($DefaultPwdPolicy.MaxPasswordAge.Days) days." `
            -Impact "Passwords that never expire give attackers unlimited time to crack harvested hashes." `
            -Remediation "Set password maximum age to 90-180 days, or adopt a breach-detection based rotation strategy." `
            -Details "Max age: $($DefaultPwdPolicy.MaxPasswordAge.Days) days"
    }

    if (@($PwdNeverExpires).Count -gt 0) {
        $pneNames = (($PwdNeverExpires | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Password Policy" -Severity "High" `
            -Title "Accounts with Password Never Expires" `
            -Description "Found $($Stats['PwdNeverExpires']) enabled user accounts with 'Password Never Expires' flag set." `
            -Impact "These accounts may have static, potentially compromised credentials. High-value targets for attackers." `
            -Remediation "Review each account. Remove the flag for standard users; enforce monitoring for service accounts." `
            -Details "Affected accounts: $pneNames"
    }

    if (@($PwdNotRequired).Count -gt 0) {
        $pnrNames = (($PwdNotRequired | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Password Policy" -Severity "Critical" `
            -Title "Accounts with Password Not Required" `
            -Description "Found $($Stats['PwdNotRequired']) accounts where password is not required (PASSWD_NOTREQD flag)." `
            -Impact "These accounts can log in without a password, bypassing authentication entirely." `
            -Remediation "Immediately remove the PASSWD_NOTREQD flag from all accounts and set strong passwords." `
            -Details "Accounts: $pnrNames"
    }

    if (@($ReversiblePwd).Count -gt 0) {
        $rpNames = (($ReversiblePwd | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Password Policy" -Severity "Critical" `
            -Title "Reversible Password Encryption Enabled" `
            -Description "Found $(@($ReversiblePwd).Count) accounts with 'Store password using reversible encryption' enabled." `
            -Impact "Reversibly encrypted passwords can be recovered in plaintext by an attacker with access to the directory." `
            -Remediation "Disable reversible encryption on all accounts. Reset passwords for affected accounts immediately." `
            -Details "Accounts: $rpNames"
    }

    Write-Host "[+] Password policy analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 - PRIVILEGE ESCALATION
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipPrivilegeEscalation) {
    Write-Host "[*] Analyzing privilege escalation paths..." -ForegroundColor Yellow

    # Kerberoastable accounts
    $Kerberoastable = $AllUsers | Where-Object {
        $_.ServicePrincipalNames.Count -gt 0 -and
        $_.Enabled -eq $true -and
        $_.SamAccountName -ne "krbtgt"
    }
    if (@($Kerberoastable).Count -gt 0) {
        $kNames = (($Kerberoastable | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "Kerberoastable Service Accounts" `
            -Description "Found $(@($Kerberoastable).Count) enabled user accounts with SPNs, making them targets for Kerberoasting attacks." `
            -Impact "Attackers can request Kerberos service tickets and crack them offline to recover plaintext passwords." `
            -Remediation "Use Group Managed Service Accounts (gMSA). Ensure SPN accounts have passwords of 25+ characters." `
            -Details "Accounts: $kNames"
    }

    # AS-REP Roastable accounts
    $ASREPRoastable = $AllUsers | Where-Object {
        $_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true
    }
    if (@($ASREPRoastable).Count -gt 0) {
        $arpNames = (($ASREPRoastable | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "AS-REP Roastable Accounts" `
            -Description "Found $(@($ASREPRoastable).Count) accounts with Kerberos pre-authentication disabled." `
            -Impact "Attackers can obtain encrypted AS-REP responses without authentication and crack them offline." `
            -Remediation "Enable Kerberos pre-authentication on all user accounts unless technically required otherwise." `
            -Details "Accounts: $arpNames"
    }

    # AdminCount orphans
    $AdminCountUsers = $AllUsers | Where-Object { $_.AdminCount -eq 1 -and $_.Enabled -eq $true }
    $ProtectedGroupMembers = @()
    foreach ($pg in $PrivGroups) {
        try {
            $members = Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue
            if ($members) { $ProtectedGroupMembers += $members.SamAccountName }
        }
        catch {}
    }
    $AdminCountOrphans = $AdminCountUsers | Where-Object { $_.SamAccountName -notin $ProtectedGroupMembers }
    if (@($AdminCountOrphans).Count -gt 0) {
        $acNames = (($AdminCountOrphans | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "AdminCount=1 Orphaned Accounts" `
            -Description "Found $(@($AdminCountOrphans).Count) accounts with AdminCount=1 not in any protected group (SDProp issue)." `
            -Impact "These accounts retain AdminSDHolder ACL inheritance but are no longer monitored, creating a hidden privilege escalation path." `
            -Remediation "Clear the AdminCount attribute and force SDProp to run. Audit ACLs on these accounts." `
            -Details "Accounts: $acNames"
    }

    # Service accounts in privileged groups
    $SvcInPriv = @()
    foreach ($pg in $PrivGroups) {
        try {
            $members = Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if ($m.objectClass -eq "user" -and $m.SamAccountName -match "svc|service|sa_|_svc|bot|scan|backup") {
                    $SvcInPriv += "$($m.SamAccountName) in $($pg.Name)"
                }
            }
        }
        catch {}
    }
    if ($SvcInPriv.Count -gt 0) {
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "Service Accounts in Privileged Groups" `
            -Description "Found $($SvcInPriv.Count) apparent service accounts that are members of privileged groups." `
            -Impact "Service accounts in privileged groups are high-value targets; compromise grants immediate elevated domain access." `
            -Remediation "Remove service accounts from privileged groups. Implement least-privilege with task-specific accounts or gMSA." `
            -Details ($SvcInPriv -join ' | ')
    }

    # Excessive Domain Admins
    if ($Stats["DomainAdmins"] -gt 10) {
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "Excessive Domain Administrator Accounts" `
            -Description "Domain Admins group contains $($Stats['DomainAdmins']) members. Best practice recommends fewer than 5." `
            -Impact "More admin accounts means a larger attack surface. Each account is a potential path to full domain compromise." `
            -Remediation "Review Domain Admins membership. Remove unnecessary members. Implement Just-In-Time (JIT) privileged access." `
            -Details "Domain Admins count: $($Stats['DomainAdmins'])"
    }

    # Unconstrained delegation - computers
    $UnconstrainedComputers = $AllComputers | Where-Object {
        $_.TrustedForDelegation -eq $true -and
        $_.Name -notin ($DomainControllers | ForEach-Object { $_.Name })
    }
    if (@($UnconstrainedComputers).Count -gt 0) {
        $ucNames = (($UnconstrainedComputers | ForEach-Object { $_.Name }) -join ', ')
        Add-Finding -Category "Privilege Escalation" -Severity "Critical" `
            -Title "Unconstrained Delegation on Non-DC Computers" `
            -Description "Found $(@($UnconstrainedComputers).Count) non-DC computer accounts with unconstrained Kerberos delegation enabled." `
            -Impact "An attacker who compromises these machines can impersonate any user, including Domain Admins, to any service." `
            -Remediation "Disable unconstrained delegation. Migrate to constrained or resource-based constrained delegation (RBCD)." `
            -Details "Computers: $ucNames"
    }

    # Unconstrained delegation - users
    $UnconstrainedUsers = $AllUsers | Where-Object {
        $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true
    }
    if (@($UnconstrainedUsers).Count -gt 0) {
        $uuNames = (($UnconstrainedUsers | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Privilege Escalation" -Severity "Critical" `
            -Title "Unconstrained Delegation on User Accounts" `
            -Description "Found $(@($UnconstrainedUsers).Count) user accounts trusted for unconstrained Kerberos delegation." `
            -Impact "These accounts can impersonate any domain user, effectively granting domain-level compromise capability." `
            -Remediation "Remove unconstrained delegation from user accounts immediately. Use constrained delegation or gMSA instead." `
            -Details "Accounts: $uuNames"
    }

    # Privileged accounts not marked sensitive
    $PrivNotSensitive = @()
    foreach ($pg in $PrivGroups | Where-Object { $_.Name -in @("Domain Admins","Enterprise Admins","Schema Admins") }) {
        try {
            $members = Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if ($m.objectClass -eq "user") {
                    $u = Get-ADUser -Identity $m.DistinguishedName -Properties AccountNotDelegated -Server $Domain -ErrorAction SilentlyContinue
                    if ($u -and $u.AccountNotDelegated -eq $false) {
                        $PrivNotSensitive += $u.SamAccountName
                    }
                }
            }
        }
        catch {}
    }
    $PrivNotSensitive = $PrivNotSensitive | Select-Object -Unique
    if ($PrivNotSensitive.Count -gt 0) {
        Add-Finding -Category "Privilege Escalation" -Severity "High" `
            -Title "Privileged Accounts Not Marked as Sensitive" `
            -Description "Found $($PrivNotSensitive.Count) privileged accounts not flagged as 'Account is sensitive and cannot be delegated'." `
            -Impact "Privileged credentials can be delegated through Kerberos, allowing impersonation attacks against high-value services." `
            -Remediation "Set the AccountNotDelegated flag on all privileged user accounts." `
            -Details "Accounts: $($PrivNotSensitive -join ', ')"
    }

    Write-Host "[+] Privilege escalation analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 - LATERAL MOVEMENT
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipLateralMovement) {
    Write-Host "[*] Analyzing lateral movement risks..." -ForegroundColor Yellow

    if ($Stats["StaleUsers"] -gt 0) {
        Add-Finding -Category "Lateral Movement" -Severity "Medium" `
            -Title "Stale Enabled User Accounts (90+ days inactive)" `
            -Description "Found $($Stats['StaleUsers']) enabled user accounts that have not logged on in 90+ days." `
            -Impact "Stale accounts are often overlooked and may have weak passwords, providing persistent footholds for attackers." `
            -Remediation "Disable or remove stale accounts. Implement an automated joiner-mover-leaver process." `
            -Details "Stale account count: $($Stats['StaleUsers'])"
    }

    if ($Stats["NeverLogon"] -gt 5) {
        Add-Finding -Category "Lateral Movement" -Severity "Low" `
            -Title "Accounts That Have Never Logged On" `
            -Description "Found $($Stats['NeverLogon']) enabled accounts that have never been used (no logon date)." `
            -Impact "Unused accounts may indicate orphaned provisioning or backdoor accounts expanding the attack surface." `
            -Remediation "Review and disable all unused accounts. Investigate accounts that should have logon history." `
            -Details "Count: $($Stats['NeverLogon'])"
    }

    # Print Spooler on DCs
    $SpoolerDCs = @()
    foreach ($dc in $DomainControllers) {
        try {
            $svc = Get-Service -ComputerName $dc.HostName -Name Spooler -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                $SpoolerDCs += $dc.HostName
            }
        }
        catch {}
    }
    if ($SpoolerDCs.Count -gt 0) {
        Add-Finding -Category "Lateral Movement" -Severity "Critical" `
            -Title "Print Spooler Running on Domain Controllers" `
            -Description "Found $($SpoolerDCs.Count) domain controller(s) with the Print Spooler service running." `
            -Impact "Enables PrintNightmare (CVE-2021-34527) and SpoolSample attacks - remote code execution on DCs with SYSTEM privileges." `
            -Remediation "Disable and stop the Print Spooler service on all Domain Controllers. Set startup type to Disabled." `
            -Details "Affected DCs: $($SpoolerDCs -join ', ')"
    }

    # Machine Account Quota
    $MAQ = (Get-ADObject -Identity $DomainDN -Properties "ms-DS-MachineAccountQuota" -Server $Domain)."ms-DS-MachineAccountQuota"
    if ($MAQ -gt 0) {
        Add-Finding -Category "Lateral Movement" -Severity "Medium" `
            -Title "Non-Zero Machine Account Quota" `
            -Description "ms-DS-MachineAccountQuota is set to $MAQ. Any authenticated domain user can join up to $MAQ computers to the domain." `
            -Impact "Allows attackers to create computer accounts for RBCD, Kerberoasting, and persistence attacks with only standard user credentials." `
            -Remediation "Set ms-DS-MachineAccountQuota to 0. Delegate computer join rights to specific accounts or OUs only." `
            -Details "Current MAQ: $MAQ"
    }

    # NTLM LmCompatibilityLevel on DCs
    foreach ($dc in $DomainControllers) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            if ($key) {
                $lmc = $key.GetValue("LmCompatibilityLevel")
                if ($lmc -ne $null -and $lmc -lt 3) {
                    Add-Finding -Category "Lateral Movement" -Severity "High" `
                        -Title "Weak NTLM Authentication Level on DC: $($dc.HostName)" `
                        -Description "LmCompatibilityLevel is set to $lmc on $($dc.HostName). Level 3+ is required to reject LM/NTLMv1." `
                        -Impact "Allows downgrade attacks to weaker authentication (NTLMv1/LM), crackable in seconds with modern hardware." `
                        -Remediation "Set LmCompatibilityLevel to 5 (NTLMv2 only) on all domain controllers via Group Policy." `
                        -Details "DC: $($dc.HostName) | Level: $lmc"
                }
            }
        }
        catch {}
    }

    Write-Host "[+] Lateral movement analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 - KERBEROS SECURITY
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipKerberos) {
    Write-Host "[*] Analyzing Kerberos configuration..." -ForegroundColor Yellow

    $KrbtgtAccount = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, PasswordNeverExpires, ServicePrincipalNames -Server $Domain
    $KrbtgtAge     = (Get-Date) - $KrbtgtAccount.PasswordLastSet

    if ($KrbtgtAge.Days -gt 180) {
        Add-Finding -Category "Kerberos Security" -Severity "High" `
            -Title "KRBTGT Password Not Rotated Recently" `
            -Description "KRBTGT account password was last changed $([int]$KrbtgtAge.Days) days ago (recommended: every 180 days max)." `
            -Impact "A stale KRBTGT password extends the validity window for Golden Ticket attacks." `
            -Remediation "Rotate KRBTGT password twice (with a replication delay) using the Microsoft KRBTGT rotation script." `
            -Details "Last set: $($KrbtgtAccount.PasswordLastSet) | Age: $([int]$KrbtgtAge.Days) days"
    }

    if ($KrbtgtAccount.ServicePrincipalNames.Count -gt 2) {
        $spnList = ($KrbtgtAccount.ServicePrincipalNames -join ', ')
        Add-Finding -Category "Kerberos Security" -Severity "Critical" `
            -Title "KRBTGT Account Has Extra SPNs (Kerberoastable)" `
            -Description "The KRBTGT account has $($KrbtgtAccount.ServicePrincipalNames.Count) SPNs assigned, making it potentially Kerberoastable." `
            -Impact "If KRBTGT is Kerberoasted and cracked, attackers can forge Golden Tickets for indefinite domain persistence." `
            -Remediation "Remove all non-default SPNs from the KRBTGT account immediately." `
            -Details "SPNs: $spnList"
    }

    $ProtocolTransition = $AllUsers | Where-Object {
        $_.TrustedToAuthForDelegation -eq $true -and $_.Enabled -eq $true
    }
    if (@($ProtocolTransition).Count -gt 0) {
        $ptNames = (($ProtocolTransition | ForEach-Object { $_.SamAccountName }) -join ', ')
        Add-Finding -Category "Kerberos Security" -Severity "High" `
            -Title "Accounts with Protocol Transition (S4U2Self) Delegation" `
            -Description "Found $(@($ProtocolTransition).Count) accounts trusted to authenticate for delegation (T2A4D flag), enabling S4U2Self abuse." `
            -Impact "These accounts can impersonate any user to services they are constrained to delegate to, without needing credentials." `
            -Remediation "Review all T2A4D accounts. Remove the flag unless technically required; prefer RBCD instead." `
            -Details "Accounts: $ptNames"
    }

    Write-Host "[+] Kerberos analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 - GPO ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipGPO) {
    Write-Host "[*] Analyzing Group Policy configuration..." -ForegroundColor Yellow

    try {
        $AllGPOs = Get-GPO -All -Domain $Domain -ErrorAction Stop

        $UnlinkedGPOs = @()
        foreach ($gpo in $AllGPOs) {
            $links = (Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue)
            if ($links -and $links -notmatch "<LinksTo>") {
                $UnlinkedGPOs += $gpo.DisplayName
            }
        }
        if ($UnlinkedGPOs.Count -gt 5) {
            Add-Finding -Category "GPO Configuration" -Severity "Low" `
                -Title "Excessive Unlinked Group Policy Objects" `
                -Description "Found $($UnlinkedGPOs.Count) GPOs that are not linked to any OU, domain, or site." `
                -Impact "Unlinked GPOs create management overhead and may contain sensitive configuration data." `
                -Remediation "Review and remove or archive all unlinked GPOs. Maintain a GPO lifecycle management process." `
                -Details "Unlinked GPO count: $($UnlinkedGPOs.Count)"
        }

        Add-Finding -Category "GPO Configuration" -Severity "Informational" `
            -Title "Group Policy Audit Recommendation" `
            -Description "Total of $GPOCount Group Policy Objects found in domain $Domain. Regular GPO audits are recommended." `
            -Impact "Unmanaged or conflicting GPOs can weaken security baselines and create unpredictable system behavior." `
            -Remediation "Perform quarterly GPO reviews. Use Microsoft Security Compliance Toolkit baselines." `
            -Details "Total GPOs: $GPOCount"
    }
    catch {
        Write-Host "[!] GPO analysis skipped (GroupPolicy module may not be available): $_" -ForegroundColor Yellow
    }

    Write-Host "[+] GPO analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 - ACL / DELEGATION AUDIT
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipDelegation) {
    Write-Host "[*] Analyzing ACL delegation..." -ForegroundColor Yellow

    $DCSyncAccounts = @()
    try {
        $DomainACL        = Get-ACL -Path "AD:\$DomainDN" -ErrorAction SilentlyContinue
        $ReplicateAllGuid = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        $ReplicateChgGuid = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

        if ($DomainACL) {
            foreach ($ace in $DomainACL.Access) {
                if ($ace.ObjectType -in @($ReplicateAllGuid, $ReplicateChgGuid) -and
                    $ace.ActiveDirectoryRights -match "ExtendedRight" -and
                    $ace.AccessControlType -eq "Allow") {
                    $identity = $ace.IdentityReference.ToString()
                    if ($identity -notmatch "Domain Controllers|Enterprise Domain Controllers|Administrators|SYSTEM") {
                        $DCSyncAccounts += $identity
                    }
                }
            }
        }
    }
    catch {}

    if ($DCSyncAccounts.Count -gt 0) {
        Add-Finding -Category "ACL Delegation" -Severity "Critical" `
            -Title "Excessive DCSync Permissions" `
            -Description "Found $($DCSyncAccounts.Count) non-standard accounts with DCSync (Replicating Directory Changes All) rights on the domain root." `
            -Impact "Accounts with DCSync rights can extract all domain password hashes including Domain Admins and KRBTGT, resulting in full domain compromise." `
            -Remediation "Remove DCSync rights from all non-DC/non-Azure AD Connect accounts. Audit monthly for re-addition." `
            -Details "Principals: $($DCSyncAccounts -join ' | ')"
    }

    Write-Host "[+] ACL delegation analysis complete." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# COMPUTE FINAL SCORE
# ─────────────────────────────────────────────────────────────────────────────
$EndTime       = Get-Date
$Duration      = $EndTime - $StartTime
$DurationStr   = "{0:D2}:{1:D2}:{2:D2}" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds

$CriticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
$HighCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
$MediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
$LowCount      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
$InfoCount     = @($Findings | Where-Object { $_.Severity -eq "Informational" }).Count
$TotalFindings = $Findings.Count

$RiskScore = [math]::Min(100, ($CriticalCount * 20) + ($HighCount * 8) + ($MediumCount * 3) + ($LowCount * 1))
$RiskLevel = if     ($RiskScore -ge 80) { "CRITICAL" }
             elseif ($RiskScore -ge 50) { "HIGH" }
             elseif ($RiskScore -ge 25) { "MEDIUM" }
             else                       { "LOW" }

# ─────────────────────────────────────────────────────────────────────────────
# BUILD RECOMMENDATIONS (driven by actual findings)
# ─────────────────────────────────────────────────────────────────────────────

# Each recommendation:
#   Phase    : Immediate / Short-Term / Medium-Term / Long-Term
#   Priority : P1 Critical / P2 High / P3 Medium / P4 Low
#   Title, What, How, Tools, Effort
#   TriggerTitles : list of finding titles that activate this rec

$RecommendationCatalog = @(

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Eliminate Password-Free and No-Password-Required Accounts"
        What     = "Accounts with no password or the PASSWD_NOTREQD flag set allow unauthenticated access and represent a direct compromise path."
        How      = "1. Run: Get-ADUser -Filter {PasswordNotRequired -eq `$true} -Properties * | Set-ADUser -PasswordNotRequired `$false`n2. Immediately set strong passwords on all affected accounts.`n3. Enable auditing to alert on future use of this flag."
        Tools    = "PowerShell AD module, GPO: Account Policies"
        Effort   = "1-2 hours"
        TriggerTitles = @("Accounts with Password Not Required")
    },

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Remove Unauthorized DCSync Rights"
        What     = "Non-DC accounts holding Replicating Directory Changes All rights can extract all domain password hashes, leading to instant full domain compromise."
        How      = "1. Run: (Get-ACL 'AD:\DC=domain,DC=local').Access | Where ObjectType -eq '1131f6ad...' to identify holders.`n2. Use ADSI Edit or PowerShell to remove the ACE from unauthorized principals.`n3. Monitor domain root ACL changes with audit policy."
        Tools    = "ADSI Edit, PowerShell, BloodHound (to verify)"
        Effort   = "2-4 hours"
        TriggerTitles = @("Excessive DCSync Permissions")
    },

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Disable Print Spooler on All Domain Controllers"
        What     = "Print Spooler on DCs enables PrintNightmare (CVE-2021-34527) and SpoolSample - both allow SYSTEM-level code execution and credential coercion."
        How      = "1. Run on each DC: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled`n2. Deploy via GPO: Computer > Windows Settings > System Services > Print Spooler = Disabled`n3. Verify: Get-Service -ComputerName <DC> -Name Spooler"
        Tools    = "PowerShell, Group Policy Management Console (GPMC)"
        Effort   = "30 minutes"
        TriggerTitles = @("Print Spooler Running on Domain Controllers")
    },

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Disable Unconstrained Kerberos Delegation"
        What     = "Machines or users with unconstrained delegation cache TGTs of all authenticating users. An attacker who owns these systems can impersonate any domain user including Domain Admins."
        How      = "1. Identify: Get-ADComputer -Filter {TrustedForDelegation -eq `$true}`n2. Disable: Set-ADComputer <name> -TrustedForDelegation `$false`n3. Replace with constrained delegation or Resource-Based Constrained Delegation (RBCD) as needed.`n4. Protect DCs - they legitimately use unconstrained delegation."
        Tools    = "PowerShell AD module, BloodHound"
        Effort   = "4-8 hours (testing required)"
        TriggerTitles = @("Unconstrained Delegation on Non-DC Computers","Unconstrained Delegation on User Accounts")
    },

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Remove Extra SPNs from KRBTGT Account"
        What     = "Unnecessary SPNs on KRBTGT make it susceptible to Kerberoasting. A cracked KRBTGT hash enables Golden Ticket attacks for permanent stealthy persistence."
        How      = "1. Check: Get-ADUser krbtgt -Properties ServicePrincipalNames`n2. Remove extra SPNs: Set-ADUser krbtgt -ServicePrincipalNames @{Remove='<SPN>'}`n3. Rotate KRBTGT password twice after remediation."
        Tools    = "PowerShell AD module"
        Effort   = "1 hour"
        TriggerTitles = @("KRBTGT Account Has Extra SPNs (Kerberoastable)")
    },

    @{
        Phase    = "Immediate"
        Priority = "P1"
        PriorityLabel = "Critical"
        PriorityColor = "#c0392b"
        Title    = "Disable Reversible Password Encryption"
        What     = "Reversibly encrypted passwords are stored in a format recoverable as plaintext by any attacker with directory access."
        How      = "1. Find affected accounts: Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true}`n2. Disable flag: Set-ADUser <user> -AllowReversiblePasswordEncryption `$false`n3. Force password reset for all affected accounts immediately."
        Tools    = "PowerShell AD module, ADUC"
        Effort   = "1-2 hours"
        TriggerTitles = @("Reversible Password Encryption Enabled")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Enforce Strong Domain Password Policy"
        What     = "A minimum password length below 12 characters significantly increases risk of successful brute-force and credential spray attacks."
        How      = "1. Open GPMC > Default Domain Policy > Computer Config > Windows Settings > Security Settings > Account Policies`n2. Set: Minimum password length = 14, Complexity = Enabled, History = 24, Max age = 90 days`n3. Consider Microsoft LAPS for local admin passwords.`n4. Use Fine-Grained Password Policies (PSO) for privileged accounts requiring stricter settings."
        Tools    = "GPMC, PowerShell: Set-ADDefaultDomainPasswordPolicy"
        Effort   = "2-4 hours"
        TriggerTitles = @("Weak Minimum Password Length","Insufficient Password History","Password Expiration Not Configured Properly")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Enable Account Lockout Policy"
        What     = "Without an account lockout threshold, attackers can attempt unlimited password guesses against any account, enabling password spray and brute-force attacks."
        How      = "1. Default Domain Policy > Account Lockout Policy:`n   - Threshold: 5-10 invalid attempts`n   - Duration: 15-30 minutes`n   - Reset counter: 15 minutes`n2. For privileged accounts, use Fine-Grained PSO with stricter lockout (3 attempts).`n3. Monitor: Event ID 4740 (account lockout)."
        Tools    = "GPMC, PowerShell: Set-ADDefaultDomainPasswordPolicy"
        Effort   = "1-2 hours"
        TriggerTitles = @("Account Lockout Policy Disabled")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Remediate Kerberoastable Service Accounts"
        What     = "User accounts with SPNs can have their Kerberos tickets requested and cracked offline. Service accounts often have weak, static passwords making this highly effective."
        How      = "1. Identify: Get-ADUser -Filter {ServicePrincipalNames -ne '*'} -Properties ServicePrincipalNames`n2. For each account: Migrate to Group Managed Service Accounts (gMSA) which rotate passwords automatically`n3. If gMSA not possible: Set passwords to 25+ random characters`n4. Monitor TGS requests for service accounts (Event ID 4769)."
        Tools    = "PowerShell AD module, Rubeus (for testing), Microsoft gMSA documentation"
        Effort   = "1-3 days (per service migration)"
        TriggerTitles = @("Kerberoastable Service Accounts")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Enable Kerberos Pre-Authentication on All Accounts"
        What     = "Accounts with pre-auth disabled allow anyone to request AS-REP hashes and crack them offline without needing valid credentials."
        How      = "1. Find: Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}`n2. Fix: Set-ADUser <user> -DoesNotRequirePreAuth `$false`n3. Only disable pre-auth when technically required (legacy Kerberos clients)."
        Tools    = "PowerShell AD module, ADUC"
        Effort   = "1-2 hours"
        TriggerTitles = @("AS-REP Roastable Accounts")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Reduce Domain Admins Membership and Implement JIT Access"
        What     = "An oversized Domain Admins group dramatically increases the attack surface. Every DA account is a potential path to full domain compromise."
        How      = "1. Audit DA membership: Get-ADGroupMember 'Domain Admins' -Recursive`n2. Remove all accounts that do not strictly require permanent DA rights`n3. Implement Just-In-Time access using Microsoft PAM (AD 2016+) or CyberArk/BeyondTrust`n4. Create dedicated admin accounts (tier-0) separate from daily-use accounts`n5. Alert on DA logon to non-DC systems (Event ID 4624 + DA membership)."
        Tools    = "PowerShell, Microsoft PAM, CyberArk, BeyondTrust"
        Effort   = "1-2 weeks"
        TriggerTitles = @("Excessive Domain Administrator Accounts")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Rotate KRBTGT Password"
        What     = "A KRBTGT password that has not been rotated in 180+ days means any Golden Ticket created from a previous breach remains valid."
        How      = "1. Download Microsoft's New-KrbtgtKeys.ps1 script`n2. Run rotation in audit mode first, then live`n3. Rotate TWICE: first rotation invalidates old tickets, second ensures full cleanup`n4. Wait 10+ hours between rotations to allow replication`n5. Schedule automated rotation every 180 days."
        Tools    = "Microsoft New-KrbtgtKeys.ps1 (GitHub)"
        Effort   = "2-4 hours (including replication wait)"
        TriggerTitles = @("KRBTGT Password Not Rotated Recently")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Mark Privileged Accounts as Sensitive and Remove Service Accounts from Admin Groups"
        What     = "Privileged accounts not marked sensitive can have credentials delegated through Kerberos. Service accounts in admin groups are frequently exploited for privilege escalation."
        How      = "1. Mark sensitive: Set-ADUser <DA_account> -AccountNotDelegated `$true`n2. Remove service accounts: Get-ADGroupMember 'Domain Admins' | where name -match 'svc' | remove..`n3. Create dedicated service account OUs with minimal permissions`n4. Use gMSA or LAPS where applicable."
        Tools    = "PowerShell AD module, ADUC"
        Effort   = "4-8 hours"
        TriggerTitles = @("Privileged Accounts Not Marked as Sensitive","Service Accounts in Privileged Groups","AdminCount=1 Orphaned Accounts")
    },

    @{
        Phase    = "Short-Term"
        Priority = "P2"
        PriorityLabel = "High"
        PriorityColor = "#e74c3c"
        Title    = "Enforce NTLMv2 and Disable Legacy Authentication"
        What     = "Low LmCompatibilityLevel allows NTLMv1 and LM authentication, which can be cracked in seconds with modern hardware and are vulnerable to relay attacks."
        How      = "1. Via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options`n   - Network security: LAN Manager authentication level = 'Send NTLMv2 response only. Refuse LM and NTLM'`n2. Also configure: Minimum session security for NTLM SSP (require NTLMv2 + 128-bit encryption)`n3. Test in audit mode first to identify legacy clients before enforcing."
        Tools    = "GPMC, Network Monitor (legacy client detection)"
        Effort   = "1 day (includes legacy client audit)"
        TriggerTitles = @("Weak NTLM Authentication Level on DC")
    },

    @{
        Phase    = "Medium-Term"
        Priority = "P3"
        PriorityLabel = "Medium"
        PriorityColor = "#e67e22"
        Title    = "Clean Up Stale and Unused Accounts"
        What     = "Stale and never-used accounts expand the attack surface, are frequently overlooked in access reviews, and are prime targets for credential stuffing."
        How      = "1. Export stale accounts: Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90) -and Enabled -eq `$true}`n2. Stage: Move to a 'Quarantine' OU, disable accounts (do not delete immediately)`n3. After 30-day hold with no complaints, delete`n4. Implement automated deprovisioning via ITSM/IDM integration`n5. Set up recurring quarterly access reviews."
        Tools    = "PowerShell, Microsoft Identity Manager, Entra ID Governance"
        Effort   = "1-2 days initial cleanup, ongoing process"
        TriggerTitles = @("Stale Enabled User Accounts (90+ days inactive)","Accounts That Have Never Logged On")
    },

    @{
        Phase    = "Medium-Term"
        Priority = "P3"
        PriorityLabel = "Medium"
        PriorityColor = "#e67e22"
        Title    = "Set Machine Account Quota to Zero"
        What     = "A non-zero ms-DS-MachineAccountQuota lets any authenticated user create computer accounts, enabling RBCD and persistence attacks."
        How      = "1. Set to 0: Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'='0'}`n2. Delegate computer account creation to specific admin accounts or OUs only`n3. Use a service account with restricted rights for workstation joins (e.g., via SCCM/Intune)."
        Tools    = "PowerShell AD module, ADSI Edit"
        Effort   = "1 hour"
        TriggerTitles = @("Non-Zero Machine Account Quota")
    },

    @{
        Phase    = "Medium-Term"
        Priority = "P3"
        PriorityLabel = "Medium"
        PriorityColor = "#e67e22"
        Title    = "Remediate S4U2Self Protocol Transition Accounts"
        What     = "Accounts with TrustedToAuthForDelegation (T2A4D) can impersonate any user to constrained services without needing the user's credentials."
        How      = "1. Identify: Get-ADUser -Filter {TrustedToAuthForDelegation -eq `$true}`n2. For each: assess if protocol transition is still needed`n3. Replace with Resource-Based Constrained Delegation (RBCD) where possible`n4. Remove T2A4D flag for accounts that no longer need it."
        Tools    = "PowerShell AD module, BloodHound"
        Effort   = "1-2 days"
        TriggerTitles = @("Accounts with Protocol Transition (S4U2Self) Delegation")
    },

    @{
        Phase    = "Medium-Term"
        Priority = "P3"
        PriorityLabel = "Medium"
        PriorityColor = "#e67e22"
        Title    = "Deploy Accounts with Password Never Expires Remediation Plan"
        What     = "Accounts with non-expiring passwords are high-value targets since any compromised credential remains valid indefinitely."
        How      = "1. For standard users: Remove PasswordNeverExpires flag and enforce policy`n2. For service accounts: Migrate to gMSA (auto-rotating passwords)`n3. For break-glass accounts: Store in PAM vault with check-out/check-in workflow`n4. Create a Fine-Grained PSO for service accounts with extended expiry but not unlimited."
        Tools    = "PowerShell, gMSA, CyberArk/BeyondTrust PAM"
        Effort   = "1-2 weeks"
        TriggerTitles = @("Accounts with Password Never Expires")
    },

    @{
        Phase    = "Medium-Term"
        Priority = "P3"
        PriorityLabel = "Medium"
        PriorityColor = "#e67e22"
        Title    = "Clean Up Orphaned AdminCount Accounts"
        What     = "Accounts with AdminCount=1 that are not in protected groups inherit AdminSDHolder ACLs silently, creating hidden privilege escalation paths."
        How      = "1. Find orphans: Get-ADUser -Filter {AdminCount -eq 1} (then cross-check group membership)`n2. For each: verify if privileged access is still needed`n3. Clear flag: Set-ADUser <user> -Clear AdminCount`n4. Manually fix ACL inheritance on the account object`n5. Run SDProp: Invoke-Command -ScriptBlock { `$null = [adsisearcher]''; ... } or restart NetLogon service."
        Tools    = "PowerShell AD module, ADSI Edit, SDProp trigger"
        Effort   = "4-8 hours"
        TriggerTitles = @("AdminCount=1 Orphaned Accounts")
    },

    @{
        Phase    = "Long-Term"
        Priority = "P4"
        PriorityLabel = "Strategic"
        PriorityColor = "#2980b9"
        Title    = "Implement Active Directory Tiering Model"
        What     = "Without tiering, privileged credentials from Tier 0 (DCs, AD) are exposed on lower-trust systems enabling credential theft and lateral movement."
        How      = "1. Define three tiers: Tier 0 (AD/DC), Tier 1 (Servers), Tier 2 (Workstations)`n2. Create separate admin accounts per tier (e.g., admin.t0@domain, admin.t1@domain)`n3. Enforce via Authentication Policy Silos (Windows Server 2012 R2+)`n4. Deploy Privileged Access Workstations (PAWs) for Tier 0 administration`n5. Use GPO to restrict logon rights per tier (Deny log on locally, Deny log on through RD Services)"
        Tools    = "GPMC, Authentication Policy Silos, PAW deployment guide (Microsoft)"
        Effort   = "2-4 weeks"
        TriggerTitles = @("Excessive Domain Administrator Accounts","Privileged Accounts Not Marked as Sensitive")
    },

    @{
        Phase    = "Long-Term"
        Priority = "P4"
        PriorityLabel = "Strategic"
        PriorityColor = "#2980b9"
        Title    = "Deploy Microsoft LAPS for Local Administrator Password Management"
        What     = "Reused local admin passwords across machines allow attackers to use Pass-the-Hash for lateral movement after a single workstation compromise."
        How      = "1. Download and install Microsoft LAPS (or use Windows LAPS built into Server 2022/Win11)`n2. Extend AD schema: Update-LapsADSchema`n3. Set permissions: Set-LapsADComputerSelfPermission -Identity <OU>`n4. Deploy via GPO: Enable LAPS, set password age (30 days), complexity`n5. Restrict ms-Mcs-AdmPwd read access to helpdesk tier only."
        Tools    = "Microsoft LAPS, GPMC, PowerShell"
        Effort   = "1-2 days"
        TriggerTitles = @("Stale Enabled User Accounts (90+ days inactive)","Excessive Domain Administrator Accounts")
    },

    @{
        Phase    = "Long-Term"
        Priority = "P4"
        PriorityLabel = "Strategic"
        PriorityColor = "#2980b9"
        Title    = "Conduct GPO Baseline Review and Security Hardening"
        What     = "Unlinked and unreviewed GPOs create configuration drift. Missing security baselines leave credential protection, NTLM hardening, and audit policies ungoverned."
        How      = "1. Run Microsoft Security Compliance Toolkit - download baselines for your OS versions`n2. Use Policy Analyzer to compare current GPOs against baseline`n3. Remove/archive all unlinked GPOs after review`n4. Apply CIS or Microsoft baseline GPOs in audit mode first, then enforce`n5. Implement: LSA Protection, Credential Guard, WDigest disabled, AppLocker/WDAC."
        Tools    = "Microsoft Security Compliance Toolkit, CIS Benchmarks, GPMC, Policy Analyzer"
        Effort   = "1-2 weeks"
        TriggerTitles = @("Excessive Unlinked Group Policy Objects","Group Policy Audit Recommendation")
    },

    @{
        Phase    = "Long-Term"
        Priority = "P4"
        PriorityLabel = "Strategic"
        PriorityColor = "#2980b9"
        Title    = "Implement Continuous AD Security Monitoring"
        What     = "Point-in-time assessments miss changes that occur after the scan. Continuous monitoring detects privilege escalation, persistence, and lateral movement in real time."
        How      = "1. Enable Advanced Audit Policy (GPO) for: Account Logon, Account Management, DS Access, Privilege Use, Logon/Logoff`n2. Forward logs to SIEM (Sentinel, Splunk, QRadar)`n3. Create alerts for: DA group changes, DCSync activity, AdminCount changes, Kerberoast spikes (4769), Pass-the-Hash (4768+4769 anomalies)`n4. Consider dedicated AD monitoring: Microsoft Defender for Identity (MDI), Semperis DSP, or Netwrix Auditor."
        Tools    = "Microsoft Defender for Identity, Azure Sentinel, Netwrix, Semperis DSP"
        Effort   = "2-4 weeks"
        TriggerTitles = @()  # Always included as a general recommendation
        AlwaysInclude = $true
    }
)

# Match recommendations to actual findings
$ActiveFindingTitles = $Findings | ForEach-Object { $_.Title }

$Recommendations = @()
foreach ($rec in $RecommendationCatalog) {
    $alwaysOn = $rec.ContainsKey('AlwaysInclude') -and $rec['AlwaysInclude'] -eq $true
    $triggered = $false
    foreach ($trigTitle in $rec.TriggerTitles) {
        # Partial match to handle findings like "Weak NTLM... on DC: hostname"
        foreach ($activeTitle in $ActiveFindingTitles) {
            if ($activeTitle -like "*$trigTitle*" -or $trigTitle -like "*$activeTitle*") {
                $triggered = $true
                break
            }
        }
        if ($triggered) { break }
    }
    if ($triggered -or $alwaysOn) {
        $Recommendations += $rec
    }
}

# Build Recommendations HTML
$RecHTML = ""
$Phases  = @("Immediate","Short-Term","Medium-Term","Long-Term")
$PhaseIcons = @{
    "Immediate"   = "&#9888;"   # warning triangle
    "Short-Term"  = "&#9654;"   # play arrow
    "Medium-Term" = "&#9679;"   # circle
    "Long-Term"   = "&#9670;"   # diamond
}
$PhaseColors = @{
    "Immediate"   = "#c0392b"
    "Short-Term"  = "#e74c3c"
    "Medium-Term" = "#e67e22"
    "Long-Term"   = "#2980b9"
}

$recIndex = 0
foreach ($phase in $Phases) {
    $phaseRecs = $Recommendations | Where-Object { $_.Phase -eq $phase }
    if (-not $phaseRecs) { continue }

    $phaseColor = $PhaseColors[$phase]
    $phaseIcon  = $PhaseIcons[$phase]
    $phaseCount = @($phaseRecs).Count

    $RecHTML += @"
<div class="rec-phase-block">
  <div class="rec-phase-header" style="border-left:4px solid $phaseColor">
    <span class="rec-phase-icon" style="color:$phaseColor">$phaseIcon</span>
    <span class="rec-phase-title">$phase Actions</span>
    <span class="rec-phase-count" style="background:$phaseColor">$phaseCount recommendation$(if($phaseCount -ne 1){'s'})</span>
  </div>
"@

    foreach ($rec in $phaseRecs) {
        $recIndex++
        $recId = "rec-$recIndex"
        # Convert newlines in How to <br> for HTML
        $howHtml = ($rec.How -replace "`n", "<br>")

        $RecHTML += @"
  <div class="rec-card" id="$recId">
    <div class="rec-card-header">
      <div class="rec-left">
        <span class="rec-num">$recIndex</span>
        <div>
          <div class="rec-title">$($rec.Title)</div>
          <div class="rec-meta">
            <span class="rec-priority-badge" style="background:$($rec.PriorityColor)">$($rec.Priority) - $($rec.PriorityLabel)</span>
            <span class="rec-effort"><strong>Effort:</strong> $($rec.Effort)</span>
          </div>
        </div>
      </div>
      <button class="rec-toggle" onclick="toggleRec('$recId')">Show Details</button>
    </div>
    <div class="rec-body" id="${recId}-body" style="display:none">
      <div class="rec-section">
        <div class="rec-section-label">What &amp; Why</div>
        <div class="rec-section-text">$($rec.What)</div>
      </div>
      <div class="rec-section">
        <div class="rec-section-label">How To Fix</div>
        <div class="rec-section-text rec-code">$howHtml</div>
      </div>
      <div class="rec-section rec-tools-row">
        <div><span class="rec-section-label">Recommended Tools:</span> <span class="rec-tools-text">$($rec.Tools)</span></div>
      </div>
    </div>
  </div>
"@
    }
    $RecHTML += "</div>"
}

# ─────────────────────────────────────────────────────────────────────────────
# BUILD FINDINGS HTML
# ─────────────────────────────────────────────────────────────────────────────
$Categories    = $Findings | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object
$FindingsHTML  = ""

foreach ($cat in $Categories) {
    $catFindings  = $Findings | Where-Object { $_.Category -eq $cat }
    $FindingsHTML += "<div class='category-section'><h2 class='cat-heading'><span class='cat-icon'>&#9670;</span> $cat</h2>"
    foreach ($f in $catFindings) {
        $sevClass = switch ($f.Severity) {
            "Critical"      { "severity-critical" }
            "High"          { "severity-high" }
            "Medium"        { "severity-medium" }
            "Low"           { "severity-low" }
            "Informational" { "severity-info" }
            default         { "severity-info" }
        }
        $detailsBlock = ""
        if ($f.Details) {
            $detailsBlock = "<div class='details-box'><strong>Technical Details:</strong> $($f.Details)</div>"
        }
        $FindingsHTML += @"
<div class="finding-card">
  <div class="finding-header $sevClass">
    <div class="finding-title-group">
      <span class="severity-badge">$($f.Severity)</span>
      <h3>$($f.Title)</h3>
    </div>
  </div>
  <div class="finding-content">
    <p><strong>Description:</strong> $($f.Description)</p>
    <p><strong>Impact:</strong> $($f.Impact)</p>
    <p><strong>Remediation:</strong> $($f.Remediation)</p>
    $detailsBlock
  </div>
</div>
"@
    }
    $FindingsHTML += "</div>"
}

# Risk color
$RiskColor = switch ($RiskLevel) {
    "CRITICAL" { "#c0392b" }
    "HIGH"     { "#e74c3c" }
    "MEDIUM"   { "#f39c12" }
    "LOW"      { "#27ae60" }
    default    { "#3498db" }
}

# DC list for domain info table
$DCList = ($DomainControllers | ForEach-Object { $_.HostName }) -join ', '

# TOC links
$TocHTML = ""
foreach ($cat in $Categories) {
    $anchor   = "cat-" + ($cat -replace '[^a-zA-Z0-9]', '-')
    $TocHTML += "<li><a href='#$anchor'>$cat</a></li>"
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
$ReportFile = Join-Path -Path $OutputPath -ChildPath "ConsultimIT-AD-Report_$Timestamp.html"

$HTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Consultim-IT | $ReportTitle</title>
<style>
:root {
  --bg:#f0f2f5; --surface:#ffffff; --surface2:#f8f9fa; --border:#dee2e6;
  --text:#1a1a2e; --text-muted:#6c757d;
  --accent:#0077b6; --accent2:#0a2540;
  --shadow:0 4px 20px rgba(0,0,0,.08); --shadow-sm:0 2px 8px rgba(0,0,0,.06);
}
[data-theme="dark"] {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2433; --border:#30363d;
  --text:#e6edf3; --text-muted:#8b949e;
  --accent:#58c4dc; --accent2:#1f6feb;
  --shadow:0 4px 20px rgba(0,0,0,.4); --shadow-sm:0 2px 8px rgba(0,0,0,.3);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;transition:background .3s,color .3s}
a{color:var(--accent)}
.container{max-width:1280px;margin:0 auto;padding:0 24px 60px}

/* HEADER */
.header{background:linear-gradient(135deg,#0a2540 0%,#0c3460 60%,#0077b6 100%);color:#fff;margin-bottom:32px;box-shadow:0 6px 30px rgba(0,0,0,.25)}
.header-inner{max-width:1280px;margin:0 auto;padding:28px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px}
.brand{display:flex;align-items:center;gap:16px}
.brand-logo{width:52px;height:52px;background:rgba(255,255,255,.15);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:900;color:#fff;border:2px solid rgba(255,255,255,.3);flex-shrink:0;letter-spacing:-1px;text-align:center}
.brand-text h1{font-size:1.6em;font-weight:700}
.brand-text p{font-size:.85em;opacity:.8;margin-top:2px}
.header-meta{text-align:right;font-size:.82em;opacity:.85;line-height:1.8}

/* TOGGLE */
.theme-toggle{position:fixed;top:20px;right:20px;z-index:999;background:var(--surface);border:1px solid var(--border);border-radius:50px;padding:8px 16px;cursor:pointer;font-size:.85em;color:var(--text);display:flex;align-items:center;gap:8px;box-shadow:var(--shadow);transition:all .2s}
.theme-toggle:hover{background:var(--accent);color:#fff;border-color:var(--accent)}

/* RISK BANNER */
.risk-banner{background:$RiskColor;color:#fff;padding:16px 28px;border-radius:12px;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;box-shadow:var(--shadow)}
.risk-banner .risk-label{font-size:.9em;opacity:.9}
.risk-banner .risk-score{font-size:2.2em;font-weight:900}
.risk-banner .risk-title{font-size:1.2em;font-weight:700}

/* SEV GRID */
.sev-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}
@media(max-width:700px){.sev-grid{grid-template-columns:repeat(3,1fr)}}
.sev-card{border-radius:10px;padding:16px 12px;text-align:center;color:#fff;box-shadow:var(--shadow-sm)}
.sev-card .sev-num{font-size:2.2em;font-weight:900}
.sev-card .sev-lbl{font-size:.75em;opacity:.9;text-transform:uppercase;letter-spacing:.5px}
.sev-critical{background:#c0392b}.sev-high{background:#e74c3c}.sev-medium{background:#f39c12}.sev-low{background:#2980b9}.sev-info{background:#636e72}

/* STAT GRID */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px;margin-bottom:8px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px 16px;text-align:center;box-shadow:var(--shadow-sm);transition:transform .2s,box-shadow .2s}
.stat-card:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.stat-num{font-size:2em;font-weight:800;color:var(--accent);line-height:1.1}
.stat-num.danger{color:#e74c3c}.stat-num.warning{color:#f39c12}.stat-num.success{color:#27ae60}
.stat-label{font-size:.75em;color:var(--text-muted);margin-top:6px;text-transform:uppercase;letter-spacing:.5px}

/* SECTION CARD */
.section-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px;margin-bottom:24px;box-shadow:var(--shadow-sm)}
.section-card>h2{font-size:1.1em;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid var(--border)}

/* INFO TABLE */
.info-table{width:100%;border-collapse:collapse;font-size:.88em}
.info-table td{padding:8px 12px;border-bottom:1px solid var(--border);color:var(--text)}
.info-table td:first-child{font-weight:600;color:var(--text-muted);width:38%}
.info-table tr:last-child td{border-bottom:none}

/* TOC */
.toc{list-style:none;display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}
.toc li a{background:var(--surface2);border:1px solid var(--border);padding:6px 14px;border-radius:20px;font-size:.82em;color:var(--text);transition:all .2s}
.toc li a:hover{background:var(--accent);color:#fff;border-color:var(--accent);text-decoration:none}

/* FINDINGS */
.cat-heading{font-size:1.25em;color:var(--accent);margin:36px 0 16px;padding-bottom:10px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:10px}
.cat-icon{color:var(--accent)}
.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:16px;overflow:hidden;box-shadow:var(--shadow-sm);transition:transform .2s}
.finding-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.finding-header{padding:14px 18px;color:#fff;display:flex;align-items:center;gap:12px}
.finding-title-group{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.finding-header h3{font-size:1em;font-weight:600;margin:0}
.severity-badge{background:rgba(255,255,255,.25);padding:3px 10px;border-radius:20px;font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.8px;white-space:nowrap}
.severity-critical{background:#c0392b}.severity-high{background:#e74c3c}.severity-medium{background:#e67e22}.severity-low{background:#2980b9}.severity-info{background:#636e72}
.finding-content{padding:16px 18px}
.finding-content p{margin-bottom:8px;font-size:.9em}
.finding-content strong{color:var(--accent)}
.details-box{background:var(--surface2);border-left:3px solid var(--accent);padding:10px 14px;border-radius:0 8px 8px 0;font-size:.82em;color:var(--text-muted);margin-top:10px;word-break:break-word}

/* ═══ DASHBOARD ══════════════════════════════════════════════════════ */

/* Row 1 */
.dash-row1{display:grid;grid-template-columns:320px 1fr;gap:20px;margin-bottom:20px}
@media(max-width:900px){.dash-row1{grid-template-columns:1fr}}

/* Secure Score */
.score-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:20px;text-align:center}
.score-label{font-size:.75em;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:8px;font-weight:700}
.score-gauge-wrap{width:200px;margin:0 auto 12px}
.gauge-svg{width:100%;overflow:visible}
.gauge-track{stroke:var(--border)}
.gauge-num{font-size:28px;font-weight:900;font-family:'Segoe UI',sans-serif}
.gauge-grade{font-size:11px;font-weight:700;font-family:'Segoe UI',sans-serif}
.score-sub-row{display:flex;gap:8px;margin-top:8px}
.score-sub{flex:1;text-align:center}
.score-sub-num{font-size:1.4em;font-weight:800;line-height:1}
.score-sub-lbl{font-size:.65em;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin:3px 0 5px}
.score-sub-bar{height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.score-sub-fill{height:100%;border-radius:2px;transition:width 1.2s ease}

/* KPI grid */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:700px){.kpi-grid{grid-template-columns:repeat(2,1fr)}}
.kpi-card{border-radius:12px;padding:16px 12px;text-align:center;color:#fff;box-shadow:var(--shadow-sm);position:relative;overflow:hidden;transition:transform .2s}
.kpi-card:hover{transform:translateY(-3px)}
.kpi-icon{font-size:1.5em;margin-bottom:4px;opacity:.85}
.kpi-num{font-size:1.8em;font-weight:900;line-height:1.1}
.kpi-lbl{font-size:.68em;opacity:.9;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.kpi-blue{background:linear-gradient(135deg,#0077b6,#00b4d8)}
.kpi-green{background:linear-gradient(135deg,#27ae60,#2ecc71)}
.kpi-purple{background:linear-gradient(135deg,#8e44ad,#9b59b6)}
.kpi-teal{background:linear-gradient(135deg,#16a085,#1abc9c)}
.kpi-red{background:linear-gradient(135deg,#c0392b,#e74c3c)}
.kpi-orange{background:linear-gradient(135deg,#d35400,#e67e22)}
.kpi-yellow{background:linear-gradient(135deg,#b7950b,#f39c12)}
.kpi-dc{background:linear-gradient(135deg,#2c3e50,#34495e)}

/* Row 2 */
.dash-row2{display:grid;grid-template-columns:1fr 1.6fr 1fr;gap:20px;margin-bottom:20px}
@media(max-width:1100px){.dash-row2{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.dash-row2{grid-template-columns:1fr}}

.chart-card{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:20px}
.chart-title{font-size:.78em;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}

/* Donut */
.donut-wrap{width:160px;margin:0 auto 12px}
.donut-svg{width:100%;overflow:visible;transform:rotate(-90deg)}
.donut-seg{transition:stroke-dasharray 1s ease,stroke-dashoffset 1s ease}
.donut-center-num{font-size:24px;font-weight:900;fill:var(--text);font-family:'Segoe UI',sans-serif;transform:rotate(90deg);transform-origin:100px 100px}
.donut-center-lbl{font-size:10px;fill:var(--text-muted);font-family:'Segoe UI',sans-serif;transform:rotate(90deg);transform-origin:100px 100px}
.donut-legend{display:flex;flex-wrap:wrap;gap:6px 12px;justify-content:center;margin-top:4px}
.dl-item{display:flex;align-items:center;gap:5px;font-size:.72em;color:var(--text)}
.dl-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

/* Flow chart */
.flow-card{padding:16px 12px}
.flow-wrap{display:flex;flex-direction:column;align-items:center;gap:0;font-size:.82em}
.flow-node{border:2px solid var(--accent);border-radius:10px;padding:8px 18px;text-align:center;background:var(--surface);min-width:110px}
.flow-num{font-size:1.4em;font-weight:800;color:var(--accent)}
.flow-lbl{font-size:.72em;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px}
.flow-arrows-row{display:flex;gap:20px;width:100%;justify-content:center;margin:6px 0}
.flow-arrow-col{display:flex;flex-direction:column;align-items:center;gap:4px;flex:1}
.flow-arrow-col-right{flex:0 0 120px}
.flow-arrow-line{width:2px;height:18px;border-left:2px dashed var(--border)}
.flow-sub-row{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:4px;width:100%}
.flow-sub-node{border:1px solid var(--border);border-radius:8px;padding:6px 8px;text-align:center;background:var(--surface)}
.flow-sub-num{font-size:1.1em;font-weight:800}
.flow-sub-lbl{font-size:.65em;color:var(--text-muted)}
.flow-risk-row{display:flex;gap:8px;margin-top:12px;width:100%;justify-content:center}
.flow-risk-item{border:1.5px solid var(--border);border-radius:8px;padding:8px 12px;text-align:center;flex:1;background:var(--surface)}
.flow-risk-num{font-size:1.3em;font-weight:900;color:#e74c3c}
.flow-risk-lbl{font-size:.65em;color:var(--text-muted)}

/* Row 3 */
.dash-row3{display:grid;grid-template-columns:1fr 300px;gap:20px}
@media(max-width:900px){.dash-row3{grid-template-columns:1fr}}
.chart-wide{flex:1}

/* Bar chart */
.bar-chart-wrap{display:flex;flex-direction:column;gap:10px}
.bar-row{display:flex;align-items:center;gap:10px}
.bar-row-label{font-size:.78em;color:var(--text);width:160px;text-align:right;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-row-track{flex:1;height:24px;background:var(--border);border-radius:6px;overflow:hidden}
.bar-row-fill{height:100%;border-radius:6px;transition:width 1s ease;display:flex;align-items:center;justify-content:flex-end;padding-right:8px}
.bar-row-val{font-size:.72em;font-weight:700;color:#fff;white-space:nowrap}

/* Severity bars */
.sev-bar-wrap{display:flex;flex-direction:column;gap:14px}
.sev-bar-item{display:flex;align-items:center;gap:10px}
.sev-bar-label{font-size:.78em;color:var(--text);width:55px;flex-shrink:0}
.sev-bar-track{flex:1;height:18px;background:var(--border);border-radius:20px;overflow:hidden}
.sev-bar-fill{height:100%;border-radius:20px;width:0;transition:width 1s ease}
.sev-bar-num{font-size:.8em;font-weight:700;color:var(--text);width:24px;text-align:right;flex-shrink:0}

/* RECOMMENDATIONS */
.rec-phase-block{margin-bottom:32px}
.rec-phase-header{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--surface2);border-radius:10px;margin-bottom:16px;border-left:4px solid #ccc}
.rec-phase-icon{font-size:1.2em}
.rec-phase-title{font-weight:700;font-size:1.05em;color:var(--text)}
.rec-phase-count{font-size:.75em;padding:3px 10px;border-radius:20px;color:#fff;font-weight:600;margin-left:auto}

.rec-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow-sm);transition:box-shadow .2s}
.rec-card:hover{box-shadow:var(--shadow)}
.rec-card-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;gap:16px;flex-wrap:wrap}
.rec-left{display:flex;align-items:flex-start;gap:14px;flex:1;min-width:0}
.rec-num{width:32px;height:32px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.85em;flex-shrink:0;margin-top:2px}
.rec-title{font-weight:700;font-size:.95em;color:var(--text);margin-bottom:6px}
.rec-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.rec-priority-badge{font-size:.7em;padding:2px 8px;border-radius:12px;color:#fff;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.rec-effort{font-size:.78em;color:var(--text-muted)}
.rec-toggle{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:6px 14px;font-size:.8em;cursor:pointer;color:var(--text);transition:all .2s;white-space:nowrap;flex-shrink:0}
.rec-toggle:hover{background:var(--accent);color:#fff;border-color:var(--accent)}

.rec-body{padding:0 20px 20px}
.rec-section{margin-bottom:14px}
.rec-section-label{font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--accent);margin-bottom:5px}
.rec-section-text{font-size:.88em;color:var(--text);line-height:1.7}
.rec-code{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;font-family:'Courier New',monospace;font-size:.82em;white-space:pre-wrap;word-break:break-word}
.rec-tools-row{display:flex;align-items:flex-start;gap:8px}
.rec-tools-text{font-size:.85em;color:var(--text-muted)}

/* FOOTER */
.footer{background:linear-gradient(135deg,#0a2540,#0c3460);color:rgba(255,255,255,.85);border-radius:14px;padding:28px 32px;margin-top:40px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.footer-brand{font-size:1.1em;font-weight:700;color:#fff}
.footer-meta{font-size:.8em;opacity:.7;margin-top:4px}
.footer-right{text-align:right;font-size:.8em;opacity:.75}

@media print{.theme-toggle{display:none}}
</style>
</head>
<body>

<button class="theme-toggle" onclick="toggleTheme()">
  <span id="toggleIcon">&#9790;</span> <span id="themeLabel">Dark Mode</span>
</button>

<div class="header">
  <div class="header-inner">
    <div class="brand">
      <div class="brand-logo">C-IT</div>
      <div class="brand-text">
        <h1>Consultim-IT</h1>
        <p>Active Directory Security Assessment Report</p>
      </div>
    </div>
    <div class="header-meta">
      <div><strong>Domain:</strong> $Domain</div>
      <div><strong>Scan Date:</strong> $($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</div>
      <div><strong>Duration:</strong> $DurationStr</div>
      <div><strong>Author:</strong> Ranim Hassine</div>
    </div>
  </div>
</div>

<div class="container">

  <div class="risk-banner">
    <div><div class="risk-label">Overall Risk Level</div><div class="risk-title">$RiskLevel</div></div>
    <div><div class="risk-label">Risk Score</div><div class="risk-score">$RiskScore / 100</div></div>
    <div><div class="risk-label">Total Findings</div><div class="risk-score">$TotalFindings</div></div>
  </div>

  <div class="sev-grid">
    <div class="sev-card sev-critical"><div class="sev-num">$CriticalCount</div><div class="sev-lbl">Critical</div></div>
    <div class="sev-card sev-high"><div class="sev-num">$HighCount</div><div class="sev-lbl">High</div></div>
    <div class="sev-card sev-medium"><div class="sev-num">$MediumCount</div><div class="sev-lbl">Medium</div></div>
    <div class="sev-card sev-low"><div class="sev-num">$LowCount</div><div class="sev-lbl">Low</div></div>
    <div class="sev-card sev-info"><div class="sev-num">$InfoCount</div><div class="sev-lbl">Info</div></div>
  </div>

  <!-- ═══ DASHBOARD ═══════════════════════════════════════════════════ -->
  <div class="section-card" id="sec-stats">
    <h2>Security Dashboard</h2>

    <!-- Row 1: Secure Score + 3 sub-scores + quick counters -->
    <div class="dash-row1">

      <!-- Secure Score Gauge -->
      <div class="score-card">
        <div class="score-label">AD Secure Score</div>
        <div class="score-gauge-wrap">
          <svg viewBox="0 0 200 120" class="gauge-svg">
            <defs>
              <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%"   stop-color="#c0392b"/>
                <stop offset="40%"  stop-color="#f39c12"/>
                <stop offset="70%"  stop-color="#2ecc71"/>
                <stop offset="100%" stop-color="#27ae60"/>
              </linearGradient>
            </defs>
            <!-- Track -->
            <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="#e0e0e0" stroke-width="16" stroke-linecap="round" class="gauge-track"/>
            <!-- Fill -->
            <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="url(#gaugeGrad)" stroke-width="16" stroke-linecap="round"
                  stroke-dasharray="251.2" stroke-dashoffset="251.2" class="gauge-fill" data-score="$SecureScore"/>
            <!-- Score text -->
            <text x="100" y="95"  text-anchor="middle" class="gauge-num" fill="$SecureScoreColor">$SecureScore</text>
            <text x="100" y="115" text-anchor="middle" class="gauge-grade" fill="$SecureScoreColor">Grade: $SecureScoreGrade</text>
          </svg>
        </div>
        <div class="score-sub-row">
          <div class="score-sub">
            <div class="score-sub-num" style="color:#3498db">$PwdPolicyScore</div>
            <div class="score-sub-lbl">Password Policy</div>
            <div class="score-sub-bar"><div class="score-sub-fill" style="width:${PwdPolicyScore}%;background:#3498db"></div></div>
          </div>
          <div class="score-sub">
            <div class="score-sub-num" style="color:#9b59b6">$PrivScore</div>
            <div class="score-sub-lbl">Privilege Hygiene</div>
            <div class="score-sub-bar"><div class="score-sub-fill" style="width:${PrivScore}%;background:#9b59b6"></div></div>
          </div>
          <div class="score-sub">
            <div class="score-sub-num" style="color:#1abc9c">$HygieneScore</div>
            <div class="score-sub-lbl">Account Hygiene</div>
            <div class="score-sub-bar"><div class="score-sub-fill" style="width:${HygieneScore}%;background:#1abc9c"></div></div>
          </div>
        </div>
      </div>

      <!-- Quick KPI counters -->
      <div class="kpi-grid">
        <div class="kpi-card kpi-blue">
          <div class="kpi-icon">&#128100;</div>
          <div class="kpi-num counter" data-target="$($Stats['TotalUsers'])">0</div>
          <div class="kpi-lbl">Total Users</div>
        </div>
        <div class="kpi-card kpi-green">
          <div class="kpi-icon">&#128187;</div>
          <div class="kpi-num counter" data-target="$($Stats['TotalComputers'])">0</div>
          <div class="kpi-lbl">Computers</div>
        </div>
        <div class="kpi-card kpi-purple">
          <div class="kpi-icon">&#128274;</div>
          <div class="kpi-num counter" data-target="$($Stats['TotalGroups'])">0</div>
          <div class="kpi-lbl">Groups</div>
        </div>
        <div class="kpi-card kpi-teal">
          <div class="kpi-icon">&#128196;</div>
          <div class="kpi-num counter" data-target="$($Stats['TotalGPOs'])">0</div>
          <div class="kpi-lbl">GPOs</div>
        </div>
        <div class="kpi-card kpi-red">
          <div class="kpi-icon">&#9888;</div>
          <div class="kpi-num counter" data-target="$CriticalCount">0</div>
          <div class="kpi-lbl">Critical Findings</div>
        </div>
        <div class="kpi-card kpi-orange">
          <div class="kpi-icon">&#128737;</div>
          <div class="kpi-num counter" data-target="$($Stats['DomainAdmins'])">0</div>
          <div class="kpi-lbl">Domain Admins</div>
        </div>
        <div class="kpi-card kpi-yellow">
          <div class="kpi-icon">&#128336;</div>
          <div class="kpi-num counter" data-target="$($Stats['StaleUsers'])">0</div>
          <div class="kpi-lbl">Stale Accounts</div>
        </div>
        <div class="kpi-card kpi-dc">
          <div class="kpi-icon">&#128268;</div>
          <div class="kpi-num counter" data-target="$($Stats['DomainControllers'])">0</div>
          <div class="kpi-lbl">Domain Controllers</div>
        </div>
      </div>
    </div>

    <!-- Row 2: User Health Donut + Flow + Computer OS Donut -->
    <div class="dash-row2">

      <!-- User Health Donut -->
      <div class="chart-card">
        <div class="chart-title">User Health Breakdown</div>
        <div class="donut-wrap">
          <svg viewBox="0 0 200 200" class="donut-svg" id="userDonut">
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#27ae60" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$UH_Healthy" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#e74c3c" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$UH_AtRisk" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#f39c12" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$UH_Inactive" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#95a5a6" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$UH_Disabled" data-offset="0"/>
            <text x="100" y="96"  text-anchor="middle" class="donut-center-num">$($Stats['TotalUsers'])</text>
            <text x="100" y="114" text-anchor="middle" class="donut-center-lbl">Total Users</text>
          </svg>
        </div>
        <div class="donut-legend">
          <div class="dl-item"><span class="dl-dot" style="background:#27ae60"></span>Healthy ($UH_Healthy%)</div>
          <div class="dl-item"><span class="dl-dot" style="background:#e74c3c"></span>At Risk ($UH_AtRisk%)</div>
          <div class="dl-item"><span class="dl-dot" style="background:#f39c12"></span>Inactive ($UH_Inactive%)</div>
          <div class="dl-item"><span class="dl-dot" style="background:#95a5a6"></span>Disabled ($UH_Disabled%)</div>
        </div>
      </div>

      <!-- User Health Flow -->
      <div class="chart-card flow-card">
        <div class="chart-title">User Account Flow</div>
        <div class="flow-wrap">
          <div class="flow-node flow-total">
            <div class="flow-num">$($Stats['TotalUsers'])</div>
            <div class="flow-lbl">All Accounts</div>
          </div>
          <div class="flow-arrows-row">
            <div class="flow-arrow-col">
              <div class="flow-arrow-line" style="border-color:#27ae60"></div>
              <div class="flow-node flow-enabled" style="border-color:#27ae60">
                <div class="flow-num" style="color:#27ae60">$($Stats['EnabledUsers'])</div>
                <div class="flow-lbl">Enabled</div>
              </div>
              <div class="flow-sub-row">
                <div class="flow-sub-node" style="border-color:#27ae60;background:rgba(39,174,96,.07)">
                  <div class="flow-sub-num" style="color:#27ae60">$($Stats['HealthyUsers'])</div>
                  <div class="flow-sub-lbl">Healthy</div>
                </div>
                <div class="flow-sub-node" style="border-color:#f39c12;background:rgba(243,156,18,.07)">
                  <div class="flow-sub-num" style="color:#f39c12">$($Stats['StaleUsers'])</div>
                  <div class="flow-sub-lbl">Stale 90d+</div>
                </div>
                <div class="flow-sub-node" style="border-color:#e74c3c;background:rgba(231,76,60,.07)">
                  <div class="flow-sub-num" style="color:#e74c3c">$($Stats['AtRiskUsers'])</div>
                  <div class="flow-sub-lbl">At Risk</div>
                </div>
                <div class="flow-sub-node" style="border-color:#9b59b6;background:rgba(155,89,182,.07)">
                  <div class="flow-sub-num" style="color:#9b59b6">$($Stats['NeverLogon'])</div>
                  <div class="flow-sub-lbl">Never Logged On</div>
                </div>
              </div>
            </div>
            <div class="flow-arrow-col flow-arrow-col-right">
              <div class="flow-arrow-line" style="border-color:#95a5a6"></div>
              <div class="flow-node flow-disabled" style="border-color:#95a5a6">
                <div class="flow-num" style="color:#95a5a6">$($Stats['DisabledUsers'])</div>
                <div class="flow-lbl">Disabled</div>
              </div>
            </div>
          </div>
          <!-- Risk detail row -->
          <div class="flow-risk-row">
            <div class="flow-risk-item" style="border-color:#c0392b">
              <div class="flow-risk-num">$($Stats['PwdNotRequired'])</div>
              <div class="flow-risk-lbl">No Password Required</div>
            </div>
            <div class="flow-risk-item" style="border-color:#e74c3c">
              <div class="flow-risk-num">$($Stats['PwdNeverExpires'])</div>
              <div class="flow-risk-lbl">Pwd Never Expires</div>
            </div>
            <div class="flow-risk-item" style="border-color:#e67e22">
              <div class="flow-risk-num">$($Stats['DomainAdmins'])</div>
              <div class="flow-risk-lbl">Domain Admins</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Computer OS Donut -->
      <div class="chart-card">
        <div class="chart-title">Computer OS Distribution</div>
        <div class="donut-wrap">
          <svg viewBox="0 0 200 200" class="donut-svg" id="osDonut">
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#0077b6" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$PC_Win11" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#00b4d8" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$PC_Win10" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#48cae4" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$PC_Srv" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#c0392b" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$PC_Legacy" data-offset="0"/>
            <circle class="donut-seg" cx="100" cy="100" r="70" fill="none" stroke="#95a5a6" stroke-width="28"
                    stroke-dasharray="0 439.8" data-val="$PC_Other" data-offset="0"/>
            <text x="100" y="96"  text-anchor="middle" class="donut-center-num">$($Stats['TotalComputers'])</text>
            <text x="100" y="114" text-anchor="middle" class="donut-center-lbl">Computers</text>
          </svg>
        </div>
        <div class="donut-legend">
          <div class="dl-item"><span class="dl-dot" style="background:#0077b6"></span>Windows 11 ($($Stats['Win11']))</div>
          <div class="dl-item"><span class="dl-dot" style="background:#00b4d8"></span>Windows 10 ($($Stats['Win10']))</div>
          <div class="dl-item"><span class="dl-dot" style="background:#48cae4"></span>Server 2016+ ($($Stats['Server2016']))</div>
          <div class="dl-item"><span class="dl-dot" style="background:#c0392b"></span>Legacy OS ($($Stats['LegacyOS']))</div>
          <div class="dl-item"><span class="dl-dot" style="background:#95a5a6"></span>Other ($($Stats['OtherOS']))</div>
        </div>
      </div>
    </div>

    <!-- Row 3: Findings Bar Chart + Severity Breakdown -->
    <div class="dash-row3">
      <!-- Findings by Category Bar -->
      <div class="chart-card chart-wide">
        <div class="chart-title">Findings by Category</div>
        <div class="bar-chart-wrap" id="barChart">
          <!-- injected by JS -->
        </div>
      </div>

      <!-- Severity breakdown vertical bars -->
      <div class="chart-card">
        <div class="chart-title">Severity Distribution</div>
        <div class="sev-bar-wrap">
          <div class="sev-bar-item">
            <div class="sev-bar-label">Critical</div>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="background:#c0392b" data-pct="$(if($TotalFindings -gt 0){[math]::Round($CriticalCount/$TotalFindings*100)}else{0})"></div></div>
            <div class="sev-bar-num">$CriticalCount</div>
          </div>
          <div class="sev-bar-item">
            <div class="sev-bar-label">High</div>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="background:#e74c3c" data-pct="$(if($TotalFindings -gt 0){[math]::Round($HighCount/$TotalFindings*100)}else{0})"></div></div>
            <div class="sev-bar-num">$HighCount</div>
          </div>
          <div class="sev-bar-item">
            <div class="sev-bar-label">Medium</div>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="background:#e67e22" data-pct="$(if($TotalFindings -gt 0){[math]::Round($MediumCount/$TotalFindings*100)}else{0})"></div></div>
            <div class="sev-bar-num">$MediumCount</div>
          </div>
          <div class="sev-bar-item">
            <div class="sev-bar-label">Low</div>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="background:#2980b9" data-pct="$(if($TotalFindings -gt 0){[math]::Round($LowCount/$TotalFindings*100)}else{0})"></div></div>
            <div class="sev-bar-num">$LowCount</div>
          </div>
          <div class="sev-bar-item">
            <div class="sev-bar-label">Info</div>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="background:#636e72" data-pct="$(if($TotalFindings -gt 0){[math]::Round($InfoCount/$TotalFindings*100)}else{0})"></div></div>
            <div class="sev-bar-num">$InfoCount</div>
          </div>
        </div>
      </div>
    </div>

  </div><!-- /sec-stats -->

  <div class="section-card">
    <h2>Domain Information</h2>
    <table class="info-table">
      <tr><td>Domain Name</td><td>$Domain</td></tr>
      <tr><td>Domain DN</td><td>$DomainDN</td></tr>
      <tr><td>Forest Root</td><td>$($ForestObj.RootDomain)</td></tr>
      <tr><td>Forest Functional Level</td><td>$($Stats['ForestFunctional'])</td></tr>
      <tr><td>Domain Functional Level</td><td>$($Stats['DomainFunctional'])</td></tr>
      <tr><td>Domain Controllers</td><td>$DCList</td></tr>
      <tr><td>Enterprise Admins</td><td>$($Stats['EnterpriseAdmins'])</td></tr>
      <tr><td>Scan Duration</td><td>$DurationStr</td></tr>
      <tr><td>Assessed By</td><td>Ranim Hassine - Consultim-IT</td></tr>
    </table>
  </div>

  <ul class="toc">
    <li><a href="#sec-stats">AD Statistics</a></li>
    <li><a href="#sec-recommendations">Recommendations</a></li>
    <li><a href="#sec-findings">Detailed Findings</a></li>
    $TocHTML
  </ul>

  <div class="section-card" id="sec-recommendations">
    <h2>Prioritized Recommendations</h2>
    <p style="font-size:.88em;color:var(--text-muted);margin-bottom:20px">
      The following $($Recommendations.Count) recommendation$(if($Recommendations.Count -ne 1){'s'}) were generated based on the findings detected in this assessment.
      They are ordered by urgency - address <strong>Immediate</strong> items first to close the highest-risk exposure windows.
    </p>
    $RecHTML
  </div>

  <div class="section-card" id="sec-findings">
    <h2>Detailed Security Findings</h2>
    $FindingsHTML
  </div>

  <div class="footer">
    <div>
      <div class="footer-brand">Consultim-IT - Active Directory Assessment</div>
      <div class="footer-meta">Author: Ranim Hassine | Generated: $($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))</div>
      <div class="footer-meta">This report is confidential. For internal use only.</div>
    </div>
    <div class="footer-right">
      <div>Consultim-IT Security Practice</div>
      <div>consultim-it.com</div>
    </div>
  </div>

</div>

<script>
/* ── Theme ───────────────────────────────────────────────── */
function toggleTheme() {
  var html = document.documentElement;
  var isDark = html.getAttribute('data-theme') === 'dark';
  html.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('themeLabel').textContent = isDark ? 'Dark Mode' : 'Light Mode';
  document.getElementById('toggleIcon').textContent = isDark ? '\u263D' : '\u2600';
}

/* ── Rec toggle ──────────────────────────────────────────── */
function toggleRec(id) {
  var body = document.getElementById(id + '-body');
  var btn  = document.querySelector('#' + id + ' .rec-toggle');
  if (body.style.display === 'none') {
    body.style.display = 'block'; btn.textContent = 'Hide Details';
  } else {
    body.style.display = 'none'; btn.textContent = 'Show Details';
  }
}

/* ── Finding category anchors ────────────────────────────── */
document.querySelectorAll('.cat-heading').forEach(function(el) {
  el.id = 'cat-' + el.textContent.trim().replace(/[^a-zA-Z0-9]/g, '-');
});

/* ── Animated counters ───────────────────────────────────── */
function animateCounters() {
  document.querySelectorAll('.counter').forEach(function(el) {
    var target = parseInt(el.getAttribute('data-target')) || 0;
    var duration = 1200;
    var start = performance.now();
    function step(now) {
      var elapsed = now - start;
      var progress = Math.min(elapsed / duration, 1);
      var ease = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(ease * target);
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });
}

/* ── Gauge animation ─────────────────────────────────────── */
function animateGauge() {
  var fill = document.querySelector('.gauge-fill');
  if (!fill) return;
  var score = parseInt(fill.getAttribute('data-score')) || 0;
  var circ  = 251.2;
  var offset = circ - (score / 100) * circ;
  setTimeout(function() {
    fill.style.transition = 'stroke-dashoffset 1.4s ease';
    fill.setAttribute('stroke-dasharray', circ + ' ' + circ);
    fill.setAttribute('stroke-dashoffset', offset);
  }, 300);
}

/* ── Donut charts ────────────────────────────────────────── */
function animateDonut(svgId) {
  var svg = document.getElementById(svgId);
  if (!svg) return;
  var segs = svg.querySelectorAll('.donut-seg');
  var circ = 2 * Math.PI * 70; // r=70 => 439.8
  var offset = 0;
  segs.forEach(function(seg) {
    var pct = parseInt(seg.getAttribute('data-val')) || 0;
    var len = (pct / 100) * circ;
    var gap = circ - len;
    setTimeout(function() {
      seg.style.transition = 'stroke-dasharray 1s ease, stroke-dashoffset 1s ease';
      seg.setAttribute('stroke-dasharray', len + ' ' + gap);
      seg.setAttribute('stroke-dashoffset', -offset);
    }, 400);
    offset += len;
  });
}

/* ── Severity bars ───────────────────────────────────────── */
function animateSevBars() {
  document.querySelectorAll('.sev-bar-fill').forEach(function(el) {
    var pct = parseInt(el.getAttribute('data-pct')) || 0;
    setTimeout(function() { el.style.width = pct + '%'; }, 500);
  });
}

/* ── Bar chart (findings by category) ───────────────────── */
function buildBarChart() {
  var wrap = document.getElementById('barChart');
  if (!wrap) return;
  var catData = [$catValues];
  var catLabels = [$catLabels];
  if (catData.length === 0 || catData.every(function(v){ return v === 0; })) {
    wrap.innerHTML = '<p style="color:var(--text-muted);font-size:.85em">No findings data.</p>';
    return;
  }
  var maxVal = Math.max.apply(null, catData);
  var colors = ['#c0392b','#e74c3c','#e67e22','#f39c12','#2980b9','#8e44ad','#16a085','#27ae60'];
  var html = '';
  for (var i = 0; i < catLabels.length; i++) {
    var pct = maxVal > 0 ? Math.round((catData[i] / maxVal) * 100) : 0;
    var color = colors[i % colors.length];
    html += '<div class="bar-row">' +
      '<div class="bar-row-label" title="' + catLabels[i] + '">' + catLabels[i] + '</div>' +
      '<div class="bar-row-track">' +
        '<div class="bar-row-fill" style="background:' + color + ';width:0" data-pct="' + pct + '">' +
          '<span class="bar-row-val">' + catData[i] + '</span>' +
        '</div>' +
      '</div>' +
    '</div>';
  }
  wrap.innerHTML = html;
  setTimeout(function() {
    wrap.querySelectorAll('.bar-row-fill').forEach(function(el) {
      el.style.width = el.getAttribute('data-pct') + '%';
    });
  }, 500);
}

/* ── Run all on load ─────────────────────────────────────── */
window.addEventListener('load', function() {
  animateCounters();
  animateGauge();
  animateDonut('userDonut');
  animateDonut('osDonut');
  animateSevBars();
  buildBarChart();
});
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Host "[+] Report saved to: $ReportFile" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |      CONSULTIM-IT AD ASSESSMENT COMPLETE            |" -ForegroundColor Cyan
Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  | Domain   : $Domain" -ForegroundColor White
Write-Host "  | Duration : $DurationStr" -ForegroundColor White
Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
$lvlColor = if ($RiskLevel -in @("CRITICAL","HIGH")) { "Red" } elseif ($RiskLevel -eq "MEDIUM") { "Yellow" } else { "Green" }
Write-Host "  | Risk     : $RiskLevel  (Score: $RiskScore/100)" -ForegroundColor $lvlColor
Write-Host "  | Findings : $TotalFindings total" -ForegroundColor White
Write-Host "  |   Critical : $CriticalCount" -ForegroundColor Red
Write-Host "  |   High     : $HighCount" -ForegroundColor DarkRed
Write-Host "  |   Medium   : $MediumCount" -ForegroundColor Yellow
Write-Host "  |   Low      : $LowCount" -ForegroundColor Cyan
Write-Host "  |   Info     : $InfoCount" -ForegroundColor Gray
Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  | Report: $ReportFile" -ForegroundColor Green
Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Consultim-IT | Author: Ranim Hassine" -ForegroundColor DarkGray
Write-Host ""
