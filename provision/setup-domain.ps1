<#
    setup-domain.ps1  —  build the vulnerable CORP.LOCAL lab domain.

    Run on a fresh Windows Server 2022 (eval) as Administrator from an elevated
    PowerShell. It will:
      1. install AD DS and promote this box to a Domain Controller (reboots)
      2. on second run (after reboot, now a DC) create the OU, users, groups,
         SPNs, AS-REP roastable account, and a dangerous ACL

    The user set and passwords mirror the gpu-hash-cracking repo so dumped
    hashes land in that workflow.

    LAB ONLY. These are intentional misconfigurations. Never run on a real DC.
#>

$DomainName   = "corp.local"
$NetbiosName  = "CORP"
$SafeModePwd  = ConvertTo-SecureString "LabDSRM!Pass123" -AsPlainText -Force

function Install-Forest {
    Write-Host "[*] Installing AD DS role..." -ForegroundColor Cyan
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Write-Host "[*] Promoting to DC for $DomainName (will reboot)..." -ForegroundColor Cyan
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $SafeModePwd `
        -InstallDns -Force
}

function New-LabUser($Sam, $Name, $Password, [switch]$NoPreAuth) {
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
    New-ADUser -SamAccountName $Sam -Name $Name -AccountPassword $sec `
        -Enabled $true -PasswordNeverExpires $true -Path "OU=Lab,DC=corp,DC=local"
    if ($NoPreAuth) {
        Set-ADAccountControl -Identity $Sam -DoesNotRequirePreAuth $true
        Write-Host "    [!] $Sam is AS-REP roastable (no pre-auth)" -ForegroundColor Yellow
    }
}

function Build-Domain {
    Import-Module ActiveDirectory
    New-ADOrganizationalUnit -Name "Lab" -Path "DC=corp,DC=local" -ErrorAction SilentlyContinue

    # --- standard users (passwords match gpu-hash-cracking answer key) ---
    New-LabUser jsmith   "John Smith"    "password1"   -NoPreAuth   # AS-REP roastable
    New-LabUser mjones   "Mary Jones"    "Summer2024!"
    New-LabUser rpatel   "Raj Patel"     "Welcome123"
    New-LabUser klee     "Karen Lee"     "Falcons2023"
    New-LabUser dgarcia  "Dan Garcia"    "Spring2024"
    New-LabUser twilson  "Tom Wilson"    "Letmein!1"
    New-LabUser bchen    "Bob Chen"      "qwertyuiop"
    New-LabUser afoster  "Amy Foster"    "Monkey123!"
    New-LabUser ghall    "Grace Hall"    "7Kp!vQ2z@Lm9xRt"         # strong, should survive

    # --- Kerberoastable service accounts (SPN + weak password) ---
    New-LabUser svc_sql    "SQL Service"    "Sql`$erv1ce"
    New-LabUser svc_backup "Backup Service" "Backup2024#"
    Set-ADUser svc_sql    -ServicePrincipalNames @{Add="MSSQLSvc/db01.corp.local:1433"}
    Set-ADUser svc_backup -ServicePrincipalNames @{Add="BACKUP/bak01.corp.local"}
    Write-Host "    [!] svc_sql, svc_backup are Kerberoastable (SPN set)" -ForegroundColor Yellow

    # --- dangerous ACL: low-priv user gets GenericAll over Domain Admins ---
    # (BloodHound flags this as a direct path to domain compromise)
    $lowPriv = Get-ADUser rpatel
    $targetDn = (Get-ADGroup "Domain Admins").DistinguishedName
    $acl = Get-Acl "AD:$targetDn"
    $sid = New-Object System.Security.Principal.SecurityIdentifier $lowPriv.SID
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, "GenericAll", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl "AD:$targetDn" $acl
    Write-Host "    [!] rpatel has GenericAll over Domain Admins (ACL abuse path)" -ForegroundColor Yellow

    Write-Host "[+] CORP.LOCAL built. Users, SPNs, AS-REP, and ACL path in place." -ForegroundColor Green
}

# Decide which phase we are in: not yet a DC -> install; already a DC -> build.
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -lt 4) {
    Install-Forest
} else {
    Build-Domain
}
