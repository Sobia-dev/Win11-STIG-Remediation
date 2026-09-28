<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000315 on Windows 11.

.DESCRIPTION
    WN11-CC-000315: The Windows Installer feature "Always install with
    elevated privileges" must be disabled.

    If enabled, ANY user can run an .msi installer with SYSTEM rights -
    a well-known privilege escalation path (MITRE ATT&CK T1548).

    Registry location:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
      Value: AlwaysInstallElevated (REG_DWORD) = 0

.NOTES
    STIG ID     : WN11-CC-000315
    Severity    : CAT I (High)
    Author      : SR
    Tested on   : Windows 11
#>

# ---------- Settings ----------
$StigId        = "WN11-CC-000315"
$RegPath       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$ValueName     = "AlwaysInstallElevated"
$RequiredValue = 0

# ---------- 1. Admin check ----------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "=== Remediating $StigId ===" -ForegroundColor Cyan

# ---------- 2. Check current value ----------
$current = (Get-ItemProperty -Path $RegPath -Name ValueName-ErrorActionSilentlyContinue).ValueName

if ($null -eq $current) {
    Write-Host "[-] Current value: not set (non-compliant - STIG requires it to be explicitly 0)"
} else {
    Write-Host "[-] Current value: $current"
}

# ---------- 3 & 4. Fix if needed ----------
if ($current -ne $RequiredValue) {
    try {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Write-Host "[+] Created registry key: $RegPath"
        }

        New-ItemProperty -Path $RegPath -Name $ValueName -Value $RequiredValue `
                         -PropertyType DWord -Force | Out-Null
        Write-Host "[+] Set $ValueName to $RequiredValue (disabled)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to set registry value: (_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[=] Already compliant - no change made." -ForegroundColor Green
}

# ---------- 5. Apply policy ----------
gpupdate /force | Out-Null
Write-Host "[+] Ran gpupdate /force"

# ---------- 6. Verify ----------
$final = (Get-ItemProperty -Path $RegPath -Name ValueName-ErrorActionSilentlyContinue).ValueName

if ($final -eq $RequiredValue) {
    Write-Host "[PASS] $StigId - AlwaysInstallElevated = $final" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] $StigId - AlwaysInstallElevated = $final" -ForegroundColor Red
    exit 1
}

