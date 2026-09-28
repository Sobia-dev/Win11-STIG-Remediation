<##
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000038 on Windows 11.

.DESCRIPTION
    WN11-CC-000038: WDigest Authentication must be disabled.

    When WDigest is enabled, Windows keeps user passwords in memory
    (LSASS) in plain text, where tools like Mimikatz can dump them.

    Registry location:
      HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
      Value: UseLogonCredential (REG_DWORD) = 0

.NOTES
    STIG ID     : WN11-CC-000038
    Severity    : CAT II
    Author      : SR
    Tested on   : Windows 11
#>

# ---------- Settings ----------
$StigId        = "WN11-CC-000038"
$RegPath       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$ValueName     = "UseLogonCredential"
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
        Write-Host "[+] Set $ValueName to $RequiredValue (WDigest disabled)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to set registry value: (_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[=] Already compliant - no change made." -ForegroundColor Green
}

# ---------- 5. Verify ----------
$final = (Get-ItemProperty -Path $RegPath -Name ValueName-ErrorActionSilentlyContinue).ValueName

if ($final -eq $RequiredValue) {
    Write-Host "[PASS] $StigId - UseLogonCredential = $final" -ForegroundColor Green
    Write-Host "[i] Restart recommended so no plaintext credentials remain in memory."
    exit 0
} else {
    Write-Host "[FAIL] $StigId - UseLogonCredential = $final" -ForegroundColor Red
    exit 1
}

