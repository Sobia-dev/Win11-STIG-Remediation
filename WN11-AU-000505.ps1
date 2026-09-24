<#
.SYNOPSIS
    Remediates DISA STIG WN11-AU-000505 on Windows 11.

.DESCRIPTION
    WN11-AU-000505: The Security event log size must be configured to
    5120000 KB or greater (per current Tenable audit Policy Value).

    Registry location:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security
      Value: MaxSize (REG_DWORD) = 5120000 (0x4E2000) or greater

.NOTES
    STIG ID     : WN11-AU-000505
    Severity    : CAT II
    Author      : SR
    Tested on   : Windows 11
    Change log  : Updated from 1024000 KB (STIG v1r4) to 5120000 KB
                  to match current Tenable audit Policy Value.
#>

# ---------- Settings ----------
$StigId       = "WN11-AU-000505"
$RegPath      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$ValueName    = "MaxSize"
$RequiredSize = 5120000   # KB

# ---------- 1. Admin check ----------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "=== Remediating $StigId ===" -ForegroundColor Cyan

# ---------- 2. Check current value ----------
$current = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($null -eq $current) {
    Write-Host "[-] Current value: not set (non-compliant)"
} else {
    Write-Host "[-] Current value: $current KB"
}

# ---------- 3 & 4. Fix if needed ----------
if ($null -eq $current -or $current -lt $RequiredSize) {
    try {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Write-Host "[+] Created registry key: $RegPath"
        }

        New-ItemProperty -Path $RegPath -Name $ValueName -Value $RequiredSize `
                         -PropertyType DWord -Force | Out-Null
        Write-Host "[+] Set $ValueName to $RequiredSize KB" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to set registry value: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[=] Already compliant - no change made." -ForegroundColor Green
}

# ---------- 5. Apply policy ----------
gpupdate /force | Out-Null
Write-Host "[+] Ran gpupdate /force"

# ---------- 6. Verify ----------
$final = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
$live  = (Get-WinEvent -ListLog Security).MaximumSizeInBytes

Write-Host "[i] Registry MaxSize      : $final KB"
Write-Host "[i] Live log max size     : $live bytes (target: $($RequiredSize * 1024))"

if ($final -ge $RequiredSize) {
    Write-Host "[PASS] $StigId - Security log MaxSize = $final KB" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] $StigId - Security log MaxSize = $final KB" -ForegroundColor Red
    exit 1
}
