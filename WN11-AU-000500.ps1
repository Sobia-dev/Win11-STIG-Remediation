<#
.SYNOPSIS
    Remediates DISA STIG WN11-AU-000500 on Windows 11.

.DESCRIPTION
    WN11-AU-000500: The Application event log size must be configured to 32768 KB or greater. Why it matters: Windows sets a small default size for the Application log.
    Once the log fills up, the oldest events get overwritten, and during an investigation that can mean the evidence you need is already gone. A bigger log keeps more history.

    This script:
      1. Confirms it is running as Administrator
      2. Checks the current MaxSize policy value
      3. Creates the registry key if it does not exist
      4. Sets MaxSize to 32768 KB (only if missing or too small)
      5. Verifies the result and reports PASS/FAIL

    Registry location:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
      Value: MaxSize (REG_DWORD) = 32768 (0x8000) or greater

.NOTES
    STIG ID     : WN11-AU-000500
    Severity    : CAT II
    Author      : Sobia R.
    Tested on   : Windows 11

.USAGE
    Run in PowerShell as Administrator:
      PS C:\> .\WN11-AU-000500_Remediation.ps1

    If script execution is blocked, run it once with:
      PS C:\> powershell.exe -ExecutionPolicy Bypass -File .\WN11-AU-000500_Remediation.ps1
#>

# ---------- Settings ----------
$StigId       = "WN11-AU-000500"
$RegPath      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName    = "MaxSize"
$RequiredSize = 32768   # KB

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

# ---------- 5. Verify ----------
$final = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

if ($final -ge $RequiredSize) {
    Write-Host "[PASS] $StigId - Application log MaxSize = $final KB" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] $StigId - Application log MaxSize = $final KB" -ForegroundColor Red
    exit 1
}
