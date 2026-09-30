<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000326 on Windows 11.

.DESCRIPTION
    WN11-CC-000326: PowerShell script block logging must be enabled.

    Records the actual code PowerShell runs (even if obfuscated/encoded)
    as Event ID 4104 in:
      Microsoft-Windows-PowerShell/Operational

    Registry location:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
      Value: EnableScriptBlockLogging (REG_DWORD) = 1

    WHY IT MATTERS:
      - Attackers "live off the land" with PowerShell because it is
        built into every Windows machine and trusted by default.
      - They often hide commands with encoding/obfuscation.
        PowerShell must decode the code before it runs - script
        block logging records it at that moment, in plain readable
        text.
      - Event ID 4104 can be sent to a SIEM (e.g. Microsoft Sentinel)
        to detect suspicious activity such as credential dumping
        tools, remote downloads or encoded commands.
      - During incident response it shows exactly what code ran,
        when, and under which account.
      - MITRE ATT&CK: helps detect T1059.001 (PowerShell) and
        T1027 (Obfuscated Files or Information).

    MANUAL FIX (without this script - run in admin PowerShell):
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
      gpupdate /force

    MANUAL FIX (Command Prompt / reg.exe - one line):
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

    MANUAL FIX (Group Policy):
      gpedit.msc > Computer Configuration > Administrative Templates >
      Windows Components > Windows PowerShell >
      "Turn on PowerShell Script Block Logging" > Enabled

    VERIFY:
      reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging
        (expect 0x1)
      Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 | Where-Object Id -eq 4104 | Select-Object TimeCreated, Message
        (expect recent 4104 events - open a NEW PowerShell window first)

.NOTES
    STIG ID     : WN11-CC-000326
    Severity    : CAT II
    Author      : SR
    Tested on   : Windows 11
#>

# ---------- Settings ----------
$StigId        = "WN11-CC-000326"
$RegPath       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$ValueName     = "EnableScriptBlockLogging"
$RequiredValue = 1

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
        Write-Host "[+] Set $ValueName to $RequiredValue (script block logging ON)" -ForegroundColor Green
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

if ($final -eq $RequiredValue) {
    Write-Host "[PASS] $StigId - EnableScriptBlockLogging = $final" -ForegroundColor Green
    Write-Host "[i] Open a NEW PowerShell window, run a command, then check Event ID 4104."
    exit 0
} else {
    Write-Host "[FAIL] $StigId - EnableScriptBlockLogging = $final" -ForegroundColor Red
    exit 1
}
