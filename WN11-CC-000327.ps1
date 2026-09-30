<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000327 on Windows 11.

.DESCRIPTION
    WN11-CC-000327: PowerShell Transcription must be enabled.

    Saves a plain-text record of every PowerShell session - what was
    typed AND what the computer returned.

    Registry location:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
      Value: EnableTranscripting (REG_DWORD) = 1

    WHY IT MATTERS:
      - Script block logging (WN11-CC-000326) records the code that
        ran. Transcription records the whole session: commands in
        order plus their output.
      - Output shows what an attacker actually learned (usernames,
        files, network details), which helps scope an incident.
      - Transcripts are plain text files, so they are easy to read
        and collect without special tools.
      - Together with script block logging, gives incident
        responders the what, the how and the result.
      - MITRE ATT&CK: supports detection of T1059.001 (PowerShell).

    MANUAL FIX (admin PowerShell):
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -Value 1 -Type DWord
      gpupdate /force

    MANUAL FIX (Command Prompt / reg.exe - one line):
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f

    MANUAL FIX (Group Policy):
      gpedit.msc > Computer Configuration > Administrative Templates >
      Windows Components > Windows PowerShell >
      "Turn on PowerShell Transcription" > Enabled

    VERIFY:
      reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting
        (expect 0x1)
      Open a NEW PowerShell window, run a command, then look for a
      PowerShell_transcript.*.txt file under the user's Documents
      folder (in a dated subfolder, e.g. Documents\20260930).

.NOTES
    STIG ID     : WN11-CC-000327
    Severity    : CAT II
    Author      : SR
    Tested on   : Windows 11
#>

# ---------- Settings ----------
$StigId        = "WN11-CC-000327"
$RegPath       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$ValueName     = "EnableTranscripting"
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
        Write-Host "[+] Set $ValueName to $RequiredValue (transcription ON)" -ForegroundColor Green
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
    Write-Host "[PASS] $StigId - EnableTranscripting = $final" -ForegroundColor Green
    Write-Host "[i] Open a NEW PowerShell window and run a command - a transcript file should appear in Documents."
    exit 0
} else {
    Write-Host "[FAIL] $StigId - EnableTranscripting = $final" -ForegroundColor Red
    exit 1
}
