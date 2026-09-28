<#
.SYNOPSIS
    Remediates DISA STIG WN11-CC-000180, WN11-CC-000185 and WN11-CC-000190 (AutoPlay / AutoRun) on Windows 11.

.DESCRIPTION
    WN11-CC-000180: AutoPlay must be turned off for non-volume devices. 
    Non-volume devices are things that don't show up as a drive letter, like phones, cameras, and MP3 players. 
    With this set to 1, Windows won't pop up or act automatically when you plug one in. Without it, a malicious phone or gadget could trigger an action on connect.
      HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer
      NoAutoplayfornonVolume (REG_DWORD) = 1

    WN11-CC-000185: The default AutoRun behavior must be configured to prevent AutoRun commands.
    Old USB drives and CDs could hold a file called autorun.inf that told Windows which program to launch automatically. 
    With this set to 1, Windows ignores those instructions. Worms like Conficker spread this way.
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
      NoAutorun (REG_DWORD) = 1

   WN11-CC-000190: AutoPlay must be disabled for all drives.
   0xff is 255 in hex. It's a bitmask, meaning each bit stands for a drive type: USB, hard drive, CD, network drive, and so on. 
   0xff sets every bit, so AutoPlay is off for every drive type.
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
      NoDriveTypeAutoRun (REG_DWORD) = 255 (0xFF)

    Why: AutoPlay/AutoRun can launch code automatically when a USB drive, CD or phone is plugged in.
    Together these STIGs block malware from spreading through plugged-in media (MITRE ATT&CK T1091 – Replication Through Removable Media).

.NOTES
    Severity    : CAT I (000185, 000190) / CAT II (000180) - confirm in your scan
    Author      : SR
    Tested on   : Windows 11
#>

# ---------- Settings (one row per STIG rule) ----------
$Rules = @(
    @{ StigId = "WN11-CC-000180"
       Path   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
       Name   = "NoAutoplayfornonVolume"
       Value  = 1 },

    @{ StigId = "WN11-CC-000185"
       Path   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
       Name   = "NoAutorun"
       Value  = 1 },

    @{ StigId = "WN11-CC-000190"
       Path   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
       Name   = "NoDriveTypeAutoRun"
       Value  = 255 }
)

# ---------- 1. Admin check ----------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$failCount = 0

# ---------- 2. Loop through each rule ----------
foreach ($rule in $Rules) {
    Write-Host ""
    Write-Host "=== Remediating $($rule.StigId) ===" -ForegroundColor Cyan

    # Check current value
    $current = (Get-ItemProperty -Path $rule.Path -Name $rule.Name -ErrorAction SilentlyContinue).($rule.Name)

    if ($null -eq $current) {
        Write-Host "[-] $($rule.Name): not set (non-compliant)"
    } else {
        Write-Host "[-] $($rule.Name): $current"
    }

    # Fix if needed
    if ($current -ne $rule.Value) {
        try {
            if (-not (Test-Path $rule.Path)) {
                New-Item -Path $rule.Path -Force | Out-Null
                Write-Host "[+] Created registry key: $($rule.Path)"
            }
            New-ItemProperty -Path $rule.Path -Name $rule.Name -Value $rule.Value `
                             -PropertyType DWord -Force | Out-Null
            Write-Host "[+] Set $($rule.Name) to $($rule.Value)" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[=] Already compliant - no change made." -ForegroundColor Green
    }

    # Verify
    $final = (Get-ItemProperty -Path $rule.Path -Name $rule.Name -ErrorAction SilentlyContinue).($rule.Name)
    if ($final -eq $rule.Value) {
        Write-Host "[PASS] $($rule.StigId) - $($rule.Name) = $final" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $($rule.StigId) - $($rule.Name) = $final" -ForegroundColor Red
        $failCount++
    }
}

# ---------- 3. Apply policy ----------
gpupdate /force | Out-Null
Write-Host ""
Write-Host "[+] Ran gpupdate /force"

# ---------- 4. Summary ----------
if ($failCount -eq 0) {
    Write-Host "[DONE] All 3 AutoPlay/AutoRun rules PASSED." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[DONE] $failCount rule(s) FAILED - review output above." -ForegroundColor Red
    exit 1
}
