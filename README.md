# STIG - Security Technical Implementation Guide

Author: SR (Sobia-dev) · Environment: Windows 11 VM in Azure · Tools: PowerShell, Tenable Vulnerability Management, Registry, Group Policy

STIG stands for Security Technical Implementation Guide. STIGs are required on DoD systems and private companies also use them as a strict baseline. They're hardening checklists published by DISA (the Defense Information Systems Agency, part of the U.S. Department of Defense). A STIG is made up of individual rules. Each rule has an ID (like V-253256), a description of the risk, a "check" (how to see if you're compliant), and a "fix" (how to fix it). A typical rule looks like "Account lockout must happen after 3 failed logons" or "SMBv1 must be disabled."

## What I Did

Scanned a Windows 11 VM against the DISA Windows 11 STIG using Tenable
Wrote PowerShell scripts to fix failed audit checks (check → fix → verify → PASS/FAIL)
Verified fixes with reg query, event logs and Tenable rescans
Documented each fix with before/after evidence on GitHub

Every rule gets a severity category:

CAT I is high risk and can lead directly to compromise, like a default admin password.

CAT II is medium risk, and most rules fall here.

CAT III is low risk, more like good hygiene.

STIGs that I have implemented in this project (in-progress):

| STIG ID | What It Fixes | Why It Matters | How I Fixed It |
|---|---|---|---|
| **WN11-AU-000500** | Application log size ≥ 32 MB | Keeps app logs from being overwritten too fast | Registry `MaxSize = 32768` |
| **WN11-AU-000505** | Security log size ≥ ~4.9 GB | Keeps logon/attack evidence for investigations | Registry `MaxSize = 5120000` |
| **WN11-CC-000038** | Turns off WDigest | Stops passwords being kept in memory in plain text (credential theft – T1003.001) | Registry `UseLogonCredential = 0` |
| **WN11-CC-000315** | Blocks "Always install elevated" | Stops normal users installing software as SYSTEM (privilege escalation – T1548) | Registry `AlwaysInstallElevated = 0` |
| **WN11-CC-000180** | AutoPlay off for phones/cameras | Blocks auto-actions from plugged-in devices | Registry `NoAutoplayfornonVolume = 1` |
| **WN11-CC-000185** | Blocks AutoRun commands | Stops USBs auto-launching programs (T1091) | Registry `NoAutorun = 1` |
| **WN11-CC-000190** | AutoPlay off for all drives | Closes USB-based malware spread | Registry `NoDriveTypeAutoRun = 255` |
| **WN11-CC-000326** | PowerShell script block logging | Records the real code PowerShell runs, even if hidden (Event 4104 → SIEM) | Registry `EnableScriptBlockLogging = 1` |
| **WN11-CC-000327** | PowerShell transcription | Saves full PowerShell sessions (commands + output) for investigations | Registry `EnableTranscripting = 1` |

## Problems I Solved

Failed fix → root cause found: WN11-AU-000505 still failed after my first fix. Tenable's Actual vs. Policy Value showed my value (1024000) came from a deprecated STIG version; the current audit needed 5120000. Updated script → Passed.
Antivirus block: Windows Defender (AMSI) blocked a script because its comments named real attack tools. Rewrote the comments in general terms → script ran. Showed how AMSI inspects PowerShell.
Ruled out policy overrides with gpresult before changing anything.

## Skills Shown

Vulnerability management & compliance scanning (Tenable)

Windows hardening (Registry, Group Policy)

PowerShell scripting & automation

Troubleshooting & root-cause analysis

Mapping fixes to MITRE ATT&CK

Technical documentation (GitHub)


---

   

