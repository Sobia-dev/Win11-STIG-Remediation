# STIG - Security Technical Implementation Guide

STIG stands for Security Technical Implementation Guide. They're hardening checklists published by DISA (the Defense Information Systems Agency, part of the U.S. Department of Defense). Each one tells you exactly how to lock down a specific product securely, like Windows 11, Windows Server, Red Hat Linux, Cisco routers, SQL Server, or Chrome.

A STIG is made up of individual rules. Each rule has an ID (like V-253256), a description of the risk, a "check" (how to see if you're compliant), and a "fix" (how to fix it). A typical rule looks like "Account lockout must happen after 3 failed logons" or "SMBv1 must be disabled."

Every rule gets a severity category:

CAT I is high risk and can lead directly to compromise, like a default admin password.
CAT II is medium risk, and most rules fall here.
CAT III is low risk, more like good hygiene.

STIGs are required on DoD systems and common with government contractors. Plenty of private companies also use them as a strict baseline. They're similar to CIS Benchmarks, but STIGs are usually stricter and more focused on the military.

Some tools you'll run into:

STIG Viewer is DISA's free app for reading STIGs and filling in checklists.
SCAP Compliance Checker (SCC) scans a machine automatically against the STIG rules.
Tenable/Nessus has built-in DISA STIG audit files, so you can run compliance scans alongside your vulnerability scans. That's worth trying in your internship and your VM lab.
Group Policy and Intune are how you actually push many of the Windows STIG settings out to machines at scale.

A common workflow goes like this: scan against the STIG, review the failed rules, fix them (or document why a rule can't apply), then rescan to prove you're compliant. This kind of hands-on remediation shows up a lot in vulnerability management and SOC job postings, so it's a good resume skill.

The official STIGs are free to download at public.cyber.mil/stigs.
