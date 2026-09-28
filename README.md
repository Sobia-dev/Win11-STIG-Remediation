# STIG - Security Technical Implementation Guide

STIG stands for Security Technical Implementation Guide. STIGs are required on DoD systems and private companies also use them as a strict baseline. They're hardening checklists published by DISA (the Defense Information Systems Agency, part of the U.S. Department of Defense). A STIG is made up of individual rules. Each rule has an ID (like V-253256), a description of the risk, a "check" (how to see if you're compliant), and a "fix" (how to fix it). A typical rule looks like "Account lockout must happen after 3 failed logons" or "SMBv1 must be disabled."

Every rule gets a severity category:

CAT I is high risk and can lead directly to compromise, like a default admin password.

CAT II is medium risk, and most rules fall here.

CAT III is low risk, more like good hygiene.

STIGs that I have implemented in this project (in-progress):

1. WN11-AU-OOO500
2. WN11-AU-000505
3. WN11-CC-000038
4. WN11-CC-000315
   

