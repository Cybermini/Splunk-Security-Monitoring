# T1003.001 — LSASS Memory Dump (Credential Access)

**Tactic:** Credential Access  
**MITRE Link:** https://attack.mitre.org/techniques/T1003/001/  
**Status:** ✅ Complete

---

## Why Attackers Use This

LSASS (Local Security Authority Subsystem Service) is the Windows process responsible for authentication. It stores credentials in memory including:
- NTLM password hashes
- Kerberos tickets
- Cleartext passwords (on older systems)

Dumping LSASS memory gives attackers everything needed for **Pass-the-Hash**, **Pass-the-Ticket**, and **lateral movement** without ever knowing the plaintext password.

**Technique used:** `comsvcs.dll MiniDump` — a Living Off the Land (LOLBin) method using a Microsoft-signed Windows DLL. Modern threat actors prefer this over Mimikatz because:
- `comsvcs.dll` is signed by Microsoft — bypasses many AV signatures
- No external tooling needed — uses a built-in Windows binary (`rundll32.exe`)
- Same credential access result as Mimikatz with lower detection surface

**Real-world threat groups using this technique:** LAPSUS$, BlackCat/ALPHV, Conti, APT29, Cobalt Strike operators.

---

## Attack Scenario

Simulating a threat actor who has gained Administrator access and dumps LSASS memory using the built-in `comsvcs.dll` method to extract credentials for lateral movement.

---

## Attack Commands Executed

```powershell
# Step 1 — Identify lsass PID
Get-Process lsass

# Step 2 — Dump lsass memory using comsvcs.dll (LOLBin)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 632 C:\Users\Public\lsass.dmp full

# Step 3 — Confirm dump created
dir C:\Users\Public\lsass.dmp
```

**Result:** `lsass.dmp` created at `C:\Users\Public\` — 145 MB dump file containing credential material.

---

## Logs Generated

See [logs-observed.md](./logs-observed.md) for full lab evidence.

| Log Source | Event ID | Description | Captured |
|------------|----------|-------------|----------|
| Sysmon | **1** | Process creation — `rundll32.exe` with `comsvcs.dll MiniDump` command line | ✅ |
| Sysmon | **10** | Process access to `lsass.exe` | ⚠️ Requires ProcessAccess config |
| Windows Security | 4688 | Process creation with command line | ⚠️ Requires audit policy |

> **Lab note:** Sysmon Event ID 10 requires an explicit `ProcessAccess` rule in the Sysmon configuration XML. Without it, lsass memory access is not logged. This represents a common detection gap in environments running default Sysmon deployments. See tuning-notes.md for the configuration fix.

---

## Detection

- **Sigma Rule:** [sigma-rule.yml](./sigma-rule.yml)
- **Splunk SPL:** [splunk-spl.txt](./splunk-spl.txt)
- **Tuning Notes:** [tuning-notes.md](./tuning-notes.md)

---

## Screenshots

See [screenshots/](./screenshots/) for lab evidence.

---

## My Observations

The lab environment I used had no internet access, which meant I couldn't download Mimikatz. I switched to the `comsvcs.dll` MiniDump method instead — and honestly, this ended up being more realistic. Modern ransomware operators don't use raw Mimikatz because it gets flagged. They use LOLBins like this one. `comsvcs.dll` is signed by Microsoft, ships with every Windows install, and produces the same output. The detection still catches it — if anything, simulating the more evasive version is better for testing.

Sysmon Event 10 (Process Access) did not fire at all. I searched extensively and got zero results. The reason is that the default Sysmon configuration doesn't include a `<ProcessAccess>` rule targeting `lsass.exe`. This is a real detection gap I would not have found without actually testing — documentation says Event 10 is how you detect LSASS dumping, but if the Sysmon config doesn't include that rule, you never see it. I documented the XML config addition and moved on to Event 1 as the primary evidence source.

The 145 MB dump file at `C:\Users\Public\lsass.dmp` is itself interesting as an artifact. A `.dmp` file in a public, world-writable directory is inherently suspicious — that's not where crash dumps normally go. I added the file path detection to the SPL queries for this reason.

The LSASS PID (632 in my lab) will change every boot, so detections can't hardcode PIDs. The command line pattern — `rundll32.exe ... comsvcs.dll MiniDump` — is consistent regardless of the PID used and is the right detection anchor.
