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
