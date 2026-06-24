# T1021.002 — SMB / Windows Admin Shares (Lateral Movement)

**Tactic:** Lateral Movement  
**MITRE Link:** https://attack.mitre.org/techniques/T1021/002/  
**Status:** ⏳ Planned

---

## Why Attackers Use This

After obtaining credentials (often via LSASS dump), attackers use SMB to move laterally to other machines using built-in Windows admin shares (`ADMIN$`, `C$`, `IPC$`). Tools like PsExec, Impacket, and CrackMapExec automate this. Pass-the-hash attacks allow movement without knowing the plaintext password.

**Key logs generated:**
- Event ID 4624 — Logon Type 3 (Network logon) on target machine
- Event ID 4648 — Explicit credential logon
- Event ID 5140 — Network share object accessed
- Sysmon Event ID 3 — Network connection from lateral movement tool

---

*Content coming soon — lab simulation in progress.*
