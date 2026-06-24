# T1486 — Data Encrypted for Impact (Ransomware Simulation)

**Tactic:** Impact  
**MITRE Link:** https://attack.mitre.org/techniques/T1486/  
**Status:** ⏳ Planned

---

## Why Attackers Use This

Ransomware operators encrypt files to extort victims. Detection at this stage is the last line of defense — the goal is to detect encryption behavior early enough to contain the blast radius. Key indicators include mass file renaming, extension changes, shadow copy deletion (`vssadmin delete shadows`), and high-volume file write operations in short time windows.

**Key logs generated:**
- Sysmon Event ID 11 — FileCreate (mass file creation/rename with new extension)
- Event ID 4688 — `vssadmin.exe delete shadows /all` process creation
- Event ID 7045 — Ransomware service installation
- Sysmon Event ID 1 — `wmic.exe shadowcopy delete` execution

---

*Content coming soon — lab simulation in progress.*
