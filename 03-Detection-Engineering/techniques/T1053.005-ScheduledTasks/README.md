# T1053.005 — Scheduled Task Creation

**Tactic:** Persistence  
**MITRE Link:** https://attack.mitre.org/techniques/T1053/005/  
**Status:** ⏳ Planned

---

## Why Attackers Use This

Scheduled tasks allow attackers to maintain persistent access across reboots without modifying registry run keys. A malicious task can re-execute a payload at login, on a time interval, or on a system event — surviving reboots, user logoffs, and basic cleanup.

**Key logs generated:**
- Event ID 4698 — Scheduled task created (Windows Security)
- Event ID 4702 — Scheduled task updated
- Sysmon Event ID 1 — `schtasks.exe` process creation with full command line

---

*Content coming soon — lab simulation in progress.*
