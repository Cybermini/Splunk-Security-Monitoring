# T1003.001 — LSASS Memory Dump

**Tactic:** Credential Access  
**MITRE Link:** https://attack.mitre.org/techniques/T1003/001/  
**Status:** ⏳ Planned

---

## Why Attackers Use This

LSASS (Local Security Authority Subsystem Service) stores credentials in memory for single sign-on. Dumping LSASS memory with tools like Mimikatz (`sekurlsa::logonpasswords`) extracts plaintext passwords, NTLM hashes, and Kerberos tickets — enabling pass-the-hash and pass-the-ticket attacks.

**Key logs generated:**
- Sysmon Event ID 10 — Process access to lsass.exe
- Event ID 4656 — Handle request to lsass.exe object (Security log)
- Windows Defender alerts (if enabled)

---

*Content coming soon — lab simulation in progress.*
