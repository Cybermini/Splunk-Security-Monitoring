# Project 03 — Detection Engineering: MITRE ATT&CK Kill Chain to Sigma & Splunk

**Yamini Savalia** | SOC Analyst · CompTIA Security+ · CKA  
[LinkedIn](https://www.linkedin.com/in/yamini-savalia-387ab6100/) · [cybermini.com](https://cybermini.com)

---

## About This Project

I picked a ransomware kill chain as the scenario for this project because it's the most complete story in threat detection — it touches execution, persistence, credential theft, lateral movement, and impact all in one attack path. If I could build working detections for each stage, I'd have covered a significant chunk of what SOC analysts actually see during a real incident.

The methodology I followed for each technique: read the MITRE ATT&CK page, simulate the attack in an isolated Windows lab, capture the logs it generates, write a Sigma rule, convert it to Splunk SPL with sigma-cli, then document every legitimate scenario that could trigger a false positive.

What I did not do is write detection rules based on documentation alone. Every Sigma rule and SPL query here was validated against logs I actually generated.

---

## Kill Chain Covered

```
[Execution]          T1059.001 — PowerShell Abuse
        ↓
[Persistence]        T1053.005 — Scheduled Task Creation
        ↓
[Credential Access]  T1003.001 — LSASS Memory Dump
        ↓
[Lateral Movement]   T1021.002 — SMB / Admin Share Access
        ↓
[Impact]             T1486    — Data Encryption (Ransomware Simulation)
```

---

## Techniques

| # | Technique | MITRE ID | Tactic | Status |
|---|-----------|----------|--------|--------|
| 1 | [PowerShell Abuse](./techniques/T1059.001-PowerShell/) | T1059.001 | Execution | ✅ Complete |
| 2 | [Scheduled Task Creation](./techniques/T1053.005-ScheduledTasks/) | T1053.005 | Persistence | ✅ Complete |
| 3 | [LSASS Memory Dump](./techniques/T1003.001-LSASS-Dump/) | T1003.001 | Credential Access | ✅ Complete |
| 4 | [SMB Lateral Movement](./techniques/T1021.002-SMB-Lateral/) | T1021.002 | Lateral Movement | ✅ Complete |
| 5 | [Ransomware Simulation](./techniques/T1486-Ransomware-Sim/) | T1486 | Impact | ✅ Complete |

---

## My Methodology

For every technique I followed the same six steps:

1. **Study** — Read the MITRE ATT&CK technique page, understand what the attacker is doing and why
2. **Simulate** — Execute the attack in an isolated Windows lab (TryHackMe rooms with no internet access to production)
3. **Log Analysis** — Search Event Viewer and Splunk for what the attack left behind
4. **Sigma Rule** — Write the detection in Sigma YAML
5. **SPL Conversion** — Convert using sigma-cli, clean up the output, test against captured logs
6. **Tuning** — Think through every way this detection could fire on legitimate activity, add filters

Full methodology write-up: [methodology.md](./methodology.md)

---

## Things I Ran Into

This is the section that most documentation leaves out. These are real things that happened during the lab work:

**Windows logs almost nothing by default.**  
Out of the box, Windows Event 4688 (process creation) does not log command-line arguments. Event 4698 (scheduled task created) requires enabling "Other Object Access Events" in audit policy. I had to manually configure `auditpol` before I saw any useful process creation logs. If this is your environment, you're probably missing a lot.

**The default Sysmon config has gaps.**  
Sysmon Event 10 (Process Access) is not included in the default configuration — it requires an explicit `<ProcessAccess>` rule targeting `lsass.exe`. I ran the LSASS dump and got zero Event 10 logs. I documented this as a detection gap rather than pretending the log existed, and added the Sysmon XML config that would close it.

**SMB1 was disabled on the target.**  
When I tried to use smbclient for lateral movement simulation, the connection was refused because SMB1 is disabled by default on modern Windows. I switched to crackmapexec with SMB2, which gave me the same attack path and generated the same Event 4624 (Network Logon) and Event 5140 (File Share Access) logs. The detection logic didn't change at all — the log evidence is identical.

**vssadmin said "no items found."**  
The ransomware lab machine had no existing shadow copies, so `vssadmin delete shadows /all /quiet` returned a "no items found" message. The command still ran, and Sysmon Event 1 still captured the process execution and command line. The detection works regardless — we're watching for the command being executed, not for it to succeed.

**Sysmon Event 11 needed a config change.**  
Mass file encryption detection via Sysmon Event 11 (FileCreate) requires a FileCreate rule targeting `.encrypted` and similar extensions. The default Sysmon config doesn't include this. I documented the XML config addition needed and explained it as a hardening recommendation.

**I used comsvcs.dll instead of Mimikatz.**  
The lab environment I was using had no internet access, so I couldn't download Mimikatz. I used the built-in `comsvcs.dll` MiniDump method via rundll32 instead — this is actually a more realistic simulation since it uses a Windows-native binary (a LOLBin), which is exactly how real attackers avoid EDR tools that flag known malware.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Sysmon (Sysinternals) | Enhanced Windows event logging (Process Create, Process Access, File Create) |
| Windows Event Viewer | Viewing raw Security and Task Scheduler logs |
| Sigma | Detection rule language (YAML) |
| sigma-cli | Converting Sigma rules to Splunk SPL |
| Splunk Enterprise (Free) | Testing and validating SPL queries |
| crackmapexec | SMB lateral movement simulation |
| TryHackMe | Isolated Windows lab environments |

---

## Repository Structure

```
03-Detection-Engineering/
├── techniques/
│   ├── T1059.001-PowerShell/       ← PowerShell abuse (Execution)
│   ├── T1053.005-ScheduledTasks/   ← Scheduled task persistence
│   ├── T1003.001-LSASS-Dump/       ← LSASS memory dump (Credential Access)
│   ├── T1021.002-SMB-Lateral/      ← SMB lateral movement
│   └── T1486-Ransomware-Sim/       ← Ransomware impact simulation
├── sigma-rules/                    ← All Sigma YAML rules in one place
├── splunk-queries/                 ← All SPL queries in one place
└── methodology.md                  ← Full 6-step process documented
```

Each technique folder contains:
- `README.md` — technique overview, attack scenario, what logs to expect
- `logs-observed.md` — actual log evidence from the lab (real Event IDs, real values)
- `sigma-rule.yml` — Sigma detection rule
- `splunk-spl.txt` — Converted SPL queries (multiple variants)
- `tuning-notes.md` — False positive scenarios and how to handle them
- `screenshots/` — Screenshots from the live lab session
