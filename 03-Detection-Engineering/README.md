# Project 03 — Detection Engineering: MITRE ATT&CK Sigma Rules to Splunk

**Author:** [Yamini Savalia](https://www.linkedin.com/in/yamini-savalia-387ab6100/) — SOC Analyst | CompTIA Security+ | CKA  
**Portfolio:** [cybermini.com](https://cybermini.com)

---

## Threat Scenario

This project simulates a financially motivated threat actor executing a ransomware attack against a Windows environment. Five techniques from the MITRE ATT&CK framework are covered end-to-end — from adversary simulation in an isolated lab to production-ready Sigma detection rules converted to Splunk SPL.

---

## Attack Kill Chain

```
[Execution]          T1059.001 — PowerShell Abuse
       ↓
[Persistence]        T1053.005 — Scheduled Task Creation
       ↓
[Credential Access]  T1003.001 — LSASS Memory Dump (Mimikatz)
       ↓
[Lateral Movement]   T1021.002 — SMB / Admin Share Access
       ↓
[Impact]             T1486    — Data Encryption (Ransomware Simulation)
```

---

## Detection Engineering Methodology

For each technique:
1. **Study** — MITRE ATT&CK technique page reviewed
2. **Simulate** — Attack executed in isolated Windows lab environment
3. **Log Analysis** — Windows Event IDs and Sysmon events captured
4. **Sigma Rule** — Detection rule authored in Sigma YAML
5. **SPL Conversion** — Rule converted to Splunk search using sigma-cli
6. **Tuning** — False positive scenarios documented and filtered

Full methodology: [methodology.md](./methodology.md)

---

## Techniques Covered

| # | Technique | MITRE ID | Tactic | Status |
|---|-----------|----------|--------|--------|
| 1 | [PowerShell Abuse](./techniques/T1059.001-PowerShell/) | T1059.001 | Execution | ✅ Complete |
| 2 | [Scheduled Task Creation](./techniques/T1053.005-ScheduledTasks/) | T1053.005 | Persistence | ✅ Complete |
| 3 | [LSASS Memory Dump](./techniques/T1003.001-LSASS-Dump/) | T1003.001 | Credential Access | ✅ Complete |
| 4 | [SMB Lateral Movement](./techniques/T1021.002-SMB-Lateral/) | T1021.002 | Lateral Movement | ⏳ Planned |
| 5 | [Ransomware Simulation](./techniques/T1486-Ransomware-Sim/) | T1486 | Impact | ⏳ Planned |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Sysmon (Sysinternals) | Enhanced Windows event logging |
| Windows Event Viewer | Native log collection |
| Sigma | Detection rule language |
| sigma-cli | Sigma → SPL conversion |
| Splunk Enterprise (Free) | SPL query testing |
| Isolated Windows Lab | Attack simulation environment |

---

## Repository Layout

```
03-Detection-Engineering/
├── techniques/          ← One folder per MITRE technique (study → simulate → detect → tune)
├── sigma-rules/         ← All Sigma YAML rules collected in one place
└── splunk-queries/      ← All converted SPL queries collected in one place
```
