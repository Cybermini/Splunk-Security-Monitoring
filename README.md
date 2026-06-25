# Detection Engineering Lab

**Yamini Savalia** | SOC Analyst · CompTIA Security+ · CKA  
[LinkedIn](https://www.linkedin.com/in/yamini-savalia-387ab6100/) · [cybermini.com](https://cybermini.com)

---

I have spent four years working SOC alerts — triaging EDR hits, investigating phishing, pulling logs during incidents. But at some point I started wondering: how do these detections actually get built? Who wrote the original rule that caught the thing I'm investigating?

That question is what led to this project.

This repo documents my path from learning SPL basics all the way to authoring production-grade detection rules from scratch — picking a real MITRE ATT&CK technique, simulating it in an isolated lab, capturing the actual logs it generates, writing a Sigma rule, converting it to Splunk SPL, and working through every scenario that would cause it to fire incorrectly in production.

The detection engineering project (Project 03) took the most time. I ran every technique myself in a lab environment and documented exactly what I observed — including the things that didn't work the way I expected, the detection gaps I found in default Windows configurations, and the places where I had to adapt on the fly.

---

## Projects

| # | Project | What It Covers |
|---|---------|----------------|
| 01 | [SPL Query Language — Windows Event Log Analysis](./01-SPL-Query-Language/) | SPL search syntax, field extraction, transforming commands, statistical analysis, anomaly detection patterns |
| 02 | [SOC Lab Setup — Splunk Installation, Log Ingestion, Dashboards & Alerting](./02-SOC-Lab-Setup/) | Splunk Enterprise + Universal Forwarder, custom indexes, saved searches, dashboards, real-time alert triggers |
| 03 | [Detection Engineering — MITRE ATT&CK Kill Chain to Sigma Rules & Splunk SPL](./03-Detection-Engineering/) | Full adversary simulation across a ransomware kill chain, Sigma YAML rule authoring, sigma-cli conversion, false positive tuning |

---

## Skills Demonstrated

- Writing Sigma detection rules (YAML) and converting them to Splunk SPL using sigma-cli
- Windows audit policy configuration and Sysmon deployment for enhanced log visibility
- Reading and interpreting Security, Sysmon, and Task Scheduler event logs
- MITRE ATT&CK framework — mapping observed behaviors to techniques and tactics
- Detection tuning — identifying false positive scenarios and writing exclusion logic
- Lab-based adversary simulation using isolated Windows environments

---

## Tech Stack

`Splunk Enterprise` · `Sysmon (Sysinternals)` · `Sigma / sigma-cli` · `Windows Event Logs` · `MITRE ATT&CK` · `crackmapexec` · `TryHackMe`

---

*All Sigma rules, SPL queries, and log samples in this repo came out of real hands-on lab work. The screenshots in each technique folder are from my actual lab sessions.*
