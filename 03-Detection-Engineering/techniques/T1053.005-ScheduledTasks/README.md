# T1053.005 — Scheduled Task Creation

**Tactic:** Persistence  
**MITRE Link:** https://attack.mitre.org/techniques/T1053/005/  
**Status:** ✅ Complete

---

## Why Attackers Use This

Scheduled tasks are a built-in Windows mechanism for running programs automatically — at logon, at startup, on a time interval, or on a system event. Attackers abuse them to establish persistence that survives reboots, user logoffs, and basic cleanup, because:

- Tasks are stored in `C:\Windows\System32\Tasks\` as XML files — not registry keys
- They can run as SYSTEM without needing a logged-in user
- Task names can be disguised as legitimate Windows processes (`WindowsUpdate`, `SystemHealthCheck`)
- They can trigger payloads from arbitrary paths including writable user directories

**Real-world threat groups using this technique:** APT29, FIN6, Emotet, TrickBot, Cobalt Strike operators.

---

## Attack Scenario

Simulating a threat actor who has gained Administrator access and creates three scheduled tasks to maintain persistence:

1. A task triggering at every user logon — runs hidden PowerShell
2. A task running every 5 minutes — simulates a C2 beacon check-in
3. A task running at system startup — runs as SYSTEM

---

## Attack Commands Executed

```cmd
# Task 1 — Logon trigger (hidden PowerShell)
schtasks /create /tn "WindowsUpdate" /tr "powershell -WindowStyle Hidden -Command whoami" /sc onlogon /ru SYSTEM

# Task 2 — Recurring 5-minute trigger (C2 beacon simulation)
schtasks /create /tn "SystemHealthCheck" /tr "C:\Users\Public\payload.exe" /sc minute /mo 5

# Task 3 — Startup trigger running as SYSTEM
schtasks /create /tn "DriverUpdate" /tr "cmd /c whoami > C:\Users\Public\out.txt" /sc onstart /ru SYSTEM

# Query to confirm creation
schtasks /query /tn "WindowsUpdate" /fo LIST /v

# Cleanup
schtasks /delete /tn "WindowsUpdate" /f
schtasks /delete /tn "SystemHealthCheck" /f
schtasks /delete /tn "DriverUpdate" /f
```

---

## Logs Generated

See [logs-observed.md](./logs-observed.md) for full lab evidence.

| Log Source | Event ID | Description |
|------------|----------|-------------|
| Task Scheduler Operational | **106** | Task registered — fires on every `schtasks /create` |
| Task Scheduler Operational | **141** | Task deleted — fires on `schtasks /delete` |
| Windows Security | 4698 | Scheduled task created (requires audit policy) |
| Windows Security | 4699 | Scheduled task deleted (requires audit policy) |
| Sysmon | 1 | `schtasks.exe` process creation with full command line |

> **Lab note:** Sysmon was not installed on this lab machine. Task Scheduler Operational log (Event 106/141) was used as primary evidence source.

---

## Detection

- **Sigma Rule:** [sigma-rule.yml](./sigma-rule.yml)
- **Splunk SPL:** [splunk-spl.txt](./splunk-spl.txt)
- **Tuning Notes:** [tuning-notes.md](./tuning-notes.md)

---

## Screenshots

See [screenshots/](./screenshots/) for lab evidence.

---

## My Observations

Getting visibility into scheduled task creation took more setup than I expected. The Task Scheduler Operational log is disabled by default — I had to enable it through Event Viewer (right-click the log → Enable) before any events appeared. Event 4698 (task created in the Security log) also required enabling "Other Object Access Events" via `auditpol`. On a default Windows installation, you're blind to task creation events entirely.

Event 4698 showed 0 events until I ran the auditpol command. Once enabled, it populated. But I found Event 106 from the Task Scheduler Operational log to be more immediately useful because it fired reliably and contained the task name directly — so I used that as my primary evidence source and documented 4698 as a secondary.

The task names I used — `WindowsUpdate`, `SystemHealthCheck`, `DriverUpdate` — are deliberately chosen to blend in. They look legitimate to anyone glancing at Task Scheduler. The detection can't rely on name-based filtering; it has to look at the payload path and execution context. A task running from `C:\Users\Public\` or a temp directory and executing as SYSTEM is suspicious regardless of what it's named.

The correlated detection (task created, then deleted in the same session) ended up being one of the more interesting detection ideas from this technique. Attackers often create a task, use it, then delete it to clean up. The fact that a task was created *and* deleted in the same short window is itself suspicious — legitimate software installers create tasks but don't delete them hours later.
