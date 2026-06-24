# Tuning Notes — T1059.001 PowerShell Abuse

Detection tuning is the difference between a rule that fires constantly (alert fatigue) and one that fires reliably (actionable alerts). Below are the false positive scenarios identified during testing and how each was handled.

---

## False Positive 1 — Microsoft Exchange Server Management

**Scenario:** Exchange health check scripts run daily using `-ExecutionPolicy Bypass`.

**Evidence:** `ParentImage` was `C:\Program Files\Microsoft\Exchange Server\V15\bin\MSExchangeMailboxReplication.exe`

**Fix Applied:** Exclude by `ParentImage` path containing `Exchange Server`.

```yaml
filter_legitimate_admin:
  ParentImage|contains:
    - 'C:\Program Files\Microsoft\Exchange Server'
```

**Why this is safe:** Exchange is a known and specific path. Attackers do not typically masquerade under this exact parent.

---

## False Positive 2 — Software Installers (SCCM / Intune)

**Scenario:** Endpoint management agents (SCCM, Intune) push software updates using hidden PowerShell windows.

**Evidence:** `CommandLine` contained `-WindowStyle Hidden` with `ParentImage` of `ccmexec.exe` or `intunemanagementextension.exe`.

**Fix Applied:** Exclude known management agent parent processes.

```yaml
filter_management_agents:
  ParentImage|endswith:
    - '\ccmexec.exe'
    - '\IntuneManagementExtension.exe'
```

---

## False Positive 3 — Developer / DevOps Tooling

**Scenario:** Developers running build scripts with `-NonInteractive -NoProfile` flags in CI pipelines.

**Evidence:** `User` context was a service account (`svc-build`), `ParentImage` was Jenkins or Azure DevOps agent.

**Fix Applied:** Add user-context exclusion for known build service accounts (environment-specific — must be documented per deployment).

**Recommendation:** Rather than blanket-excluding service accounts, lower the severity to `informational` for known CI parent processes and alert at `medium` for everything else.

---

## Remaining Risk After Tuning

| Scenario | Risk Level | Notes |
|----------|-----------|-------|
| Encoded command from `cmd.exe` | High | No legitimate business need for encoded PS from interactive shell |
| `-WindowStyle Hidden` from `winword.exe` / `excel.exe` | Critical | Office spawning hidden PowerShell = likely macro-based malware |
| `-ExecutionPolicy Bypass` from user profile path | High | Admin tools run from Program Files, not user Desktop/Downloads |
| Download cradle (`Invoke-WebRequest`, `Net.WebClient`) | High | Rare in legitimate automation without a known software installer context |

---

## Final Recommended Alert Thresholds

| Condition | Severity |
|-----------|---------|
| PowerShell + EncodedCommand from Office app parent | Critical |
| PowerShell + download cradle flags | High |
| PowerShell + bypass/hidden flags (no known parent exclusion) | Medium |
| PowerShell + -NoProfile -NonInteractive from service account | Low / Informational |
