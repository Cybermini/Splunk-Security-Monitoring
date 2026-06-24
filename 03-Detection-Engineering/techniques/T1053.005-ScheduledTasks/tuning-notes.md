# Tuning Notes — T1053.005 Scheduled Task Creation

---

## False Positive 1 — Software Installers

**Scenario:** Applications like Adobe, Chrome, Java, and antivirus products create scheduled tasks during installation using `schtasks /create` with `cmd /c` or PowerShell.

**Evidence:** `ParentImage` is typically an installer (e.g., `setup.exe`, `msiexec.exe`) running from `C:\Program Files\` or `C:\Windows\Installer\`.

**Fix:** Exclude by parent image path and known software task name patterns:

```yaml
filter_installers:
  ParentImage|contains:
    - 'C:\Windows\Installer\'
    - '\msiexec.exe'
  CommandLine|contains:
    - 'Adobe'
    - 'GoogleUpdate'
    - 'MicrosoftEdge'
```

---

## False Positive 2 — SCCM / Intune Endpoint Management

**Scenario:** Endpoint management agents deploy software and policies by creating scheduled tasks remotely, often running as SYSTEM with PowerShell payloads.

**Evidence:** `ParentImage` is `ccmexec.exe` or `IntuneManagementExtension.exe`. Task names follow organizational naming conventions.

**Fix:** Exclude known management agent parents:

```yaml
filter_management:
  ParentImage|endswith:
    - '\ccmexec.exe'
    - '\IntuneManagementExtension.exe'
    - '\ServiceUI.exe'
```

---

## False Positive 3 — System Administrator Scripts

**Scenario:** IT admins create tasks via PowerShell scripts for maintenance, backups, and patching — often running as SYSTEM on startup.

**Evidence:** `User` is a known admin account. `CommandLine` points to a network share or IT tool path.

**Fix:** Whitelist known admin accounts and task name prefixes in environment-specific tuning. Do not apply globally — this is deployment-specific.

---

## High Confidence Indicators (Tune DOWN, not away)

These patterns have very few legitimate use cases and should remain at **high** severity:

| Pattern | Reason |
|---|---|
| Task payload in `C:\Users\Public\` | No legitimate software installs payloads here |
| Task payload in `C:\Temp\` | Temporary directory — not a valid install location |
| `mshta.exe` or `wscript.exe` as task action | Living-off-the-land binary abuse |
| Task created + deleted within same hour | Execute-and-cleanup pattern |
| Task name exactly mimics Windows component (`WindowsUpdate`, `svchost`) | Masquerading |

---

## Recommended Alert Thresholds

| Condition | Severity |
|---|---|
| schtasks + payload in Public/Temp directory | High |
| schtasks + PowerShell hidden window as SYSTEM | High |
| Task created and deleted within 1 hour | High |
| schtasks + mshta/wscript/rundll32 payload | Critical |
| schtasks + /ru SYSTEM from non-admin parent | Medium |
| Generic schtasks /create with PowerShell | Medium |
