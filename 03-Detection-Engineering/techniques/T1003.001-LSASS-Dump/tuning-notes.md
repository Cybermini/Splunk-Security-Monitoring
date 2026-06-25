# Tuning Notes — T1003.001 LSASS Memory Dump

---

## False Positive 1 — Windows Error Reporting (WER)

**Scenario:** Windows automatically creates memory dumps for crashed processes via `WerFault.exe`. These write `.dmp` files but NOT using `comsvcs.dll`.

**Why it's not a problem:** The `comsvcs.dll + MiniDump` signature is unique to the attacker technique. WerFault writes dumps via its own mechanism — the command line will never contain `comsvcs` or `MiniDump`. The filter in the Sigma rule excludes `werfault` paths for the rare edge case.

**Risk of over-filtering:** Do NOT broadly exclude all `.dmp` file creation — that removes the Sysmon Event 11 detection for dump files in suspicious paths.

---

## False Positive 2 — Legitimate Debug/Support Tools

**Scenario:** IT support or developers using ProcDump, Task Manager, or WinDbg to capture process dumps for troubleshooting.

**Evidence:** `SourceImage` will be `procdump.exe`, `taskmgr.exe`, or a known debugging tool. `GrantedAccess` values will differ.

**Fix:** In the Event 10 detection, whitelist known support tool paths:

```yaml
filter_debug_tools:
  SourceImage|contains:
    - '\procdump'
    - '\taskmgr.exe'
    - '\windbg.exe'
```

**Important:** Only whitelist if these tools are confirmed in your environment via an approved software list.

---

## False Positive 3 — Security Products Scanning lsass

**Scenario:** EDR agents, AV products, and DLP tools legitimately read lsass memory for threat detection. These generate Event 10 with specific `GrantedAccess` values.

**Evidence:** `SourceImage` is a known security product path (`C:\Program Files\CrowdStrike\`, `C:\Program Files\SentinelOne\`).

**Fix:** The Sigma rule already excludes `C:\Program Files\*` from Event 10 detection. Review your specific EDR path and add it explicitly.

---

## Sysmon Event 10 — GrantedAccess Values Reference

Not all lsass access is credential dumping. Use `GrantedAccess` to tune severity:

| GrantedAccess | Meaning | Risk |
|---|---|---|
| `0x1fffff` | Full access — read, write, all | **Critical** — almost always credential dump |
| `0x1010` | Read VM + Query info | **High** — common Mimikatz value |
| `0x1438` | Read VM + Query + Duplicate | **High** — common credential dump value |
| `0x0400` | Query process info only | **Low** — normal system activity |
| `0x0040` | Duplicate handle | **Low** — normal system activity |

---

## Hardening Recommendation — Enable Sysmon Event 10

The most impactful hardening step for this detection is adding a ProcessAccess rule to Sysmon config:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

Without this rule, any tool that accesses lsass memory — Mimikatz, comsvcs.dll, ProcDump, custom malware — goes undetected at the memory access layer. Event ID 1 (process creation) can still catch known command patterns but misses fileless or renamed binary attacks.

---

## Recommended Alert Thresholds

| Condition | Severity |
|---|---|
| `rundll32.exe` + `comsvcs.dll` + `MiniDump` in command line | **Critical** |
| Any process + `GrantedAccess 0x1fffff` against `lsass.exe` | **Critical** |
| `.dmp` file created in `C:\Users\Public\` or `C:\Temp\` | **High** |
| `lsass.dmp` filename anywhere on disk | **High** |
| Correlation: dump command + dump file within 5 minutes | **Critical** |
