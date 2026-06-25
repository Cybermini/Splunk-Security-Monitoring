# Tuning Notes — T1486 Ransomware Impact Detection

---

## False Positive 1 — Legitimate Shadow Copy Management

**Scenario:** System administrators or backup software (Veeam, Acronis, Windows Server Backup) delete shadow copies as part of maintenance or before creating new backup snapshots.

**Evidence:** Execution time matches scheduled maintenance window. `ParentImage` is a known backup agent. `User` is a dedicated backup service account.

**Fix:** Create time-based exclusions for maintenance windows and whitelist backup service accounts:
```yaml
filter_backup:
  User: 'svc-backup'
  ParentImage|contains:
    - '\VeeamAgent'
    - '\BackupExec'
```

**Important:** The `/quiet` flag in `vssadmin delete shadows /all /quiet` is not used by legitimate backup tools — they typically log output. The quiet flag is a strong malicious indicator — raise severity if present.

---

## False Positive 2 — File Compression/Archiving Tools

**Scenario:** Tools like 7-Zip or WinRAR creating compressed archives generate high-volume file creation events that could trigger mass file creation detections.

**Evidence:** Extension is `.zip`, `.7z`, `.rar` — not `.encrypted`. `Image` is a known archiver. File creation rate is not exponential.

**Fix:** Exclude known archiver paths and non-ransomware extensions in Event 11 detection. The `.encrypted`, `.locked`, `.crypt` extensions have no legitimate business use.

---

## No False Positives for These — Alert at Critical

| Pattern | Why No FP |
|---|---|
| `vssadmin delete shadows /all /quiet` | The `/quiet` flag has no legitimate use — backup tools don't suppress output |
| `wmic shadowcopy delete` | Never used by standard Windows tools or backup software |
| `bcdedit /set recoveryenabled No` | No legitimate admin ever disables Windows recovery via script |
| Mass `.encrypted` file creation (10+ files/min) | This extension has zero legitimate use cases in any business environment |
| `README_DECRYPT.txt` file creation | Ransomware-specific filename — no legitimate tool creates this |

---

## Recommended Sysmon Config Additions

To close Event 11 detection gap, add to Sysmon config:

```xml
<FileCreate onmatch="include">
  <!-- Ransomware encryption extensions -->
  <TargetFilename condition="contains">.encrypted</TargetFilename>
  <TargetFilename condition="contains">.locked</TargetFilename>
  <TargetFilename condition="contains">.crypt</TargetFilename>
  <TargetFilename condition="contains">.ransom</TargetFilename>
  <!-- Ransomware note filenames -->
  <TargetFilename condition="contains">README_DECRYPT</TargetFilename>
  <TargetFilename condition="contains">HOW_TO_RESTORE</TargetFilename>
  <TargetFilename condition="contains">DECRYPT_INSTRUCTIONS</TargetFilename>
  <!-- Suspicious paths -->
  <TargetFilename condition="contains">C:\Users\Public\</TargetFilename>
</FileCreate>
```

---

## Recommended Alert Thresholds

| Condition | Severity |
|---|---|
| `vssadmin delete shadows` any variant | **Critical** |
| `wmic shadowcopy delete` | **Critical** |
| `bcdedit /set recoveryenabled No` | **Critical** |
| Mass `.encrypted` file creation (10+/min) | **Critical** |
| Ransom note filename created anywhere on disk | **Critical** |
| Correlated chain: shadow delete + encryption + ransom note | **Critical — Immediate IR response** |
| Single `.encrypted` file creation | **High** |
