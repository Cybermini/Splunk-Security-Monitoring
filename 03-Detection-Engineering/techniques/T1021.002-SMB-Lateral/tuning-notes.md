# Tuning Notes — T1021.002 SMB Lateral Movement

---

## False Positive 1 — Domain Controllers Authenticating to Each Other

**Scenario:** In Active Directory environments, DCs replicate data and authenticate between themselves via SMB — generating Event 4624 Logon Type 3 constantly.

**Evidence:** `IpAddress` matches another known DC IP. `TargetUserName` is a machine account ending in `$`.

**Fix:** Maintain a DC IP allowlist and exclude machine accounts:
```yaml
filter_dc_replication:
  IpAddress|cidr: '<DC_subnet>/32'
  TargetUserName|endswith: '$'
```

---

## False Positive 2 — Backup Solutions

**Scenario:** Backup agents (Veeam, Acronis, Backup Exec) access `C$` remotely on a schedule to image drives or copy files.

**Evidence:** `SubjectUserName` is a dedicated backup service account. Events occur on a regular schedule (nightly/weekly).

**Fix:** Whitelist backup service account names and their known source IPs:
```yaml
filter_backup:
  SubjectUserName: 'svc-backup'
  IpAddress: '<backup-server-IP>'
```

---

## False Positive 3 — SCCM / Remote Admin Tools

**Scenario:** IT admins using SCCM, PSRemoting, or Sysinternals PsExec for legitimate remote administration generate identical logs to attacker lateral movement.

**Evidence:** `IpAddress` matches known admin workstations. Activity occurs during business hours. Username matches IT admin accounts.

**Fix:** This is the hardest to tune — privileged admin activity and attacker lateral movement look identical in logs. Recommended approach:
- Create an approved admin source IP list
- Alert on admin share access from IPs NOT on the approved list
- Use time-of-day context (after-hours access = higher severity)

---

## High Confidence Indicators — Do Not Tune Away

| Pattern | Severity | Rationale |
|---|---|---|
| C$ access from Linux IP | Critical | No legitimate Windows admin tool runs from Linux |
| ADMIN$ access from workstation (not server) | High | Workstations should never access admin shares |
| LogonType 3 + NTLM to DC (not Kerberos) | High | Pass-the-Hash indicator in Kerberos domain |
| Same IpPort in 4624 + 5140 within seconds | Critical | Definitively ties logon to share access |
| C$ access at 2-4 AM outside maintenance window | High | Time-based anomaly |

---

## Recommended Alert Thresholds

| Condition | Severity |
|---|---|
| C$ or ADMIN$ access from non-approved IP | High |
| NTLM Type 3 logon to DC from non-DC IP | High |
| Correlated 4624 + 5140 from same source | Critical |
| Linux/Mac IP accessing Windows admin share | Critical |
| File created in C:\Users\Public\ via SMB | High |
