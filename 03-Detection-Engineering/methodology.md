# My Detection Engineering Methodology

This is the process I followed for each technique in this project. I wanted a consistent approach that actually validated the detection against real log data — not just written based on documentation.

---

## Step 1 — Study the Technique

I started with the [MITRE ATT&CK](https://attack.mitre.org/) technique page for each attack — reading what the technique is, why attackers use it, which threat groups have been observed using it, and what tools or variations exist. The goal here is understanding *intent*: knowing what an attacker is trying to accomplish tells you what detection opportunities exist and where they're likely to try to evade.

For some techniques I also read threat intelligence reports (e.g., Conti ransomware playbooks, LAPSUS$ incident reports) to see how the technique looks in a real intrusion versus a controlled lab.

---

## Step 2 — Simulate the Attack

Every technique in this project was executed hands-on in an isolated Windows environment (TryHackMe lab rooms with no external network access). I didn't write detection rules based on documentation alone — I ran the attacks first.

For each simulation I recorded:
- Exact commands executed
- Which user account and machine
- What output the commands produced
- Any errors or adaptations I had to make

Some things required adapting from the original plan. For example:
- **LSASS dump:** no internet in lab → switched from Mimikatz to comsvcs.dll (actually more realistic)
- **SMB lateral movement:** SMB1 disabled on target → switched from smbclient to crackmapexec

---

## Step 3 — Analyze Logs

After each simulation I searched for the evidence in Event Viewer and Splunk. This step included:
- Identifying which Event IDs fired
- Noting which ones *didn't* fire that I expected (and why)
- Capturing raw log output with timestamps, command lines, user context, and computer names
- Documenting detection gaps where default Windows/Sysmon configs were insufficient

This is where I found the most gaps. Windows logs almost nothing by default — enabling the right audit policies and Sysmon configuration is a prerequisite for any of this detection to work.

---

## Step 4 — Author Sigma Rule

The detection rule is written in Sigma YAML after validating what the logs actually contain. Writing the rule against real log values (not assumed field names) is what makes it deployable.

Each Sigma rule targets one or more of the log sources discovered in Step 3, using field names from the Windows/Sysmon Sigma schema.

---

## Step 5 — Convert to Splunk SPL

```bash
# Install sigma-cli
pip install sigma-cli

# Convert a rule
sigma convert -t splunk sigma-rules/powershell-suspicious-flags.yml

# Convert all rules at once
sigma convert -t splunk sigma-rules/*.yml
```

The converted SPL is then cleaned up and tested against the captured logs to confirm it fires on the true positive. Where the auto-converted query was overly broad or missed field mappings, I adjusted it manually.

Each technique has multiple SPL variants: a primary high-fidelity detection, individual signal queries, and a correlated version that chains multiple indicators.

---

## Step 6 — Tune

The last step is thinking through false positives — every legitimate scenario that would trigger this detection in a production environment. For each one I documented:
- What causes it
- What distinguishes it from a true positive
- What exclusion logic to apply

This section is important because a detection that generates constant false positive noise doesn't get actioned. Knowing the edge cases is what makes a rule production-ready versus lab-only.

---

## Key Log Sources by Technique

| Source | Event IDs | Techniques |
|--------|-----------|------------|
| Windows Security Log | 4624, 4625, 4688, 4698, 4699, 4656, 5140 | T1059.001, T1053.005, T1021.002 |
| PowerShell Operational | 4103, 4104 | T1059.001 |
| Task Scheduler Operational | 106, 141 | T1053.005 |
| Sysmon | 1 (Process Create), 10 (Process Access), 11 (FileCreate) | T1003.001, T1486 |

---

## What Enabled Logging Requires

On a default Windows installation, most of these events don't appear without additional configuration:

| Logging Type | How to Enable |
|---|---|
| Process Creation + Command Line (4688) | `auditpol /set /subcategory:"Process Creation" /success:enable` + GPO for command line |
| Scheduled Task Creation (4698) | `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable` |
| Task Scheduler Operational log (106/141) | Event Viewer → right-click log → Enable |
| Script Block Logging (4104) | Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` |
| Sysmon Event 10 (Process Access) | Custom Sysmon config XML with `<ProcessAccess>` rule |
| Sysmon Event 11 (FileCreate) | Custom Sysmon config XML with `<FileCreate>` rule |
