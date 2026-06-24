# Detection Engineering Methodology

This project follows a six-step process for each MITRE ATT&CK technique.

---

## Step 1 — Study the Technique

- Read the official [MITRE ATT&CK](https://attack.mitre.org/) technique page
- Understand why threat actors use it, what they achieve, and real-world examples
- Note sub-techniques, associated tools, and common procedures used by known threat groups

## Step 2 — Simulate the Attack

- Execute the technique in an isolated Windows lab environment
- Use documented attacker commands and tools (Mimikatz, PowerShell, net.exe, schtasks, etc.)
- Record every command run with exact syntax

## Step 3 — Analyze Logs

- Identify which Windows Event IDs are generated
- Identify which Sysmon Event IDs fire (where Sysmon is deployed)
- Capture raw log output with timestamp, command line, and process details visible

## Step 4 — Author Sigma Rule

- Write the detection rule in Sigma YAML format
- Map rule fields to the Windows/Sysmon log schema
- Validate syntax with `sigma check`

## Step 5 — Convert to Splunk SPL

- Use `sigma-cli` to convert the Sigma rule to Splunk SPL
- Test SPL query in Splunk against the captured logs
- Verify the true positive fires correctly

## Step 6 — Tune

- Identify false positive scenarios (legitimate admin activity, software installers, etc.)
- Apply filtering logic: field exclusions, process path whitelisting, user context
- Document the final tuned rule with rationale for each filter

---

## Key Log Sources

| Source | Event IDs Used |
|--------|---------------|
| Windows Security Log | 4624, 4625, 4688, 4698, 4656 |
| PowerShell Operational | 4103, 4104 |
| Sysmon | 1 (Process Create), 3 (Network), 7 (Image Load), 10 (Process Access) |
| Windows System Log | 7045 (Service Install) |
