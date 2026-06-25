# Sigma Rules — All Techniques

All Sigma YAML detection rules from this project collected in one place for easy deployment.

| Rule File | Technique | MITRE ID | Status |
|-----------|-----------|----------|--------|
| [powershell-suspicious-flags.yml](./powershell-suspicious-flags.yml) | PowerShell Abuse | T1059.001 | ✅ Complete |
| [scheduled-task-creation.yml](./scheduled-task-creation.yml) | Scheduled Task Creation | T1053.005 | ✅ Complete |
| [lsass-memory-dump.yml](./lsass-memory-dump.yml) | LSASS Memory Dump | T1003.001 | ✅ Complete |
| [smb-lateral-movement.yml](./smb-lateral-movement.yml) | SMB Lateral Movement | T1021.002 | ✅ Complete |
| [ransomware-impact.yml](./ransomware-impact.yml) | Ransomware Simulation | T1486 | ✅ Complete |

## Usage

```bash
# Install sigma-cli
pip install sigma-cli

# Convert a single rule to Splunk SPL
sigma convert -t splunk sigma-rules/powershell-suspicious-flags.yml

# Convert all rules
sigma convert -t splunk sigma-rules/*.yml
```
