# Sigma Rules — All Techniques

All Sigma YAML detection rules from this project collected in one place for easy deployment.

| Rule File | Technique | MITRE ID | Status |
|-----------|-----------|----------|--------|
| [powershell-suspicious-flags.yml](./powershell-suspicious-flags.yml) | PowerShell Abuse | T1059.001 | ✅ Complete |
| [scheduled-task-creation.yml](./scheduled-task-creation.yml) | Scheduled Task Creation | T1053.005 | ✅ Complete |
| lsass-memory-dump.yml | LSASS Memory Dump | T1003.001 | ⏳ Planned |
| smb-lateral-movement.yml | SMB Lateral Movement | T1021.002 | ⏳ Planned |
| ransomware-file-encryption.yml | Ransomware Simulation | T1486 | ⏳ Planned |

## Usage

```bash
# Install sigma-cli
pip install sigma-cli

# Convert a single rule to Splunk SPL
sigma convert -t splunk sigma-rules/powershell-suspicious-flags.yml

# Convert all rules
sigma convert -t splunk sigma-rules/*.yml
```
