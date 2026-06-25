# Splunk SPL Queries — All Techniques

All converted Splunk search queries from this project collected in one place.

| Query File | Technique | MITRE ID | Status |
|------------|-----------|----------|--------|
| [T1059.001-powershell.txt](./T1059.001-powershell.txt) | PowerShell Abuse | T1059.001 | ✅ Complete |
| [T1053.005-scheduled-tasks.txt](./T1053.005-scheduled-tasks.txt) | Scheduled Task Creation | T1053.005 | ✅ Complete |
| [T1003.001-lsass-dump.txt](./T1003.001-lsass-dump.txt) | LSASS Memory Dump | T1003.001 | ✅ Complete |
| [T1021.002-smb-lateral.txt](./T1021.002-smb-lateral.txt) | SMB Lateral Movement | T1021.002 | ✅ Complete |
| T1486-ransomware.txt | Ransomware Simulation | T1486 | ⏳ Planned |

## Notes

- Queries are written for Splunk Enterprise with Windows Security and Sysmon log sources
- Adjust `index=` and `sourcetype=` values to match your Splunk environment
- Sysmon versions of queries are preferred where available — they provide richer context
