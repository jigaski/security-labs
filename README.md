# Security Labs
Hands-on security labs and documented investigations.

| Lab | Description | Tools |
|-----|-------------|-------|
| [Phishing Analysis](phishing-analysis/) | Manual triage of a real Amazon-impersonation phishing email — header/auth analysis, MIME structure, attachment triage, IOC extraction across the kill chain | PowerShell, Python, VirusTotal, urlscan.io |
| [AWS CloudTrail → Splunk](aws-cloudtrail-splunk/) | Five scheduled CloudTrail detections in Splunk (failed logins, root usage, IAM privilege changes, S3 exposure, log tampering) — MITRE-mapped, with an ingestion-lag vs. search-window bug diagnosed through scheduler logs and fixed with index-time scoping | Splunk, AWS, SPL |
| [Wazuh Detection Engineering](wazuh) | AD brute-force detection on a Windows Server 2022 DC — atomic vs. composite rule escalation (60122 → 60204), MITRE T1110 mapping, a documented scan coverage gap, and an agent-health/fleet-reporting cycle | Wazuh, Sysmon, netexec, nmap, Kali |
