# SOC Sentinel v2
Multi-Stage Intrusion Detection & Incident Triage

## What it does
Correlates authentication, endpoint/process, PowerShell, and network telemetry into one SOC incident.

### Detects
- 5+ failed logins followed by success — MITRE T1110
- Encoded PowerShell — MITRE T1059.001
- Office -> PowerShell process chain — MITRE T1059.001
- Large outbound transfer to threat-listed IP — MITRE T1041
- Multi-stage correlation by host and time window
- IOC extraction
- Automated detection tests
- Analyst-ready report + HTML dashboard

## Windows
Run:
    run_full.bat

## Manual commands
    python src\analyze_incident.py data\security_events.csv
    python src\extract_iocs.py
    python -m unittest tests\test_detections.py -v

Outputs:
- output/findings.json
- output/iocs.json
- output/timeline.csv
- output/incident_report.md
- output/dashboard.html
