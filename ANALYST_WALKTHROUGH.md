# Analyst Walkthrough

## Investigation chain
1. Five failed logins hit `anita@WS-17` from the same external source.
2. A successful login follows 5 seconds later.
3. `winword.exe` spawns encoded `powershell.exe`.
4. One minute later WS-17 sends 2.5 MB to a threat-listed IP over 443.
5. Cross-source correlation promotes the incident to HIGH.

## Analyst verdict
High-priority suspected account compromise with post-authentication execution and suspicious outbound activity.

## Interview explanation
“I built a Python SOC correlation engine that ingests authentication, process and network telemetry. It detects suspicious patterns, maps them to MITRE ATT&CK, correlates alerts by host and time, extracts IOCs and generates an analyst-ready incident report. I also added automated tests so the detections can be validated instead of relying only on visual inspection.”
