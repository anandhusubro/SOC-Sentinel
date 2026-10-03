# Incident Report — SOC Sentinel v2

**Severity:** HIGH
**Risk score:** 100/100
**Affected host:** WS-17
**MITRE ATT&CK:** T1041, T1059.001, T1110

## Executive Summary

A rapid failed-login sequence was followed by successful authentication, encoded PowerShell launched from Microsoft Word, and a large outbound transfer to a threat-listed IP. Correlation by host and time window raises the incident to high severity.

## Evidence

- **2026-09-18T09:01:25Z — Failed logins followed by successful authentication**
  - MITRE: T1110 — Brute Force
  - Rationale: Same user, host and source IP; success follows rapid failures.
  - Evidence: `{"failed_attempts": 5, "source_ip": "203.0.113.45", "first_failure": "2026-09-18T09:01:00Z", "success": "2026-09-18T09:01:25Z", "rationale": "Same user, host and source IP; success follows rapid failures."}`
- **2026-09-18T09:03:00Z — Encoded PowerShell execution**
  - MITRE: T1059.001 — PowerShell
  - Rationale: Encoded PowerShell reduces command visibility and merits investigation.
  - Evidence: `{"parent": "winword.exe", "command_line": "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "rationale": "Encoded PowerShell reduces command visibility and merits investigation."}`
- **2026-09-18T09:03:00Z — Office application spawned PowerShell**
  - MITRE: T1059.001 — PowerShell
  - Rationale: Office-to-PowerShell is an unusual parent-child chain often investigated for malicious document execution.
  - Evidence: `{"parent": "winword.exe", "child": "powershell.exe", "rationale": "Office-to-PowerShell is an unusual parent-child chain often investigated for malicious document execution."}`
- **2026-09-18T09:04:00Z — Large outbound transfer to threat-listed IP**
  - MITRE: T1041 — Exfiltration Over C2 Channel
  - Rationale: Large transfer alone is insufficient; threat-intel match and nearby endpoint activity increase confidence.
  - Evidence: `{"destination": "45.83.64.12", "port": "443", "bytes_out": 2500000, "threat_intel_match": true, "rationale": "Large transfer alone is insufficient; threat-intel match and nearby endpoint activity increase confidence."}`

## False-positive considerations

- Login failures may be user error; the immediate success from the same source increases suspicion.
- Encoded PowerShell can be administrative; validate signer, user context and change history.
- Large HTTPS transfers are common; the threat-intel match and temporal correlation drive priority.

## Recommended response

1. Isolate WS-17.
2. Reset/disable the affected account and revoke sessions.
3. Collect PowerShell Operational and Script Block logs.
4. Preserve authentication, process and network evidence.
5. Block confirmed malicious indicators.
6. Hunt for the same indicators across other hosts.