# Incident Report — SOC Sentinel v2

**Severity:** HIGH  
**Risk Score:** 100/100  
**Affected Host:** WS-17  
**Affected User:** anita  

**MITRE ATT&CK Techniques:**
- T1110 — Brute Force
- T1059.001 — PowerShell
- T1041 — Exfiltration Over C2 Channel

---

## Executive Summary

SOC Sentinel identified a correlated multi-stage security incident involving suspicious authentication activity, encoded PowerShell execution, an unusual Office-to-PowerShell process chain, and outbound communication to a threat-listed external IP.

The activity occurred on workstation `WS-17` within a short time window and was correlated into a single **HIGH severity incident** with a risk score of **100/100**.

The observed activity is consistent with a suspected account compromise followed by post-authentication execution and suspicious outbound network activity.

---

## Incident Timeline

### 09:01:00 — Authentication Failures Begin

Five failed authentication attempts were observed against user `anita` on workstation `WS-17`.

**Source IP:** `203.0.113.45`

The attempts occurred within approximately 20 seconds.

---

### 09:01:25 — Successful Authentication

A successful authentication occurred from the same source IP immediately after the failed attempts.

This pattern increased suspicion of successful password guessing or compromised credentials.

**MITRE ATT&CK:** `T1110 — Brute Force`

---

### 09:03:00 — Encoded PowerShell Execution

The following process chain was observed:

```text
winword.exe
    ↓
powershell.exe
