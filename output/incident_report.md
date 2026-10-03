# SOC Sentinel v2

**Multi-Stage Intrusion Detection & Incident Triage Engine**

SOC Sentinel is a Python-based SOC investigation project that correlates authentication, endpoint/process, PowerShell, and network telemetry to identify multi-stage intrusion activity.

Instead of treating alerts independently, the engine links suspicious events by **host and time window**, maps activity to **MITRE ATT&CK**, assigns a risk score, extracts IOCs, and produces analyst-ready investigation artifacts.

![SOC Sentinel Dashboard](screenshots/dashboard.png)

---

## Detection Scenario

The dataset contains **231 security events**, including:

- 220 benign background events
- multiple users and endpoints
- normal authentication activity
- normal process execution
- normal HTTPS/network traffic
- benign failed-login activity
- one hidden multi-stage attack against `WS-17`

SOC Sentinel identifies the malicious sequence from the surrounding noise.

### Attack Chain

```text
5 Failed Login Attempts
        ↓
Successful Authentication
        ↓
winword.exe → powershell.exe
        ↓
Encoded PowerShell Execution
        ↓
2.5 MB Outbound Transfer
        ↓
Threat-Listed External IP
        ↓
HIGH Severity Incident
```

---

## Detection Results

```text
Analyzed 231 events
Generated 4 findings

INCIDENT
Host: WS-17
Severity: HIGH
Risk Score: 100/100

MITRE ATT&CK:
T1110
T1059.001
T1041
```

---

## Detection Capabilities

### Brute Force → Successful Authentication

Detects five or more failed authentication attempts followed by a successful login from the same source.

**MITRE ATT&CK:** `T1110 — Brute Force`

---

### Encoded PowerShell

Identifies suspicious PowerShell execution containing encoded command-line arguments.

**MITRE ATT&CK:** `T1059.001 — PowerShell`

---

### Suspicious Parent-Child Process

Detects Microsoft Office applications spawning PowerShell.

Example:

```text
winword.exe
     ↓
powershell.exe
```

This process relationship can indicate malicious document execution.

---

### Suspicious Network Egress

Detects high-volume outbound traffic to threat-listed external destinations.

SOC Sentinel does not classify high traffic as malicious by itself. The severity increases because the network activity occurs shortly after suspicious authentication and endpoint execution on the same workstation.

**MITRE ATT&CK:** `T1041 — Exfiltration Over C2 Channel`

---

## Cross-Source Correlation

Individual alerts may have benign explanations.

SOC Sentinel therefore correlates:

```text
Authentication Telemetry
          +
Process Telemetry
          +
PowerShell Activity
          +
Network Telemetry
          +
Threat Intelligence
          ↓
Correlated Incident
```

When the events occur on the same endpoint within the configured investigation window, the incident receives an increased risk score.

---

## False-Positive Handling

The project intentionally considers alternative explanations.

Examples:

- Failed logins may be caused by password mistakes.
- Encoded PowerShell may be used by legitimate administrators.
- Large HTTPS transfers occur during normal business operations.

The system increases confidence when several independent indicators appear on the same host within a short period.

---

## Automated IOC Extraction

SOC Sentinel extracts investigation indicators into:

```text
output/iocs.json
```

Example indicators include:

- source IP addresses
- destination IP addresses
- affected endpoints
- affected users
- suspicious command lines

---

## Automated Detection Testing

Detection logic is validated with Python unit tests.

Run:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Expected result:

```text
test_attack_chain ... ok
test_benign_host_not_escalated ... ok

Ran 2 tests

OK
```

The second test ensures benign activity is not incorrectly promoted into an incident.

---

## Generated Investigation Artifacts

SOC Sentinel automatically creates:

```text
output/
├── dashboard.html
├── findings.json
├── incident_report.md
├── iocs.json
└── timeline.csv
```

### `dashboard.html`

Visual investigation summary showing:

- incident severity
- risk score
- correlated detections
- MITRE ATT&CK techniques

### `incident_report.md`

Analyst-readable incident assessment containing:

- executive summary
- evidence
- investigation rationale
- false-positive considerations
- containment recommendations

### `timeline.csv`

Chronological investigation timeline.

### `findings.json`

Machine-readable detection results.

### `iocs.json`

Extracted investigation indicators.

---

## Project Structure

```text
SOC-Sentinel/
│
├── data/
│   └── security_events.csv
│
├── src/
│   ├── analyze_incident.py
│   └── extract_iocs.py
│
├── tests/
│   └── test_detections.py
│
├── rules/
│   └── detections.yml
│
├── output/
│   ├── dashboard.html
│   ├── findings.json
│   ├── incident_report.md
│   ├── iocs.json
│   └── timeline.csv
│
├── screenshots/
│   └── dashboard.png
│
├── ANALYST_WALKTHROUGH.md
├── run_full.bat
└── README.md
```

---

## Run SOC Sentinel

### Windows

```bat
run_full.bat
```

Or manually:

```bash
python src/analyze_incident.py data/security_events.csv
python src/extract_iocs.py
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Investigation Verdict

**High-priority suspected account compromise with post-authentication execution and suspicious outbound network activity.**

Recommended response:

1. Isolate `WS-17`.
2. Disable or reset the affected account.
3. Revoke active sessions.
4. Collect PowerShell Operational and Script Block logs.
5. Preserve authentication, endpoint, and network telemetry.
6. Block validated malicious indicators.
7. Hunt for related indicators across other endpoints.

---

## Skills Demonstrated

`Python` · `SOC Analysis` · `Incident Response` · `SIEM Concepts` · `MITRE ATT&CK` · `Windows Security` · `PowerShell Analysis` · `Network Analysis` · `Threat Detection` · `IOC Analysis` · `Detection Engineering`

---

## Disclaimer

All telemetry and attack activity used in this project are simulated for defensive cybersecurity training and portfolio demonstration.
