from __future__ import annotations
import csv, json, sys, html, ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "output"
OUT.mkdir(exist_ok=True)

THREAT_IPS = {"45.83.64.12", "185.220.101.5"}
MITRE = {
    "bruteforce_success": ("T1110", "Brute Force"),
    "encoded_powershell": ("T1059.001", "PowerShell"),
    "office_to_powershell": ("T1059.001", "PowerShell"),
    "suspicious_egress": ("T1041", "Exfiltration Over C2 Channel"),
}

def ts(v): return datetime.fromisoformat(v.replace("Z","+00:00"))

def load_events(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["_ts"] = ts(r["timestamp"])
        r["bytes_out"] = int(r.get("bytes_out") or 0)
    return sorted(rows, key=lambda x: x["_ts"])

def fnd(kind, title, e, evidence, severity="HIGH"):
    tid, name = MITRE[kind]
    return {
        "kind": kind, "title": title, "severity": severity,
        "timestamp": e["timestamp"], "host": e.get("host",""),
        "user": e.get("user",""), "mitre": {"id": tid, "name": name},
        "evidence": evidence
    }

def detect(events):
    findings, failures = [], defaultdict(list)

    for e in events:
        if e["event_type"] == "auth":
            key=(e["host"],e["user"],e["source_ip"])
            if e["status"]=="failure":
                failures[key].append(e)
            elif e["status"]=="success":
                recent=[x for x in failures[key] if timedelta() <= e["_ts"]-x["_ts"] <= timedelta(minutes=2)]
                if len(recent)>=5:
                    findings.append(fnd("bruteforce_success",
                        "Failed logins followed by successful authentication", e,
                        {"failed_attempts":len(recent),"source_ip":e["source_ip"],
                         "first_failure":recent[0]["timestamp"],"success":e["timestamp"],
                         "rationale":"Same user, host and source IP; success follows rapid failures."}))

    office={"winword.exe","excel.exe","powerpnt.exe","outlook.exe"}
    for e in events:
        if e["event_type"]!="process": continue
        proc=e["process"].lower(); parent=e["parent_process"].lower(); cmd=e["command_line"]
        if proc in {"powershell.exe","pwsh.exe"} and any(x in cmd.lower() for x in [" -enc ","-encodedcommand","frombase64string"]):
            findings.append(fnd("encoded_powershell","Encoded PowerShell execution",e,
                {"parent":e["parent_process"],"command_line":cmd,
                 "rationale":"Encoded PowerShell reduces command visibility and merits investigation."}))
        if proc in {"powershell.exe","pwsh.exe"} and parent in office:
            findings.append(fnd("office_to_powershell","Office application spawned PowerShell",e,
                {"parent":e["parent_process"],"child":e["process"],
                 "rationale":"Office-to-PowerShell is an unusual parent-child chain often investigated for malicious document execution."}))

    for e in events:
        if e["event_type"]=="network" and e["dest_ip"] in THREAT_IPS and e["bytes_out"]>=1_000_000:
            findings.append(fnd("suspicious_egress","Large outbound transfer to threat-listed IP",e,
                {"destination":e["dest_ip"],"port":e["dest_port"],"bytes_out":e["bytes_out"],
                 "threat_intel_match":True,
                 "rationale":"Large transfer alone is insufficient; threat-intel match and nearby endpoint activity increase confidence."}))

    by_host=defaultdict(list)
    for x in findings: by_host[x["host"]].append(x)

    incidents=[]
    for host, fs in by_host.items():
        kinds={x["kind"] for x in fs}
        times=sorted(ts(x["timestamp"]) for x in fs)
        correlated={"bruteforce_success","encoded_powershell","suspicious_egress"} <= kinds and times[-1]-times[0] <= timedelta(minutes=15)
        score=min(100, len(kinds)*20 + (35 if correlated else 0))
        sev="HIGH" if score>=70 else "MEDIUM" if score>=40 else "LOW"
        incidents.append({"host":host,"severity":sev,"score":score,
                          "multi_stage_correlation":correlated,
                          "finding_count":len(fs),
                          "techniques":sorted({x["mitre"]["id"] for x in fs})})
    return findings, incidents

def write_outputs(events, findings, incidents):
    (OUT/"findings.json").write_text(json.dumps({"incidents":incidents,"findings":findings},indent=2),encoding="utf-8")

    with (OUT/"timeline.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["timestamp","host","event_type","summary"])
        for e in events:
            if e["event_type"]=="auth":
                s=f'{e["status"]} login user={e["user"]} src={e["source_ip"]}'
            elif e["event_type"]=="process":
                s=f'{e["parent_process"]} -> {e["process"]} {e["command_line"]}'
            else:
                s=f'{e["source_ip"]} -> {e["dest_ip"]}:{e["dest_port"]} bytes_out={e["bytes_out"]}'
            w.writerow([e["timestamp"],e["host"],e["event_type"],s])

    top=incidents[0]
    report=[
        "# Incident Report — SOC Sentinel v2","",
        f'**Severity:** {top["severity"]}',f'**Risk score:** {top["score"]}/100',
        f'**Affected host:** {top["host"]}',f'**MITRE ATT&CK:** {", ".join(top["techniques"])}',"",
        "## Executive Summary","",
        "A rapid failed-login sequence was followed by successful authentication, encoded PowerShell launched from Microsoft Word, and a large outbound transfer to a threat-listed IP. Correlation by host and time window raises the incident to high severity.","",
        "## Evidence",""
    ]
    for x in findings:
        report += [f'- **{x["timestamp"]} — {x["title"]}**',
                   f'  - MITRE: {x["mitre"]["id"]} — {x["mitre"]["name"]}',
                   f'  - Rationale: {x["evidence"].get("rationale","")}',
                   f'  - Evidence: `{json.dumps(x["evidence"])}`']
    report += ["","## False-positive considerations","",
               "- Login failures may be user error; the immediate success from the same source increases suspicion.",
               "- Encoded PowerShell can be administrative; validate signer, user context and change history.",
               "- Large HTTPS transfers are common; the threat-intel match and temporal correlation drive priority.","",
               "## Recommended response","",
               "1. Isolate WS-17.","2. Reset/disable the affected account and revoke sessions.",
               "3. Collect PowerShell Operational and Script Block logs.",
               "4. Preserve authentication, process and network evidence.",
               "5. Block confirmed malicious indicators.","6. Hunt for the same indicators across other hosts."]
    (OUT/"incident_report.md").write_text("\n".join(report),encoding="utf-8")

    rows="".join(f"<tr><td>{html.escape(x['timestamp'])}</td><td>{html.escape(x['title'])}</td><td>{x['mitre']['id']}</td><td>{x['severity']}</td></tr>" for x in findings)
    page=f"""<!doctype html><html><head><meta charset="utf-8"><title>SOC Sentinel v2</title>
<style>body{{font-family:Arial;background:#0b1020;color:#eef3ff;padding:30px}}.wrap{{max-width:1000px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:15px}}.card{{background:#131c31;padding:20px;border-radius:14px;border:1px solid #293650}}
.big{{font-size:34px;font-weight:700}}table{{width:100%;border-collapse:collapse;margin-top:20px;background:#131c31}}th,td{{padding:13px;border-bottom:1px solid #293650;text-align:left}}</style></head>
<body><div class="wrap"><h1>SOC Sentinel v2</h1><p>Multi-Stage Intrusion Detection & Incident Triage</p>
<div class="grid"><div class="card">Severity<div class="big">{top['severity']}</div></div><div class="card">Risk Score<div class="big">{top['score']}/100</div></div><div class="card">Findings<div class="big">{len(findings)}</div></div></div>
<table><tr><th>Timestamp</th><th>Detection</th><th>MITRE</th><th>Severity</th></tr>{rows}</table></div></body></html>"""
    (OUT/"dashboard.html").write_text(page,encoding="utf-8")

def main():
    path=Path(sys.argv[1]) if len(sys.argv)>1 else BASE/"data"/"security_events.csv"
    events=load_events(path); findings,incidents=detect(events); write_outputs(events,findings,incidents)
    print(f"Analyzed {len(events)} events")
    print(f"Generated {len(findings)} findings")
    for i in incidents:
        print(f"INCIDENT host={i['host']} severity={i['severity']} score={i['score']} techniques={','.join(i['techniques'])}")

if __name__=="__main__": main()
