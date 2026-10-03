from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
data=json.loads((ROOT/"output"/"findings.json").read_text(encoding="utf-8"))
ips,hosts,users,commands=set(),set(),set(),set()
for f in data["findings"]:
    hosts.add(f["host"]); users.add(f["user"])
    e=f["evidence"]
    for k in ("source_ip","destination"):
        if e.get(k): ips.add(str(e[k]))
    if e.get("command_line"): commands.add(e["command_line"])
result={"ip_addresses":sorted(ips),"hosts":sorted(hosts),"users":sorted(users),"command_lines":sorted(commands)}
(ROOT/"output"/"iocs.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
print("IOC extraction complete:", len(ips), "IPs,", len(hosts), "hosts,", len(users), "users")
