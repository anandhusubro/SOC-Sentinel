import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from analyze_incident import load_events, detect

class DetectionTests(unittest.TestCase):
    def test_attack_chain(self):
        events=load_events(ROOT/"data"/"security_events.csv")
        findings,incidents=detect(events)
        kinds={x["kind"] for x in findings}
        self.assertTrue({"bruteforce_success","encoded_powershell","office_to_powershell","suspicious_egress"} <= kinds)
        ws17=next(x for x in incidents if x["host"]=="WS-17")
        self.assertEqual(ws17["severity"],"HIGH")
        self.assertTrue(ws17["multi_stage_correlation"])

    def test_benign_host_not_escalated(self):
        events=load_events(ROOT/"data"/"security_events.csv")
        findings,incidents=detect(events)
        self.assertFalse(any(x["host"]=="WS-22" for x in incidents))

if __name__=="__main__": unittest.main()
