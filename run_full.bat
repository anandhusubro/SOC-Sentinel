@echo off
python src\analyze_incident.py data\security_events.csv
python src\extract_iocs.py
python -m unittest discover -s tests -p "test_*.py" -v
pause
