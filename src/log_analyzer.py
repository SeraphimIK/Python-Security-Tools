"""
Log Analyzer
------------
Analyzes an authentication log (CSV: timestamp, source_ip, username, event)
for suspicious activity patterns:
  - Brute force: many failed logins from a single source IP in a short window
  - Username enumeration: a single source IP trying many different usernames
  - Successful login immediately following a burst of failures (possible
    credential stuffing success)

Run from the repository root:
    python src/log_analyzer.py
"""

import csv
import os
from collections import defaultdict
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE = os.path.join(BASE_DIR, "data", "sample_auth_log.csv")

FAILED_LOGIN_THRESHOLD = 4          # flag if an IP has >= this many failures
ENUMERATION_USER_THRESHOLD = 3       # flag if an IP tries >= this many distinct usernames


def load_log(path):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def analyze(rows):
    findings = []
    by_ip = defaultdict(list)
    for row in rows:
        by_ip[row["source_ip"]].append(row)

    for ip, events in by_ip.items():
        failures = [e for e in events if e["event"] == "failed_login"]
        usernames_tried = {e["username"] for e in events}
        successes = [e for e in events if e["event"] == "successful_login"]

        if len(failures) >= FAILED_LOGIN_THRESHOLD:
            findings.append(
                f"[BRUTE FORCE] {ip}: {len(failures)} failed logins "
                f"(usernames: {', '.join(sorted(usernames_tried))})"
            )

        if len(usernames_tried) >= ENUMERATION_USER_THRESHOLD:
            findings.append(
                f"[USER ENUMERATION] {ip}: attempted {len(usernames_tried)} distinct usernames"
            )

        if failures and successes:
            last_failure_time = datetime.strptime(failures[-1]["timestamp"], "%Y-%m-%d %H:%M:%S")
            for s in successes:
                success_time = datetime.strptime(s["timestamp"], "%Y-%m-%d %H:%M:%S")
                if 0 <= (success_time - last_failure_time).total_seconds() <= 30:
                    findings.append(
                        f"[POSSIBLE COMPROMISE] {ip}: successful login as '{s['username']}' "
                        f"immediately after {len(failures)} failed attempts"
                    )

    return findings


if __name__ == "__main__":
    rows = load_log(INPUT_FILE)
    findings = analyze(rows)

    print("=" * 65)
    print("AUTH LOG ANALYSIS")
    print("=" * 65)
    print(f"Total events analyzed: {len(rows)}")
    print(f"Unique source IPs: {len({r['source_ip'] for r in rows})}")
    print("-" * 65)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No suspicious patterns detected.")
    print("=" * 65)
