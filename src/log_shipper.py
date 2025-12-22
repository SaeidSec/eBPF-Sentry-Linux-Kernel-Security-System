import requests
import json
from datetime import datetime
import getpass
import re
import os

# Updated to point to local dashboard backend
API_BASE = "http://localhost:5000/api" 

IPS_LOG_FILE = "ips_actions.log"
IDS_LOG_FILE = "ids_alerts.json"

# -----------------------
# LOGIN (GET JWT TOKEN)
# -----------------------
def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    try:
        resp = requests.post(f"{API_BASE}/login", json={
            "username": username,
            "password": password
        }, timeout=10)

        if resp.status_code != 200:
            print("Login failed:", resp.text)
            exit(1)

        print("Login successful!")
        return resp.json()["token"]
    except Exception as e:
        print(f"Connection error: {e}")
        exit(1)

# -----------------------
# PARSE IPS LOGS
# -----------------------
def parse_ips_logs():
    logs = []
    if not os.path.exists(IPS_LOG_FILE): return []

    # Format: 2025-12-21 10:00:00 - [BLOCKED] PID 123 TERMINATED -> bash | Rule: rule_name
    regex = r"^(.*?) - \[BLOCKED\] PID (\d+) TERMINATED -> (.*?) \| Rule: (.*)$"

    with open(IPS_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.search(regex, line)
            if not match:
                continue

            ts_raw, pid, info, rule = match.groups()

            logs.append({
                "timestamp": ts_raw, # ISO format usually matches
                "pid": int(pid),
                "info": info,
                "rule": rule,
                "action": "KILLED"
            })

    return logs

# -----------------------
# PARSE IDS LOGS
# -----------------------
def parse_ids_logs():
    logs = []
    if not os.path.exists(IDS_LOG_FILE): return []

    with open(IDS_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                logs.append(data)
            except:
                pass

    return logs

# -----------------------
# SEND LOG TO BACKEND
# -----------------------
def send_log(token, log_type, data):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "logType": log_type,
        "logData": data,
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat() + "Z")
    }

    try:
        resp = requests.post(f"{API_BASE}/logs", json=payload, headers=headers, timeout=5)
        if resp.status_code == 201:
            print(f"[OK] Sent {log_type} log")
        else:
            print(f"[ERR] Failed to send {log_type} log: {resp.text}")
    except:
        print(f"[ERR] Timeout/Error sending log")

# -----------------------
# MAIN
# -----------------------
def main():
    print("eBPF-Sentry Log Shipper")
    token = login()

    print("\nReading IPS logs...")
    ips_logs = parse_ips_logs()
    print(f"Found {len(ips_logs)} IPS logs")

    print("Reading IDS logs...")
    ids_logs = parse_ids_logs()
    print(f"Found {len(ids_logs)} IDS logs")

    print("\nSending logs...\n")

    for log in ips_logs:
        send_log(token, "ips", log)

    for log in ids_logs:
        send_log(token, "ids", log)

    print("\nAll logs sent!")

if __name__ == "__main__":
    main()

