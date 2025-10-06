#!/usr/bin/env python3

import boto3
import json
import time
from datetime import datetime

# Config
LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
# The S3 bucket name on AWS is honeypot-logs-bucket1
S3_BUCKET = "honeypot-logs-bucket1"

# AWS S3 client
s3 = boto3.client("s3")

sessions = {}

def save_to_s3(session_id, data):
    """Save session data to S3 as JSON"""
    file_name = f"cowrie-session-{session_id}.json"
    s3_key = f"logs/{datetime.utcnow().strftime('%Y-%m-%d')}/{file_name}"
    
    with open(file_name, "w") as f:
        json.dump(data, f, indent=4)
    
    s3.upload_file(file_name, S3_BUCKET, s3_key)
    print(f"Uploaded {file_name} -> s3://{S3_BUCKET}/{s3_key}")

def follow(file):
    """Tail -f equivalent in Python"""
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line.strip()

def main():
    global sessions
    with open(LOG_FILE, "r") as f:
        for line in follow(f):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            eventid = event.get("eventid")
            session = event.get("session")

            if not session:
                continue

            # New connection
            if eventid == "cowrie.session.connect":
                sessions[session] = {
                    "session_id": session,
                    "ip": event.get("src_ip"),
                    "start_time": event.get("timestamp"),
                    "commands": []
                }

            # Command entered
            elif eventid == "cowrie.command.input":
                if session in sessions:
                    sessions[session]["commands"].append(event.get("input"))

            # Session closed
            elif eventid == "cowrie.session.closed":
                if session in sessions:
                    sessions[session]["end_time"] = event.get("timestamp")
                    save_to_s3(session, sessions[session])
                    del sessions[session]

if __name__ == "__main__":
    main()
