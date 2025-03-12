import json
import base64
from collections import defaultdict

# Load the log file
LOG_FILE = "ssh_log.log"
OUTPUT_REPORT = "ssh_honeypot_report.md"

# Data storage
unique_ips = set()
login_attempts = defaultdict(list)
executed_commands = defaultdict(list)
session_summaries = []

# Function to decode base64
def decode_base64(text):
    try:
        return base64.b64decode(text).decode("utf-8")
    except Exception:
        return text  # Return original if decoding fails

# Read log file and process entries
with open(LOG_FILE, "r") as log:
    for line in log:
        try:
            log_entry = json.loads(line)

            # Capture unique IPs
            if "src_ip" in log_entry:
                unique_ips.add(log_entry["src_ip"])

            # Capture login attempts
            if "username" in log_entry and "password" in log_entry:
                login_attempts[log_entry["username"]].append(
                    {
                        "password": log_entry["password"],
                        "status": "Success" if "success" in log_entry["message"].lower() else "Failed"
                    }
                )

            # Capture executed commands
            if "details" in log_entry and "User input" in log_entry["message"]:
                decoded_command = decode_base64(log_entry["details"])
                executed_commands[log_entry.get("username", "Unknown")].append(decoded_command)

            # Capture session summaries
            if "details" in log_entry and "Session summary" in log_entry["message"]:
                session_summaries.append(log_entry["details"])

        except json.JSONDecodeError:
            continue  # Skip lines that are not JSON formatted

# Generate Report
with open(OUTPUT_REPORT, "w") as report:
    report.write("# SSH Honeypot Attack Report\n\n")

    report.write("## **Overview**\n")
    report.write("This report provides an analysis of SSH login attempts, executed commands, and activities recorded in the honeypot.\n\n")

    # Unique Attacker IPs
    report.write("## **Unique Attacker IPs**\n")
    for ip in sorted(unique_ips):
        report.write(f"- `{ip}`\n")
    report.write("\n")

    # Login Attempts
    report.write("## **Login Attempts**\n")
    for username, attempts in login_attempts.items():
        report.write(f"### **Username: {username}**\n")
        for attempt in attempts:
            report.write(f"- **Password:** `{attempt['password']}` - **Status:** {attempt['status']}\n")
        report.write("\n")

    # Executed Commands
    report.write("## **Executed Commands**\n")
    for user, commands in executed_commands.items():
        report.write(f"### **User: {user}**\n")
        for cmd in commands:
            report.write(f"- `{cmd}`\n")
        report.write("\n")

    # Session Summaries
    report.write("## **Session Summaries**\n")
    for summary in session_summaries:
        report.write(f"- {summary}\n")
    report.write("\n")

    report.write("## **Conclusion**\n")
    report.write("This attack demonstrates attempts to brute-force SSH credentials, execute reconnaissance commands, and deploy malware.\n")

print(f"Report generated: {OUTPUT_REPORT}")
