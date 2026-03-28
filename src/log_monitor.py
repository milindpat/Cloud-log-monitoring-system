import re
import time
import csv
import json
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("data/server_log.txt")
ALERT_FILE = Path("output/alerts.txt")
ATTACK_REPORT_FILE = Path("output/attack_report.csv")
SUSPICIOUS_IP_FILE = Path("output/suspicious_ips.txt")
SUSPICIOUS_IP_JSON_FILE = Path("output/suspicious_ips.json")
ATTACK_SUMMARY_FILE = Path("output/attack_summary.txt")
THRESHOLD = 5

def ensure_output_directories():
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUSPICIOUS_IP_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUSPICIOUS_IP_JSON_FILE.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)

def extract_ip(line: str):
    match = re.search(r'ip:(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
    return match.group(1) if match else None


def initialize_attack_report():
    if not ATTACK_REPORT_FILE.exists():
        with open(ATTACK_REPORT_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "Failed Attempts", "Timestamp"])


def write_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        file.write(f"[{timestamp}] {message}\n")


def log_attack(ip, attempts):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ATTACK_REPORT_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([ip, attempts, timestamp])

def save_suspicious_ip(ip):
    try:
        with open(SUSPICIOUS_IP_FILE, "r", encoding="utf-8") as file:
            existing_ips = {line.strip() for line in file}
    except FileNotFoundError:
        existing_ips = set()

    if ip not in existing_ips:
        with open(SUSPICIOUS_IP_FILE, "a", encoding="utf-8") as file:
            file.write(ip + "\n")

def save_suspicious_ips_json(alerted_ips):
    data = {
        "suspicious_ips": sorted(list(alerted_ips)),
        "total_suspicious_ips": len(alerted_ips),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(SUSPICIOUS_IP_JSON_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def write_attack_summary(failed_attempts, alerted_ips):
    total_failed_attempts = sum(failed_attempts.values())

    if failed_attempts:
        most_aggressive_ip = max(failed_attempts, key=failed_attempts.get)
        highest_failed_attempts = failed_attempts[most_aggressive_ip]
    else:
        most_aggressive_ip = "None"
        highest_failed_attempts = 0

    summary_lines = [
        "Attack Summary",
        "--------------",
        f"Total suspicious IPs detected: {len(alerted_ips)}",
        f"Total failed login attempts: {total_failed_attempts}",
        f"Most aggressive IP: {most_aggressive_ip}",
        f"Highest failed attempts from one IP: {highest_failed_attempts}",
        f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ]

    summary_text = "\n".join(summary_lines)

    print("\n" + summary_text)

    with open(ATTACK_SUMMARY_FILE, "w", encoding="utf-8") as file:
        file.write(summary_text + "\n")


def monitor_logs(log_file: Path, threshold: int):
    failed_attempts = defaultdict(int)
    alerted_ips = set()
    ensure_output_directories()

    print("Real-Time Log Monitoring Started...")
    print("Watching for new failed login attempts...\n")

    initialize_attack_report()

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            file.seek(0, 2)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(1)
                    continue

                line = line.strip()
                print(f"New log entry: {line}")

                if "login failed" in line.lower():
                    ip = extract_ip(line)

                    if ip:
                        failed_attempts[ip] += 1
                        print(f"Failed login count for {ip}: {failed_attempts[ip]}")

                        if failed_attempts[ip] >= threshold and ip not in alerted_ips:
                            alert_message = (
                                f"ALERT: {failed_attempts[ip]} failed login attempts detected from IP {ip}"
                            )

                            print(alert_message)
                            write_alert(alert_message)
                            log_attack(ip, failed_attempts[ip])
                            save_suspicious_ip(ip)
                            alerted_ips.add(ip)
                    else:
                        print("Warning: failed login detected but no valid IP found.")

    except FileNotFoundError:
        print(f"Error: log file '{log_file}' not found.")
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        write_attack_summary(failed_attempts, alerted_ips)
        save_suspicious_ips_json(alerted_ips)
        print(f"\nSummary saved to: {ATTACK_SUMMARY_FILE}")
        print(f"Suspicious IP JSON saved to: {SUSPICIOUS_IP_JSON_FILE}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Real-time authentication log monitoring tool")
    parser.add_argument(
        "--log",
        type=Path,
        default=LOG_FILE,
        help="Path to the log file to monitor"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=THRESHOLD,
        help="Failed login threshold before triggering an alert"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    monitor_logs(args.log, args.threshold)