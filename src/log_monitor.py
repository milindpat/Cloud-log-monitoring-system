import re
import time
import csv
from datetime import datetime
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("data/server_log.txt")
ALERT_FILE = Path("output/alerts.txt")
ATTACK_REPORT_FILE = Path("output/attack_report.csv")
SUSPICIOUS_IP_FILE = Path("data/suspicious_ips.txt")
THRESHOLD = 5


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

def initialize_attack_report():
    if not ATTACK_REPORT_FILE.exists():
        with open(ATTACK_REPORT_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "Failed Attempts", "Timestamp"])

def save_suspicious_ip(ip):
    try:
        with open(SUSPICIOUS_IP_FILE, "r", encoding="utf-8") as file:
            existing_ips = {line.strip() for line in file}
    except FileNotFoundError:
        existing_ips = set()

    if ip not in existing_ips:
        with open(SUSPICIOUS_IP_FILE, "a", encoding="utf-8") as file:
            file.write(ip + "\n")


def print_attack_summary(failed_attempts, alerted_ips):
    print("\nAttack Summary")
    print("--------------")
    print(f"Total attacks detected: {len(alerted_ips)}")
    print(f"Unique attacking IPs: {len(alerted_ips)}")

    if failed_attempts:
        most_aggressive_ip = max(failed_attempts, key=failed_attempts.get)
        print(f"Most aggressive IP: {most_aggressive_ip}")
        print(f"Highest failed attempts: {failed_attempts[most_aggressive_ip]}")
    else:
        print("Most aggressive IP: None")
        print("Highest failed attempts: 0")


def monitor_logs(log_file: Path, threshold: int):
    failed_attempts = defaultdict(int)
    alerted_ips = set()

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
        print_attack_summary(failed_attempts, alerted_ips)


if __name__ == "__main__":
    monitor_logs(LOG_FILE, THRESHOLD)