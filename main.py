import re
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

# Parse timestamps from log
def parse_timestamp(line):
    try:
        parts = line.split()
        timestamp_str = " ".join(parts[0:3])
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    except:
        return None

# Simulated geo-IP lookup
def fake_geo_lookup(ip):
    if ip == "192.168.1.10":
        return "Russia"
    return "Unknown"

# Load log file
with open("logs/auth.log", "r") as file:
    lines = file.readlines()

# Extract failed login attempts
failed_logins = defaultdict(list)
pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

for line in lines:
    match = re.search(pattern, line)
    if match:
        ip = match.group(1)
        timestamp = parse_timestamp(line)
        if timestamp:
            failed_logins[ip].append(timestamp)

# Detect brute-force attempts (5+ in 2 mins)
threshold = 5
window = timedelta(minutes=2)
suspicious_ips = []

for ip, timestamps in failed_logins.items():
    timestamps.sort()
    for i in range(len(timestamps) - threshold + 1):
        if timestamps[i + threshold - 1] - timestamps[i] <= window:
            suspicious_ips.append(ip)
            break

# Write report
with open("report.txt", "w") as report:
    if suspicious_ips:
        for ip in suspicious_ips:
            country = fake_geo_lookup(ip)
            report.write(f"[!] {ip} ({country}) – Brute force attempt\n")
    else:
        report.write("No brute force detected.\n")

# Simulate blocking IPs
with open("blocklist.txt", "w") as blockfile:
    for ip in suspicious_ips:
        blockfile.write(ip + "\n")

# Plot attempts
ip_counts = {ip: len(times) for ip, times in failed_logins.items()}
plt.bar(ip_counts.keys(), ip_counts.values(), color="orange")
plt.xlabel("IP Address")
plt.ylabel("Failed Attempts")
plt.title("Failed Login Attempts Per IP")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("attempts_chart.png")

print("[✓] Detection complete. Report, blocklist, and chart generated.")
