from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Use the email credentials from the .env file
email_sender = os.getenv("EMAIL_USER")
email_password = os.getenv("EMAIL_PASS")

import re
import time
import smtplib
import socket
import requests
from datetime import datetime, timedelta
from collections import defaultdict, deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# CONFIGURATION
log_file = "test_log.txt"
 # Update this path based on your OS
threshold = 5  # Number of failed attempts
window = timedelta(minutes=5)  # Time window to count failed attempts
email_sender = "youremail@example.com"
email_password = "yourpassword"
email_receiver = "receiver@example.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587

# PATTERN TO DETECT FAILED LOGIN
pattern = r"Failed password for (invalid user )?\w+ from (\d{1,3}(?:\.\d{1,3}){3})"

# TRACKING VARIABLES
failed_logins = defaultdict(deque)
suspicious_ips = []

# 📬 Email alert
def send_email_alert(ip):
    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['Subject'] = f"Brute Force Alert: {ip}"

    body = f"Brute force attack detected from IP: {ip} at {datetime.now()}."
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_sender, email_password)
        server.sendmail(email_sender, email_receiver, msg.as_string())
        server.quit()
        print("[EMAIL] Alert sent successfully.")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

# 🌍 Geolocation
def real_geo_lookup(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/")
        data = res.json()
        city = data.get("city", "Unknown")
        country = data.get("country_name", "Unknown")
        return f"{city}, {country}"
    except:
        return "Unknown Location"

# 🚫 Simulate IP Blocking
def block_ip(ip):
    print(f"[BLOCK] IP {ip} would be blocked (simulated).")

# 🕵️ Monitor the log file in real time
def follow_log(file_path):
    with open(file_path, "r") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

# 🕒 Extract timestamp from each line (simplified)
def parse_timestamp(line):
    try:
        date_str = " ".join(line.split()[:3])
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S")
        now = datetime.now()
        return dt.replace(year=now.year)
    except:
        return None

# 🔍 Main detection loop
for line in follow_log(log_file):
    match = re.search(pattern, line)
    if match:
        ip = match.group(2)
        timestamp = parse_timestamp(line)
        if timestamp:
            failed_logins[ip].append(timestamp)

            # Keep only recent attempts within time window
            timestamps = failed_logins[ip]
            timestamps = deque([t for t in timestamps if t > timestamp - window])
            failed_logins[ip] = timestamps

            # 🚨 Brute Force Detected
            if len(timestamps) >= threshold and ip not in suspicious_ips:
                suspicious_ips.append(ip)
                print(f"[ALERT] Brute force detected from {ip}")

                # 📝 Log to report.txt
                with open("report.txt", "a") as report_file:
                    report_file.write(f"{datetime.now()} - Brute force detected from {ip}\n")

                # 📝 Add to blocklist.txt
                with open("blocklist.txt", "a") as blocklist_file:
                    blocklist_file.write(f"{ip}\n")

                # 📬 Email alert
                send_email_alert(ip)

                # 🌍 Show location
                location = real_geo_lookup(ip)
                print(f"[GEO] IP origin: {location}")

                # 🚫 Block IP
                block_ip(ip)
