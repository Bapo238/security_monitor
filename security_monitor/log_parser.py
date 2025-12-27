#!/usr/bin/env python3

import re

import time

import os

import smtplib

from datetime import datetime

from collections import defaultdict

from email.mime.text import MIMEText


class SecurityMonitor:

    def __init__(self, log_file):

        self.log_file = log_file

        # Ubuntu specific failure patterns

        self.failed_patterns = [

            r'Failed password',

            r'invalid user',

            r'authentication failure',

            r'Connection closed by authenticating user'

        ]

        self.suspicious_ips = defaultdict(int)

        self.alert_threshold = 3 


    def tail_log(self):

        """Standard 'tail -f' behavior for Linux logs"""

        try:

            with open(self.log_file, 'r') as f:

                f.seek(0, 2)  # Start at the end of the file

                while True:

                    line = f.readline()

                    if not line:

                        time.sleep(0.1)

                        continue

                    yield line

        except PermissionError:

            print("Error: Permission Denied. Run this script with 'sudo'.")

            exit(1)

        except FileNotFoundError:

            print(f"Error: {self.log_file} not found!")

            exit(1)


    def parse_line(self, line):

        """Regex tuned for Ubuntu /var/log/auth.log format"""

        patterns = {

            # Matches 'Dec 25 14:00:01'

            'timestamp': r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', 

            'user': r'for (?:invalid user )?(\w+)',

            'ip': r'from (\d+\.\d+\.\d+\.\d+)'

        }

        

        extracted = {}

        for key, pattern in patterns.items():

            match = re.search(pattern, line)

            if match:

                extracted[key] = match.group(1) if key != 'user' else match.group(match.lastindex)

        

        extracted['message'] = line.strip()

        return extracted


    def check_threats(self, log_data):

        alerts = []

        for pattern in self.failed_patterns:

            if re.search(pattern, log_data['message'], re.IGNORECASE):

                alerts.append(f"Failed Attempt: {log_data['message']}")

                

                if 'ip' in log_data:

                    ip = log_data['ip']

                    self.suspicious_ips[ip] += 1

                    if self.suspicious_ips[ip] >= self.alert_threshold:

                        alerts.append(f"CRITICAL: Brute Force detected from IP {ip}")

        return alerts


    def send_alert(self, alert_message):

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        formatted_alert = f"[{timestamp}] SECURITY ALERT: {alert_message}"

        

        # Console output

        print(f"\033[91m{formatted_alert}\033[0m") 

        

        # Log to file

        with open('security_alerts.log', 'a') as f:

            f.write(formatted_alert + '\n')


        # Trigger Email

        self.send_email_alert(formatted_alert)


    def send_email_alert(self, message):

        # --- CONFIGURATION START ---

        sender = "michaelclanor2@gmail.com"

        receiver = "michaelclanor2@gmail.com" # Can be the same

        password = "deab wrgj lzkx nbmn"    # 16-character Google App Password

        # --- CONFIGURATION END ---


        msg = MIMEText(message)

        msg['Subject'] = 'VM Security Alert: Intrusion Detected'

        msg['From'] = sender

        msg['To'] = receiver


        try:

            # Use Gmail's SMTP settings

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:

                server.login(sender, password)

                server.sendmail(sender, receiver, msg.as_string())

        except Exception as e:

            print(f"Email failed: {e}")


    def monitor(self):

        print(f"Monitoring {self.log_file} for real-time threats...")

        for line in self.tail_log():

            log_data = self.parse_line(line)

            alerts = self.check_threats(log_data)

            for alert in alerts:

                self.send_alert(alert)


if __name__ == "__main__":

    # Pointing to the REAL Ubuntu auth log

    monitor = SecurityMonitor('/var/log/auth.log')

    monitor.monitor()
