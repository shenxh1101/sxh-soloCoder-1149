import random
from datetime import date, timedelta

random.seed(42)

today = date.today()

lines = []
hostnames = ["web01", "web02", "app01", "db01", "cache01"]
programs = ["sshd", "nginx", "kernel", "cron", "systemd"]

messages_normal = [
    "Accepted password for root from 192.168.1.100 port 22 ssh2",
    "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
    "connection from 192.168.1.50 port 80",
    "out of memory: Killed process 12345 (java)",
    "session opened for user www-data by (uid=0)",
    "Starting Daily Cleanup Service...",
    "Finished Daily Cleanup Service.",
]

base_hour = 8
for minute in range(120):
    h = base_hour + minute // 60
    m = minute % 60
    ts_str = f"{today.strftime('%b')} {today.day:2d} {h:02d}:{m:02d}:00"

    for _ in range(random.randint(1, 4)):
        host = random.choice(hostnames)
        prog = random.choice(programs)
        pid = random.randint(1000, 99999)
        msg = random.choice(messages_normal)
        line = f"{ts_str} {host} {prog}[{pid}]: {msg}"
        lines.append(line)

print(f"Generated {len(lines)} syslog lines (date: {today})")
with open("sample_syslog.log", "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line + "\n")
print("Saved to sample_syslog.log")
