import random
from datetime import datetime, timedelta

random.seed(42)

normal_templates = [
    ("GET /api/users/{id}", 200),
    ("GET /api/products", 200),
    ("POST /api/orders", 201),
    ("GET /api/health", 200),
    ("GET /static/style.css", 200),
    ("GET /favicon.ico", 200),
    ("POST /api/login", 200),
    ("GET /api/search?q=keyword", 200),
]

spike_templates = [
    ("GET /api/deprecated/endpoint", 404),
    ("POST /api/payments", 500),
    ("GET /api/users/{id}", 502),
    ("GET /api/internal/admin", 403),
]

base_time = datetime(2024, 6, 15, 8, 0, 0)
lines = []
ips = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]
users = ["-", "alice", "bob", "charlie", "dave"]
methods = ["GET", "POST", "PUT", "DELETE"]

for minute in range(120):
    current = base_time + timedelta(minutes=minute)
    ts = current.strftime("%d/%b/%Y:%H:%M:%S +0800")

    for _ in range(random.randint(5, 15)):
        template, status = random.choice(normal_templates)
        ip = random.choice(ips)
        user = random.choice(users)
        size = random.randint(100, 50000)
        url = template.replace("{id}", str(random.randint(1, 1000)))
        method = url.split()[0] if " " in url else "GET"
        path = url.split()[-1] if " " in url else url
        line = f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'
        lines.append((current, line))

    if 50 <= minute <= 80:
        for _ in range(random.randint(15, 40)):
            template, status = random.choice(spike_templates)
            ip = random.choice(ips)
            user = random.choice(users)
            size = random.randint(100, 5000)
            url = template.replace("{id}", str(random.randint(1, 1000)))
            method = url.split()[0] if " " in url else "GET"
            path = url.split()[-1] if " " in url else url
            line = f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'
            lines.append((current, line))

lines.sort(key=lambda x: x[0])

with open("sample_access.log", "w", encoding="utf-8") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"Generated {len(lines)} log lines to sample_access.log")

app_lines = []
base_time2 = datetime(2024, 6, 15, 8, 0, 0)
loggers = ["auth.service", "payment.service", "api.gateway", "db.pool", "cache.redis"]
levels = ["INFO", "DEBUG", "WARN", "ERROR"]

for minute in range(120):
    current = base_time2 + timedelta(minutes=minute)
    ts = current.strftime("%Y-%m-%d %H:%M:%S")

    for _ in range(random.randint(3, 10)):
        logger = random.choice(loggers)
        level = random.choice(levels[:3])
        if level == "INFO":
            msgs = [
                f"Request processed in {random.randint(10, 200)}ms",
                f"User session created for user_id={random.randint(1, 1000)}",
                f"Cache hit for key=product:{random.randint(1, 500)}",
                f"Database query returned {random.randint(1, 100)} rows",
            ]
        elif level == "DEBUG":
            msgs = [
                f"Processing request headers: content-length={random.randint(100, 10000)}",
                f"Token validation succeeded for client_id={random.randint(1, 50)}",
                f"Connection pool status: active={random.randint(1, 20)}, idle={random.randint(1, 10)}",
            ]
        else:
            msgs = [
                f"Slow query detected: {random.randint(500, 5000)}ms",
                f"Retry attempt {random.randint(1, 3)} for external service",
            ]
        msg = random.choice(msgs)
        line = f"{ts} [{level}] {logger}: {msg}"
        app_lines.append((current, line))

    if 60 <= minute <= 90:
        for _ in range(random.randint(10, 25)):
            logger = "payment.service"
            ts_err = current.strftime("%Y-%m-%d %H:%M:%S")
            msgs = [
                f"Payment gateway timeout: order_id={random.randint(10000, 99999)}",
                f"Connection refused to payment provider: port={random.randint(8000, 9000)}",
                f"SSL handshake failed: certificate expired",
                f"Transaction failed: insufficient funds account_id={random.randint(1, 1000)}",
            ]
            msg = random.choice(msgs)
            line = f"{ts_err} [ERROR] {logger}: {msg}"
            app_lines.append((current, line))

app_lines.sort(key=lambda x: x[0])

with open("sample_app.log", "w", encoding="utf-8") as f:
    for _, line in app_lines:
        f.write(line + "\n")

print(f"Generated {len(app_lines)} log lines to sample_app.log")
