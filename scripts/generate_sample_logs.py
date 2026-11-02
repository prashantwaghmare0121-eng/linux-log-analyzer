"""Generate small synthetic log files for demos. All IPs come from documentation ranges
(RFC 5737), so no real addresses are used. Run from the project root."""
import random

random.seed(42)
MONTH_DAY = "Nov  2"


def auth_lines():
    lines = []
    attackers = {"203.0.113.5": ["root", "admin", "test", "oracle", "ubuntu", "user"],
                 "203.0.113.77": ["root", "pi"],
                 "198.51.100.23": ["admin"]}
    for ip, users in attackers.items():
        for i in range(random.randint(7, 12) if ip != "198.51.100.23" else 3):
            u = users[i % len(users)]
            sec = random.randint(0, 59)
            prefix = "invalid user " if u not in ("root",) else ""
            lines.append(f"{MONTH_DAY} 03:{random.randint(10, 40):02d}:{sec:02d} web01 "
                         f"sshd[{random.randint(1000, 9999)}]: Failed password for {prefix}{u} "
                         f"from {ip} port {random.randint(30000, 60000)} ssh2")
    for ip, user in (("192.0.2.10", "prashant"), ("192.0.2.11", "deploy")):
        lines.append(f"{MONTH_DAY} 09:{random.randint(10, 59):02d}:00 web01 "
                     f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} "
                     f"from {ip} port {random.randint(30000, 60000)} ssh2: RSA SHA256:abc")
    lines.append(f"{MONTH_DAY} 09:15:01 web01 CRON[2211]: pam_unix(cron:session): session opened")
    random.shuffle(lines)
    return sorted(lines, key=lambda l: l[:15])


def access_lines():
    ok_paths = ["/", "/index.html", "/about", "/contact", "/static/app.js"]
    scan_paths = ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin", "/xmlrpc.php", "/.git/config"]
    lines = []
    for _ in range(40):
        ip = random.choice(["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"])
        path = random.choice(ok_paths)
        status = random.choices([200, 304, 500], weights=[85, 12, 3])[0]
        lines.append(f'{ip} - - [02/Nov/2026:10:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} +0530] '
                     f'"GET {path} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "Mozilla/5.0"')
    for _ in range(14):
        lines.append(f'203.0.113.5 - - [02/Nov/2026:11:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} +0530] '
                     f'"GET {random.choice(scan_paths)} HTTP/1.1" 404 153 "-" "curl/7.88"')
    return sorted(lines, key=lambda l: l.split("[")[1])


if __name__ == "__main__":
    with open("sample_logs/auth.log", "w") as f:
        f.write("\n".join(auth_lines()) + "\n")
    with open("sample_logs/access.log", "w") as f:
        f.write("\n".join(access_lines()) + "\n")
    print("wrote sample_logs/auth.log and sample_logs/access.log")
