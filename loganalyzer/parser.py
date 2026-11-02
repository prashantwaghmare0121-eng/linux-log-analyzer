"""Line parsers for two common Linux log formats.

* SSH auth log (syslog style, e.g. /var/log/auth.log)
* Web access log in the "combined" format (nginx / Apache)

Each parser returns a dict for a line it understands, or None for anything else.
"""
import re
from datetime import datetime

AUTH_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s"
    r"sshd\[\d+\]:\s(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r"(?P<status>\d{3}) (?P<size>\d+|-)"
)


def parse_auth_line(line, year):
    """Parse one sshd line. Only failed and accepted logins are kept.

    Syslog timestamps have no year, so the caller supplies it.
    """
    m = AUTH_RE.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    for regex, event in ((FAILED_RE, "failed"), (ACCEPTED_RE, "accepted")):
        found = regex.search(msg)
        if found:
            ts_text = re.sub(r"\s+", " ", m.group("ts"))
            ts = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")
            return {
                "ts": ts.isoformat(),
                "host": m.group("host"),
                "event": event,
                "user": found.group("user"),
                "ip": found.group("ip"),
            }
    return None


def parse_access_line(line):
    """Parse one combined-format access log line."""
    m = ACCESS_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    size = m.group("size")
    return {
        "ts": ts.isoformat(),
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": int(m.group("status")),
        "size": 0 if size == "-" else int(size),
    }
