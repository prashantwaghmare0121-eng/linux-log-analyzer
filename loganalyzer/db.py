"""SQLite storage."""
import sqlite3

from .parser import parse_access_line, parse_auth_line

SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_events (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    TEXT NOT NULL,
    host  TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('failed', 'accepted')),
    user  TEXT NOT NULL,
    ip    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    ip     TEXT NOT NULL,
    method TEXT NOT NULL,
    path   TEXT NOT NULL,
    status INTEGER NOT NULL,
    size   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_events (ip);
CREATE INDEX IF NOT EXISTS idx_access_ip ON access_events (ip);
"""


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def ingest_auth(conn, lines, year):
    """Insert parsed auth events. Returns (stored, skipped)."""
    rows, skipped = [], 0
    for line in lines:
        ev = parse_auth_line(line, year)
        if ev:
            rows.append((ev["ts"], ev["host"], ev["event"], ev["user"], ev["ip"]))
        else:
            skipped += 1
    conn.executemany(
        "INSERT INTO auth_events (ts, host, event, user, ip) VALUES (?, ?, ?, ?, ?)", rows
    )
    conn.commit()
    return len(rows), skipped


def ingest_access(conn, lines):
    """Insert parsed access events. Returns (stored, skipped)."""
    rows, skipped = [], 0
    for line in lines:
        ev = parse_access_line(line)
        if ev:
            rows.append((ev["ts"], ev["ip"], ev["method"], ev["path"], ev["status"], ev["size"]))
        else:
            skipped += 1
    conn.executemany(
        "INSERT INTO access_events (ts, ip, method, path, status, size) VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return len(rows), skipped
