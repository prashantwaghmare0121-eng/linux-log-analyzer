# Linux Log Analyzer

A small Python tool that reads Linux **SSH auth logs** and **web server access logs**, stores them in **SQLite**, and reports on suspicious activity such as SSH brute-force attempts and scanners probing for files like `/.env`. It has a command line interface and a read-only **JSON REST API**.

It uses only the Python standard library, so there is nothing to install.

## Features
- Parses `sshd` failed and accepted logins from syslog-style auth logs
- Parses nginx / Apache "combined" access logs
- Stores events in SQLite and analyzes them with SQL (`GROUP BY`, `HAVING`, aggregates)
- Flags IPs with many failed SSH logins (configurable threshold)
- Shows the most targeted usernames, HTTP status breakdown, top paths, and IPs that trigger many 404s
- Text or JSON reports, plus an HTTP API
- Unit tests for the parsers, SQL analysis and API

## Requirements
Python 3.9 or newer.

## Quick start
```bash
python scripts/generate_sample_logs.py        # optional: regenerates the synthetic sample logs
python -m loganalyzer ingest --auth sample_logs/auth.log --access sample_logs/access.log --db logs.db --year 2026
python -m loganalyzer report --db logs.db --threshold 5
```

Example output:
```
=== SSH ===
Failed logins: 24 | Accepted: 2 | Unique IPs: 5

Suspicious IPs (>= 5 failed logins):
  203.0.113.5        12 attempts, 6 usernames
  203.0.113.77        9 attempts, 2 usernames

Most targeted usernames:
  root                7
  admin               5
  ...

=== HTTP ===
Responses by status class:
  2xx: 30
  3xx: 8
  4xx: 14
  5xx: 2
...
```

Use `--json` for machine-readable output. To analyze a real server, point `--auth` at `/var/log/auth.log` (you may need `sudo` to read it) and `--access` at your nginx or Apache access log.

## REST API
```bash
python -m loganalyzer serve --db logs.db --port 8000
```

| Endpoint | Description |
|---|---|
| `GET /health` | Service status |
| `GET /summary` | Failed / accepted SSH logins and unique IPs |
| `GET /suspicious-ips?threshold=5` | IPs with at least `threshold` failed logins |
| `GET /failed-logins?limit=5` | Most targeted usernames |

Invalid query values return `400`; unknown paths return `404`.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Docker
```bash
docker build -t linux-log-analyzer .
docker run -p 8000:8000 linux-log-analyzer
```
The container loads the sample logs and serves the API on port 8000.

## Project layout
```
loganalyzer/
  parser.py     # regex parsers for auth and access log lines
  db.py         # SQLite schema and ingestion
  analyzer.py   # SQL queries and report formatting
  api.py        # JSON API (http.server)
  cli.py        # ingest / report / serve commands
tests/          # unittest suites
sample_logs/    # synthetic data (RFC 5737 documentation IP ranges)
scripts/        # sample log generator
```

## Notes and limitations
- The sample logs are **synthetic**. They use reserved documentation IP addresses, not real traffic.
- Syslog lines carry no year, so `ingest` takes a `--year` option.
- Only failed and accepted SSH logins are parsed; other log lines are counted as skipped.
- Detection is simple threshold counting, not a replacement for tools like fail2ban.
- This project was written with help from an AI assistant (Claude). I reviewed, ran and tested the code.
