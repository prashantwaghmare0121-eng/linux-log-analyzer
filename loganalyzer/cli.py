"""Command line interface: ingest, report, serve."""
import argparse
import json
from datetime import datetime

from . import analyzer, api, db


def build_parser():
    p = argparse.ArgumentParser(prog="loganalyzer", description="Analyze SSH and web access logs.")
    sub = p.add_subparsers(dest="command", required=True)

    ing = sub.add_parser("ingest", help="load log files into the database")
    ing.add_argument("--auth", help="path to an SSH auth log")
    ing.add_argument("--access", help="path to a combined-format access log")
    ing.add_argument("--db", default="logs.db")
    ing.add_argument("--year", type=int, default=datetime.now().year,
                     help="year for auth log timestamps (syslog lines have no year)")

    rep = sub.add_parser("report", help="print a report")
    rep.add_argument("--db", default="logs.db")
    rep.add_argument("--threshold", type=int, default=5)
    rep.add_argument("--json", action="store_true", help="output JSON instead of text")

    srv = sub.add_parser("serve", help="start the JSON API")
    srv.add_argument("--db", default="logs.db")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8000)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "ingest":
        if not (args.auth or args.access):
            raise SystemExit("Give at least one of --auth or --access.")
        conn = db.connect(args.db)
        if args.auth:
            with open(args.auth, encoding="utf-8", errors="replace") as f:
                stored, skipped = db.ingest_auth(conn, f, args.year)
            print(f"auth log: {stored} events stored, {skipped} lines skipped")
        if args.access:
            with open(args.access, encoding="utf-8", errors="replace") as f:
                stored, skipped = db.ingest_access(conn, f)
            print(f"access log: {stored} events stored, {skipped} lines skipped")
        conn.close()
    elif args.command == "report":
        conn = db.connect(args.db)
        report = analyzer.build_report(conn, args.threshold)
        conn.close()
        print(json.dumps(report, indent=2) if args.json else analyzer.format_report(report))
    elif args.command == "serve":
        db.connect(args.db).close()  # make sure the schema exists
        api.serve(args.db, args.host, args.port)
