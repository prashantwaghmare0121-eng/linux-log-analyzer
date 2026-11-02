import unittest

from loganalyzer import analyzer, db

AUTH = [
    f"Nov  2 03:10:{s:02d} web01 sshd[1]: Failed password for {u} from 203.0.113.5 port 22 ssh2"
    for s, u in enumerate(["root", "admin", "root", "test", "root", "admin"])
] + [
    "Nov  2 03:20:00 web01 sshd[2]: Failed password for root from 198.51.100.9 port 22 ssh2",
    "Nov  2 09:20:00 web01 sshd[3]: Accepted publickey for deploy from 192.0.2.11 port 22 ssh2",
    "Nov  2 09:15:01 web01 CRON[4]: ignored line",
]
ACCESS = (
    ['203.0.113.5 - - [02/Nov/2026:11:00:00 +0530] "GET /.env HTTP/1.1" 404 153 "-" "curl"'] * 5
    + ['192.0.2.10 - - [02/Nov/2026:10:00:00 +0530] "GET / HTTP/1.1" 200 500 "-" "x"'] * 3
    + ['192.0.2.10 - - [02/Nov/2026:10:00:01 +0530] "GET /a HTTP/1.1" 500 10 "-" "x"']
)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        self.auth_result = db.ingest_auth(self.conn, AUTH, 2026)
        self.access_result = db.ingest_access(self.conn, ACCESS)

    def test_ingest_counts(self):
        self.assertEqual(self.auth_result, (8, 1))
        self.assertEqual(self.access_result, (9, 0))

    def test_ssh_summary(self):
        s = analyzer.ssh_summary(self.conn)
        self.assertEqual((s["failed"], s["accepted"], s["unique_ips"]), (7, 1, 3))

    def test_suspicious_ips_respects_threshold(self):
        rows = analyzer.suspicious_ips(self.conn, threshold=5)
        self.assertEqual([r["ip"] for r in rows], ["203.0.113.5"])
        self.assertEqual(rows[0]["failed_attempts"], 6)
        self.assertEqual(rows[0]["distinct_users"], 3)
        self.assertEqual(len(analyzer.suspicious_ips(self.conn, threshold=1)), 2)

    def test_top_targeted_users(self):
        top = analyzer.top_targeted_users(self.conn, limit=1)
        self.assertEqual(top, [{"user": "root", "failed_attempts": 4}])

    def test_status_summary(self):
        got = {r["status_class"]: r["requests"] for r in analyzer.status_summary(self.conn)}
        self.assertEqual(got, {"2xx": 3, "4xx": 5, "5xx": 1})

    def test_probing_ips(self):
        self.assertEqual(analyzer.probing_ips(self.conn, 5), [{"ip": "203.0.113.5", "not_found": 5}])

    def test_report_text_renders(self):
        text = analyzer.format_report(analyzer.build_report(self.conn))
        self.assertIn("203.0.113.5", text)
        self.assertIn("Failed logins: 7", text)

    def test_empty_database(self):
        conn = db.connect(":memory:")
        s = analyzer.ssh_summary(conn)
        self.assertEqual((s["failed"], s["accepted"]), (0, 0))
        self.assertIn("none", analyzer.format_report(analyzer.build_report(conn)))


if __name__ == "__main__":
    unittest.main()
