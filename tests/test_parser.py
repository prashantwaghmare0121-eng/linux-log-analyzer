import unittest

from loganalyzer.parser import parse_access_line, parse_auth_line


class AuthParserTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        line = "Nov  2 03:10:07 web01 sshd[5506]: Failed password for root from 203.0.113.5 port 38024 ssh2"
        ev = parse_auth_line(line, 2026)
        self.assertEqual(ev["event"], "failed")
        self.assertEqual(ev["user"], "root")
        self.assertEqual(ev["ip"], "203.0.113.5")
        self.assertEqual(ev["ts"], "2026-11-02T03:10:07")

    def test_failed_password_invalid_user(self):
        line = "Nov 12 03:10:07 web01 sshd[1]: Failed password for invalid user oracle from 198.51.100.9 port 22 ssh2"
        ev = parse_auth_line(line, 2026)
        self.assertEqual(ev["user"], "oracle")
        self.assertEqual(ev["ts"], "2026-11-12T03:10:07")

    def test_accepted_login(self):
        line = "Nov  2 09:20:00 web01 sshd[9]: Accepted publickey for deploy from 192.0.2.11 port 5555 ssh2: RSA SHA256:x"
        ev = parse_auth_line(line, 2026)
        self.assertEqual(ev["event"], "accepted")
        self.assertEqual(ev["user"], "deploy")

    def test_unrelated_lines_are_ignored(self):
        self.assertIsNone(parse_auth_line("Nov  2 09:15:01 web01 CRON[2211]: session opened", 2026))
        self.assertIsNone(parse_auth_line("garbage", 2026))


class AccessParserTests(unittest.TestCase):
    def test_normal_line(self):
        line = '192.0.2.10 - - [02/Nov/2026:10:01:07 +0530] "GET /about HTTP/1.1" 200 6147 "-" "Mozilla/5.0"'
        ev = parse_access_line(line)
        self.assertEqual(ev["path"], "/about")
        self.assertEqual(ev["status"], 200)
        self.assertEqual(ev["size"], 6147)
        self.assertTrue(ev["ts"].startswith("2026-11-02T10:01:07"))

    def test_dash_size_becomes_zero(self):
        line = '192.0.2.10 - - [02/Nov/2026:10:01:07 +0530] "GET / HTTP/1.1" 304 - "-" "x"'
        self.assertEqual(parse_access_line(line)["size"], 0)

    def test_bad_line(self):
        self.assertIsNone(parse_access_line("not a log line"))


if __name__ == "__main__":
    unittest.main()
