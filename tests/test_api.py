import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from loganalyzer import api, db


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(cls.tmp.name, "t.db")
        conn = db.connect(path)
        lines = [f"Nov  2 03:10:0{i} web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"
                 for i in range(6)]
        db.ingest_auth(conn, lines, 2026)
        conn.close()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), api.make_handler(path))
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_health(self):
        self.assertEqual(self.get("/health"), (200, {"status": "ok"}))

    def test_summary(self):
        status, body = self.get("/summary")
        self.assertEqual(status, 200)
        self.assertEqual(body["failed"], 6)

    def test_suspicious_ips(self):
        status, body = self.get("/suspicious-ips?threshold=5")
        self.assertEqual(status, 200)
        self.assertEqual(body[0]["ip"], "203.0.113.5")
        self.assertEqual(self.get("/suspicious-ips?threshold=10")[1], [])

    def test_bad_query_value(self):
        self.assertEqual(self.get("/suspicious-ips?threshold=abc")[0], 400)
        self.assertEqual(self.get("/failed-logins?limit=0")[0], 400)

    def test_unknown_path(self):
        self.assertEqual(self.get("/nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
