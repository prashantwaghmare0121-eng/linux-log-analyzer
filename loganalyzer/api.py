"""A small read-only JSON API built on the standard library."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import analyzer, db

# path -> (query parameter name, function(conn, n))
ROUTES = {
    "/summary": (None, lambda conn, n: analyzer.ssh_summary(conn)),
    "/suspicious-ips": ("threshold", analyzer.suspicious_ips),
    "/failed-logins": ("limit", analyzer.top_targeted_users),
}


def _positive_int(query, name, default=5):
    try:
        value = int(query.get(name, [default])[0])
    except ValueError:
        return None
    return value if value > 0 else None


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, payload):
            body = json.dumps(payload, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/health":
                return self._send(200, {"status": "ok"})
            route = ROUTES.get(url.path)
            if route is None:
                return self._send(404, {"error": "not found"})
            param, func = route
            n = _positive_int(parse_qs(url.query), param) if param else 0
            if n is None:
                return self._send(400, {"error": f"'{param}' must be a positive integer"})
            conn = db.connect(db_path)
            try:
                self._send(200, func(conn, n))
            finally:
                conn.close()

        def log_message(self, fmt, *args):  # keep output quiet
            pass

    return Handler


def serve(db_path, host="127.0.0.1", port=8000):
    server = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"Serving on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
