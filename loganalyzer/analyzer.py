"""SQL-based analysis of the stored events."""


def ssh_summary(conn):
    row = conn.execute(
        """SELECT
               COALESCE(SUM(event = 'failed'), 0)   AS failed,
               COALESCE(SUM(event = 'accepted'), 0) AS accepted,
               COUNT(DISTINCT ip)                   AS unique_ips
           FROM auth_events"""
    ).fetchone()
    return dict(row)


def suspicious_ips(conn, threshold=5):
    """IPs with at least `threshold` failed SSH logins (possible brute force)."""
    rows = conn.execute(
        """SELECT ip,
                  COUNT(*)             AS failed_attempts,
                  COUNT(DISTINCT user) AS distinct_users,
                  MIN(ts)              AS first_seen,
                  MAX(ts)              AS last_seen
           FROM auth_events
           WHERE event = 'failed'
           GROUP BY ip
           HAVING COUNT(*) >= ?
           ORDER BY failed_attempts DESC, ip""",
        (threshold,),
    ).fetchall()
    return [dict(r) for r in rows]


def top_targeted_users(conn, limit=5):
    rows = conn.execute(
        """SELECT user, COUNT(*) AS failed_attempts
           FROM auth_events
           WHERE event = 'failed'
           GROUP BY user
           ORDER BY failed_attempts DESC, user
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def status_summary(conn):
    rows = conn.execute(
        """SELECT (status / 100) || 'xx' AS status_class, COUNT(*) AS requests
           FROM access_events
           GROUP BY status / 100
           ORDER BY status / 100"""
    ).fetchall()
    return [dict(r) for r in rows]


def top_paths(conn, limit=5):
    rows = conn.execute(
        """SELECT path, COUNT(*) AS requests
           FROM access_events
           GROUP BY path
           ORDER BY requests DESC, path
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def probing_ips(conn, threshold=5):
    """IPs that received many 404 responses, which usually means a scanner."""
    rows = conn.execute(
        """SELECT ip, COUNT(*) AS not_found
           FROM access_events
           WHERE status = 404
           GROUP BY ip
           HAVING COUNT(*) >= ?
           ORDER BY not_found DESC, ip""",
        (threshold,),
    ).fetchall()
    return [dict(r) for r in rows]


def build_report(conn, threshold=5):
    return {
        "ssh_summary": ssh_summary(conn),
        "suspicious_ips": suspicious_ips(conn, threshold),
        "top_targeted_users": top_targeted_users(conn),
        "http_status": status_summary(conn),
        "top_paths": top_paths(conn),
        "probing_ips": probing_ips(conn, threshold),
        "threshold": threshold,
    }


def format_report(report):
    s = report["ssh_summary"]
    out = ["=== SSH ===",
           f"Failed logins: {s['failed']} | Accepted: {s['accepted']} | Unique IPs: {s['unique_ips']}",
           "", f"Suspicious IPs (>= {report['threshold']} failed logins):"]
    out += [f"  {r['ip']:<16} {r['failed_attempts']:>4} attempts, {r['distinct_users']} usernames"
            for r in report["suspicious_ips"]] or ["  none"]
    out += ["", "Most targeted usernames:"]
    out += [f"  {r['user']:<16} {r['failed_attempts']:>4}" for r in report["top_targeted_users"]] or ["  none"]
    out += ["", "=== HTTP ===", "Responses by status class:"]
    out += [f"  {r['status_class']}: {r['requests']}" for r in report["http_status"]] or ["  none"]
    out += ["", "Most requested paths:"]
    out += [f"  {r['requests']:>4}  {r['path']}" for r in report["top_paths"]] or ["  none"]
    out += ["", f"Probing IPs (>= {report['threshold']} 404 responses):"]
    out += [f"  {r['ip']:<16} {r['not_found']:>4} x 404" for r in report["probing_ips"]] or ["  none"]
    return "\n".join(out)
