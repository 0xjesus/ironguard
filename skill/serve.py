#!/usr/bin/env python3
"""IronGuard dashboard server — serves the live dashboard + JSON API from SQLite.

Reads ~/ironguard/ironguard.db (written by audit.py runs / cron) and serves:
  GET /             -> dashboard.html (auto-refreshing)
  GET /api/latest   -> latest scan: summary, per-repo findings, recent history

Usage:  python3 serve.py        (port 8787, or $IRONGUARD_PORT)
"""
import os, json, sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("IRONGUARD_DB", os.path.join(HERE, "ironguard.db"))
PORT = int(os.environ.get("IRONGUARD_PORT", "8787"))
RISK_ORDER = "CASE risk WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def latest():
    if not os.path.exists(DB):
        return {"repos": [], "summary": {}, "history": [], "generated_at": None}
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    scan = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    if not scan:
        con.close()
        return {"repos": [], "summary": {}, "history": [], "generated_at": None}
    sid = scan["id"]
    repos = {}
    for r in con.execute(f"SELECT * FROM repos WHERE scan_id=? ORDER BY {RISK_ORDER}, name", (sid,)):
        repos[r["name"]] = {"name": r["name"], "root": r["root"], "risk": r["risk"],
                            "secrets": [], "vulnerabilities": [], "code_vulnerabilities": []}
    KIND = {"secret": "secrets", "vuln": "vulnerabilities", "code": "code_vulnerabilities"}
    for f in con.execute("SELECT * FROM findings WHERE scan_id=?", (sid,)):
        d = json.loads(f["detail"])
        if f["repo"] in repos:
            repos[f["repo"]][KIND.get(f["kind"], "vulnerabilities")].append(d)
    hist = [dict(x) for x in con.execute(
        "SELECT ts,repositories,secrets,vulnerable_deps,malicious_deps FROM scans ORDER BY id DESC LIMIT 40")]
    con.close()
    return {
        "root": scan["root"], "generated_at": scan["ts"], "scan_id": sid,
        "summary": {"repositories": scan["repositories"], "secrets": scan["secrets"],
                    "vulnerable_dependencies": scan["vulnerable_deps"],
                    "malicious_dependencies": scan["malicious_deps"]},
        "repos": list(repos.values()),
        "history": list(reversed(hist)),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html", "/dashboard.html"):
            try:
                body = open(os.path.join(HERE, "dashboard.html"), "rb").read()
            except OSError:
                body = b"<h1>dashboard.html not found next to serve.py</h1>"
            self._send(200, body, "text/html; charset=utf-8")
        elif path == "/api/latest":
            self._send(200, json.dumps(latest()).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print(f"IronGuard dashboard live at http://127.0.0.1:{PORT}   (db={DB})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
