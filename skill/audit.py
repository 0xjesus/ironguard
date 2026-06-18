#!/usr/bin/env python3
"""IronGuard — deterministic read-only workspace security auditor.

Scans every repository under a workspace root for exposed secrets and audits
dependency manifests against the live OSV.dev vulnerability/malware database,
then writes a self-contained dashboard data file.

Usage:  python3 audit.py [WORKSPACE_ROOT] [OUTPUT_DIR]
Defaults: WORKSPACE_ROOT=cwd, OUTPUT_DIR=~/ironguard

Read-only: never writes to or modifies the scanned repositories. Output (report.js
+ report.json) goes only to OUTPUT_DIR. Secret values are masked, never stored raw.
"""
import os, re, sys, json, sqlite3, datetime, urllib.request

# Optional LLM deep code analysis (NEAR AI confidential TEE). On unless IRONGUARD_AI=0.
AI_ENABLED = os.environ.get("IRONGUARD_AI", "1") != "0"
try:
    import ai_analyze
except Exception:
    ai_analyze = None

SECRET_PATTERNS = [
    ("AWS Access Key ID", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", "high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("OpenAI API Key", "high", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("Slack Token", "high", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API Key", "high", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe Secret Key", "critical", re.compile(r"[sr]k_live_[0-9a-zA-Z]{20,}")),
    ("NPM Token", "high", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("Private Key Block", "critical", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
]
GENERIC = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret|auth[_-]?token)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9/+_=.\-]{16,})['\"]?")
MANIFESTS = {"package.json": "package.json", "requirements.txt": "requirements.txt", "Cargo.toml": "cargo.toml"}
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", "venv", ".venv", "__pycache__", ".next", "vendor"}
SECRET_FILE_HINT = re.compile(r"(\.env|\.pem|\.key|\.cfg|\.conf|\.ya?ml|\.json|\.toml|\.ini|\.txt|secret|config|credential)", re.I)
RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def mask(s):
    return (s[:4] + "…" + s[-4:] + f" ({len(s)} chars)") if len(s) > 10 else "•" * len(s)


def shannon(s):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def scan_secrets(path, content):
    out = []
    for i, line in enumerate(content.splitlines(), 1):
        for kind, sev, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if m:
                out.append({"path": path, "line": i, "kind": kind, "severity": sev, "preview": mask(m.group(0))})
        g = GENERIC.search(line)
        if g and shannon(g.group(2)) >= 3.0:
            out.append({"path": path, "line": i, "kind": "Generic Secret Assignment", "severity": "medium", "preview": mask(g.group(2))})
    return out


def clean_version(spec):
    s = spec.strip().lstrip("^~=><v ")
    tok = ""
    for c in s:
        if c.isalnum() or c in ".-+":
            tok += c
        else:
            break
    return tok if tok[:1].isdigit() else None


def parse_manifest(kind, content):
    deps = []
    if kind == "package.json":
        try:
            v = json.loads(content)
        except Exception:
            return deps
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, spec in (v.get(key) or {}).items():
                if isinstance(spec, str):
                    cv = clean_version(spec)
                    if cv:
                        deps.append(("npm", name, cv))
    elif kind == "requirements.txt":
        for raw in content.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-") or "==" not in line:
                continue
            name = line.split("==", 1)[0].split("[", 1)[0].strip()
            ver = ""
            for c in line.split("==", 1)[1].strip():
                if c.isalnum() or c in ".-+!":
                    ver += c
                else:
                    break
            if name and ver:
                deps.append(("PyPI", name, ver))
    elif kind == "cargo.toml":
        in_deps = False
        for raw in content.splitlines():
            t = raw.strip()
            if t.startswith("["):
                in_deps = t in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
                continue
            if not in_deps or not t or t.startswith("#") or "=" not in t:
                continue
            name = t.split("=", 1)[0].strip().strip('"')
            rhs = t.split("=", 1)[1].strip()
            ver = None
            if rhs.startswith("{"):
                m = re.search(r'version\s*=\s*"([^"]+)"', rhs)
                ver = m.group(1) if m else None
            elif rhs.startswith('"'):
                ver = rhs.strip('"')
            if ver and name:
                cv = clean_version(ver)
                if cv:
                    deps.append(("crates.io", name, cv))
    return deps


def osv_query(deps):
    findings = []
    deps = list(dict.fromkeys(deps))
    for i in range(0, len(deps), 200):
        chunk = deps[i:i + 200]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in chunk]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                     headers={"Content-Type": "application/json", "User-Agent": "IronGuard/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
        except Exception as ex:
            findings.append({"_error": f"OSV query failed: {ex}"})
            continue
        for j, res in enumerate(data.get("results", [])):
            e, n, v = chunk[j]
            ids = [x.get("id") for x in (res.get("vulns") or []) if x.get("id")]
            if not ids:
                continue
            findings.append({"ecosystem": e, "name": n, "version": v, "advisory_ids": ids,
                             "advisory_count": len(ids), "malicious": any(i.startswith("MAL") for i in ids)})
    return findings


def repo_risk(secrets, vulns, code=None):
    code = code or []
    worst_code = max([RANK.get(c.get("severity"), 0) for c in code], default=0)
    sec = max([RANK.get(s["severity"], 0) for s in secrets], default=0)
    if any(v.get("malicious") for v in vulns) or worst_code == 3 or sec == 3:
        return "critical"
    if vulns or code or sec == 2 or worst_code == 2:
        return "high"
    if sec == 1 or worst_code == 1:
        return "medium"
    return "low"


def audit_repo(repo_root):
    secrets, deps = [], []
    for dirpath, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            fp = os.path.join(dirpath, f)
            rel = os.path.relpath(fp, repo_root)
            if f in MANIFESTS:
                try:
                    deps += parse_manifest(MANIFESTS[f], open(fp, encoding="utf-8", errors="ignore").read())
                except Exception:
                    pass
            if SECRET_FILE_HINT.search(f):
                try:
                    secrets += scan_secrets(rel, open(fp, encoding="utf-8", errors="ignore").read())
                except Exception:
                    pass
    vulns = [v for v in osv_query(deps) if "_error" not in v] if deps else []
    code = ai_analyze.analyze_repo(repo_root) if (AI_ENABLED and ai_analyze) else []
    return {"secrets": secrets, "vulnerabilities": vulns, "code_vulnerabilities": code,
            "dependencies_checked": len(set(deps)), "risk": repo_risk(secrets, vulns, code)}


def write_sqlite(report, db_path):
    """Persist this scan + its findings as a new row set (full history retained)."""
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, root TEXT,
            repositories INT, secrets INT, vulnerable_deps INT, malicious_deps INT);
        CREATE TABLE IF NOT EXISTS repos(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INT, name TEXT, root TEXT,
            risk TEXT, secrets INT, vulns INT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INT, repo TEXT,
            kind TEXT, severity TEXT, detail TEXT);
        """
    )
    s = report["summary"]
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    cur = con.execute(
        "INSERT INTO scans(ts,root,repositories,secrets,vulnerable_deps,malicious_deps) VALUES(?,?,?,?,?,?)",
        (ts, report["root"], s["repositories"], s["secrets"], s["vulnerable_dependencies"], s["malicious_dependencies"]),
    )
    scan_id = cur.lastrowid
    for r in report["repos"]:
        con.execute("INSERT INTO repos(scan_id,name,root,risk,secrets,vulns) VALUES(?,?,?,?,?,?)",
                    (scan_id, r["name"], r["root"], r["risk"], len(r["secrets"]), len(r["vulnerabilities"])))
        for sec in r["secrets"]:
            con.execute("INSERT INTO findings(scan_id,repo,kind,severity,detail) VALUES(?,?,?,?,?)",
                        (scan_id, r["name"], "secret", sec["severity"], json.dumps(sec)))
        for v in r["vulnerabilities"]:
            con.execute("INSERT INTO findings(scan_id,repo,kind,severity,detail) VALUES(?,?,?,?,?)",
                        (scan_id, r["name"], "vuln", "critical" if v["malicious"] else "high", json.dumps(v)))
        for c in r.get("code_vulnerabilities", []):
            con.execute("INSERT INTO findings(scan_id,repo,kind,severity,detail) VALUES(?,?,?,?,?)",
                        (scan_id, r["name"], "code", c.get("severity", "medium"), json.dumps(c)))
    con.commit()
    con.close()
    return scan_id, ts


def main():
    root = os.path.abspath(os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "."))
    out_dir = os.path.expanduser(sys.argv[2] if len(sys.argv) > 2 else "~/ironguard")
    os.makedirs(out_dir, exist_ok=True)
    def is_repo(d):
        # A directory counts as a repo if it's a git repo OR contains a dependency
        # manifest anywhere within a few levels (handles nested/monorepo layouts).
        if os.path.isdir(os.path.join(d, ".git")):
            return True
        base = d.rstrip("/").count(os.sep)
        for dp, dirs, files in os.walk(d):
            if dp.count(os.sep) - base > 4:
                dirs[:] = []
                continue
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            if any(f in MANIFESTS for f in files):
                return True
        return False

    children = [os.path.join(root, d) for d in sorted(os.listdir(root))
                if os.path.isdir(os.path.join(root, d)) and d not in SKIP_DIRS]
    child_repos = [c for c in children if is_repo(c)]
    if child_repos:
        targets = child_repos            # workspace root is a container of repos
    elif is_repo(root):
        targets = [root]                 # root is itself a single repo
    else:
        targets = children or [root]     # loose fallback
    repos = []
    for repo in targets:
        r = audit_repo(repo)
        if r["secrets"] or r["vulnerabilities"] or r["dependencies_checked"]:
            repos.append({"name": os.path.basename(repo) or repo, "root": repo, **r})
    report = {"root": root, "repos": repos,
              "summary": {"repositories": len(repos),
                          "secrets": sum(len(r["secrets"]) for r in repos),
                          "vulnerable_dependencies": sum(len(r["vulnerabilities"]) for r in repos),
                          "malicious_dependencies": sum(sum(1 for v in r["vulnerabilities"] if v["malicious"]) for r in repos),
                          "code_vulnerabilities": sum(len(r.get("code_vulnerabilities", [])) for r in repos)}}
    scan_id, ts = write_sqlite(report, os.path.join(out_dir, "ironguard.db"))
    report["generated_at"] = ts
    report["scan_id"] = scan_id
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(out_dir, "report.js"), "w") as f:
        f.write("window.REPORT = " + json.dumps(report) + ";\n")
    s = report["summary"]
    print(f"IronGuard audit #{scan_id} @ {ts}: {s['repositories']} repos, {s['secrets']} secrets, "
          f"{s['vulnerable_dependencies']} vulnerable deps ({s['malicious_dependencies']} malicious).")
    print(f"DB: {os.path.join(out_dir, 'ironguard.db')}  |  Dashboard server: http://127.0.0.1:8787")


if __name__ == "__main__":
    main()
