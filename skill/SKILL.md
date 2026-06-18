---
name: "ironguard"
version: "0.1.0"
description: "Read-only security auditor for a developer workspace. Recursively scans every repository for exposed secrets and audits dependencies against the live OSV.dev vulnerability/malware database, then renders a local per-repo dashboard."
tags: ["security", "audit", "secrets", "dependencies", "supply-chain", "osv"]
activation:
  keywords:
    - audit
    - scan
    - secrets
    - vulnerabilities
    - dependencies
    - supply chain
    - workspace
    - sentinel
  patterns:
    - "(audit|scan).*(workspace|repos|repositories|projects|dependencies|secrets)"
    - "check.*(for )?(leaked|exposed) (secrets|keys|credentials)"
    - "are my dependencies (safe|vulnerable|compromised)"
  max_context_tokens: 3000
---

# ironguard

Read-only security auditor for a local developer workspace. It NEVER writes to or
modifies the scanned repositories. For each repository under a target directory it:

1. Finds exposed **secrets** (API keys, tokens, private keys) in tracked files.
2. Audits **dependencies** against the live **OSV.dev** vulnerability + malware database
   via the `ironguard.scan` tool.
3. Writes a small **local dashboard** the user can open in a browser.

This skill pairs with the `ironguard.scan` WASM tool, which must be installed
and activated. The tool does the OSV lookup; this skill does the read-only filesystem
traversal and secret grep, then merges both into one report.

## CRITICAL CONSTRAINTS — READ FIRST

- **Read-only.** Use only read/list/grep operations on the workspace. Never write,
  edit, move, or delete anything inside the scanned repositories. The only files you
  may write are the report + dashboard under the output directory (`~/ironguard/`).
- **Never pass file contents that contain secrets as tool arguments** — the host rejects
  secret-like tokens in capability arguments. Secret detection is done here via `grep`;
  only dependency manifests (which contain no secrets) are passed to `ironguard.scan`.
- **Never echo a real secret value back to the user.** Report only masked previews
  (first/last few characters). Grep with the masking step below already does this.
- Do the heavy lifting with a single `shell` command where possible (deterministic,
  few model steps), not many separate file reads.

## Method: audit_workspace

**Parameters (ask only if unclear):**

| Parameter | Required | Notes |
|---|---|---|
| `path` | yes | Absolute path to the workspace root to scan (e.g. `~/code`). Default to the current working directory if the user does not specify one. |

**Step 1 — Enumerate + grep secrets (one `shell` call, read-only).**

Run this shell command (substituting `$ROOT` with the resolved `path`). It lists each
repository, its dependency manifests, and masked secret hits, as JSON on stdout:

```bash
ROOT="$path"
python3 - "$ROOT" <<'PY'
import os, sys, json, re
root = os.path.expanduser(sys.argv[1])
PATTERNS = [
  ("AWS Access Key ID","critical", re.compile(r"AKIA[0-9A-Z]{16}")),
  ("GitHub Token","high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
  ("OpenAI API Key","high", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
  ("Slack Token","high", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
  ("Google API Key","high", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
  ("Stripe Secret Key","critical", re.compile(r"[sr]k_live_[0-9a-zA-Z]{20,}")),
  ("Private Key Block","critical", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
]
MANIFESTS = {"package.json":"package.json","requirements.txt":"requirements.txt","Cargo.toml":"cargo.toml"}
SKIP = {".git","node_modules","target","dist","build","venv",".venv","__pycache__",".next"}
def mask(s):
  return (s[:4]+"…"+s[-4:]+f" ({len(s)} chars)") if len(s)>10 else "•"*len(s)
repos=[]
# treat each immediate subdirectory of root as a repo (plus root itself if it has manifests)
candidates=[root]+[os.path.join(root,d) for d in sorted(os.listdir(root)) if os.path.isdir(os.path.join(root,d)) and d not in SKIP]
for repo in candidates:
  manifests=[]; secrets=[]
  for dirpath,dirs,files in os.walk(repo):
    dirs[:]=[d for d in dirs if d not in SKIP]
    for f in files:
      fp=os.path.join(dirpath,f); rel=os.path.relpath(fp,repo)
      if f in MANIFESTS:
        try: manifests.append({"path":rel,"kind":MANIFESTS[f],"content":open(fp,encoding="utf-8",errors="ignore").read()[:200000]})
        except Exception: pass
      # scan likely-secret files for secrets
      if f.startswith(".env") or f.endswith((".env",".pem",".key",".cfg",".conf",".yaml",".yml",".json",".toml",".ini",".txt")) or "secret" in f.lower() or "config" in f.lower():
        try:
          for i,line in enumerate(open(fp,encoding="utf-8",errors="ignore"),1):
            for kind,sev,rx in PATTERNS:
              m=rx.search(line)
              if m: secrets.append({"path":rel,"line":i,"kind":kind,"severity":sev,"preview":mask(m.group(0))})
        except Exception: pass
  if manifests or secrets:
    repos.append({"name":os.path.basename(repo) or repo,"root":repo,"manifests":manifests,"secrets":secrets})
print(json.dumps({"root":root,"repos":repos}))
PY
```

**Step 2 — Audit dependencies per repo.** For each repo in the JSON that has `manifests`,
call the `ironguard.scan` tool with `{ "repo": <name>, "manifests": <that repo's manifests> }`.
Do NOT include the `files`/secrets — secrets are already handled in step 1 and must not be
passed as arguments. Collect each repo's returned `vulnerabilities` and `risk`.

**Step 3 — Merge + score.** For each repo combine: `secrets` (from step 1) +
`vulnerabilities` (from step 2). Repo risk = `critical` if any malicious dependency or any
`critical` secret; else `high` if any vulnerability or `high` secret; else `medium` if any
`medium` secret; else `low`.

**Step 4 — Write the dashboard.** Write the merged result as a JS data file so the bundled
dashboard can render it without a server:

- `memory_write` / `write_file` to `~/ironguard/report.js` with exactly:
  `window.REPORT = <the merged JSON>;`
- Ensure `~/ironguard/dashboard.html` exists (the skill ships it alongside this file;
  copy it there if missing).

**Step 5 — Report to the user.** Summarize: number of repos scanned, total secrets found,
total vulnerable + malicious dependencies, and the highest risk repo. Tell them to open
`~/ironguard/dashboard.html` in a browser. Show masked secret previews only.

## What this skill does NOT do

- It does not modify, fix, or delete anything in the repositories — it only reports.
- It does not upload code anywhere; the OSV query sends only package name + version, never your code.
- It does not pass secret values to any tool or echo them to the user — only masked previews.
