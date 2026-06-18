---
name: "ironguard"
version: "0.3.0"
description: "Read-only workspace security auditor. Operated by running ONE bundled command that scans every repo for exposed secrets, malicious/vulnerable dependencies (OSV.dev), and code vulnerabilities (LLM), then updates a live dashboard. Persists history to SQLite."
tags: ["security", "audit", "secrets", "dependencies", "supply-chain", "osv", "sast"]
activation:
  keywords:
    - audit
    - scan
    - secrets
    - vulnerabilities
    - dependencies
    - supply chain
    - workspace
    - ironguard
  patterns:
    - "(audit|scan|check).*(workspace|repo|repos|repositories|project|projects|dependencies|secrets|code)"
    - "check.*(for )?(leaked|exposed) (secrets|keys|credentials)"
    - "(are|is) my (dependencies|code|workspace) (safe|vulnerable|compromised|secure)"
  max_context_tokens: 2000
---

# ironguard

Read-only security auditor for a developer workspace. You operate it by running **one bundled
command** — you do **not** inspect the workspace yourself.

## HARD RULES — follow exactly, do not deviate
1. To perform an audit, your **ONLY** action is a **single `shell` tool call** (Step 1 below).
   Do **NOT** call `list_dir`, `glob`, `read_file`, `grep`, or any other tool first. Do **NOT**
   explore or read the workspace. The bundled auditor does all of that internally.
2. Read-only: never modify the scanned repositories.
3. Never print a raw secret value — the auditor masks them; report only the masked previews.

## Method: audit_workspace

**Parameter:** `path` — absolute path to audit. If the user didn't give one, ask once; never guess.

**Step 1 — make EXACTLY ONE `shell` call** (substitute `<PATH>`):
```
python3 "$HOME/ironguard/audit.py" "<PATH>"
```
This one command scans every repo for secrets, audits dependencies against OSV.dev, runs the LLM
code analysis, writes SQLite history, and updates the dashboard. For a very large tree, prefix
`IRONGUARD_AI=0` to skip the slower LLM pass. If it errors that `audit.py` is missing, tell the
user to run `ironguard/skill/run.sh <PATH>` once, then retry.

**Step 2 — read the result once:** `read_file` on `$HOME/ironguard/report.json`.

**Step 3 — report:** worst-risk repo first, then per repo the `risk` and the concrete findings —
masked secrets, vulnerable/malicious dependencies (call out `malicious: true`), and AI code
vulnerabilities (`file:line` + recommended fix). End with: live dashboard at
`http://127.0.0.1:8787`.

That is the entire procedure: **one shell call, one file read, one summary. Nothing else.**

## Does NOT
- Modify or upload your code — OSV receives only package name + version; the LLM code analysis
  runs on NEAR AI's confidential (TEE-attested) endpoint.
- Print raw secret values — only masked previews from the report.
