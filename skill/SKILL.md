---
name: "ironguard"
version: "0.2.0"
description: "Read-only security auditor for a developer workspace. Recursively scans every repository for exposed secrets, malicious/vulnerable dependencies (OSV.dev), and code vulnerabilities (LLM analysis), then renders a live local dashboard. Persists history to SQLite."
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
    - "(audit|scan|check).*(workspace|repos|repositories|projects|dependencies|secrets|code)"
    - "check.*(for )?(leaked|exposed) (secrets|keys|credentials)"
    - "are my dependencies (safe|vulnerable|compromised)"
    - "(any|find).*vulnerabilit"
  max_context_tokens: 2500
---

# ironguard

Read-only security auditor for a developer workspace. For every repository under a target
directory it reports three classes of risk: **exposed secrets** (masked), **malicious/vulnerable
dependencies** (checked against live OSV.dev), and **code vulnerabilities** (LLM analysis of the
source — injection, SSRF, auth bypass, unsafe eval, …). Results persist to SQLite and render on a
live dashboard at `http://127.0.0.1:8787`.

## CRITICAL CONSTRAINTS — READ FIRST
- **Read-only.** Never write to, edit, or delete anything inside the scanned repositories.
- **Do NOT re-implement the scan** by reading files one by one — that is slow and unreliable.
  Invoke the bundled auditor **once** via the `shell` tool; it performs the entire audit
  (secrets + OSV dependencies + LLM code analysis) and writes the dashboard + SQLite history.
- **Never print a raw secret value.** The auditor masks secrets (e.g. `AKIA…MPLE (20 chars)`);
  report only those masked previews.

## Method: audit_workspace

**Parameter:** `path` — absolute path to the workspace to audit. If the user doesn't give one,
ask, or default to the current working directory.

**Steps:**
1. Run **exactly one** `shell` command (the auditor does everything):
   ```
   python3 "$HOME/ironguard/audit.py" "<path>"
   ```
   - For a large tree where you only want the fast, free pass (secrets + OSV, no LLM), prefix
     with `IRONGUARD_AI=0`.
   - If `$HOME/ironguard/audit.py` does not exist, tell the user to deploy it first by running
     `ironguard/skill/run.sh <path>` from the IronGuard repo, then retry.
2. Read `$HOME/ironguard/report.json` (the structured result).
3. Give the user a prioritized summary: highest-risk repository first, then per repo the
   `risk` and counts, then the concrete findings — masked secrets, vulnerable/malicious
   dependencies (with advisory ids; call out anything `malicious: true`), and AI-detected code
   vulnerabilities (with `file:line`, the issue, and the recommended fix).
4. Tell the user the **live dashboard** is at `http://127.0.0.1:8787` (auto-refreshes; SQLite
   keeps the full scan history).

## Related tool
The `ironguard.scan` WASM tool performs the sandboxed OSV dependency + malware check. You may
call it directly with a single repo's manifest contents (e.g. a `package.json`) to audit
dependencies in isolation — useful to demonstrate the tool on its own.

## What this skill does NOT do
- It does not modify, fix, or delete anything in the repositories — it only reports.
- It does not upload your code; OSV receives only package name + version, and the LLM code
  analysis runs on NEAR AI's confidential (TEE-attested) endpoint.
- It does not print raw secret values — only masked previews from the report.
