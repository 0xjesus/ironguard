---
name: "ironguard"
version: "0.5.0"
description: "Audit a repository for security risks using the ironguard.scan tool: vulnerable & malicious dependencies (OSV.dev) and exposed secrets. Use whenever the user asks to audit/scan/check a repo, its dependencies, or its security."
tags: ["security", "audit", "secrets", "dependencies", "supply-chain", "osv", "malware"]
activation:
  keywords:
    - audit
    - scan
    - secrets
    - vulnerabilities
    - dependencies
    - supply chain
    - malware
    - ironguard
  patterns:
    - "(audit|scan|check|review).*(repo|repos|repository|project|dependencies|deps|packages|secrets|security|vulnerab)"
    - "(are|is) my (dependencies|deps|packages|code|repo) (safe|vulnerable|compromised|secure|malicious)"
  max_context_tokens: 2000
---

# ironguard

When the user asks to **audit / scan / check** a repository (or its dependencies, packages, or
security), you perform the audit by calling the **`ironguard.scan`** tool — a sandboxed WASM tool
that checks dependencies against the live OSV.dev database (known vulnerabilities + **malicious**
packages) and scans provided file contents for exposed secrets.

## Method: audit_repo

**Parameter:** `path` — the repository to audit (ask once if not given).

**Steps (do exactly this — it's short):**
1. **Read ONLY the dependency manifest** with `read_file`. Try these paths in order and use the
   first that exists (one read each): `<path>/package.json`, then `<path>/requirements.txt`, then
   `<path>/Cargo.toml`. Do **NOT** read `.env` or any other secret-bearing file — the host rejects
   tool arguments that contain secret-like tokens, which would make the call fail. (Exposed secrets
   are handled separately by the local `audit.py` engine, which masks them — never through tool args.)
2. **Call the `ironguard.scan` tool ONCE** with:
   - `repo`: the repository name
   - `manifests`: `[{ "path": "<the manifest file name>", "kind": "<package.json | requirements.txt | cargo.toml>", "content": "<exactly the manifest content you just read>" }]`
     — **`kind` must be EXACTLY one of** `package.json`, `requirements.txt`, `cargo.toml`.
   - Do **not** pass a `files` array — it would carry secrets into the tool arguments and the host
     will deny the call.
3. **Report what `ironguard.scan` returns**: vulnerable dependencies (with advisory ids), any
   package where `malicious` is true (call these out loudly — supply-chain attack), and the overall
   risk score.
4. **Always end your report with the dashboard pointer.** IronGuard also runs an always-on,
   recursive audit of the whole workspace (secrets + OSV + LLM code analysis) persisted to SQLite,
   served at **http://127.0.0.1:8787**. Tell the user: "The full, continuously-updated report
   (with scan history and masked secrets) is on your live dashboard at http://127.0.0.1:8787."

**Rules:** Use the `ironguard.scan` tool to do the analysis — do NOT inspect or judge dependencies
yourself. Read only the dependency manifest; never read `.env`/secret files or the whole repository.

## Method: watch_workspace (always-on cron monitoring)

When the user asks to **continuously scan / keep monitoring / set up the cron / always-on audit /
"keep an eye on" / "scan every few minutes"** a workspace, set up the background watcher with **one
`shell` command**:

- Default — fast & free (deterministic: secrets + OSV dependency/malware):
  ```
  bash __IRONGUARD_HOME__/watch.sh "<workspace>"
  ```
- If the user wants the **AI code-vulnerability layer too** (injection, SSRF, auth bypass, … via the
  LLM on NEAR's confidential TEE — uses NEAR AI credits), add `ai`:
  ```
  bash __IRONGUARD_HOME__/watch.sh "<workspace>" ai
  ```

This installs a 5-minute cron, (re)starts the dashboard, and runs an initial recursive scan of every
repo (secrets + OSV + optional AI code analysis), persisted to SQLite. After it returns, tell the
user: *"\<workspace\> is now continuously audited every 5 minutes — the live dashboard (with full
scan history and masked secrets) is at **http://127.0.0.1:8787**."*

For a quick one-repo dependency check (no cron), use the `ironguard.scan` tool above instead.
