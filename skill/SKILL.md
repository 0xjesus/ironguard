---
name: "ironguard"
version: "0.4.0"
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
1. **Read the dependency manifest** with `read_file`. Try these paths in order and use the first
   that exists (one read each): `<path>/package.json`, then `<path>/requirements.txt`, then
   `<path>/Cargo.toml`. If you also want to check for leaked secrets, `read_file` a `<path>/.env`
   too (only if it exists).
2. **Call the `ironguard.scan` tool ONCE** with:
   - `repo`: the repository name
   - `manifests`: `[{ "path": "<the manifest file name>", "kind": "<package.json | requirements.txt | cargo.toml>", "content": "<exactly the file content you just read>" }]`
     — **`kind` must be EXACTLY one of** `package.json`, `requirements.txt`, `cargo.toml`.
   - `files` *(optional)*: `[{ "path": ".env", "content": "<.env content>" }]` to scan for secrets.
3. **Report what `ironguard.scan` returns**: vulnerable dependencies (with advisory ids), any
   package where `malicious` is true (call these out loudly — supply-chain attack), exposed secrets
   (already masked by the tool), and the overall risk score.

**Rules:** Use the `ironguard.scan` tool to do the analysis — do NOT inspect or judge dependencies
yourself. Read only the manifest (and optionally `.env`); never read the whole repository. Never
print a raw secret value (the tool masks them).

## Continuous / whole-workspace audit (optional)
`ironguard.scan` audits one repo's dependencies. For an always-on, recursive, multi-repo audit with
a live dashboard (secrets + OSV + LLM code analysis, persisted to SQLite), the bundled engine runs
on a cron — installed by `install.sh`. To trigger a full workspace scan on demand, run via the
`shell` tool: `python3 __IRONGUARD_HOME__/audit.py <workspace>` — then point the user at the
dashboard at `http://127.0.0.1:8787`. For a single repo's dependencies, prefer the `ironguard.scan`
tool above.
