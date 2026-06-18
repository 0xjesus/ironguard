Use this capability to audit a repository for security problems. Call it once per repository.

Parameters:
- repo: the repository name or path (for labeling).
- files: array of { path, content } for files that may contain secrets — read the repo's `.env`, `.env.*`, and obvious config files read-only and pass their contents here.
- manifests: array of { path, kind, content } for dependency manifests — pass the contents of `package.json`, `requirements.txt`, and/or `Cargo.toml`. `kind` is inferred from the path if omitted.

The tool detects exposed secrets (API keys, tokens, private keys; matches are masked) and audits every dependency against the live OSV.dev vulnerability and malware database. It returns JSON: `summary`, an overall `risk` (low/medium/high/critical), a `secrets` list (path, line, kind, severity, masked preview), and a `vulnerabilities` list (ecosystem, name, version, advisory_ids, advisory_count, malicious). `malicious: true` means OSV flagged that exact package version as malware.

This tool is read-only and never modifies the repository. Do not paste real secret values back to the user — report only the masked previews the tool returns.
