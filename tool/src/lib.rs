//! IronGuard — read-only repository security auditor tool for IronClaw.
//!
//! The `scan` capability performs two deterministic checks on content handed to
//! it by the skill (the skill walks the workspace read-only and passes file
//! contents; the tool itself does NO filesystem traversal):
//!
//!   1. Secret detection — curated high-signal regex patterns plus a Shannon
//!      entropy gate for generic `key = value` assignments. Matches are masked
//!      before they leave the sandbox.
//!   2. Dependency audit — parses `package.json` / `requirements.txt` /
//!      `Cargo.toml` into (ecosystem, name, version) tuples and queries the
//!      public OSV.dev vulnerability + malware database (`/v1/querybatch`).
//!
//! It returns a structured per-repository findings object with a risk score.

wit_bindgen::generate!({
    world: "sandboxed-tool",
    path: "../../wit/tool.wit",
});

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

struct WorkspaceSentinelTool;

#[derive(Debug, Deserialize)]
struct ScanParams {
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    files: Vec<FileInput>,
    #[serde(default)]
    manifests: Vec<ManifestInput>,
}

#[derive(Debug, Deserialize)]
struct FileInput {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ManifestInput {
    path: String,
    /// `package.json` | `requirements.txt` | `cargo.toml`. Inferred from `path` when absent.
    #[serde(default)]
    kind: Option<String>,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Dependency {
    ecosystem: String,
    name: String,
    version: String,
}

impl exports::near::agent::tool::Guest for WorkspaceSentinelTool {
    fn execute(req: exports::near::agent::tool::Request) -> exports::near::agent::tool::Response {
        match run(&req.params) {
            Ok(output) => exports::near::agent::tool::Response {
                output: Some(output),
                error: None,
            },
            Err(e) => exports::near::agent::tool::Response {
                output: None,
                error: Some(e),
            },
        }
    }

    fn schema() -> String {
        SCHEMA.to_string()
    }

    fn description() -> String {
        DESCRIPTION.to_string()
    }
}

export!(WorkspaceSentinelTool);

fn run(params_json: &str) -> Result<String, String> {
    let params: ScanParams =
        serde_json::from_str(params_json).map_err(|e| format!("invalid params: {e}"))?;

    near::agent::host::log(
        near::agent::host::LogLevel::Info,
        &format!(
            "ironguard scan: {} file(s), {} manifest(s)",
            params.files.len(),
            params.manifests.len()
        ),
    );

    // 1. Secret scan over provided file contents.
    let mut secrets: Vec<Value> = Vec::new();
    for file in &params.files {
        scan_file_secrets(&file.path, &file.content, &mut secrets);
    }

    // 2. Parse dependency manifests.
    let mut deps: Vec<Dependency> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for m in &params.manifests {
        let kind = m.kind.clone().unwrap_or_else(|| infer_kind(&m.path));
        match kind.as_str() {
            "package.json" => parse_package_json(&m.content, &mut deps, &mut notes),
            "requirements.txt" => parse_requirements_txt(&m.content, &mut deps),
            "cargo.toml" => parse_cargo_toml(&m.content, &mut deps),
            other => notes.push(format!("skipped {} (unsupported manifest kind '{}')", m.path, other)),
        }
    }
    dedup(&mut deps);

    // 3. Query OSV.dev for vulnerabilities + malware.
    let mut vulnerabilities: Vec<Value> = Vec::new();
    if !deps.is_empty() {
        match query_osv(&deps) {
            Ok(v) => vulnerabilities = v,
            Err(e) => notes.push(format!("OSV query failed: {e}")),
        }
    }

    // 4. Risk score.
    let any_malicious = vulnerabilities
        .iter()
        .any(|v| v.get("malicious").and_then(|m| m.as_bool()).unwrap_or(false));
    let max_secret = secrets
        .iter()
        .filter_map(|s| s.get("severity").and_then(|x| x.as_str()))
        .map(severity_rank)
        .max()
        .unwrap_or(0);
    let any_vuln = !vulnerabilities.is_empty();
    let risk = if any_malicious || max_secret == 3 {
        "critical"
    } else if any_vuln || max_secret == 2 {
        "high"
    } else if max_secret == 1 {
        "medium"
    } else {
        "low"
    };

    let malicious_count = vulnerabilities
        .iter()
        .filter(|v| v.get("malicious").and_then(|m| m.as_bool()).unwrap_or(false))
        .count();

    let out = json!({
        "ok": true,
        "repo": params.repo.clone().unwrap_or_else(|| "workspace".to_string()),
        "summary": {
            "files_scanned": params.files.len(),
            "secrets_found": secrets.len(),
            "dependencies_checked": deps.len(),
            "vulnerable_dependencies": vulnerabilities.len(),
            "malicious_dependencies": malicious_count,
        },
        "risk": risk,
        "secrets": secrets,
        "vulnerabilities": vulnerabilities,
        "notes": notes,
    });
    Ok(out.to_string())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

// ----------------------------------------------------------------------------
// Secret detection
// ----------------------------------------------------------------------------

fn scan_file_secrets(path: &str, content: &str, out: &mut Vec<Value>) {
    let patterns = secret_patterns();
    let generic = regex::Regex::new(
        r#"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9/+_=.\-]{16,})['"]?"#,
    )
    .ok();

    for (idx, line) in content.lines().enumerate() {
        let lineno = idx + 1;
        for (kind, severity, re) in &patterns {
            if let Some(m) = re.find(line) {
                out.push(secret_finding(path, lineno, kind, severity, m.as_str()));
            }
        }
        if let Some(g) = &generic {
            if let Some(caps) = g.captures(line) {
                if let Some(val) = caps.get(2) {
                    if shannon_entropy(val.as_str()) >= 3.0 {
                        out.push(secret_finding(
                            path,
                            lineno,
                            "Generic Secret Assignment",
                            "medium",
                            val.as_str(),
                        ));
                    }
                }
            }
        }
    }
}

fn secret_patterns() -> Vec<(&'static str, &'static str, regex::Regex)> {
    const RAW: &[(&str, &str, &str)] = &[
        ("AWS Access Key ID", "critical", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", "high", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("OpenAI API Key", "high", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        ("Slack Token", "high", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("Google API Key", "high", r"AIza[0-9A-Za-z_\-]{35}"),
        ("Stripe Secret Key", "critical", r"[sr]k_live_[0-9a-zA-Z]{20,}"),
        ("NPM Token", "high", r"npm_[A-Za-z0-9]{36}"),
        (
            "JWT",
            "medium",
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        ),
        ("Private Key Block", "critical", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ];
    RAW.iter()
        .filter_map(|(k, s, p)| regex::Regex::new(p).ok().map(|re| (*k, *s, re)))
        .collect()
}

fn secret_finding(path: &str, line: usize, kind: &str, severity: &str, matched: &str) -> Value {
    json!({
        "path": path,
        "line": line,
        "kind": kind,
        "severity": severity,
        "preview": mask(matched),
    })
}

fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 10 {
        return format!("{} ({} chars)", "•".repeat(n.min(8)), n);
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{}…{} ({} chars)", head, tail, n)
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ----------------------------------------------------------------------------
// Dependency manifest parsing
// ----------------------------------------------------------------------------

fn infer_kind(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with("package.json") {
        "package.json".to_string()
    } else if lower.ends_with("requirements.txt") {
        "requirements.txt".to_string()
    } else if lower.ends_with("cargo.toml") {
        "cargo.toml".to_string()
    } else {
        "unknown".to_string()
    }
}

fn clean_version(spec: &str) -> Option<String> {
    let s = spec.trim().trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']);
    let token: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '+')
        .collect();
    if token.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        Some(token)
    } else {
        None
    }
}

fn parse_package_json(content: &str, deps: &mut Vec<Dependency>, notes: &mut Vec<String>) {
    let v: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            notes.push(format!("package.json parse error: {e}"));
            return;
        }
    };
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = v.get(key).and_then(|x| x.as_object()) {
            for (name, ver) in obj {
                if let Some(spec) = ver.as_str() {
                    if let Some(version) = clean_version(spec) {
                        deps.push(Dependency {
                            ecosystem: "npm".to_string(),
                            name: name.clone(),
                            version,
                        });
                    }
                }
            }
        }
    }
}

fn parse_requirements_txt(content: &str, deps: &mut Vec<Dependency>) {
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(idx) = line.find("==") {
            let name = line[..idx].split('[').next().unwrap_or("").trim();
            let version: String = line[idx + 2..]
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '+' || *c == '!')
                .collect();
            if !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    ecosystem: "PyPI".to_string(),
                    name: name.to_string(),
                    version,
                });
            }
        }
    }
}

fn parse_cargo_toml(content: &str, deps: &mut Vec<Dependency>) {
    let mut in_deps = false;
    for raw in content.lines() {
        let t = raw.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]" || t == "[dev-dependencies]" || t == "[build-dependencies]";
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(eq) = t.find('=') {
            let name = t[..eq].trim().trim_matches('"').trim();
            let rhs = t[eq + 1..].trim();
            let version: Option<String> = if rhs.starts_with('{') {
                rhs.find("version").and_then(|vi| {
                    let after = &rhs[vi..];
                    after.find('"').and_then(|q1| {
                        after[q1 + 1..].find('"').map(|q2| after[q1 + 1..q1 + 1 + q2].to_string())
                    })
                })
            } else if rhs.starts_with('"') {
                Some(rhs.trim_matches('"').to_string())
            } else {
                None
            };
            if let Some(ver) = version {
                if let Some(cv) = clean_version(&ver) {
                    if !name.is_empty() {
                        deps.push(Dependency {
                            ecosystem: "crates.io".to_string(),
                            name: name.to_string(),
                            version: cv,
                        });
                    }
                }
            }
        }
    }
}

fn dedup(deps: &mut Vec<Dependency>) {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    deps.retain(|d| seen.insert((d.ecosystem.clone(), d.name.clone(), d.version.clone())));
}

// ----------------------------------------------------------------------------
// OSV.dev query
// ----------------------------------------------------------------------------

fn query_osv(deps: &[Dependency]) -> Result<Vec<Value>, String> {
    let mut findings: Vec<Value> = Vec::new();
    for chunk in deps.chunks(200) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|d| {
                json!({
                    "package": {"name": d.name, "ecosystem": d.ecosystem},
                    "version": d.version,
                })
            })
            .collect();
        let body_bytes = json!({ "queries": queries }).to_string().into_bytes();
        let headers = json!({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "IronClaw-WorkspaceSentinel/0.1"
        })
        .to_string();

        let resp = near::agent::host::http_request(
            "POST",
            OSV_QUERYBATCH_URL,
            &headers,
            Some(body_bytes.as_slice()),
            Some(25000),
        )
        .map_err(|e| format!("http_request: {e}"))?;

        if resp.status < 200 || resp.status >= 300 {
            return Err(format!("OSV HTTP {}", resp.status));
        }

        let parsed: Value =
            serde_json::from_slice(&resp.body).map_err(|e| format!("OSV response parse: {e}"))?;
        let results = parsed
            .get("results")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();

        for (i, res) in results.iter().enumerate() {
            let Some(dep) = chunk.get(i) else { continue };
            let vulns = res.get("vulns").and_then(|v| v.as_array());
            let ids: Vec<String> = vulns
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.get("id").and_then(|id| id.as_str()).map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if ids.is_empty() {
                continue;
            }
            let malicious = ids.iter().any(|id| id.starts_with("MAL"));
            findings.push(json!({
                "ecosystem": dep.ecosystem,
                "name": dep.name,
                "version": dep.version,
                "advisory_ids": ids,
                "advisory_count": vulns.map(|a| a.len()).unwrap_or(0),
                "malicious": malicious,
            }));
        }
    }
    Ok(findings)
}

// ----------------------------------------------------------------------------
// Static metadata
// ----------------------------------------------------------------------------

const DESCRIPTION: &str = "Read-only workspace security auditor. Given file contents and dependency \
manifests, it detects exposed secrets (API keys, tokens, private keys) and audits dependencies \
against the OSV.dev vulnerability and malware database. Returns structured per-repo findings with a \
risk score. The caller (skill) provides file/manifest contents; this tool performs no filesystem access.";

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "repo": {"type": "string", "description": "Repository name or path, used to label the report."},
    "files": {
      "type": "array",
      "description": "Files to scan for exposed secrets (e.g. .env, config files).",
      "items": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"]
      }
    },
    "manifests": {
      "type": "array",
      "description": "Dependency manifests to audit against OSV.dev.",
      "items": {
        "type": "object",
        "properties": {
          "path": {"type": "string"},
          "kind": {"type": "string", "enum": ["package.json", "requirements.txt", "cargo.toml"]},
          "content": {"type": "string"}
        },
        "required": ["path", "content"]
      }
    }
  }
}"#;
