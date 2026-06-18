# 🛡️ IronGuard

**An always-on, privacy-first security auditor for your dev workspace — built as an IronClaw agent.**

IronGuard continuously watches every repository in your workspace and surfaces three classes of risk on a single live dashboard:

1. **🔑 Exposed secrets** — API keys, tokens, private keys (detected locally, **masked**, never sent anywhere).
2. **📦 Compromised dependencies** — vulnerable *and* malicious packages, checked against the live [OSV.dev](https://osv.dev) database (the same source that tracks real npm supply-chain attacks).
3. **🧠 Code vulnerabilities** — injection, SSRF, auth bypass, unsafe `eval`, insecure crypto… found by an **LLM reasoning about your actual source code** (running on NEAR AI's confidential TEE), not regex.

> Regex finds secrets. OSV finds *known*-bad dependencies. The **LLM finds the bugs in your own code that nothing else can** — and it does it privately.

---

## Why

The most damaging incidents of the last few years are **supply-chain**: malware shipped inside npm/PyPI packages that your tools (and increasingly your AI agents) install automatically. Meanwhile real vulnerabilities sit in your own code, and secrets leak into `.env` files. Existing scanners are either deterministic (miss novel attacks and logic bugs) or cloud SaaS (you ship them your code).

IronGuard combines **deterministic facts** with **LLM judgment**, and keeps your code private via confidential compute.

---

## What it looks like

A live dashboard at `http://127.0.0.1:8787`, auto-refreshing, with scan history and per-repo drill-down:

```
IronGuard            LIVE · auto-refresh 15s
 2 repos | 2 secrets | 3 vulnerable deps | 1 malicious | 2 code vulns (AI)

▼ payments-api  [2 secrets · 3 vuln · 1 malware · 2 code]  CRITICAL
   Exposed secrets:   AWS Access Key (.env:1)   GitHub Token (.env:2)   [masked]
   Vulnerable deps:   lodash 4.17.11 (7 advisories)   flatmap-stream 0.1.1  ⚠ MALWARE MAL-2025-20690
   AI code vulns:     critical  command-injection  server.js:7  "/ping concatenates req.query.host into a shell exec"
                      critical  sql-injection      server.js:12 "/user concatenates req.query.id into a SQL string"
▶ blog          [0 secrets · 0 vuln · 0 code]  LOW
```

Every finding above is **real**, verified against live OSV data and a live LLM analysis — no mock data.

---

## Architecture

```
                    ┌──────────────────────── IronClaw agent ────────────────────────┐
   cron / trigger → │  skill: ironguard                                                │
                    │    ├─ deterministic engine (local, no cloud)                     │
                    │    │     • secret scan (regex + entropy, masked on the spot)      │
                    │    │     • parse package.json / requirements.txt / Cargo.toml     │
                    │    │     • ironguard.scan  (WASM tool) → OSV.dev querybatch        │
                    │    └─ AI brain → NEAR AI (confidential TEE) deep code analysis     │
                    └───────────────────────────────┬─────────────────────────────────┘
                                                     ▼
                          SQLite (history)  →  serve.py  →  live dashboard (127.0.0.1)
```

- **Deterministic layer** = the facts. Runs entirely on your machine. The only thing it ever sends out is *package name + version* to OSV.dev.
- **AI layer** = the judgment. Source code is analyzed by NEAR AI inside a **TEE with remote attestation** — not even NEAR or the cloud provider can read it.
- **`ironguard.scan`** is a real sandboxed **WASM tool** (Rust → `wasm32-wasip2`) that the IronClaw agent invokes; it queries OSV from inside the sandbox.

---

## Privacy — and how to *verify* it (don't trust, check)

Your secrets and code never leave your machine in the clear. You can prove it:

| Claim | How to verify yourself |
|---|---|
| Secret detection is 100% local | `grep urllib skill/audit.py` → the only outbound call is OSV. Run it offline → it **still finds your secrets**. |
| Only package metadata leaves the box | The OSV request body is `{"queries":[{"package":{"name":...},"version":...}]}` — no code, no secrets. |
| Raw secrets are never stored | Inspect `~/ironguard/ironguard.db` → only masked previews (`AKIA…MPLE (20 chars)`). |
| The dashboard isn't exposed | `serve.py` binds `127.0.0.1` (loopback only). |
| Even the AI part is private | NEAR AI runs inference in a TEE and returns a cryptographic **attestation**. See [NEAR AI — Private Inference](https://docs.near.ai/cloud/private-inference/). |

---

## Quickstart

> Requires only **Python 3**. A NEAR AI key in `~/.nearai-env` (`export NEARAI_API_KEY="..."`) enables the optional LLM code scan; without it the secret + OSV dependency audit still runs.

### Install — one command
```bash
git clone https://github.com/0xjesus/ironguard && bash ironguard/install.sh ~/code
# → IronGuard is live ▶ http://127.0.0.1:8787   (watching ~/code every 5 min)
```
That single command installs the auditor, **registers the `ironguard` IronClaw skill into any IronClaw home it finds**, runs an initial scan, starts the dashboard, and installs a 5-minute cron. **No binary patch, no special profile, no manual config** — the auditor is plain Python that calls OSV.dev (and optionally NEAR AI) directly, so it runs on a **vanilla IronClaw** (or standalone). Set `IRONGUARD_AI=1` to include the LLM code scan on the initial run.

Then drive it from the IronClaw chat — *"audit ~/code with ironguard"* — or just open the dashboard.

### Standalone (no IronClaw at all)
```bash
python3 ironguard/skill/audit.py ~/code     # secrets + OSV deps + (optional) AI code scan → SQLite
python3 ironguard/skill/serve.py             # dashboard at :8787
```

### Advanced — the sandboxed WASM tool (upstream contribution)
`ironguard.scan` runs the OSV audit **inside IronClaw's WASM sandbox**. It depends on the core
**egress fix** in [`patches/`](patches/) being merged (see below) — so it's offered as an upstream
contribution, **not required** for the one-command install above. Build (Rust ≥ 1.92 + `cargo-component`,
patch applied): `bash tool/install.sh` inside an IronClaw checkout.

---

## The IronClaw patch (`patches/ironclaw-wasm-egress-fix.patch`)

Building IronGuard surfaced a real bug in IronClaw Reborn: a **custom WASM tool that declares the `network` effect but carries no per-credential audience** was given an empty network allowlist, which the host's obligation validator then **rejected** — so the tool could be installed and invoked but never *executed* (`obligation handling failed: Network`).

The fix (one function in `runtime/local_dev/extension_surface.rs`): grant such a tool a broad local-dev allowlist (private/metadata IPs still blocked). Apply with:
```bash
cd ironclaw && git apply ../ironguard/patches/ironclaw-wasm-egress-fix.patch
```
We're submitting this upstream — see [`docs/PR.md`](docs/PR.md).

---

## Repo layout
```
tool/      the ironguard.scan WASM tool (Rust) + manifest/schemas/prompt + installer
skill/     the IronClaw skill, the deterministic auditor (audit.py), the AI analyzer
           (ai_analyze.py), the dashboard server (serve.py) + dashboard.html, run.sh
patches/   the one-function IronClaw fix that makes custom WASM tools execute
docs/      upstream PR draft, demo script, submission notes
```

## Built for
The **NEAR Legion IronClaw Hackathon** (Barcelona, June 2026). Skills + WASM tools for the IronClaw ecosystem.

## License
MIT
