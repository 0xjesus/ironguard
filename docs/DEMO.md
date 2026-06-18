# IronGuard — 5-minute demo script

Goal: show all three layers + the privacy proof, ending on the live dashboard. Record full screen (terminal + browser) with OBS / GNOME recorder (`Ctrl+Alt+Shift+R`) → upload unlisted/public to YouTube.

---

### 0:00 — Hook (15s)
> "The worst breaches today are supply-chain — malware your tools install for you — plus secrets in `.env` and bugs in your own code. IronGuard is an always-on IronClaw agent that catches all three, and your code never leaves your machine. Let me show you."

### 0:15 — The workspace (20s)
Show a folder with a couple of repos. Point out: a `.env` with keys, a `package.json`, a `server.js`.
> "A normal dev workspace. Secrets in env files, npm dependencies, real code."

### 0:35 — One command (25s)
```bash
bash skill/run.sh ~/code
```
> "One command deploys the auditor: it scans now, starts the dashboard, and installs a cron so it keeps watching."

### 1:00 — The dashboard (90s) — the core
Open `http://127.0.0.1:8787`. Walk the CRITICAL repo:
- **Secrets** → "Found an AWS key and a GitHub token — but notice they're *masked*. The raw values never left the machine."
- **Dependencies** → "lodash has 7 known advisories. And **flatmap-stream is flagged MALWARE — `MAL-2025-20690`** — a real npm supply-chain attack, straight from OSV."
- **AI code vulns** → "And here's where the LLM earns its keep: it *read the code* and found a **command injection** and a **SQL injection** in `server.js` — with the exploit reasoning and the fix. No database knows these; they're bugs in *your* code."

### 2:30 — Why it's private (60s) — the differentiator
> "A security tool that reads your code and secrets had better not leak them. Two layers:"
- `grep urllib skill/audit.py` → "Secret scanning is local Python. The only thing that leaves is a package name+version to OSV."
- Unplug network / show offline run still finds secrets → "Detection is 100% local — a hallucination can't survive an unplugged cable."
- > "And the AI analysis runs on **NEAR AI's confidential TEE** with remote attestation — not even NEAR can read your code. That's *why* we use NEAR cloud: cloud-grade model, hardware-guaranteed privacy."

### 3:30 — It's a real IronClaw agent (45s)
> "This isn't a script — it's an IronClaw skill + a sandboxed WASM tool (`ironguard.scan`) the agent calls. Building it surfaced a real bug in IronClaw core, which we fixed and are upstreaming — so every future keyless-network WASM tool works."

### 4:15 — Always-on + close (45s)
Show the scan-history bars + cron.
> "It runs on a schedule, keeps history in SQLite, and only pings you about what's *new*. IronGuard: deterministic facts, LLM judgment, full privacy — an agent that guards your workspace so you don't have to."

---
**Checklist:** ✅ secrets masked ✅ OSV malware catch ✅ AI injection catch ✅ privacy proof ✅ IronClaw WASM tool + skill ✅ live dashboard
