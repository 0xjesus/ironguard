# Hackathon submission — ready-to-use values

Submit by telling your IronClaw agent: **"Submit my final entry."** The `ironclaw-hackathon`
skill collects these fields and uploads via the `nova-submit` tool to group `ironclaw-hackathon-260618`.

## Fields

| Field | Value |
|---|---|
| **nova_account_id** | `0xjdev.near`  *(must match registration)* |
| **nova_api_key** | *(your secret — give it to the agent at submit time; never commit/paste in chat; rotate after)* |
| **title** | `IronGuard` |
| **workflow_description** | see below (≤280 chars) |
| **demo_url** | ⏳ *your public YouTube link — REQUIRED, record first (see docs/DEMO.md)* |
| **github_repo** | `https://github.com/0xjesus/ironguard` |
| **skills_list** | `ironguard (skill), ironguard.scan (WASM tool)` |
| **demo_notes** | see below |

### workflow_description (≈240 chars — under the 280 limit)
> An always-on IronClaw agent that audits every repo for leaked secrets, malicious/vulnerable dependencies (OSV), and code vulnerabilities found by an LLM on NEAR's confidential TEE — on a live local dashboard. Your code never leaves your machine.

### demo_notes
> Three layers in one dashboard: local masked secret scan, OSV dependency+malware check (catches real attacks, e.g. MAL-2025-20690), and LLM code analysis on NEAR's TEE (caught command + SQL injection in the demo). Privacy is verifiable: secret detection is local Python (works offline), only package name+version leaves the box, AI runs in NEAR's attested TEE. Building it surfaced + fixed an IronClaw core bug (keyless-network WASM tools couldn't execute) — PR included in the repo.

## Preconditions (must all be true before submitting)
1. ✅ `nova-submit` tool + `ironclaw-hackathon` skill installed.
2. ⏳ **Registration recorded** (`hackathon/registrations/0xjdev.md`) — re-run "Register me for the hackathon" once if unsure.
3. ⏳ **Staff added `0xjdev.near`** to the submission group (you sent the block to @NEARLegionBarcelona — confirm with staff).
4. ⏳ **Demo video uploaded** (public YouTube) → fill `demo_url`.
5. On success the tool returns a **CID**. **Then rotate your NOVA API key.**
