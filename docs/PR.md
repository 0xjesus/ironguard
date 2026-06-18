# Upstream PR / issue draft — `nearai/ironclaw`

**Title:** local-dev: custom WASM tool with `network` effect but no credential audience can't execute (empty allowlist rejected)

## Summary
A custom (local-dev) WASM tool that declares the `network` effect but has **no per-credential audience** (e.g. a tool calling a public, keyless API like OSV.dev) is given an **empty** network allowlist. The host's network-obligation validator then rejects it, so the tool installs and the agent can invoke it, but execution always fails with:

```
capability <id> obligation handling failed: Network
```

## Root cause
`crates/ironclaw_reborn_composition/src/runtime/local_dev/extension_surface.rs::extension_network_policy` builds `allowed_targets` only from `capability.runtime_credentials[].audience` (plus the web-search special case). For a no-credential network tool, `targets` stays empty, producing `NetworkPolicy { allowed_targets: [], deny_private_ip_ranges: true, .. }`.

That policy is "constrained" (`deny_private_ip_ranges == true`), so `obligations_for_grant` emits an `ApplyNetworkPolicy` obligation — but `ironclaw_host_runtime::obligations::validate_network_policy_metadata` rejects any policy whose `allowed_targets.is_empty()`. Result: a valid keyless-network tool can never run.

## Fix
When a capability declares `EffectKind::Network` but resolved to no targets, grant a broad local-dev allowlist (`host_pattern: "*"`), keeping `deny_private_ip_ranges: true` so private/metadata/loopback ranges stay blocked. Extensions that carry credential audiences (gmail, exa, …) already populate `targets` and are unaffected.

See `patches/ironclaw-wasm-egress-fix.patch` (one function, ~16 lines).

## Testing
- Built a custom WASM tool (`ironguard.scan`) that POSTs to `api.osv.dev/v1/querybatch`.
- Before: `obligation handling failed: Network` on every invocation.
- After: tool executes; verified it returns real OSV advisories (e.g. `flatmap-stream@0.1.1 → MAL-2025-20690`).
- No behavior change for credentialed extensions (their `targets` are non-empty before this branch).

## Notes
Scope is local-dev composition only; production network-policy resolution is untouched.
