# RootCause Server agent instructions

## Mission

Build an evidence-first, cross-platform observability and root-cause control
plane. Preserve Windows, Linux and macOS support in every change.

## Required reading

Before editing, read:

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/CAPABILITIES.md`
4. `docs/SECURITY_REQUIREMENTS.md`
5. `docs/THREAT_MODEL.md`

Read the affected ADR and API sections for the task.

## Non-negotiable boundaries

- RootCause complements antivirus, EDR, SIEM and firewalls; it does not replace
  them.
- Do not add malware sandboxing, reverse engineering, a kernel driver, or a
  signature engine to this repository.
- Keep the agent read-only by default.
- Never add an automatic destructive action.
- Do not label a correlation as confirmed causality without sufficient evidence.
- Never claim a planned capability is implemented.
- Preserve REQ-SEC-001 and REQ-SEC-002.

## Engineering rules

- Rust is the primary language for domain, server and agent.
- Keep `rootcause-core` independent from transport and operating systems.
- Maintain protocol compatibility or document and test a migration.
- Avoid unsafe Rust. Any exception requires a dedicated ADR and review.
- Keep dependencies minimal and disable unused default features.
- Never log tokens, credentials, personal data or unbounded request bodies.
- Add tests and update capabilities, threat model and changelog with changes.

## Completion gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The CI matrix must remain green on Windows, Linux and macOS.
