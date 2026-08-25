# Contributing

1. Create a focused branch and keep changes small.
2. Run `cargo fmt --all -- --check`.
3. Run `cargo clippy --workspace --all-targets -- -D warnings`.
4. Run `cargo test --workspace`.
5. Update tests and documentation with behavior changes.
6. Never commit tokens, telemetry from real people, private IP inventories, or
   production logs.

Architecture decisions that affect data collection, retention, automated
actions, privacy or cross-platform behavior require an ADR in `docs/adr/`.
