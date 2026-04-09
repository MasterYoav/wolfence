# Getting Started

## Development Goal

The current repository is the first implementation pass for Wolfence as a Rust
CLI. The codebase is intentionally lightweight so the architecture can harden
before external scanner integrations are added.

## Local Commands

```bash
cargo fmt
cargo test
cargo install --path . --force
cargo run -- init
cargo run -- config
cargo run -- doctor
cargo run -- doctor --json
cargo run -- help
cargo run -- trust help
cargo run -- trust list
cargo run -- trust verify security-team
cargo run -- trust init security-team security-team 2026-12-31 secret,policy
cargo run -- trust archive security-team "rotation complete"
cargo run -- trust restore security-team
cargo run -- receipt help
cargo run -- receipt list
cargo run -- receipt new .wolfence/receipts/allow.toml push secret secret:abc123 yoav 2026-04-16 "Temporary exception"
cargo run -- receipt verify .wolfence/receipts/allow.toml
cargo run -- receipt archive .wolfence/receipts/allow.toml "Underlying issue resolved"
cargo run -- scan
cargo run -- scan --json
cargo run -- scan push
cargo run -- scan push --json
cargo run -- push
cargo run -- push --json
cargo run -- audit list --json
cargo run -- audit verify --json
```

After `cargo install --path . --force`, the intended operator interface is:

```bash
wolf init
wolf doctor
wolf doctor --json
wolf scan
wolf scan --json
wolf scan push
wolf scan push --json
wolf push
wolf push --json
```

## Current Command Status

- `scan`: real scaffold path that previews policy on staged files or the real outbound push scope without invoking `git push`; both staged and push preview modes exit non-zero when the preview would block
- `push`: real guarded push path that evaluates outbound branch content before delegating to `git push`
- `init`: creates repo-local config and installs a managed `pre-push` hook
- `doctor`: audits whether the local enforcement path is actually trustworthy
- `doctor --json`: returns machine-readable repo health for local UI and automation
- `config`: explains how the effective mode was resolved
- `trust list`: shows published versus active trust keys, metadata status, expiry posture, and category scope
- `trust verify`: explains whether one trust key is active, inactive, or archived and which receipt categories it may sign when active
- `trust init`: creates canonical trust metadata for an existing key under `.wolfence/trust/`, with optional comma-separated category scope
- `trust archive`: moves one live trust key into `.wolfence/trust/archive/` so it stops affecting signed-receipt posture but remains reviewable
- `trust restore`: restores the latest un-restored archived trust key back into `.wolfence/trust/` and records the restoration in archive history
- `receipt list`: shows active, ignored, and archived receipts for the current repository
- `receipt new`: creates a canonical unsigned receipt draft under `.wolfence/receipts/`
- `receipt checksum`: prints the canonical checksum for one reviewable override receipt
- `receipt verify`: evaluates one receipt against the current repo trust model and reports whether it is active or ignored
- `receipt archive`: moves one receipt into `.wolfence/receipts/archive/` so it no longer affects enforcement but remains reviewable
- `receipt sign`: preflights repo receipt policy, recomputes the checksum, signs the canonical payload, verifies it against trusted public key material, and updates the receipt in place
- reviewable exceptions live in `.wolfence/receipts/*.toml` and are audited by `doctor`
- `scan --json`, `push --json`, and `audit ... --json` are the intended app-facing command surfaces; see `docs/development/json-output.md`

## Contribution Standard

This repository should stay heavily documented. Every meaningful module should
have:

- a module-level doc comment explaining why it exists
- clear type names
- obvious boundaries between orchestration, policy, and I/O
- documentation updates when architecture changes
