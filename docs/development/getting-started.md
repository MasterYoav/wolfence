# Getting Started

## Development Goal

The repository now contains two tightly-coupled local surfaces:

- the Rust `wolf` CLI, which remains the authoritative enforcement engine
- a native SwiftUI macOS app at the repo root, which renders repo posture and
  audit evidence without duplicating policy logic

The codebase is still intentionally local-first. The CLI owns protected Git
execution and security decisions. The macOS app is a downstream operator
console over repo-local evidence and `--json` command surfaces.

## Local Commands

### Rust CLI

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
cargo run -- baseline capture
cargo run -- baseline show
cargo run -- baseline clear
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
wolf baseline capture
wolf baseline show
wolf baseline clear
wolf push
wolf push --json
```

### Native macOS App

```bash
open Wolfence.xcodeproj
xcodebuild -project Wolfence.xcodeproj -scheme Wolfence -destination 'platform=macOS' build
xcodebuild -project Wolfence.xcodeproj -scheme Wolfence -destination 'platform=macOS' test
```

The app looks for the Wolfence binary in this order:

1. `target/debug/wolf`
2. `target/release/wolf`
3. `wolf` on `PATH`

That means the smoothest local loop is usually:

1. build the CLI
2. keep `target/debug/wolf` available
3. run or debug the app from Xcode against real repositories

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
- `receipt new`: creates a canonical unsigned receipt draft under `.wolfence/receipts/`, accepts `auto` and `+<days>d` expiry shortcuts, and prints the effective receipt-governance requirements plus the next expected step
- `receipt checksum`: prints the canonical checksum for one reviewable override receipt
- `receipt verify`: evaluates one receipt against the current repo trust model and reports whether it is active or ignored
- `receipt archive`: moves one receipt into `.wolfence/receipts/archive/` so it no longer affects enforcement but remains reviewable
- `receipt sign`: preflights repo receipt policy, recomputes the checksum, signs the canonical payload, verifies it against trusted public key material, and updates the receipt in place
- reviewable exceptions live in `.wolfence/receipts/*.toml` and are audited by `doctor`
- `scan --json`, `push --json`, and `audit ... --json` are the intended app-facing command surfaces; see `docs/development/json-output.md`
- `baseline capture`: records the current push or staged finding fingerprints in `.wolfence/history/baseline.json` so later runs can distinguish accepted starting state from newly introduced risk
- `baseline show`: prints the current repo-local accepted baseline metadata
- `baseline clear`: removes the current accepted baseline snapshot

## Current App Status

- the root-level macOS app is a real project, not a placeholder handoff
- it supports a persistent multi-repository sidebar workspace
- it refreshes current repo posture with `wolf doctor --json` and `wolf scan push --json`
- it reads `.wolfence/config.toml`, `.wolfence/policy/receipts.toml`, and `.wolfence/audit/decisions.jsonl` directly
- it highlights new versus recurring findings and accepted baseline versus needs-review findings from push preview data
- it currently focuses on monitoring, evidence display, and scan refresh rather than config editing or trust editing
- the current implementation details live in `docs/ui/macos-console.md`

## Contribution Standard

This repository should stay heavily documented. Every meaningful module should
have:

- a module-level doc comment explaining why it exists
- clear type names
- obvious boundaries between orchestration, policy, and I/O
- documentation updates when architecture changes
- documentation updates when either the Rust engine or the macOS console
  changes user-visible behavior

## Regression Fixtures

The repository now includes small sample repos under `fixtures/repos/`.

Those fixtures are used by `cargo test` to exercise end-to-end scan and push
behavior against realistic repository layouts instead of only hand-built temp
files. Add a new fixture when a regression is easiest to express as a small
repo snapshot with committed or staged content. The current corpus includes
harmless repos, secret-bearing push fixtures, unsigned override fixtures,
trust-required rejection fixtures, trust-verified signed override fixtures,
receipt-policy fixtures for reviewer requirements, reviewer allowlists, and
category-scoped signing rules, category-scoped approver and key-id allowlists,
degraded push-transport fixtures, governance-and-receipt interplay fixtures
around CODEOWNERS coverage for changed exception material, governance-as-code
regressions, release-governance interplay fixtures around changed publish and
ruleset authority paths, IaC posture regressions, dependency provenance
regressions, live GitHub governance fixtures that inject deterministic `gh api`
responses for drift and required-unavailable paths, and appsec code
regressions. Each fixture's `.fixture.json` now declares its
expected staged or push policy verdict, optionally overrides the expected
command exit for cases such as transport failure after a policy-allowed
decision, and records the finding IDs that must remain present. Fixtures may
also declare optional `not_finding_ids` guards for false-positive regressions,
optional JSON payload invariants including receipt override and issue counts,
and optional push audit-log expectations such as entry count, health,
outcomes, applied override counts, and receipt-issue counts.

Push fixtures may also declare an `upstream_fixture` directory name. When
present, the harness first materializes that snapshot, pushes it to a local
temporary bare remote, and only then applies the final fixture tree as the
ahead commit or staged state. Use that pattern when a push fixture needs
pre-existing remote policy material such as receipts, trust metadata, or
governance files without treating those files as part of the outbound change.

Push fixtures may also declare `live_github_governance` metadata. When
present, the harness rewires the temp repo's `origin` to the declared GitHub
repository, installs a deterministic fake `gh` binary, and applies the
requested `WOLFENCE_GITHUB_GOVERNANCE` mode before evaluating `push` or
`scan push --json`. Use that pattern when a fixture needs to prove live GitHub
drift or required-verification failures without making real network calls.

If the same fixture also declares `live_github_governance_receipt`, the harness
computes a real `policy` override receipt for the requested live-governance
scenario before evaluation. Use that to cover exact-match live-drift overrides
and stale receipts that no longer match the current live GitHub drift. The same
receipt metadata can also request trusted signing so fixtures cover unsigned
receipt rejection, wrong-key policy rejection, unknown-key trust rejection, and
valid signed live-governance overrides under repo trust. When a fixture needs
trust material to exist without trusting the signing key itself, declare
`trusted_key_id` separately from the receipt `key_id`.
