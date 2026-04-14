# Wolfence macOS Console

## Purpose

The repository now includes a native macOS app at the repo root.

Its purpose is to act as a calm, evidence-first operator console for Wolfence's
local security gate. It does not replace the Rust CLI. It makes the current
repository posture easier to inspect across multiple repositories at once.

## Canonical Rule

The `wolf` binary remains authoritative for:

- protected push decisions
- scanner execution
- policy evaluation
- audit entry creation

The macOS app is authoritative only for presentation and local workspace state.

## Current Implementation

The current app lives in:

- `Wolfence/WolfenceApp.swift`
- `Wolfence/ContentView.swift`
- `Wolfence.xcodeproj`

The app currently provides:

- a persistent sidebar of repository workspaces
- per-repository refresh and scan actions
- a high-level push-safety hero state
- doctor posture and priority checks
- a dedicated live GitHub governance panel driven by `wolf doctor --json`
- repo-local policy and receipt-policy display
- findings and exception display from push-preview JSON
- finding history and accepted-baseline posture so new findings stand out from known starting state
- remediation-driven `Fix Now` actions derived from finding metadata
- an audit timeline sourced from `.wolfence/audit/decisions.jsonl`
- repository icon customization persisted in app storage

## Source Of Truth

The app currently reads state from these sources:

1. `.wolfence/config.toml`
2. `.wolfence/policy/receipts.toml`
3. `.wolfence/history/baseline.json`
4. `.wolfence/audit/decisions.jsonl`
5. `wolf doctor --json`
6. `wolf scan push --json`

The app prefers repo-local files when a stable file already exists and prefers
`--json` command output when current state must be recomputed.

## Binary Discovery

When the app needs to execute Wolfence, it currently looks for the binary in
this order:

1. `target/debug/wolf`
2. `target/release/wolf`
3. `wolf` on `PATH`

That lets the app work naturally inside the repository during development while
still supporting an installed binary.

## Current Boundaries

The app currently does not try to:

- execute independent policy logic
- parse fragile human-readable terminal output when JSON exists
- edit trust material
- edit override receipts
- replace the protected `wolf push` path

Those remain Rust CLI responsibilities unless the CLI exposes a stable
machine-readable workflow that the app can safely drive.

## Developer Workflow

Typical local loop:

```bash
cargo install --path . --force
open Wolfence.xcodeproj
```

Or build and test from the command line:

```bash
xcodebuild -project Wolfence.xcodeproj -scheme Wolfence -destination 'platform=macOS' build
xcodebuild -project Wolfence.xcodeproj -scheme Wolfence -destination 'platform=macOS' test
```

## Relationship To Other Docs

- `docs/development/json-output.md` defines the app-facing command contracts
- `docs/ui/swiftui-xcode-handoff.md` defines the broader product translation
  rules and forward-looking UI contract
- `docs/architecture/overview.md` explains why the app is downstream of the
  Rust enforcement core
