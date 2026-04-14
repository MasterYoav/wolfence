# Wolfence Repository Map

## Current Structure

```text
.
|-- Cargo.toml
|-- fixtures/
|-- Media/
|-- README.md
|-- Wolfence/
|   |-- Assets.xcassets/
|   |-- ContentView.swift
|   `-- WolfenceApp.swift
|-- Wolfence.xcodeproj/
|-- WolfenceTests/
|   `-- WolfenceTests.swift
|-- WolfenceUITests/
|   |-- WolfenceUITests.swift
|   `-- WolfenceUITestsLaunchTests.swift
|-- docs/
|   |-- architecture/
|   |   |-- decision-records/
|   |   |   `-- 0001-modular-monolith.md
|   |   `-- overview.md
|   |-- development/
|   |   |-- audit.md
|   |   |-- doctor.md
|   |   |-- configuration.md
|   |   |-- getting-started.md
|   |   |-- json-output.md
|   |   `-- prototype-demo.md
|   |-- security/
|   |   |-- audit-chain.md
|   |   |-- detection-model.md
|   |   |-- live-advisories.md
|   |   |-- override-receipts.md
|   |   |-- policy-model.md
|   |   |-- receipt-approval-policy.md
|   |   |-- scanner-inventory.json
|   |   |-- scanner-inventory.md
|   |   |-- safety-check-roadmap.md
|   |   |-- trust-store.md
|   |   `-- threat-model.md
|   `-- ui/
|       |-- macos-console.md
|       `-- swiftui-xcode-handoff.md
`-- src/
    |-- app.rs
    |-- cli.rs
    |-- test_support.rs
    |-- commands/
    |   |-- audit.rs
    |   |-- baseline.rs
    |   |-- config.rs
    |   |-- doctor.rs
    |   |-- hook_pre_push.rs
    |   |-- init.rs
    |   |-- json.rs
    |   |-- mod.rs
    |   |-- protected.rs
    |   |-- push.rs
    |   |-- receipt.rs
    |   |-- scan.rs
    |   `-- trust.rs
    `-- core/
        |-- audit.rs
        |-- config.rs
        |-- context.rs
        |-- finding_baseline.rs
        |-- finding_history.rs
        |-- findings.rs
        |-- git.rs
        |-- github_governance.rs
        |-- hooks.rs
        |-- mod.rs
        |-- orchestrator.rs
        |-- osv.rs
        |-- policy.rs
        |-- receipt_policy.rs
        |-- receipts.rs
        |-- scanners.rs
        `-- trust.rs
```

## How To Read The Codebase

Start in this order:

1. `README.md`
2. `docs/architecture/overview.md`
3. `docs/development/getting-started.md`
4. `docs/ui/macos-console.md`
5. `docs/ui/swiftui-xcode-handoff.md`
6. `docs/security/threat-model.md`
7. `docs/security/detection-model.md`
8. `docs/security/scanner-inventory.md`
9. `docs/security/scanner-inventory.json`
10. `docs/security/safety-check-roadmap.md`
11. `docs/security/policy-model.md`
12. `docs/security/override-receipts.md`
13. `docs/security/receipt-approval-policy.md`
14. `docs/security/live-advisories.md`
15. `docs/security/audit-chain.md`
16. `docs/security/trust-store.md`
17. `docs/development/audit.md`
18. `docs/development/doctor.md`
19. `docs/development/json-output.md`
20. `docs/development/prototype-demo.md`
21. `src/main.rs`
22. `src/app.rs`
23. `src/commands/mod.rs`
24. `src/commands/receipt.rs`
25. `src/core/mod.rs`
26. `Wolfence/ContentView.swift`
27. `Wolfence/WolfenceApp.swift`

That order mirrors the way the protected CLI and the native macOS console fit
together: product narrative first, then security model, then the Rust engine,
then the app surface that consumes structured Wolfence state.

## Ownership Intent

### `src/`

Production Rust code for the local Wolfence binary.

### `Wolfence/`

Production SwiftUI code for the root-level native macOS workspace app.

### `Wolfence.xcodeproj/`

Xcode project, shared scheme, and build configuration for the native app and
its test targets.

### `WolfenceTests/` and `WolfenceUITests/`

Native macOS app unit and UI test targets.

### `src/commands/`

User-facing workflows. These files should stay thin and avoid business logic
that belongs in the core domain.

### `src/core/`

Long-lived domain modules. This is where the security model, orchestration, and
policy engine should mature.

### `docs/architecture/`

Architecture narratives and decision records. Add a new ADR whenever a major
technical choice becomes intentional enough to defend later.

### `docs/security/`

Threat models, trust boundaries, security assumptions, and later secure
development lifecycle guidance.

### `docs/development/`

Reserved for contributor workflows, release playbooks, coding standards, and
future integration guides.

### `docs/ui/`

Native app documentation. This is where current macOS console behavior,
machine-readable contracts, and UI translation guidance stay aligned with the
Rust CLI.

### `Media/`

Shared brand and app assets used by the README, app icon pipeline, and native
desktop presentation.

### `fixtures/`

Small real-repo regression samples used by end-to-end scan and push tests.
