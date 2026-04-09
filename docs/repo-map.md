# Wolfence Repository Map

## Current Structure

```text
.
|-- Cargo.toml
|-- README.md
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
|   |   |-- trust-store.md
|   |   `-- threat-model.md
|   `-- ui/
|       `-- swiftui-xcode-handoff.md
`-- src/
    |-- app.rs
    |-- cli.rs
    |-- commands/
    |   |-- audit.rs
    |   |-- config.rs
    |   |-- doctor.rs
    |   |-- hook_pre_push.rs
    |   |-- init.rs
    |   |-- json.rs
    |   |-- mod.rs
    |   |-- protected.rs
    |   |-- push.rs
    |   |-- receipt.rs
    |   `-- scan.rs
    `-- core/
        |-- audit.rs
        |-- config.rs
        |-- context.rs
        |-- findings.rs
        |-- git.rs
        |-- hooks.rs
        |-- mod.rs
        |-- orchestrator.rs
        |-- osv.rs
        |-- policy.rs
        |-- receipts.rs
        |-- scanners.rs
        `-- trust.rs
```

## How To Read The Codebase

Start in this order:

1. `README.md`
2. `docs/architecture/overview.md`
3. `docs/security/threat-model.md`
4. `docs/security/detection-model.md`
5. `docs/security/policy-model.md`
6. `docs/security/override-receipts.md`
7. `docs/security/receipt-approval-policy.md`
8. `docs/security/live-advisories.md`
9. `docs/security/audit-chain.md`
10. `docs/security/trust-store.md`
11. `docs/development/audit.md`
12. `docs/development/doctor.md`
13. `docs/development/json-output.md`
14. `docs/development/prototype-demo.md`
15. `docs/ui/swiftui-xcode-handoff.md`
16. `src/main.rs`
17. `src/app.rs`
18. `src/commands/mod.rs`
19. `src/commands/receipt.rs`
20. `src/core/mod.rs`

That order mirrors the way a protected command flows through the system.

## Ownership Intent

### `src/`

Production Rust code for the local Wolfence binary.

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

Native app handoff material. This is where machine-readable contracts and UI
translation guidance should stay aligned with the Rust CLI.
