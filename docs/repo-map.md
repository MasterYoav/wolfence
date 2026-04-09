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
|   |   `-- prototype-demo.md
|   `-- security/
|       |-- audit-chain.md
|       |-- detection-model.md
|       |-- live-advisories.md
|       |-- override-receipts.md
|       |-- policy-model.md
|       |-- receipt-approval-policy.md
|       |-- trust-store.md
|       `-- threat-model.md
`-- src/
    |-- app.rs
    |-- cli.rs
    |-- commands/
    |   |-- audit.rs
    |   |-- config.rs
    |   |-- doctor.rs
    |   |-- hook_pre_push.rs
    |   |-- init.rs
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
13. `docs/development/prototype-demo.md`
14. `src/main.rs`
15. `src/app.rs`
16. `src/commands/mod.rs`
17. `src/commands/receipt.rs`
18. `src/core/mod.rs`

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
