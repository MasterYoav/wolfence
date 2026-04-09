# ADR 0001: Choose a Local-First Modular Monolith

## Status

Accepted

## Date

2026-04-09

## Context

Wolfence is meant to intercept developer Git workflows before code leaves the
machine. The most important action in the product is a protected push, which
must:

1. inspect local changes
2. run security analysis
3. evaluate policy
4. allow or block the outbound operation

The project is at the beginning of implementation, so the architectural choice
needs to reduce moving parts without blocking future growth.

## Decision

Wolfence will start as a single Rust binary with a modular monolith
architecture.

The binary will contain distinct internal modules for:

- CLI parsing
- command orchestration
- Git integration
- execution context building
- scanner adapters
- normalized findings
- policy evaluation
- operator explanations

## Rationale

- Local safety decisions must be deterministic and fast.
- Security products are harder to trust when they depend on network services.
- Shipping one binary is easier to audit, sign, and distribute.
- Early cloud complexity would dilute effort away from the core blocking path.
- A modular monolith still allows strong boundaries and future extraction if
  there is real evidence those seams need to become services.

## Consequences

### Positive

- simpler development and debugging
- smaller attack surface in the first releases
- easier local testing
- cleaner supply-chain story
- better operator trust

### Negative

- long-term cloud features will need deliberate integration points
- scanner execution, persistence, and UI concerns must remain disciplined so the
  binary does not become a tangled codebase

## Follow-Up Work

- define the normalized finding schema as a stable internal contract
- implement strict policy and override boundaries
- add signed release and provenance workflow
- define which future capabilities remain local and which may become optional
  remote services
