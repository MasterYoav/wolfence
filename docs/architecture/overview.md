# Wolfence Architecture Overview

## Purpose

Wolfence is a local-first security gate that stands in front of Git operations.
Its core promise is simple:

1. A developer asks to push code.
2. Wolfence inspects the outbound change set.
3. Wolfence decides whether the action is safe enough to proceed.
4. Git side effects happen only after the security decision is complete.

That means the architecture must optimize for deterministic local execution,
clear operator feedback, and strong separation between finding generation and
policy judgment.

## Recommended Architecture

The architecture chosen for the first implementation is a modular monolith in a
single Rust binary.

This is the right fit because:

- The highest-value workflow is synchronous and local.
- Security tooling becomes fragile when it depends on distributed services too early.
- One binary is easier to trust, audit, version, sign, and distribute.
- The core decision path should not depend on network reachability.

The repository now also contains a native macOS app. That app is intentionally
downstream of the Rust core: it observes local Wolfence state and structured
command output, but it does not own enforcement.

## Product Surfaces

Wolfence currently ships with two local-first surfaces:

- `wolf`: the authoritative CLI and protected Git execution path
- `Wolfence.app`: a root-level SwiftUI operator console for multi-repository
  monitoring

This separation matters:

- only the Rust binary may decide whether a push is allowed
- the macOS app may read `.wolfence/*` state and call `wolf ... --json`
- the macOS app must not fork the policy model or invent its own security
  verdicts

## High-Level Flow

```text
CLI
  -> command layer
  -> repository context loader
  -> orchestrator
  -> scanner adapters
  -> normalized findings
  -> policy engine
  -> decision
  -> optional Git delegation

macOS app
  -> repository workspace selection
  -> repo-local state adapters (.wolfence/*)
  -> wolf JSON command adapters
  -> native presentation layer
```

## Core Modules

### CLI layer

The CLI exists only to parse operator intent and hand off to the application
layer. It should never own security logic.

### Command layer

The command layer maps a parsed command such as `push` or `scan` into a use
case. It prints human-readable operator output, but it should rely on the core
domain modules for every real security judgment.

### Native desktop console

The root-level SwiftUI app is an operator console, not a second policy engine.
Its responsibilities are:

- select and persist repository workspaces
- render push posture, doctor posture, policy posture, and audit evidence
- render finding history so newly introduced risk is distinct from recurring known findings
- render finding baseline posture so accepted starting state stays distinct from newly introduced risk
- refresh structured state by calling `wolf doctor --json` and
  `wolf scan push --json`
- read repo-local files such as `.wolfence/config.toml`,
  `.wolfence/policy/receipts.toml`, `.wolfence/history/baseline.json`, and `.wolfence/audit/decisions.jsonl`

Its non-responsibilities are equally important:

- no independent security verdict logic
- no alternate policy rules
- no bypass around the Rust protected path

### Git integration layer

Wolfence is intentionally a wrapper around Git rather than a reimplementation
of Git internals. The integration layer asks Git for repository state, staged
files, branch information, and later commit and push metadata.

### Execution context

Every protected command should create one immutable execution context. This
context is the shared input to all scanners and policy checks, which avoids
duplicated Git discovery and keeps results easier to test.

### Scanner engine

Scanners run behind one shared trait. That allows the orchestrator to treat
secret scanning, SAST, dependency review, configuration analysis, and future
policy bundles as interchangeable producers of normalized findings.

### Finding model

This is the most important data contract in the system. Every scanner must emit
the same finding shape. The product can only stay coherent if policy,
explanations, persistence, and cloud sync all depend on normalized findings
instead of scanner-specific output formats.

### Policy engine

The policy engine converts findings into one final decision:

- allow
- warn
- block

This layer will later absorb:

- repo-level policy
- organization policy
- exception workflows
- signed rule bundles
- mode presets such as advisory, standard, and strict

### Git delegation layer

Git side effects should happen last. This is a security invariant, not just an
implementation preference. If Wolfence allows Git to mutate state before the
gate completes, the product's value collapses.

## Why Rust

Rust is the preferred implementation language because it aligns with the trust
profile of the product:

- memory safety without a garbage collector
- single-binary distribution
- strong type system for security-critical state transitions
- predictable performance for local scans
- good ecosystem for CLIs, serialization, and process control

## Near-Term MVP Boundaries

The MVP should focus on:

- `wolf scan`
- staged and push-scope preview modes
- `wolf push`
- `wolf doctor`
- outbound push delta discovery
- built-in heuristic secret scanning
- lightweight SAST signals
- basic dependency posture checks
- basic configuration risk checks
- policy modes
- explainable policy rationale
- clear operator explanations

The MVP should not depend on:

- cloud APIs
- background daemons
- remote rule fetches
- complex exception workflows
- multi-user control planes

## Evolution Path

The modular monolith should remain authoritative even after cloud features are
introduced. Future services can enrich the product with:

- dashboards
- team policy management
- central aggregation of repo-local finding history
- signed rule distribution
- fleet analytics
- IDE and GitHub integrations

Those services should extend the product, not become a hard dependency of the
local safety gate.

The native macOS app follows the same rule. It is a high-value local surface,
but it is still a consumer of the authoritative security engine rather than a
replacement for it.
