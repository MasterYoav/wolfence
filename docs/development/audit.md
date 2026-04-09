# Audit Operations

## Purpose

Wolfence already writes a chained local audit log under `.wolfence/audit/`.
This guide covers the operator-facing commands for inspecting and verifying that
history without opening the JSONL file directly.

## Commands

List the current chain health and the 10 most recent entries:

```bash
cargo run -- audit list
```

Verify the hash chain only:

```bash
cargo run -- audit verify
```

## What `audit list` Shows

The command prints:

- repo root
- audit log path
- total entry count
- chain health
- the 10 most recent entries in reverse chronological order

Each listed entry includes:

- sequence number
- unix timestamp
- source
- status
- outcome
- verdict
- finding counts
- override and receipt-issue counts
- branch or upstream metadata when present
- detail when Wolfence needs to preserve push-transport context

## Why This Matters

Wolfence separates three facts that are easy to blur together:

- policy allowed the outbound content
- the operator requested a real push
- native `git push` actually completed

That means a harmless change in a repo with no configured remote can produce:

1. `policy-allowed`
2. `push-failed`

instead of a misleading single “allowed” outcome.

## Relationship To `doctor`

`wolfence doctor` verifies the audit chain as one health check.

Use `audit verify` when you only want the chain result.

Use `audit list` when you want both the chain health and the recent local
decision history.
