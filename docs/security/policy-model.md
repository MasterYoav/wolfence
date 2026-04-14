# Policy Model

## Purpose

Wolfence does not treat every finding the same way.

That is deliberate. A trustworthy local gate needs to distinguish between:

- how bad a condition would be if true
- how strong the detection signal is
- whether the finding comes from a heuristic code smell or a concrete
  provenance, secret, or policy problem

The current policy engine therefore evaluates each finding across three axes:

- `severity`
- `confidence`
- `category`

## Inputs

### Severity

Severity describes impact:

- `info`
- `low`
- `medium`
- `high`
- `critical`

### Confidence

Confidence describes how trustworthy the signal is:

- `low`
- `medium`
- `high`

This matters because some findings are direct evidence, while others are
heuristics that deserve review but not the same default enforcement.

### Category

The current categories are:

- `secret`
- `vulnerability`
- `dependency`
- `configuration`
- `policy`

The category matters because a high-confidence private key leak is not the same
as a medium-confidence SAST pattern.

## Current Mode Semantics

### `advisory`

`advisory` never blocks. It warns on:

- all `medium`, `high`, and `critical` findings
- any high-confidence non-vulnerability finding

This mode is suitable for onboarding and signal review, not for hard
enforcement.

### `standard`

`standard` is the default balanced mode.

It blocks:

- all `high` and `critical` findings
- `medium` findings when confidence is `high` and the category is not
  `vulnerability`
- declared internal package ownership drift and direct-source bypass findings,
  even if a scanner later reports them below `medium`

It warns on:

- remaining `medium` findings
- high-confidence non-vulnerability findings that are not severe enough to
  block

This means medium-confidence SAST heuristics still surface, but a high-signal
dependency provenance or policy failure can block even at `medium`. It also
means Wolfence treats explicit private-package ownership drift more strictly
than generic custom-source posture warnings, because those findings violate a
declared provenance policy instead of merely signaling ambiguous risk.

### `strict`

`strict` is the hardened local gate.

It blocks:

- all `medium`, `high`, and `critical` findings
- `low` findings when confidence is `high` and the category is not
  `vulnerability`
- declared internal package ownership drift and direct-source bypass findings
  as hard provenance failures regardless of their coarse severity

It warns on:

- remaining `low` findings
- high-confidence informational findings that are not severe enough to block

This mode is meant for repositories where provenance, policy posture, and
configuration drift should be treated aggressively.

## Why Vulnerability Findings Are Treated Differently

The current vulnerability scanner is still heuristic. It can be useful, but it
does not yet provide the same proof quality as:

- a private key header
- a known token prefix
- a missing lockfile integrity field
- a repo policy file being absent

Because of that, medium-severity vulnerability findings warn in `standard`
instead of blocking by default. That is a false-positive control choice, not a
statement that vulnerabilities are less important.

## Determinism Guarantees

Before policy evaluation, findings are normalized further by:

- sorting stronger findings first
- deduplicating repeated fingerprints

This keeps the decision path stable and the operator output predictable across
repeated runs.

## Override Receipts

The current policy engine can suppress a warning or block only when a
repo-local override receipt matches the finding category, fingerprint, and
action.

Receipts are intentionally narrow:

- one receipt targets one finding fingerprint
- receipts are action-scoped
- receipts require an owner and human reason
- receipts expire on a fixed ISO date
- receipts must pass an integrity checksum check

If a receipt is malformed, expired, duplicated, or fails integrity validation,
Wolfence ignores it and reports the issue through `doctor` and protected push
output.

Receipt governance can also be constrained by repo policy in
`.wolfence/policy/receipts.toml`, including:

- maximum receipt lifetime
- required reviewer metadata
- category-specific reviewer and approver allowlists
- allowed reviewer identities
- allowed signing approvers

This means a receipt can now be structurally valid but still ignored if it does
not satisfy the repository's explicit approval policy.

## Live Advisory Availability

Live OSV advisory intelligence changes one aspect of policy posture: not the
local rule semantics, but the completeness of current dependency risk context.

Wolfence therefore exposes advisory availability separately through
`WOLFENCE_OSV`:

- `off`
- `auto`
- `require`

`auto` preserves local-first behavior by treating OSV as best-effort.
`require` is the stricter posture and emits a finding when the advisory lookup
cannot run.

## Operator Output

Blocked and warning findings should explain:

- severity
- confidence
- category
- scanner
- location
- detail
- remediation
- policy rationale

The rationale is important. A security tool should not just say "blocked"; it
should say why the current mode treated that finding the way it did.
