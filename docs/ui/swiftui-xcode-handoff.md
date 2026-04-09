# Wolfence SwiftUI Handoff

This document is for Codex in Xcode.

Its job is to explain how to translate Wolfence's existing CLI states, audit
log, and repository-local policy surfaces into a native SwiftUI application
without inventing a different product model.

The app should feel like a native operator console for a local security gate,
not a generic log viewer.

## Product Rule

The UI must preserve one core truth:

- Wolfence is a local gate in front of `git push`
- the most important state is the current push decision
- the second most important state is whether the local enforcement path is trustworthy
- logs and receipts are evidence, not the primary product

The app should therefore center:

1. current push posture
2. current health / doctor posture
3. recent audit trail
4. findings and exceptions

## Source Of Truth Order

Use sources in this order:

1. direct repo files when a structured file already exists
2. Wolfence command output when structured files do not exist yet
3. Git state only when Wolfence itself depends on that Git state

Concrete mapping:

- audit timeline:
  read `.wolfence/audit/decisions.jsonl` directly
- repo config / receipt policy / receipts / trust:
  read files directly
- current health:
  run `wolf doctor --json`
- current effective configuration:
  run `wolf config`
- current push preview / active push action:
  run `wolf scan push --json` or `wolf push --json`

Do not build the audit screen by scraping `wolf audit list` if the JSONL file is
available.

Also do not scrape terminal text from `doctor`, `scan`, `push`, or `audit`
when `--json` is available. The machine-readable contract is documented in
[json-output.md](/Users/yoavperetz/Developer/Wolfence/docs/development/json-output.md).

## Core Domain Model

Mirror these Rust concepts in Swift exactly.

### Finding

Source: [findings.rs](/Users/yoavperetz/Developer/Wolfence/src/core/findings.rs)

```swift
struct UIFinding: Identifiable, Hashable {
    var id: String
    var scanner: String
    var severity: FindingSeverity
    var confidence: FindingConfidence
    var category: FindingCategory
    var file: String?
    var line: Int?
    var title: String
    var detail: String
    var remediation: String
    var fingerprint: String
}
```

Enums:

- `FindingSeverity`: `info`, `low`, `medium`, `high`, `critical`
- `FindingConfidence`: `low`, `medium`, `high`
- `FindingCategory`: `secret`, `vulnerability`, `dependency`, `configuration`, `policy`

### Scan Report

Source: [orchestrator.rs](/Users/yoavperetz/Developer/Wolfence/src/core/orchestrator.rs)

```swift
struct UIScanReport {
    var findings: [UIFinding]
    var discoveredFiles: Int
    var scannedFiles: Int
    var ignoredFiles: Int
    var scannersRun: Int
}
```

### Policy Decision

Source: [policy.rs](/Users/yoavperetz/Developer/Wolfence/src/core/policy.rs)

```swift
enum UIVerdict: String {
    case allow
    case warn
    case block
}

struct UIPolicyFinding: Identifiable, Hashable {
    var id: String { finding.fingerprint + rationale }
    var finding: UIFinding
    var rationale: String
}

struct UIOverriddenFinding: Identifiable, Hashable {
    var id: String { finding.fingerprint + receipt.receiptID }
    var finding: UIFinding
    var receipt: UIOverrideReceipt
}

struct UIPolicyDecision {
    var verdict: UIVerdict
    var blockingFindings: [UIPolicyFinding]
    var warningFindings: [UIPolicyFinding]
    var overriddenFindings: [UIOverriddenFinding]
}
```

### Push Status

Source: [git.rs](/Users/yoavperetz/Developer/Wolfence/src/core/git.rs)

The UI should normalize push scope into:

```swift
enum UIPushScopeState {
    case noCommits
    case upToDate
    case ready(
        branch: String,
        upstream: String?,
        commitsAhead: Int,
        discoveredFiles: Int,
        scannedFiles: Int,
        ignoredFiles: Int
    )
}
```

### Push Outcome

Source: [push.rs](/Users/yoavperetz/Developer/Wolfence/src/commands/push.rs)

This should be a first-class UI state machine:

```swift
enum UIPushOutcome {
    case noOpNoCommits
    case noOpUpToDate
    case blocked
    case allowedDryRun
    case allowedTransportFailed(detail: String)
    case completed
}
```

Map from current audit / command vocabulary:

- `status = "no-commits"`, `outcome = "no-op"` -> `.noOpNoCommits`
- `status = "up-to-date"`, `outcome = "no-op"` -> `.noOpUpToDate`
- `status = "ready"`, `outcome = "blocked"` -> `.blocked`
- `status = "ready"`, `outcome = "allowed-dry-run"` -> `.allowedDryRun`
- `status = "ready"`, `outcome = "policy-allowed"` -> intermediate state only, not final success
- `status = "ready"`, `outcome = "push-failed"` -> `.allowedTransportFailed`
- `status = "completed"`, `outcome = "push-completed"` -> `.completed`

Important:

- `policy-allowed` is not the same as a successful push
- the UI must distinguish "policy passed" from "network / Git transport succeeded"

### Audit Entry

Source: [audit.rs](/Users/yoavperetz/Developer/Wolfence/src/core/audit.rs)

```swift
struct UIAuditEntry: Identifiable, Hashable, Decodable {
    var id: Int { sequence }
    var sequence: Int
    var timestampUnix: UInt64
    var source: String
    var action: String
    var status: String
    var outcome: String
    var detail: String?
    var verdict: String?
    var discoveredFiles: Int
    var candidateFiles: Int
    var ignoredFiles: Int
    var findings: Int
    var warnings: Int
    var blocks: Int
    var overridesApplied: Int
    var receiptIssues: Int
    var branch: String?
    var upstream: String?
    var commitsAhead: Int?
}
```

### Doctor

Source: [doctor.rs](/Users/yoavperetz/Developer/Wolfence/src/commands/doctor.rs)

```swift
enum UIDoctorStatus: String {
    case pass
    case warn
    case fail
    case info
}

struct UIDoctorCheck: Identifiable, Hashable {
    var id: String { name }
    var name: String
    var status: UIDoctorStatus
    var detail: String
    var remediation: String?
}

struct UIDoctorSummary {
    var pass: Int
    var warn: Int
    var fail: Int
    var info: Int
}
```

### Receipts

Source: [receipts.rs](/Users/yoavperetz/Developer/Wolfence/src/core/receipts.rs)

```swift
struct UIOverrideReceipt: Identifiable, Hashable {
    var id: String { receiptID }
    var path: String
    var receiptID: String
    var action: String
    var category: String
    var categoryBound: Bool
    var fingerprint: String
    var owner: String
    var reviewer: String?
    var reviewedOn: String?
    var approver: String?
    var keyID: String?
    var reason: String
    var createdOn: String
    var expiresOn: String
    var checksum: String
}

struct UIReceiptIssue: Identifiable, Hashable {
    var id: String { path + detail }
    var path: String
    var detail: String
    var remediation: String
}
```

## UI Information Architecture

Build the app around five top-level surfaces.

## 1. Overview

This is the landing screen.

Show:

- current repo path
- current effective mode
- current push posture
- doctor summary
- last audit entry
- counts:
  findings, warnings, blocks, receipt issues, active receipts

Primary cards:

- `Push Status`
- `Health`
- `Recent Decision`
- `Exceptions`

The overview should answer:

- can I push right now?
- if not, why not?
- is the local gate trustworthy?

## 2. Push Review

This is the most important detailed screen.

Use it for:

- previewing `wolf scan push`
- rendering the latest `wolf push`
- browsing blocking findings and warnings

Layout:

- header:
  repo, branch, upstream, commits ahead
- scope bar:
  discovered / scanned / ignored
- verdict banner:
  allow / warn / block
- grouped findings:
  blocking, warnings, overridden
- receipt issues section if present

Rules:

- blocking findings first
- warnings second
- overridden findings collapsed by default
- show scanner, location, detail, remediation, and policy rationale

## 3. Health

Render `wolf doctor` as a health console, not a log dump.

Layout:

- summary counters at top
- sections grouped by status severity:
  fail, warn, pass, info

Each row shows:

- check name
- status badge
- detail
- remediation if present

Rules:

- `fail` rows always expanded
- `warn` rows expanded by default
- `pass` and `info` rows can be collapsed

## 4. Audit Timeline

Source this from `.wolfence/audit/decisions.jsonl`.

The timeline should feel evidence-grade:

- reverse chronological list
- each row shows:
  sequence, date/time, source, outcome, verdict
- secondary metadata:
  branch, upstream, commits ahead
- scope summary:
  discovered, scanned, ignored
- decision summary:
  findings, warnings, blocks, overrides, receipt issues

If `detail` exists, render it as the event explanation.

This screen should support:

- filtering by outcome
- filtering by verdict
- filtering by source
- searching by branch or detail text

## 5. Policy / Exceptions

This is where configuration and trust surfaces live.

Show:

- effective mode
- scan ignore paths
- receipt policy posture
- trust posture
- active receipt count
- receipt issue count
- trust key counts:
  trusted, published, expired, scoped, unrestricted, archived

This screen is not the landing screen.
It is an operator details screen.

## Visual Translation Rules

### Verdict Colors

- `allow`: green
- `warn`: amber
- `block`: red

### Doctor Status Colors

- `pass`: green
- `warn`: amber
- `fail`: red
- `info`: neutral blue or gray

### Finding Severity Presentation

- `critical`: strongest red treatment
- `high`: red
- `medium`: amber
- `low`: yellow-gray
- `info`: neutral

### Category Icons

- `secret`: key / lock
- `vulnerability`: shield slash / bug
- `dependency`: package / cube
- `configuration`: slider / wrench
- `policy`: checklist / document

## UX Translation Rules

Do not expose raw Rust type names.

Use these UI phrases:

- `allow` -> `Safe To Push`
- `warn` -> `Push Allowed With Warnings`
- `block` -> `Push Blocked`
- `no-op` with `up-to-date` -> `Nothing To Push`
- `allowed but transport failed` -> `Security Passed, Git Push Failed`

Do not flatten all failures into one red state.

The app must distinguish:

- policy failure
- health/runtime failure
- Git transport failure
- no-op state

## Parsing Rules

## Audit JSONL

Decode each line as one JSON object.

Do not treat the whole file as one JSON array.

## Command Output

For CLI output, prefer line-oriented parsing with indentation-aware sections.

Useful patterns:

- `key: value` top-level lines
- grouped sections:
  `blocking findings:`, `warnings:`, `applied overrides:`, `ignored receipt issues:`
- indented detail lines under findings:
  `scanner:`, `location:`, `detail:`, `remediation:`, `policy:`

Do not build the app around fragile full-text regex matching if the same data
can be read from files or normalized state adapters.

## Recommended Swift Architecture

Use four layers:

1. `WolfProcessClient`
   runs `wolf` commands with `Process`

2. `WolfRepositoryStore`
   reads `.wolfence/*` files and audit JSONL

3. `WolfDomainMapper`
   converts command/file data into stable Swift models

4. `SwiftUI ViewModels`
   drive screens from domain models, not raw command text

Recommended view models:

- `OverviewViewModel`
- `PushReviewViewModel`
- `DoctorViewModel`
- `AuditTimelineViewModel`
- `PolicyViewModel`

## Recommended First App Scope

The first version should ship only these features:

1. repo picker / repo root display
2. run `wolf doctor`
3. run `wolf scan push`
4. run `wolf push`
5. render latest audit timeline from JSONL

Do not start with receipt editing, trust editing, or config editing.
Those can come later.

## Future-Proofing Rule

The current CLI is human-readable, not JSON-first.

So the app should isolate parsing behind adapters and keep UI models stable.
When Wolfence later gains machine-readable command output, only the adapter
layer should change.

## Non-Negotiable UI Principle

The native app must make Wolfence feel calmer and clearer than the terminal,
but never softer.

If Wolfence blocks a push, the UI must be explicit, evidence-driven, and hard
to misread:

- what was scanned
- what was ignored
- what blocked
- what warned
- what was overridden
- why the final verdict happened

That is the translation target.
