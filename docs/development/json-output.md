# JSON Output

Wolfence now exposes stable machine-readable output for the command surfaces a
native UI or automation layer should consume directly:

- `wolf doctor --json`
- `wolf scan --json`
- `wolf scan staged --json`
- `wolf scan push --json`
- `wolf push --json`
- `wolf audit list --json`
- `wolf audit verify --json`

This document defines the contract the Swift app, scripts, and future local
integrations should depend on.

## Design Rule

Prefer JSON command output over terminal scraping whenever Wolfence already
offers a structured command for the state you need.

Use direct file reads only where the source is already structured and repo-local:

- read `.wolfence/audit/decisions.jsonl` directly for a full audit timeline
- read `.wolfence/config.toml`, `.wolfence/policy/receipts.toml`,
  `.wolfence/receipts/`, and `.wolfence/trust/` directly for repo-local policy
  material
- use `wolf ... --json` for computed or aggregated state such as doctor, scan,
  push, and audit verification

## Shared Conventions

### Exit Codes

- `0`: command completed without a blocking verdict or verification failure
- non-zero: command blocked, verification failed, or command execution failed

For UI work, prefer the JSON payload's `result`, `status`, `verdict`, and
`outcome` fields over the process exit code when rendering state.

### Enums

The JSON layer uses lowercase string enums for core security concepts:

- severity: `info`, `low`, `medium`, `high`, `critical`
- confidence: `low`, `medium`, `high`
- finding category: `secret`, `vulnerability`, `dependency`, `configuration`, `policy`
- remediation kind: `rotate-secret`, `restrict-scope`, `pin-reference`, `add-integrity`, `patch-dependency`, `review-code`, `remove-artifact`, `restore-wolfence-guard`, `tighten-governance`, `investigate`
- remediation urgency: `immediate`, `before-push`
- remediation owner surface: `secrets`, `workflow`, `dependency`, `registry`, `code`, `artifact`, `governance`, `wolfence`, `container`, `infrastructure`
- verdict: `allow`, `warn`, `block`
- doctor status: `pass`, `warn`, `fail`, `info`
- protected action: `scan`, `push`

### Finding Shape

Every finding object returned under `report.findings`, `decision.blocking_findings[].finding`,
`decision.warning_findings[].finding`, and `decision.overridden_findings[].finding`
contains both a legacy free-text remediation string and normalized remediation
metadata:

```json
{
  "scanner": "secret-scanner",
  "severity": "critical",
  "confidence": "high",
  "category": "secret",
  "file": ".env",
  "line": 3,
  "title": "Inline credential detected",
  "detail": "A high-signal credential pattern was found in repository content.",
  "remediation": "Rotate the credential and remove it from repository scope.",
  "remediation_advice": {
    "kind": "rotate-secret",
    "urgency": "immediate",
    "owner_surface": "secrets",
    "primary_action": "Rotate the exposed credential and remove it from repository scope.",
    "primary_command": null,
    "docs_ref": "docs/security/detection-model.md"
  },
  "fingerprint": "...",
  "history": {
    "status": "new",
    "first_seen_unix": 1775779200,
    "last_seen_unix": 1775779200,
    "times_seen": 1
  },
  "baseline": {
    "accepted": false,
    "captured_on_unix": 1775700000
  }
}
```

`remediation` remains the backward-compatible human string. New UI and
automation consumers should prefer `remediation_advice` when grouping or
prioritizing fixes.

The `history` object is repo-local state derived from prior Wolfence runs. It
is intended to help operators prioritize newly introduced risk before recurring
known findings.

The `baseline` object is repo-local operator metadata derived from
`.wolfence/history/baseline.json`. It marks whether the finding fingerprint is
part of an accepted starting set. It does not suppress policy or override a
blocking verdict.

### Error Envelope

When a JSON-capable command fails before it can emit its normal success
payload, Wolfence returns this error envelope:

```json
{
  "command": "push",
  "status": "error",
  "error": {
    "kind": "git",
    "message": "git error: no git remote is configured for this repository"
  }
}
```

`error.kind` is one of:

- `io`
- `git`
- `cli`
- `config`

## `wolf doctor --json`

### Purpose

Returns the current repository health posture and all individual checks needed
to decide whether local Wolfence enforcement is trustworthy.

The exact check list may grow as Wolfence adds more trust-surface verification,
including optional live GitHub governance checks. Consumers should treat
`checks[].name` as descriptive output rather than hard-coding a fixed list.

### Shape

```json
{
  "command": "doctor",
  "repo_root": "/path/to/repo",
  "effective_mode": "standard",
  "mode_source": "repo-file",
  "summary": {
    "pass": 15,
    "warn": 0,
    "fail": 0,
    "info": 4
  },
  "checks": [
    {
      "name": "repo config",
      "status": "pass",
      "detail": "...",
      "remediation": null
    }
  ],
  "result": "ok"
}
```

### Result Values

- `ok`
- `failed`

The UI should render doctor as a trust surface, not as a scan result.

## `wolf scan --json` and `wolf scan staged --json`

### Purpose

Preview the staged working set under the current policy without invoking
`git push`.

### Shape

```json
{
  "command": "scan",
  "scope": "staged",
  "action": "scan",
  "repo_root": "/path/to/repo",
  "mode": "standard",
  "mode_source": "repo-file",
  "status": "ready",
  "branch": null,
  "upstream": null,
  "commits_ahead": null,
  "scanners_run": 6,
  "report": {
    "findings": [],
    "discovered_files": 0,
    "scanned_files": 0,
    "ignored_files": 0,
    "scanners_run": 6
  },
  "decision": {
    "verdict": "allow",
    "blocking_findings": [],
    "warning_findings": [],
    "overridden_findings": []
  },
  "receipts": {
    "issues": [],
    "issue_count": 0,
    "overrides_applied": 0
  },
  "scan_scope": {
    "discovered_files": 0,
    "scanned_files": 0,
    "ignored_files": 0,
    "scanned_paths": [],
    "ignored_paths": [],
    "ignore_patterns": ["docs/"]
  },
  "result": "completed"
}
```

### Result Values

- `completed`
- `blocked`

## `wolf scan push --json`

### Purpose

Preview the real outbound push scope without invoking `git push`.

### Shape

The payload shape matches staged scan, but `scope` is `push` and `action` is
`push-preview`.

The push-preview command also models no-op states directly:

```json
{
  "command": "scan",
  "scope": "push",
  "action": "push-preview",
  "repo_root": "/path/to/repo",
  "mode": null,
  "mode_source": null,
  "status": "up-to-date",
  "branch": null,
  "upstream": null,
  "commits_ahead": 0,
  "scanners_run": 0,
  "report": null,
  "decision": null,
  "receipts": {
    "issues": [],
    "issue_count": 0,
    "overrides_applied": 0
  },
  "scan_scope": null,
  "result": "no-op"
}
```

### Status Values

- `no-commits`
- `up-to-date`
- `ready`

### Result Values

- `no-op`
- `completed`
- `blocked`

## `wolf push --json`

### Purpose

Run the actual protected push path and return both the policy decision and the
final Git transport outcome.

### Shape

```json
{
  "command": "push",
  "action": "push",
  "repo_root": "/path/to/repo",
  "mode": "standard",
  "mode_source": "repo-file",
  "status": "ready",
  "branch": "main",
  "upstream": "origin/main",
  "commits_ahead": 2,
  "report": {
    "findings": [],
    "discovered_files": 35,
    "scanned_files": 25,
    "ignored_files": 10,
    "scanners_run": 6,
    "finding_history": {
      "new_findings": 1,
      "recurring_findings": 3,
      "issue": null
    },
    "finding_baseline": {
      "accepted_findings": 3,
      "unaccepted_findings": 1,
      "issue": null
    }
  },
  "decision": {
    "verdict": "allow",
    "blocking_findings": [],
    "warning_findings": [],
    "overridden_findings": []
  },
  "scan_scope": {
    "discovered_files": 35,
    "scanned_files": 25,
    "ignored_files": 10,
    "scanned_paths": ["README.md"],
    "ignored_paths": ["docs/development/doctor.md"],
    "ignore_patterns": ["docs/"]
  },
  "receipt_issues": [],
  "outcome": "push-completed",
  "git_error": null
}
```

When live GitHub governance drift exists, `report.findings` and `decision`
include a `policy.github.live-governance.drift` finding with a stable
fingerprint. When `WOLFENCE_GITHUB_GOVERNANCE=require` and verification cannot
run, the payload instead includes `policy.github.live-governance.unavailable`.
The report-level `finding_history` summary mirrors the per-finding `history`
objects so UIs can highlight newly introduced risk quickly.
The report-level `finding_baseline` summary mirrors the per-finding `baseline`
objects so UIs can prioritize newly introduced findings over accepted starting
state without weakening enforcement.

### Status Values

- `no-commits`
- `up-to-date`
- `ready`
- `completed`

### Outcome Values

- `no-op`
- `blocked`
- `allowed-dry-run`
- `policy-allowed`
- `push-failed`
- `push-completed`

Important:

- `policy-allowed` means the security gate passed, but `git push` has not yet
  completed
- `push-failed` means policy allowed the push and Git transport failed later
- `push-completed` is the only final success state for a real push

### UI Mapping Rule

The UI must keep these states distinct:

- blocked by policy
- allowed by policy but skipped because of dry-run
- allowed by policy but failed at Git transport
- fully completed push

Do not collapse them into one generic “success” or “failure” label.

## `wolf audit list --json`

### Purpose

Return both audit-chain health and the current local audit entries.

### Shape

```json
{
  "command": "audit",
  "subcommand": "list",
  "repo_root": "/path/to/repo",
  "verification": {
    "log_path": "/path/to/repo/.wolfence/audit/decisions.jsonl",
    "entries": 22,
    "healthy": true,
    "issue": null
  },
  "entries": [
    {
      "sequence": 21,
      "timestamp_unix": 1775768140,
      "source": "push-command",
      "action": "push",
      "status": "completed",
      "outcome": "push-completed",
      "detail": null,
      "verdict": "allow",
      "discovered_files": 35,
      "candidate_files": 25,
      "ignored_files": 10,
      "findings": 0,
      "warnings": 0,
      "blocks": 0,
      "overrides_applied": 0,
      "receipt_issues": 0,
      "branch": "main",
      "upstream": "origin/main",
      "commits_ahead": 2
    }
  ],
  "result": "healthy"
}
```

### Result Values

- `no-entries`
- `healthy`
- `unhealthy`

## `wolf audit verify --json`

### Purpose

Return only audit verification posture when the caller does not need every
entry.

### Shape

```json
{
  "command": "audit",
  "subcommand": "verify",
  "repo_root": "/path/to/repo",
  "verification": {
    "log_path": "/path/to/repo/.wolfence/audit/decisions.jsonl",
    "entries": 22,
    "healthy": true,
    "issue": null
  },
  "result": "verified"
}
```

### Result Values

- `verified`
- `verification-failed`

## Stability Guidance

This JSON contract is now part of the intended product surface for local
integrations.

That means:

- additive fields are acceptable
- existing field meanings should stay stable
- enum strings should not be renamed casually
- the SwiftUI app should ignore unknown fields so the CLI can grow safely
