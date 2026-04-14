# Doctor Command

## Purpose

`wolf doctor` exists to answer one operational question:

Is this repository actually protected the way the operator thinks it is?

Scanning alone is not enough. A local gate can still fail operationally if:

- the repo policy file is missing
- the policy file cannot be committed
- repo trust material cannot be committed
- override receipts are malformed, expired, or ignored
- signed receipts are required but cannot be verified
- live advisory lookups are disabled or unsupported unexpectedly
- live GitHub governance verification is disabled, unavailable, or drifting from repo-as-code intent unexpectedly
- the shell is overriding the configured mode
- dry-run mode is still enabled
- the managed hook is missing
- the hook is present but cannot execute
- the local audit chain is corrupted

The doctor command audits those conditions directly.

Wolfence also supports:

```bash
wolf doctor --json
```

Use the text output for direct terminal review.

Use `--json` for the native app or other local integrations. The payload
contract is documented in `docs/development/json-output.md`.

## Current Checks

### Repo config

Checks whether `.wolfence/config.toml` exists and resolves cleanly.

### Config trackability

Checks whether `.wolfence/config.toml` would be ignored by Git. If it is
ignored, repository policy cannot be shared or reviewed properly.

### Receipt trackability

Checks whether `.wolfence/receipts/*.toml` would be ignored by Git. If they
are, exceptions can still exist locally but they stop being reviewable.

### Trust trackability

Checks whether `.wolfence/trust/*.pem` would be ignored by Git. If trust
material is not trackable, signed receipt verification can still happen
locally, but the repository trust model stops being reviewable.

### Trust metadata

Checks whether published trust keys have companion metadata files and whether
any trusted keys are expired and therefore inactive.

If the repo publishes only expired keys, doctor fails because signed receipts
may still be required while no active verification key remains.

Keys with missing or incomplete metadata are also treated as inactive.

Doctor also warns when active trust keys do not declare category scope. Those
keys still work, but they are effectively repo-wide signers rather than
least-privilege signers.

### Policy posture

Explains whether the effective mode is advisory, standard, or strict, and what
that means for enforcement.

### Scan exclusions

Checks whether repo-local scan exclusions are configured and whether they cover
higher-risk paths.

- no exclusions: informational only
- narrow exclusions such as `docs/` or fixture trees: pass with remediation guidance
- exclusions covering source, CI, manifest, lockfile, or Wolfence policy paths: warning

### Environment overrides

Warns when:

- `WOLFENCE_MODE` is overriding repo policy
- `WOLFENCE_DRY_RUN` is changing push behavior
- `WOLFENCE_OSV` is changing live advisory behavior
- `WOLFENCE_GITHUB_GOVERNANCE` is changing live GitHub governance verification behavior

These are useful development tools, but they should never be invisible.

### Wolf runtime

Checks whether the running `wolf` executable resolves to a stable binary path.
Managed hooks now pin that binary directly and only fall back to Cargo when the
binary cannot be found.

### Git identity

Checks whether effective Git `user.name` and `user.email` are configured for
the current repository context.

This is not a security control, but it is operationally important for trying
the prototype because the demo path requires real commits.

### Curl runtime

Checks whether `curl` is available because the current OSV integration uses it
for bounded live advisory queries.

### GitHub CLI runtime

Checks whether `gh` is available because the current live GitHub governance
verification uses GitHub CLI authentication and `gh api`.

### OpenSSL runtime

Checks whether `openssl` is available because the current signed-receipt model
uses it for detached signature verification.

If the repository has trusted receipt keys, missing `openssl` is a blocking
failure instead of a warning because signed overrides cannot be verified.

### Pre-push hook

Checks whether the repo has:

- no `pre-push` hook
- an unmanaged `pre-push` hook
- a managed Wolfence `pre-push` hook that is executable
- which launcher model the managed hook uses

This is how Wolfence stays honest about native `git push`. If the hook is
missing or unmanaged, native pushes are not reliably guarded.

### Audit log

Checks whether `.wolfence/audit/decisions.jsonl` is either absent because no
protected pushes have run yet, or present with an intact chained hash history.

### Override receipts

Checks whether active override receipts exist and whether any receipts were
ignored because they are malformed, expired, duplicated, fail integrity
validation, or fail signed-receipt validation.

### Push window

Reports whether:

- the branch has no commits
- the branch is up to date
- the branch is ahead and how many candidate files are in scope
- the current outbound push window includes files that repo-local exclusions would ignore

This is informational context for the current repository state.

### Live GitHub governance

When `WOLFENCE_GITHUB_GOVERNANCE` is `auto` or `require`, doctor also compares
local repo-as-code governance intent against live GitHub state.

Current scope includes:

- protected-branch posture inferred from `.github/settings.yml` or
  `.github/repository.yml`, across locally declared governed branches and the
  default branch fallback
- live ruleset presence and active enforcement compared with local
  `.github/rulesets/*`
- drift such as live force-push allowance, disabled admin enforcement, missing
  code-owner review, too-few approvals, or missing active rulesets

If the repository is not hosted on GitHub, or if no local governance intent is
present, this check becomes informational instead of warning or failure.

## Exit Behavior

`wolf doctor` exits non-zero only when it finds blocking environment
failures, such as:

- a managed hook that is not executable
- a repo config file that exists but is ignored by Git
- a missing or invalid Wolf runtime for the current managed-hook model
- a repository with trusted receipt keys but no working OpenSSL runtime
- a repository that publishes only expired trust keys
- a repository that requires signed receipts but has no active trusted keys
- required live GitHub governance verification that cannot run

Warnings do not fail the command, but they should not be ignored.

## Why This Matters

A security product loses trust when the UI says "protected" but the operator's
actual workflow bypasses the control. `wolf doctor` is the current local
reality check for that problem.
