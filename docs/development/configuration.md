# Configuration

## Current Model

Wolfence now supports a repo-local configuration file at:

```text
.wolfence/config.toml
```

The current format is intentionally small. That is a feature, not a limitation.
Security tooling becomes dangerous when configuration grows faster than the
policy engine behind it.

## Current Keys

### `[policy]`

Policy-related settings for this repository.

### `[scan]`

Scanner scope controls for this repository.

### `[dependency]`

Dependency provenance ownership hints for this repository.

### `mode`

Supported values:

- `advisory`
- `standard`
- `strict`

Behavior:

- `advisory`: never block, but still warn on medium-and-above findings and other high-confidence non-vulnerability signals
- `standard`: block high and critical findings, and also block medium high-confidence non-vulnerability findings
- `strict`: block medium-and-above findings, and also block low high-confidence non-vulnerability findings

### `ignore_paths`

Repository-relative paths or path prefixes to exclude from scanning.

Supported shapes:

- `docs/`
- `fixtures/**`
- `README.md`

Invalid shapes are rejected during config loading. In particular, Wolfence does
not allow root-wide or ambiguous patterns such as `.`, `./`, `/`, `*`, `**`,
absolute paths, parent-directory traversal, or unsupported wildcard forms like
`docs/*`.

Use this sparingly. It is intended for documentation examples, generated
artifacts, or known fixture trees that would otherwise create non-production
noise.

When exclusions are active, `wolf scan`, `wolf push`, and the managed
`pre-push` hook print both the discovered candidate-file count and the ignored
count so the reduced scan surface is explicit at runtime.
`wolf doctor` also warns if exclusions cover higher-risk paths such as
`src/`, `.github/`, lockfiles, manifests, or Wolfence policy directories.

### `node_internal_packages`

Unscoped internal Node package names that are expected to resolve through the
repository's private registry configuration.

Use this only when the repository intentionally mixes custom registry config
with unscoped internal package names. Wolfence uses this list to suppress the
dependency-confusion posture finding for those specific names.

Example:

```toml
[dependency]
node_internal_packages = ["internal-sdk", "platform-core"]
```

### `node_internal_package_prefixes`

Package-name prefixes that are expected to belong to internal unscoped Node
packages resolved through the repository's private registry configuration.

Use this when internal packages follow a stable naming convention and a flat
per-package allowlist would be too brittle.

Example:

```toml
[dependency]
node_internal_package_prefixes = ["platform-", "corp-"]
```

### `node_registry_ownership`

Owner-host rules for internal Node packages.

Each entry uses one of these forms:

- `packages.example.com=internal-sdk`
- `packages.example.com=platform-*`

Use this when you want Wolfence to verify that a declared internal package or
package prefix actually maps to the expected tracked private registry host,
both in tracked registry config, in supported changed lockfiles
(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, and
`yarn.lock`), and in direct remote `package.json` dependency specs, instead of
only suppressing ambiguity heuristics.

### `ruby_source_ownership`

Owner-host rules for internal Ruby gems.

Each entry uses one of these forms:

- `gems.example.com=internal-sdk`
- `gems.example.com=corp-*`

Use this when you want Wolfence to verify that internal gems are backed by the
expected Ruby source host, both in direct-source `Gemfile` or `gems.rb`
entries and in Bundler lockfiles (`Gemfile.lock` or `gems.locked`).

### `python_internal_packages`

Internal Python package names that are expected to resolve through custom
package indexes declared in tracked requirements files.

Use this only for private package names the repository explicitly owns.
Wolfence uses this list to suppress the dependency-confusion posture finding
for those specific names.

Example:

```toml
[dependency]
python_internal_packages = ["internal-sdk", "corp-utils"]
```

### `python_internal_package_prefixes`

Package-name prefixes that are expected to belong to internal Python packages
resolved through custom package indexes declared in tracked requirements files.

Use this when internal Python packages share an organizational naming prefix.

Example:

```toml
[dependency]
python_internal_package_prefixes = ["corp-", "internal-"]
```

### `python_index_ownership`

Owner-host rules for internal Python packages.

Each entry uses one of these forms:

- `packages.example.com=internal-sdk`
- `packages.example.com=corp-*`

Use this when you want Wolfence to verify that internal Python packages are
backed by the expected tracked package-index host, both in tracked package
index config, in supported changed lockfiles (`poetry.lock`, `uv.lock`, and
`Pipfile.lock` when index sources are available), and in direct remote
`pyproject.toml`, `Pipfile`, or `requirements*.txt` dependency references.

## Precedence

The effective mode is resolved in this order:

1. `WOLFENCE_MODE`
2. `.wolfence/config.toml`
3. built-in default of `standard`

## Development Overrides

### `WOLFENCE_MODE`

Temporarily override the effective policy mode without editing repo config.

### `WOLFENCE_DRY_RUN`

When set to `1`, `true`, or `yes`, `wolf push` still evaluates the real
push candidate set and policy decision, but skips the final `git push`
execution. This is useful while developing Wolfence itself.

### `WOLFENCE_OSV`

Controls live OSV advisory lookups for exact dependency versions during
protected pushes.

Supported values:

- `off`: disable live advisory lookups
- `auto`: try live advisory lookups, but do not fail the push if OSV or network access is unavailable
- `require`: treat live advisory availability as part of the protected push path and emit a finding if the lookup cannot run

### `WOLFENCE_GITHUB_GOVERNANCE`

Controls optional live GitHub governance verification during `wolf doctor` and
protected push.

Supported values:

- `off`: disable live GitHub governance verification
- `auto`: try the live verification with `gh api`; `doctor` stays best-effort on availability, but protected push still blocks if live GitHub state drifts from repo-as-code governance intent
- `require`: treat live verification availability as part of both doctor's trust posture and the protected push path, so verification failures become blocking

This verification compares repo-as-code governance intent from local files such
as `.github/settings.yml`, `.github/repository.yml`, and `.github/rulesets/*`
against live GitHub state across locally declared governed branches, with the
repository default branch used as a fallback when no explicit branch list is
present in repo-admin settings.

When protected push blocks on live GitHub governance drift, Wolfence emits a
stable `policy` finding fingerprint. That means the only bypass path is an
explicit override receipt for that exact live drift state.

## Initialization

Create the baseline config with:

```bash
cargo run -- init
```

Then inspect the effective resolved config with:

```bash
cargo run -- config
```

That output now includes the effective `scan ignore paths`,
`dependency node internal packages`, `dependency node internal package prefixes`,
`dependency node registry ownership rules`, `dependency python internal packages`,
`dependency python internal package prefixes`, and `dependency python index ownership rules`
so repo-local ownership hints stay visible during review.

Audit the local enforcement posture with:

```bash
cargo run -- doctor
```

Canonical receipt maintenance is also available from the CLI:

```bash
cargo run -- receipt list
cargo run -- receipt new .wolfence/receipts/allow.toml push secret secret:abc123 yoav 2026-04-16 "Temporary exception"
cargo run -- receipt checksum .wolfence/receipts/allow.toml
cargo run -- receipt verify .wolfence/receipts/allow.toml
cargo run -- receipt sign .wolfence/receipts/allow.toml security-team security-team /path/to/security-team-private.pem
```

`wolf init` also installs a managed `pre-push` Git hook. That hook pins the
current Wolf executable directly, falls back to `wolf` on `PATH`, and only uses
`cargo run --quiet --bin wolf -- ...` as a development fallback.

Wolfence also reserves this directory for reviewable exception receipts:

```text
.wolfence/receipts/*.toml
```

Archived exception material can be retained under:

```text
.wolfence/receipts/archive/*.toml
```

These receipts are not global bypasses. They are scoped to specific finding
fingerprints and are only honored when they are still valid.

Receipt governance can also be made explicit through:

```text
.wolfence/policy/receipts.toml
```

That file currently supports:

- `require_explicit_category`
- `require_signed_receipts`
- `max_lifetime_days`
- `require_reviewer_metadata`
- `allowed_reviewers`
- `allowed_approvers`
- `allowed_key_ids`

It also supports category-specific sections such as:

```toml
[categories.secret]
require_signed_receipts = true
require_reviewer_metadata = true
allowed_reviewers = ["security-team"]
allowed_approvers = ["security-team"]
allowed_key_ids = ["security-team"]
```

Wolfence also reserves this directory for trusted public keys used to verify
signed override receipts:

```text
.wolfence/trust/*.pem
.wolfence/trust/*.toml
.wolfence/trust/archive/*.pem
.wolfence/trust/archive/*.toml
```

When that directory contains at least one trusted key, signed receipts become
mandatory for this repository.

Active trust keys currently require:

- a committed `.pem` file
- companion metadata with `owner`
- companion metadata with `expires_on`

Trust metadata can also optionally declare:

- `categories = ["secret", "policy"]`

If categories are present, the key may only sign receipts for those finding
categories. If categories are omitted, the key stays active but unrestricted,
and `doctor` warns because that is broader authority than most repositories
should want.

Retired trust keys should be moved into `.wolfence/trust/archive/` instead of
left in the live trust directory. That keeps the retirement evidence
reviewable without letting stale trust material continue to flip signed-receipt
posture.

Wolfence also writes a local chained audit log to:

```text
.wolfence/audit/decisions.jsonl
```

This log is local operational evidence by default, not a committed repo
artifact.

`cargo run -- doctor` checks:

- whether repo config exists
- whether `.wolfence/config.toml` is trackable by Git
- whether `.wolfence/policy/receipts.toml` exists and is trackable by Git
- whether `.wolfence/trust/*.pem` is trackable by Git
- how many active trust keys are category-scoped versus unrestricted
- whether the current mode is actually enforcing
- whether live GitHub governance verification is enabled and whether GitHub CLI is available
- whether repo-as-code governance intent matches live GitHub branch protection and rulesets when that verification is enabled
- whether shell overrides are changing behavior
- whether live OSV advisories are enabled and whether `curl` is available
- whether `openssl` is available for signed receipt verification
- whether Cargo is available for the managed hook
- whether the managed `pre-push` hook is present and executable
- whether the local audit chain is healthy
- whether override receipts are trackable and valid
- what the current outbound push window looks like

## Example

```toml
[policy]
mode = "standard"

[scan]
ignore_paths = ["docs/examples/", "fixtures/**"]
```
