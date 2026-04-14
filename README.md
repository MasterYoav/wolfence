![Wolfence banner](Media/banner.png)


Wolfence is a **security-first Git interface** that prevents unsafe code
from ever leaving a developer's machine.

The repository now contains two product surfaces:

- the authoritative `wolf` Rust CLI that enforces security decisions and wraps
  protected Git operations
- a native SwiftUI macOS app at the repo root that monitors multiple
  repositories, renders Wolfence evidence, and refreshes structured repo state

[![Rust](https://img.shields.io/badge/Rust-%23000000.svg?e&logo=rust&logoColor=white)](#)
[![Swift](https://img.shields.io/badge/Swift-F54A2A?logo=swift&logoColor=white)](#)


------------------------------------------------------------------------

Modern developers move fast --- sometimes too fast.

Sensitive data, insecure patterns, vulnerable dependencies, and
misconfigurations often slip into repositories unnoticed.

**Wolfence changes that.**

> Wolfence stands between your code and the world --- and decides if
> it's safe to pass.
> It does not try to replace your whole Git workflow.

You write code normally.\
You commit normally.\
Then `wolf push` decides whether the outbound code is safe enough to leave the
machine.

Before any code is pushed, Wolfence:

1.  Analyzes your changes\
2.  Runs deep security scans\
3.  Detects vulnerabilities\
4.  Blocks unsafe code\
5.  Explains issues\
6.  Allows safe code automatically

------------------------------------------------------------------------

## Core Concept

Traditional flow:

git push → code goes to repo → problems discovered later

Wolfence flow:

wolf push → scan → (block OR allow) → push

------------------------------------------------------------------------

## Protection Layers

### Secrets

API keys, tokens, private keys, .env leaks

### Vulnerabilities

command injection, SSRF, path traversal, unsafe deserialization, XSS, unsafe eval

### Dependencies

CVEs, lockfile drift, risky registries, direct package sources

### Config

Docker, CI/CD, Terraform, permissions

### Policies

Custom org rules

------------------------------------------------------------------------

## Features

-   Fast (scan only changed code)
-   Blocks unsafe pushes
-   Clear explanations
-   Git integration
-   Extensible engine
-   High-signal appsec checks for command execution, SSRF, path traversal, unsafe deserialization, and remote script execution
-   Artifact inspection for packaged archives, compiled binaries, and suspicious minified bundles
-   Dependency provenance checks across Cargo, npm, pnpm, Yarn, Go modules, Bundler, Poetry, uv, Pipenv, and pinned Python requirements, including tracked registry posture, repo-local internal package ownership hints, owner-host mismatch detection in supported changed lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `Gemfile.lock`, `gems.locked`, `poetry.lock`, `uv.lock`, `Pipfile.lock`), and direct-source checks in manifests plus Python lockfiles that catch declared internal packages bypassing normal registry or index flow through Git, archive, file, path, or editable-style sources
-   Self-protection, governance, and release-integrity checks for `.wolfence` authority changes, hook drift, `CODEOWNERS` coverage, repo-admin settings, rulesets, and risky GitHub Actions publish paths
-   IaC posture checks for Terraform/OpenTofu public storage, wildcard IAM, public admin ingress, and Kubernetes RBAC or pod-hardening risks
-   Optional live GitHub governance verification in `doctor` and protected push using `gh api` and repo-as-code intent
-   Repo-local finding history so CLI, JSON, and the macOS app can distinguish new risk from recurring findings by fingerprint
-   Repo-local accepted finding baselines so teams can mark a starting state without weakening push policy
-   Native macOS monitoring workspace for local repositories

------------------------------------------------------------------------

## Architecture

Protected path:

`wolf CLI → Orchestrator → Scanners → Policy → Decision → Git`

Operator console:

`macOS app → .wolfence files + wolf --json surfaces → native workspace UI`

------------------------------------------------------------------------

## Implementation Direction

Wolfence is now implemented as a **local-first Rust security engine** with a
**native SwiftUI macOS console**.

Why:

- one trusted binary
- deterministic local enforcement
- strong performance for scans
- good fit for a security-sensitive developer tool
- a native local console can observe the gate without moving trust decisions
  out of the Rust core

The Rust binary remains authoritative for every security judgment. The macOS
app is an operator console that reads repo-local evidence and machine-readable
Wolfence output instead of reimplementing policy.

Core docs:

- `docs/architecture/overview.md`
- `docs/architecture/decision-records/0001-modular-monolith.md`
- `docs/security/threat-model.md`
- `docs/security/detection-model.md`
- `docs/security/scanner-inventory.md`
- `docs/security/scanner-inventory.json`
- `docs/security/safety-check-roadmap.md`
- `docs/security/policy-model.md`
- `docs/security/override-receipts.md`
- `docs/security/receipt-approval-policy.md`
- `docs/security/live-advisories.md`
- `docs/security/audit-chain.md`
- `docs/security/trust-store.md`
- `docs/development/audit.md`
- `docs/development/doctor.md`
- `docs/development/json-output.md`
- `docs/development/prototype-demo.md`
- `docs/ui/macos-console.md`
- `docs/ui/swiftui-xcode-handoff.md`
- `docs/repo-map.md`

------------------------------------------------------------------------

## Commands

wolf init\
wolf push\
wolf push --json\
wolf scan\
wolf scan --json\
wolf scan push\
wolf scan push --json\
wolf baseline capture [push|staged]\
wolf baseline show\
wolf baseline clear\
wolf doctor\
wolf doctor --json\
wolf config\
wolf audit list\
wolf audit list --json\
wolf audit verify\
wolf audit verify --json\
wolf trust list\
wolf trust verify <key-id>\
wolf trust init <key-id> <owner> <expires-on> [categories]\
wolf trust archive <key-id> <reason>\
wolf trust restore <key-id>\
wolf receipt list\
wolf receipt new <receipt-path> <action> <category> <fingerprint> <owner> <expires-on> <reason>\
wolf receipt checksum <receipt-path>\
wolf receipt verify <receipt-path>\
wolf receipt archive <receipt-path> <reason>\
wolf receipt sign <receipt-path> <approver> <key-id> <private-key-path>

------------------------------------------------------------------------

## 📦 Install

Build and install the local binary:

```bash
cargo install --path . --force
```

Then the tool is available directly as:

```bash
wolf push
```

During development, `cargo run -- push` still works, but the intended product
surface is `wolf ...`.

For UI work and automation, prefer the documented machine-readable surfaces in:

`docs/development/json-output.md`

For native app work, the root-level Xcode project is:

`Wolfence.xcodeproj`

------------------------------------------------------------------------

## 🧪 Modes

Advisory / Standard / Strict

------------------------------------------------------------------------

## Configuration

Wolfence now uses a repo-local config file at:

` .wolfence/config.toml `

Current precedence:

1. `WOLFENCE_MODE`
2. repo config
3. built-in default (`standard`)

Initialize it with:

`wolf init`

Inspect the resolved config with:

`wolf config`

Try the current local prototype end to end with:

`docs/development/prototype-demo.md`

------------------------------------------------------------------------

## MVP

-   wolf push
-   secret scanning
-   basic SAST
-   dependency scan
-   git hooks

Current `wolf push` behavior:

- scans the outbound push candidate set, not just staged files
- if an upstream exists, compares `upstream..HEAD`
- if no upstream exists yet, treats the current `HEAD` snapshot as the initial push payload
- only runs `git push` after policy evaluation allows the action
- initial protected pushes prefer `origin`, then fall back to the first configured remote
- use `WOLFENCE_DRY_RUN=1` to test the decision path without executing the final push
- `wolf init` installs a managed `pre-push` hook for native `git push`
- `wolf doctor` audits whether local enforcement is actually trustworthy
- repo-local override receipts can suppress specific findings only when they are explicit, unexpired, and integrity-valid
- protected push decisions are written to a chained local audit log under `.wolfence/audit/`
- the audit log now distinguishes policy allowance from real `git push` completion and records push transport failures explicitly
- `wolf doctor --json`, `wolf scan --json`, `wolf push --json`, and `wolf audit ... --json` expose stable machine-readable envelopes for native UI and local automation

Current detection strengths:

- layered secret detection for sensitive file paths, private keys, known token families, high-entropy secret assignments, escaped key blobs, and embedded connection-string secrets
- dependency intelligence for direct Git/URL sources, insecure transport, wildcard versions, lockfile integrity posture, and manifest/lockfile drift
- GitHub Actions hardening checks for dangerous triggers, mutable third-party and reusable workflows, self-hosted PR runners, artifact execution chains, dispatch/release ref misuse, unsafe command settings, attestation-permission gaps, and mutable tag minting
- Docker build hardening checks for mutable or non-digest-pinned base images
- optional OSV-backed live advisory checks for exact dependency versions during protected pushes

Current policy strengths:

- deterministic sorting and deduplication of findings before policy evaluation
- severity, confidence, and category-aware decisions instead of severity alone
- stronger standard-mode blocking for medium high-confidence non-vulnerability findings
- explicit standard-mode blocking for declared internal package ownership drift and direct-source bypasses, even when they would otherwise look like lower-severity dependency posture issues
- strict-mode blocking for low high-confidence non-vulnerability findings that still weaken provenance or policy posture
- rich blocked-push explanations with location, remediation, and policy rationale
- reviewable override receipts with owner, reason, expiry, and integrity checks
- repo-local trust material that upgrades receipts from checksum-only to signed exceptions
- category-scoped trust keys so one signer does not automatically gain approval power across every receipt type
- archived trust keys so signer retirement removes live trust influence without deleting reviewable evidence
- `trust verify` now distinguishes live keys from archived keys instead of treating retired trust material as absent
- `trust restore` can recover the latest archived signer back into live trust while recording the restoration in archive history
- first-class receipt creation, checksum, and signing commands so exception material is generated canonically
- receipt ids and reviewer metadata so exception ownership is visible in the CLI
- repo-local receipt approval policy with reviewer/approver allowlists and lifetime bounds
- explicit live advisory modes: `off`, `auto`, and `require`
- tamper-evident local audit entries for protected push decisions

------------------------------------------------------------------------

## Roadmap

-   Document the product plan for the macOS console so the desktop app grows
    without stealing authority from the Rust gate\
-   Expand Wolfence into a comprehensive pre-push safety-check engine across
    secrets, appsec, dependency risk, CI, IaC, policy, and provenance\
-   Cloud dashboard\
-   AI analysis\
-   VSCode extension\
-   GitHub integration

------------------------------------------------------------------------

## Philosophy

Every push must survive the wolf.

------------------------------------------------------------------------

## 📜 License

MIT
`wolf scan` previews the staged set under current policy, and `wolf scan push`
previews the real outbound push scope. Both return a failing exit code when the
current policy would block, without invoking `git push`.
