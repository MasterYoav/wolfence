# Scanner Inventory

## Purpose

This document is the current-state inventory for Wolfence's built-in safety
checks.

It exists to answer three questions clearly:

1. what is actually shipped today
2. what is only partially covered today
3. what is still outside the gate

`docs/security/detection-model.md` explains how the detection model works.

This document is narrower. It is the operational inventory and coverage matrix
for the current scanner set.

For tooling that should not scrape Markdown, the same inventory is mirrored in
machine-readable form at `docs/security/scanner-inventory.json`.

## Status Legend

- `Shipped`: implemented, tested, and part of the current default scanner set
- `Partial`: implemented in meaningful slices, but still missing major expected
  surfaces inside that family
- `Planned`: intentionally on the roadmap, but not yet implemented in the
  current scanner set

## Scanner Modules

| Scanner | Rust Surface | Purpose | Current State |
| --- | --- | --- | --- |
| `secret-scanner` | `src/core/scanners.rs` | credential, token, key, and embedded secret detection | `Shipped` |
| `basic-sast` | `src/core/scanners.rs` | high-signal appsec heuristics for obviously dangerous execution or parsing paths | `Partial` |
| `artifact-scanner` | `src/core/scanners.rs` | opaque archive, binary, and suspicious generated bundle inspection | `Partial` |
| `dependency-scanner` | `src/core/scanners.rs` and `src/core/osv.rs` | manifest, lockfile, provenance, and live advisory checks | `Partial` |
| `config-scanner` | `src/core/scanners.rs` | CI, Docker, Kubernetes, infrastructure exposure, and release-attestation posture checks | `Partial` |
| `policy-scanner` | `src/core/scanners.rs` | Wolfence local policy, trust, override authority, and hook-integrity checks | `Partial` |

## Coverage Matrix

| Detection Family | Status | Current Shipped Coverage | Explicit Current Gaps |
| --- | --- | --- | --- |
| Secrets and credential exposure | `Shipped` | sensitive file paths, prefixed service tokens, private-key material, suspicious secret assignments, inline auth headers, cookie and session secrets, registry auth files, webhook URLs, connection-string secrets | more cloud and SaaS token families, structured secret parsing beyond line heuristics, decoded or transformed secret representations |
| Dependency and supply-chain risk | `Partial` | Cargo, npm, pnpm, Yarn, Go modules, Bundler, Poetry, uv, Pipenv, and pinned Python requirements; lockfile relationship checks; direct source detection; tracked package-manager registry config posture; custom index posture; dependency-confusion posture for custom registries and unqualified package names; repo-local Node and Python internal package exact-name and prefix allowlists in `.wolfence/config.toml`; owner-host mismatch detection from `node_registry_ownership`, `ruby_source_ownership`, and `python_index_ownership` across tracked config, changed lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `Gemfile.lock`, `gems.locked`, `poetry.lock`, `uv.lock`, `Pipfile.lock`), and explicit direct-source manifest entries in `package.json`, `Gemfile`, `gems.rb`, `pyproject.toml`, `Pipfile`, and `requirements*.txt`; direct-source bypass detection when declared internal packages use Git, archive, file, path, or editable-style sources instead of normal registry or index flow, including in `uv.lock`, `poetry.lock`, and `Pipfile.lock`; OSV exact-version querying on supported files | broader ecosystems, full structural parsing for every supported format, transitive graph resolution, per-package registry semantics beyond current host-and-pattern policy, maintainer or reputation signals |
| CI, IaC, and deployment configuration | `Partial` | GitHub Actions hardening, branch-push publish detection, GitHub Release, Goreleaser, and semantic-release action publication detection, long-lived GitHub release credential detection, attestation-permission checks, trusted-publishing permission checks, keyless-signing permission checks, long-lived registry-credential publish detection, OCI long-lived registry-credential detection, long-lived signing-credential detection, OCI publish provenance checks for `docker/build-push-action`, mutable release-ref detection, branch workflows that mint tags, Docker base-image pinning, Docker final-stage explicit root-user detection, Docker remote-installer pipe detection, Docker remote download-and-execute detection, Docker remote `ADD` source detection, Kubernetes Secret inline data, Kubernetes RBAC wildcard and cluster-admin binding checks, Kubernetes pod-hardening checks (`privileged`, privilege escalation, host namespaces, `hostPath`, root posture), Kubernetes ingress HTTPS-redirect disablement detection, Kubernetes sensitive ingress-path exposure checks, Kubernetes Pod Security privileged-enforcement detection, Kubernetes admission webhook fail-open detection, Terraform and OpenTofu public-storage checks, Terraform and OpenTofu remote-state encryption-disablement detection, Terraform and OpenTofu insecure HTTP backend detection, Terraform and OpenTofu secret-bearing output sensitivity-disablement detection, Terraform and OpenTofu secret-bearing variable sensitivity-disablement detection, Terraform and OpenTofu inline literal secret-attribute detection, wildcard IAM principal and wildcard-permission checks, public admin-ingress checks, public sensitive-service ingress checks, public all-ports ingress checks, and broad exposure needles like `0.0.0.0/0` | broader cloud-provider coverage, deeper Terraform and OpenTofu structural parsing, cloud IAM and storage misconfiguration checks beyond current line-level signals, broader ecosystem-specific trusted-publishing and release-signing posture checks |
| Application security signals | `Partial` | remote script execution, dynamic execution sinks, request-driven command execution, SSRF-style outbound fetches, cloud metadata access, request-driven path sinks, unsafe deserialization primitives, string-built SQL query detection with untrusted input, insecure secret and token randomness detection, unsafe crypto primitive and mode detection, request-driven uploaded-file write detection, request-driven archive extraction detection, request-driven privilege assignment detection, privileged-surface access-control bypass marker detection | broader language-aware taint tracking |
| Repository governance and release safety | `Partial` | repo-local config presence, release workflow trust checks, external hooks-path review, external hook-symlink review, external hook-helper review, legacy managed-hook launcher detection, missing or malformed `CODEOWNERS`, duplicate `CODEOWNERS` files, uncovered governance-sensitive paths such as workflows and `.wolfence/*`, and semantic checks for repo-admin settings and rulesets including required signed-commit, linear-history, conversation-resolution, and status-check governance | live branch protection posture, broader hook tamper detection beyond current launcher, path, external-symlink, and helper-indirection signals, broader release signing and provenance validation, deeper ownership semantics than current local `CODEOWNERS` matching |
| Binary and artifact inspection | `Partial` | artifact download plus execute detection in GitHub Actions, packaged archive detection, zip-like archive entry traversal detection, zip-like archive embedded executable detection, compiled binary detection, suspicious minified remote-loader bundle detection, minified bundle beaconing detection, source map artifact detection, generated-asset embedded secret detection, new executable text launcher provenance detection | deeper archive contents inspection beyond current zip-like entry-name checks |
| Wolfence self-protection | `Partial` | scanner-bundle surface change detection, scanner-bundle changes without local rule-provenance updates, repo-local config change detection, advisory-mode downgrade detection, sensitive ignore-path detection, receipt-policy change detection, trust-store change detection, override-receipt change detection, external hooks-path review, external hook-symlink detection, external hook-helper detection, repo-local alternate hooks-path detection, additional unmanaged executable hook detection, managed-hook launcher drift detection, native pre-push transport validation against the evaluated current-branch snapshot, and push-snapshot revalidation elsewhere in the product | broader unmanaged hook replacement detection beyond current alternate-path, external-symlink, helper-indirection, and additional-hook checks, signed or external rule-distribution provenance beyond current repo-local inventory coupling, broader time-of-check to time-of-push coverage beyond the current native branch-push guard and `wolf push` snapshot revalidation |

## Current File-Format Coverage

### Dependency manifests, lockfiles, and registry config

Current shipped dependency coverage recognizes these sources directly:

- `Cargo.toml`
- `Cargo.lock`
- `.cargo/config`
- `.cargo/config.toml`
- `package.json`
- `.npmrc`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `.yarnrc.yml`
- `.yarnrc.yaml`
- `go.mod`
- `go.sum`
- `Gemfile`
- `Gemfile.lock`
- `gems.rb`
- `gems.locked`
- `pyproject.toml`
- `poetry.lock`
- `uv.lock`
- `Pipfile`
- `Pipfile.lock`
- `requirements*.txt`

### CI and infrastructure files

Current shipped config coverage directly recognizes these surfaces:

- `.github/workflows/*`
- `Dockerfile`
- Kubernetes YAML or JSON content that defines Secrets, RBAC resources, bindings, or pod runtime security fields
- Terraform and OpenTofu `.tf` files through current IAM, public-storage, and network-posture checks

### Code-oriented appsec surfaces

Current shipped appsec heuristics are primarily aimed at:

- JavaScript and TypeScript
- Python
- Java and JVM-adjacent build files
- PHP
- Ruby
- Go
- C#
- shell and PowerShell execution surfaces

This is file-type-aware heuristic coverage, not full semantic analysis.

## Measurement Rules

A coverage family should only move from `Partial` to `Shipped` when all of the
following are true:

- the rule family has a clear documented scope
- the default-on checks are implemented
- targeted tests exist for the main positive paths
- at least one safe or benign case is covered where false positives are likely
- the current limits are written down explicitly

If any of those are missing, the family stays `Partial`.

## Update Discipline

When a new rule family or file format is added:

1. update `src/core/scanners.rs` and tests first
2. update `docs/security/detection-model.md`
3. update this inventory
4. update `docs/security/safety-check-roadmap.md` if the roadmap status changed

That keeps product claims tied to implemented coverage instead of intent.
