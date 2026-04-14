# Safety Check Roadmap

## Goal

Wolfence should aim to become the strongest possible pre-push local safety gate.

The current implemented coverage inventory lives in
`docs/security/scanner-inventory.md`.

That does not mean claiming "100% safety". No local scanner can guarantee that
every pushed change is safe once it reaches GitHub or any other remote. The
defensible goal is:

- maximize pre-push coverage for meaningful security failure modes
- block high-confidence incidents by default
- make residual risk explicit instead of pretending it does not exist
- keep the gate explainable, deterministic, and hard to bypass

## Product Promise

A stronger Wolfence promise is:

`Every push is evaluated against a broad, explicit, reviewable set of safety checks before code leaves the machine.`

That is defensible.

`100% safe code reaches GitHub`

is not defensible and should not be a product claim.

## Current Strengths

Wolfence is already materially useful in these areas:

- secret and credential leakage detection
- structured config-secret detection such as escaped private keys and embedded connection-string credentials
- dependency provenance and lockfile posture across Cargo, npm, pnpm, Yarn, Poetry, uv, Pipenv, and pinned Python requirements
- repo-local policy and override governance
- initial repository-governance coverage for `CODEOWNERS` presence, validity, sensitive-path ownership, and repo-admin ruleset posture
- selected high-signal GitHub Actions, CI, and infrastructure risk checks
- initial local artifact inspection for packaged archives, compiled binaries, and suspicious minified bundles
- initial Wolfence self-protection checks for `.wolfence` authority changes, hook drift, and risky GitHub Actions release paths
- local health checks for bypass-prone enforcement paths

## Coverage Model

To be "best in class", Wolfence needs broad coverage across seven detection
families.

## 1. Secrets And Credential Exposure

This category should remain the most aggressively blocked path.

Current coverage already includes many token families, sensitive paths, inline
credentials, and key material.

Priority expansions:

- more cloud-provider credentials and account identifiers
- database credentials and DSN patterns
- signing keys, certificates, and mobile keystore material
- GitHub App, GitHub Actions, npm, PyPI, Docker, and package-registry auth variants
- bearer tokens in test fixtures, snapshots, and generated client code
- base64-decoded and escaped secret representations
- secret detectors for structured formats beyond line-oriented heuristics

## 2. Application Security Signals

Wolfence currently has lightweight SAST.

To become a serious gate, it should expand into high-signal checks for:

- command injection
- path traversal
- SSRF
- unsafe deserialization
- template injection

Rule quality matters more than raw rule count. The target is explainable,
language-aware blocking signals, not a giant pile of noisy regexes.

## 3. Dependency And Supply-Chain Risk

This is one of the most important long-term categories.

Priority expansions:

- broader ecosystem coverage beyond the current Cargo, Node, and Python focus
- structural parsers for more manifest and lockfile formats
- exact-version advisory checks across more ecosystems
- dependency confusion and private-registry posture checks
- provenance checks for Git dependencies, direct URLs, and archive downloads
- maintainer-risk and package-reputation signals treated as warnings first
- build-integrity posture such as pinned actions, pinned container digests, and checksum verification

## 4. CI, IaC, And Deployment Configuration

Unsafe automation reaches production fast. This category should become much
deeper.

Recently shipped slices:

- GitHub Actions trust-boundary and release-integrity checks
- Docker base-image pinning checks
- Docker final-stage root-user detection, remote-installer pipe checks, remote download-and-execute checks, and remote `ADD` source checks
- Kubernetes ingress HTTPS-redirect disablement and sensitive-path exposure checks
- Kubernetes Pod Security privileged-enforcement checks and admission webhook fail-open detection
- Terraform/OpenTofu remote-state encryption-disablement and insecure backend transport checks
- Terraform/OpenTofu secret-bearing output and variable sensitivity-disablement checks
- Terraform/OpenTofu public sensitive-service ingress checks beyond SSH/RDP-only exposure
- Terraform/OpenTofu broad public all-ports ingress checks
- Terraform/OpenTofu inline literal secret-attribute checks
- Terraform and OpenTofu checks for public object-storage exposure, wildcard IAM trust and permission posture, and public admin ingress
- Kubernetes checks for Secrets with inline data, wildcard RBAC, cluster-admin bindings, privileged containers, privilege escalation, root posture, host namespace sharing, and `hostPath` mounts

Priority expansions:

- GitHub Actions hardening:
  permissions, third-party action pinning, secret exposure, untrusted PR execution
- Terraform and OpenTofu posture:
  public ingress, wide IAM, plaintext secrets, unsafe state handling
- Kubernetes posture:
  privileged containers, host mounts, wildcard RBAC, broader unsafe ingress coverage, secret misuse, and deeper admission-policy coverage beyond current privileged-enforcement and fail-open webhook checks
- Docker and container posture:
  broad capabilities, remote fetch verification beyond direct shell pipes, and additional runtime hardening beyond current base-image pinning and explicit final-stage root-user checks
- cloud configuration files:
  public buckets, wildcard principals, dangerous security-group openings

## 5. Repository Governance And Release Safety

Some push risk is not inside source files alone.

Priority expansions:

- risky changes to hook scripts, `core.hooksPath`, and local enforcement files
- tamper-prone edits to `.wolfence/*` policy and trust material
- live branch protection posture and deeper ownership semantics beyond current
  local `CODEOWNERS`, repo-admin, ruleset, signed-commit, linear-history, and
  conversation-resolution, and status-check governance checks
- release automation that can publish from unreviewed branches or tags
- signing and provenance posture for artifacts when the repo contains release automation, including attestation-permission integrity and mutable tag minting paths

## 6. Binary And Artifact Inspection

Developers often push generated output or vendor blobs that hide risk.

Priority expansions:

- deepen archive contents inspection beyond current zip-like entry-name checks

## 7. Wolfence Self-Protection

The tool itself is part of the trust boundary.

Priority expansions:

- stronger detection of hook bypass, external hook authority paths, or unmanaged hook replacement
- release signing and provenance verification for Wolfence itself
- signed rule updates if external rule distribution is introduced
- broader native push transport coverage and tighter time-of-check versus time-of-push guarantees where feasible

## Implementation Principles

Every new safety check should satisfy these rules:

- normalized finding output
- explicit severity, confidence, and category
- clear remediation text
- deterministic local execution when possible
- bounded use of remote intelligence
- policy behavior that is documented before the rule is enabled by default

## Priority Order

Recommended implementation order:

1. deepen secrets and credential detection
2. deepen CI, IaC, and deployment checks
3. expand dependency and provenance intelligence
4. add stronger language-aware appsec checks
5. add artifact and generated-file inspection
6. harden Wolfence self-protection and release integrity further

That order keeps focus on the categories most likely to convert an ordinary push
into an immediate incident.

## Success Criteria

We should judge the safety program by measurable outcomes, not slogans.

Wolfence should eventually track:

- coverage by detection family
- supported ecosystems and file formats
- true-positive and false-positive rates for high-confidence rules
- time-to-scan on realistic repository sizes
- number of blocked incidents by category
- residual-risk classes that still require manual review or future scanners

## Product Discipline

The right bar is not:

- "we perform every safety check out there"

The right bar is:

- "we maintain the broadest credible pre-push safety coverage we can defend, and we document what is still outside the gate"

That is how Wolfence becomes trustworthy instead of just ambitious.
