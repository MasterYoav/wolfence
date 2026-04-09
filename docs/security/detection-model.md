# Detection Model

## Purpose

Wolfence is a local gate, not a cloud SIEM. Its detection model is optimized
for one narrow but valuable moment:

1. code is about to leave the machine
2. the tool must decide quickly whether that outbound change is acceptable

That means the detectors need to prioritize:

- high-confidence blocking signals
- explainable heuristics
- predictable local execution
- low operational dependency on remote services

## Secret Detection

Wolfence now uses a layered secret detector instead of a few single-string
checks.

### Layer 1: Sensitive file paths

The scanner flags paths that strongly suggest credential or key material, such
as:

- `.env` and `.env.*`
- `.npmrc`
- `.pypirc`
- `.netrc`
- `.docker/config.json`
- `.aws/credentials`
- `.ssh/*`
- `terraform.tfvars` and `*.auto.tfvars`
- key and keystore extensions like `.key`, `.p12`, `.pfx`, `.jks`

This catches the common "wrong file got committed" failure mode.

### Layer 2: High-confidence secret signatures

The scanner looks for token families with strong prefixes or shapes, including:

- AWS access key identifiers
- GitHub personal and fine-grained tokens
- GitLab personal access tokens
- Hugging Face tokens
- Slack tokens
- Slack and Discord webhook URLs
- Stripe live keys
- npm auth tokens
- SendGrid API keys
- private key PEM headers

These findings should usually be treated as high-confidence incidents.

### Layer 3: Generic secret assignments

The scanner also looks for suspicious assignments such as:

- `API_KEY=...`
- `"client_secret": "..."`
- `token: ...`

A generic assignment is only flagged when:

- the key name looks secret-bearing
- the value is long enough to matter
- the value is not a known placeholder
- the value looks structured or has high entropy

This is the main false-positive control layer.

### Layer 4: Embedded credentials in URLs

The scanner detects URLs with inline credentials such as:

- `https://user:password@example.com`
- `.npmrc` auth lines such as `//registry.npmjs.org/:_authToken=...`
- `.netrc` `password ...` machine entries
- `.pypirc` password or token assignments
- `Authorization: Bearer <token>`
- `Authorization: Basic <base64>`
- `X-API-Key: <token>`
- `X-Auth-Token: <token>`
- `Cookie: sessionid=<token>`
- `Set-Cookie: auth_token=<token>`

That pattern remains a common source of accidental leaks.

## Dependency Intelligence

Wolfence now does more than check whether a lockfile exists.

### Relationship checks

It checks whether changed manifests are accompanied by changed lockfiles across:

- Cargo
- Node
- Python

This is still heuristic, but it catches reviewability gaps early.

### Manifest intelligence

The scanner reviews dependency declarations for:

- direct Git sources
- direct HTTP or HTTPS package URLs
- local path dependencies
- wildcard or `latest` version selectors
- Cargo source overrides like `[patch]` and `[replace]`

These do not all mean "malicious", but they do change the trust and review
model of the dependency graph.

### Lockfile intelligence

The scanner reviews lockfiles for:

- Git-sourced packages
- insecure HTTP registry or tarball transport
- missing integrity metadata in Node lockfiles
- missing Cargo checksums for registry packages

This shifts the scanner from simple presence checks toward actual provenance and
tamper-resistance posture.

### Live advisory intelligence

During protected pushes, Wolfence can also query OSV for exact dependency
versions extracted from lockfiles and pinned requirements.

Current supported sources are:

- `Cargo.lock`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `poetry.lock`
- pinned `requirements*.txt`

This layer is intentionally bounded:

- exact versions only
- capped batch size
- push-first by default
- best-effort in `auto` mode
- fail-closed availability in `require` mode

## Configuration Exposure Signals

Wolfence also looks for configuration changes that widen exposure or embed
secret material directly in infrastructure definitions.

Current examples include:

- privileged container settings
- wide-open network exposure like `0.0.0.0/0`
- elevated CI runner settings
- Kubernetes `Secret` manifests with inline `data` or `stringData`
- GitHub Actions workflows with `permissions: write-all`
- GitHub Actions `pull_request_target` workflows, especially when they reference pull-request head content

## Lightweight SAST Signals

Wolfence also applies a small set of line-level code and script heuristics for
obviously risky execution paths.

Current examples include:

- `eval(` dynamic execution
- `Runtime.getRuntime().exec` command execution sinks
- `innerHTML` raw HTML sinks
- remote script execution patterns such as `curl ... | sh`, `wget ... | bash`,
  or `Invoke-WebRequest ... | iex`

These are intentionally high-signal, local heuristics rather than a full static
analysis engine. Remote-script execution is severity-scaled by path: it is
treated as higher severity in real execution surfaces such as CI workflows,
shell scripts, PowerShell, and Dockerfiles than in generic text or docs files.

## Confidence Philosophy

The scanner intentionally separates:

- `severity`: how bad the condition would be if true
- `confidence`: how strong the detection signal is

That distinction matters for policy design. A high-severity, high-confidence
private key should block aggressively. A lower-confidence heuristic should be
reviewable without pretending it is proof.

## Known Limits

The current hardened model is still not the final system.

Important limits:

- it does not yet use a live vulnerability feed such as OSV during scans
- it does not yet resolve full dependency graphs by ecosystem
- it does not yet parse every manifest format structurally
- it still relies on heuristics for some generic secret findings
- it does not yet persist findings for override history or deduplicated triage

Those are deliberate scope limits, not oversights. The current objective is a
defensible local gate with strong high-signal coverage before adding remote
dependency or advisory complexity.
