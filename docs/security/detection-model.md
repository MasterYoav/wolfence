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

For the explicit current-state coverage matrix, shipped families, and known
gaps, see `docs/security/scanner-inventory.md`.

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
- OpenAI project and service-account keys
- Anthropic API keys
- Slack tokens
- Slack and Discord webhook URLs
- Stripe live keys
- Stripe webhook secrets
- npm auth tokens
- SendGrid API keys
- private key PEM headers

These findings should usually be treated as high-confidence incidents.

### Layer 3: Generic secret assignments

The scanner also looks for suspicious assignments such as:

- `API_KEY=...`
- `"client_secret": "..."`
- `token: ...`
- `"private_key": "-----BEGIN PRIVATE KEY-----..."`

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

### Layer 5: Structured connection and config secrets

The scanner also looks for secrets embedded in structured connection material,
for example:

- SQL-style connection strings with `Password=` or `Pwd=`
- storage or service connection strings with `AccountKey=`
- escaped private-key blobs assigned through JSON-style fields

This catches the common case where the secret is not a standalone token, but is
still clearly live credential material inside config content.

## Dependency Intelligence

Wolfence now does more than check whether a lockfile exists.

### Relationship checks

It checks whether changed manifests are accompanied by changed lockfiles across:

- Cargo with `Cargo.lock`
- Node with `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, and `yarn.lock`
- Go with `go.sum`
- Bundler with `Gemfile.lock` or `gems.locked`
- Python with `poetry.lock`, `uv.lock`, and `Pipfile.lock`

This is still heuristic, but it catches reviewability gaps early.

### Manifest intelligence

The scanner reviews dependency declarations for:

- direct Git sources
- direct HTTP or HTTPS package URLs
- local path dependencies
- Go module `replace` directives
- Ruby `source` and `git_source` overrides
- tracked package-manager registry config such as `.npmrc`, `.yarnrc.yml`, and `.cargo/config.toml`
- wildcard or `latest` version selectors
- custom Python package indexes and source sections
- `requirements` index overrides such as `--index-url` and `--extra-index-url`
- `requirements` transport exceptions such as `--trusted-host`
- out-of-band package link sources such as `--find-links`
- Pipenv sources with `verify_ssl = false`
- Cargo source overrides like `[patch]` and `[replace]`

These do not all mean "malicious", but they do change the trust and review
model of the dependency graph.

It also reviews tracked package-manager registry configuration for:

- custom Node registry overrides in `.npmrc` and Yarn config
- insecure HTTP package registries
- package-manager TLS verification disablement such as `strict-ssl=false` or `enableStrictSsl: false`
- Cargo `replace-with` and custom registry index configuration in `.cargo/config*`

It now also raises dependency-confusion posture findings when:

- a repository configures custom Node registries and still depends on unscoped package names
- a Python requirements file uses custom or extra indexes while still relying on unqualified package entries

These are still heuristic findings. They do not prove a package takeover, but
they do flag provenance setups where package ownership can become ambiguous.
Repositories can narrow that heuristic by declaring explicit internal package
ownership in `.wolfence/config.toml` through `[dependency].node_internal_packages`
and `[dependency].python_internal_packages`, plus the broader
`[dependency].node_internal_package_prefixes` and
`[dependency].python_internal_package_prefixes` lists when internal packages
follow a stable naming convention.

It can also raise stronger host-mismatch findings when `.wolfence/config.toml`
declares owner-host rules through `[dependency].node_registry_ownership`,
`[dependency].ruby_source_ownership`, or
`[dependency].python_index_ownership`, but the tracked registry, source, or
index configuration points elsewhere.

It now extends that same owner-host check into explicit resolved and direct
source surfaces when the package name and remote host are clear enough to make
the claim defensible.

For direct-source manifests, Wolfence also distinguishes a second case:
internal packages that still point at an expected host, but do so through a
direct Git or archive source instead of the normal registry or index flow.
That is treated as an ownership-path bypass rather than a host mismatch.

The same distinction now applies in supported Python lockfiles when the
resolved graph shows a direct Git, file, path, or editable-style source
instead of normal private-index resolution.

### Lockfile intelligence

The scanner reviews lockfiles for:

- Git-sourced packages
- local path sourced packages in Bundler and Go replacement flows
- local file or path sourced packages in Python lockfiles
- custom gem-source provenance in Bundler lockfiles
- custom package-index provenance in Pipenv lockfiles
- insecure HTTP registry or tarball transport
- missing integrity metadata in Node and Yarn lockfiles
- missing Cargo checksums for registry packages
- owner-host mismatches for internal packages in supported Node, Ruby, and Python lockfiles

This shifts the scanner from simple presence checks toward actual provenance and
tamper-resistance posture.

Current owner-host resolution checks cover changed:

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- direct-source `Gemfile` or `gems.rb` entries
- `Gemfile.lock`
- `gems.locked`
- direct remote `package.json` dependency specs
- direct remote Python requirement references
- `pyproject.toml` direct dependency references using `name @ https://...` or inline tables such as `{ url = "...", git = "..." }`
- `Pipfile` package-table direct dependency references such as `{ file = "...", git = "..." }`
- `poetry.lock`
- `uv.lock`
- `Pipfile.lock` when `_meta.sources` exposes index URLs

That means owner-host policy is enforced across both tracked registry or index
configuration and the highest-signal changed resolution surfaces, instead of
stopping at configuration intent alone.

### Live advisory intelligence

During protected pushes, Wolfence can also query OSV for exact dependency
versions extracted from lockfiles and pinned requirements.

Current supported sources are:

- `Cargo.lock`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `go.sum`
- `Gemfile.lock`
- `gems.locked`
- `poetry.lock`
- `uv.lock`
- `Pipfile.lock`
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
- Dockerfiles with mutable or non-digest-pinned base images
- Dockerfiles that leave the final runtime stage on explicit `USER root` or `USER 0`
- Dockerfiles that fetch remote content and pipe it directly into a shell such as `curl ... | sh`
- Dockerfiles that fetch remote content and then execute the downloaded payload in the same `RUN` step
- Dockerfiles that use `ADD https://...` to pull remote build inputs directly
- Kubernetes `Secret` manifests with inline `data` or `stringData`
- Kubernetes `Role` or `ClusterRole` manifests with wildcard RBAC permissions
- Kubernetes `ClusterRoleBinding` manifests that bind subjects directly to `cluster-admin`
- Kubernetes workloads that enable `privileged: true`, `allowPrivilegeEscalation: true`, `runAsNonRoot: false`, host namespace sharing, or `hostPath` volume mounts
- Kubernetes `Ingress` manifests that explicitly disable HTTPS redirect behavior
- Kubernetes `Ingress` manifests that expose sensitive paths such as `/admin` or `/metrics` without a visible source-range allowlist
- Kubernetes `Namespace` manifests that set Pod Security admission enforcement to `privileged`
- admission webhook configurations that use `failurePolicy: Ignore` and therefore fail open on webhook errors
- Terraform or OpenTofu object-storage posture that allows public ACLs or disables public-access blocking
- Terraform or OpenTofu S3 backends that explicitly disable state encryption with `encrypt = false`
- Terraform or OpenTofu `http` backends that send remote state traffic over `http://`
- Terraform or OpenTofu secret-bearing `output` blocks that explicitly set `sensitive = false`
- Terraform or OpenTofu secret-bearing `variable` blocks that explicitly set `sensitive = false`
- Terraform or OpenTofu secret-bearing attributes such as `master_password` that assign literal values directly in `.tf` config
- Terraform or OpenTofu IAM policy documents with wildcard principals, actions, or resources
- Terraform or OpenTofu network rules that expose administrative ports like SSH or RDP to `0.0.0.0/0`
- Terraform or OpenTofu network rules that expose sensitive service ports such as database, cache, observability, or control-plane ports to `0.0.0.0/0`
- Terraform or OpenTofu network rules that expose effectively all ports or all protocols to `0.0.0.0/0`
- GitHub Actions workflows with `permissions: write-all`
- GitHub Actions `pull_request_target` workflows, especially when they reference pull-request head content
- GitHub Actions workflows that use mutable third-party action references instead of full commit SHAs
- GitHub Actions workflows that use mutable reusable workflow references instead of full commit SHAs
- GitHub Actions workflows that run pull-request-triggered jobs on self-hosted runners
- reusable GitHub Actions workflows that use `secrets: inherit`
- GitHub Actions workflows that enable `ACTIONS_ALLOW_UNSECURE_COMMANDS`
- GitHub Actions workflows that bridge trust through `workflow_run`
- GitHub Actions workflows that download artifacts and appear to execute them
- dispatch-triggered workflows that feed caller-controlled refs into checkout
- release-triggered workflows that build from mutable `target_commitish` refs
- GitHub Actions workflows that publish artifacts directly from mutable branch pushes instead of tag or release-controlled triggers
- GitHub Actions attestation steps that lack the explicit `id-token: write` and `attestations: write` permissions they rely on
- GitHub Actions trusted publishing flows such as `npm publish --provenance` or `pypa/gh-action-pypi-publish` that lack `id-token: write`
- GitHub Actions publish workflows that rely on long-lived registry credentials from repository or organization secrets
- GitHub Release, Goreleaser, and semantic-release action workflows such as
  `softprops/action-gh-release`, `ncipollo/release-action`,
  `actions/create-release`, `goreleaser/goreleaser-action`, or
  `cycjimmy/semantic-release-action` that publish from mutable branch pushes or
  without provenance/signing signals
- GitHub Release, Goreleaser, or semantic-release publication paths that rely
  on PAT-style secrets such as `GH_PAT`, `github_token: ${{ secrets.* }}`, or
  `GITHUB_TOKEN: ${{ secrets.* }}` instead of ephemeral repository tokens
- GitHub Actions OCI publish workflows that use `docker/build-push-action` with `push: true` but no explicit provenance or signing signal
- GitHub Actions OCI publish workflows that authenticate through `docker/login-action` with secret-backed long-lived registry credentials before pushing images
- GitHub Actions keyless signing flows such as `cosign sign --keyless` or `cosign attest --keyless` that lack `id-token: write`
- GitHub Actions signing workflows that rely on long-lived signing key or passphrase secrets such as `COSIGN_PRIVATE_KEY` or GPG private-key material
- tag- or release-triggered workflows that override checkout back to a mutable branch ref
- branch-triggered workflows that mint and push Git tags as part of release automation
- `pull_request_target` workflows that use `actions/checkout` without explicitly disabling persisted credentials

## Lightweight SAST Signals

Wolfence also applies a small set of line-level code and script heuristics for
obviously risky execution paths.

Current examples include:

- `eval(` dynamic execution
- `Runtime.getRuntime().exec` command execution sinks
- `innerHTML` raw HTML sinks
- request or CLI-controlled input flowing into command execution sinks such as Node `exec`, Python `os.system` and `subprocess(..., shell=True)`, JVM `Runtime.exec`, and similar PHP or Ruby sinks
- request or CLI-controlled input flowing into outbound HTTP client calls, which can create SSRF risk
- direct outbound requests to cloud metadata-service endpoints such as `169.254.169.254`
- request or CLI-controlled input flowing into filesystem and file-delivery sinks such as `open`, `send_file`, `fs.readFile`, `res.sendFile`, `file_get_contents`, and similar JVM file APIs
- unsafe deserialization primitives such as `pickle.loads`, `yaml.load`, `unserialize`, `ObjectInputStream.readObject`, and `BinaryFormatter.Deserialize`
- string-built SQL queries that interpolate request or CLI-controlled input before execution
- non-cryptographic randomness used for token, session, nonce, reset, or similar secret-bearing value generation
- weak hashes for password-, token-, or secret-like material, plus legacy cipher or ECB-mode encryption usage
- uploaded-file writes and archive extraction that operate directly from request or uploaded-file context
- request-controlled privilege or ownership assignment, plus privileged surfaces explicitly marked `AllowAny`, `PermitAll`, `skipAuth`, or equivalent bypass markers
- remote script execution patterns such as `curl ... | sh`, `wget ... | bash`,
  or `Invoke-WebRequest ... | iex`

These are intentionally high-signal, local heuristics rather than a full static
analysis engine. Remote-script execution is severity-scaled by path: it is
treated as higher severity in real execution surfaces such as CI workflows,
shell scripts, PowerShell, and Dockerfiles than in generic text or docs files.

## Artifact And Generated-File Signals

Wolfence now also inspects opaque outbound artifacts that reduce reviewability.

Current examples include:

- packaged archives such as zip files, tarballs, jars, and compressed bundles
- zip-like archive contents that contain traversal-style entry paths or embedded
  executable payload names
- compiled native binaries such as ELF, PE, and Mach-O payloads
- minified JavaScript bundles that combine dynamic loader behavior with remote
  endpoints
- minified JavaScript bundles that beacon to remote telemetry or collection
  endpoints through `sendBeacon`, keepalive fetches, or image-pixel style
  requests
- generated or distribution assets that embed credential-like material such as
  bearer tokens, secret-bearing headers, private keys, webhook URLs, or
  suspicious secret assignments
- newly added executable text launchers outside normal script or tooling paths,
  which deserve provenance review before they become hidden entrypoints
- source map artifacts such as `.js.map` files that can expose original source
  structure and implementation detail

This is intentionally narrow. The current goal is to catch the riskiest opaque
payload classes without flagging every generated file in a normal build output.

## Repository Governance And Release Safety Signals

Wolfence also inspects repository-native governance material that shapes who is
expected to review sensitive changes.

Current examples include:

- `.github/settings.yml`, `.github/repository.yml`, or `.github/rulesets/*` that
  allow force pushes or deletions on protected ref surfaces
- repo-admin config that disables administrator enforcement, code-owner review,
  stale-review dismissal, meaningful approving-review requirements, or required
  signed commits
- repo-admin config that disables required linear history on protected branch
  surfaces
- repo-admin config that disables required conversation resolution on protected
  branch surfaces
- repo-admin config that disables required status checks on protected branch
  surfaces
- rulesets that are left in `evaluate` or `disabled` mode instead of active
  enforcement
- rulesets that declare explicit bypass actors or allowances
- rulesets that appear to disable non-fast-forward protection
- rulesets that appear to disable required signed commits
- rulesets that appear to disable required linear history
- rulesets that appear to disable required conversation resolution
- rulesets that appear to disable required status checks
- repositories that contain workflows, `.wolfence` policy material, or other
  governance surfaces but have no effective `CODEOWNERS` file
- repositories that contain multiple `CODEOWNERS` files, even though GitHub
  only honors the highest-precedence one
- malformed `CODEOWNERS` rules that declare a path pattern without any owners
- sensitive governance paths such as `.github/workflows/*`, `.github/rulesets/*`,
  `.github/settings.yml`, or `.wolfence/*` that are not covered by any effective
  `CODEOWNERS` rule

These checks are local governance signals, not proof of GitHub's live branch
protection state. They make review ownership explicit where the repository can
express it directly.

## Wolfence Self-Protection Signals

Wolfence also inspects changes that alter the gate's own trust or override
authority.

Current examples include:

- changes to Wolfence's own scanner-bundle surfaces such as local detector,
  finding, trust, receipt, hook, or protected-push engine paths
- scanner-bundle changes that do not also update declared local rule provenance
  surfaces such as `scanner-inventory.*` or the detection model
- `.wolfence/config.toml` changes in general as review-significant policy edits
- `.wolfence/config.toml` changes that lower enforcement to `advisory`
- `.wolfence/config.toml` scan exclusions that target source, CI, dependency, or
  `.wolfence` policy surfaces
- `.wolfence/policy/receipts.toml` changes that alter override approval policy
- `.wolfence/trust/*` changes that alter receipt-signing authority
- trust metadata that appears to create unrestricted signer scope
- `.wolfence/receipts/*` changes that add or alter active override material
- repositories whose effective `core.hooksPath` resolves outside the repository root
- repositories whose active Git hook entrypoints are symlinked to targets
  outside the repository root
- repositories whose active Git hook entrypoints directly delegate to helper
  paths outside the repository root
- repositories whose `core.hooksPath` is explicitly redirected to an alternate
  repo-local hooks directory
- effective hooks directories that contain additional executable unmanaged hook
  files beyond the managed Wolfence pre-push path
- managed pre-push hooks that still use a legacy cargo-only launcher
- managed pre-push hooks whose launcher pattern no longer matches known Wolfence-managed forms

Outside `policy-scanner`, Wolfence also tightens native transport integrity by
rejecting managed `pre-push` hook executions that do not map cleanly to the
evaluated current-branch snapshot, such as tag pushes, branch deletions,
multi-ref pushes, or pushes of a different branch than the one Wolfence just
reviewed. `wolf push` separately revalidates the outbound push snapshot again
immediately before transport.

These checks are about protecting the authority boundary around Wolfence, not
about application code alone.

## Confidence Philosophy

The scanner intentionally separates:

- `severity`: how bad the condition would be if true
- `confidence`: how strong the detection signal is

That distinction matters for policy design. A high-severity, high-confidence
private key should block aggressively. A lower-confidence heuristic should be
reviewable without pretending it is proof.

## Known Limits

The current hardened model is still not the final system.

The intended expansion path for broader pre-push coverage is documented in
`docs/security/safety-check-roadmap.md`.

The explicit current-state inventory lives in
`docs/security/scanner-inventory.md`.

Important limits:

- it does not yet use a live vulnerability feed such as OSV during scans
- it does not yet resolve full dependency graphs by ecosystem
- some ecosystem parsing still relies on line-oriented heuristics instead of full structural parsers
- it still relies on heuristics for some generic secret findings

Those are deliberate scope limits, not oversights. The current objective is a
defensible local gate with strong high-signal coverage before adding remote
dependency or advisory complexity.

Wolfence now also persists repo-local finding history by fingerprint so
repeated findings can be classified as new or recurring across runs.

Wolfence also supports a repo-local accepted finding baseline in
`.wolfence/history/baseline.json` so operators can mark a known starting state.
That baseline is prioritization metadata only. It does not suppress findings,
alter severity, or change push verdicts.
