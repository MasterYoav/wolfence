# Wolfence Threat Model

## Objective

Wolfence is itself a security product, which means the project has two threat
surfaces:

1. the code a developer is trying to push
2. Wolfence as a trusted local enforcement component

The second surface matters just as much as the first. If Wolfence is easy to
bypass, corrupt, or confuse, the product fails regardless of scanner quality.

## Security Goals

- prevent obviously unsafe code from being pushed by default
- keep the allow-or-block decision local and deterministic
- explain decisions clearly enough that developers can act on them
- minimize false negatives for high-risk categories such as secrets
- keep override and exception paths auditable
- preserve user trust through transparent and predictable behavior

## Protected Assets

- staged code and repository metadata
- local policy configuration
- override decisions and audit history
- scanner definitions and policy bundles
- release artifacts and update channels
- trust in the authenticity of the Wolfence binary itself

## Primary Threat Actors

- a rushed but non-malicious developer
- a malicious insider attempting to bypass policy
- malware on the developer workstation
- a supply-chain attacker targeting dependencies or update channels
- an attacker trying to poison scanner definitions or policy data

## Key Abuse Cases

### Secrets leakage

A developer accidentally stages an `.env` file, a private key, or an API token.
Wolfence must detect high-confidence indicators and block the outbound action.

### Vulnerable code patterns

A change introduces dangerous sinks such as unsanitized HTML rendering or
dynamic code execution. Wolfence should detect common high-risk patterns and
route them through policy.

### Dependency risk

A dependency update introduces vulnerable or malicious software. The MVP can
start with posture checks, but the roadmap should include vulnerability
intelligence and provenance validation.

### Configuration exposure

Infrastructure or CI changes unintentionally create broad network access,
privileged containers, or overpowered automation tokens.

### Bypass attempts

A user or attacker tries to call Git directly, edit hooks, disable Wolfence, or
replace policy files. Wolfence must be honest about what it can and cannot
enforce locally, and should support optional hook integration and tamper-evident
configuration over time.

### Supply-chain compromise of Wolfence

If the distributed binary or rule bundle is compromised, the product can become
an attack vector. Signed releases, provenance, and reproducible verification are
important from early in the lifecycle.

## Trust Boundaries

### Boundary 1: CLI to local operating system

Wolfence trusts the local OS only partially. It runs with the user's rights and
must assume files can be changed between scan and execution unless the design
reduces time-of-check/time-of-use gaps.

### Boundary 2: Wolfence to Git

Git is treated as the source of truth for repository state. Wolfence wraps Git
but should never assume Git commands always succeed or return expected output.

### Boundary 3: Wolfence to external scanners and data

External tools and vulnerability feeds are valuable, but they are also supply
chain inputs. They need version pinning, authenticity checks, and careful
failure behavior.

### Boundary 4: Local machine to remote services

Future dashboards, policy services, or update channels must never become a hard
dependency for the core local decision path.

## Design Principles Derived From the Threat Model

- local-first enforcement
- default-deny posture for high-confidence critical findings
- normalized findings with explicit confidence and severity
- minimal side effects before policy decision
- signed releases and provenance for the Wolfence binary
- explicit audit trail for overrides and policy exceptions
- fail-closed behavior for malformed or expired override receipts
- clear separation between signal generation and policy judgment
- tamper-evident local decision history for protected push outcomes

## Current Detection Priorities

The current implementation is strongest in these areas:

- high-confidence secret and key-material detection
- dependency provenance and lockfile posture signals
- configuration mistakes that widen exposure or privilege

This is intentional. A local gate should be strongest on the categories that
most often turn a routine push into an incident.

## Reference Standards

The project should align with these security baselines:

- OWASP ASVS 5.0.0
- OWASP Top 10:2021
- OWASP SCVS
- NIST SP 800-218 SSDF 1.1
- SLSA for build integrity and provenance
- Sigstore for signing and verification
- OSV and OpenSSF Scorecard for supply-chain intelligence and posture
