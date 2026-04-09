# Live Advisories

## Purpose

Wolfence is strongest when it combines deterministic local posture checks with
current dependency intelligence.

The live advisory layer adds OSV-backed vulnerability lookups for exact
dependency versions during protected pushes.

## Current Provider

Wolfence currently queries:

- OSV `POST /v1/querybatch`

This lets Wolfence check multiple exact dependency versions in one bounded
request.

## Current Coverage

Wolfence currently extracts exact-version dependencies from:

- `Cargo.lock`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `poetry.lock`
- pinned `requirements*.txt`

It does not yet resolve full dependency graphs for every ecosystem and it does
not yet use `pnpm-lock.yaml` for live OSV lookups.

## Advisory Modes

The advisory layer is controlled by `WOLFENCE_OSV`.

### `off`

Disable live advisory lookups entirely.

### `auto`

Attempt live advisory lookups during protected pushes, but do not fail the push
path if:

- `curl` is unavailable
- the network is unavailable
- OSV cannot be reached
- the API response cannot be used

This is the default because Wolfence should remain usable as a local gate even
without network access.

### `require`

Treat live advisory availability as part of the protected push posture.

If the lookup cannot run, Wolfence emits a finding instead of silently
continuing without advisory coverage.

## Bounded Behavior

The current implementation is intentionally bounded:

- push-first only
- exact versions only
- deduplicated package/version queries
- capped batch size
- fail-open in `auto`
- fail-closed availability in `require`

Those limits are deliberate. They keep the local tool predictable while still
adding meaningful current-risk coverage.

## Operator Expectations

Live advisories should be treated as a complement to, not a replacement for:

- lockfile provenance review
- dependency source review
- local policy checks
- override receipt discipline

The advisory layer helps answer "is this known-bad right now?" It does not
replace the rest of the gate.
