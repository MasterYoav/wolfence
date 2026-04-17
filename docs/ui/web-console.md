# Wolfence Web Console

## Purpose

Wolfence now has a cross-platform browser console at:

- `apps/web-console`

Its job is the same as the native macOS app:

- present local Wolfence state
- help operators inspect push posture
- render findings, policy, and audit evidence

It must not become a second policy engine.

## Canonical Rule

The `wolf` binary remains authoritative for:

- scanner execution
- policy evaluation
- protected push decisions
- audit creation
- hook management

The browser console is authoritative only for presentation.

## Why A Browser Surface Exists

Wolfence already works on macOS, Linux, and Windows, but the existing desktop
console is macOS-only. The web console fills that gap without changing the
trust model:

- one local Rust engine
- one cross-platform browser UI
- no remote dependency in the core safety path

## Required Architecture

The browser UI cannot safely replace the local engine. Browsers cannot
portably:

- enumerate arbitrary local repositories without an explicit local bridge
- run `wolf doctor --json`
- run `wolf scan push --json`
- install or verify Git hooks
- execute a protected push

So the required shape is:

```text
browser
  -> local bridge
  -> wolf JSON / local state adapters
  -> Wolfence Rust core
```

## MVP Shape

### Frontend

- Astro application under `apps/web-console`
- information architecture mirrors the native console:
  - workspace rail
  - push posture
  - doctor posture
  - findings
  - repo policy
  - audit timeline

### Local Bridge

The first stable bridge should be local-only and listen on localhost.

Current command shape:

- `wolf ui`
- `wolf ui serve`
- `wolf ui verify`

Current bridge endpoints:

- `GET /api/health`
- `GET /api/console`
- `GET /api/scan/push/stream`
- `GET /api/workspaces`
- `POST /api/workspaces`
- `POST /api/workspaces/select`
- `POST /api/workspaces/remove`
- `POST /api/workspaces/refresh`
- `POST /api/workspaces/refresh-all`
- `GET /api/comparison-sets`
- `POST /api/comparison-sets`
- `POST /api/comparison-sets/select`
- `POST /api/comparison-sets/clear`
- `POST /api/comparison-sets/remove`
- `GET /api/repositories/:id/doctor`
- `GET /api/repositories/:id/push-preview`
- `GET /api/repositories/:id/audit`
- `POST /api/repositories/:id/scan`
- `POST /api/repositories/:id/push`
- `POST /api/repositories/:id/verify/surface`
- `POST /api/repositories/:id/verify/browser`
- `POST /api/repositories/current/push`

### Local Sources Of Truth

The web console should follow the same data contract as the native app:

1. `.wolfence/config.toml`
2. `.wolfence/policy/receipts.toml`
3. `.wolfence/history/baseline.json`
4. `.wolfence/audit/decisions.jsonl`
5. `wolf doctor --json`
6. `wolf scan push --json`

Where a stable repo-local file already exists, the UI may read it through the
bridge. Where current computed state is needed, the UI must prefer structured
`wolf ... --json` output.

## Non-Responsibilities

The browser console must not:

- invent verdict logic
- parse terminal text when JSON exists
- bypass `wolf push`
- mutate trust or receipt material without a stable Rust command surface
- treat browser-local storage as security state

## UI Direction

The browser surface should feel like an operator workspace, not a generic SaaS
dashboard:

- calm, evidence-first layout
- strong hierarchy around the current push verdict
- dense but readable findings
- explicit repo and branch context
- live scan progress when the bridge supports streaming events

## Current Status

The repository now contains:

- an Astro console in `apps/web-console`
- a localhost-only `wolf ui` bridge
- a lightweight `/api/console` payload that exposes:
  - repo identity
  - repo-local config
  - receipt policy
  - bridge metadata
  - workspace rail state

Selected repo evidence comes from dedicated per-repo endpoints instead of
being bundled into `/api/console`:

- `wolf doctor --json`
- `wolf scan push --json`
- `wolf audit list --json`

The current bridge serves the built Astro app from `apps/web-console/dist`
when that bundle exists, and otherwise returns a local HTML instruction page
telling the operator how to build the frontend.

The bridge now includes background cache refresh scheduling for pinned
workspaces. By default, `wolf ui` refreshes stale workspace summaries every
300 seconds through the same local bridge process. That interval can be
adjusted with `WOLFENCE_UI_AUTO_REFRESH_SECS`, and `0` disables the scheduler.

The scan stream endpoint emits real orchestrator progress from the Rust core:

- outbound snapshot loaded
- scanner started / finished
- per-file scan progress
- governance, history, baseline, and policy phases
- final push-preview result

The current workspace model is repo-local persistence under the host
repository's `.wolfence/ui/workspaces.json`. Cached workspace posture lives
next to it in `.wolfence/ui/workspace-cache.json`. That lets one local browser
session pin and switch between multiple repositories without moving policy or
trust state into the frontend, while avoiding a full `doctor` and `scan push`
recompute for every pinned repo on every page load.

The workspace rail now carries backend-computed posture for every pinned repo:

- verdict label
- tone
- summary line
- doctor summary
- last refresh timestamp

The browser now also supports richer pinned-repo drill-down without switching
the active push target first. Operators can inspect a pinned repo's:

- branch and upstream posture
- cached verdict and summary
- live doctor status
- live push-preview state
- recent audit outcome
- repo-local verification support and latest persisted smoke/browser results
- repo-local smoke and browser verification actions when that repo contains a
  Wolfence browser-console surface

The browser also supports side-by-side comparison across pinned repos:

- compare multiple pinned repos at once
- keep the active push target separate from the comparison set
- save named comparison sets in repo-local UI state and restore them on reload
- line up blocker/warning counts, doctor posture, scope, and recent audit state
- show trend strips from recent audit history
- show deltas against the last recorded audit for each pinned repo
- apply shared history windows like `24h`, `7d`, `30d`, or `all`
- inspect a filtered per-repo recent audit timeline in the dossier
- export the comparison board as JSON or Markdown artifacts

There is now also a multi-repo operations board on the main console:

- ranks pinned repos into `Needs action`, `Watchlist`, and `Ready`
- combines cached workspace posture with recent per-repo audit history
- highlights stale cache state, recent blocked activity, and the active target
- turns the console into a pinned-repo fleet surface instead of a single-repo inspector
- exposes direct smoke/browser verification actions for pinned repos that
  support the Wolfence browser console

There is now also a dedicated history screen for pinned repos:

- route: `/history`
- selects a repo from the pinned workspace set
- deep-links from the main console into a full audit timeline view
- reuses the same shared history windows
- shows the repo’s full filtered audit stream alongside live doctor and push posture
- exports the filtered history view as JSON or Markdown artifacts

The dossier and history layers also support lightweight artifact generation in
the browser itself:

- dossier exports include the selected repo’s current branch, verdict, doctor
  posture, push posture, and filtered audit slice
- history exports include the filtered full timeline plus live doctor and push
  posture for the selected repo
- comparison exports include all currently compared repos, the active repo,
  the shared history window, summarized posture, and filtered audit evidence
- exports are client-side downloads only and do not introduce a second engine
  path or new local authority surface

The browser surface now also carries explicit action feedback for operators:

- inline status banners for working, success, and error states
- busy button treatment during refresh, selection, save/load, and push actions
- clearer confirmation that protected push, comparison save/load, and exports
  actually completed
- a keyboard-first command palette on the main console for scan, push, history,
  refresh, comparison, and pinned-repo selection (`Cmd/Ctrl+K`)

There is now also a local smoke-check command for the console itself:

- `wolf ui verify`
- verifies the built static bundle and route files
- verifies a temporary live localhost bridge can serve `/`, `/history`,
  `/api/health`, `/api/console`, and one built static asset
- verifies the bridge can assemble `/api/console`, workspace state, and saved comparison metadata
- verifies the selected repo still returns machine-readable `doctor`, `push-preview`, and `audit` payloads
- persists the latest smoke-check result in `.wolfence/ui/verification-status.json`

`wolf doctor` now also includes the non-recursive part of that surface check:

- static bundle presence
- route file presence
- `/api/console` shape
- workspace rail state
- saved comparison-set metadata

`wolf doctor` now also reports the latest browser-backed verification posture
from `.wolfence/ui/verification-status.json`, so operators can see whether the
real localhost UI path passed recently without rerunning the browser verifier
first.

The browser console now surfaces that same persisted verification posture
through `/api/console`, so the main console and history view can show the
latest smoke and browser-backed verification results inline.

The main console can now also invoke both verification commands through the
local bridge itself:

- `POST /api/verify/surface`
- `POST /api/verify/browser`

Those actions are exposed as buttons in the verification block and as command
palette actions, so operators do not need to leave the browser surface just to
refresh verification posture.

There is now also a browser-driven end-to-end path for the live console:

- `npm run verify:browser` from `apps/web-console`
- `wolf ui verify-browser`
- starts a temporary local `wolf ui` bridge on localhost
- opens the console in Puppeteer
- verifies the main console, command palette, and `/history` screen render
- exits with a clear setup error when Puppeteer has not downloaded a browser yet
- writes failure artifacts under `apps/web-console/.artifacts/verify-browser/`
  including a screenshot, page HTML, summary text, and captured bridge output
- persists the latest browser-backed result in `.wolfence/ui/verification-status.json`

The repository CI now runs that browser-console path on every push and pull
request:

- install `apps/web-console` dependencies with `npm ci`
- build the Astro console
- run `cargo check`
- run `cargo run -- ui verify`

The repository CI now also runs the browser-backed end-to-end path:

- install `apps/web-console` dependencies with `npm ci`
- build the Astro console
- install a Chrome-for-Testing binary with `npx puppeteer browsers install chrome`
- run `cargo run -- ui verify-browser`
- upload `apps/web-console/.artifacts/verify-browser/` if the browser job fails
- skip the browser job entirely when neither browser-console nor local bridge files changed

The shared Node/Rust/npm build setup for those CI jobs now lives in:

- `.github/actions/setup-web-console/action.yml`

The CI workflow now also:

- cancels superseded in-progress runs for the same branch or pull request ref
- applies explicit timeouts to the smoke and browser jobs so browser-console
  verification does not pile up stale work
- publishes a short workflow summary showing whether the browser-backed path
  ran, was skipped due to change filtering, or failed

Those workspace summaries are cached by the Rust bridge and refreshed
explicitly:

- `POST /api/workspaces/refresh` refreshes one pinned repo
- `POST /api/workspaces/refresh-all` refreshes every pinned repo
- selecting a repo or adding a new pinned repo refreshes that repo immediately
- the background scheduler refreshes stale cached workspaces on a timer

The order of authority remains:

1. Rust engine
2. machine-readable JSON and repo-local state
3. browser presentation
