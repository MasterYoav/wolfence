# Wolfence Web Console

Astro-based browser console for Wolfence's local-first security engine.

This app is intentionally downstream of the Rust core:

- `wolf` owns scan, policy, and push decisions
- the web console owns presentation
- the local `wolf ui` bridge exposes repo-local state and structured
  `wolf ... --json` output to the browser over localhost

## Local Development

```bash
npm install
npm run dev
```

Smoke-check the local browser console with:

```bash
cargo run -- ui verify
```

That verification now checks both:

- the built bundle and route files on disk
- a temporary live localhost bridge serving `/`, `/history`, `/api/health`,
  `/api/console`, and one built static asset

For a browser-driven end-to-end pass against the live localhost console:

```bash
npm run verify:browser
```

The same flow is also exposed through Wolfence itself:

```bash
wolf ui verify-browser
```

If Puppeteer has not downloaded a browser yet, install one from
`apps/web-console` with:

```bash
npx puppeteer browsers install chrome
```

When the browser verifier fails, it writes debug artifacts under:

```bash
apps/web-console/.artifacts/verify-browser/
```

That directory includes a screenshot, page HTML, a short failure summary, and
captured `wolf ui` bridge output.

The latest `wolf ui verify` and `wolf ui verify-browser` results are also
persisted in:

```bash
.wolfence/ui/verification-status.json
```

`wolf doctor` reads that file and reports the latest browser-backed
verification posture as part of the normal local health output.

The browser console also renders that persisted verification posture through
the local bridge, so operators can see the latest smoke and browser-backed
results from the main console and history view.

The main console can now also trigger both verification paths directly through
the local bridge:

- `Run smoke verify`
- `Run browser verify`

Those same actions are also exposed through the command palette.

Pinned repos with their own Wolfence browser-console surface also expose the
same smoke and browser verification actions from the dossier view, so
multi-workspace operators do not have to switch the active target just to run
repo-local UI verification.

`wolf doctor` now also includes a browser-console surface check, so missing
bundle/routes or broken local bridge metadata show up in the normal local
health report.

The repository CI now mirrors that same path:

- `npm ci`
- `npm run build` in `apps/web-console`
- `cargo check`
- `cargo run -- ui verify`

There is also a browser-backed CI job for the full live console flow:

- `npm ci`
- `npm run build` in `apps/web-console`
- `npx puppeteer browsers install chrome`
- `cargo run -- ui verify-browser`
- uploads `apps/web-console/.artifacts/verify-browser/` when the browser job fails
- only runs when browser-console or local bridge files changed

Both CI jobs now share the same repo-local setup action at:

```bash
.github/actions/setup-web-console/action.yml
```

The CI workflow also cancels superseded in-progress runs for the same ref and
puts explicit time limits on the smoke and browser jobs so UI verification does
not accumulate stale work.

The workflow now also publishes a short CI summary that states:

- whether the smoke path passed
- whether browser-relevant files changed
- whether the browser-backed path ran, was skipped, or failed

The design and bridge contract are documented in:

- `docs/ui/web-console.md`

## Scope

Current surface:

- workspace rail
- pinned workspace add/select/remove flow through the local bridge
- cached per-workspace summaries with explicit refresh actions
- pinned workspace dossier view for live drill-down without switching the active repo
- repo-local verification posture and dossier-triggered smoke/browser verification for pinned repos that support the browser console
- side-by-side comparison board across pinned repos
- saved named comparison sets restored through the local bridge
- historical trend strips and audit deltas in the comparison board
- shared audit time-window filtering and per-repo recent history timelines
- dedicated `/history` screen for full pinned-repo audit timelines
- JSON and Markdown export artifacts for the comparison board, pinned-repo dossiers, and full-history views
- action-status banners and busy states for refresh, save/load comparison, repo selection, and protected push flows
- multi-repo fleet board ranking pinned repos by urgency, stale posture, and recent audit behavior
- fleet-board smoke/browser verification actions for pinned repos that support the browser console
- keyboard-first command palette for scan, push, refresh, history, and pinned-repo actions (`Cmd/Ctrl+K`)
- push posture
- doctor posture
- findings panel
- policy panel
- audit panel
- live push-preview activity streamed from the Rust bridge
- protected push trigger for the selected workspace
