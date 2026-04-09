# Prototype Demo

## Purpose

This guide is the shortest path to trying Wolfence as a real local prototype.

It intentionally focuses on two outcomes:

- a harmless change that Wolfence allows
- a risky change that Wolfence blocks

Use `WOLFENCE_DRY_RUN=1` for these first passes so the policy path runs without
requiring a real remote push target.

## Prerequisites

- `git`
- `cargo`
- `curl`
- `openssl`
- configured Git `user.name` and `user.email`

Initialize the current repository once:

```bash
cargo run -- init
cargo run -- doctor
```

The second command should report no blocking failures before you rely on the
results.

If you want to inspect the same state through a machine-readable contract while
testing UI or automation, use the parallel JSON commands documented in
`docs/development/json-output.md`:

```bash
cargo run -- doctor --json
cargo run -- scan --json
cargo run -- scan push --json
cargo run -- push --json
```

## Scenario 1: Allowed Push

Create a harmless commit:

```bash
printf '# Demo\n\nHarmless prototype content.\n' > README.md
git add README.md
git commit -m "Add harmless demo content"
WOLFENCE_DRY_RUN=1 cargo run -- push
```

Expected result:

- Wolfence evaluates the outbound candidate set
- findings stay at `0` or non-blocking informational levels
- the command exits successfully
- the final line explains that policy allowed the push but `git push` was
  skipped because of `WOLFENCE_DRY_RUN=1`

## Scenario 2: Blocked Push

Create a clearly risky outbound file:

```bash
printf 'DATABASE_URL=postgres://prod.example.internal/app\n' > .env
git add .env
git commit -m "Add env file"
WOLFENCE_DRY_RUN=1 cargo run -- push
```

Expected result:

- Wolfence flags `.env` as an outbound environment file
- the finding is high-severity and blocks in `standard` mode
- the command exits non-zero
- the output includes location, remediation, and policy rationale

## Why These Scenarios Matter

These are not just hand-written examples. The current test suite exercises the
same protected-decision paths directly:

- `wolf push` dry-run allows a harmless initial commit
- `wolf push` dry-run blocks a risky `.env` initial commit
- the managed `pre-push` hook allows a harmless initial commit
- the managed `pre-push` hook blocks a risky `.env` initial commit

That means the prototype already has a real command-level safety check for its
most important product boundary.

## After The Demo

Once those dry-run flows look correct, the next practical step is to try the
same path with a real remote:

1. create or configure a Git remote
2. leave `WOLFENCE_DRY_RUN` unset
3. run `cargo run -- push`

If you skip step 1, Wolfence now fails cleanly after policy evaluation and
records that outcome in the audit chain as a push transport failure instead of
pretending the push completed.

For native Git behavior through hooks instead of explicit `wolf push`,
continue with:

```bash
git push
```

because `wolf init` installs the managed `pre-push` hook.
