# Audit Chain

## Purpose

Wolfence should not only decide. It should also leave a local record of what it
decided and why.

The current audit layer writes protected push outcomes to an append-only JSONL
file with a chained content hash. This creates tamper-evident local history for
the decisions that matter most.

## Location

```text
.wolfence/audit/decisions.jsonl
```

This file is local operational evidence by default and is not meant to be
committed to the repository.

## Current Scope

Wolfence currently records:

- `wolf push`
- managed `pre-push` hook evaluations

This includes:

- no-op outcomes such as `no-commits` and `up-to-date`
- policy-allowed pushes before transport
- completed pushes after `git push` succeeds
- push transport failures after policy allowed the action
- blocked pushes
- dry-run allowed pushes

## Recorded Fields

Each audit entry currently includes:

- sequence number
- unix timestamp
- source
- action
- status
- outcome
- detail when Wolfence needs to preserve transport or evaluation context
- verdict
- candidate file count
- discovered and ignored candidate-file counts for newer exclusion-aware audit entries
- finding counts
- warning count
- block count
- applied override count
- receipt issue count
- branch metadata when available
- previous entry hash
- current entry hash

## Integrity Model

Every entry stores:

- `prev_hash`
- `entry_hash`

`entry_hash` is computed over the canonical entry payload, including
`prev_hash`. That creates a forward-linked chain:

1. first entry points to `genesis`
2. each later entry points to the previous entry hash
3. changing one historical entry breaks every later verification step

## Verification

`wolf doctor` verifies the chain by:

- reading entries in order
- checking sequence continuity
- checking `prev_hash`
- recomputing `entry_hash`

If the chain is broken, doctor reports the audit log as unhealthy.

## Outcome Semantics

Wolfence now treats policy and transport as separate facts:

- `policy-allowed` means the policy engine allowed the outbound content
- `push-completed` means native `git push` succeeded after policy allowance
- `push-failed` means policy allowed the content, but the underlying Git
  transport step failed

This matters because a security gate should not record a completed outbound
action when the code never actually left the machine.

## Current Limits

This is tamper-evident, not tamper-proof.

Current limits:

- the log is local only
- the chain is not externally anchored
- entries are not signed
- a fully privileged local attacker can still delete the file

Even with those limits, the chain is still valuable because accidental edits,
partial corruption, and sloppy tampering become visible immediately.

## Future Direction

Stronger future options:

- signed audit entries
- remote anchoring
- immutable append sinks
- cross-machine or org-level collection
