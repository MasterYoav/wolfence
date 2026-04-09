# Override Receipts

## Purpose

Wolfence needs an exception path, but it cannot be a silent bypass.

The current model uses repo-local override receipts so an exception is:

- explicit
- scoped
- time-bounded
- reviewable
- visible to `wolfence doctor`
- optionally signature-backed once the repo publishes trusted keys

## Location

```text
.wolfence/receipts/*.toml
```

Each file represents one candidate override receipt.

Archived receipts can be moved out of active scope into:

```text
.wolfence/receipts/archive/*.toml
```

Archived receipts are preserved for review, but Wolfence does not load them as
active exceptions.

## Baseline Receipt Fields

Every receipt requires:

- `receipt_id`
- `version`
- `action`
- `category`
- `fingerprint`
- `owner`
- `reason`
- `created_on`
- `expires_on`
- `checksum`

When the repository publishes trusted public keys under `.wolfence/trust/`,
Wolfence also requires:

- `reviewer`
- `reviewed_on`
- `approver`
- `key_id`
- `signature`

## Example

```toml
version = "1"
receipt_id = "wr_0123abcd4567"
action = "push"
category = "dependency"
fingerprint = "dependency-lock-missing-integrity:package-lock.json:41"
owner = "yoav"
reason = "Temporary exception while regenerating the lockfile on the release branch."
created_on = "2026-04-09"
expires_on = "2026-04-16"
checksum = "REPLACE_WITH_COMPUTED_CHECKSUM"
```

Wolfence can generate the same canonical unsigned draft for you:

```bash
cargo run -- receipt new .wolfence/receipts/allow-secret.toml push dependency dependency-lock-missing-integrity:package-lock.json:41 yoav 2026-04-16 "Temporary exception while regenerating the lockfile on the release branch."
```

You can inspect the repository-wide receipt surface at any time:

```bash
cargo run -- receipt list
```

## Semantics

### `action`

The protected action the receipt applies to.

Current supported values:

- `push`
- `scan`

In practice, push is the main value that matters today because `scan` is an
inspection command and does not execute side effects.

### `fingerprint`

The exact finding fingerprint that the receipt can suppress.

This is intentionally narrow. A receipt does not suppress a whole scanner or a
whole file. It suppresses one concrete signal.

### `category`

The normalized finding category that the receipt is allowed to target.

Current supported values:

- `secret`
- `vulnerability`
- `dependency`
- `configuration`
- `policy`

New receipts bind this field into both the checksum and signed payload, so a
receipt approved for one category cannot be replayed against another.

Older receipts without `category` still load through legacy fingerprint-prefix
inference unless the repo enables `require_explicit_category = true` in
`.wolfence/policy/receipts.toml`.

### `owner`

The person or role accepting responsibility for the exception.

### `receipt_id`

The stable identifier for the receipt itself.

New Wolfence-created receipts generate this automatically. Older receipts
without `receipt_id` still load through a deterministic legacy fallback id so
they remain auditable during migration.

### `reason`

A human explanation for why the exception exists.

Short vague reasons such as "needed" or "temporary" are not good enough in
practice, even if the parser accepts them.

### `created_on` and `expires_on`

Exact ISO dates in `YYYY-MM-DD` format.

Expired receipts are ignored automatically.

### `reviewer` and `reviewed_on`

Optional governance metadata for unsigned receipts, and signed-review metadata
for signed receipts.

When Wolfence signs a receipt, it records:

- `reviewer`
- `reviewed_on`

These fields are surfaced in `receipt list` and `receipt verify`.

## Integrity Model

The current receipt checksum is generated from a canonical payload built from:

- version
- action
- category
- fingerprint
- owner
- reason
- created_on
- expires_on

If any of those fields change without updating the checksum, Wolfence ignores
the receipt and reports the issue.

This checksum is an integrity check, not an approval signature. It catches
accidental or sloppy edits, but it is not sufficient for strong tamper
resistance on its own.

When `.wolfence/trust/*.pem` contains at least one trusted public key, Wolfence
switches to signed-receipt mode automatically. In that posture, unsigned
receipts are ignored.

## Computing The Checksum

Wolfence currently uses the same content hash that `git hash-object --stdin`
would return for this exact canonical payload shape:

```text
version=1
action=<action>
category=<category>
fingerprint=<fingerprint>
owner=<owner>
reason=<reason>
created_on=<created_on>
expires_on=<expires_on>
```

For the example receipt above, the checksum can be generated with:

```bash
printf 'version=1\naction=push\ncategory=dependency\nfingerprint=dependency-lock-missing-integrity:package-lock.json:41\nowner=yoav\nreason=Temporary exception while regenerating the lockfile on the release branch.\ncreated_on=2026-04-09\nexpires_on=2026-04-16\n' | git hash-object --stdin
```

The resulting hash goes into the `checksum` field exactly as printed.

Wolfence now exposes the same calculation directly:

```bash
cargo run -- receipt checksum .wolfence/receipts/allow-secret.toml
```

You can also evaluate whether one receipt is currently active or ignored under
the repo's current trust model:

```bash
cargo run -- receipt verify .wolfence/receipts/allow-secret.toml
```

When a receipt is no longer needed, archive it instead of deleting it:

```bash
cargo run -- receipt archive .wolfence/receipts/allow-secret.toml "underlying issue resolved"
```

## Failure Modes

Wolfence ignores a receipt when:

- a required field is missing
- the version is unsupported
- the action is unsupported
- the category is unsupported
- the dates are malformed
- the expiry is earlier than the creation date
- the receipt is expired
- the checksum does not match
- multiple active receipts target the same action and fingerprint

When signed receipts are required, Wolfence also ignores a receipt when:

- `reviewer` is missing
- `reviewed_on` is missing
- `reviewed_on` is malformed
- `approver` is missing
- `key_id` is missing
- `signature` is missing
- `key_id` does not match a trusted public key in `.wolfence/trust/`
- signature verification fails
- the repo approval policy rejects the receipt category, reviewer, approver, or lifetime

Ignored receipts do not weaken enforcement. They simply fail closed and appear
as receipt issues in `wolfence doctor` and protected push output.

## Operational Guidance

- Keep receipts short-lived.
- Prefer fixing the underlying issue over adding a receipt.
- Commit receipts when they represent a team-reviewed exception.
- If the repo adopts signed receipts, commit the matching public keys under `.wolfence/trust/`.
- Remove receipts as soon as the underlying condition is resolved.
- Run `cargo run -- doctor` after adding or editing receipts.

## Signed Receipts

See `docs/security/trust-store.md` for the trust-store model and the canonical
signature payload.

If the repository already publishes the matching trusted public key, Wolfence
can sign the receipt for you in place:

```bash
cargo run -- receipt sign .wolfence/receipts/allow-secret.toml security-team security-team /path/to/security-team-private.pem
```
