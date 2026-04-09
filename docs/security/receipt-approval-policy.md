# Receipt Approval Policy

## Purpose

Receipts are an exception path. That means the repository should be able to say
who may review them, who may approve them, and how long they may live.

Wolfence models that governance through:

```text
.wolfence/policy/receipts.toml
```

## Current Keys

### `require_explicit_category`

When `true`, Wolfence rejects legacy receipts that rely on fingerprint-prefix
inference instead of storing an explicit `category` field.

This is the clean migration switch once a repository wants all active receipts
to be fully category-bound.

### `require_signed_receipts`

When `true`, Wolfence requires signed receipts even if the repository has not
yet adopted the trust-store-driven global signed posture.

This is useful when one repository wants to make signatures mandatory by policy
instead of waiting for every receipt workflow to depend on the mere presence of
trusted keys.

### `max_lifetime_days`

Optional maximum number of days between `created_on` and `expires_on`.

If a receipt exceeds that bound, Wolfence ignores it.

### `require_reviewer_metadata`

When `true`, every active receipt must include:

- `reviewer`
- `reviewed_on`

### `allowed_reviewers`

Optional allowlist of identities permitted in the receipt `reviewer` field.

If the list is non-empty, receipts without a reviewer are ignored.

### `allowed_approvers`

Optional allowlist of identities permitted in the signed receipt `approver`
field.

If the list is non-empty, receipts without a valid matching approver are
ignored.

### `allowed_key_ids`

Optional allowlist of trusted key ids permitted in the receipt `key_id` field.

If the list is non-empty, receipts without a matching signing key id are
ignored even if the key itself exists in `.wolfence/trust/`.

## Example

```toml
require_explicit_category = true
require_signed_receipts = false
max_lifetime_days = 14
require_reviewer_metadata = true
allowed_reviewers = ["security-team", "repo-owner"]
allowed_approvers = ["security-team"]
allowed_key_ids = ["security-team"]

[categories.secret]
require_signed_receipts = true
require_reviewer_metadata = true
max_lifetime_days = 7
allowed_reviewers = ["security-team"]
allowed_approvers = ["security-team"]
allowed_key_ids = ["security-team"]
```

Category-specific sections override the repo-wide settings for that finding
class. This matters when secret or policy exceptions need tighter review than
dependency or configuration exceptions.

## Interaction With Signed Receipts

The receipt approval policy is separate from the trust store:

- `.wolfence/trust/*.pem` controls whether signed receipts are required
- `.wolfence/trust/*.toml` can further scope each trusted key to specific receipt categories
- `.wolfence/policy/receipts.toml` controls who may review or approve them

That means a receipt can now fail for multiple reasons:

- invalid checksum
- expired
- invalid signature
- signature is required by category policy but missing
- legacy category-less receipt format is rejected
- reviewer metadata missing
- reviewer not in the allowlist
- approver not in the allowlist
- signing key id not in the allowlist
- trusted signing key exists but is not trusted for the receipt category
- lifetime exceeds policy
- category-specific reviewer or approver rules reject the receipt

Wolfence fails closed in all of those cases.

## Operational Surfaces

Wolfence exposes this policy through:

- `cargo run -- init`
- `wolf config`
- `wolf doctor`
- `wolf receipt verify <receipt-path>`

Those commands should make it obvious whether governance rules exist and
whether receipts are being rejected because of them.
