# Trust Store

## Purpose

Wolfence treats override receipts as a bounded exception path, not a hidden
escape hatch.

Unsigned receipts are acceptable for a single developer repository, but they do
not provide strong tamper resistance. Once a repository publishes trusted
public keys, Wolfence upgrades the model:

- receipts must be signed
- signatures must match a trusted repo-local public key
- invalid or incomplete receipts are ignored

The trust store is what flips Wolfence from checksum-only exceptions to signed
exceptions.

Wolfence can also require signed receipts earlier through
`.wolfence/policy/receipts.toml`, including per-category policy such as
`[categories.secret] require_signed_receipts = true`. In that posture, the
trust store becomes a required dependency for any affected receipts rather than
just a repo-wide switch.

## Location

```text
.wolfence/trust/*.pem
.wolfence/trust/*.toml
```

Each `.pem` file is one trusted public key. The file stem becomes the receipt
`key_id`.

Wolfence also supports companion metadata files with the same stem:

```text
.wolfence/trust/security-team.toml
```

Current metadata keys:

- `owner`
- `expires_on`
- `categories` (optional)

An active trusted key now requires both fields.

If metadata is missing, incomplete, or `expires_on` is in the past, the key is
still treated as published trust material for doctor and policy posture, but it
is inactive for verification.

Example:

```text
.wolfence/trust/security-team.pem
.wolfence/trust/security-team.toml
```

This creates the trusted key id:

```text
security-team
```

Example metadata:

```toml
owner = "security-team"
expires_on = "2026-12-31"
categories = ["secret", "policy"]
```

Wolfence can create that metadata file for you once the `.pem` already exists:

```bash
cargo run -- trust init security-team security-team 2026-12-31 secret,policy
```

You can inspect the resulting trust posture with:

```bash
cargo run -- trust list
cargo run -- trust verify security-team
```

If a key has already been archived, `trust verify <key-id>` reports that
archived state and the recorded retirement reason instead of treating the key
as unknown.

When a signer key should no longer participate in live trust decisions, archive
it instead of leaving it under `.wolfence/trust/`:

```bash
cargo run -- trust archive security-team "rotation complete"
```

That moves the `.pem`, optional metadata, and a small archive note into:

```text
.wolfence/trust/archive/
```

If you need to recover the latest archived signer for the same `key_id`, use:

```bash
cargo run -- trust restore security-team
```

That moves the archived `.pem` and optional metadata back into `.wolfence/trust/`
and appends restoration metadata to the archive note so the recovery remains
reviewable.

## Activation Model

Signed receipts are not controlled by a separate config flag.

They become required automatically when Wolfence detects at least one published
trusted public key in `.wolfence/trust/`.

That means:

- `0` published trust keys: unsigned receipts are allowed
- `1+` published trust keys: signed receipts are required

Separately, only active trust keys can verify signatures:

- a key is active when it has a `.pem`, a matching `.toml`, an `owner`, and a non-expired `expires_on`
- a key is inactive when metadata is missing, incomplete, or expired
- a key may also be category-scoped through `categories = ["..."]`; if omitted, the key is active but unrestricted

This fail-closed transition is deliberate. The repository should not be able to
publish trust material and then silently keep accepting unsigned overrides.

Wolfence warns on unrestricted active keys in `doctor` because least-privilege
signers are safer than repo-wide signer authority.

## Receipt Requirements Under Trust

When signed receipts are required, each receipt must include:

- `approver`
- `key_id`
- `signature`

The `key_id` must match one of the trusted `.pem` file stems under
`.wolfence/trust/`.

If the trusted key declares `categories`, the receipt `category` must also be
listed there.

If the key is missing, unknown, or the signature does not verify, Wolfence
ignores the receipt and reports the issue.

## Signature Payload

Wolfence verifies receipt signatures over this canonical payload:

```text
version=1
receipt_id=<receipt_id>
action=<action>
category=<category>
fingerprint=<fingerprint>
owner=<owner>
reviewer=<reviewer>
reviewed_on=<reviewed_on>
approver=<approver>
key_id=<key_id>
reason=<reason>
created_on=<created_on>
expires_on=<expires_on>
checksum=<checksum>
```

This is intentionally separate from the checksum payload. The checksum still
protects receipt field integrity, while the signature binds the approver and
trusted key identity to the reviewed receipt contents.

## Example Signed Receipt

```toml
version = "1"
receipt_id = "wr_0123abcd4567"
action = "push"
category = "secret"
fingerprint = "secret:abc123"
owner = "yoav"
reviewer = "security-team"
reviewed_on = "2026-04-09"
approver = "security-team"
key_id = "security-team"
reason = "Temporary exception while rotating a leaked test credential."
created_on = "2026-04-09"
expires_on = "2026-04-16"
checksum = "REPLACE_WITH_COMPUTED_CHECKSUM"
signature = "REPLACE_WITH_HEX_SIGNATURE"
```

## Signing Flow

1. Compute the checksum exactly as documented in `override-receipts.md`.
2. Build the canonical signed payload exactly in this order:

```text
version=1
receipt_id=wr_0123abcd4567
action=push
category=secret
fingerprint=secret:abc123
owner=yoav
reviewer=security-team
reviewed_on=2026-04-09
approver=security-team
key_id=security-team
reason=Temporary exception while rotating a leaked test credential.
created_on=2026-04-09
expires_on=2026-04-16
checksum=<computed-checksum>
```

3. Sign that payload with the private key that matches
   `.wolfence/trust/security-team.pem`.
4. Hex-encode the detached signature and place it in the receipt `signature`
   field.

One possible shell flow is:

```bash
printf 'version=1\nreceipt_id=wr_example123456\naction=push\ncategory=secret\nfingerprint=secret:abc123\nowner=yoav\nreviewer=security-team\nreviewed_on=2026-04-09\napprover=security-team\nkey_id=security-team\nreason=Temporary exception while rotating a leaked test credential.\ncreated_on=2026-04-09\nexpires_on=2026-04-16\nchecksum=<computed-checksum>\n' > /tmp/wolfence-receipt-payload.txt
openssl dgst -sha256 -sign /path/to/security-team-private.pem -out /tmp/wolfence-receipt-signature.bin /tmp/wolfence-receipt-payload.txt
xxd -p -c 4096 /tmp/wolfence-receipt-signature.bin
```

The final hex output from `xxd` is the value for the receipt `signature`
field.

Wolfence can perform that workflow directly once the matching trusted public
key already exists under `.wolfence/trust/`:

```bash
cargo run -- receipt new .wolfence/receipts/allow-secret.toml push secret secret:abc123 yoav 2026-04-16 "Temporary exception while rotating a leaked test credential."
cargo run -- receipt verify .wolfence/receipts/allow-secret.toml
cargo run -- receipt sign .wolfence/receipts/allow-secret.toml security-team security-team /path/to/security-team-private.pem
cargo run -- receipt verify .wolfence/receipts/allow-secret.toml
```

That command first checks the repo's receipt approval policy for the receipt
category, approver identity, signing key id, and trusted key category scope. It then recomputes the
checksum, signs the canonical payload, verifies the fresh signature against the
trusted public key, and only then updates the receipt file in place. It also
records reviewer metadata in the receipt so the approval trail is visible
without re-deriving it from filenames or commit history.

## Verification Runtime

Wolfence currently verifies signatures through the local `openssl` executable.

Operational implications:

- `wolf doctor` checks whether `openssl` is available
- if signed receipts are required and `openssl` is unavailable, doctor fails
- if signed receipts are not yet required, missing `openssl` is only a warning

This keeps the enforcement model honest about its external runtime dependency.

## Operational Guidance

- Commit trusted public keys so the repo-level trust model is reviewable.
- Commit companion metadata so key ownership and expiry are reviewable too.
- Keep the trusted key set small and intentional.
- Rotate or remove keys when the approver set changes.
- Archive retired keys so they stop affecting live trust posture.
- Expire keys deliberately instead of letting them live indefinitely.
- Treat trust-store changes like policy changes and review them carefully.
- Run `cargo run -- doctor` after adding or removing trusted keys.

## Failure Modes

Wolfence ignores a signed receipt when:

- `approver` is missing
- `key_id` is missing
- `signature` is missing
- `key_id` does not match a trusted public key
- signature verification fails

Ignored receipts do not weaken enforcement. They simply fail closed and show up
in doctor output and protected push output.
