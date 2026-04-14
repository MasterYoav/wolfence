# Push Secret Signed Key Disallowed Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy allowlists `security-team` for both the
approver and signing key id. The receipt is cryptographically valid, but it is
signed with the trusted `staging-team` key id, so policy must reject it and
the push must remain blocked.
