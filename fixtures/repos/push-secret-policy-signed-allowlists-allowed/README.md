# Push Secret Signed Allowlist Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy explicitly allowlists the approver and key
id used by a valid signed receipt. The push should therefore be allowed with
one applied override.
