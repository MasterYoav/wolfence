# Push Secret Reviewer Allowlist Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy allows only the `security-team` reviewer.
The receipt is present but names a different reviewer, so the override must be
ignored and the push must remain blocked.
