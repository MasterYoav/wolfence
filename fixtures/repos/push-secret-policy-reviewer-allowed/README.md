# Push Secret Reviewer Allow Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy requires reviewer metadata and restricts
reviewers to `security-team`. The receipt satisfies that policy, so the push
should be allowed with one applied override.
