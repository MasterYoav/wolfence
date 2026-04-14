# Push Secret Reviewer Policy Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy requires reviewer metadata. The receipt is
present but missing reviewer fields, so the override must be ignored and the
push must remain blocked.
