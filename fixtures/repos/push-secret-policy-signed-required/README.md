# Push Secret Signed Policy Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot whose secret receipt policy requires signed receipts. The receipt is
present but unsigned, so the override must be ignored and the push must remain
blocked.
