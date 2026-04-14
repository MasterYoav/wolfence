# Push Secret Trust Signed Fixture

This repository adds a secret-bearing `.env` file on top of an upstream
snapshot that already contains trust material and a valid signed override
receipt. `wolf push` should therefore allow the push while still surfacing the
underlying secret finding in the raw report and recording one applied override.
