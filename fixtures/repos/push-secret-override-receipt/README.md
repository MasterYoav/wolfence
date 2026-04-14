# Push Secret Override Fixture

This repository intentionally contains a blocking `.env` file together with a
canonical active override receipt. `wolf push` should still surface the secret
finding in the raw report, but policy should allow the push and record one
applied override in the audit log.
