# Push Transport Failure Fixture

This repository is intentionally harmless from a policy perspective and has no
configured Git remote. `wolf push` should therefore allow the content, then
fail during transport and record a two-entry audit chain.
