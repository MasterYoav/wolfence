# Push Secret Trust Fixture

This repository carries the same secret override receipt as the unsigned
override fixture, but it also publishes repo trust material. That trust state
requires signed receipts, so the unsigned receipt must be ignored and the push
must remain blocked while recording one receipt issue in the audit trail.
