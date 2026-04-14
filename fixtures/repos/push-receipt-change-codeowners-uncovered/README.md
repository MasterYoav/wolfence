# Push Receipt Change With Uncovered CODEOWNERS Fixture

This repository modifies a Wolfence override receipt while CODEOWNERS exists
but does not cover `.wolfence` policy material. The push should stay blocked by
the changed receipt itself and also report the missing governance coverage.
