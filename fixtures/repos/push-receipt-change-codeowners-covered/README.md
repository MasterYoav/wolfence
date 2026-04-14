# Push Receipt Change With Covered CODEOWNERS Fixture

This repository modifies a Wolfence override receipt while CODEOWNERS does
cover `.wolfence` policy material. The push should still stay blocked because
the exception path itself changed, but it should not report missing CODEOWNERS
coverage for that path.
