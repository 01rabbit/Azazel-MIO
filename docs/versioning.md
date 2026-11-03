# Package version and build identity

`pyproject.toml` is the package-version source of truth. A public release uses
the project's release version and an immutable tag; development and integration
artifacts must not reuse a wheel filename when their contents differ.

For a source-built integration candidate that contains the same product
behavior as a reviewed source snapshot but has no new public release, use a
PEP 440 local version such as `0.1.0+git.c31c244`. The `0.1.0` portion remains
the product compatibility line; the local suffix distinguishes this wheel from
other builds on that line. Record the complete source commit, source tree,
build environment, and artifact SHA-256 in the consuming lock and verification
record. Do not publish local-version artifacts as public releases or replace
an existing artifact in place.

Use a new pre-release or release version when the project intentionally cuts a
new distribution milestone. Do not increment the product version mechanically
for every commit. For this 0.x package, compatibility-breaking changes require
an explicit migration note and a new minor line; compatible fixes and additive
features are grouped into the next planned release unit.
