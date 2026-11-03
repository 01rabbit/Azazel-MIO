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
record. Form the source archive with an explicit archive umask (for example,
`git -c tar.umask=0022 archive`), and fix the build backend, `SOURCE_DATE_EPOCH`,
and process umask. The consumer must record the exact values and verify the
resulting artifact hash. Do not publish local-version artifacts as public
releases or replace an existing artifact in place.

## Current integration identity example (2026-11-04)

At MIO main `e4a0e504bae91153f3dcb8105f8658ff80d4e884`, `pyproject.toml`
declares `0.1.0+git.c31c244`. PR #41's source head
`b441d431532507387fb81f1e03e31fd1aea57b68` and the merge commit have the same
source tree `f879a97422f14aeca0c6cee75e97cb4b5268a747`. The suffix refers to
the real commit `c31c2442899e778f1c49e5becd739c59ef8f1092` (PR #40), from which
the package source files were carried forward. Comparing `c31c244` with the
PR #41 source head shows changes only to `pyproject.toml` and this versioning
document; `src/` and `tests/` are unchanged. Thus the suffix names a source-code
baseline/local build label, not the full wheel source commit or merge SHA.
Consumers must continue recording the full source commit/tree and reproducible
build/artifact identity in their own lock and verification record. This example
does not declare a public release, package publication, or deployment.

Use a new pre-release or release version when the project intentionally cuts a
new distribution milestone. Do not increment the product version mechanically
for every commit. For this 0.x package, compatibility-breaking changes require
an explicit migration note and a new minor line; compatible fixes and additive
features are grouped into the next planned release unit.
