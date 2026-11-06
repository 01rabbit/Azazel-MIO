# Package version and build identity

`pyproject.toml` is the package-version source of truth. A public release uses
the project's release version and an immutable tag. Development and integration
records must distinguish source/version identity from exact wheel identity:
independent builds may share a filename without producing identical bytes.

For a source-built integration candidate that contains the same product
behavior as a reviewed source snapshot but has no new public release, use a
PEP 440 local version such as `0.1.0+git.c31c244`. The `0.1.0` portion remains
the product compatibility line; the local suffix labels an implementation
baseline rather than the complete wheel identity. Record the complete source commit, source tree,
declared package version, build environment, and actual artifact SHA-256 in the
consumer's verification record or offline lock, as applicable. To reproduce
the canonical wheel, form the source archive with an explicit archive umask
(for example,
`git -c tar.umask=0022 archive`), and fix the build backend, `SOURCE_DATE_EPOCH`,
and process umask. Record those inputs and the resulting artifact hash;
the consumer-specific acceptance requirements below determine whether that
hash must equal the canonical wheel's. Do not publish local-version artifacts
as public releases or replace an existing artifact in place.

## Current candidate artifact (2026-11-06)

MIO main is `57464216a08456d1b97ef292f7558c21b0ff0b34`; its metadata remains
`0.1.0+git.c31c244`. MIO #47 is unmerged and has a separate development identity:

| Field | Canonical candidate value |
| --- | --- |
| Consumer source pin / MIO #47 head | `a1807bf7abb08788b834ae038f7a8b46d09d0acc` |
| Implementation source label | `bb6dcfdaa731e939da0fc29be212bb2b5851009f` |
| Package version | `0.1.0.dev20261106+gitbb6dcfd` |
| Wheel filename | `azazel_mio-0.1.0.dev20261106+gitbb6dcfd-py3-none-any.whl` |
| Canonical wheel SHA-256 | `cb67a8c00f9011b0accd14a9901298d29dd0eb30b036e9af8c1ec5b5878356ff` |

The canonical build uses setuptools `84.0.0`, `SOURCE_DATE_EPOCH=1793887544`,
archive/process umask `0022`, and an offline build with no build isolation or
dependency resolution. The version suffix identifies the implementation
baseline, while the complete consumer pin identifies the metadata commit.
The canonical SHA-256 above identifies the recorded candidate wheel; it does
not identify every wheel built from the same source/version or grant runtime
authority. Earlier `context1` and `gitb333657` candidate artifacts do not
represent this tuple.

The two consumer candidates have different artifact acceptance requirements:

- **Edge #538:** accept the exact VCS source commit and declared package
  version, checking installed `direct_url.json` VCS provenance against the pin
  and recording the actual build provenance. Its pip-built wheel may have a
  different hash; canonical wheel byte equality is not an Edge acceptance
  requirement. A matching version string alone is insufficient, and this
  source/version acceptance does not prove canonical wheel reproducibility.
- **Nexus #405:** its offline lock requires the exact canonical wheel above.
  Verify the wheel bytes against that SHA-256 and preserve the offline build
  lock and provenance. Matching source/version alone does not satisfy this
  artifact requirement.

Edge main `3e6ccf4d3cffdf0d101c69392c3f7a9cc1a65f0c` still pins MIO
`9fedb01bc9936531407a5181aa8fa5553ec19d55`. Unmerged Edge #538
(`df98300f08a294f33482ef13579192447c9d0ac0`) and Nexus #405
(`28900ebec35acdb618776340bfdc3065725d12bf`) pin MIO `a1807bf7` above.
Fabric stable is `v0.10.0`; Edge, Knowledge, Deception and Nexus's optional
`fabric` extra declare it; Gadget remains on `v0.9.0`. Fabric Knowledge
Context v1 remains experimental after #86. Nexus #402/#403 are merged
software integrations with a default-disabled, uncommissioned Context broker;
Knowledge #116, MIO #47 and Nexus #405 remain unmerged candidates. No public
MIO release, product deployment, HG acceptance or production admission is
implied. Older fixed-head examples and process results below and in the
[inventory](architecture/ai-inventory.md) remain historical and were not rerun.

## Historical integration identity example (2026-11-04)

At MIO main `5bb09c8d28c57604dc1c63903b98fed7587b49ea` (tree
`75b20e000a0be2dad1c9aae3219e5cf5f14700bf`), the base of Draft PR #42, `pyproject.toml` still declares
`0.1.0+git.c31c244`. PR #43 changed `src/`, `tests/` and `CHANGELOG.md` but
no package version or dependency pin. PR #44 adds a developer-only local model
smoke tool and documentation; PR #45 adds a bounded metadata-only measured
transport wrapper and API documentation. Neither changes the package version
or dependency pins. Before PR #43, main
`4d92b4451a3bf1ec44eb7215ebadb0fd05879c1d` (docs-only PR #39) kept
`pyproject.toml`, `src/`, and `tests/` unchanged from PR #41's merge. PR #41's source head
`b441d431532507387fb81f1e03e31fd1aea57b68` and merge commit
`e4a0e504bae91153f3dcb8105f8658ff80d4e884` have the same source tree
`f879a97422f14aeca0c6cee75e97cb4b5268a747`. The suffix refers to
the real commit `c31c2442899e778f1c49e5becd739c59ef8f1092` (PR #40), from which
the package source files were carried forward. Comparing `c31c244` with the
PR #41 source head (historical comparison) shows changes only to `pyproject.toml` and this versioning
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
