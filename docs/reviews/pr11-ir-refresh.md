# PR 11 offline IR refresh candidate

Additive standalone offline evidence utility, separate from MIO reasoning. Current package exports are retained; this branch registers the `mio-ir` console script and assigns a unique development version. No network, elevation, model or production actions.

## Historical: exact sources before changes

- Base c6a0e0d6ef589693bc7bd54a4c2c1cdf32371524; tree 2943cc80691148d63f71200198f661bf71462ee1.
- PR11 head 9debcfdf504ee580f8bf3b2ab061b87eed111540; tree 977a453d74aca810c4419ab11064a877aec7a973.
- Historical base 6302e665c3ac6cf7004407965299d81dc9ddfc8a.
- PR15 head 6df0d75c1ebf835dd9b3d764300c6743335174ce; tree 7d93bb9e9753ca5853e6043653aecedbfd471c9b.

No AGENTS.md in the fresh checkout. Inspected the historical PR11 six-file diff and PR15 source. Restored a distinct CLI, synthetic fixture, tests and deployment guide; integrated the then-current pyproject rather than old packaging or initializer.

## Historical findings

IR11-01 (medium): a pre-existing objects symlink redirected imports outside the store; root/database symlinks aliased storage. Reproduced with the old CLI and synthetic data. Reject these entries and mark verification invalid for a symlinked object directory. Tests: `test_storage_symlinks_rejected`, `test_database_symlink_rejected`.

IR11-02 (medium): the original export guard allowed SQLite sidecar overwrite and outside hardlinks to internal evidence/database inodes. Reject exports anywhere inside private storage and atomically replace external exports using private temporary files. Tests: `test_report_cannot_overwrite_internal_journal`, `test_report_hardlink_does_not_truncate_evidence`.

## Historical plan and validation

Restore standalone slice, fix above concrete issues, run focused tests then full suite because package metadata changed. macOS Python 3.12.14:

- python3.12 -m venv .venv: exit 0.
- .venv/bin/python -m pip install -e .: exit 0.
- .venv/bin/python -m unittest discover -s tests -p test_ir_workflow.py -v: exit 0, 9 passed.
- .venv/bin/python -m unittest discover -s tests -v: exit 1, 3 import errors due to absent pytest, 44 tests collected.
- .venv/bin/python -m pip install pytest: exit 0.
- .venv/bin/python -m pytest tests/test_ir_workflow.py -q: exit 0, 9 passed.
- .venv/bin/python -m pytest -q: exit 0, 297 passed, 36 subtests passed.
- .venv/bin/mio-ir --help: exit 0.
- git diff --check and git diff --cached --check: exit 0.

No pytest skips/warnings reported for this historical candidate. Validation logs
were kept outside the repository and are not part of this PR. Synthetic evidence only.

## Historical limitations

Debian ARM64 guest not validated. Not forensic WORM storage. User must control private storage and parent directories; concurrent hostile filesystem mutation remains outside this utility boundary. JSON/JSONL mapping, hashes, case isolation and SQLite behavior preserved; reports now require export outside store. At the time of this historical pre-rebase snapshot, no existing PR branch had been rewritten or pushed.

## Historical IR11-03 follow-up

IR11-03 (high): an existing hardlinked database
paths allow SQLite initialization and case writes to mutate an outside inode.
Before SQLite open, lstat now requires an existing database to be a regular file
with exactly one link. Regression tests use an empty outside file hardlinked as
cases.sqlite3, verify connect never calls SQLite, invoke case create and check
exit 1 with unchanged outside bytes; a FIFO test verifies nonregular rejection.
Concurrent hostile path swaps remain outside the documented filesystem boundary.
The existing report hardlink test now targets stored evidence, since database
hardlinks are intentionally rejected before report dispatch.

Follow-up validation on Python 3.12.14: initial focused/full runs exited 1 solely
because the old report regression expected database hardlinks to remain usable
(10 passed / 298 passed plus 36 subtests respectively). After adapting that
regression to an evidence hardlink, focused tests exited 0 (11 passed); full
suite exited 0 (299 passed, 36 subtests passed), with no warnings or skips.
Both git diff --check and staged diff check exited 0.

Reviewer commands from an environment with this checkout installed and pytest available:

```sh
python -m pytest tests/test_ir_workflow.py -q
python -m pytest -q
```

Alternatively create a new Python 3.12 virtual environment outside the checkout,
install this checkout with `pip install -e .` and install pytest. No virtual
environment or local test log is committed.

## Historical current-main rebase candidate — 2026-11-05 (superseded below)

All hashes and test totals before this historical checkpoint are superseded.
MIO main at that time was
`5bb09c8d28c57604dc1c63903b98fed7587b49ea`. At that earlier snapshot, the
PR #11-only diff was six files:
`deploy/standalone-vm/README.md`, `docs/reviews/pr11-ir-refresh.md`,
`examples/synthetic_ir_case/events.jsonl`, `pyproject.toml`,
`src/azazel_mio/cli.py`, and `tests/test_ir_workflow.py`. Current main exports
are retained. The candidate registers the `mio-ir` console script and assigns
a distinct development version in `pyproject.toml`.

## Historical independent review findings and disposition

Claude Code Haiku/low's first review of `611e893` was incomplete because it did
not read all of `cli.py`. A later review read all six changed files at
`6da9e93c9f2fdf7ac67541176c6485a11af198d9`; it had no High/blocking code
finding and raised four Low/Medium issues. A final review of the then-current
`6b27c86dd99294ff4797702c40ee72e25fb659c1` read all six files and found five
Low items, with no High/blocking finding. Their dispositions are:

- F1 (`text.splitlines()` split valid JSONL strings containing U+2028/U+0085):
  now split only on LF and strip an optional CR, with regression cases
  (`parse_records`, `test_jsonl_keeps_unicode_separators_inside_strings`).
- F2 (recursive `str()` on an object-valued summary could raise): non-scalar
  summaries are rejected before string conversion, covered
  by `test_nested_summary_is_a_clean_input_error`.
- F3 (existing file mode bits were not checked): directory modes are enforced;
  existing database, sidecar, and object mode bits remain unchecked and
  unchanged; newly stored objects are created with mode `0400` inside the
  private `0700` storage directory.
- F4 (test totals were tied to an earlier commit): the then-current executable
  source and test commit was `599ff221dfc8f34df06adfc48d1788802fdc18cb`, tree
  `2daa3e9bbe3a1627d7e556bbdbb6bcde37b02892`; later sections supersede it. This
  document was a following documentation-only update; the PR description then
  recorded the final PR head and
  the tested source commit separately.
- F5 (`report generate` returned success with invalid evidence): it writes
  the report, then exits 3 if any evidence failed verification. The regression
  verifies the JSON result and exit code.
- Prior storage findings remain fixed: existing directories are never chmodded;
  DB and SQLite sidecars are checked before open; imported and verified objects
  reject symlinks, hardlinks, FIFOs, nonregular entries and foreign ownership;
  directories require current-user ownership/private mode; deep JSON is a clean
  error. Owner validation fails closed without POSIX UID support.
- The guest guide preinstalls `setuptools>=77.0.3` and `wheel` from a local
  offline wheelhouse, uses `--no-index`, and exports reports into a private
  `mktemp` directory. It states Python `>=3.11`.
- Duplicate byte imports intentionally create separate evidence receipts/event
  sets while storing one SHA-256 object; README and regression coverage agree.
- The docs name all changed files, separate historical evidence, and contain no
  private `.git` log paths.

Validation on the then-current source/test commit `599ff221dfc8f34df06adfc48d1788802fdc18cb`
(tree above), based on the then-current main: focused IR workflow **27 passed / 11
subtests passed**; full MIO suite **672 passed / 254 subtests passed**, CPython
3.12.14, exit 0. The README offline editable-install procedure was exercised
from the same source commit in a disposable Linux arm64 / Python 3.12 Docker
container (`--rm --network=none`): `mio-ir --help` succeeded and installed
version was `0.1.0+git.c31c244`. No distributable wheel was published.

This historical source snapshot was not the final refreshed candidate. Debian
ARM64 guest acceptance remained separate and had not been run.

## Historical independent review fixes and validation — 2026-11-05 (superseded below)

The earlier statement that final independent review was pending referred to the
`599ff221` source snapshot and is superseded here. Claude Code Haiku/low reviewed
that then-current-main candidate and raised the following findings:

- Medium: JSONL record limits were checked after `split()` allocated every line;
  JSON arrays were fully decoded before checking record count.
- Low: timezone conversion could raise `OverflowError`; explicit null summary
  rendered as `None`; storage path fallback accepted an empty/relative value;
  object verification read the entire file; invalid UTF-8 fields could leave an
  orphaned object; timestamps were not length-bounded; and invalid-evidence exit
  status overlapped argparse usage errors.
- Low: the hardlink report test did not first prove that its source evidence was
  valid. The review also identified documentation overclaims about determinism
  and imprecise summary semantics.

The reviewed recommendations were applied in source commit
`dc6eba670601bb12438504f8a875c8531bb96f8f` (tree
`ec4da2199712ed8e3506707b2b9819636c4bbfb6`). Parsing now enforces the record
limit incrementally; summaries and timestamps have explicit bounds and strict
UTF-8 handling; null is represented as an empty summary while an omitted value
keeps its default; overflow timestamps remain unknown; object reads are bounded;
invalid evidence exits 3 while argparse usage errors retain 2; and empty,
relative, or unavailable default storage paths fail clearly. Regression tests
cover each disposition. The README describes these limits and fail-closed
behavior. Candidate package metadata is now
`0.1.0.dev20261105+ir11r2`, rather than reusing a version string from a
previous local build.

Validation for the exact source commit/tree above:

- Self-contained Git archive, Docker `python:3.12-arm64-c65`, Python 3.12,
  `pytest==8.4.2`, full suite: **687 passed**, exit 0. The archive was mounted
  read-only and copied to the container's ephemeral `/tmp` because two existing
  tests intentionally create `.codex-work` below the source root. Docker was
  run with `--rm`; suite execution used the workspace's existing serialized
  test lock. The command inside the container was
  `PYTHONPATH=src python -m pytest -q -p no:cacheprovider`.
- ARM64 wheel build from that archive, installed into the same disposable
  container: `mio-ir --help` succeeded and metadata reported
  `0.1.0.dev20261105+ir11r2`. Wheel SHA-256:
  `e677241bc62bffe155f911142934163273c57240a1a5b424e620cdf11fc13663`.
  This local test artifact is not published.
- Two harness attempts are retained separately: the first lacked pytest in the
  base image; the second exposed the read-only source assumption in two tests.
  Neither result is counted as a passing test run. The successful third run
  used the writable ephemeral copy described above.

Debian ARM64 guest acceptance remains outstanding. The refreshed candidate has
not yet been pushed and remained a Draft PR candidate. The then-current main
base was
`5bb09c8d28c57604dc1c63903b98fed7587b49ea`; the former remote PR head is
`a5b74ec256e21a8314ff378ab95f4d31dfb397a`.

## Historical final-candidate independent review follow-up — 2026-11-05 (superseded below)

Claude Code Haiku/low independently read the complete six-file candidate at
`b62fdc853f2e7a0dd59005459b628f27312bb215`. No High or Medium finding was
reported. The reviewer could not verify Git object identity because it had only
read tools; this coordinator verified the base, HEAD, tree, parent, and changed
file list locally. No reviewer tests were run. The returned low findings were
checked against source and handled as follows:

- Markdown report summaries now replace both CR and LF with spaces; a CLI
  regression covers a CR followed by heading syntax.
- The offline-size tests now intercept `Path.open` and assert the oversized
  object path is never opened (rather than patching the unused `read_bytes`).
- The guide captures the created `case_id` from JSON and uses it for later
  commands, so an existing store cannot redirect the example into case 1.
- The guide now documents summary truncation (with original bytes retained),
  offset-bearing ISO string timestamps (naive timestamps remain unknown),
  rejection of overlong timestamps, empty JSONL,
  empty JSON/BOM rejection, per-import record numbering, and markdown line
  sanitization. It also documents that output paths are resolved, so an external
  symlink points to the destination replaced atomically.
- Stale review references now identify code locations for that candidate; invalid evidence
  is documented as exit 3; the review-record opening distinguishes retained
  exports from the new command; `pyproject.toml` sets the candidate version.
- Markdown summaries escape CommonMark punctuation as well as normalizing
  CR/LF. The CLI closes the SQLite connection after commit. The report hardlink
  regression confirms the object is invalid due to its link count before
  invoking report generation.
- Added regression cases for summary truncation with raw-object preservation,
  empty JSONL versus empty JSON, BOM rejection, markdown injection, and naive
  timestamps.

The refreshed source/test commit is
`2f1818acabcea8ac14d449a24eb2c13e58fc44e0` (tree
`db4fc38f6da29a9206ce255e06d001e27f7dc174`). Its package version was bumped
from `0.1.0.dev20261105+ir11r2` to
`0.1.0.dev20261105+ir11r3` before the final wheel build, so the artifact filename
identifies this content. Exact-source validation used a
self-contained Git archive copied into a disposable Docker `python:3.12-arm64-c65`
container, `pytest==8.4.2`, and the serialized suite lock: **693 passed**, exit
0. A wheel built from the same archive installed successfully in Linux ARM64 /
Python 3.12; `mio-ir --help` succeeded, the installed version was
`0.1.0.dev20261105+ir11r3`, and the wheel SHA-256 was
`4415b2c8b562b1272ffb5e7d2c23014b4f0d5f7de1a15a6a1123f8f6a16965c8`.

The candidate has no cumulative per-case evidence or event count limit; timeline
and report generation load all case events. Input bounds are per imported file.
That read-only review found no High/Medium issue but led to the fixes
recorded above; it did not run tests or verify Git object identities.
Debian ARM64 VMware guest acceptance remains pending and is independent of this
Linux ARM64 container check.

## Prior review refinements and validation (source 2f1818a; historical)

A second Claude Code Haiku/low read-only review of the then-current candidate
reported no High/Medium issues and six Low items. Its findings and dispositions:

- Markdown punctuation in untrusted summaries could create links, emphasis, or
  raw HTML in a rendered report. The CLI now escapes CommonMark punctuation
  after replacing CR/LF; regressions cover heading-like CR input and link/HTML/
  emphasis/code syntax.
- The candidate version was reused across wheels with different contents. The
  tested source commit below uses the distinct `+ir11r3` development version;
  only the earlier `+ir11r2` artifact predates it. Both local artifacts remain
  in separate evidence directories with their own hashes and are historical
  only. The then-current wheel uses the filename for `+ir11r3` and its hash
  below.
- The document opening now distinguishes retained exports from the new
  console-script and development-version metadata. The CLI module docstring now
  says event timestamps come from input records. Import/report timestamps are
  generated at processing time.
- Limits are explicitly per input file. There is no cumulative per-case event or
  evidence cap, and timeline/report materializes the case's events; this remains
  a documented local-tool limitation.
- Naive timestamps without a UTC offset remain unknown and are documented.
- SQLite connections are closed after transaction commit. The hardlink report
  test asserts that verification sees the linked object as invalid before
  report generation; the exit 3 is due to object link-count validation, while
  the test also confirms atomic output replacement preserves evidence bytes.

The exact tested source/test commit is
`2f1818acabcea8ac14d449a24eb2c13e58fc44e0` (tree
`db4fc38f6da29a9206ce255e06d001e27f7dc174`), package version
`0.1.0.dev20261105+ir11r3`. From a self-contained Git archive in Docker
`python:3.12-arm64-c65`, Python 3.12, `pytest==8.4.2`, serialized by the suite
lock, the full suite passed: **693 passed**, exit 0. The matching ARM64 wheel
was installed in a disposable container; its `mio-ir --help` succeeded and its
SHA-256 is
`4415b2c8b562b1272ffb5e7d2c23014b4f0d5f7de1a15a6a1123f8f6a16965c8`.

The packaged README workflow also passed in that container using only synthetic
fixtures: create a case and parse its returned ID, import the five-record JSONL,
verify evidence, build its timeline, and generate a nonempty JSON report. No
real evidence or credentials were used; the wheel remains local and unpublished.

The review did not run tests or validate commit identities. It did not report a
High/Medium defect. Debian ARM64 VMware guest acceptance remains outstanding.

The review of the prior `bc28645` candidate returned three Low items and
informational notes. The escape set is now all ASCII punctuation via
`string.punctuation`, with regressions for tilde, ampersand, colon, links, raw
HTML, emphasis and code. Candidate version history now states that only the
`+ir11r2` wheel preceded `+ir11r3`; the then-current `+ir11r4` identified new source
content. The record removes the local absolute suite-lock path, corrects
timezone wording, and documents missing Markdown timestamps as `unknown`.
The `docs/versioning.md` scheme distinguishes an integration wheel built from
an unchanged reviewed snapshot (`+git.<commit>`) from a development candidate
that changes behavior; this candidate uses a PEP 440 `.dev` version with a
unique local label. ARM64 wheel build/install confirms the metadata is accepted.

Final source/test commit:
`b3574603fd5be7a9ee5cb1fcb65fa89aa1956c15` (tree
`9187f1bbfb891379afd2002fc6bb6bd577fc9f63`), version
`0.1.0.dev20261105+ir11r4`. Self-contained Git archive, Docker
`python:3.12-arm64-c65`, Python 3.12, pytest 8.4.2, full suite: **695 passed**,
exit 0. The wheel was installed and `mio-ir --help` succeeded; SHA-256:
`be2260d95df38db5aee3a59e45d45dc0d2e8efd6dd609daff9b2abb39351f9f7`. The
documented five-record create/import/verify/timeline/report workflow also
completed successfully with synthetic input. These results are for the exact
source commit above; this record's final docs-only commit is not executable test
input. Debian ARM64 VMware guest acceptance remains outstanding.

## Historical review findings and validation (source d69cbbe; superseded below)

Claude Code Haiku/low's read-only review of candidate `e050cf4` reported no
High/Medium issue and four Low findings. The record's prior `2f1818a` / `r3`
section is historical and is not current evidence. Dispositions:

- Rewrote the historical section heading to identify its source revision.
- Documented that newly created objects use mode `0400`, while existing
  database, sidecar, and object modes are not checked or changed; access relies
  on ownership and the `0700` storage directory.
- JSONL now skips only empty, ASCII-space-only, or tab-only lines. Unicode
  whitespace-only lines are rejected by the JSON parser; regressions cover
  U+2028 and U+00A0. The guide says the same.
- The successful `main()` connection close is now tested; schema setup failure
  continues to close the connection as well.

The then-final source/test commit was
`d69cbbe061ef4ea486f2fc7811d22346d3700aeb` (tree
`52db1cf1c2150ba06a0c90d0cf765fbe234ab7b9`), version
`0.1.0.dev20261105+ir11r5`. On the self-contained Git archive in Docker
`python:3.12-arm64-c65`, CPython 3.12 and pytest 8.4.2, the full suite passed:
**697 passed**, exit 0. The matching ARM64 wheel built and installed, and
`mio-ir --help` succeeded. Wheel SHA-256:
`ef72995953528290ebc1192593fa59a0c210d2372dd9937f82f91f6a8ac21ef1`.
The documented synthetic create/import/verify/timeline/report workflow passed
on that installed wheel. No real evidence was used and no artifact was
published. These tests do not establish Debian ARM64 VMware guest acceptance.

## Final candidate validation — 2026-11-05

Independent review of exact candidate `e17c7129bafd223cb92a6502b5da38c8bf4e29cd`
(base `5bb09c8d28c57604dc1c63903b98fed7587b49ea`) found two Medium and five
Low findings, plus one Info. Both Medium findings were fixed:

The independent follow-up on `59fb7785108b5ec00ae8ea6d8ba32ac6bae4c221`
found no High/Medium findings. It noted remaining low-level coverage and
wording gaps; the final review-limit section, emoji-path regression test and
subshell-wrapped README commands address those points.

- IR-01: Three mutation tests identified by review modified new `0400` objects
  without making them writable, so root could mask a permission failure. The
  mutation tests now set `0600` explicitly. Full tests were rerun as uid 1001.
- IR-02: Markdown summary rendering now replaces C0/C1 controls, line
  separators and bidi controls before escaping punctuation. Regression coverage
  includes ESC, NUL, bidi override and U+2028. README no longer claims this is a
  universal Markdown sanitizer.

Low findings were addressed or bounded:

- IR-03: Output containment now walks ancestors with `samefile`, covering
  case-insensitive filesystem aliases. Its regression test passed on macOS;
  it is skipped on a case-sensitive filesystem.
- IR-04: The foreign-owner test now uses a nonexistent path and exercises the
  new-directory branch, checking the created mode is `0700` before rejection.
- IR-05: README shell setup now uses `set -euo pipefail` and checks the case ID;
  a broken sentence was fixed. `MIO_IR_HOME` is described accurately: expand
  `~`, require an absolute path, and do not canonicalize it.
- IR-06: CLI JSON status output uses ASCII escapes so a non-ASCII local path
  cannot make printing fail after an atomic report replacement. A regression
  test checks an emoji path round-trip and escaped stdout.
- IR-07: The review record now has an explicit `Review limits` section for
  guest/hardware and downstream-renderer coverage boundaries.

Current MIO main/base is `5bb09c8d28c57604dc1c63903b98fed7587b49ea`. The final
candidate changes seven files: `.gitignore`, `deploy/standalone-vm/README.md`,
`docs/reviews/pr11-ir-refresh.md`, `examples/synthetic_ir_case/events.jsonl`,
`pyproject.toml`, `src/azazel_mio/cli.py`, and `tests/test_ir_workflow.py`.
Package source and metadata are fixed at commit
`0cfb0fea08a1449d1041ea54a7124b2c5b5aa326` (tree
`a469c0e69c79c3a2e7d5786a22da3d57d67cbdd6`), version
`0.1.0.dev20261105+ir11r8`. Full tests ran against commit
`c7735c6c6fe93c384e0fdd68d9f14122b4f02b78` (tree
`731473fa785cbd7e793026527b2425979eb3229d`). In a self-contained Git archive
in Docker `python:3.12-arm64-c65`, CPython 3.12 with `pytest==8.4.2`, the full
suite passed as uid 1001: **703 passed, 1
skipped**, exit 0. The skipped test is specifically the case-alias test on the
Linux case-sensitive filesystem; it passed separately on macOS with CPython
`3.14` using `unittest`. An ARM64 wheel was built and installed, and
`mio-ir --help` succeeded. Wheel SHA-256:
`cc5cafad996d54c1cbd3b696d150db6f28925c65dc984754f1abeab8cbbbf5e3`.
The exact package-source wheel was retained at
`/Users/mao/CodexWork/mio-ir11-rebase-evidence-20261105/final-84fb89/artifacts/azazel_mio-0.1.0.dev20261105+ir11r8-py3-none-any.whl`
with SHA-256 `2904c0ba5e3c4417638ae602f2bf6f4a5b365c4d4f9ebf28e552f779c93489d4`.
It installed in the isolated ARM64 container and the README's case-create,
import, verify, timeline and report commands passed with five synthetic
records; the output contained five events and valid evidence. Both wheel
builds use the same package source/metadata commit and version; their distinct
build hashes are recorded rather than substituting one for the other.

### Review limits

The reviewers did not execute tests. The full test result above is from the
separate recorded run. Debian VMware guest setup, real evidence, credentials,
deployment, publication and hardware acceptance were not exercised. The
case-alias test is conditional on filesystem behavior; Linux skipped it and
macOS ran it directly. Markdown escaping covers the explicitly listed control,
line-separator and bidi characters, not every possible display transformation
in every downstream Markdown renderer.
