# PR 11 offline IR refresh candidate

Additive standalone offline evidence utility, separate from MIO reasoning. Current package exports and metadata preserved; only console script registration added. No network, elevation, model or production actions.

## Exact sources before changes

- Base c6a0e0d6ef589693bc7bd54a4c2c1cdf32371524; tree 2943cc80691148d63f71200198f661bf71462ee1.
- PR11 head 9debcfdf504ee580f8bf3b2ab061b87eed111540; tree 977a453d74aca810c4419ab11064a877aec7a973.
- Historical base 6302e665c3ac6cf7004407965299d81dc9ddfc8a.
- PR15 head 6df0d75c1ebf835dd9b3d764300c6743335174ce; tree 7d93bb9e9753ca5853e6043653aecedbfd471c9b.

No AGENTS.md in fresh checkout. Inspected PR11 historical six-file diff and PR15 source. Restored distinct CLI, synthetic fixture, tests and deployment guide; integrated current pyproject rather than old packaging or initializer.

## Findings

IR11-01 (medium), src/azazel_mio/cli.py:21 and :90: pre-existing objects symlink redirects imports outside store; root/database symlinks alias storage. Reproduced old CLI writing synthetic evidence through objects symlink. Reject these entries and mark verification invalid for a symlinked object directory. Tests: test_storage_symlinks_rejected, test_database_symlink_rejected.

IR11-02 (medium), src/azazel_mio/cli.py:171: original export guard allows SQLite sidecar overwrite and outside hardlinks to internal evidence/database inodes. Reject exports anywhere inside private storage and atomically replace external exports using private temporary files. Tests: test_report_cannot_overwrite_internal_journal, test_report_hardlink_does_not_truncate_evidence.

## Plan and validation

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

## Limitations

Debian ARM64 guest not validated. Not forensic WORM storage. User must control private storage and parent directories; concurrent hostile filesystem mutation remains outside this utility boundary. JSON/JSONL mapping, hashes, case isolation and SQLite behavior preserved; reports now require export outside store. At the time of this historical pre-rebase snapshot, no existing PR branch had been rewritten or pushed.

## IR11-03 follow-up

IR11-03 (high), src/azazel_mio/cli.py:27: existing hardlinked database
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

## Current-main rebase candidate — 2026-11-05

Hashes, code line references and 297/299 test totals in earlier sections are
historical, not current-main evidence. Current MIO main is
`5bb09c8d28c57604dc1c63903b98fed7587b49ea`. The PR #11-only diff is six files:
`deploy/standalone-vm/README.md`, `docs/reviews/pr11-ir-refresh.md`,
`examples/synthetic_ir_case/events.jsonl`, `pyproject.toml`,
`src/azazel_mio/cli.py`, and `tests/test_ir_workflow.py`. Current main package
metadata and exports are retained; only the `mio-ir` console script is added.

## Independent review findings and disposition

Claude Code Haiku/low's first review of `611e893` was incomplete because it did
not read all of `cli.py`. A later review read all six changed files at
`6da9e93c9f2fdf7ac67541176c6485a11af198d9`; it had no High/blocking code
finding and raised four Low/Medium issues. A final review of the then-current
`6b27c86dd99294ff4797702c40ee72e25fb659c1` read all six files and found five
Low items, with no High/blocking finding. Their dispositions are:

- F1 (`text.splitlines()` split valid JSONL strings containing U+2028/U+0085):
  now split only on LF and strip an optional CR, with regression cases
  (`cli.py:107-109`, `test_jsonl_keeps_unicode_separators_inside_strings`).
- F2 (recursive `str()` on an object-valued summary could raise): non-scalar
  summaries are rejected before string conversion (`cli.py:116-118`), covered
  by `test_nested_summary_is_a_clean_input_error`.
- F3 (file mode bits were not checked): directory modes are enforced; internal
  data files are checked for current owner, regular-file type and single link,
  but their mode bits are not changed or rejected. They remain inside storage
  directories with mode `0700`; this minimizes compatibility risk while keeping
  them inaccessible to other users. The README and this document now state the
  distinction accurately.
- F4 (test totals were tied to an earlier commit): current executable source
  and test commit is `599ff221dfc8f34df06adfc48d1788802fdc18cb`, tree
  `2daa3e9bbe3a1627d7e556bbdbb6bcde37b02892`. This document is a following
  documentation-only update; the PR description records the final PR head and
  the tested source commit separately.
- F5 (`report generate` returned success with invalid evidence): it now writes
  the report, then exits 2 if any evidence failed verification. The regression
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

Validation on source/test commit `599ff221dfc8f34df06adfc48d1788802fdc18cb`
(tree above), based on current main: focused IR workflow **27 passed / 11
subtests passed**; full MIO suite **672 passed / 254 subtests passed**, CPython
3.12.14, exit 0. The README offline editable-install procedure was exercised
from the same source commit in a disposable Linux arm64 / Python 3.12 Docker
container (`--rm --network=none`): `mio-ir --help` succeeded and installed
version was `0.1.0+git.c31c244`. No distributable wheel was published.

The final independent review of this refreshed document and source commit is
pending. Debian ARM64 guest acceptance remains separate and has not been run.
