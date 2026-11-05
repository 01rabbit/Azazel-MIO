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

Debian ARM64 guest not validated. Not forensic WORM storage. User must control private storage and parent directories; concurrent hostile filesystem mutation remains outside this utility boundary. JSON/JSONL mapping, hashes, case isolation and SQLite behavior preserved; reports now require export outside store. No existing PR rewritten or pushed. Updating PR11 with resliced base requires a separately authorized branch/history operation.

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

The historical hashes, code line references, and 297/299 test counts above
describe the earlier refresh candidate; they are not evidence for the current
main rebase. Current MIO main is `5bb09c8d28c57604dc1c63903b98fed7587b49ea`.
The PR #11-only diff remains the six IR files listed above, with current main's
package metadata and exports retained and only the `mio-ir` script added.

The independent Haiku/low review of candidate `611e89352c182d3525982ee3509489c1a27e17b3`
found no High issue, but identified four Low/Medium items and documentation
drift. Before syncing the rebased PR, the candidate addresses these as follows:

- Existing storage directories are no longer chmodded. They must already be
  owned by the invoking user and private; new roots are created mode `0700`.
- The database, SQLite sidecars and existing content objects are checked with
  `lstat`; symlinks, hardlinks, non-regular entries and foreign ownership are
  refused before open/read. A FIFO object is covered by a regression test.
- Excessive JSON nesting is converted to a bounded input error rather than a
  traceback.
- Re-importing identical bytes intentionally creates a distinct evidence
  receipt/event set while content objects remain SHA-256 deduplicated. README
  and regression coverage make this behavior explicit.
- The Debian ARM64 guide now states the package's Python `>=3.11` requirement.

The rebased code candidate before this security follow-up was
`611e89352c182d3525982ee3509489c1a27e17b3`. Claude Haiku/low reviewed its six
changed files and found no High issue, but the review was incomplete for full
acceptance: it had not read all of `cli.py` and did not verify the checkout
head. Findings and disposition:

- `cli.py:25-26`, existing directory mode mutation: fixed by refusing an
  existing directory unless it is owned by the invoking user and already
  private; no existing directory is chmodded (`cli.py:26-36`).
- `cli.py:23-33`, SQLite sidecars and non-regular content objects: fixed by
  `lstat` checks for the database, `-journal`, `-wal`, `-shm`, and existing
  digest objects (`cli.py:38-45`, `48-53`, `137-140`). Symlinks, hardlinks,
  FIFOs, non-regular entries and foreign-owned files are rejected. Verification
  reports unsafe/missing objects invalid (`cli.py:69-87`).
- `cli.py:61-66`, deeply nested JSON parser exception: fixed by translating
  `RecursionError` to a bounded input `ValueError` (`cli.py:93-105`).
- Re-import duplication: retained as separate import receipts so each invocation
  and its source filename/time remain visible; the object bytes are content
  deduplicated. README wording and `test_reimport_creates_distinct_receipts_but_deduplicates_object`
  make this behavior explicit.
- Documentation now states Python `>=3.11`, matching package metadata. The
  hashes and 297/299 test totals in the earlier sections are historical results
  for the earlier tree, not current-main rebase evidence.

Candidate after these changes: commit `5fa161a1626c64088b338eed9f7aec0bac7a7360`,
tree `6dc00dd00dd1a4c04901114b5b8fd5b7e8722366`, based on current MIO main
`5bb09c8d28c57604dc1c63903b98fed7587b49ea`. Validation on that tree: focused
IR workflow **18 passed / 6 subtests passed**; complete MIO suite **663 passed /
249 subtests passed**, Python 3.12.14, exit 0; `git diff --check` passed. A
read-only isolated Docker editable install on Linux arm64 / Python 3.12 also
passed: `mio-ir --help` showed the four command groups and installed package
version was `0.1.0+git.c31c244`. The temporary container used `--rm` and
`--network=none`; no distributable wheel was published or retained.

The final independent review of the corrected current-head candidate is still
required. Debian ARM64 guest validation remains a separate acceptance gate.
