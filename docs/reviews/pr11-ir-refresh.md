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

Hashes, line references and 297/299 test totals in the historical sections
above describe the earlier refresh tree, not the current-main rebase. Current
MIO main is `5bb09c8d28c57604dc1c63903b98fed7587b49ea`. The PR #11-only diff is
limited to six files: `deploy/standalone-vm/README.md`,
`docs/reviews/pr11-ir-refresh.md`, `examples/synthetic_ir_case/events.jsonl`,
`pyproject.toml`, `src/azazel_mio/cli.py`, and `tests/test_ir_workflow.py`.
Current main package metadata and exports are retained; only the `mio-ir`
console script is added.

## Independent review findings and disposition

Claude Code Haiku/low first reviewed candidate
`611e89352c182d3525982ee3509489c1a27e17b3`; that review was incomplete because
it did not read all of `cli.py`. A second review read the complete 665-line diff,
entire CLI and test file, packaging metadata, and both docs at candidate
`6da9e93c9f2fdf7ac67541176c6485a11af198d9`. It reported no High/blocking code
finding and four Low/Medium findings. Fixes in current candidate code commit
`d40ac7130adb7e4685f68b055a4acfd6cedfacf8`:

- Existing storage directories are never chmodded. Existing roots must already
  be owned by the invoking user and private; new roots are created mode `0700`.
  Ownership cannot be proven on platforms without POSIX UID support, so those
  platforms fail closed (`cli.py:22-42`).
- The database and all three SQLite sidecars are checked before SQLite opens;
  existing objects and `objects/` are checked before use. Symlinks, hardlinks,
  FIFOs, non-regular entries, broad permissions and foreign ownership are
  rejected. Verification returns invalid for unsafe objects/directories
  (`cli.py:53-60`, `74-96`, `143-148`).
- Deep JSON and JSONL nesting is converted to a clean input error rather than a
  traceback (`cli.py:99-112`).
- Re-importing the same bytes intentionally creates a separate receipt and event
  set while storing one SHA-256 object. README and test make this explicit.
- The guest guide now preinstalls `setuptools>=77.0.3` and `wheel` from an
  offline wheelhouse, uses `--no-index`, and writes reports to a private
  `mktemp` directory. It states the Python `>=3.11` package requirement.
- Documentation names all six changed files, labels earlier PR/hash/test data
  as historical, and no longer cites private `.git` test-log paths.

The second review also flagged a test-versus-doc base/head attribution gap. The
tested code commit `5fa161a1626c64088b338eed9f7aec0bac7a7360` and doc-only commit
`6da9e93c9f2fdf7ac67541176c6485a11af198d9` differ only in
`docs/reviews/pr11-ir-refresh.md`; subsequent code/tests are in `d40ac71`. The
final candidate head and review must be recorded after this refresh.

Validation on candidate code commit `d40ac7130adb7e4685f68b055a4acfd6cedfacf8`
(tree `83409a03b1095a525c7feaf61d6c2a796ab4954c`), based on current main above:
focused IR workflow **24 passed / 9 subtests passed**; complete MIO suite
**669 passed / 252 subtests passed**, CPython 3.12.14, exit 0. The README's
offline install procedure was exercised in a disposable Linux arm64 / Python
3.12 Docker container (`--rm --network=none`): editable install and
`mio-ir --help` passed, reporting version `0.1.0+git.c31c244`. The exact runner
log is not committed; no wheel was published. The final independent review of
the corrected candidate and guest Debian ARM64 acceptance remain outstanding.
