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

No pytest skips/warnings reported. Logs retained locally in .git/ir-refresh-evidence. Synthetic evidence only.

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

Reviewer commands from this checkout, using the retained local environment:

```sh
.git/ir-refresh-evidence/venv/bin/python -m pytest tests/test_ir_workflow.py -q
.git/ir-refresh-evidence/venv/bin/python -m pytest -q
```

Alternatively create a new Python 3.12 virtual environment outside the checkout,
install this checkout with pip install -e . and install pytest. No virtual
environment is committed. Logs: .git/ir-refresh-evidence/ir11-03-*.log.
