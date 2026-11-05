# Debian ARM64 VMware Fusion PoC

Requires Python 3.11+ (matching the MIO package metadata); no LLM, Docker or network service at runtime. Install from a locally available checkout and dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
# Point this at the already-provisioned offline wheelhouse in the guest.
: "${WHEELHOUSE:?set WHEELHOUSE to the guest's offline wheelhouse}"
python -m pip install --no-index --find-links "$WHEELHOUSE" "setuptools>=77.0.3" wheel
python -m pip install --no-index --no-build-isolation --no-deps -e .
export MIO_IR_HOME="$HOME/mio-ir-data"
mio-ir case create --name "Synthetic IR Case"
mio-ir evidence import --case 1 --file examples/synthetic_ir_case/events.jsonl --format jsonl
mio-ir evidence verify --case 1
mio-ir timeline build --case 1
REPORT_DIR=$(mktemp -d "$HOME/mio-ir-reports.XXXXXX")
mio-ir report generate --case 1 --format json --output "$REPORT_DIR/mio-ir-report.json"
```

Input summaries must be JSON scalars (string, number, boolean, or null). JSONL records are separated only by LF
(with an optional preceding CR for CRLF); Unicode line-separator characters
inside strings remain part of their record. `evidence verify` and
`report generate` return exit code 2 when any stored evidence fails integrity
verification.

Run the commands inside the Debian ARM64 guest and record results. macOS tests do not establish guest verification. This is an initial vertical slice, not forensic WORM storage. Avoid real sensitive evidence until security review.

This CLI is a separate local evidence utility; it does not call the MIO reasoning
core or take production actions. Store evidence under a dedicated private
`MIO_IR_HOME` directory. Symlinked storage entries are rejected; use a directory
owned by the current user with no group or other access. A new storage directory
is created with mode `0700`; an existing directory with unsafe ownership or
permissions is refused without changing its mode. The database, SQLite sidecars,
and content objects must be owned regular files with one link; symlinks,
hardlinks, FIFOs, and other non-regular entries are refused. Ownership checks
require POSIX user-ID reporting; unsupported platforms fail closed. Reports
must be exported outside the storage directory, including SQLite journal paths.
Existing report files are replaced atomically with private files.

Each evidence import invocation creates a distinct receipt and event set, even
when the same bytes were imported before. The stored object bytes are deduplicated
by SHA-256, while the separate receipt records each import action.

These checks do not defend against a concurrent writer with access to the
storage directory or its parent directories.
