# Debian ARM64 VMware Fusion PoC

Requires Python 3.11+ (matching the MIO package metadata); no LLM, Docker or network service at runtime. Run the following commands from the checkout root:

```sh
set -o pipefail
python3 -m venv .venv
. .venv/bin/activate
# Point this at the already-provisioned offline wheelhouse in the guest.
: "${WHEELHOUSE:?set WHEELHOUSE to the guest's offline wheelhouse}"
python -m pip install --no-index --find-links "$WHEELHOUSE" "setuptools>=77.0.3" wheel
python -m pip install --no-index --no-build-isolation --no-deps -e .
export MIO_IR_HOME="$HOME/mio-ir-data"
CASE_ID=$(mio-ir case create --name "Synthetic IR Case" | python -c 'import json,sys; print(json.load(sys.stdin)["case_id"])')
test -n "$CASE_ID"
mio-ir evidence import --case "$CASE_ID" --file examples/synthetic_ir_case/events.jsonl --format jsonl
mio-ir evidence verify --case "$CASE_ID"
mio-ir timeline build --case "$CASE_ID"
REPORT_DIR=$(mktemp -d "$HOME/mio-ir-reports.XXXXXX")
mio-ir report generate --case "$CASE_ID" --format json --output "$REPORT_DIR/mio-ir-report.json"
```

Input summaries must be JSON scalars (string, finite number, boolean, or null).
An omitted summary becomes `No summary provided`; an explicit null becomes an
empty summary. Summaries longer than 2,048 characters are truncated in timeline
and report text; the original input remains available through the stored object.
Only ISO-formatted string timestamps with an explicit timezone offset are
normalized to UTC; other types and naive timestamps remain unknown.
String timestamps longer than 256 characters are rejected; shorter unparseable
or unrepresentable timestamps remain unknown. JSONL records are separated only
by LF (with an optional preceding CR for CRLF); Unicode line-separator
characters inside strings remain part of their record. Empty lines, spaces-only
lines and tabs-only lines are skipped; other Unicode whitespace is rejected.
Each input file is limited to 16 MiB and 10,000 records. There is no cumulative per-case event or
evidence limit. `evidence
verify` and `report generate` return exit code 3 when stored evidence fails
integrity verification; argparse usage errors return 2.
An empty JSONL file has no records; the empty JSON array `[]` is accepted and
also has no records. Empty JSON input and UTF-8 BOM-prefixed input are rejected.
Timeline `record` is the one-based event index within that import,
not a physical source line number. Markdown reports show missing timestamps as
`unknown`, replace control characters, line separators and bidirectional
format controls in summaries with spaces, and escape ASCII punctuation in
rendered Markdown. This reduces display spoofing; it is not a general-purpose
sanitizer for arbitrary Markdown consumers.

Run the commands inside the Debian ARM64 guest and record results. macOS tests do not establish guest verification. This is an initial vertical slice, not forensic WORM storage. Avoid real sensitive evidence until security review.

This CLI is a separate local evidence utility; it does not call the MIO reasoning
core or take production actions. Store evidence under a dedicated private
`MIO_IR_HOME` directory. Symlinked storage entries are rejected; use a directory
owned by the current user with no group or other access. Only the final
storage-directory component of a new store is created with mode
`0700`; missing parent components use the default creation mode and must be
trusted. An existing directory with unsafe ownership or
permissions is refused without changing its mode. The database, SQLite sidecars,
and content objects must be owned regular files with one link; symlinks,
hardlinks, FIFOs, and other non-regular entries are refused. Ownership checks
require POSIX user-ID reporting; unsupported platforms fail closed. Reports
must be exported outside the storage directory, including SQLite journal paths.
New content objects are created with mode `0400`. Existing database, sidecar,
and object file mode bits are not checked or changed; access relies on ownership
and the private storage-directory mode.
Output paths are resolved before validation; an external output symlink therefore
targets its resolved destination. Existing report files are replaced atomically
with private files.

`MIO_IR_HOME` must be non-empty and resolve to an absolute path after `~`
expansion. If it is unset, `HOME` must be
set and the default store is `$HOME/.local/share/azazel-mio`. The final storage
directory and its entries are checked; parent path components must be trusted
and are not independently inspected for symlinks. If an existing object at the
expected content hash is corrupt or oversized, import fails closed and does not
replace that object.

Each evidence import invocation creates a distinct receipt and event set, even
when the same bytes were imported before. The stored object bytes are deduplicated
by SHA-256, while the separate receipt records each import action.

These checks do not defend against a concurrent writer with access to the
storage directory or its parent directories.
