# Debian ARM64 VMware Fusion PoC

Requires Python 3.12+; no LLM, Docker or network service at runtime. Install from a locally available checkout and dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --no-build-isolation --no-deps -e .
export MIO_IR_HOME="$HOME/mio-ir-data"
mio-ir case create --name "Synthetic IR Case"
mio-ir evidence import --case 1 --file examples/synthetic_ir_case/events.jsonl --format jsonl
mio-ir evidence verify --case 1
mio-ir timeline build --case 1
mio-ir report generate --case 1 --format json --output /tmp/mio-ir-report.json
```

Run the commands inside the Debian ARM64 guest and record results. macOS tests do not establish guest verification. This is an initial vertical slice, not forensic WORM storage. Avoid real sensitive evidence until security review.

This CLI is a separate local evidence utility; it does not call the MIO reasoning
core or take production actions. Store evidence under a dedicated private
`MIO_IR_HOME` directory. Symlinked storage entries are rejected; use a directory
owned and controlled by the current user. Reports must be exported outside that
directory, including SQLite journal paths. Existing report files are replaced
atomically with private files. These checks do not defend against a concurrent
writer with access to the storage directory or its parent directories.
