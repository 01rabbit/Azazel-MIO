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
