#!/usr/bin/env python3
"""Guest-only acceptance runner for an already installed ``mio-ir``.

Runs only inside a provisioned Debian ARM64 guest (Linux, aarch64/arm64). It never
provisions, installs, uses sudo or the network, and uses only a private
TemporaryDirectory with synthetic evidence. There is deliberately no bypass flag.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

COMMAND = "mio-ir"
PACKAGE = "azazel-mio"
TIMEOUT_SECONDS = 30
DIAG_LIMIT = 400
MAX_REPORT_BYTES = 4 * 1024 * 1024
GUEST_ARCHES = frozenset({"aarch64", "arm64"})
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_REFUSED = 3
VERIFY_INVALID_EXIT = 2  # mio-ir evidence verify returns 2 when any object is invalid

SYNTHETIC_RECORDS = [
    {"timestamp": "2026-01-01T00:00:02Z", "summary": "synthetic alert A"},
    {"timestamp": "2026-01-01T00:00:01+00:00", "summary": "synthetic alert B"},
    {"summary": "synthetic record without timestamp"},
]


class AcceptanceError(Exception):
    def __init__(self, step: str, message: str) -> None:
        super().__init__(message)
        self.step = step
        self.message = message


class GuestRefused(AcceptanceError):
    """Raised when the host is not a Debian ARM64 guest."""


def bounded(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= DIAG_LIMIT:
        return collapsed
    return collapsed[:DIAG_LIMIT] + "...[truncated]"


def elapsed_ms(started: float) -> float:
    return round((time.monotonic() - started) * 1000, 1)


def require(step: str, condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(step, message)


def parse_os_release(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def read_os_release() -> str:
    try:
        return Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def check_guest(system: str, machine: str, os_release_text: str) -> dict[str, str]:
    if system != "Linux":
        raise GuestRefused("guest-check", "refused: OS must be Linux, got " + bounded(system))
    if machine not in GUEST_ARCHES:
        raise GuestRefused("guest-check", "refused: architecture must be aarch64 or arm64, got " + bounded(machine))
    if parse_os_release(os_release_text).get("ID") != "debian":
        raise GuestRefused("guest-check", "refused: distribution must be Debian (ID=debian)")
    return {"os": "linux", "distro": "debian", "arch": machine}


def installed_version() -> str:
    try:
        return importlib.metadata.version(PACKAGE)
    except importlib.metadata.PackageNotFoundError as exc:
        raise AcceptanceError("command-version", PACKAGE + " is not installed") from exc


def run_mio(exe: str, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [exe, *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcceptanceError("timeout", "mio-ir timed out after " + str(TIMEOUT_SECONDS) + "s") from exc
    except OSError as exc:
        raise AcceptanceError("exec", "mio-ir could not start: " + bounded(str(exc))) from exc


def parse_json_stdout(step: str, text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AcceptanceError(step, "stdout is not JSON: " + bounded(text)) from exc


def all_valid(rows: Any) -> bool:
    return isinstance(rows, list) and len(rows) > 0 and all(
        isinstance(row, dict) and row.get("valid") is True for row in rows
    )


def tamper_object(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise AcceptanceError("tamper", "stored synthetic object is not a regular file")
    os.chmod(path, 0o600)
    path.write_bytes(b"tampered by acceptance runner\n")


def read_small(path: Path) -> str:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise AcceptanceError("report", "generated report exceeds size bound")
    return path.read_text(encoding="utf-8")


def peak_rss_kb(system: str) -> int:
    peak = max(
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
    )
    # Linux reports ru_maxrss in KiB; macOS reports bytes.
    return peak // 1024 if system == "Darwin" else peak


class Acceptance:
    def __init__(self, exe: str, env: dict[str, str]) -> None:
        self.exe = exe
        self.env = env
        self.steps: list[dict[str, Any]] = []

    def invoke(self, step: str, args: list[str], accept: tuple[int, ...] = (0,)) -> Any:
        started = time.monotonic()
        try:
            proc = run_mio(self.exe, args, self.env)
            if proc.returncode not in accept:
                raise AcceptanceError(step, "exit " + str(proc.returncode) + ": " + bounded(proc.stderr))
            return parse_json_stdout(step, proc.stdout)
        finally:
            self.steps.append({"step": step, "duration_ms": elapsed_ms(started)})

    def run(self, work: Path) -> dict[str, Any]:
        out = work / "out"
        out.mkdir()
        source = work / "synthetic.jsonl"
        source.write_text("\n".join(json.dumps(r) for r in SYNTHETIC_RECORDS) + "\n", encoding="utf-8")

        created = self.invoke("case.create", ["case", "create", "--name", "acceptance-synthetic"])
        case_id = created.get("case_id") if isinstance(created, dict) else None
        require("case.create", isinstance(case_id, int) and case_id > 0, "no case_id returned")

        cases = self.invoke("case.list", ["case", "list"])
        require("case.list", isinstance(cases, list) and any(
            isinstance(c, dict) and c.get("case_id") == case_id for c in cases), "created case not listed")

        case_arg = str(case_id)
        imported = self.invoke("evidence.import", [
            "evidence", "import", "--case", case_arg, "--file", str(source), "--format", "jsonl"])
        require("evidence.import", isinstance(imported, dict) and isinstance(imported.get("evidence_id"), int),
                "no evidence_id returned")

        verified = self.invoke("evidence.verify", ["evidence", "verify", "--case", case_arg])
        require("evidence.verify", all_valid(verified), "imported evidence did not verify")
        digest = verified[0].get("sha256")

        timeline = self.invoke("timeline.build", ["timeline", "build", "--case", case_arg])
        require("timeline.build", isinstance(timeline, list) and len(timeline) == len(SYNTHETIC_RECORDS),
                "timeline event count mismatch")

        json_out = out / "report.json"
        self.invoke("report.json", ["report", "generate", "--case", case_arg,
                                    "--format", "json", "--output", str(json_out)])
        report = parse_json_stdout("report.json", read_small(json_out))
        require("report.json", isinstance(report, dict) and "timeline" in report and "evidence" in report,
                "report missing timeline or evidence")

        md_out = out / "report.md"
        self.invoke("report.markdown", ["report", "generate", "--case", case_arg,
                                        "--format", "markdown", "--output", str(md_out)])
        require("report.markdown", read_small(md_out).startswith("# IR Case"), "markdown report malformed")

        tamper_object(Path(self.env["MIO_IR_HOME"]) / "objects" / str(digest))
        tampered = self.invoke("evidence.verify.tampered", ["evidence", "verify", "--case", case_arg],
                               accept=(VERIFY_INVALID_EXIT,))
        require("evidence.verify.tampered", isinstance(tampered, list) and any(
            isinstance(r, dict) and r.get("valid") is False for r in tampered),
            "integrity refusal not observed after tamper")

        return {"case_id": case_id, "evidence_id": imported["evidence_id"],
                "timeline_events": len(timeline), "tamper_detected": True}


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the mio-ir acceptance path inside a Debian ARM64 guest. No options other than --help.")
    parser.parse_args(argv)
    started = time.monotonic()
    system = platform.system()
    try:
        guest = check_guest(system, platform.machine(), read_os_release())
        exe = shutil.which(COMMAND)
        if exe is None:
            raise AcceptanceError("command", COMMAND + " not found on PATH")
        version = installed_version()
        with tempfile.TemporaryDirectory(prefix="mio-ir-accept-") as tmp:
            env = {
                "PATH": os.environ.get("PATH", ""),
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "MIO_IR_HOME": str(Path(tmp) / "home"),
            }
            runner = Acceptance(exe, env)
            summary = runner.run(Path(tmp))
        result = {
            "ok": True,
            "guest": guest,
            "command": {"name": COMMAND, "path": exe, "version": version},
            "steps": runner.steps,
            "total_duration_ms": elapsed_ms(started),
            "peak_rss_kb": peak_rss_kb(system),
            **summary,
        }
        emit(result)
        return EXIT_OK
    except GuestRefused as exc:
        emit({"ok": False, "step": exc.step, "error": bounded(exc.message)})
        return EXIT_REFUSED
    except AcceptanceError as exc:
        emit({"ok": False, "step": exc.step, "error": bounded(exc.message)})
        return EXIT_FAILURE
    except (OSError, ValueError) as exc:
        emit({"ok": False, "step": "runtime", "error": bounded(str(exc))})
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
