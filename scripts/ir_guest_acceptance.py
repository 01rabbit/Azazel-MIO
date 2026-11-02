#!/usr/bin/env python3
"""Guest-only acceptance runner for an already installed ``mio-ir``.

Runs only inside a Debian ARM64 VMware guest. It does not provision or install
software, invoke sudo, or itself access the network. It uses synthetic evidence
inside a private temporary directory. There is deliberately no bypass flag.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

COMMAND = "mio-ir"
PACKAGE = "azazel-mio"
TIMEOUT_SECONDS = 30
TOTAL_TIMEOUT_SECONDS = 120
VM_CHECK_TIMEOUT_SECONDS = 3
VERSION_CHECK_TIMEOUT_SECONDS = 5
DIAG_LIMIT = 400
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
GUEST_ARCHES = frozenset({"aarch64", "arm64"})
VM_DETECTOR_PATHS = (Path("/usr/bin/systemd-detect-virt"), Path("/bin/systemd-detect-virt"))
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


def check_vmware(virt_type: str) -> str:
    if virt_type != "vmware":
        raise GuestRefused("guest-check", "refused: VMware guest required")
    return virt_type


def resolve_vm_detector() -> str | None:
    """Use the Debian system utility, not a same-named PATH entry."""
    for candidate in VM_DETECTOR_PATHS:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def console_script_interpreter(exe: str, path: str) -> str:
    try:
        with open(exe, "rb") as script:
            first_line = script.readline(512).decode("utf-8", errors="replace").strip()
    except OSError as exc:
        raise AcceptanceError("command-version", "cannot read mio-ir entry point: " + bounded(str(exc))) from exc
    if not first_line.startswith("#!"):
        raise AcceptanceError("command-version", "mio-ir entry point has no interpreter shebang")
    try:
        words = shlex.split(first_line[2:].strip())
    except ValueError as exc:
        raise AcceptanceError("command-version", "invalid mio-ir interpreter shebang") from exc
    if not words:
        raise AcceptanceError("command-version", "empty mio-ir interpreter shebang")
    if Path(words[0]).name == "env":
        env_words = words[1:]
        if env_words and env_words[0] == "-S":
            env_words = env_words[1:]
        interpreter = next((word for word in env_words if not word.startswith("-")), None)
        resolved = shutil.which(interpreter, path=path) if interpreter else None
    else:
        resolved = words[0] if Path(words[0]).is_absolute() else shutil.which(words[0], path=path)
    if resolved is None:
        raise AcceptanceError("command-version", "mio-ir interpreter is not available on PATH")
    return resolved


def run_captured(command: list[str], env: dict[str, str], timeout: float,
                 label: str) -> subprocess.CompletedProcess[str]:
    """Capture bounded output without a shell and enforce a single deadline."""
    proc: subprocess.Popen[bytes] | None = None
    terminate_group = False
    selector = selectors.DefaultSelector()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, start_new_session=True)
        assert proc.stdout is not None and proc.stderr is not None
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_group = True
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(remaining):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = buffers[key.data]
                if len(target) + len(chunk) > MAX_COMMAND_OUTPUT_BYTES:
                    terminate_group = True
                    raise AcceptanceError("output", label + " exceeded output limit")
                target.extend(chunk)
        returncode = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(
            command, returncode,
            bytes(buffers["stdout"]).decode("utf-8", errors="replace"),
            bytes(buffers["stderr"]).decode("utf-8", errors="replace"),
        )
    except subprocess.TimeoutExpired as exc:
        terminate_group = True
        raise AcceptanceError(label, label + " timed out") from exc
    except OSError as exc:
        terminate_group = True
        raise AcceptanceError(label, label + " could not start: " + bounded(str(exc))) from exc
    finally:
        selector.close()
        if proc is not None:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            if terminate_group or proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()


def installed_version(exe: str, path: str, home: str) -> str:
    interpreter = console_script_interpreter(exe, path)
    code = "import importlib.metadata as m; print(m.version('" + PACKAGE + "'))"
    env = {"PATH": path, "HOME": home, "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    proc = run_captured([interpreter, "-P", "-c", code], env, VERSION_CHECK_TIMEOUT_SECONDS,
                        "package version check")
    if proc.returncode != 0:
        raise AcceptanceError("command-version", PACKAGE + " metadata unavailable for mio-ir interpreter")
    version = proc.stdout.strip()
    if not version or "\n" in version:
        raise AcceptanceError("command-version", "invalid azazel-mio version response")
    return version


def run_mio(exe: str, args: list[str], env: dict[str, str],
            timeout: float = TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return run_captured([exe, *args], env, timeout, "mio-ir")


def parse_json_stdout(step: str, text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AcceptanceError(step, "stdout is not JSON: " + bounded(text)) from exc


def all_valid(rows: Any) -> bool:
    return isinstance(rows, list) and len(rows) > 0 and all(
        isinstance(row, dict) and row.get("valid") is True for row in rows
    )


def tamper_object(home: Path, digest: Any, allowed_root: Path) -> None:
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AcceptanceError("tamper", "stored object digest is not a SHA-256 hex value")
    object_dir = home / "objects"
    try:
        directory_info = object_dir.lstat()
        home_real = home.resolve(strict=True)
        allowed_real = allowed_root.resolve(strict=True)
        object_real = object_dir.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError("tamper", "stored object directory is unavailable") from exc
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode):
        raise AcceptanceError("tamper", "stored object directory is not a real directory")
    if not home_real.is_relative_to(allowed_real):
        raise AcceptanceError("tamper", "MIO_IR_HOME escaped the temporary acceptance directory")
    if object_real != home_real / "objects":
        raise AcceptanceError("tamper", "stored object directory escaped MIO_IR_HOME")
    directory_fd = None
    read_fd = None
    object_fd = None
    try:
        directory_fd = os.open(object_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        read_fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        metadata = os.fstat(read_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AcceptanceError("tamper", "stored object is not a single-link regular file")
        os.fchmod(read_fd, 0o600)
        object_fd = os.open(digest, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        writable = os.fstat(object_fd)
        if (writable.st_dev, writable.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise AcceptanceError("tamper", "stored object changed during safe open")
        os.ftruncate(object_fd, 0)
        replacement = b"tampered by acceptance runner\n"
        offset = 0
        while offset < len(replacement):
            offset += os.write(object_fd, replacement[offset:])
    except OSError as exc:
        raise AcceptanceError("tamper", "stored object cannot be safely modified") from exc
    finally:
        if object_fd is not None:
            os.close(object_fd)
        if read_fd is not None:
            os.close(read_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def read_small(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AcceptanceError("report", "generated report is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise AcceptanceError("report", "generated report is not a regular file")
    if info.st_size > MAX_REPORT_BYTES:
        raise AcceptanceError("report", "generated report exceeds size bound")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AcceptanceError("report", "generated report is unreadable") from exc


def peak_rss_kb() -> dict[str, int]:
    """Return runner and all-child RSS high-water marks; Linux reports KiB."""
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return {"runner": own, "children_all_steps": children, "max": max(own, children)}


def resolved_home() -> str:
    configured = os.environ.get("HOME")
    if configured:
        return configured
    try:
        return str(Path.home())
    except RuntimeError:
        return "/nonexistent"


class Acceptance:
    def __init__(self, exe: str, env: dict[str, str]) -> None:
        self.exe = exe
        self.env = env
        self.steps: list[dict[str, Any]] = []
        self.deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS

    def read_report(self, step: str, path: Path) -> str:
        started = time.monotonic()
        try:
            return read_small(path)
        finally:
            self.steps.append({"step": step + ".read", "duration_ms": elapsed_ms(started)})

    def invoke(self, step: str, args: list[str], accept: tuple[int, ...] = (0,)) -> Any:
        started = time.monotonic()
        try:
            remaining = self.deadline - time.monotonic()
            require(step, remaining > 0, "overall acceptance deadline exceeded")
            proc = run_mio(self.exe, args, self.env, min(TIMEOUT_SECONDS, remaining))
            if proc.returncode not in accept:
                raise AcceptanceError(step, "exit " + str(proc.returncode) + ": " + bounded(proc.stderr))
            return parse_json_stdout(step, proc.stdout)
        except AcceptanceError as exc:
            raise AcceptanceError(step, exc.message) from exc
        finally:
            self.steps.append({"step": step, "duration_ms": elapsed_ms(started)})

    def run(self, work: Path) -> dict[str, Any]:
        out = work / "out"
        out.mkdir()
        source = work / "synthetic.jsonl"
        source.write_text("\n".join(json.dumps(r) for r in SYNTHETIC_RECORDS) + "\n", encoding="utf-8")
        expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()

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
        require("evidence.verify", len(verified) == 1 and
                verified[0].get("evidence_id") == imported["evidence_id"],
                "unexpected evidence verification result")
        digest = verified[0].get("sha256")
        require("evidence.verify", digest == expected_digest, "evidence digest does not match synthetic source")

        timeline = self.invoke("timeline.build", ["timeline", "build", "--case", case_arg])
        require("timeline.build", isinstance(timeline, list) and len(timeline) == len(SYNTHETIC_RECORDS)
                and all(isinstance(event, dict) for event in timeline),
                "timeline event count mismatch")
        expected_summaries = ["synthetic alert B", "synthetic alert A", "synthetic record without timestamp"]
        expected_timestamps = ["2026-01-01T00:00:01+00:00", "2026-01-01T00:00:02+00:00", None]
        require("timeline.build", [event.get("summary") for event in timeline] == expected_summaries,
                "timeline ordering mismatch")
        require("timeline.build", [event.get("timestamp_utc") for event in timeline] == expected_timestamps,
                "timeline UTC normalization mismatch")

        json_out = out / "report.json"
        self.invoke("report.json", ["report", "generate", "--case", case_arg,
                                    "--format", "json", "--output", str(json_out)])
        report = parse_json_stdout("report.json", self.read_report("report.json", json_out))
        require("report.json", isinstance(report, dict) and report.get("timeline") == timeline
                and all_valid(report.get("evidence")), "JSON report mismatch")

        md_out = out / "report.md"
        self.invoke("report.markdown", ["report", "generate", "--case", case_arg,
                                        "--format", "markdown", "--output", str(md_out)])
        markdown = self.read_report("report.markdown", md_out)
        require("report.markdown", markdown.startswith("# IR Case") and
                "synthetic alert A" in markdown and "synthetic alert B" in markdown and
                "Evidence verification:" in markdown, "markdown report malformed")

        tamper_started = time.monotonic()
        try:
            tamper_object(Path(self.env["MIO_IR_HOME"]), digest, work)
        finally:
            self.steps.append({"step": "tamper.object", "duration_ms": elapsed_ms(tamper_started)})
        tampered = self.invoke("evidence.verify.tampered", ["evidence", "verify", "--case", case_arg],
                               accept=(VERIFY_INVALID_EXIT,))
        require("evidence.verify.tampered", isinstance(tampered, list) and len(tampered) == 1 and
                isinstance(tampered[0], dict) and tampered[0].get("evidence_id") == imported["evidence_id"] and
                tampered[0].get("sha256") == expected_digest and
                tampered[0].get("valid") is False,
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
    runner: Acceptance | None = None
    try:
        guest = check_guest(system, platform.machine(), read_os_release())
        virt_tool = resolve_vm_detector()
        if virt_tool is None:
            raise GuestRefused("guest-check", "refused: systemd-detect-virt is required to verify VMware")
        virt_env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
        virt = run_captured([virt_tool, "--vm"], virt_env, VM_CHECK_TIMEOUT_SECONDS,
                            "VMware guest check")
        if virt.returncode != 0:
            raise GuestRefused("guest-check", "refused: unable to verify virtual machine")
        guest["virtualization"] = check_vmware(virt.stdout.strip())
        exe = shutil.which(COMMAND)
        if exe is None:
            raise AcceptanceError("command", COMMAND + " not found on PATH")
        child_home = resolved_home()
        version = installed_version(exe, os.environ.get("PATH", ""), child_home)
        with tempfile.TemporaryDirectory(prefix="mio-ir-accept-") as tmp:
            home = Path(tmp) / "home"
            home.mkdir(mode=0o700)
            env = {
                "PATH": os.environ.get("PATH", ""),
                # Preserve user-site package resolution; all CLI case data is isolated by MIO_IR_HOME.
                "HOME": child_home,
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "MIO_IR_HOME": str(home / "mio-ir-data"),
            }
            runner = Acceptance(exe, env)
            summary = runner.run(Path(tmp))
        result = {
            "ok": True,
            "guest": guest,
            "command": {"name": COMMAND, "path": exe, "version": version},
            "steps": runner.steps,
            "total_duration_ms": elapsed_ms(started),
            "peak_rss_kb": peak_rss_kb(),
            **summary,
        }
        emit(result)
        return EXIT_OK
    except GuestRefused as exc:
        emit({"ok": False, "step": exc.step, "error": bounded(exc.message),
              "steps": runner.steps if runner else [], "total_duration_ms": elapsed_ms(started)})
        return EXIT_REFUSED
    except AcceptanceError as exc:
        emit({"ok": False, "step": exc.step, "error": bounded(exc.message),
              "steps": runner.steps if runner else [], "total_duration_ms": elapsed_ms(started)})
        return EXIT_FAILURE
    except (OSError, ValueError, RecursionError) as exc:
        emit({"ok": False, "step": "runtime", "error": bounded(str(exc)),
              "steps": runner.steps if runner else [], "total_duration_ms": elapsed_ms(started)})
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
