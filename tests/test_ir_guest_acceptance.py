"""Host-side unit tests for scripts/ir_guest_acceptance.py.

No real mio-ir, VM, or Docker is used: subprocess and platform helpers are mocked.
"""
import importlib.metadata
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ir_guest_acceptance.py"
_spec = importlib.util.spec_from_file_location("ir_guest_acceptance", SCRIPT)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\nVERSION_ID="12"\n'


def test_parse_os_release_strips_quotes_and_comments():
    fields = runner.parse_os_release('# comment\nID="debian"\n\nNOEQUALS\nNAME=\'Debian\'\n')
    assert fields == {"ID": "debian", "NAME": "Debian"}


@pytest.mark.parametrize("machine", ["aarch64", "arm64"])
def test_check_guest_accepts_debian_arm64(machine):
    guest = runner.check_guest("Linux", machine, DEBIAN)
    assert guest == {"os": "linux", "distro": "debian", "arch": machine}


@pytest.mark.parametrize(
    "system,machine,os_release,fragment",
    [
        ("Darwin", "arm64", DEBIAN, "Linux"),
        ("Linux", "x86_64", DEBIAN, "aarch64"),
        ("Linux", "aarch64", "ID=ubuntu\n", "Debian"),
        ("Linux", "aarch64", "ID_LIKE=debian\n", "Debian"),
        ("Linux", "aarch64", "", "Debian"),
    ],
)
def test_check_guest_refuses_non_guest(system, machine, os_release, fragment):
    with pytest.raises(runner.GuestRefused, match=fragment):
        runner.check_guest(system, machine, os_release)


def test_main_refuses_non_guest_without_running_commands(capsys):
    with mock.patch.object(runner.platform, "system", return_value="Darwin"), \
            mock.patch.object(runner.platform, "machine", return_value="arm64"), \
            mock.patch.object(runner.subprocess, "run") as run, \
            mock.patch.object(runner.shutil, "which") as which:
        code = runner.main([])
    assert code == runner.EXIT_REFUSED
    run.assert_not_called()
    which.assert_not_called()
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["step"] == "guest-check"


def test_main_has_no_bypass_option():
    with pytest.raises(SystemExit) as exc:
        runner.main(["--force-guest"])
    assert exc.value.code == 2


def test_run_mio_uses_argument_array_without_shell():
    done = subprocess.CompletedProcess([], 0, "{}", "")
    with mock.patch.object(runner.subprocess, "run", return_value=done) as run:
        runner.run_mio("/usr/bin/mio-ir", ["case", "list"], {"PATH": "/usr/bin"})
    assert run.call_args.args[0] == ["/usr/bin/mio-ir", "case", "list"]
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["timeout"] == runner.TIMEOUT_SECONDS


def test_run_mio_timeout_is_bounded_failure():
    with mock.patch.object(runner.subprocess, "run",
                           side_effect=subprocess.TimeoutExpired(["mio-ir"], 30)):
        with pytest.raises(runner.AcceptanceError, match="timed out") as exc:
            runner.run_mio("mio-ir", [], {})
    assert exc.value.step == "timeout"


def test_run_mio_os_error_is_bounded_failure():
    with mock.patch.object(runner.subprocess, "run", side_effect=OSError("no such file")):
        with pytest.raises(runner.AcceptanceError, match="could not start"):
            runner.run_mio("mio-ir", [], {})


def test_parse_json_stdout_accepts_json():
    assert runner.parse_json_stdout("case.list", '[{"case_id": 1}]') == [{"case_id": 1}]


def test_parse_json_stdout_rejects_non_json_with_bounded_message():
    with pytest.raises(runner.AcceptanceError) as exc:
        runner.parse_json_stdout("case.list", "x" * 5000)
    assert exc.value.step == "case.list"
    assert len(exc.value.message) <= runner.DIAG_LIMIT + 200


def test_bounded_truncates_and_collapses_whitespace():
    assert runner.bounded("a  \n b") == "a b"
    assert len(runner.bounded("z" * 5000)) <= runner.DIAG_LIMIT + len("...[truncated]")


def test_all_valid_requires_nonempty_all_true():
    assert runner.all_valid([{"valid": True}])
    assert not runner.all_valid([])
    assert not runner.all_valid([{"valid": True}, {"valid": False}])
    assert not runner.all_valid({"valid": True})


def test_installed_version_reports_missing_package():
    with mock.patch.object(runner.importlib.metadata, "version",
                           side_effect=importlib.metadata.PackageNotFoundError("azazel-mio")):
        with pytest.raises(runner.AcceptanceError, match="not installed"):
            runner.installed_version()


def test_installed_version_returns_version_string():
    with mock.patch.object(runner.importlib.metadata, "version", return_value="0.1.0"):
        assert runner.installed_version() == "0.1.0"


def test_peak_rss_converts_bytes_on_darwin_only():
    usage = SimpleNamespace(ru_maxrss=2048 * 1024)
    with mock.patch.object(runner.resource, "getrusage", return_value=usage):
        assert runner.peak_rss_kb("Darwin") == 2048
        assert runner.peak_rss_kb("Linux") == 2048 * 1024


def test_tamper_object_refuses_missing_path(tmp_path):
    with pytest.raises(runner.AcceptanceError, match="not a regular file"):
        runner.tamper_object(tmp_path / "missing")


def test_tamper_object_rewrites_only_given_temp_file(tmp_path):
    target = tmp_path / "digest"
    target.write_bytes(b"original")
    runner.tamper_object(target)
    assert target.read_bytes() == b"tampered by acceptance runner\n"


def test_require_raises_with_step():
    with pytest.raises(runner.AcceptanceError) as exc:
        runner.require("step.x", False, "bad")
    assert exc.value.step == "step.x"
