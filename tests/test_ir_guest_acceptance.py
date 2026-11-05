"""Host-side tests for the guest acceptance runner; no real mio-ir is invoked."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ir_guest_acceptance.py"
_spec = importlib.util.spec_from_file_location("ir_guest_acceptance", SCRIPT)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\nVERSION_ID="12"\n'
TIMELINE = [
    {"event_id": 2, "evidence_id": 1, "record": 2,
     "timestamp_utc": "2026-01-01T00:00:01+00:00", "summary": "synthetic alert B"},
    {"event_id": 1, "evidence_id": 1, "record": 1,
     "timestamp_utc": "2026-01-01T00:00:02+00:00", "summary": "synthetic alert A"},
    {"event_id": 3, "evidence_id": 1, "record": 3,
     "timestamp_utc": None, "summary": "synthetic record without timestamp"},
]


def test_parse_os_release_strips_quotes_and_comments():
    fields = runner.parse_os_release('# comment\nID="debian"\n\nNOEQUALS\nNAME=\'Debian\'\n')
    assert fields == {"ID": "debian", "NAME": "Debian"}


@pytest.mark.parametrize("machine", ["aarch64", "arm64"])
def test_check_guest_accepts_debian_arm64(machine):
    assert runner.check_guest("Linux", machine, DEBIAN) == {
        "os": "linux", "distro": "debian", "arch": machine,
    }


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


@pytest.mark.parametrize("virt_type", ["vmware"])
def test_check_vmware_accepts_only_vmware(virt_type):
    assert runner.check_vmware(virt_type) == "vmware"


@pytest.mark.parametrize("virt_type", ["", "none", "kvm", "docker"])
def test_check_vmware_refuses_other_hosts(virt_type):
    with pytest.raises(runner.GuestRefused, match="VMware"):
        runner.check_vmware(virt_type)


def test_vm_detector_uses_only_fixed_system_paths(tmp_path, monkeypatch):
    tool = tmp_path / "systemd-detect-virt"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setattr(runner, "VM_DETECTOR_PATHS", (tool,))
    assert runner.resolve_vm_detector() == str(tool)
    tool.chmod(0o644)
    assert runner.resolve_vm_detector() is None


def test_main_refuses_non_guest_without_running_commands(capsys):
    with mock.patch.object(runner.platform, "system", return_value="Darwin"), \
            mock.patch.object(runner.platform, "machine", return_value="arm64"), \
            mock.patch.object(runner, "read_os_release", return_value=DEBIAN), \
            mock.patch.object(runner.subprocess, "Popen") as popen, \
            mock.patch.object(runner.shutil, "which") as which:
        code = runner.main([])
    assert code == runner.EXIT_REFUSED
    popen.assert_not_called()
    which.assert_not_called()
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["step"] == "guest-check"


def test_main_has_no_bypass_option():
    with pytest.raises(SystemExit) as exc:
        runner.main(["--force-guest"])
    assert exc.value.code == 2


def test_console_script_resolves_env_shebang_to_command_path(tmp_path):
    exe = tmp_path / "mio-ir"
    exe.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    with mock.patch.object(runner.shutil, "which", return_value="/venv/bin/python3") as which:
        assert runner.console_script_interpreter(str(exe), "/venv/bin:/usr/bin") == "/venv/bin/python3"
    which.assert_called_once_with("python3", path="/venv/bin:/usr/bin")


def test_console_script_resolves_direct_shebang(tmp_path):
    exe = tmp_path / "mio-ir"
    exe.write_text("#!/venv/bin/python3\n", encoding="utf-8")
    assert runner.console_script_interpreter(str(exe), "/usr/bin") == "/venv/bin/python3"


def test_installed_version_uses_entrypoint_interpreter(tmp_path):
    exe = tmp_path / "mio-ir"
    exe.write_text("#!/venv/bin/python3\n", encoding="utf-8")
    done = subprocess.CompletedProcess([], 0, "0.1.0\n", "")
    with mock.patch.object(runner, "run_captured", return_value=done) as run:
        assert runner.installed_version(str(exe), "/venv/bin", "/user-home") == "0.1.0"
    assert run.call_args.args[0][0] == "/venv/bin/python3"
    assert run.call_args.args[0][1:3] == ["-P", "-c"]
    assert run.call_args.args[1]["HOME"] == "/user-home"


def test_installed_version_rejects_metadata_failure(tmp_path):
    exe = tmp_path / "mio-ir"
    exe.write_text("#!/venv/bin/python3\n", encoding="utf-8")
    done = subprocess.CompletedProcess([], 1, "", "missing package")
    with mock.patch.object(runner, "run_captured", return_value=done):
        with pytest.raises(runner.AcceptanceError, match="metadata unavailable"):
            runner.installed_version(str(exe), "/venv/bin", "/user-home")


def test_run_captured_uses_argv_without_shell_and_returns_json():
    with mock.patch.object(runner.subprocess, "Popen", wraps=subprocess.Popen) as popen:
        result = runner.run_mio(sys.executable, ["-c", "print('{}')"], {}, timeout=2)
    assert result.returncode == 0
    assert result.stdout.strip() == "{}"
    assert popen.call_args.args[0] == [sys.executable, "-c", "print('{}')"]
    assert popen.call_args.kwargs["shell"] is False


def test_run_captured_enforces_timeout():
    with pytest.raises(runner.AcceptanceError, match="timed out"):
        runner.run_mio(sys.executable, ["-c", "import time; time.sleep(2)"], {}, timeout=0.5)


def test_run_captured_bounds_stdout_and_stderr():
    with mock.patch.object(runner, "MAX_COMMAND_OUTPUT_BYTES", 64):
        with pytest.raises(runner.AcceptanceError, match="output limit"):
            runner.run_mio(sys.executable, ["-c", "print('x' * 1000)"], {}, timeout=2)
        with pytest.raises(runner.AcceptanceError, match="output limit"):
            runner.run_mio(sys.executable, ["-c", "import sys; print('x' * 1000, file=sys.stderr)"], {}, timeout=2)


def test_acceptance_deadline_fails_before_invoking_another_command():
    accept = runner.Acceptance("mio-ir", {})
    accept.deadline = runner.time.monotonic() - 1
    with mock.patch.object(runner, "run_mio") as run:
        with pytest.raises(runner.AcceptanceError) as exc:
            accept.invoke("case.create", ["case", "create"])
    assert exc.value.step == "case.create"
    run.assert_not_called()


def test_parse_json_stdout_accepts_json():
    assert runner.parse_json_stdout("case.list", '[{"case_id": 1}]') == [{"case_id": 1}]
    assert runner.parse_json_stdout("case.list", '{"text": "[[[[not nesting]]]]"}') == {
        "text": "[[[[not nesting]]]]"
    }


def test_parse_json_stdout_rejects_invalid_and_deep_json():
    with pytest.raises(runner.AcceptanceError, match="stdout is not JSON"):
        runner.parse_json_stdout("case.list", "x" * 5000)
    with pytest.raises(runner.AcceptanceError, match="stdout is not JSON"):
        runner.parse_json_stdout("case.list", "[" * 2000 + "0" + "]" * 2000)
    depth = runner.MAX_JSON_DEPTH
    assert runner.parse_json_stdout(
        "case.list", "[" * depth + "0" + "]" * depth
    ) == nested_list(depth)


def nested_list(depth):
    value = 0
    for _ in range(depth):
        value = [value]
    return value


def test_bounded_truncates_and_collapses_whitespace():
    assert runner.bounded("a  \n b") == "a b"
    assert len(runner.bounded("z" * 5000)) <= runner.DIAG_LIMIT + len("...[truncated]")


def test_all_valid_requires_nonempty_all_true():
    assert runner.all_valid([{"valid": True}])
    assert not runner.all_valid([])
    assert not runner.all_valid([{"valid": True}, {"valid": False}])
    assert not runner.all_valid({"valid": True})


def test_tamper_object_rejects_bad_digest_and_preserves_external_file(tmp_path):
    home = tmp_path / "home"
    (home / "objects").mkdir(parents=True)
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(runner.AcceptanceError, match="SHA-256"):
        runner.tamper_object(home, "../sentinel", tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_tamper_object_rewrites_only_digest_child(tmp_path):
    home = tmp_path / "home"
    objects = home / "objects"
    objects.mkdir(parents=True)
    digest = "a" * 64
    target = objects / digest
    target.write_bytes(b"original")
    target.chmod(0o444)
    runner.tamper_object(home, digest, tmp_path)
    assert target.read_bytes() == b"tampered by acceptance runner\n"


def test_tamper_object_refuses_symlink_and_hardlink(tmp_path):
    home = tmp_path / "home"
    objects = home / "objects"
    objects.mkdir(parents=True)
    digest = "b" * 64
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    (objects / digest).symlink_to(outside)
    with pytest.raises(runner.AcceptanceError, match="safely modified"):
        runner.tamper_object(home, digest, tmp_path)
    (objects / digest).unlink()
    (objects / digest).hardlink_to(outside)
    with pytest.raises(runner.AcceptanceError, match="single-link"):
        runner.tamper_object(home, digest, tmp_path)
    assert outside.read_bytes() == b"preserve"


def test_tamper_object_refuses_home_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    (outside / "objects").mkdir(parents=True)
    digest = "c" * 64
    (outside / "objects" / digest).write_bytes(b"preserve")
    accepted = tmp_path / "accepted"
    accepted.mkdir()
    home_link = accepted / "home"
    home_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(runner.AcceptanceError, match="escaped"):
        runner.tamper_object(home_link, digest, accepted)
    assert (outside / "objects" / digest).read_bytes() == b"preserve"


def _mock_cli(*, bad_create=None, fake_digest=None, tamper_detected=True,
              tamper_exit_code=None, timeline_override=None, report_override=None):
    state = {"source": None, "digest": None}
    def run(_exe, args, env, timeout=runner.TIMEOUT_SECONDS):
        del timeout
        if args[:2] == ["case", "create"]:
            payload = bad_create if bad_create is not None else {"case_id": 1}
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        if args == ["case", "list"]:
            return subprocess.CompletedProcess(args, 0, '[{"case_id":1,"name":"acceptance-synthetic"}]', "")
        if args[:2] == ["evidence", "import"]:
            source = Path(args[args.index("--file") + 1])
            state["source"] = source.read_bytes()
            digest = hashlib.sha256(state["source"]).hexdigest()
            state["digest"] = digest
            objects = Path(env["MIO_IR_HOME"]) / "objects"
            objects.mkdir(parents=True, exist_ok=True)
            (objects / digest).write_bytes(state["source"])
            return subprocess.CompletedProcess(args, 0, '{"evidence_id":1}', "")
        if args[:2] == ["evidence", "verify"]:
            digest = fake_digest if fake_digest is not None else state["digest"]
            path = Path(env["MIO_IR_HOME"]) / "objects" / str(state["digest"])
            content_ok = path.read_bytes() == state["source"]
            valid = content_ok if args[2:] == ["--case", "1"] and tamper_detected else content_ok
            if args[2:] == ["--case", "1"] and path.read_bytes() != state["source"]:
                valid = not tamper_detected
            code = 0 if valid else runner.VERIFY_INVALID_EXIT
            if args[2:] == ["--case", "1"] and tamper_exit_code is not None and path.read_bytes() != state["source"]:
                code = tamper_exit_code
            payload = [{"evidence_id": 1, "sha256": digest, "valid": valid}]
            return subprocess.CompletedProcess(args, code, json.dumps(payload), "")
        if args[:2] == ["timeline", "build"]:
            payload = TIMELINE if timeline_override is None else timeline_override
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        if args[:2] == ["report", "generate"]:
            output = Path(args[args.index("--output") + 1])
            fmt = args[args.index("--format") + 1]
            if fmt == "json":
                data = report_override if report_override is not None else {
                    "case_id": 1, "timeline": TIMELINE,
                    "evidence": [{"evidence_id": 1, "sha256": state["digest"], "valid": True}],
                }
                output.write_text(json.dumps(data), encoding="utf-8")
            else:
                output.write_text(
                    "# IR Case 1\n- synthetic alert A\n- synthetic alert B\nEvidence verification: []\n",
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(args, 0, json.dumps({"output": str(output)}), "")
        raise AssertionError("unexpected command: " + repr(args))
    return run


def test_acceptance_run_checks_full_success_sequence_and_tamper(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    home = work / "home"
    home.mkdir()
    accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
    with mock.patch.object(runner, "run_mio", side_effect=_mock_cli()):
        summary = accept.run(work)
    assert summary == {"case_id": 1, "evidence_id": 1, "timeline_events": 3, "tamper_detected": True}
    assert [step["step"] for step in accept.steps] == [
        "case.create", "case.list", "evidence.import", "evidence.verify", "timeline.build",
        "report.json", "report.json.read", "report.markdown", "report.markdown.read",
        "tamper.object", "evidence.verify.tampered",
    ]


def test_acceptance_run_rejects_bad_json_and_missing_case_id(tmp_path):
    for payload, expected in [(None, "stdout is not JSON"), ({"wrong": 1}, "no case_id")]:
        home = tmp_path / ("home-" + str(payload))
        home.mkdir()
        accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
        fake = _mock_cli(bad_create=payload if payload is not None else None)
        if payload is None:
            fake = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-json", "")
        work = tmp_path / ("work-" + str(payload))
        work.mkdir()
        with mock.patch.object(runner, "run_mio", side_effect=fake):
            with pytest.raises(runner.AcceptanceError, match=expected):
                accept.run(work)


def test_acceptance_includes_actual_failed_step_and_partial_timing():
    accept = runner.Acceptance("mio-ir", {})
    with mock.patch.object(runner, "run_mio", side_effect=runner.AcceptanceError("timeout", "timed out")):
        with pytest.raises(runner.AcceptanceError) as exc:
            accept.invoke("case.create", ["case", "create"])
    assert exc.value.step == "case.create"
    assert [step["step"] for step in accept.steps] == ["case.create"]


def test_acceptance_rejects_untested_tamper_failure(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    home = work / "home"
    home.mkdir()
    accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
    fake = _mock_cli(tamper_detected=False, tamper_exit_code=runner.VERIFY_INVALID_EXIT)
    with mock.patch.object(runner, "run_mio", side_effect=fake):
        with pytest.raises(runner.AcceptanceError) as exc:
            accept.run(work)
    assert exc.value.step == "evidence.verify.tampered"


def test_acceptance_rejects_digest_escape_from_cli_output(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    home = work / "home"
    home.mkdir()
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
    with mock.patch.object(runner, "run_mio", side_effect=_mock_cli(fake_digest="../sentinel")):
        with pytest.raises(runner.AcceptanceError, match="does not match") as exc:
            accept.run(work)
    assert exc.value.step == "evidence.verify"
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_acceptance_rejects_wrong_well_formed_digest(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    home = work / "home"
    home.mkdir()
    accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
    with mock.patch.object(runner, "run_mio", side_effect=_mock_cli(fake_digest="0" * 64)):
        with pytest.raises(runner.AcceptanceError, match="does not match") as exc:
            accept.run(work)
    assert exc.value.step == "evidence.verify"


@pytest.mark.parametrize("timeline,report", [([1, 2, 3], None), (None, {"timeline": [], "evidence": []})])
def test_acceptance_rejects_malformed_timeline_and_report(tmp_path, timeline, report):
    work = tmp_path / "work"
    work.mkdir()
    home = work / "home"
    home.mkdir()
    accept = runner.Acceptance("mio-ir", {"MIO_IR_HOME": str(home)})
    with mock.patch.object(runner, "run_mio", side_effect=_mock_cli(
            timeline_override=timeline, report_override=report)):
        with pytest.raises(runner.AcceptanceError) as exc:
            accept.run(work)
    assert exc.value.step == ("timeline.build" if timeline is not None else "report.json")


def test_main_success_reports_vmware_version_home_and_steps(monkeypatch, capsys):
    observed = {}
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(runner, "read_os_release", lambda: DEBIAN)
    monkeypatch.setattr(runner, "resolve_vm_detector", lambda: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runner, "run_captured", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, "vmware\n", ""))
    monkeypatch.setattr(runner, "installed_version", lambda *_args: "0.1.0")
    monkeypatch.setattr(runner, "peak_rss_kb", lambda: {
        "runner": 100, "children_all_steps": 200, "max": 200,
    })

    def fake_acceptance_run(self, work):
        home = Path(self.env["HOME"])
        observed["home_preserved"] = str(home) == os.environ.get("HOME", str(home))
        observed["mio_home_inside_work"] = Path(self.env["MIO_IR_HOME"]).is_relative_to(work)
        self.steps.append({"step": "case.create", "duration_ms": 1.0})
        return {"case_id": 1, "evidence_id": 1, "timeline_events": 3, "tamper_detected": True}

    monkeypatch.setattr(runner.Acceptance, "run", fake_acceptance_run)
    assert runner.main([]) == runner.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["guest"]["virtualization"] == "vmware"
    assert payload["command"]["version"] == "0.1.0"
    assert payload["steps"] == [{"step": "case.create", "duration_ms": 1.0}]
    assert payload["peak_rss_kb"] == {"runner": 100, "children_all_steps": 200, "max": 200}
    assert observed == {"home_preserved": True, "mio_home_inside_work": True}


def test_main_failure_reports_step_and_partial_timings(monkeypatch, capsys):
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(runner, "read_os_release", lambda: DEBIAN)
    monkeypatch.setattr(runner, "resolve_vm_detector", lambda: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(runner, "resolve_vm_detector", lambda: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runner, "run_captured", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, "vmware\n", ""))
    monkeypatch.setattr(runner, "installed_version", lambda *_args: "0.1.0")

    def failing_run(self, _work):
        self.steps.append({"step": "case.create", "duration_ms": 5.0})
        raise runner.AcceptanceError("case.create", "fixture failure")

    monkeypatch.setattr(runner.Acceptance, "run", failing_run)
    assert runner.main([]) == runner.EXIT_FAILURE
    payload = json.loads(capsys.readouterr().out)
    assert payload["step"] == "case.create"
    assert payload["steps"] == [{"step": "case.create", "duration_ms": 5.0}]


@pytest.mark.parametrize("detector,output", [(None, ""), ("/usr/bin/systemd-detect-virt", "kvm\n")])
def test_main_refuses_missing_or_non_vmware_detector(monkeypatch, capsys, detector, output):
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(runner, "read_os_release", lambda: DEBIAN)
    monkeypatch.setattr(runner, "resolve_vm_detector", lambda: detector)
    with mock.patch.object(runner, "run_captured", return_value=
                           subprocess.CompletedProcess([], 0 if detector else 1, output, "")) as run:
        with mock.patch.object(runner, "installed_version") as version:
            assert runner.main([]) == runner.EXIT_REFUSED
    payload = json.loads(capsys.readouterr().out)
    assert payload["step"] == "guest-check"
    version.assert_not_called()
    assert run.called is (detector is not None)


def test_main_supplies_fallback_home_when_home_is_unset(monkeypatch, capsys):
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setattr(runner.Path, "home", lambda: Path("/synthetic-home"))
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(runner, "read_os_release", lambda: DEBIAN)
    monkeypatch.setattr(runner, "resolve_vm_detector", lambda: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(runner, "run_captured", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, "vmware\n", ""))
    monkeypatch.setattr(runner.shutil, "which", lambda _name: "/usr/bin/mio-ir")
    monkeypatch.setattr(runner, "installed_version", lambda *_args: "0.1.0")
    monkeypatch.setattr(runner, "peak_rss_kb", lambda: {"runner": 1, "children_all_steps": 1, "max": 1})
    observed = {}

    def fake_run(self, work):
        observed["HOME"] = self.env["HOME"]
        observed["MIO_IR_HOME_inside_temp"] = Path(self.env["MIO_IR_HOME"]).is_relative_to(work)
        self.steps.append({"step": "done", "duration_ms": 1.0})
        return {"case_id": 1, "evidence_id": 1, "timeline_events": 0, "tamper_detected": True}

    monkeypatch.setattr(runner.Acceptance, "run", fake_run)
    assert runner.main([]) == runner.EXIT_OK
    capsys.readouterr()
    assert observed == {"HOME": "/synthetic-home", "MIO_IR_HOME_inside_temp": True}
