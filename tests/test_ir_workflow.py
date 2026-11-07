import io
import json
import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from azazel_mio import cli as ir_cli
from azazel_mio.cli import (
    EXIT_INVALID_EVIDENCE,
    MAX_BYTES,
    MAX_JSON_NESTING,
    MAX_RECORDS,
    MAX_TIMESTAMP_CHARS,
    connect,
    import_file,
    main,
    parse_records,
    report,
    root_path,
    timeline,
    verify,
)
from azazel_mio.fast_assessment import FastAssessmentInput, PortSignal, assess_fast
from azazel_mio.ir_adapter import KERNEL_SOURCE_REVISION

INPUT_SCHEMA = "mio.ir.fast-assessment-inputs.v1"
EXPLANATION = (
    "Candidate-only advisory priority index from caller-asserted normalized signals; "
    "factors are the kernel terms. Not a fact, probability or authorization."
)


class IRWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.inputs, True)
        self.db = connect(self.root)
        self.addCleanup(self.db.close)
        self.case = self.db.execute("INSERT INTO cases(name,created) VALUES('test','now')").lastrowid
        self.db.commit()
        self.source = self.root / "sample.jsonl"
        self.source.write_text('{"timestamp":"2026-10-01T10:00:00+09:00","summary":"synthetic"}\n', encoding="utf-8")

    def test_import_verify_timeline_report(self):
        eid = import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertTrue(verify(self.db, self.root, self.case)[0]["valid"])
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        stored = self.root / "objects" / digest
        self.assertEqual(stat.S_IMODE(stored.lstat().st_mode), 0o400)
        self.assertEqual(verify(self.db, self.root, self.case)[0]["case_id"], self.case)
        self.assertEqual(timeline(self.db, self.case)[0]["evidence_id"], eid)
        self.assertEqual(timeline(self.db, self.case)[0]["case_id"], self.case)
        self.assertEqual(timeline(self.db, self.case)[0]["timestamp_utc"], "2026-10-01T01:00:00+00:00")
        self.assertEqual(report(self.db, self.root, self.case)["timeline"][0]["record"], 1)

    def test_tamper_detected(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        (self.root / "objects" / digest).chmod(0o600)
        (self.root / "objects" / digest).write_text("tampered")
        self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])

    def test_verify_does_not_read_oversized_object_into_memory(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        stored = self.root / "objects" / digest
        stored.chmod(0o600)
        with stored.open("wb") as handle:
            handle.truncate(MAX_BYTES + 1)
        original_open = Path.open
        opened = []

        def track_open(path, *args, **kwargs):
            opened.append(path)
            if path == stored:
                raise AssertionError("oversized object must not be opened")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=track_open):
            self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])
        self.assertNotIn(stored, opened)

    def test_import_refuses_oversized_existing_object_without_reading_it(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        stored = self.root / "objects" / digest
        stored.chmod(0o600)
        with stored.open("wb") as handle:
            handle.truncate(MAX_BYTES + 1)
        original_open = Path.open
        opened = []

        def track_open(path, *args, **kwargs):
            opened.append(path)
            if path == stored:
                raise AssertionError("oversized object must not be opened")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=track_open):
            with self.assertRaisesRegex(ValueError, "stored object corrupted or too large"):
                import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertNotIn(stored, opened)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_existing_fifo_object_is_rejected_without_reading(self):
        digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        objects = self.root / "objects"
        objects.mkdir(mode=0o700)
        os.mkfifo(objects / digest)
        with self.assertRaisesRegex(ValueError, "stored object"):
            import_file(self.db, self.root, self.case, self.source, "jsonl")

    def test_existing_hardlinked_object_is_rejected(self):
        raw = self.source.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        objects = self.root / "objects"
        objects.mkdir(mode=0o700)
        outside = self.root / "outside-object"
        outside.write_bytes(raw)
        (objects / digest).hardlink_to(outside)
        with self.assertRaisesRegex(ValueError, "stored object"):
            import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertEqual(outside.read_bytes(), raw)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_verify_marks_symlink_hardlink_and_fifo_objects_invalid(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        objects = self.root / "objects"
        stored = objects / digest
        outside = self.root / "outside-object"
        outside.write_bytes(self.source.read_bytes())
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if stored.exists() or stored.is_symlink():
                    stored.unlink()
                if kind == "symlink":
                    stored.symlink_to(outside)
                elif kind == "hardlink":
                    stored.hardlink_to(outside)
                else:
                    os.mkfifo(stored)
                self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])

    def test_verify_marks_foreign_owned_object_invalid(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        stored_inode = (self.root / "objects" / digest).lstat().st_ino

        def owner_check(metadata):
            return metadata.st_ino != stored_inode

        with patch("azazel_mio.cli.current_user_owns", side_effect=owner_check):
            self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])

    def test_import_refuses_shared_objects_directory_without_chmod(self):
        objects = self.root / "objects"
        objects.mkdir(mode=0o755)
        objects.chmod(0o755)
        before = stat.S_IMODE(objects.lstat().st_mode)
        with self.assertRaisesRegex(ValueError, "owned private directory"):
            import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertEqual(stat.S_IMODE(objects.lstat().st_mode), before)

    def test_deep_json_is_reported_as_input_error(self):
        source = self.root / "deep.json"
        source.write_bytes(b'{"x":' * 10000 + b"0" + b"}" * 10000)
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", "evidence", "import", "--case", str(self.case),
                         "--file", str(source), "--format", "json"]
        ):
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(), 1)
        self.assertIn("error: JSON nesting exceeds parser limit", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_json_nesting_limit_accepts_boundary(self):
        nested = (b'{"x":' * (MAX_JSON_NESTING - 1) + b"0"
                  + b"}" * (MAX_JSON_NESTING - 1))
        raw = b'{"summary":"bounded","nested":' + nested + b"}"
        self.assertEqual(len(parse_records(raw, "json")), 1)

    def test_json_nesting_limit_rejects_one_above_boundary(self):
        nested = (b'{"x":' * MAX_JSON_NESTING + b"0"
                  + b"}" * MAX_JSON_NESTING)
        raw = b'{"summary":"too deep","nested":' + nested + b"}"
        with self.assertRaisesRegex(ValueError, "JSON nesting exceeds parser limit"):
            parse_records(raw, "json")

    def test_json_nesting_limit_ignores_braces_inside_strings(self):
        raw = json.dumps({"summary": "{" * (MAX_JSON_NESTING + 1) + "}" * (MAX_JSON_NESTING + 1)}).encode()
        self.assertEqual(len(parse_records(raw, "json")), 1)

    def test_deep_jsonl_is_a_bounded_input_error(self):
        nested = b'{"x":' * 10000 + b"0" + b"}" * 10000
        raw = b'{"summary":"deep","nested":' + nested + b"}\n"
        with self.assertRaisesRegex(ValueError, "JSON nesting exceeds parser limit"):
            parse_records(raw, "jsonl")

    def test_jsonl_record_limit_stops_before_parsing_extra_record(self):
        raw = b"{}\n" * MAX_RECORDS + b"not-json\n"
        with self.assertRaisesRegex(ValueError, "record count"):
            parse_records(raw, "jsonl")

    def test_json_array_record_limit_stops_before_parsing_extra_record(self):
        raw = b"[" + b",".join([b"{}"] * MAX_RECORDS) + b",not-json]"
        with self.assertRaisesRegex(ValueError, "record count"):
            parse_records(raw, "json")

    def test_json_array_rejects_trailing_comma(self):
        with self.assertRaises(json.JSONDecodeError):
            parse_records(b"[{} ,]", "json")

    def test_empty_json_array_has_zero_records(self):
        self.assertEqual(parse_records(b"[]", "json"), [])

    def test_json_scalar_top_level_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "JSON input must be an object or array"):
            parse_records(b"5", "json")

    def test_json_array_requires_object_records(self):
        with self.assertRaisesRegex(ValueError, "each JSON array record must be an object"):
            parse_records(b"[5]", "json")

    def test_jsonl_scalar_record_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "each JSONL record must be an object"):
            parse_records(b"5\n", "jsonl")

    def test_jsonl_keeps_unicode_separators_inside_strings(self):
        for separator in ("\u2028", "\u0085"):
            with self.subTest(separator=hex(ord(separator))):
                raw = json.dumps(
                    {"summary": "left" + separator + "right"}, ensure_ascii=False
                ).encode("utf-8") + b"\r\n"
                records = parse_records(raw, "jsonl")
                self.assertEqual(records[0][3], "left" + separator + "right")

    def test_jsonl_rejects_unicode_whitespace_only_lines(self):
        for separator in ("\u2028", "\u00a0"):
            with self.subTest(separator=hex(ord(separator))), self.assertRaises(json.JSONDecodeError):
                parse_records((separator + "\n{}").encode("utf-8"), "jsonl")

    def test_nested_summary_is_a_clean_input_error(self):
        source = self.root / "nested-summary.json"
        source.write_text('{"summary":{"nested":[{"value":1}]}}', encoding="utf-8")
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", "evidence", "import", "--case", str(self.case),
                         "--file", str(source), "--format", "json"]
        ):
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(), 1)
        self.assertIn("error: summary must be a JSON scalar", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_null_summary_is_empty_and_absent_summary_uses_default(self):
        null_summary = parse_records(b'{"summary":null}', "json")[0][3]
        absent_summary = parse_records(b"{}", "json")[0][3]
        self.assertEqual(null_summary, "")
        self.assertEqual(absent_summary, "No summary provided")

    def test_unrepresentable_summary_is_rejected_before_object_write(self):
        source = self.root / "surrogate-summary.json"
        source.write_text('{"summary":"\\ud800"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "summary must be valid UTF-8"):
            import_file(self.db, self.root, self.case, source, "json")
        self.assertFalse((self.root / "objects").exists())

    def test_reimport_creates_distinct_receipts_but_deduplicates_object(self):
        first = import_file(self.db, self.root, self.case, self.source, "jsonl")
        second = import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertNotEqual(first, second)
        count = self.db.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id=?", (self.case,)
        ).fetchone()[0]
        self.assertEqual(count, 2)
        self.assertEqual(len(list((self.root / "objects").iterdir())), 1)
        rows = timeline(self.db, self.case)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["evidence_id"] for row in rows}, {first, second})

    def test_invalid_timestamp_unknown(self):
        self.assertIsNone(parse_records(b'{"timestamp":"not-a-date","summary":"x"}', "json")[0][1])

    def test_timestamp_utc_overflow_is_unknown(self):
        record = b'{"timestamp":"0001-01-01T00:00:00+09:00"}'
        self.assertIsNone(parse_records(record, "json")[0][1])

    def test_timestamp_without_explicit_offset_is_unknown(self):
        record = b'{"timestamp":"2026-10-01T10:00:00"}'
        self.assertIsNone(parse_records(record, "json")[0][1])

    def test_timestamp_length_is_bounded(self):
        oversized = "x" * (MAX_TIMESTAMP_CHARS + 1)
        raw = json.dumps({"timestamp": oversized}).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "timestamp exceeds length limit"):
            parse_records(raw, "json")

    def test_summary_truncation_preserves_original_object(self):
        long_summary = "x" * 2050
        source = self.root / "long-summary.json"
        original = json.dumps({"summary": long_summary}).encode("utf-8")
        source.write_bytes(original)
        import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(len(timeline(self.db, self.case)[0]["summary"]), 2048)
        digest = hashlib.sha256(original).hexdigest()
        self.assertEqual((self.root / "objects" / digest).read_bytes(), original)

    def test_empty_jsonl_is_empty_but_empty_json_is_rejected(self):
        self.assertEqual(parse_records(b"", "jsonl"), [])
        with self.assertRaises(json.JSONDecodeError):
            parse_records(b"", "json")

    def test_utf8_bom_is_rejected_for_json_and_jsonl(self):
        for fmt in ("json", "jsonl"):
            with self.subTest(fmt=fmt), self.assertRaises(json.JSONDecodeError):
                parse_records(b"\xef\xbb\xbf{}", fmt)

    def test_empty_mio_ir_home_is_rejected(self):
        with patch.dict(os.environ, {"MIO_IR_HOME": ""}):
            with self.assertRaisesRegex(ValueError, "MIO_IR_HOME must not be empty"):
                root_path()

    def test_relative_mio_ir_home_is_rejected(self):
        with patch.dict(os.environ, {"MIO_IR_HOME": "relative-store"}):
            with self.assertRaisesRegex(ValueError, "storage path must be absolute"):
                root_path()

    def test_missing_home_is_a_clean_cli_error(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "sys.argv", ["mio-ir", "case", "create", "--name", "test"]
        ):
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(), 1)
        self.assertIn("error: HOME is required", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_empty_mio_ir_home_is_a_clean_cli_error(self):
        with patch.dict(os.environ, {"MIO_IR_HOME": ""}), patch(
            "sys.argv", ["mio-ir", "case", "create", "--name", "test"]
        ):
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(), 1)
        self.assertIn("error: MIO_IR_HOME must not be empty", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_symlink_rejected(self):
        link = self.root / "link.jsonl"
        link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            import_file(self.db, self.root, self.case, link, "jsonl")

    def test_storage_symlinks_rejected(self):
        link = self.root / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unsafe storage"):
            connect(link)
        directory = self.root / "objects"
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unsafe object directory"):
            import_file(self.db, self.root, self.case, self.source, "jsonl")

    def test_existing_shared_storage_mode_is_not_changed(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        before = stat.S_IMODE(shared.lstat().st_mode)
        with self.assertRaisesRegex(ValueError, "owned private directory"):
            connect(shared)
        self.assertEqual(stat.S_IMODE(shared.lstat().st_mode), before)

    def test_new_storage_is_private(self):
        new_root = self.root / "new-private-store"
        db = connect(new_root)
        db.close()
        self.assertEqual(stat.S_IMODE(new_root.lstat().st_mode), 0o700)

    def test_new_storage_rejects_foreign_owner(self):
        new_root = self.root / "new-foreign-store"
        with patch("azazel_mio.cli.current_user_owns", return_value=False):
            with self.assertRaisesRegex(ValueError, "owned private directory"):
                connect(new_root)
        self.assertTrue(new_root.is_dir())
        self.assertEqual(stat.S_IMODE(new_root.lstat().st_mode), 0o700)

    def test_storage_fails_closed_without_owner_identity(self):
        with patch("azazel_mio.cli.os.getuid", None):
            with self.assertRaisesRegex(ValueError, "owned private directory"):
                connect(self.root)

    def test_connect_closes_database_when_schema_setup_fails(self):
        db = MagicMock()
        with patch("azazel_mio.cli.sqlite3.connect", return_value=db), patch(
                "azazel_mio.cli.migrate_schema", side_effect=sqlite3.Error("schema failure")) as migrate:
            with self.assertRaisesRegex(sqlite3.Error, "schema failure"):
                connect(self.root)
        migrate.assert_called_once_with(db)
        db.close.assert_called_once()

    def test_main_closes_database_after_successful_command(self):
        db = sqlite3.connect(self.root / "cases.sqlite3")
        output = StringIO()
        with patch("azazel_mio.cli.sqlite3.connect", return_value=db), patch.dict(
            os.environ, {"MIO_IR_HOME": str(self.root)}
        ), patch("sys.argv", ["mio-ir", "case", "create", "--name", "created"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)
        self.assertEqual(json.loads(output.getvalue())["case_id"], 2)
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")

    def test_sqlite_sidecars_reject_links_before_open(self):
        for suffix in ("-journal", "-wal", "-shm"):
            for kind in ("symlink", "hardlink"):
                with self.subTest(suffix=suffix, kind=kind):
                    store = self.root / f"store-{suffix[1:]}-{kind}"
                    store.mkdir(mode=0o700)
                    outside = self.root / f"outside-{suffix[1:]}-{kind}"
                    outside.write_text("preserve", encoding="utf-8")
                    sidecar = store / ("cases.sqlite3" + suffix)
                    if kind == "symlink":
                        sidecar.symlink_to(outside)
                    else:
                        sidecar.hardlink_to(outside)
                    with patch("azazel_mio.cli.sqlite3.connect") as sqlite_connect:
                        with self.assertRaisesRegex(ValueError, "SQLite sidecar"):
                            connect(store)
                        sqlite_connect.assert_not_called()
                    self.assertEqual(outside.read_text(encoding="utf-8"), "preserve")

    def test_database_symlink_rejected(self):
        other = self.root / "other"
        other.mkdir(mode=0o700)
        (other / "cases.sqlite3").symlink_to(self.root / "cases.sqlite3")
        with self.assertRaisesRegex(ValueError, "unsafe storage"):
            connect(other)

    def test_database_hardlink_rejected_before_sqlite_open(self):
        other = self.root / "other"
        other.mkdir(mode=0o700)
        outside = self.root / "outside.sqlite3"
        outside.write_bytes(b"")
        (other / "cases.sqlite3").hardlink_to(outside)
        with patch("azazel_mio.cli.sqlite3.connect") as sqlite_connect:
            with self.assertRaisesRegex(ValueError, "single-link regular file"):
                connect(other)
            sqlite_connect.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"")
        with patch.dict(os.environ, {"MIO_IR_HOME": str(other)}), patch(
            "sys.argv", ["mio-ir", "case", "create", "--name", "test"]
        ):
            self.assertEqual(main(), 1)
        self.assertEqual(outside.read_bytes(), b"")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_nonregular_database_rejected_before_sqlite_open(self):
        other = self.root / "other"
        other.mkdir(mode=0o700)
        os.mkfifo(other / "cases.sqlite3")
        with patch("azazel_mio.cli.sqlite3.connect") as sqlite_connect:
            with self.assertRaisesRegex(ValueError, "single-link regular file"):
                connect(other)
            sqlite_connect.assert_not_called()

    def run_report(self, output, fmt="json"):
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", "report", "generate", "--case", str(self.case),
                         "--format", fmt, "--output", str(output)]
        ):
            return main()

    def test_markdown_report_keeps_carriage_return_inside_summary_line(self):
        source = self.root / "carriage-return.jsonl"
        source.write_text('{"summary":"safe\\r# injected heading"}\n', encoding="utf-8")
        import_file(self.db, self.root, self.case, source, "jsonl")
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.md"
            self.assertEqual(self.run_report(output, "markdown"), 0)
            content = output.read_text(encoding="utf-8")
            self.assertNotIn("\r", content)
            self.assertIn("safe \\# injected heading", content)

    def test_markdown_report_escapes_untrusted_markup(self):
        source = self.root / "markdown.jsonl"
        source.write_text(
            '{"summary":"[x](https://example.invalid) <img src=x> *bold* `code` ~~gone~~ & :"}\n',
            encoding="utf-8",
        )
        import_file(self.db, self.root, self.case, source, "jsonl")
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.md"
            self.assertEqual(self.run_report(output, "markdown"), 0)
            content = output.read_text(encoding="utf-8")
            for escaped in (r"\[x\]", r"\(", r"\<img", r"\*bold\*", r"\`code\`",
                            r"\~\~gone\~\~", r"\&", r"\:"):
                self.assertIn(escaped, content)
            for raw in ("[x]", "<img src=x>", "*bold*", "`code`", "~~gone~~"):
                self.assertNotIn(raw, content)

    def test_markdown_report_replaces_terminal_and_direction_controls(self):
        source = self.root / "controls.jsonl"
        source.write_text(
            '{"summary":"left\\u001b[31mred\\u0000\\u202eRIGHT\\u2028next"}\n',
            encoding="utf-8",
        )
        import_file(self.db, self.root, self.case, source, "jsonl")
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.md"
            self.assertEqual(self.run_report(output, "markdown"), 0)
            content = output.read_text(encoding="utf-8")
            unsafe = r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
            self.assertNotRegex(content, unsafe)
            self.assertIn(r"left \[31mred  RIGHT next", content)

    def test_markdown_report_labels_missing_timestamp_unknown(self):
        source = self.root / "naive-timestamp.jsonl"
        source.write_text('{"timestamp":"2026-10-01T10:00:00","summary":"event"}\n', encoding="utf-8")
        import_file(self.db, self.root, self.case, source, "jsonl")
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.md"
            self.assertEqual(self.run_report(output, "markdown"), 0)
            self.assertIn("- unknown | evidence 1 record 1: event", output.read_text(encoding="utf-8"))

    def test_report_cannot_overwrite_internal_journal(self):
        output = self.root / "cases.sqlite3-wal"
        output.write_text("reserved")
        errors = StringIO()
        with redirect_stderr(errors):
            self.assertEqual(self.run_report(output), 1)
        self.assertIn("output may not overwrite internal storage", errors.getvalue())

    def test_report_rejects_case_alias_of_internal_storage(self):
        alternate_spelling = Path(str(self.root).swapcase())
        if not alternate_spelling.exists():
            self.skipTest("filesystem treats path case as significant")
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        output = alternate_spelling / "objects" / "report.md"
        errors = StringIO()
        with redirect_stderr(errors):
            self.assertEqual(self.run_report(output), 1)
        self.assertFalse(output.exists())
        self.assertIn("output may not overwrite internal storage", errors.getvalue())

    def test_report_status_json_escapes_non_ascii_path(self):
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "rapport-📄.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(self.run_report(output), 0)
            self.assertIn(r"rapport-\ud83d\udcc4.json", stdout.getvalue())
            self.assertEqual(json.loads(stdout.getvalue()), {"output": str(output.resolve())})

    def test_report_hardlink_does_not_truncate_evidence(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertTrue(verify(self.db, self.root, self.case)[0]["valid"])
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        evidence = self.root / "objects" / digest
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.json"
            output.hardlink_to(evidence)
            self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])
            original = evidence.read_bytes()
            self.assertEqual(self.run_report(output), EXIT_INVALID_EVIDENCE)
            self.assertEqual(evidence.read_bytes(), original)
            self.assertEqual(json.loads(output.read_text())["case_id"], self.case)
            self.assertFalse(json.loads(output.read_text())["evidence"][0]["valid"])

    def test_report_exit_code_is_nonzero_when_evidence_is_invalid(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        evidence = self.root / "objects" / digest
        evidence.chmod(0o600)
        evidence.write_text("tampered", encoding="utf-8")
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.json"
            self.assertEqual(self.run_report(output), EXIT_INVALID_EVIDENCE)
            self.assertFalse(json.loads(output.read_text())["evidence"][0]["valid"])

    def test_verify_command_uses_distinct_invalid_evidence_exit_code(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        evidence = self.root / "objects" / digest
        evidence.chmod(0o600)
        evidence.write_text("tampered", encoding="utf-8")
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", "evidence", "verify", "--case", str(self.case)]
        ):
            with redirect_stderr(StringIO()):
                self.assertEqual(main(), EXIT_INVALID_EVIDENCE)

    def test_usage_error_keeps_argparse_exit_code_distinct(self):
        with patch("sys.argv", ["mio-ir", "--bad-option"]):
            errors = StringIO()
            with redirect_stderr(errors):
                with self.assertRaises(SystemExit) as raised:
                    main()
        self.assertEqual(raised.exception.code, 2)

    def test_cross_case_isolation(self):
        other = self.db.execute("INSERT INTO cases(name,created) VALUES('other','now')").lastrowid
        self.db.commit()
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertEqual(timeline(self.db, other), [])

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", *argv]
        ), redirect_stdout(out), redirect_stderr(err):
            code = main()
        return code, out.getvalue(), err.getvalue()

    def import_records(self):
        source = self.inputs / "events.jsonl"
        source.write_text(
            '{"timestamp":"2026-10-01T10:00:00+09:00","summary":"Synthetic PowerShell execution"}\n'
            '{"timestamp":"2026-10-01T10:02:00+09:00","summary":"Synthetic DNS query"}\n',
            encoding="utf-8",
        )
        code, out, err = self.run_cli(
            "evidence", "import", "--case", str(self.case), "--file", str(source), "--format", "jsonl"
        )
        self.assertEqual((code, err), (0, ""))
        evidence_id = json.loads(out)["evidence_id"]
        code, out, err = self.run_cli("timeline", "build", "--case", str(self.case))
        self.assertEqual((code, err), (0, ""))
        rows = json.loads(out)
        self.assertEqual({row["evidence_id"] for row in rows}, {evidence_id})
        return rows

    def candidate_document(self, rows, **overrides):
        first = rows[0]
        document = {
            "schema_version": INPUT_SCHEMA,
            "case_id": self.case,
            "candidates": [
                {
                    "event_id": first["event_id"],
                    "evidence_id": first["evidence_id"],
                    "record_number": first["record"],
                    "normalizer_version": "synthetic-normalizer-1",
                    "inputs": {
                        "severity": 2,
                        "classes": ["c2"],
                        "token_only": False,
                        "ports": [{"kind": "web", "port": 443}],
                        "action": "drop",
                        "deception_sid": False,
                        "benign_classless": False,
                    },
                }
            ],
        }
        document.update(overrides)
        return document

    def write_input(self, document, name="normalized-input.json"):
        path = self.inputs / name
        path.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
        return path

    def assess(self, path, case=None):
        return self.run_cli(
            "assessment", "candidate", "--case", str(self.case if case is None else case), "--file", str(path)
        )

    def assert_rejected(self, result):
        code, out, err = result
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error:", err)

    def snapshot(self):
        return [self.db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() for table in ("cases", "evidence", "events")]

    def test_cli_candidate_assessment_end_to_end(self):
        rows = self.import_records()
        path = self.write_input(self.candidate_document(rows))
        before = self.snapshot()

        code, out, err = self.assess(path)

        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertEqual(
            set(result),
            {"schema", "adapter_version", "kernel_source_revision", "case_id", "status", "candidates", "limitations"},
        )
        self.assertEqual(result["kernel_source_revision"], KERNEL_SOURCE_REVISION)
        self.assertEqual(result["status"], "candidates")
        self.assertEqual(result["case_id"], self.case)
        (entry,) = result["candidates"]
        self.assertEqual(
            set(entry),
            {"event_id", "record_number", "evidence_refs", "normalizer_version", "provenance",
             "status", "score", "factors", "conflict_evidence_ids", "explanation"},
        )
        self.assertEqual(entry["event_id"], rows[0]["event_id"])
        self.assertEqual(entry["record_number"], rows[0]["record"])
        self.assertEqual(entry["evidence_refs"], [rows[0]["evidence_id"]])
        self.assertEqual(entry["status"], "scored")
        self.assertEqual(entry["score"], 93)
        self.assertEqual(entry["factors"], [
            "severity=2", "sid_present", "threat_class=c2(48)", "web_port=443", "action=drop(contained)",
        ])
        expected = assess_fast(FastAssessmentInput(
            severity=2, classes=("c2",), ports=(PortSignal("web", 443),), action="drop"))
        self.assertEqual((entry["score"], entry["factors"]), (expected.score, list(expected.factors)))
        self.assertEqual(entry["provenance"], "caller_asserted_unverified")
        self.assertEqual(entry["conflict_evidence_ids"], [])
        self.assertEqual(entry["explanation"], EXPLANATION)
        self.assertTrue(any(item.startswith("no_authority:") for item in result["limitations"]))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.assess(path), (0, out, ""))

    def test_cli_candidate_abstains_on_empty_candidates(self):
        self.import_records()
        path = self.write_input({"schema_version": INPUT_SCHEMA, "case_id": self.case, "candidates": []})

        code, out, err = self.assess(path)

        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertEqual(result["status"], "abstained_no_normalized_input")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["kernel_source_revision"], KERNEL_SOURCE_REVISION)

    def test_cli_candidate_connection_is_query_only_after_bootstrap(self):
        rows = self.import_records()
        path = self.write_input(self.candidate_document(rows))
        before = self.snapshot()
        real = ir_cli.assess_candidates
        write_errors = []

        def probe(db, root, case, file):
            # A write through the same connection must fail once the command runs.
            try:
                db.execute("INSERT INTO cases(name,created) VALUES('probe','now')")
            except sqlite3.OperationalError as exc:
                write_errors.append(str(exc))
            return real(db, root, case, file)

        with patch.object(ir_cli, "assess_candidates", probe):
            code, out, err = self.assess(path)

        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(write_errors), 1)
        self.assertIn("readonly", write_errors[0])
        self.assertEqual(self.snapshot(), before)

    def test_cli_candidate_rejects_malformed_and_wrong_references(self):
        rows = self.import_records()
        mutations = {
            "raw summary text": lambda d: d["candidates"][0].update(summary="raw evidence text"),
            "unknown top-level key": lambda d: d.update(extra=1),
            "wrong schema version": lambda d: d.update(schema_version="mio.ir.fast-assessment-inputs.v0"),
            "file case mismatch": lambda d: d.update(case_id=self.case + 1),
            "string severity": lambda d: d["candidates"][0]["inputs"].update(severity="2"),
            "unknown signal key": lambda d: d["candidates"][0]["inputs"].update(label="c2"),
            "bool event id": lambda d: d["candidates"][0].update(event_id=True),
            "unknown event": lambda d: d["candidates"][0].update(event_id=999999),
            "wrong evidence": lambda d: d["candidates"][0].update(evidence_id=999999),
            "wrong record": lambda d: d["candidates"][0].update(record_number=99),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                document = self.candidate_document(rows)
                mutate(document)
                self.assert_rejected(self.assess(self.write_input(document)))

    def test_cli_candidate_rejects_malformed_json(self):
        self.import_records()
        base = '"schema_version":"%s","case_id":%d' % (INPUT_SCHEMA, self.case)
        texts = {
            "not json": "{not json",
            "duplicate key": '{%s,"case_id":%d,"candidates":[]}' % (base, self.case),
            "non-finite number": '{%s,"candidates":[{"event_id":NaN}]}' % base,
        }
        for label, text in texts.items():
            with self.subTest(label):
                self.assert_rejected(self.assess(self.write_input(text)))
        # Nesting beyond the default recursion limit must fail as a concise
        # ValueError, not as an uncaught RecursionError traceback.
        deep = "[" * 10000 + "]" * 10000
        with self.subTest("deep nesting"):
            result = self.assess(self.write_input(deep))
            self.assert_rejected(result)
            self.assertIn("error: input nesting too deep", result[2])
            self.assertNotIn("Traceback", result[2])

    def test_cli_candidate_rejects_nested_conflict_array_as_error(self):
        rows = self.import_records()
        document = self.candidate_document(rows)
        document["candidates"][0]["conflict_evidence_ids"] = [[rows[0]["evidence_id"]]]
        result = self.assess(self.write_input(json.dumps(document)))

        code, out, err = result
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: conflict evidence is not verified"), err)
        self.assertNotIn("Traceback", err)

    def test_cli_candidate_rejects_unverified_evidence(self):
        rows = self.import_records()
        digest = self.db.execute("SELECT digest FROM evidence WHERE case_id=?", (self.case,)).fetchone()[0]
        path = self.write_input(self.candidate_document(rows))
        target = self.root / "objects" / digest
        target.chmod(0o600)
        target.write_text("tampered")

        self.assert_rejected(self.assess(path))

    def test_cli_candidate_rejects_cross_case_and_unknown_case(self):
        rows = self.import_records()
        other = json.loads(self.run_cli("case", "create", "--name", "other")[1])["case_id"]
        path = self.write_input(self.candidate_document(rows))
        # Document names this case, but the selected case is the other one.
        self.assert_rejected(self.assess(path, case=other))
        # Document names the other case but references this case's event and evidence.
        path = self.write_input(self.candidate_document(rows, case_id=other))
        self.assert_rejected(self.assess(path, case=other))
        self.assert_rejected(self.assess(path, case=999))

    def test_cli_candidate_input_must_be_regular_and_bounded(self):
        rows = self.import_records()
        real = self.write_input(self.candidate_document(rows))
        link = self.inputs / "link.json"
        link.symlink_to(real)
        self.assert_rejected(self.assess(link))
        fifo = self.inputs / "fifo.json"
        os.mkfifo(fifo)
        self.assert_rejected(self.assess(fifo))
        oversized = self.write_input("{" + " " * (512 * 1024) + "}", name="oversized.json")
        self.assert_rejected(self.assess(oversized))
        self.assert_rejected(self.assess(self.inputs / "missing.json"))


if __name__ == "__main__":
    unittest.main()
