import json
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import MagicMock, patch

from azazel_mio.cli import (
    EXIT_INVALID_EVIDENCE,
    MAX_BYTES,
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


class IRWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
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
        self.assertEqual(timeline(self.db, self.case)[0]["evidence_id"], eid)
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
        with patch("azazel_mio.cli.current_user_owns", return_value=False):
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

    def test_json_scalar_top_level_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "JSON input must be an object or array"):
            parse_records(b"5", "json")

    def test_json_array_requires_object_records(self):
        with self.assertRaisesRegex(ValueError, "each JSON array record must be an object"):
            parse_records(b"[5]", "json")

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
        with patch("azazel_mio.cli.current_user_owns", return_value=False):
            with self.assertRaisesRegex(ValueError, "owned private directory"):
                connect(self.root)

    def test_storage_fails_closed_without_owner_identity(self):
        with patch("azazel_mio.cli.os.getuid", None):
            with self.assertRaisesRegex(ValueError, "owned private directory"):
                connect(self.root)

    def test_connect_closes_database_when_schema_setup_fails(self):
        db = MagicMock()
        db.executescript.side_effect = sqlite3.Error("schema failure")
        with patch("azazel_mio.cli.sqlite3.connect", return_value=db):
            with self.assertRaisesRegex(sqlite3.Error, "schema failure"):
                connect(self.root)
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
        (self.root / "objects" / digest).write_text("tampered", encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
