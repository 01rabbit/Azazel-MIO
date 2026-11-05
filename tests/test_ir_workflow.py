import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch

from azazel_mio.cli import connect, import_file, main, report, timeline, verify, parse_records


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
        self.assertEqual(timeline(self.db, self.case)[0]["evidence_id"], eid)
        self.assertEqual(timeline(self.db, self.case)[0]["timestamp_utc"], "2026-10-01T01:00:00+00:00")
        self.assertEqual(report(self.db, self.root, self.case)["timeline"][0]["record"], 1)

    def test_tamper_detected(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        (self.root / "objects" / digest).chmod(0o600)
        (self.root / "objects" / digest).write_text("tampered")
        self.assertFalse(verify(self.db, self.root, self.case)[0]["valid"])

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

    def run_report(self, output):
        with patch.dict(os.environ, {"MIO_IR_HOME": str(self.root)}), patch(
            "sys.argv", ["mio-ir", "report", "generate", "--case", str(self.case),
                         "--format", "json", "--output", str(output)]
        ):
            return main()

    def test_report_cannot_overwrite_internal_journal(self):
        output = self.root / "cases.sqlite3-wal"
        output.write_text("reserved")
        self.assertEqual(self.run_report(output), 1)
        self.assertEqual(output.read_text(), "reserved")

    def test_report_hardlink_does_not_truncate_evidence(self):
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        digest = verify(self.db, self.root, self.case)[0]["sha256"]
        evidence = self.root / "objects" / digest
        with tempfile.TemporaryDirectory() as export:
            output = Path(export) / "report.json"
            output.hardlink_to(evidence)
            original = evidence.read_bytes()
            self.assertEqual(self.run_report(output), 0)
            self.assertEqual(evidence.read_bytes(), original)
            self.assertEqual(json.loads(output.read_text())["case_id"], self.case)

    def test_cross_case_isolation(self):
        other = self.db.execute("INSERT INTO cases(name,created) VALUES('other','now')").lastrowid
        self.db.commit()
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertEqual(timeline(self.db, other), [])


if __name__ == "__main__":
    unittest.main()
