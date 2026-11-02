import json
import os
from pathlib import Path
import tempfile
import unittest
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

    def test_database_symlink_rejected(self):
        other = self.root / "other"
        other.mkdir()
        (other / "cases.sqlite3").symlink_to(self.root / "cases.sqlite3")
        with self.assertRaisesRegex(ValueError, "unsafe storage"):
            connect(other)

    def test_database_hardlink_rejected_before_sqlite_open(self):
        other = self.root / "other"
        other.mkdir()
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

    def test_nonregular_database_rejected_before_sqlite_open(self):
        other = self.root / "other"
        other.mkdir()
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
