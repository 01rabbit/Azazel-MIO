import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azazel_mio.cli import connect, import_file, report, timeline, verify, parse_records


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

    def test_cross_case_isolation(self):
        other = self.db.execute("INSERT INTO cases(name,created) VALUES('other','now')").lastrowid
        self.db.commit()
        import_file(self.db, self.root, self.case, self.source, "jsonl")
        self.assertEqual(timeline(self.db, other), [])


if __name__ == "__main__":
    unittest.main()
