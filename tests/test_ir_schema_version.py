import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from azazel_mio.cli import connect, timeline

LEGACY_DDL = """
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
  filename TEXT NOT NULL, digest TEXT NOT NULL, format TEXT NOT NULL, imported TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  record_number INTEGER NOT NULL, timestamp TEXT, original_timestamp TEXT, summary TEXT NOT NULL);
"""


def snapshot(path):
    with closing(sqlite3.connect(path)) as raw:
        objects = raw.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        version = raw.execute("PRAGMA user_version").fetchone()[0]
    return objects, version


class IRSchemaVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "cases.sqlite3"

    def test_fresh_database_gets_version_1(self):
        with closing(connect(self.root)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
        objects, version = snapshot(self.database)
        self.assertEqual(version, 1)
        self.assertEqual(sorted(name for _, name, _ in objects), ["cases", "events", "evidence"])

    def test_legacy_v0_database_adopted_with_records_preserved(self):
        with closing(sqlite3.connect(self.database)) as raw:
            raw.executescript(LEGACY_DDL)
            raw.execute("INSERT INTO cases(id,name,created) VALUES(1,'legacy','now')")
            raw.execute("INSERT INTO evidence(id,case_id,filename,digest,format,imported) "
                        "VALUES(1,1,'a.jsonl','d','jsonl','now')")
            raw.execute("INSERT INTO events(id,evidence_id,record_number,timestamp,original_timestamp,summary) "
                        "VALUES(1,1,1,'2026-10-01T01:00:00+00:00','2026-10-01T10:00:00+09:00','legacy-summary')")
            raw.commit()
        self.assertEqual(snapshot(self.database)[1], 0)
        with closing(connect(self.root)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT name FROM cases WHERE id=1").fetchone()[0], "legacy")
            self.assertEqual(timeline(db, 1)[0]["summary"], "legacy-summary")
        self.assertEqual(snapshot(self.database)[1], 1)

    def test_version_1_is_idempotent(self):
        with closing(connect(self.root)) as db:
            db.execute("INSERT INTO cases(name,created) VALUES('kept','now')")
            db.commit()
        before = snapshot(self.database)
        with closing(connect(self.root)) as db:
            self.assertEqual(db.execute("SELECT name FROM cases").fetchall(), [("kept",)])
        self.assertEqual(snapshot(self.database), before)

    def test_unknown_newer_version_rejected_unchanged(self):
        with closing(sqlite3.connect(self.database)) as raw:
            raw.execute("CREATE TABLE future(x INTEGER)")
            raw.execute("PRAGMA user_version=2")
            raw.commit()
        before_bytes = self.database.read_bytes()
        before = snapshot(self.database)
        with self.assertRaisesRegex(ValueError, "unsupported storage schema version"):
            connect(self.root)
        self.assertEqual(snapshot(self.database), before)
        self.assertEqual(self.database.read_bytes(), before_bytes)

    def test_malformed_partial_schema_rejected_unchanged(self):
        with closing(sqlite3.connect(self.database)) as raw:
            raw.execute("CREATE TABLE cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL)")
            raw.commit()
        before_bytes = self.database.read_bytes()
        before = snapshot(self.database)
        with self.assertRaisesRegex(ValueError, "malformed storage schema"):
            connect(self.root)
        self.assertEqual(snapshot(self.database), before)
        self.assertEqual(self.database.read_bytes(), before_bytes)

    def test_version_1_marker_on_empty_database_rejected_unchanged(self):
        with closing(sqlite3.connect(self.database)) as raw:
            raw.execute("PRAGMA user_version=1")
            raw.commit()
        before = snapshot(self.database)
        with self.assertRaisesRegex(ValueError, "malformed storage schema"):
            connect(self.root)
        self.assertEqual(snapshot(self.database), before)

    def test_migration_failure_rolls_back_without_partial_ddl(self):
        broken = (
            "CREATE TABLE cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL)",
            "CREATE TABLE evidence(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES nosuch(,",
        )
        with patch("azazel_mio.cli.SCHEMA_V1", broken):
            with self.assertRaises(sqlite3.Error):
                connect(self.root)
        objects, version = snapshot(self.database)
        self.assertEqual(objects, [])
        self.assertEqual(version, 0)


if __name__ == "__main__":
    unittest.main()
