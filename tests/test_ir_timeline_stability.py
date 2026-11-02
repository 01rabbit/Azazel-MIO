"""IR-04 verification slice: JSONL timestamp handling and timeline stability.

Rationale: a record whose time cannot be established as an absolute instant
(naive local time, or no timestamp at all) is retained in the case but is not
assigned a UTC time. Naive values are never guessed to be UTC or to belong to
any vendor/timezone, and unknown-time records sort after every known-time
record. Ordering ties fall back to insertion order (events.id), and refs
(event_id, evidence_id, record) must not change between repeated reads.
"""
import json
import tempfile
import unittest
from pathlib import Path

from azazel_mio.cli import connect, import_file, timeline

AWARE_JST = "2026-10-01T09:00:00+09:00"  # == 2026-10-01T00:00:00+00:00
AWARE_EARLIER_UTC = "2026-09-30T23:00:00Z"  # == 2026-09-30T23:00:00+00:00
NAIVE = "2026-10-01T09:00:00"


class TimelineStabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = connect(self.root)
        self.addCleanup(self.db.close)
        self.case = self.db.execute("INSERT INTO cases(name,created) VALUES('timeline','now')").lastrowid
        self.db.commit()

    def write_jsonl(self, name, rows):
        path = self.root / name
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def import_rows(self, rows, name="events.jsonl"):
        source = self.write_jsonl(name, rows)
        return import_file(self.db, self.root, self.case, source, "jsonl")

    def test_aware_naive_and_missing_timestamps_are_retained_without_guessing(self):
        eid = self.import_rows([
            {"timestamp": AWARE_JST, "summary": "aware"},
            {"timestamp": NAIVE, "summary": "naive"},
            {"summary": "missing"},
        ])
        rows = timeline(self.db, self.case)
        self.assertEqual(len(rows), 3)
        by_summary = {row["summary"]: row for row in rows}

        aware = by_summary["aware"]
        self.assertEqual(aware["timestamp_utc"], "2026-10-01T00:00:00+00:00")
        self.assertEqual(aware["original_timestamp"], AWARE_JST)

        # Naive: kept verbatim, no UTC assigned (not assumed to be UTC).
        naive = by_summary["naive"]
        self.assertIsNone(naive["timestamp_utc"])
        self.assertEqual(naive["original_timestamp"], NAIVE)

        # Missing: retained with both fields empty.
        missing = by_summary["missing"]
        self.assertIsNone(missing["timestamp_utc"])
        self.assertIsNone(missing["original_timestamp"])

        for row in rows:
            self.assertEqual(row["evidence_id"], eid)

    def test_known_utc_sorts_before_unknown_and_unknowns_keep_insertion_order(self):
        # Input record numbers: 1 aware JST, 2 naive, 3 missing, 4 earlier aware UTC.
        self.import_rows([
            {"timestamp": AWARE_JST, "summary": "r1"},
            {"timestamp": NAIVE, "summary": "r2"},
            {"summary": "r3"},
            {"timestamp": AWARE_EARLIER_UTC, "summary": "r4"},
        ])
        rows = timeline(self.db, self.case)
        # Known instants ordered by normalized UTC (4 before 1), then unknowns
        # in insertion order (2 before 3).
        self.assertEqual([row["record"] for row in rows], [4, 1, 2, 3])
        self.assertTrue(all(row["timestamp_utc"] is not None for row in rows[:2]))
        self.assertTrue(all(row["timestamp_utc"] is None for row in rows[2:]))

    def test_aware_only_input_is_ordered_by_utc_instant_not_offset_text(self):
        # 2026-10-01T08:00:00+09:00 == 2026-09-30T23:00:00Z, which is earlier than
        # 2026-09-30T23:30:00Z even though its raw string sorts after it.
        self.import_rows([
            {"timestamp": "2026-10-01T08:00:00+09:00", "summary": "jst"},
            {"timestamp": "2026-09-30T23:30:00Z", "summary": "utc"},
        ])
        rows = timeline(self.db, self.case)
        self.assertEqual([row["record"] for row in rows], [1, 2])
        self.assertEqual(rows[0]["timestamp_utc"], "2026-09-30T23:00:00+00:00")
        self.assertEqual(rows[1]["timestamp_utc"], "2026-09-30T23:30:00+00:00")

    def test_equal_instants_in_distinct_offsets_tie_break_by_insertion_order(self):
        # All three are the same instant, 2026-10-01T00:00:00Z. Raw string order
        # would be [2, 3, 1], so this also rules out sorting by offset text.
        self.import_rows([
            {"timestamp": "2026-10-01T09:00:00+09:00", "summary": "r1"},
            {"timestamp": "2026-10-01T00:00:00Z", "summary": "r2"},
            {"timestamp": "2026-10-01T02:00:00+02:00", "summary": "r3"},
        ])
        rows = timeline(self.db, self.case)
        self.assertEqual([row["record"] for row in rows], [1, 2, 3])
        self.assertEqual({row["timestamp_utc"] for row in rows}, {"2026-10-01T00:00:00+00:00"})

    def test_unparseable_and_non_string_timestamps_have_no_utc_value(self):
        # Unparseable string: original text is kept verbatim, UTC is None.
        # Non-string value: neither field is populated.
        self.import_rows([
            {"timestamp": "not-a-time", "summary": "garbage"},
            {"timestamp": 1790000000, "summary": "numeric"},
        ])
        rows = timeline(self.db, self.case)
        by_summary = {row["summary"]: row for row in rows}

        garbage = by_summary["garbage"]
        self.assertIsNone(garbage["timestamp_utc"])
        self.assertEqual(garbage["original_timestamp"], "not-a-time")

        numeric = by_summary["numeric"]
        self.assertIsNone(numeric["timestamp_utc"])
        self.assertIsNone(numeric["original_timestamp"])

        # Both are unknown-time, so they keep insertion order.
        self.assertEqual([row["record"] for row in rows], [1, 2])

    def test_refs_are_stable_across_repeated_timeline_calls(self):
        eid = self.import_rows([
            {"timestamp": AWARE_JST, "summary": "r1"},
            {"timestamp": NAIVE, "summary": "r2"},
            {"summary": "r3"},
        ])
        first = timeline(self.db, self.case)
        second = timeline(self.db, self.case)
        self.assertEqual(first, second)
        self.assertEqual([row["record"] for row in first], [1, 2, 3])
        self.assertEqual({row["evidence_id"] for row in first}, {eid})
        event_ids = [row["event_id"] for row in first]
        self.assertEqual(len(set(event_ids)), 3)
        self.assertEqual(event_ids, [row["event_id"] for row in timeline(self.db, self.case)])

    def test_offset_timestamp_whose_utc_instant_overflows_is_retained_as_unknown(self):
        # 9999-12-31T23:00:00-05:00 is 10000-01-01T04:00:00Z, outside datetime's
        # range, so astimezone(UTC) raises OverflowError. It must be kept as an
        # unknown-time record with the original text, not abort the import.
        eid = self.import_rows([
            {"timestamp": "9999-12-31T23:00:00-05:00", "summary": "overflow"},
            {"timestamp": AWARE_JST, "summary": "known"},
        ])
        rows = timeline(self.db, self.case)
        self.assertEqual([row["summary"] for row in rows], ["known", "overflow"])
        overflow = rows[1]
        self.assertEqual(overflow["evidence_id"], eid)
        self.assertIsNone(overflow["timestamp_utc"])
        self.assertEqual(overflow["original_timestamp"], "9999-12-31T23:00:00-05:00")

    def test_equal_instants_across_files_order_by_event_id_not_record_number(self):
        # Equal instant everywhere. File A (imported first) gets event ids 1-3
        # with record numbers 1-3; file B gets ids 4-5 with record numbers 1-2.
        # Ordering by record_number would interleave A and B (record 1 of each
        # file first); ordering by events.id keeps all of A before all of B.
        ts = "2026-10-01T00:00:00Z"
        self.import_rows([{"timestamp": ts, "summary": f"a{i}"} for i in (1, 2, 3)], name="a.jsonl")
        self.import_rows([{"timestamp": ts, "summary": f"b{i}"} for i in (1, 2)], name="b.jsonl")
        rows = timeline(self.db, self.case)
        self.assertEqual([row["summary"] for row in rows], ["a1", "a2", "a3", "b1", "b2"])
        self.assertEqual([row["event_id"] for row in rows], sorted(row["event_id"] for row in rows))
        self.assertEqual([row["record"] for row in rows], [1, 2, 3, 1, 2])
        self.assertEqual(rows, timeline(self.db, self.case))

    def test_refs_are_stable_across_reconnect(self):
        self.import_rows([
            {"timestamp": AWARE_JST, "summary": "r1"},
            {"timestamp": NAIVE, "summary": "r2"},
            {"summary": "r3"},
        ])
        before = timeline(self.db, self.case)
        self.db.close()
        self.db = connect(self.root)
        self.addCleanup(self.db.close)
        after = timeline(self.db, self.case)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
