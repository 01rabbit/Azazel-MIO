import errno
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from azazel_mio.cli import connect, import_file

# Small limit so the boundary is exercised without allocating MAX_BYTES (16 MiB).
TEST_LIMIT = 256
PREFIX = '{"summary":"'
SUFFIX = '"}'


def json_payload(size):
    """Return a single-object JSON document of exactly `size` ASCII bytes."""
    pad = size - len(PREFIX) - len(SUFFIX)
    payload = (PREFIX + "x" * pad + SUFFIX).encode("ascii")
    assert len(payload) == size
    return payload


class ImportBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = connect(self.root)
        self.addCleanup(self.db.close)
        self.case = self.db.execute("INSERT INTO cases(name,created) VALUES('bounds','now')").lastrowid
        self.db.commit()
        limit = patch("azazel_mio.cli.MAX_BYTES", TEST_LIMIT)
        limit.start()
        self.addCleanup(limit.stop)

    def evidence_count(self):
        return self.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def event_count(self):
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def test_exact_limit_json_imports(self):
        source = self.root / "exact.json"
        source.write_bytes(json_payload(TEST_LIMIT))
        self.assertEqual(source.stat().st_size, TEST_LIMIT)
        eid = import_file(self.db, self.root, self.case, source, "json")
        self.assertIsInstance(eid, int)
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.event_count(), 1)

    def test_one_byte_over_limit_rejected_before_staging_or_rows(self):
        source = self.root / "over.json"
        source.write_bytes(json_payload(TEST_LIMIT + 1))
        with patch("azazel_mio.cli.os.open", side_effect=AssertionError("oversize source opened")) as opener:
            with patch("azazel_mio.cli.tempfile.mkstemp") as mkstemp:
                with self.assertRaisesRegex(ValueError, "file too large"):
                    import_file(self.db, self.root, self.case, source, "json")
                mkstemp.assert_not_called()
                opener.assert_not_called()
        self.assertFalse((self.root / "objects").exists())
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_missing_source_reports_lstat_errno_without_path(self):
        source = self.root / "missing.json"
        with self.assertRaisesRegex(
                ValueError, rf"unable to inspect source \(errno {errno.ENOENT}\)"):
            import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_bounded_read_rejects_input_larger_than_reported_stat_size(self):
        source = self.root / "grew-after-stat.json"
        source.write_bytes(json_payload(TEST_LIMIT + 1))
        original_lstat = Path.lstat
        original_open = os.open
        original_fstat = os.fstat
        original_fdopen = os.fdopen
        actual_sizes = []
        reported_sizes = []
        read_sizes = []
        source_fds = []

        def report_limit_for_source(path, *args, **kwargs):
            result = original_lstat(path, *args, **kwargs)
            if path == source:
                actual_sizes.append(result.st_size)
                fields = list(result)
                fields[6] = TEST_LIMIT
                reported_sizes.append(fields[6])
                return os.stat_result(fields)
            return result

        def record_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if Path(path) == source:
                source_fds.append(fd)
            return fd

        def report_open_limit(fd):
            result = original_fstat(fd)
            if fd in source_fds:
                fields = list(result)
                fields[6] = TEST_LIMIT
                return os.stat_result(fields)
            return result

        class RecordingReader:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def read(self, size=-1):
                read_sizes.append(size)
                return self.handle.read(size)

        def record_fdopen(fd, mode="r", *args, **kwargs):
            return RecordingReader(original_fdopen(fd, mode, *args, **kwargs))

        with patch.object(Path, "lstat", report_limit_for_source):
            with patch("azazel_mio.cli.os.open", side_effect=record_open):
                with patch("azazel_mio.cli.os.fstat", side_effect=report_open_limit):
                    with patch("azazel_mio.cli.os.fdopen", side_effect=record_fdopen) as fdopen:
                        with patch("azazel_mio.cli.tempfile.mkstemp") as mkstemp:
                            with self.assertRaisesRegex(ValueError, "file too large"):
                                import_file(self.db, self.root, self.case, source, "json")
                            mkstemp.assert_not_called()
                            self.assertEqual(fdopen.call_count, 1)
        self.assertTrue(actual_sizes)
        self.assertTrue(all(size == TEST_LIMIT + 1 for size in actual_sizes))
        self.assertTrue(reported_sizes)
        self.assertTrue(all(size == TEST_LIMIT for size in reported_sizes))
        self.assertEqual(read_sizes, [TEST_LIMIT + 1])
        self.assertFalse((self.root / "objects").exists())
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_source_replaced_with_symlink_before_open_is_rejected(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("platform has no O_NOFOLLOW; separate platform coverage required")
        source = self.root / "source.json"
        target = self.root / "target.json"
        source.write_bytes(json_payload(TEST_LIMIT))
        target.write_bytes(json_payload(TEST_LIMIT))
        original_open = os.open

        def replace_with_symlink(path, flags, *args, **kwargs):
            if Path(path) == source:
                source.unlink()
                source.symlink_to(target)
            return original_open(path, flags, *args, **kwargs)

        with patch("azazel_mio.cli.os.O_NOFOLLOW", 0):
            with patch("azazel_mio.cli.os.open", side_effect=replace_with_symlink):
                with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                    import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_open_requests_no_follow_and_nonblocking_flags(self):
        if not (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK")):
            self.skipTest("platform lacks no-follow or nonblocking open flags")
        source = self.root / "source.json"
        source.write_bytes(json_payload(TEST_LIMIT))
        original_open = os.open
        seen_flags = []

        def record_flags(path, flags, *args, **kwargs):
            if Path(path) == source:
                seen_flags.append(flags)
            return original_open(path, flags, *args, **kwargs)

        with patch("azazel_mio.cli.os.open", side_effect=record_flags):
            import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(len(seen_flags), 1)
        self.assertTrue(seen_flags[0] & os.O_NOFOLLOW)
        self.assertTrue(seen_flags[0] & os.O_NONBLOCK)

    def test_open_failure_reports_errno_without_path(self):
        source = self.root / "source.json"
        source.write_bytes(json_payload(TEST_LIMIT))
        with patch("azazel_mio.cli.os.open", side_effect=OSError(errno.EACCES, "denied")):
            with self.assertRaisesRegex(ValueError, rf"unable to open source \(errno {errno.EACCES}\)"):
                import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_source_replaced_with_fifo_before_open_is_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no FIFO support")
        source = self.root / "source.json"
        source.write_bytes(json_payload(TEST_LIMIT))
        original_open = os.open

        def replace_with_fifo(path, flags, *args, **kwargs):
            if Path(path) == source:
                source.unlink()
                os.mkfifo(source)
            return original_open(path, flags, *args, **kwargs)

        with patch("azazel_mio.cli.os.open", side_effect=replace_with_fifo):
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                import_file(self.db, self.root, self.case, source, "json")
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.event_count(), 0)

    def test_fifo_source_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no FIFO support")
        fifo = self.root / "source.fifo"
        os.mkfifo(fifo)

        def timed_out(signum, frame):
            raise TimeoutError("import_file blocked on FIFO source")

        previous = signal.signal(signal.SIGALRM, timed_out)
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        signal.alarm(5)
        self.addCleanup(signal.alarm, 0)
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            import_file(self.db, self.root, self.case, fifo, "json")
        self.assertFalse((self.root / "objects").exists())
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
