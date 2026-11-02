"""Offline IR evidence workflow; event timestamps come from input records."""
import argparse
from contextlib import closing
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import string
import sys
import tempfile
from datetime import datetime, timezone

from .ir_adapter import assess_ir_candidates, parse_candidate_document

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10000
MAX_JSON_NESTING = 256
MAX_TIMESTAMP_CHARS = 256
MAX_SUMMARY_CHARS = 2048
EXIT_INVALID_EVIDENCE = 3
MARKDOWN_ESCAPES = frozenset(string.punctuation)
MARKDOWN_UNSAFE = frozenset(
    map(chr, (*range(0x00, 0x20), 0x7f, *range(0x80, 0xa0),
              0x061c, 0x200e, 0x200f, 0x2028, 0x2029,
              *range(0x202a, 0x202f), *range(0x2066, 0x206a)))
)

def markdown_escape(value):
    sanitized = "".join(" " if char in MARKDOWN_UNSAFE else char for char in value)
    return "".join("\\" + char if char in MARKDOWN_ESCAPES else char
                   for char in sanitized)
SCHEMA_VERSION = 1
SCHEMA_V1 = (
    "CREATE TABLE cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL)",
    "CREATE TABLE evidence(id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), "
    "filename TEXT NOT NULL, digest TEXT NOT NULL, format TEXT NOT NULL, imported TEXT NOT NULL)",
    "CREATE TABLE events(id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id), "
    "record_number INTEGER NOT NULL, timestamp TEXT, original_timestamp TEXT, summary TEXT NOT NULL)",
)
# (name, declared type, notnull, pk) per column, and (table, from, to) per foreign key.
# These describe the exact legacy (user_version 0) and v1 layouts; anything else is malformed.
_EXPECTED_COLUMNS = {
    "cases": (("id", "INTEGER", 0, 1), ("name", "TEXT", 1, 0), ("created", "TEXT", 1, 0)),
    "evidence": (("id", "INTEGER", 0, 1), ("case_id", "INTEGER", 1, 0), ("filename", "TEXT", 1, 0),
                 ("digest", "TEXT", 1, 0), ("format", "TEXT", 1, 0), ("imported", "TEXT", 1, 0)),
    "events": (("id", "INTEGER", 0, 1), ("evidence_id", "INTEGER", 1, 0), ("record_number", "INTEGER", 1, 0),
               ("timestamp", "TEXT", 0, 0), ("original_timestamp", "TEXT", 0, 0), ("summary", "TEXT", 1, 0)),
}
_EXPECTED_FOREIGN_KEYS = {
    "cases": (),
    "evidence": (("cases", "case_id", "id"),),
    "events": (("evidence", "evidence_id", "id"),),
}

def _canonical_sql(sql):
    """Normalize stored DDL: SQLite drops IF NOT EXISTS but keeps the original whitespace."""
    return " ".join(re.sub(r"\bIF NOT EXISTS\s+", "", sql).split()).rstrip(";")

# Exact table DDL (after normalization). CHECK, DEFAULT, ON DELETE and similar clauses are
# compared as text, so any semantic change to a table is rejected.
_CANONICAL_TABLE_SQL = {
    re.match(r"CREATE TABLE (\w+)", stmt).group(1): _canonical_sql(stmt) for stmt in SCHEMA_V1
}

def _validate_schema(db):
    objects = db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
    if [(kind, name) for kind, name, _ in objects] != [("table", name) for name in sorted(_EXPECTED_COLUMNS)]:
        raise ValueError("malformed storage schema")
    for _, name, sql in objects:
        if sql is None or _canonical_sql(sql) != _CANONICAL_TABLE_SQL[name]:
            raise ValueError("malformed storage schema")
    for table, columns in _EXPECTED_COLUMNS.items():
        info = tuple((r[1], r[2], r[3], r[5]) for r in db.execute(f"PRAGMA table_info({table})"))
        fks = tuple((r[2], r[3], r[4]) for r in db.execute(f"PRAGMA foreign_key_list({table})"))
        if info != columns or fks != _EXPECTED_FOREIGN_KEYS[table]:
            raise ValueError("malformed storage schema")

def _adopt_or_create_locked(db, version):
    """Runs inside BEGIN IMMEDIATE; version was re-read after the write lock was taken."""
    if version == SCHEMA_VERSION:
        # Another process migrated between our read and our write lock: validate only.
        _validate_schema(db)
        return
    if version != 0:
        raise ValueError("unsupported storage schema version")
    objects = db.execute("SELECT type,name FROM sqlite_master").fetchall()
    if not objects:
        for statement in SCHEMA_V1:
            db.execute(statement)
    else:
        # Legacy v0 with the exact original tables is adopted by stamping the version only.
        # Any other shape is rejected before anything is written.
        _validate_schema(db)
    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

def migrate_schema(db):
    """Create or adopt the schema atomically. Refuses unknown versions and malformed schemas without writing.

    An already-v1 database is validated inside a read transaction only, so read-only
    commands never take a write lock. The write lock is taken only for v0 creation/adoption.
    """
    if db.in_transaction:
        raise RuntimeError("migrate_schema requires a connection outside a transaction")
    db.execute("BEGIN")
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            _validate_schema(db)
            db.execute("COMMIT")
            return
        if version != 0:
            raise ValueError("unsupported storage schema version")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")
    db.execute("BEGIN IMMEDIATE")
    try:
        _adopt_or_create_locked(db, db.execute("PRAGMA user_version").fetchone()[0])
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
MAX_INPUT_BYTES = 512 * 1024

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def root_path():
    configured = os.environ.get("MIO_IR_HOME")
    if configured is not None:
        if not configured.strip():
            raise ValueError("MIO_IR_HOME must not be empty")
        candidate = Path(configured)
    else:
        home = os.environ.get("HOME")
        if not home:
            raise ValueError("HOME is required when MIO_IR_HOME is unset")
        candidate = Path(home) / ".local/share/azazel-mio"
    try:
        path = candidate.expanduser()
    except (KeyError, RuntimeError) as exc:
        raise ValueError("storage path cannot be expanded") from exc
    if not path.is_absolute():
        raise ValueError("storage path must be absolute")
    return path

def current_user_owns(metadata):
    getuid = getattr(os, "getuid", None)
    return getuid is not None and metadata.st_uid == getuid()

def ensure_private_directory(path, label):
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"unsafe {label}: path changed during validation") from exc
        if (not stat.S_ISDIR(metadata.st_mode) or not current_user_owns(metadata)
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError(f"unsafe {label}: expected an owned private directory")
    else:
        metadata = path.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or not current_user_owns(metadata)
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError(f"unsafe {label}: expected an owned private directory")

def existing_single_link_file(path, label):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or not current_user_owns(metadata)):
        raise ValueError(f"unsafe {label}: expected an owned single-link regular file")
    return metadata

def connect(root):
    ensure_private_directory(root, "storage path")
    database = root / "cases.sqlite3"
    existing_single_link_file(database, "storage database")
    for suffix in ("-journal", "-wal", "-shm"):
        existing_single_link_file(root / ("cases.sqlite3" + suffix), "SQLite sidecar")
    db = sqlite3.connect(database)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.isolation_level = None  # explicit transaction control for schema migration
        migrate_schema(db)
        db.isolation_level = ""
    except BaseException:
        db.close()
        raise
    return db

def output_is_inside_storage(root, path):
    root = root.resolve()
    candidate = path
    while True:
        try:
            if candidate.samefile(root):
                return True
        except OSError:
            pass
        if candidate == candidate.parent:
            return False
        candidate = candidate.parent

def check_case(db, case):
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case,)).fetchone():
        raise ValueError("unknown case")

def verify(db, root, case):
    check_case(db, case)
    rows = db.execute("SELECT id,digest FROM evidence WHERE case_id=? ORDER BY id", (case,)).fetchall()
    results = []
    directory = root / "objects"
    try:
        directory_metadata = directory.lstat()
        directory_safe = (stat.S_ISDIR(directory_metadata.st_mode)
                          and current_user_owns(directory_metadata)
                          and not (stat.S_IMODE(directory_metadata.st_mode) & 0o077))
    except FileNotFoundError:
        directory_safe = False
    for eid, digest in rows:
        path = directory / digest
        valid = False
        if directory_safe:
            try:
                metadata = existing_single_link_file(path, "stored object")
            except ValueError:
                metadata = None
            if metadata is not None and metadata.st_size <= MAX_BYTES:
                try:
                    with path.open("rb") as handle:
                        raw = handle.read(MAX_BYTES + 1)
                    valid = (len(raw) <= MAX_BYTES
                             and hashlib.sha256(raw).hexdigest() == digest)
                except OSError:
                    valid = False
        results.append({"case_id": case, "evidence_id": eid, "sha256": digest, "valid": valid})
    return results

def _check_json_nesting(text, message):
    in_string = False
    escaped = False
    nesting = 0
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            nesting += 1
            if nesting > MAX_JSON_NESTING:
                raise ValueError(message)
        elif char in "]}":
            nesting = max(0, nesting - 1)

def parse_records(raw, fmt):
    text = raw.decode("utf-8")
    _check_json_nesting(text, "JSON nesting exceeds parser limit")

    def loads_bounded(value):
        try:
            return json.loads(value)
        except RecursionError as exc:
            raise ValueError("JSON nesting exceeds parser limit") from exc

    if fmt == "jsonl":
        records = []
        start = 0
        while start < len(text):
            end = text.find("\n", start)
            if end < 0:
                end = len(text)
            line = text[start:end]
            start = end + 1 if end < len(text) else len(text)
            if line.endswith("\r"):
                line = line[:-1]
            if not line.strip(" \t"):
                continue
            if len(records) >= MAX_RECORDS:
                raise ValueError("unsupported record count")
            records.append(loads_bounded(line))
    else:
        first = 0
        while first < len(text) and text[first] in " \t\r\n":
            first += 1
        if first < len(text) and text[first] == "[":
            decoder = json.JSONDecoder()
            records = []
            index = first + 1
            while True:
                while index < len(text) and text[index] in " \t\r\n":
                    index += 1
                if index < len(text) and text[index] == "]":
                    if records:
                        raise json.JSONDecodeError("Expecting value", text, index)
                    index += 1
                    break
                if len(records) >= MAX_RECORDS:
                    raise ValueError("unsupported record count")
                try:
                    record, index = decoder.raw_decode(text, index)
                except RecursionError as exc:
                    raise ValueError("JSON nesting exceeds parser limit") from exc
                records.append(record)
                while index < len(text) and text[index] in " \t\r\n":
                    index += 1
                if index < len(text) and text[index] == ",":
                    index += 1
                    continue
                if index < len(text) and text[index] == "]":
                    index += 1
                    break
                raise json.JSONDecodeError("Expecting ',' or ']'", text, index)
            while index < len(text) and text[index] in " \t\r\n":
                index += 1
            if index != len(text):
                raise json.JSONDecodeError("Extra data", text, index)
        else:
            parsed = loads_bounded(text)
            if not isinstance(parsed, dict):
                raise ValueError("JSON input must be an object or array of objects")
            records = [parsed]
    if any(not isinstance(r, dict) for r in records):
        shape = "JSONL record" if fmt == "jsonl" else "JSON array record"
        raise ValueError(f"each {shape} must be an object")
    result = []
    for n, rec in enumerate(records, 1):
        stamp = rec.get("timestamp")
        summary = rec.get("summary", "No summary provided")
        if not isinstance(summary, (str, int, float, bool)) and summary is not None:
            raise ValueError("summary must be a JSON scalar")
        if isinstance(summary, float) and not math.isfinite(summary):
            raise ValueError("summary must be a finite JSON scalar")
        summary_text = "" if summary is None else str(summary)
        try:
            summary_text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("summary must be valid UTF-8") from exc
        if isinstance(stamp, str):
            if len(stamp) > MAX_TIMESTAMP_CHARS:
                raise ValueError("timestamp exceeds length limit")
            try:
                stamp.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("timestamp must be valid UTF-8") from exc
        normalized = None
        if isinstance(stamp, str):
            try:
                dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if dt.tzinfo is not None and dt.utcoffset() is not None:
                    normalized = dt.astimezone(timezone.utc).isoformat()
            except (ValueError, OverflowError):
                pass
        result.append((n, normalized, stamp if isinstance(stamp, str) else None,
                       summary_text[:MAX_SUMMARY_CHARS]))
    return result

def import_file(db, root, case, filename, fmt):
    check_case(db, case)
    source = Path(filename)
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise ValueError(f"unable to inspect source (errno {exc.errno})") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("source must be a regular non-symlink file")
    try:
        source.name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("source filename must be valid UTF-8") from exc
    if metadata.st_size > MAX_BYTES:
        raise ValueError("file too large")
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        if exc.errno == getattr(errno, "ELOOP", None):
            raise ValueError("source must be a regular non-symlink file") from exc
        raise ValueError(f"unable to open source (errno {exc.errno})") from exc
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
            raise ValueError("source must be a regular non-symlink file")
        if opened.st_size > MAX_BYTES:
            raise ValueError("file too large")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            raw = handle.read(MAX_BYTES + 1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > MAX_BYTES:
        raise ValueError("file too large")
    records = parse_records(raw, fmt)
    digest = hashlib.sha256(raw).hexdigest()
    directory = root / "objects"
    ensure_private_directory(directory, "object directory")
    destination = directory / digest
    # Take the SQLite write lock before publishing the object. Any other writer that could
    # reference this digest must wait until this import commits or rolls back, so cleanup
    # below never unlinks an object another transaction can see.
    db.execute("BEGIN IMMEDIATE")
    created = False
    try:
        metadata = existing_single_link_file(destination, "stored object")
        if metadata is not None:
            if metadata.st_size > MAX_BYTES:
                raise ValueError("stored object corrupted or too large")
            with destination.open("rb") as handle:
                stored = handle.read(MAX_BYTES + 1)
            if (len(stored) > MAX_BYTES
                    or hashlib.sha256(stored).hexdigest() != digest):
                raise ValueError("stored object corrupted")
        else:
            fd, tmp = tempfile.mkstemp(dir=directory)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(tmp, 0o400)
                os.replace(tmp, destination)
                created = True
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        cur = db.execute("INSERT INTO evidence(case_id,filename,digest,format,imported) VALUES(?,?,?,?,?)",
                         (case, source.name, digest, fmt, utc_now()))
        eid = cur.lastrowid
        db.executemany("INSERT INTO events(evidence_id,record_number,timestamp,original_timestamp,summary) VALUES(?,?,?,?,?)",
                       [(eid, *record) for record in records])
        db.commit()
        # The object is now referenced by committed evidence; a later exception must not unlink it.
        created = False
    except BaseException:
        # Ordinary exceptions and KeyboardInterrupt both land here. Unlink only an object this
        # call published AND whose transaction is still active; if a commit already completed,
        # the object is referenced by committed evidence and must be kept.
        # Cleanup must never mask the original error or skip rollback. If the unlink fails, the
        # published object may remain as an orphan (no evidence row references it).
        try:
            if created and db.in_transaction and os.path.lexists(destination):
                os.unlink(destination)
        except OSError:
            pass
        finally:
            db.rollback()
        raise
    return eid

def timeline(db, case):
    check_case(db, case)
    return [{"case_id": case, "event_id": row[0], "evidence_id": row[1], "record": row[2],
             "timestamp_utc": row[3], "original_timestamp": row[4], "summary": row[5]}
            for row in db.execute("""
              SELECT events.id,evidence.id,events.record_number,events.timestamp,events.original_timestamp,events.summary
              FROM events JOIN evidence ON evidence.id=events.evidence_id
              WHERE evidence.case_id=? ORDER BY events.timestamp IS NULL,events.timestamp,events.id
            """, (case,))]

def report(db, root, case):
    check_case(db, case)
    name = db.execute("SELECT name FROM cases WHERE id=?", (case,)).fetchone()[0]
    return {"case_id": case, "case_name": name, "generated_at": utc_now(),
            "evidence": verify(db, root, case), "timeline": timeline(db, case),
            "limitations": ["No inference or maliciousness attribution", "JSON/JSONL explicit timestamp/summary mapping only"]}

def _reject_duplicate_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key in normalized input")
    return dict(pairs)

def _reject_constant(token):
    raise ValueError("non-finite number in normalized input")

def read_candidate_document(path):
    # O_NONBLOCK stops a FIFO from blocking open; fstat below then rejects it.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("cannot open input: " + exc.strerror) from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("input must be a regular non-symlink file")
        if info.st_size > MAX_INPUT_BYTES:
            raise ValueError("input too large")
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input too large")
    try:
        text = raw.decode("utf-8")
        _check_json_nesting(text, "input nesting too deep")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                          parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("input nesting too deep") from exc

def assess_candidates(db, root, case, path):
    # Read-only: the store is queried, never written. The timeline and verify
    # rows both come from this one selected case, and each row carries case_id.
    check_case(db, case)
    candidates = parse_candidate_document(read_candidate_document(path), case)
    return assess_ir_candidates(case, timeline(db, case), verify(db, root, case), candidates)

def main():
    parser = argparse.ArgumentParser(prog="mio-ir")
    sub = parser.add_subparsers(dest="group", required=True)
    cases = sub.add_parser("case")
    cs = cases.add_subparsers(dest="action", required=True)
    c = cs.add_parser("create"); c.add_argument("--name", required=True)
    cs.add_parser("list")
    evidence = sub.add_parser("evidence")
    es = evidence.add_subparsers(dest="action", required=True)
    imp = es.add_parser("import"); imp.add_argument("--case", type=int, required=True)
    imp.add_argument("--file", required=True); imp.add_argument("--format", choices=["json", "jsonl"], required=True)
    ver = es.add_parser("verify"); ver.add_argument("--case", type=int, required=True)
    time = sub.add_parser("timeline")
    ts = time.add_subparsers(dest="action", required=True)
    build = ts.add_parser("build"); build.add_argument("--case", type=int, required=True)
    asm = sub.add_parser("assessment")
    asms = asm.add_subparsers(dest="action", required=True)
    cand = asms.add_parser("candidate"); cand.add_argument("--case", type=int, required=True)
    cand.add_argument("--file", required=True)
    rep = sub.add_parser("report")
    rs = rep.add_subparsers(dest="action", required=True)
    gen = rs.add_parser("generate"); gen.add_argument("--case", type=int, required=True)
    gen.add_argument("--format", choices=["json", "markdown"], required=True); gen.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        root = root_path()
        with closing(connect(root)) as db, db:
            if args.group == "case":
                if args.action == "create":
                    cur = db.execute("INSERT INTO cases(name,created) VALUES(?,?)", (args.name, utc_now()))
                    output = {"case_id": cur.lastrowid}
                else:
                    output = [{"case_id": x[0], "name": x[1]} for x in db.execute("SELECT id,name FROM cases ORDER BY id")]
            elif args.group == "evidence":
                output = {"evidence_id": import_file(db, root, args.case, args.file, args.format)} if args.action == "import" else verify(db, root, args.case)
            elif args.group == "timeline":
                output = timeline(db, args.case)
            elif args.group == "assessment":
                # connect() has finished the idempotent bootstrap; from here on the
                # connection is query-only, so no write can reach the case store.
                db.execute("PRAGMA query_only=ON")
                output = assess_candidates(db, root, args.case, args.file)
            else:
                output = report(db, root, args.case)
                report_has_invalid_evidence = any(
                    not item["valid"] for item in output["evidence"]
                )
                path = Path(args.output).resolve()
                if output_is_inside_storage(root, path):
                    raise ValueError("output may not overwrite internal storage")
                if args.format == "markdown":
                    content = "# IR Case " + str(args.case) + "\n\n" + "\n".join(
                        "- " + str(x["timestamp_utc"] or "unknown") + " | evidence " + str(x["evidence_id"]) +
                        " record " + str(x["record"]) + ": " + markdown_escape(
                            x["summary"].replace("\r", " ").replace("\n", " ")
                        )
                        for x in output["timeline"]) + "\n\nEvidence verification: " + json.dumps(output["evidence"]) + "\n"
                else:
                    content = json.dumps(output, indent=2, ensure_ascii=False)
                # Replace the output entry atomically: an existing hard link must
                # never truncate the database or evidence inode it aliases.
                fd, tmp = tempfile.mkstemp(dir=path.parent)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        handle.write(content)
                    os.replace(tmp, path)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                output = {"output": str(path)}
        print(json.dumps(output, ensure_ascii=True))
        if args.group == "evidence" and args.action == "verify" and not all(x["valid"] for x in output):
            return EXIT_INVALID_EVIDENCE
        if args.group == "report" and report_has_invalid_evidence:
            return EXIT_INVALID_EVIDENCE
        return 0
    except (ValueError, OSError, sqlite3.Error, UnicodeError, json.JSONDecodeError,
            OverflowError, RuntimeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
