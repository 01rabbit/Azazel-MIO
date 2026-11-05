"""Offline, deterministic IR evidence workflow."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timezone

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10000

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def root_path():
    return Path(os.environ.get("MIO_IR_HOME", str(Path.home() / ".local/share/azazel-mio"))).expanduser()

def current_user_owns(metadata):
    getuid = getattr(os, "getuid", None)
    return getuid is None or metadata.st_uid == getuid()

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
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
      filename TEXT NOT NULL, digest TEXT NOT NULL, format TEXT NOT NULL, imported TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
      record_number INTEGER NOT NULL, timestamp TEXT, original_timestamp TEXT, summary TEXT NOT NULL);
    """)
    return db

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
                          and current_user_owns(directory_metadata))
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
            if metadata is not None:
                valid = hashlib.sha256(path.read_bytes()).hexdigest() == digest
        results.append({"evidence_id": eid, "sha256": digest, "valid": valid})
    return results

def parse_records(raw, fmt):
    text = raw.decode("utf-8")
    def loads_bounded(value):
        try:
            return json.loads(value)
        except RecursionError as exc:
            raise ValueError("JSON nesting exceeds parser limit") from exc

    if fmt == "jsonl":
        records = [loads_bounded(line) for line in text.splitlines() if line.strip()]
    else:
        parsed = loads_bounded(text)
        records = parsed if isinstance(parsed, list) else [parsed]
    if len(records) > MAX_RECORDS or any(not isinstance(r, dict) for r in records):
        raise ValueError("unsupported record count or shape")
    result = []
    for n, rec in enumerate(records, 1):
        stamp = rec.get("timestamp")
        normalized = None
        if isinstance(stamp, str):
            try:
                dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    normalized = dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
        result.append((n, normalized, stamp if isinstance(stamp, str) else None,
                       str(rec.get("summary", "No summary provided"))[:2048]))
    return result

def import_file(db, root, case, filename, fmt):
    check_case(db, case)
    source = Path(filename)
    if source.is_symlink() or not source.is_file():
        raise ValueError("source must be a regular non-symlink file")
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("file too large")
    with source.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file too large")
    records = parse_records(raw, fmt)
    digest = hashlib.sha256(raw).hexdigest()
    directory = root / "objects"
    ensure_private_directory(directory, "object directory")
    destination = directory / digest
    metadata = existing_single_link_file(destination, "stored object")
    if metadata is not None:
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
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
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    with db:
        cur = db.execute("INSERT INTO evidence(case_id,filename,digest,format,imported) VALUES(?,?,?,?,?)",
                         (case, source.name, digest, fmt, utc_now()))
        eid = cur.lastrowid
        db.executemany("INSERT INTO events(evidence_id,record_number,timestamp,original_timestamp,summary) VALUES(?,?,?,?,?)",
                       [(eid, *record) for record in records])
    return eid

def timeline(db, case):
    check_case(db, case)
    return [{"event_id": row[0], "evidence_id": row[1], "record": row[2],
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
    rep = sub.add_parser("report")
    rs = rep.add_subparsers(dest="action", required=True)
    gen = rs.add_parser("generate"); gen.add_argument("--case", type=int, required=True)
    gen.add_argument("--format", choices=["json", "markdown"], required=True); gen.add_argument("--output", required=True)
    args = parser.parse_args()
    root = root_path()
    try:
        with connect(root) as db:
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
            else:
                output = report(db, root, args.case)
                path = Path(args.output).resolve()
                if path == root.resolve() or root.resolve() in path.parents:
                    raise ValueError("output may not overwrite internal storage")
                if args.format == "markdown":
                    content = "# IR Case " + str(args.case) + "\n\n" + "\n".join(
                        "- " + str(x["timestamp_utc"]) + " | evidence " + str(x["evidence_id"]) +
                        " record " + str(x["record"]) + ": " + x["summary"].replace("\n", " ")
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
        print(json.dumps(output, ensure_ascii=False))
        if args.group == "evidence" and args.action == "verify" and not all(x["valid"] for x in output):
            return 2
        return 0
    except (ValueError, OSError, sqlite3.Error, UnicodeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
