#!/usr/bin/env python3
"""Private, bounded, stdlib-only investigation case and evidence primitives.

This module does not execute tools, interpret evidence as instructions, or transmit
original evidence. It is a first slice; large-bundle async indexing and deep
protocol decoding are intentionally deferred and must not be implied.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import struct
from typing import Any, Iterator

from capacitywork import admission_lock, verify_committed_reserve

CASE_ID = re.compile(r"^[a-f0-9]{32}$")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
QUERY_MAX = 96
MAX_MANIFEST = 1024 * 1024
MAX_ARTIFACT = 256 * 1024 ** 2  # synchronous intake; bulk/streaming worker is future scope
MAX_CASE_STORAGE = 40 * 1024 ** 3
FREE_RESERVE = 5 * 1024 ** 3
MAX_SYNC_LOG = 128 * 1024 ** 2
MAX_SYNC_PCAP = 128 * 1024 ** 2
MAX_WORKER_ARTIFACT = 8 * 1024 ** 3
MAX_WORKER_LOG = 8 * 1024 ** 3
MAX_WORKER_PCAP = 8 * 1024 ** 3
MAX_WORKER_LINES = 8_000_000
MAX_WORKER_PCAP_RECORDS = 20_000_000
MAX_CASES = 64
MAX_SYNC_LINES = 250_000
MAX_LINE = 16_384
INDEX_PAGE_BYTES = 4096
INDEX_SAFETY_MARGIN = 16 * 1024 ** 2  # cover journal/cache/gap before next periodic free-space check
INDEX_INVENTORY_LIMIT = 256
MAX_PCAP_RECORDS = 1_000_000
MAX_PCAP_BLOCK = 16 * 1024 ** 2
MAX_PREVIEW = 350
ISO_HEAD = re.compile(
    r"^\s*(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
)
SENSITIVE = re.compile(
    r"(?i)\b(password|passwd|passphrase|token|api[_-]?key|secret|authorization)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
BEARER = re.compile(r"(?i)\bbearer\s+[-A-Za-z0-9._~+/=]{6,}")
# Fail safer when log records contain JSON key-value pairs, including malformed
# JSON that cannot be parsed as a dictionary. This remains best-effort, not a
# publication or customer-data disclosure sanitizer.
JSON_SECRET = re.compile(
    r'(?i)(["\'](?:password|passwd|passphrase|token|api[_-]?key|secret|'
    r'authorization|credential|cookie|private[_-]?key)["\']\s*:\s*)'
    r'(?:(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|[^,}\s]+)'
)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}


class CaseError(Exception):
    """Non-sensitive, operator-readable case error."""


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_directory(folder: Path, *, strict: bool) -> None:
    if folder.is_symlink():
        raise CaseError("Case storage symlinks are forbidden")
    try:
        folder.mkdir(mode=0o700, exist_ok=True)
        info = folder.lstat()
    except OSError as exc:
        raise CaseError("Case storage cannot be opened") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise CaseError("Case storage ownership or type is unsafe")
    if info.st_mode & (0o077 if strict else 0o022):
        raise CaseError("Case storage permissions are unsafe")


def _regular_open(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise CaseError("Evidence must be a regular user-owned file")
        if info.st_mode & 0o077:
            raise CaseError("Evidence file must be private to the login user (mode 0600)")
        return fd, info
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise


def _write_json_atomic(path: Path, doc: dict[str, Any]) -> None:
    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(raw) > MAX_MANIFEST:
        raise CaseError("Case manifest limit exceeded")
    temp = path.parent / (".tmp-" + secrets.token_hex(12))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_json_private(path: Path) -> dict[str, Any]:
    fd, info = _regular_open(path)
    try:
        if info.st_mode & 0o077 or info.st_size > MAX_MANIFEST:
            raise CaseError("Case manifest permissions or size invalid")
        with os.fdopen(fd, "rb") as input_file:
            fd = -1
            obj = json.loads(input_file.read(MAX_MANIFEST + 1))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CaseError("Case manifest invalid") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(obj, dict) or obj.get("schema") != 1 or not isinstance(obj.get("artifacts"), dict):
        raise CaseError("Case manifest schema unsupported")
    return obj


def _clean_line(value: str) -> str:
    stripped = "".join(c if c.isprintable() and c not in "\r\n" else "?" for c in value)
    masked = JSON_SECRET.sub(lambda m: m.group(1) + '"[REDACTED]"', stripped)
    masked = SENSITIVE.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", masked)
    return BEARER.sub("Bearer [REDACTED]", masked)[:MAX_PREVIEW]


def _parse_timestamp(line: str) -> tuple[str | None, str | None]:
    found = ISO_HEAD.match(line)
    if not found:
        return None, None
    raw = found.group(1)
    try:
        dt = datetime.fromisoformat(raw.replace(",", ".").replace("Z", "+00:00"))
    except ValueError:
        return raw[:50], None
    if dt.tzinfo is None:
        return raw[:50], None  # Never invent a timezone.
    return raw[:50], dt.astimezone(timezone.utc).isoformat()


class CaseStore:
    def __init__(self, home: Path) -> None:
        self.home = home.resolve(strict=True)
        self.base = self.home / ".local" / "share" / "rocky-mcp-gateway"
        self.inbox = self.base / "inbox"
        self.cases = self.base / "cases"

    def _ensure_store(self) -> None:
        for path, strict in [
            (self.home / ".local", False),
            (self.home / ".local" / "share", False),
            (self.base, True),
            (self.inbox, True),
            (self.cases, True),
        ]:
            _private_directory(path, strict=strict)

    def _case_path(self, case_id: str) -> Path:
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise CaseError("Invalid case identifier")
        self._ensure_store()
        folder = self.cases / case_id
        if folder.is_symlink() or not folder.is_dir():
            raise CaseError("Case not found")
        info = folder.lstat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CaseError("Case directory permissions unsafe")
        return folder

    @contextmanager
    def _locked(self, case_id: str) -> Iterator[tuple[Path, dict[str, Any]]]:
        folder = self._case_path(case_id)
        # Recheck sensitive child directories on every case operation. A
        # replaced originals/indexes directory must never redirect evidence.
        _private_directory(folder / "originals", strict=True)
        _private_directory(folder / "indexes", strict=True)
        lock = folder / ".lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    info.st_mode & 0o077):
                raise CaseError("Case lock permissions unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX)
            manifest = _read_json_private(folder / "manifest.json")
            if manifest.get("id") != case_id:
                raise CaseError("Case identity mismatch")
            yield folder, manifest
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def open_case(self) -> dict[str, Any]:
        self._ensure_store()
        # Prevent unlimited case directory creation by a chat client.
        active = sum(1 for entry in self.cases.iterdir() if entry.is_dir())
        if active >= MAX_CASES:
            raise CaseError("Maximum number of cases reached")
        for _ in range(5):
            case_id = secrets.token_hex(16)
            folder = self.cases / case_id
            try:
                folder.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        else:
            raise CaseError("Case identifier allocation failed")
        try:
            _private_directory(folder / "originals", strict=True)
            _private_directory(folder / "indexes", strict=True)
            manifest = {"schema": 1, "id": case_id, "created_at": _utc(), "artifacts": {}}
            _write_json_atomic(folder / "manifest.json", manifest)
            return {"case_id": case_id, "created_at": manifest["created_at"], "status": "OPEN"}
        except BaseException:
            # New empty directory only, never erase a preexisting case.
            shutil.rmtree(folder)
            raise

    def list_cases(self) -> dict[str, Any]:
        self._ensure_store()
        seen: list[tuple[str, str, int]] = []
        inaccessible = 0
        for entry in self.cases.iterdir():
            if not CASE_ID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
                inaccessible += 1
                continue
            try:
                with self._locked(entry.name) as (_, manifest):
                    created = manifest["created_at"]
                    if not isinstance(created, str):
                        raise CaseError("Case creation timestamp unavailable")
                    seen.append((created, entry.name, len(manifest["artifacts"])))
            except (CaseError, OSError, KeyError, ValueError):
                inaccessible += 1
        seen.sort(reverse=True)
        return {"status": "PARTIAL" if inaccessible else "PASS",
                "cases": [{"case_id": cid, "created_at": created, "artifact_count": count}
                          for created, cid, count in seen[:20]],
                "cases_found": len(seen), "cases_unreadable": inaccessible,
                "list_truncated": len(seen) > 20}

    def status(self, case_id: str) -> dict[str, Any]:
        with self._locked(case_id) as (_, manifest):
            result = {"case_id": case_id, "status": "OPEN",
                      "created_at": manifest["created_at"], "artifact_count": len(manifest["artifacts"]),
                      "artifacts": []}
            for aid, item in sorted(manifest["artifacts"].items())[:20]:
                result["artifacts"].append({"artifact_id": aid, "type": item["type"],
                                            "bytes": item["bytes"], "sha256": item["sha256"]})
            result["list_truncated"] = len(manifest["artifacts"]) > 20
            return result

    def list_artifacts(self, case_id: str, *, offset: int = 0,
                       source_artifact_id: str | None = None) -> dict[str, Any]:
        """Return bounded, private case evidence metadata without original names."""
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > 10_000:
            raise CaseError("Invalid artifact listing offset")
        if source_artifact_id is not None and (
                not isinstance(source_artifact_id, str) or not CASE_ID.fullmatch(source_artifact_id)):
            raise CaseError("Invalid archive-source artifact identifier")
        with self._locked(case_id) as (_, manifest):
            if source_artifact_id is not None and source_artifact_id not in manifest["artifacts"]:
                raise CaseError("Archive-source artifact is not registered")
            records = [(aid, meta) for aid, meta in sorted(manifest["artifacts"].items())
                       if source_artifact_id is None or meta.get("derived_from") == source_artifact_id]
            selected = records[offset:offset+20]
            return {"status": "PASS", "case_id": case_id,
                    "source_artifact_id": source_artifact_id,
                    "offset": offset, "next_offset": offset + len(selected) if offset + len(selected) < len(records) else None,
                    "total": len(records),
                    "artifacts": [{"artifact_id": aid, "bytes": item["bytes"],
                                   "type": item["type"], "sha256": item["sha256"],
                                   "derived_from": item.get("derived_from")}
                                  for aid, item in selected]}

    @staticmethod
    def _classify(prefix: bytes) -> str:
        if prefix[:8] == b"ElfFile\x00":
            return "evtx"
        if prefix[:4] in PCAP_MAGIC:
            return "pcap"
        if prefix[:4] == b"\x0a\x0d\x0d\x0a":
            return "pcapng"
        if prefix[:2] == b"\x1f\x8b":
            return "gzip"  # recognition only; unpacking is separate functionality
        if prefix[:4] == b"PK\x03\x04":
            return "zip"  # expansion requires explicit approved worker job
        if len(prefix) >= 262 and prefix[257:262] == b"ustar":
            return "tar"  # expansion requires explicit approved worker job
        if b"\x00" in prefix:
            return "binary"
        return "text"

    def register(self, case_id: str, filename: str, *, worker: bool = False,
                 should_cancel=None, derived_execution_id: str | None = None) -> dict[str, Any]:
        # An 8 GiB imported original consumes a NEW copy of an inbox file.
        # Protect pending SSH-session promises while that entire copy is
        # allocated, not just at its initial disk-usage preflight.
        with admission_lock(self):
            pending = verify_committed_reserve(self)
            return self._register_with_admission(
                case_id, filename, worker=worker, should_cancel=should_cancel,
                derived_execution_id=derived_execution_id, pending_bytes=pending)

    def _register_with_admission(
            self, case_id: str, filename: str, *, worker: bool = False,
            should_cancel=None, derived_execution_id: str | None = None,
            pending_bytes: int = 0) -> dict[str, Any]:
        if not isinstance(filename, str) or not FILE_NAME.fullmatch(filename) or filename in (".", ".."):
            raise CaseError("Invalid intake filename")
        if derived_execution_id is not None and (
                not isinstance(derived_execution_id, str)
                or not CASE_ID.fullmatch(derived_execution_id)):
            raise CaseError("Invalid internal derived execution identifier")
        with self._locked(case_id) as (folder, manifest):
            fd, before = _regular_open(self.inbox / filename)
            aid = secrets.token_hex(16)
            destination = folder / "originals" / aid
            tmp = folder / "originals" / (".tmp-" + aid)
            target_fd = -1
            stored = False
            committed = False
            try:
                maximum = MAX_WORKER_ARTIFACT if worker else MAX_ARTIFACT
                if before.st_size > maximum:
                    raise CaseError("Artifact exceeds current size limit")
                used = sum(int(item["bytes"]) for item in manifest["artifacts"].values())
                if used + before.st_size > MAX_CASE_STORAGE:
                    raise CaseError("Case storage quota exceeded")
                if shutil.disk_usage(folder).free < before.st_size + FREE_RESERVE + pending_bytes:
                    raise CaseError("Insufficient space after pending upload commitments")
                target_fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                    getattr(os, "O_NOFOLLOW", 0), 0o600)
                digest = hashlib.sha256()
                length = 0
                head = b""
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    if not head:
                        head = chunk[:4096]
                    length += len(chunk)
                    if length > maximum or length > before.st_size:
                        raise CaseError("Evidence changed during intake")
                    if should_cancel is not None:
                        should_cancel()
                    digest.update(chunk)
                    written = 0
                    while written < len(chunk):
                        n = os.write(target_fd, chunk[written:])
                        if n <= 0:
                            raise CaseError("Evidence intake copy failed")
                        written += n
                os.fsync(target_fd)
                after = os.fstat(fd)
                if (before.st_size != length or after.st_size != before.st_size or
                        after.st_mtime_ns != before.st_mtime_ns or after.st_ctime_ns != before.st_ctime_ns):
                    raise CaseError("Evidence changed during intake")
                os.close(target_fd)
                target_fd = -1
                if destination.exists() or destination.is_symlink():
                    raise CaseError("Artifact identifier collision")
                os.replace(tmp, destination)
                stored = True
                item = {"sha256": digest.hexdigest(), "bytes": length,
                        "type": self._classify(head), "registered_at": _utc(),
                        "intake_name": filename}
                if derived_execution_id is not None:
                    # Durable even if worker SIGKILL happens before the later
                    # combined execution_derivatives manifest commit.
                    item["derived_execution_id"] = derived_execution_id
                manifest["artifacts"][aid] = item
                _write_json_atomic(folder / "manifest.json", manifest)
                committed = True
                return {"case_id": case_id, "artifact_id": aid,
                        "sha256": item["sha256"], "bytes": length, "type": item["type"],
                        "status": "REGISTERED", "original_preserved": True}
            finally:
                if target_fd >= 0:
                    os.close(target_fd)
                os.close(fd)
                tmp.unlink(missing_ok=True)
                # If manifest update failed, do not strand an unregistered original.
                if stored and not committed:
                    destination.unlink(missing_ok=True)

    def _artifact(self, folder: Path, manifest: dict[str, Any], artifact_id: str) -> tuple[Path, dict[str, Any]]:
        if not isinstance(artifact_id, str) or not CASE_ID.fullmatch(artifact_id):
            raise CaseError("Invalid artifact identifier")
        item = manifest["artifacts"].get(artifact_id)
        if not isinstance(item, dict):
            raise CaseError("Artifact is not registered in this case")
        path = folder / "originals" / artifact_id
        if path.is_symlink():
            raise CaseError("Artifact path unsafe")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != item["bytes"]):
            raise CaseError("Artifact integrity preflight failed")
        return path, item

    def _indexed_file(self, folder: Path, artifact_id: str) -> Path:
        target = folder / "indexes" / (artifact_id + ".sqlite3")
        if target.is_symlink():
            raise CaseError("Index symlink refused")
        return target

    def index_log(self, case_id: str, artifact_id: str, *, worker: bool = False,
                  should_cancel=None) -> dict[str, Any]:
        # Match archive and vault lock order: admit private index writes only
        # after accounting for unfinished Windows/SSH upload promises.
        with admission_lock(self):
            pending = verify_committed_reserve(self)
            return self._index_log_with_admission(
                case_id, artifact_id, worker=worker, should_cancel=should_cancel,
                pending_bytes=pending)

    def _index_log_with_admission(self, case_id: str, artifact_id: str, *,
                                  worker: bool, should_cancel, pending_bytes: int) -> dict[str, Any]:
        # Imported on demand to avoid a module dependency cycle.
        from index_recovery import sync_index_directory
        with self._locked(case_id) as (folder, manifest):
            artifact, item = self._artifact(folder, manifest, artifact_id)
            if item["type"] != "text":
                raise CaseError("Only plain text is supported by this first log indexer")
            maximum = MAX_WORKER_LOG if worker else MAX_SYNC_LOG
            line_maximum = MAX_WORKER_LINES if worker else MAX_SYNC_LINES
            if item["bytes"] > maximum:
                raise CaseError("Log exceeds analysis worker capacity")
            final_index = self._indexed_file(folder, artifact_id)
            if final_index.exists():
                raise CaseError("Index already exists; original remains unchanged")
            indexes = folder / "indexes"
            entries = list(indexes.iterdir())
            if len(entries) > INDEX_INVENTORY_LIMIT:
                raise CaseError("Log index inventory exceeds capacity bound")
            used = sum(int(x["bytes"]) for x in manifest["artifacts"].values())
            for existing in entries:
                st = existing.lstat()
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                        or st.st_mode & 0o077 or st.st_nlink != 1):
                    raise CaseError("Unsafe pre-existing index blocks storage admission")
                used += st.st_size
            free = shutil.disk_usage(folder).free
            safe_bytes = min(MAX_CASE_STORAGE - used,
                             free - FREE_RESERVE - pending_bytes - INDEX_SAFETY_MARGIN)
            if safe_bytes < 4 * INDEX_PAGE_BYTES:
                raise CaseError("Insufficient safe capacity for a private log index")
            page_cap = safe_bytes // INDEX_PAGE_BYTES
            index_work_id = secrets.token_hex(16)
            tmp = indexes / (".tmp-" + index_work_id + ".sqlite3")
            journal = indexes / (".tmp-" + index_work_id + ".index.json")
            fd, info = _regular_open(artifact)
            db = None
            journal_written = False
            published = False
            try:
                # Journal identity and index directory must be durable before
                # a partly created SQLite database can exist after SIGKILL.
                _write_json_atomic(journal, {
                    "version": 1, "case_id": case_id, "artifact_id": artifact_id,
                    "source_sha256": item["sha256"], "temp_name": tmp.name,
                })
                journal_written = True
                sync_index_directory(indexes)
                db = sqlite3.connect(tmp)
                tmp.chmod(0o600)
                # SQLite enforces this page cap during allocation, including
                # inserts between our periodic physical-space probes.
                db.execute(f"PRAGMA page_size={INDEX_PAGE_BYTES}")
                db.execute(f"PRAGMA max_page_count={page_cap}")
                applied = int(db.execute("PRAGMA max_page_count").fetchone()[0])
                if applied > page_cap or applied < 4:
                    raise CaseError("Private index SQLite page cap was not enforced")
                db.execute("PRAGMA cache_size=-4096")
                db.execute("PRAGMA journal_mode=DELETE")
                db.execute("CREATE TABLE events (line_no INTEGER PRIMARY KEY, utc TEXT, stamp TEXT, excerpt TEXT NOT NULL)")
                db.execute("CREATE TABLE facts (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
                lines, indexed, skipped, timezone_unknown = 0, 0, 0, 0
                digest = hashlib.sha256()
                with os.fdopen(fd, "rb") as source:
                    fd = -1
                    while True:
                        raw = source.readline(MAX_LINE + 1)
                        if not raw:
                            break
                        lines += 1
                        # Every physical line counts, including a skipped
                        # oversized record. Otherwise an unbounded number of
                        # oversized lines could evade the declared limit.
                        if lines > line_maximum:
                            raise CaseError("Line count exceeds analysis worker capacity")
                        if should_cancel is not None and lines % 512 == 1:
                            should_cancel()
                        if lines % 256 == 1 and shutil.disk_usage(folder).free < (
                                FREE_RESERVE + pending_bytes + INDEX_SAFETY_MARGIN):
                            raise CaseError("Index write would consume reserved storage")
                        digest.update(raw)
                        if len(raw) > MAX_LINE:
                            while raw and not raw.endswith(b"\n"):
                                raw = source.readline(MAX_LINE + 1)
                                digest.update(raw)
                            skipped += 1
                            continue
                        text = raw.decode("utf-8", errors="replace").strip("\r\n")
                        stamp, utc = _parse_timestamp(text)
                        if stamp and utc is None:
                            timezone_unknown += 1
                        db.execute("INSERT INTO events VALUES (?, ?, ?, ?)",
                                   (lines, utc, stamp, _clean_line(text)))
                        indexed += 1
                if digest.hexdigest() != item["sha256"]:
                    raise CaseError("Source hash changed since registration")
                facts = {"artifact_sha256": item["sha256"], "lines_examined": lines,
                         "lines_indexed": indexed, "lines_skipped": skipped,
                         "timestamps_without_timezone": timezone_unknown,
                         "indexed_at": _utc(), "source_bytes": info.st_size}
                db.executemany("INSERT INTO facts VALUES (?, ?)",
                               [(k, str(v)) for k, v in facts.items()])
                try:
                    db.commit()
                except sqlite3.Error as exc:
                    raise CaseError("Private log index could not commit within its quota") from exc
                if shutil.disk_usage(folder).free < FREE_RESERVE + pending_bytes:
                    raise CaseError("Index violated reserved physical capacity before publication")
                db.close()
                db = None
                # Verify the SQLite bytes and renamed directory entry become
                # durable before announcing a completed index.
                synced = os.open(tmp, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(synced)
                finally:
                    os.close(synced)
                os.replace(tmp, final_index)
                published = True
                sync_index_directory(indexes)
                journal.unlink()
                sync_index_directory(indexes)
                journal_written = False
                return {"case_id": case_id, "artifact_id": artifact_id,
                        "status": "PARTIAL" if skipped else "PASS", **facts,
                        "note": "Search covers redacted excerpts only, not entire original lines"}
            except sqlite3.Error as exc:
                raise CaseError("Private log index exceeded available safe capacity or SQLite limits") from exc
            finally:
                if fd >= 0:
                    os.close(fd)
                if db:
                    db.close()
                if journal_written and not published:
                    # A filesystem wrapper can report failure AFTER the
                    # physical rename committed. Keep the source-bound
                    # journal if the final index exists, regardless of the
                    # local 'published' flag, so the operator can inspect an
                    # ambiguous outcome without losing provenance.
                    if not (final_index.exists() or final_index.is_symlink()):
                        try:
                            for extra in (tmp, indexes / (tmp.name + "-journal")):
                                if extra.exists() or extra.is_symlink():
                                    extra.unlink()
                            sync_index_directory(indexes)
                            journal.unlink()
                            sync_index_directory(indexes)
                        except (OSError, CaseError):
                            pass

    def search_log(self, case_id: str, artifact_id: str, query: str) -> dict[str, Any]:
        if not isinstance(query, str) or not 1 <= len(query) <= QUERY_MAX or not query.isprintable():
            raise CaseError("Invalid search expression")
        with self._locked(case_id) as (folder, manifest):
            _, item = self._artifact(folder, manifest, artifact_id)
            target = self._indexed_file(folder, artifact_id)
            if not target.is_file():
                raise CaseError("Log has not been indexed")
            info = target.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    info.st_mode & 0o077):
                raise CaseError("Index permissions unsafe")
            conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
            try:
                facts = dict(conn.execute("SELECT name,value FROM facts"))
                if facts.get("artifact_sha256") != item["sha256"]:
                    raise CaseError("Index belongs to a different artifact")
                term = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                rows = conn.execute(
                    "SELECT line_no,utc,stamp,excerpt FROM events WHERE excerpt LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 21",
                    ("%" + term + "%",)).fetchall()
            except sqlite3.Error as exc:
                raise CaseError("Log index unavailable or invalid") from exc
            finally:
                conn.close()
            return {"case_id": case_id, "artifact_id": artifact_id,
                    "status": "PARTIAL" if int(facts.get("lines_skipped", "0")) else "PASS",
                    "search_term": query, "matches": [
                        {"line": line_no, "timestamp_utc": utc, "source_timestamp": stamp,
                         "excerpt": excerpt}
                        for (line_no, utc, stamp, excerpt) in rows[:20]],
                    "has_more": len(rows) > 20,
                    "searched_redacted_excerpt_only": True,
                    "warning": "Redaction is best-effort; review before sharing findings externally"}

    def summarize_pcap(self, case_id: str, artifact_id: str, *, worker: bool = False,
                       should_cancel=None) -> dict[str, Any]:
        with self._locked(case_id) as (folder, manifest):
            artifact, item = self._artifact(folder, manifest, artifact_id)
            if item["type"] not in ("pcap", "pcapng"):
                raise CaseError("Artifact is not an identified PCAP or PCAPNG file")
            maximum = MAX_WORKER_PCAP if worker else MAX_SYNC_PCAP
            if item["bytes"] > maximum:
                raise CaseError("Capture exceeds analysis worker capacity")
            fd, info = _regular_open(artifact)
            try:
                with os.fdopen(fd, "rb") as handle:
                    fd = -1
                    digest = hashlib.sha256()
                    for piece in iter(lambda: handle.read(1024 * 1024), b""):
                        if should_cancel is not None:
                            should_cancel()
                        digest.update(piece)
                    if digest.hexdigest() != item["sha256"]:
                        raise CaseError("Capture content hash mismatch")
                    handle.seek(0)
                    if item["type"] == "pcap":
                        data = _pcap_summary(handle, info.st_size,
                                             MAX_WORKER_PCAP_RECORDS if worker else MAX_PCAP_RECORDS,
                                             should_cancel)
                    else:
                        data = _pcapng_summary(handle, info.st_size,
                                               MAX_WORKER_PCAP_RECORDS if worker else MAX_PCAP_RECORDS,
                                               should_cancel)
            finally:
                if fd >= 0:
                    os.close(fd)
            return {"case_id": case_id, "artifact_id": artifact_id,
                    "sha256": item["sha256"], "source_bytes": info.st_size,
                    "payloads_examined": False, **data}


def _pcap_summary(fp, size: int, max_records: int = MAX_PCAP_RECORDS,
                  should_cancel=None) -> dict[str, Any]:
    header = fp.read(24)
    if len(header) != 24 or header[:4] not in PCAP_MAGIC:
        raise CaseError("Invalid PCAP global header")
    endian, resolution = PCAP_MAGIC[header[:4]]
    major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4) or snaplen == 0 or snaplen > MAX_PCAP_BLOCK:
        raise CaseError("Unsupported PCAP version or snapshot length")
    count, truncated, earliest, latest = 0, False, None, None
    while fp.tell() < size:
        if count >= max_records:
            truncated = True
            break
        if should_cancel is not None and count % 1024 == 0:
            should_cancel()
        record = fp.read(16)
        if len(record) != 16:
            raise CaseError("Truncated PCAP record header")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
        if (captured > snaplen or captured > MAX_PCAP_BLOCK or
                original < captured or captured > size - fp.tell()):
            raise CaseError("Invalid or truncated PCAP packet length")
        if fraction >= (1_000_000_000 if resolution == "nanosecond" else 1_000_000):
            raise CaseError("Invalid PCAP record timestamp")
        moment = seconds + fraction / (1_000_000_000 if resolution == "nanosecond" else 1_000_000)
        earliest = moment if earliest is None else min(earliest, moment)
        latest = moment if latest is None else max(latest, moment)
        fp.seek(captured, os.SEEK_CUR)
        count += 1
    return {"status": "PARTIAL" if truncated else "PASS", "capture_type": "pcap",
            "snaplen": snaplen, "linktype": network, "packets_examined": count,
            "count_truncated": truncated,
            "earliest_utc": datetime.fromtimestamp(earliest, timezone.utc).isoformat() if earliest is not None else None,
            "latest_utc": datetime.fromtimestamp(latest, timezone.utc).isoformat() if latest is not None else None,
            "analysis": "headers/timestamps only; no flow or payload decoding yet"}


def _pcapng_summary(fp, size: int, max_records: int = MAX_PCAP_RECORDS,
                    should_cancel=None) -> dict[str, Any]:
    count, blocks, truncated, interfaces, sections = 0, 0, False, 0, 0
    endian = None
    while fp.tell() < size:
        if blocks >= max_records * 2:
            truncated = True
            break
        if should_cancel is not None and blocks % 1024 == 0:
            should_cancel()
        start = fp.tell()
        header = fp.read(12)
        if len(header) != 12:
            raise CaseError("Truncated PCAPNG block")
        kind_bytes, size_bytes, bom = header[:4], header[4:8], header[8:12]
        if kind_bytes == b"\x0a\x0d\x0d\x0a":
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaseError("PCAPNG section has invalid byte order")
            sections += 1
            interfaces = 0  # Each PCAPNG section has its own interface namespace.
        elif endian is None:
            raise CaseError("PCAPNG packet block before section header")
        length = struct.unpack(endian + "I", size_bytes)[0]
        if (length < (28 if kind_bytes == b"\x0a\x0d\x0d\x0a" else 12) or
                length % 4 or length > MAX_PCAP_BLOCK or length > size - start):
            raise CaseError("Invalid PCAPNG block length")
        kind = struct.unpack(endian + "I", kind_bytes)[0]
        if kind == 1:
            if length < 20:
                raise CaseError("PCAPNG interface block too short")
            interfaces += 1
        if kind == 3 and length < 16:
            raise CaseError("PCAPNG simple packet block too short")
        if kind in (3, 6):
            count += 1
        if kind == 6 and length < 32:
            raise CaseError("Truncated enhanced packet block")
        if kind == 6:
            fp.seek(start + 8, os.SEEK_SET)
            fields = fp.read(20)
            if len(fields) != 20:
                raise CaseError("Truncated enhanced packet block")
            interface_id, _, _, captured, original = struct.unpack(endian + "IIIII", fields)
            if interface_id >= interfaces:
                raise CaseError("PCAPNG references unknown interface")
            if original < captured or captured > length - 32:
                raise CaseError("Invalid PCAPNG captured packet size")
        fp.seek(start + length - 4, os.SEEK_SET)
        trailer = fp.read(4)
        if trailer != size_bytes:
            raise CaseError("PCAPNG block length trailer disagrees")
        blocks += 1
    if sections == 0:
        raise CaseError("PCAPNG section missing")
    return {"status": "PARTIAL" if truncated else "PASS", "capture_type": "pcapng",
            "sections": sections, "interfaces": interfaces, "blocks_examined": blocks,
            "packets_examined": count, "count_truncated": truncated,
            "earliest_utc": None, "latest_utc": None,
            "analysis": "block structure only; timestamp resolution and flow decoding deferred"}
