#!/usr/bin/env python3
"""Persistent fixed-template analysis jobs for the Rocky MCP laboratory.

Only trusted built-in casework operations are dispatched. No shell commands,
operator-supplied executable path, arbitrary script, or network listener.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import sqlite3
import stat
import time
from typing import Any, Callable, Iterator

from casework import CaseError, CaseStore, CASE_ID, FILE_NAME
from archivework import unpack_case_archive, verify_case
from timelinework import build_timeline
from protocolwork import analyze_capture
from evtxwork import analyze_evtx
from correlationwork import build_correlation
from recipework import evaluate as evaluate_recipe, RECIPE_JOBS

JOB_ID = re.compile(r"^[a-f0-9]{32}$")
TEMPLATES = ("import_staged", "index_log", "pcap_summary", "unpack_archive", "verify_case", "build_timeline", "decode_pcap", "analyze_evtx", "build_correlation",
             *RECIPE_JOBS)
MAX_QUEUED = 16
MAX_HISTORY = 512
MAX_JOB_RESULT = 12000
MAX_WORK_SECONDS = 1800
MAX_WORK_MEMORY = 1024 * 1024 ** 2
MAX_WORK_FILE = 16 * 1024 ** 3


class JobError(Exception):
    """Operator-presentable, non-secret job error."""


class JobCancelled(JobError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secure_file(path: Path) -> None:
    if path.is_symlink():
        raise JobError("Analysis job state cannot be a symlink")
    try:
        info = path.lstat()
    except OSError as exc:
        raise JobError("Analysis job state is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise JobError("Analysis job state permissions must be private")


class JobStore:
    def __init__(self, home: Path):
        self.cases = CaseStore(home)
        self.base = self.cases.base
        self.dbfile = self.base / "jobs.sqlite3"
        self.worker_lock = self.base / "jobs.worker.lock"

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        self.cases._ensure_store()
        if self.dbfile.is_symlink():
            raise JobError("Analysis job database symlink refused")
        # The gateway's normal process umask is 0077. O_EXCL prevents follows
        # during initial creation and 0600 is rechecked on every operation.
        if not self.dbfile.exists():
            try:
                fd = os.open(self.dbfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            except OSError as exc:
                raise JobError("Analysis job database cannot be created") from exc
            else:
                os.close(fd)
        _secure_file(self.dbfile)
        try:
            conn = sqlite3.connect(str(self.dbfile), timeout=3)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=3000")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, case_id TEXT NOT NULL,
                artifact_id TEXT, filename TEXT, state TEXT NOT NULL,
                created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                result_json TEXT, failure_code TEXT, outcome TEXT)""")
            conn.commit()
        except sqlite3.Error as exc:
            raise JobError("Analysis job database is invalid or unavailable") from exc
        try:
            yield conn
        finally:
            conn.close()

    def submit(self, kind: str, case_id: str, artifact_id: str | None = None,
               filename: str | None = None) -> dict[str, Any]:
        if kind not in TEMPLATES:
            raise JobError("Unknown job template")
        self.cases._case_path(case_id)
        if kind == "import_staged":
            if not isinstance(filename, str) or not FILE_NAME.fullmatch(filename) or filename in (".", "..") or artifact_id is not None:
                raise JobError("Import requires approved intake filename only")
        elif kind in ("verify_case", "build_timeline", "build_correlation",
                      *RECIPE_JOBS):
            if artifact_id is not None or filename is not None:
                raise JobError("Case-wide analysis takes only a case identifier")
        else:
            if not isinstance(artifact_id, str) or not CASE_ID.fullmatch(artifact_id) or filename is not None:
                raise JobError("Analysis requires registered artifact ID only")
            with self.cases._locked(case_id) as (folder, manifest):
                self.cases._artifact(folder, manifest, artifact_id)
        with self._db() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                total = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
                pending = conn.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('QUEUED','RUNNING')").fetchone()[0]
                if total >= MAX_HISTORY or pending >= MAX_QUEUED:
                    raise JobError("Analysis job history/queue capacity reached")
                job_id = secrets.token_hex(16)
                created = _now()
                conn.execute("""INSERT INTO jobs (id,kind,case_id,artifact_id,filename,state,created_at)
                    VALUES (?,?,?,?,?,'QUEUED',?)""",
                    (job_id, kind, case_id, artifact_id, filename, created))
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        return {"job_id": job_id, "status": "QUEUED", "kind": kind,
                "case_id": case_id, "created_at": created}

    @staticmethod
    def _select(conn: sqlite3.Connection, job_id: str) -> sqlite3.Row:
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise JobError("Invalid job identifier")
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise JobError("Analysis job not found")
        return row

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        return {"job_id": row["id"], "kind": row["kind"],
                "case_id": row["case_id"], "state": row["state"],
                "outcome": row["outcome"], "created_at": row["created_at"],
                "started_at": row["started_at"], "finished_at": row["finished_at"],
                "cancel_requested": bool(row["cancel_requested"])}

    def status(self, job_id: str) -> dict[str, Any]:
        with self._db() as conn:
            return self._public(self._select(conn, job_id))

    def list(self) -> dict[str, Any]:
        with self._db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC,id DESC LIMIT 20").fetchall()
            return {"jobs": [self._public(row) for row in rows],
                    "total_jobs": count, "list_truncated": count > 20}

    def result(self, job_id: str) -> dict[str, Any]:
        with self._db() as conn:
            row = self._select(conn, job_id)
            public = self._public(row)
            if row["state"] == "SUCCEEDED":
                public["result"] = json.loads(row["result_json"])
            elif row["state"] in ("FAILED", "INTERRUPTED", "CANCELLED"):
                public["failure_code"] = row["failure_code"]
            return public

    def cancel(self, job_id: str) -> dict[str, Any]:
        with self._db() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._select(conn, job_id)
                if row["state"] == "QUEUED":
                    conn.execute("UPDATE jobs SET state='CANCELLED',outcome='CANCELLED',finished_at=?,failure_code='operator_cancelled' WHERE id=?",
                                 (_now(), job_id))
                elif row["state"] == "RUNNING":
                    conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        return self.status(job_id)

    def _worker_exclusive(self):
        self.cases._ensure_store()
        if self.worker_lock.is_symlink():
            raise JobError("Worker lock cannot be a symlink")
        fd = os.open(self.worker_lock, os.O_RDWR | os.O_CREAT |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            _secure_file(self.worker_lock)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise JobError("Another analysis worker is active") from exc
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _recover(self) -> None:
        # Called only while holding the exclusive worker lock. A killed worker
        # cannot leave a stale RUNNING record masquerading as success.
        with self._db() as conn:
            conn.execute("""UPDATE jobs SET state='INTERRUPTED',outcome='UNKNOWN',
                         finished_at=?,failure_code='worker_interrupted'
                         WHERE state='RUNNING'""", (_now(),))
            conn.commit()

    def _claim(self) -> dict[str, Any] | None:
        with self._db() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM jobs WHERE state='QUEUED' ORDER BY created_at,id LIMIT 1").fetchone()
                if row is None:
                    conn.commit()
                    return None
                conn.execute("UPDATE jobs SET state='RUNNING',started_at=? WHERE id=? AND state='QUEUED'",
                             (_now(), row["id"]))
                conn.commit()
                return dict(row)
            except BaseException:
                conn.rollback()
                raise

    def _check_cancel(self, job_id: str, deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise JobCancelled("job_timeout")
        with self._db() as conn:
            row = self._select(conn, job_id)
            if row["cancel_requested"]:
                raise JobCancelled("operator_cancelled")

    def _finish(self, job_id: str, state: str, *, result: dict[str, Any] | None = None,
                code: str | None = None) -> None:
        if state not in ("SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED"):
            raise JobError("Invalid terminal job state")
        outcome = result.get("status", "UNKNOWN") if result is not None else (
            "UNKNOWN" if state == "INTERRUPTED" else "CANCELLED" if state == "CANCELLED" else "FAIL")
        serialized = json.dumps(result, separators=(",", ":"), ensure_ascii=True) if result is not None else None
        if serialized is not None and len(serialized) > MAX_JOB_RESULT:
            raise JobError("Analysis result exceeds allowed size")
        with self._db() as conn:
            conn.execute("""UPDATE jobs SET state=?,outcome=?,finished_at=?,
                         result_json=?,failure_code=? WHERE id=? AND state='RUNNING'""",
                         (state, outcome, _now(), serialized, code, job_id))
            conn.commit()

    def work_once(self) -> dict[str, Any]:
        fd = self._worker_exclusive()
        try:
            self._recover()
            job = self._claim()
            if job is None:
                return {"worker": "IDLE", "processed": 0}
            job_id = job["id"]
            deadline = time.monotonic() + MAX_WORK_SECONDS
            def cancelled():
                self._check_cancel(job_id, deadline)
            try:
                cancelled()
                if job["kind"] == "import_staged":
                    result = self.cases.register(job["case_id"], job["filename"],
                                                 worker=True, should_cancel=cancelled)
                elif job["kind"] == "index_log":
                    result = self.cases.index_log(job["case_id"], job["artifact_id"],
                                                  worker=True, should_cancel=cancelled)
                elif job["kind"] == "pcap_summary":
                    result = self.cases.summarize_pcap(job["case_id"], job["artifact_id"],
                                                       worker=True, should_cancel=cancelled)
                elif job["kind"] == "unpack_archive":
                    result = unpack_case_archive(self.cases, job["case_id"], job["artifact_id"],
                                                 should_cancel=cancelled)
                elif job["kind"] == "verify_case":
                    result = verify_case(self.cases, job["case_id"], should_cancel=cancelled)
                elif job["kind"] == "build_timeline":
                    result = build_timeline(self.cases, job["case_id"], should_cancel=cancelled)
                elif job["kind"] == "decode_pcap":
                    result = analyze_capture(self.cases, job["case_id"], job["artifact_id"],
                                             should_cancel=cancelled)
                elif job["kind"] == "analyze_evtx":
                    result = analyze_evtx(self.cases, job["case_id"], job["artifact_id"],
                                          should_cancel=cancelled)
                elif job["kind"] == "build_correlation":
                    result = build_correlation(self.cases, job["case_id"], should_cancel=cancelled)
                elif job["kind"] in RECIPE_JOBS:
                    result = evaluate_recipe(self.cases, job["case_id"],
                        job["kind"].removeprefix("recipe_"), should_cancel=cancelled)
                else:
                    raise JobError("Unknown approved job type")
                # A completed file/index is not retroactively cancelled: the
                # cancellation checkpoint is inside each operation until commit.
                self._finish(job_id, "SUCCEEDED", result=result)
                state = "SUCCEEDED"
            except JobCancelled as exc:
                self._finish(job_id, "CANCELLED", code=str(exc))
                state = "CANCELLED"
            except (CaseError, JobError) as exc:
                self._finish(job_id, "FAILED", code=str(exc)[:120])
                state = "FAILED"
            except Exception:
                self._finish(job_id, "FAILED", code="analysis_worker_failed")
                state = "FAILED"
            return {"worker": "PROCESSED", "job_id": job_id, "state": state, "processed": 1}
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def apply_worker_limits() -> None:
    """Worker-only conservative resource ceiling; real Rocky01 must revalidate."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    soft_as, hard_as = resource.getrlimit(resource.RLIMIT_AS)
    if hard_as != resource.RLIM_INFINITY and hard_as < MAX_WORK_MEMORY:
        memory = hard_as
    else:
        memory = MAX_WORK_MEMORY
    resource.setrlimit(resource.RLIMIT_AS, (memory, hard_as))
    current_cpu, max_cpu = resource.getrlimit(resource.RLIMIT_CPU)
    cpu = min(1200, max_cpu) if max_cpu != resource.RLIM_INFINITY else 1200
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, max_cpu))
    old_file, hard_file = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = min(MAX_WORK_FILE, hard_file) if hard_file != resource.RLIM_INFINITY else MAX_WORK_FILE
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard_file))


def main() -> int:
    import argparse
    import sys
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Analysis worker refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Approved Rocky01 case analysis worker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--once", action="store_true")
    group.add_argument("--loop", action="store_true")
    args = parser.parse_args()
    try:
        store = JobStore(Path.home())
        apply_worker_limits()
        if args.once:
            store.work_once()
            return 0
        stopping = False
        def stop(*_):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not stopping:
            outcome = store.work_once()
            if not outcome["processed"]:
                time.sleep(1)
        return 0
    except (OSError, ValueError, JobError, CaseError, sqlite3.Error) as exc:
        print("Analysis worker unavailable: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
