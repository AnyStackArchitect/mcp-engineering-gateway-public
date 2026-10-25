#!/usr/bin/env python3
"""Off-host development: operator-gated, one-use rootless Podman analysis jobs.

MCP can PREPARE, READ and CANCEL, but CANNOT approve. The operator signs a
review bundle on a separate workstation holding the private Ed25519 key.
A locally staged detached signature is verified at import AND on every claim;
direct SQLite status changes are insufficient. Worker/account isolation is
still required to protect the signed-grant consumption ledger.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import sqlite3
import stat
import subprocess
import time
from typing import Any, Iterator

from casework import CaseStore, CaseError, CASE_ID, FREE_RESERVE
from approvalwork import APPROVAL_DIR, GrantError, verify as verify_grant
from capacitywork import admission_lock, verify_committed_reserve
from outputcopy import copy_outputs, CopyError
from outputwork import OutputError, register_outputs, recover_interrupted_outputs
from podman_policy import (container_run_command, container_exec_command,
                           container_remove_command)

ID = re.compile(r"^[a-f0-9]{32}$")
IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,190}@sha256:[a-f0-9]{64}$")
OUTPUT = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
MAX_SCRIPT = 16 * 1024
MAX_INPUTS = 4
MAX_INPUT_BYTES = 4 * 1024 * 1024 * 1024
MAX_OUTPUTS = 4
MAX_PENDING = 8
MAX_CAPTURE = 65536
PLAN_TTL = 1800
GRANT_TTL = 300

class ExecutionError(Exception):
    """Safe, generic execution error for an MCP client."""

def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")

def _hash_file(path: Path, expected: str | None = None) -> tuple[str, int]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ExecutionError("Source file is not a private regular file")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as inp:
        while True:
            chunk = inp.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count>info.st_size or count>MAX_INPUT_BYTES:
                raise ExecutionError("Source grew beyond approved bounded identity")
            digest.update(chunk)
    if count != info.st_size or (expected is not None and digest.hexdigest() != expected):
        raise ExecutionError("Source integrity changed")
    return digest.hexdigest(), count

def _private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ExecutionError("Execution directory symlinks are forbidden")
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ExecutionError("Execution directory permissions are unsafe")

def _private_write(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as out:
        out.write(content)
        out.flush()
        os.fsync(out.fileno())

class ExecutionStore:
    def __init__(self, home: Path, *, approval_dir: Path = APPROVAL_DIR,
                 trusted_approval_uid: int = 0):
        self.cases = CaseStore(home)
        self.approval_dir = Path(approval_dir)
        self.trusted_approval_uid = trusted_approval_uid
        self.base = self.cases.base
        self.dbfile = self.base / "execution.sqlite3"
        self.workroot = self.base / "execution"
        self.imagefile = self.cases.home / ".config" / "rocky-mcp-gateway" / "sandbox-image.txt"

    def _image(self) -> str:
        try:
            for ancestor in (self.imagefile.parent.parent, self.imagefile.parent):
                if ancestor.is_symlink():
                    raise ExecutionError("Sandbox image config has unsafe ancestry")
                meta = ancestor.stat()
                if meta.st_uid != os.getuid() or meta.st_mode & 0o022:
                    raise ExecutionError("Sandbox image config permissions unsafe")
            meta = self.imagefile.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                    or meta.st_mode & 0o077 or meta.st_nlink != 1):
                raise ExecutionError("Sandbox image config permissions unsafe")
            raw = self.imagefile.read_text("ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise ExecutionError("Pinned sandbox image is not configured") from exc
        if not IMAGE.fullmatch(raw):
            raise ExecutionError("Sandbox image must be SHA256 pinned")
        return raw

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        self.cases._ensure_store()
        if self.dbfile.is_symlink():
            raise ExecutionError("Execution database symlink refused")
        try:
            fd = os.open(self.dbfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ExecutionError("Execution database unavailable") from exc
        else:
            os.close(fd)
        info = self.dbfile.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ExecutionError("Execution database permissions unsafe")
        conn = sqlite3.connect(self.dbfile, timeout=3)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=3000")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("""CREATE TABLE IF NOT EXISTS plans (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, plan_json TEXT NOT NULL,
                script TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL,
                created INTEGER NOT NULL, approved_until INTEGER,
                approved_digest TEXT, started TEXT, finished TEXT,
                cancel INTEGER NOT NULL DEFAULT 0, failure TEXT, result_json TEXT,
                grant_json TEXT)""")
            # Existing unapproved plans get a NULL grant, never grandfathered approval.
            fields = {row[1] for row in conn.execute("PRAGMA table_info(plans)")}
            if "grant_json" not in fields:
                conn.execute("ALTER TABLE plans ADD COLUMN grant_json TEXT")
            conn.execute("""CREATE TABLE IF NOT EXISTS grant_nonces (
                nonce TEXT PRIMARY KEY, execution_id TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0)""")
            conn.commit()
            yield conn
        except sqlite3.Error as exc:
            raise ExecutionError("Execution database failed") from exc
        finally:
            conn.close()

    @staticmethod
    def _row(conn: sqlite3.Connection, plan_id: str) -> sqlite3.Row:
        if not isinstance(plan_id, str) or not ID.fullmatch(plan_id):
            raise ExecutionError("Invalid execution identifier")
        row = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ExecutionError("Execution plan not found")
        return row

    @staticmethod
    def _verified_plan(row: sqlite3.Row) -> dict[str, Any]:
        try:
            plan = json.loads(row["plan_json"])
            digest = hashlib.sha256(_canonical(plan)).hexdigest()
            script_digest = hashlib.sha256(row["script"].encode("utf-8")).hexdigest()
            if digest != row["digest"] or script_digest != plan["script_sha256"]:
                raise ExecutionError("Execution plan integrity mismatch")
            if row["approved_digest"] is not None and row["approved_digest"] != digest:
                raise ExecutionError("Execution grant identity mismatch")
            if plan["case_id"] != row["case_id"] or plan["id"] != row["id"]:
                raise ExecutionError("Execution case identity mismatch")
            return plan
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ExecutionError("Execution plan cannot be verified") from exc

    def prepare(self, case_id: str, script: str, artifact_ids: list[str],
                output_names: list[str], timeout_seconds: int = 60,
                memory_mib: int = 256, disk_mib: int = 32) -> dict[str, Any]:
        if not isinstance(script, str) or "\x00" in script or not 1 <= len(script.encode("utf-8")) <= MAX_SCRIPT:
            raise ExecutionError("Python script size or encoding invalid")
        try:
            ast.parse(script, filename="<operator-review>", mode="exec")
        except (SyntaxError, ValueError) as exc:
            raise ExecutionError("Python script syntax invalid") from exc
        if (not isinstance(artifact_ids, list) or len(artifact_ids) > MAX_INPUTS
                or any(not isinstance(v, str) or not ID.fullmatch(v) for v in artifact_ids)
                or len(set(artifact_ids)) != len(artifact_ids)):
            raise ExecutionError("Invalid registered input artifact list")
        if (not isinstance(output_names, list) or not 1 <= len(output_names) <= MAX_OUTPUTS
                or any(not isinstance(v, str) or not OUTPUT.fullmatch(v) or v in (".", "..")
                       for v in output_names) or len(set(output_names)) != len(output_names)):
            raise ExecutionError("Invalid permitted output names")
        for value, low, high in ((timeout_seconds, 10, 180), (memory_mib, 128, 2048), (disk_mib, 8, 512)):
            if type(value) is not int or not low <= value <= high:
                raise ExecutionError("Execution resource limit invalid")
        image = self._image()
        inputs = []
        with self.cases._locked(case_id) as (folder, manifest):
            total = 0
            for aid in artifact_ids:
                path, meta = self.cases._artifact(folder, manifest, aid)
                if meta["bytes"] > MAX_INPUT_BYTES:
                    raise ExecutionError("Input exceeds sandbox quota")
                digest, length = _hash_file(path, meta["sha256"])
                total += length
                inputs.append({"artifact_id": aid, "sha256": digest, "bytes": length})
            if total > MAX_INPUT_BYTES:
                raise ExecutionError("Total sandbox inputs exceed quota")
        plan_id = secrets.token_hex(16)
        plan = {"id": plan_id, "case_id": case_id, "image": image,
                "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
                "inputs": inputs, "output_names": output_names,
                "timeout_seconds": timeout_seconds, "memory_mib": memory_mib,
                "disk_mib": disk_mib}
        digest = hashlib.sha256(_canonical(plan)).hexdigest()
        now = int(time.time())
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pending = conn.execute("SELECT count(*) FROM plans WHERE state IN ('PREPARED','QUEUED','RUNNING')").fetchone()[0]
            if pending >= MAX_PENDING:
                raise ExecutionError("Execution plan capacity reached")
            conn.execute("""INSERT INTO plans(id,case_id,plan_json,script,digest,state,created)
                VALUES(?,?,?,?,?,'PREPARED',?)""", (plan_id, case_id, _canonical(plan).decode("ascii"), script, digest, now))
            conn.commit()
        return {"execution_id": plan_id, "state": "PREPARED", "plan_sha256": digest,
                "script_sha256": plan["script_sha256"], "image": image,
                "inputs": inputs, "output_names": output_names,
                "timeout_seconds": timeout_seconds, "memory_mib": memory_mib,
                "disk_mib": disk_mib, "approval": "SIGNED_OFF_HOST_OPERATOR_GRANT_REQUIRED",
                "expires_at_epoch": now + PLAN_TTL}

    def inspect_local(self, plan_id: str) -> tuple[dict[str, Any], str]:
        """Only the local operator CLI uses this; MCP never exposes full scripts."""
        with self._db() as conn:
            row = self._row(conn, plan_id)
            return {"plan": self._verified_plan(row), "digest": row["digest"],
                    "state": row["state"], "created": row["created"]}, row["script"]

    def _verified_grant(self, row: sqlite3.Row) -> dict[str, Any]:
        """Require an authentic, unexpired, plan-bound signed grant every time."""
        try:
            if row["grant_json"] is None:
                raise ExecutionError("Signed operator grant required")
            raw = row["grant_json"]
            if not isinstance(raw, str) or len(raw.encode("ascii")) > 4096:
                raise ExecutionError("Signed grant storage invalid")
            envelope = json.loads(raw)
            payload = verify_grant(envelope, trust_dir=self.approval_dir,
                                   trusted_uid=self.trusted_approval_uid)
            if (payload["decision"] != "APPROVE"
                    or payload["execution_id"] != row["id"]
                    or payload["case_id"] != row["case_id"]
                    or payload["plan_sha256"] != row["digest"]
                    or payload["expires_at"] != row["approved_until"]
                    or row["approved_digest"] != row["digest"]
                    or payload["issued_at"] < row["created"] - 30
                    or payload["expires_at"] > row["created"] + PLAN_TTL):
                raise ExecutionError("Operator grant does not match execution plan")
            return payload
        except (GrantError, ValueError, TypeError, UnicodeError) as exc:
            raise ExecutionError("Signed operator grant invalid") from exc

    def import_signed_grant(self, envelope: dict) -> dict[str, Any]:
        """Import signed operator authorization, only from local staging, never MCP."""
        try:
            payload = verify_grant(envelope, trust_dir=self.approval_dir,
                                   trusted_uid=self.trusted_approval_uid)
        except GrantError as exc:
            raise ExecutionError("Signed operator grant invalid") from exc
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, payload["execution_id"])
            plan = self._verified_plan(row)
            now = int(time.time())
            if row["state"] != "PREPARED" or row["cancel"]:
                raise ExecutionError("Execution is not awaiting a grant")
            if now >= row["created"] + PLAN_TTL:
                conn.execute("UPDATE plans SET state='EXPIRED',finished=? WHERE id=?",
                             (_utc(), row["id"]))
                conn.commit()
                raise ExecutionError("Execution plan expired")
            if (payload["case_id"] != row["case_id"]
                    or payload["plan_sha256"] != row["digest"]
                    or payload["issued_at"] < row["created"] - 30
                    or payload["expires_at"] > row["created"] + PLAN_TTL
                    or plan["image"] != self._image()):
                raise ExecutionError("Grant is not bound to current plan and image")
            try:
                conn.execute("""INSERT INTO grant_nonces(nonce,execution_id,consumed)
                                VALUES(?,?,?)""",
                             (payload["nonce"], row["id"],
                              1 if payload["decision"] == "DENY" else 0))
            except sqlite3.IntegrityError as exc:
                raise ExecutionError("Signed grant nonce already registered") from exc
            state = "DENIED" if payload["decision"] == "DENY" else "QUEUED"
            until = payload["expires_at"] if state == "QUEUED" else None
            conn.execute("""UPDATE plans SET state=?,approved_digest=?,approved_until=?,
                           grant_json=?,finished=? WHERE id=? AND state='PREPARED'""",
                         (state, row["digest"], until, 
                          json.dumps(envelope, sort_keys=True, separators=(",", ":")),
                          _utc() if state == "DENIED" else None, row["id"]))
            conn.commit()
        return {"execution_id": row["id"], "state": state,
                "plan_sha256": row["digest"], "approval_expires_epoch": until}

    def status(self, plan_id: str, *, include_result: bool = False) -> dict[str, Any]:
        with self._db() as conn:
            row = self._row(conn, plan_id)
            plan = self._verified_plan(row)
            state = row["state"]
            now = int(time.time())
            if state == "PREPARED" and now >= row["created"] + PLAN_TTL:
                state = "EXPIRED"
            if state == "QUEUED" and now >= (row["approved_until"] or 0):
                state = "EXPIRED"
            out = {"execution_id": plan_id, "state": state, "plan_sha256": row["digest"],
                   "script_sha256": plan["script_sha256"],
                   "output_names": plan["output_names"],
                   "approval_expires_epoch": row["approved_until"],
                   "started": row["started"], "finished": row["finished"],
                   "cancel_requested": bool(row["cancel"])}
            if include_result and state in ("SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED", "DENIED", "EXPIRED"):
                out["failure_code"] = row["failure"]
                if row["result_json"] is not None:
                    out["result"] = json.loads(row["result_json"])
            return out

    def cancel(self, plan_id: str) -> dict[str, Any]:
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, plan_id)
            self._verified_plan(row)
            if row["state"] in ("PREPARED", "QUEUED"):
                conn.execute("""UPDATE plans SET state='CANCELLED',cancel=1,finished=?,
                    failure='operator_cancelled' WHERE id=?""", (_utc(), plan_id))
            elif row["state"] == "RUNNING":
                conn.execute("UPDATE plans SET cancel=1 WHERE id=?", (plan_id,))
            conn.commit()
        return self.status(plan_id)

    @staticmethod
    def _env(home: Path) -> dict[str, str]:
        env = {"HOME": str(home), "USER": home.name, "LOGNAME": home.name,
               "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        for key in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            value = os.environ.get(key, "")
            if value and len(value) < 512 and "\n" not in value and "\x00" not in value:
                env[key] = value
        return env

    @staticmethod
    def _boot_identity() -> str:
        value = Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
            raise ExecutionError("Sandbox cleanup not verified")
        return value

    def _launch_marker(self, plan_id: str) -> Path:
        if not isinstance(plan_id, str) or not ID.fullmatch(plan_id):
            raise ExecutionError("Sandbox cleanup not verified")
        return self.workroot / plan_id / "launch-intent.json"

    def _check_launch_quiescence(self, plan_id: str) -> None:
        try:
            self._read_launch_quiescence(plan_id)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc

    def _read_launch_quiescence(self, plan_id: str) -> None:
        # A killed Podman CLI can leave a detached creator. PID absence and
        # `rm --ignore` success do not prove that late creation is impossible.
        marker = self._launch_marker(plan_id)
        root = marker.parent
        if root.is_symlink():
            raise ExecutionError("Sandbox cleanup not verified")
        try:
            info = marker.lstat()
        except FileNotFoundError:
            return
        try:
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 256):
                raise ValueError("unsafe marker")
            value = json.loads(marker.read_text("ascii"))
            boot = value["boot_id"]
            if (set(value) != {"boot_id", "execution_id"} or value["execution_id"] != plan_id
                    or not isinstance(boot, str)
                    or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot)
                    or boot == self._boot_identity()):
                raise ValueError("launch uncertainty requires a new boot")
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc

    def _cleanup_container(self, plan_id: str) -> None:
        self._check_launch_quiescence(plan_id)
        name = "rocky-gw-job-" + plan_id
        try:
            result = subprocess.run(container_remove_command(plan_id),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=15,
                                    env=self._env(self.cases.home), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc
        if result.returncode:
            raise ExecutionError("Sandbox cleanup not verified")
        try:
            absent = subprocess.run(["/usr/bin/podman", "container", "exists", name],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=15,
                                    env=self._env(self.cases.home), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc
        if absent.returncode != 1:
            raise ExecutionError("Sandbox cleanup not verified")

    def _cleanup_workspace(self, plan_id: str) -> None:
        try:
            self._remove_workspace(plan_id)
        except OSError as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc

    def _remove_workspace(self, plan_id: str) -> None:
        if not isinstance(plan_id, str) or not ID.fullmatch(plan_id):
            raise ExecutionError("Sandbox cleanup not verified")
        root = self.workroot / plan_id
        if root.is_symlink():
            raise ExecutionError("Sandbox cleanup not verified")
        try:
            info = root.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise ExecutionError("Sandbox cleanup not verified")
        try:
            shutil.rmtree(root)
        except OSError as exc:
            raise ExecutionError("Sandbox cleanup not verified") from exc
        if root.exists() or root.is_symlink():
            raise ExecutionError("Sandbox cleanup not verified")

    def recover_orphans(self) -> None:
        """Caller MUST hold existing JobStore worker lock; no second worker can race."""
        with self._db() as conn:
            running = [(row["id"], row["case_id"]) for row in
                       conn.execute("SELECT id,case_id FROM plans WHERE state='RUNNING'")]
        for plan_id, case_id in running:
            # Fail closed: neither container cleanup nor partial derived
            # evidence cleanup may be skipped before marking INTERRUPTED.
            self._cleanup_container(plan_id)
            self._cleanup_workspace(plan_id)
            recover_interrupted_outputs(self.cases, case_id, plan_id)
            with self._db() as conn:
                conn.execute("""UPDATE plans SET state='INTERRUPTED',failure='worker_interrupted',
                                finished=? WHERE id=? AND state='RUNNING'""", (_utc(), plan_id))
                conn.commit()

    def _claim(self) -> sqlite3.Row | None:
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM plans WHERE state='RUNNING' LIMIT 1").fetchone():
                raise ExecutionError("Sandbox cleanup not verified")
            now = int(time.time())
            conn.execute("""UPDATE plans SET state='EXPIRED',finished=?,failure='grant_expired'
                            WHERE state='QUEUED' AND approved_until<=?""", (_utc(), now))
            conn.execute("""UPDATE plans SET state='EXPIRED',finished=?,failure='plan_expired'
                            WHERE state='PREPARED' AND created+?<=?""", (_utc(), PLAN_TTL, now))
            row = conn.execute("SELECT * FROM plans WHERE state='QUEUED' ORDER BY created,id LIMIT 1").fetchone()
            if row is None:
                conn.commit()
                return None
            try:
                plan = self._verified_plan(row)
                grant = self._verified_grant(row)
                if plan["image"] != self._image() or row["cancel"]:
                    raise ExecutionError("Execution approval invalid")
                consumed = conn.execute(
                    """UPDATE grant_nonces SET consumed=1 WHERE nonce=? AND
                       execution_id=? AND consumed=0""",
                    (grant["nonce"], row["id"]))
                if consumed.rowcount != 1:
                    raise ExecutionError("Signed grant has already been consumed")
            except ExecutionError:
                conn.execute("""UPDATE plans SET state='FAILED',finished=?,failure='approval_invalid'
                                WHERE id=?""", (_utc(), row["id"]))
                conn.commit()
                return None
            conn.execute("UPDATE plans SET state='RUNNING',started=? WHERE id=? AND state='QUEUED'",
                         (_utc(), row["id"]))
            conn.commit()
            return row

    def _cancelled(self, plan_id: str) -> bool:
        with self._db() as conn:
            return bool(self._row(conn, plan_id)["cancel"])

    def _finish(self, plan_id: str, state: str, failure: str | None,
                result: dict[str, Any] | None = None) -> None:
        if state not in ("SUCCEEDED", "FAILED", "CANCELLED"):
            raise ExecutionError("Invalid execution terminal state")
        value = _canonical(result).decode("ascii") if result is not None else None
        with self._db() as conn:
            conn.execute("""UPDATE plans SET state=?,finished=?,failure=?,result_json=?
                        WHERE id=? AND state='RUNNING'""", (state, _utc(), failure, value, plan_id))
            conn.commit()

    def _stage(self, plan: dict[str, Any], script: str) -> tuple[Path, Path]:
        with admission_lock(self.cases):
            verify_committed_reserve(self.cases,extra_bytes=sum(i['bytes'] for i in plan['inputs'])+MAX_SCRIPT+65536)
            return self._stage_with_admission(plan,script)

    def _stage_with_admission(self, plan: dict[str, Any], script: str) -> tuple[Path, Path]:
        with self.cases._locked(plan["case_id"]) as (folder, manifest):
            total = sum(i["bytes"] for i in plan["inputs"])
            if shutil.disk_usage(folder).free < total + FREE_RESERVE:
                raise ExecutionError("Insufficient disk headroom before input copies")
            _private_dir(self.workroot)
            root = self.workroot / plan["id"]
            root.mkdir(mode=0o700)  # O_EXCL semantics; never reuse a previous workspace
            _private_dir(root)
            inputs_dir = root / "readonly"
            _private_dir(inputs_dir)
            _private_write(inputs_dir / "program.py", script.encode("utf-8"))
            for item in plan["inputs"]:
                source, meta = self.cases._artifact(folder, manifest, item["artifact_id"])
                if (meta["sha256"] != item["sha256"] or meta["bytes"] != item["bytes"]):
                    raise ExecutionError("Registered evidence changed after approval")
                digest, length = _hash_file(source, item["sha256"])
                if length != item["bytes"]:
                    raise ExecutionError("Approved input length changed")
                target = inputs_dir / item["artifact_id"]
                hasher = hashlib.sha256()
                copied = 0
                with source.open("rb") as inp:
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as out:
                        while True:
                            chunk = inp.read(1024 * 1024)
                            if not chunk:
                                break
                            copied += len(chunk)
                            if copied>item['bytes']:
                                raise ExecutionError("Input grew beyond approved staging length")
                            out.write(chunk)
                            hasher.update(chunk)
                        out.flush()
                        os.fsync(out.fileno())
                if copied!=item['bytes'] or hasher.hexdigest() != item["sha256"]:
                    raise ExecutionError("Input changed during staging")
            return root, inputs_dir

    def _capture(self, process: subprocess.Popen[bytes], plan_id: str, deadline: float,
                 root: Path) -> tuple[int, bytes, bytes]:
        sel = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        for pipe in (process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ)
        collected = {process.stdout: bytearray(), process.stderr: bytearray()}
        oversize = False
        try:
            while sel.get_map():
                if self._cancelled(plan_id):
                    raise ExecutionError("operator_cancelled")
                if time.monotonic() >= deadline:
                    raise ExecutionError("execution_timeout")
                for key, _ in sel.select(timeout=0.2):
                    pipe = key.fileobj
                    data = os.read(pipe.fileno(), 32768)
                    if not data:
                        sel.unregister(pipe)
                        continue
                    buffer = collected[pipe]
                    if len(buffer) + len(data) > MAX_CAPTURE:
                        oversize = True
                    buffer.extend(data[:max(0, MAX_CAPTURE - len(buffer))])
                if oversize:
                    raise ExecutionError("execution_output_limit")
            try:
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise ExecutionError("execution_timeout") from exc
            return code, bytes(collected[process.stdout]), bytes(collected[process.stderr])
        finally:
            sel.close()

    def _run(self, row: sqlite3.Row) -> dict[str, Any]:
        plan = self._verified_plan(row)
        grant = self._verified_grant(row)
        with self._db() as conn:
            current = self._row(conn, row["id"])
            consumed = conn.execute(
                "SELECT consumed FROM grant_nonces WHERE nonce=? AND execution_id=?",
                (grant["nonce"], row["id"])).fetchone()
            if (current["state"] != "RUNNING" or consumed is None
                    or consumed["consumed"] != 1):
                raise ExecutionError("Signed execution claim is not valid")
        if self._image() != plan["image"]:
            raise ExecutionError("sandbox_image_changed")
        if self._cancelled(row["id"]):
            raise ExecutionError("operator_cancelled")
        try:
            root, ro = self._stage(plan, row["script"])
        except BaseException:
            # A rejected/partial staging operation may have allocated the
            # private workspace before rejecting corrupt evidence.
            self._cleanup_workspace(row["id"])
            raise
        output = root / "output"
        try:
            _private_dir(output)
        except BaseException:
            # This can fail after approved inputs were already copied.
            # Do not leave a staging workspace if output allocation fails.
            self._cleanup_workspace(row["id"])
            raise
        name = "rocky-gw-job-" + row["id"]
        # Keep the container alive while copying files out of the bounded
        # /output tmpfs. A stopped container has already lost its tmpfs data.
        command = container_run_command(plan, ro)
        code = None
        stdout = stderr = b""
        try:
            marker = self._launch_marker(row["id"])
            _private_write(marker, _canonical({"execution_id": row["id"],
                                               "boot_id": self._boot_identity()}))
            try:
                started = subprocess.run(command, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         timeout=30, env=self._env(self.cases.home),
                                         cwd=str(self.cases.home), check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ExecutionError("sandbox_runtime_unavailable") from exc
            if started.returncode:
                raise ExecutionError("sandbox_runtime_unavailable")
            # A successful synchronous run has completed container creation.
            # Every other outcome preserves the marker, including worker death.
            marker.unlink()
            try:
                process = subprocess.Popen(
                    container_exec_command(row["id"]),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=self._env(self.cases.home), cwd=str(self.cases.home))
            except OSError as exc:
                raise ExecutionError("sandbox_runtime_unavailable") from exc
            try:
                code, stdout, stderr = self._capture(
                    process, row["id"], time.monotonic() + plan["timeout_seconds"], root)
            except ExecutionError:
                process.kill()
                process.wait(timeout=10)
                raise
            with admission_lock(self.cases):
                verify_committed_reserve(self.cases,extra_bytes=2*MAX_CAPTURE+65536)
                _private_write(root / "stdout.bin", stdout)
                _private_write(root / "stderr.bin", stderr)
            if code != 0:
                raise ExecutionError("script_nonzero_exit")
            try:
                copy_outputs(self.cases,plan,output,env=self._env(self.cases.home))
            except (OSError,CopyError,CaseError,ValueError,subprocess.SubprocessError) as exc:
                raise ExecutionError("sandbox_output_copy_failed") from exc
            try:
                files = register_outputs(
                    self.cases, plan["case_id"], row["id"], row["digest"],
                    plan["inputs"], output, plan["output_names"], plan["disk_mib"])
            except (OutputError, CaseError, OSError):
                raise ExecutionError("sandbox_output_registration_failed")
            return {"status": "PASS", "exit_code": code,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                    "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                    "outputs": sorted(files, key=lambda v: v["name"])}
        finally:
            # Both container and private workspace must be gone before a job
            # can be finalized. A cleanup error keeps RUNNING for startup repair.
            self._cleanup_container(row["id"])
            self._cleanup_workspace(row["id"])

    def work_once(self) -> dict[str, Any]:
        """Caller MUST hold the existing exclusive JobStore worker lock."""
        row = self._claim()
        if row is None:
            return {"worker": "IDLE", "processed": 0}
        try:
            result = self._run(row)
        except ExecutionError as exc:
            code = str(exc)
            if code == "Sandbox cleanup not verified":
                # Preserve RUNNING: a later worker must remove the orphan before claiming new work.
                raise
            if code not in {
                "sandbox_output_registration_failed",
                "operator_cancelled", "execution_timeout", "execution_output_limit",
                "sandbox_runtime_unavailable", "sandbox_image_changed",
                "sandbox_output_copy_failed", "sandbox_output_not_permitted",
                "sandbox_output_quota_exceeded", "script_nonzero_exit",
            }:
                code = "sandbox_validation_failed"
            state = "CANCELLED" if code == "operator_cancelled" else "FAILED"
            self._finish(row["id"], state, code)
        except (OSError, CaseError, ValueError, subprocess.SubprocessError):
            self._finish(row["id"], "FAILED", "sandbox_worker_failed")
        else:
            self._finish(row["id"], "SUCCEEDED", None, result)
        return {"worker": "PROCESSED", "processed": 1, "job_id": row["id"],
                "state": self.status(row["id"])["state"]}
