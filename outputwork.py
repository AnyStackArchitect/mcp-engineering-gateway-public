#!/usr/bin/env python3
"""Register bounded, already-copied sandbox outputs as durable case evidence.

The container never gets a writable host case/inbox mount. Only the worker,
after the container has generated and copied its isolated tmpfs outputs, can
perform this private registration. Raw output remains private; the broker
returns bounded hashes and opaque artifact IDs only.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from casework import CaseStore, CaseError, _write_json_atomic, CASE_ID
from capacitywork import admission_lock,verify_committed_reserve


class OutputError(Exception):
    """Unsafe, changed, or incomplete derived evidence."""


def _inspect(output: Path, allow: set[str], limit: int) -> list[tuple[Path, int, str]]:
    info = output.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OutputError("Output staging directory is not private")
    entries = list(output.iterdir())
    if len(entries) > len(allow):
        raise OutputError("Unapproved output count")
    used = 0
    seen: set[str] = set()
    records: list[tuple[Path, int, str]] = []
    for path in sorted(entries):
        if path.name not in allow or path.name in seen:
            raise OutputError("Output filename not approved")
        seen.add(path.name)
        if path.is_symlink():
            raise OutputError("Output symlinks forbidden")
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_nlink != 1 or meta.st_size > limit - used):
            raise OutputError("Output file is unsafe or exceeds quota")
        used += meta.st_size
        # Podman cp may preserve a 0644 file mode from the isolated tmpfs.
        # Parent is worker-private; normalize after verifying type/owner.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_ino != meta.st_ino or opened.st_dev != meta.st_dev
                    or opened.st_size != meta.st_size
                    or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
                raise OutputError("Output identity changed")
            os.fchmod(descriptor, 0o600)
            digest = hashlib.sha256()
            read = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                read += len(block)
                if read > meta.st_size:
                    raise OutputError("Output length changed")
                digest.update(block)
            after = os.fstat(descriptor)
            if (read != meta.st_size or after.st_size != meta.st_size
                    or after.st_mtime_ns != meta.st_mtime_ns):
                raise OutputError("Output changed while hashing")
            records.append((path, meta.st_size, digest.hexdigest()))
        finally:
            os.close(descriptor)
    return records


def _stage_output(cases: CaseStore,item: Path,staged: Path,length: int,expected: str) -> None:
    with admission_lock(cases):
        verify_committed_reserve(cases,extra_bytes=length+65536)
        descriptor=os.open(staged,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        digest=hashlib.sha256();total=0
        with os.fdopen(descriptor,'wb') as target,item.open('rb') as original:
            while True:
                block=original.read(1024*1024)
                if not block:break
                total+=len(block)
                if total>length:raise OutputError('Output changed during private staging')
                digest.update(block);target.write(block)
            target.flush();os.fsync(target.fileno())
        if total!=length or digest.hexdigest()!=expected:
            raise OutputError('Copied output differs from validated output')


def register_outputs(cases: CaseStore, case_id: str, execution_id: str,
                     plan_sha256: str, expected_inputs: list[dict[str, Any]],
                     output: Path, names: list[str], disk_mib: int) -> list[dict[str, Any]]:
    """Register all outputs or roll back *new* originals if any output fails."""
    allowed = set(names)
    if len(allowed) != len(names):
        raise OutputError("Duplicate output allowlist")
    records = _inspect(output, allowed, disk_mib * 1024 * 1024)
    registered: list[dict[str, Any]] = []
    tmpfiles: list[Path] = []
    try:
        for item, length, expected in records:
            staged = cases.inbox / ("derived-" + secrets.token_hex(12))
            tmpfiles.append(staged)
            _stage_output(cases,item,staged,length,expected)
            result = cases.register(
                case_id, staged.name, worker=True, derived_execution_id=execution_id)
            if result["sha256"] != expected or result["bytes"] != length:
                raise OutputError("Registered output differs from validated output")
            registered.append({"name": item.name, "artifact_id": result["artifact_id"],
                               "sha256": expected, "bytes": length})
        with cases._locked(case_id) as (folder, manifest):
            if execution_id in manifest.get("execution_derivatives", {}):
                raise OutputError("Execution derivatives already recorded")
            manifest.setdefault("execution_derivatives", {})[execution_id] = {
                "plan_sha256": plan_sha256,
                "input_artifacts": [
                    {"artifact_id": item["artifact_id"], "sha256": item["sha256"]}
                    for item in expected_inputs
                ],
                "outputs": registered,
            }
            _write_json_atomic(folder / "manifest.json", manifest)
        return registered
    except BaseException:
        # All originals here are freshly allocated by this function; never
        # delete another job's evidence or a previously referenced artifact.
        if registered:
            with cases._locked(case_id) as (folder, manifest):
                for record in registered:
                    manifest["artifacts"].pop(record["artifact_id"], None)
                _write_json_atomic(folder / "manifest.json", manifest)
                for record in registered:
                    (folder / "originals" / record["artifact_id"]).unlink(missing_ok=True)
        raise
    finally:
        for staged in tmpfiles:
            staged.unlink(missing_ok=True)


def recover_interrupted_outputs(cases: CaseStore, case_id: str,
                                execution_id: str) -> dict[str, int]:
    """Finish idempotent recovery of incomplete execution-derived originals.

    Requires the caller to have verified the orphan container is gone and to
    own the exclusive worker process lock. This executes under the case lock;
    only tagged artifacts from this interrupted execution may be unregistered.
    Two-phase cleanup markers allow SIGKILL during this cleanup to resume.
    """
    if not isinstance(execution_id, str) or not CASE_ID.fullmatch(execution_id):
        raise OutputError("Invalid recovery execution identifier")
    removed = 0
    unregistered = 0
    with cases._locked(case_id) as (folder, manifest):
        artifacts = manifest["artifacts"]
        markers = manifest.setdefault("execution_derivatives_cleanup", {})
        if not isinstance(markers, dict):
            raise OutputError("Derived cleanup ledger corrupt")
        if execution_id in markers:
            ids = markers[execution_id]
            if (not isinstance(ids, list) or len(ids) > 4096
                    or any(not isinstance(a, str) or not CASE_ID.fullmatch(a) for a in ids)
                    or len(ids) != len(set(ids))):
                raise OutputError("Derived cleanup marker corrupt")
        else:
            ids = [aid for aid, meta in artifacts.items()
                   if isinstance(meta, dict)
                   and meta.get("derived_execution_id") == execution_id]
            if len(ids) > 4096:
                raise OutputError("Too many pending derived artifacts")
            # A crash can occur after a completed case manifest commit but
            # before the job result transitions from RUNNING to SUCCEEDED.
            # That RUNNING job must not leave apparently successful outputs.
            markers[execution_id] = ids
            for aid in ids:
                artifacts.pop(aid)
            manifest.get("execution_derivatives", {}).pop(execution_id, None)
            _write_json_atomic(folder / "manifest.json", manifest)
        originals = folder / "originals"
        for aid in ids:
            path = originals / aid
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # The same cleanup can be retried after SIGKILL.
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise OutputError("Interrupted derived output cannot be safely removed")
            path.unlink()
            removed += 1

        # If the worker died after os.replace() but before the registration
        # manifest update, an original can be disk-resident yet unregistered.
        # The case lock prevents sweeping an in-flight normal registration.
        entries = list(originals.iterdir())
        if len(entries) > 4096:
            raise OutputError("Originals inventory too large for recovery")
        for path in entries:
            if path.name in artifacts:
                continue
            if not (CASE_ID.fullmatch(path.name)
                    or (path.name.startswith(".tmp-")
                        and CASE_ID.fullmatch(path.name[5:]))):
                raise OutputError("Unexpected unregistered originals entry")
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise OutputError("Unregistered original cannot be safely removed")
            path.unlink()
            unregistered += 1
        markers.pop(execution_id, None)
        if not markers:
            manifest.pop("execution_derivatives_cleanup", None)
        _write_json_atomic(folder / "manifest.json", manifest)
    return {"tagged_removed": removed, "orphan_originals_removed": unregistered}
