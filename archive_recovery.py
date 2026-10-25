#!/usr/bin/env python3
"""Manual recovery of journaled archive scratch after a worker interruption.

No auto-delete. Caller must inspect a private source-bound SHA-256 plan then
explicitly confirm it. The shared admission lock is acquired BEFORE the case
lock for scan and deletion. Registered case originals are NEVER removed.
Unknown scratch, altered output hashes, or inconsistent lineage fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from capacitywork import admission_lock
from casework import CaseError, CaseStore, CASE_ID, MAX_MANIFEST, _regular_open

WORK_ID = re.compile(r"^[a-f0-9]{32}$")
WORK_DIR = re.compile(r"^expand-([a-f0-9]{32})$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_FILES = 2052
MAX_WORKDIRS = 64
MAX_OLDER_HOURS = 8760
BUFFER = 1024 * 1024


def _directory(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise CaseError("Archive recovery directory is unsafe")
    return info


def _file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o077):
        raise CaseError("Archive recovery file is unsafe")
    return info


def _identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, stat.S_IMODE(info.st_mode),
            info.st_nlink]


def _hash_file(path: Path, limit: int | None = None) -> str:
    before = _file(path)
    if limit is not None and before.st_size > limit:
        raise CaseError("Archive recovery file exceeds allowed size")
    fd, opened = _regular_open(path)
    digest = hashlib.sha256()
    try:
        if _identity(opened) != _identity(before):
            raise CaseError("Archive recovery file changed before reading")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            seen = 0
            while True:
                block = stream.read(BUFFER)
                if not block:
                    break
                seen += len(block)
                if seen > before.st_size:
                    raise CaseError("Archive recovery file grew during reading")
                digest.update(block)
        if seen != before.st_size or _identity(_file(path)) != _identity(before):
            raise CaseError("Archive recovery file changed while hashing")
    finally:
        if fd >= 0:
            os.close(fd)
    return digest.hexdigest()


def _journal(path: Path) -> tuple[dict[str, Any], str]:
    before = _file(path)
    if not 0 < before.st_size <= MAX_MANIFEST:
        raise CaseError("Archive recovery journal size invalid")
    fd, _ = _regular_open(path)
    try:
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_MANIFEST + 1)
        if len(raw) != before.st_size or _identity(_file(path)) != _identity(before):
            raise CaseError("Archive recovery journal changed")
        digest = hashlib.sha256(raw).hexdigest()
        doc = json.loads(raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CaseError("Archive recovery journal cannot be decoded") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if (not isinstance(doc, dict) or
            set(doc) != {"version", "case_id", "source_artifact_id",
                         "source_sha256", "phase", "outputs"} or
            type(doc["version"]) is not int or doc["version"] != 1 or
            doc["phase"] not in ("STAGING", "MOVING") or
            not isinstance(doc["case_id"], str) or
            not CASE_ID.fullmatch(doc["case_id"]) or
            not isinstance(doc["source_artifact_id"], str) or
            not CASE_ID.fullmatch(doc["source_artifact_id"]) or
            not isinstance(doc["source_sha256"], str) or
            not SHA256.fullmatch(doc["source_sha256"]) or
            not isinstance(doc["outputs"], list) or len(doc["outputs"]) > 2048):
        raise CaseError("Archive recovery journal schema invalid")
    if doc["phase"] == "STAGING" and doc["outputs"]:
        raise CaseError("Archive staging journal cannot list completed outputs")
    if doc["phase"] == "MOVING" and not doc["outputs"]:
        raise CaseError("Archive move journal cannot be empty")
    ids: set[str] = set()
    for row in doc["outputs"]:
        if (not isinstance(row, dict) or
                set(row) != {"artifact_id", "sha256", "bytes"} or
                not isinstance(row["artifact_id"], str) or
                not CASE_ID.fullmatch(row["artifact_id"]) or
                not isinstance(row["sha256"], str) or
                not SHA256.fullmatch(row["sha256"]) or
                type(row["bytes"]) is not int or
                not 0 <= row["bytes"] <= 2 * 1024 ** 3 or
                row["artifact_id"] in ids):
            raise CaseError("Archive recovery output ledger invalid")
        ids.add(row["artifact_id"])
    return doc, digest


def _scan(folder: Path, manifest: dict[str, Any],
          case_id: str, work_id: str, older_hours: int,
          now_ns: int) -> tuple[dict[str, Any], list[tuple[str, Path, list[int]]]]:
    if not isinstance(work_id, str) or not WORK_ID.fullmatch(work_id):
        raise CaseError("Invalid archive recovery work identifier")
    if type(older_hours) is not int or not 24 <= older_hours <= MAX_OLDER_HOURS:
        raise CaseError("Recovery age must be 24 to 8760 whole hours")
    scratch = folder / "scratch"
    _directory(scratch)
    workdir = scratch / ("expand-" + work_id)
    winfo = _directory(workdir)
    jpath = workdir / "journal.json"
    jinfo = _file(jpath)
    doc, jhash = _journal(jpath)
    if doc["case_id"] != case_id:
        raise CaseError("Archive recovery journal case mismatch")
    registered = manifest["artifacts"]
    source = registered.get(doc["source_artifact_id"])
    if (not isinstance(source, dict) or
            source.get("sha256") != doc["source_sha256"] or
            source.get("type") not in ("zip", "gzip", "tar")):
        raise CaseError("Archive recovery source identity unavailable")
    entries = list(workdir.iterdir())
    if len(entries) > MAX_FILES:
        raise CaseError("Archive recovery scratch inventory too large")
    outputs = {x["artifact_id"]: x for x in doc["outputs"]}
    referenced = [aid for aid in outputs if aid in registered]
    if referenced and len(referenced) != len(outputs):
        raise CaseError("Partially registered archive requires independent investigation")
    disposition = ("COMMITTED" if referenced else "INTERRUPTED")
    to_remove: list[tuple[str, Path, list[int]]] = []
    observed: list[dict[str, Any]] = []
    seen_staged: set[str] = set()
    last = max(winfo.st_mtime_ns, jinfo.st_mtime_ns)
    for path in sorted(entries):
        if path.name == "journal.json":
            continue
        if CASE_ID.fullmatch(path.name) is None:
            raise CaseError("Archive scratch includes unrecognized entries")
        info = _file(path)
        seen_staged.add(path.name)
        if doc["phase"] == "MOVING":
            row = outputs.get(path.name)
            if row is None or info.st_size != row["bytes"] or _hash_file(path) != row["sha256"]:
                raise CaseError("Archive scratch file does not match move journal")
        if disposition == "COMMITTED":
            raise CaseError("Committed archive has unregistered staged bytes")
        last = max(last, info.st_mtime_ns)
        ident = _identity(info)
        to_remove.append(("scratch", path, ident))
        observed.append({"kind": "scratch", "id": path.name, "identity": ident})
    for aid, row in sorted(outputs.items()):
        target = folder / "originals" / aid
        if aid in seen_staged:
            if target.exists() or target.is_symlink():
                raise CaseError("Archive member exists in two locations")
            continue
        try:
            info = _file(target)
        except FileNotFoundError:
            if disposition == "COMMITTED":
                raise CaseError("Registered archive member is missing")
            continue
        if info.st_size != row["bytes"] or _hash_file(target) != row["sha256"]:
            raise CaseError("Archive case original differs from move journal")
        if disposition == "COMMITTED":
            saved = registered.get(aid)
            if (saved.get("sha256") != row["sha256"] or
                    saved.get("bytes") != row["bytes"] or
                    saved.get("derived_from") != doc["source_artifact_id"]):
                raise CaseError("Archive registered lineage differs from journal")
        elif aid in registered:
            raise CaseError("Refusing cleanup of a registered case original")
        else:
            to_remove.append(("unregistered_original", target, _identity(info)))
        last = max(last, info.st_mtime_ns)
        observed.append({"kind": "original", "id": aid,
                         "identity": _identity(info)})
    if now_ns - last < older_hours * 3600 * 1_000_000_000:
        raise CaseError("Archive recovery transaction is not sufficiently old")
    plan = {
        "case_id": case_id, "work_id": work_id, "source": doc["source_artifact_id"],
        "source_sha256": doc["source_sha256"], "phase": doc["phase"],
        "disposition": disposition, "journal_hash": jhash,
        "journal_identity": _identity(jinfo), "workdir_identity": _identity(winfo),
        "outputs": doc["outputs"], "observed": observed,
        "older_hours": older_hours,
    }
    phash = hashlib.sha256(json.dumps(
        plan, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    result = {
        "status": "PREVIEW_ONLY", "case_id": case_id, "work_id": work_id,
        "disposition": disposition, "scratch_files": len(seen_staged),
        "unregistered_originals": sum(1 for x in to_remove
                                      if x[0] == "unregistered_original"),
        "registered_originals_to_delete": 0,
        "plan_sha256": phash, "requires_explicit_confirmation": True,
    }
    return result, to_remove


def list_workdirs(store: CaseStore, case_id: str) -> dict[str, Any]:
    with store._locked(case_id) as (folder, _):
        scratch = folder / "scratch"
        if not scratch.exists() and not scratch.is_symlink():
            return {"status": "PASS", "case_id": case_id,
                    "work_ids": [], "unrecognized_entries": 0}
        _directory(scratch)
        entries = list(scratch.iterdir())
        if len(entries) > MAX_WORKDIRS:
            raise CaseError("Too many private archive scratch entries")
        ids: list[str] = []
        unknown = 0
        for entry in entries:
            match = WORK_DIR.fullmatch(entry.name)
            if match is None:
                unknown += 1
                continue
            _directory(entry)
            ids.append(match.group(1))
        return {"status": "PARTIAL" if unknown else "PASS",
                "case_id": case_id, "work_ids": sorted(ids),
                "unrecognized_entries": unknown}


def recover(store: CaseStore, case_id: str, work_id: str,
            *, older_hours: int = 24, confirm: bool = False,
            plan_sha256: str | None = None,
            now_ns: int | None = None) -> dict[str, Any]:
    if confirm and (not isinstance(plan_sha256, str)
                    or SHA256.fullmatch(plan_sha256) is None):
        raise CaseError("Explicit recovery requires exact preview SHA-256")
    if not confirm and plan_sha256 is not None:
        raise CaseError("Preview cannot accept a confirmation SHA-256")
    now = time.time_ns() if now_ns is None else now_ns
    if type(now) is not int or now < 0:
        raise CaseError("Invalid archive recovery clock")
    # Exact lock order used by the archive unpacker. A currently active
    # expansion cannot be mistaken for a dead/aged journal.
    with admission_lock(store):
        with store._locked(case_id) as (folder, manifest):
            preview, paths = _scan(folder, manifest, case_id, work_id,
                                   older_hours, now)
            if not confirm:
                return preview
            if preview["plan_sha256"] != plan_sha256:
                raise CaseError("Archive recovery plan changed; inspect again")
            # Work performed here is only for the approved output IDs.
            # A crash partway through removal leaves journal intact and
            # the operator can re-preview the changed inventory.
            for kind, path, saved_identity in paths:
                if _identity(_file(path)) != saved_identity:
                    raise CaseError("Archive recovery file changed during deletion")
                if kind == "unregistered_original" and path.name in manifest["artifacts"]:
                    raise CaseError("Refusing registered original cleanup")
                path.unlink()
            workdir = folder / "scratch" / ("expand-" + work_id)
            journal_path = workdir / "journal.json"
            _file(journal_path)
            journal_path.unlink()
            workdir.rmdir()
            return {
                "status": ("CLEARED_COMMITTED_JOURNAL"
                           if preview["disposition"] == "COMMITTED"
                           else "RECOVERED_INTERRUPTED"),
                "case_id": case_id, "work_id": work_id,
                "removed_scratch_files": preview["scratch_files"],
                "removed_unregistered_originals": preview["unregistered_originals"],
                "removed_registered_originals": 0,
                "plan_sha256": plan_sha256,
            }
