#!/usr/bin/env python3
"""Explicit recovery of source-linked interrupted private SQLite log indexes.

Index construction creates the source-bound journal before opening SQLite.
An operator lists, previews and separately confirms ONE aged journaled index.
No automatic deletion, generic file-path argument, MCP cleanup tool, or
registered case-original deletion is available.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any

from capacitywork import admission_lock
from casework import (CaseError, CaseStore, CASE_ID, MAX_MANIFEST, MAX_CASE_STORAGE,
                      _regular_open)

ID = re.compile(r"^[a-f0-9]{32}$")
JOURNAL_NAME = re.compile(r"^\.tmp-([a-f0-9]{32})\.index\.json$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_AGE_HOURS = 8760
MAX_INVENTORY = 256
CHUNK = 1024 * 1024


def sync_index_directory(indexes: Path) -> None:
    """Durably record index-journal and index-rename directory transitions."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(indexes, flags)
    try:
        opened = os.fstat(fd)
        current = indexes.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid()
                or opened.st_mode & 0o077 or current.st_dev != opened.st_dev
                or current.st_ino != opened.st_ino
                or not stat.S_ISDIR(current.st_mode)):
            raise CaseError("Private index directory durability boundary unsafe")
        os.fsync(fd)
    finally:
        os.close(fd)


def _identity(meta: os.stat_result) -> list[int]:
    return [meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns,
            meta.st_ctime_ns, meta.st_uid, stat.S_IMODE(meta.st_mode), meta.st_nlink]


def _owned_file(path: Path) -> os.stat_result:
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_nlink != 1 or meta.st_mode & 0o077):
        raise CaseError("Index recovery file is not private and regular")
    return meta


def _hashed(path: Path, *, max_bytes: int = MAX_CASE_STORAGE) -> tuple[list[int], str]:
    before = _owned_file(path)
    if before.st_size > max_bytes:
        raise CaseError("Index recovery input exceeds maximum size")
    fd, info = _regular_open(path)
    h = hashlib.sha256()
    try:
        if _identity(info) != _identity(before) or info.st_nlink != 1:
            raise CaseError("Index recovery input changed on open")
        seen = 0
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            while True:
                data = stream.read(CHUNK)
                if not data:
                    break
                seen += len(data)
                if seen > before.st_size:
                    raise CaseError("Index recovery input grew while hashing")
                h.update(data)
        if seen != before.st_size or _identity(_owned_file(path)) != _identity(before):
            raise CaseError("Index recovery input changed while hashing")
    finally:
        if fd >= 0:
            os.close(fd)
    return _identity(before), h.hexdigest()


def _journal(path: Path) -> tuple[dict[str, Any], list[int], str]:
    identity, digest = _hashed(path, max_bytes=1024)
    if not 0 < identity[2] <= 1024:
        raise CaseError("Private index journal length invalid")
    fd, info = _regular_open(path)
    try:
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(1025)
        if len(raw) != identity[2] or _identity(_owned_file(path)) != identity:
            raise CaseError("Index journal changed while reading")
        obj = json.loads(raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CaseError("Private index journal invalid") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if (not isinstance(obj, dict) or
            set(obj) != {"version", "case_id", "artifact_id", "source_sha256", "temp_name"} or
            type(obj["version"]) is not int or obj["version"] != 1 or
            not isinstance(obj["case_id"], str) or not CASE_ID.fullmatch(obj["case_id"]) or
            not isinstance(obj["artifact_id"], str) or not CASE_ID.fullmatch(obj["artifact_id"]) or
            not isinstance(obj["source_sha256"], str) or not SHA256.fullmatch(obj["source_sha256"]) or
            not isinstance(obj["temp_name"], str)):
        raise CaseError("Private index journal schema invalid")
    return obj, identity, digest


def list_interrupted(store: CaseStore, case_id: str) -> dict[str, Any]:
    with store._locked(case_id) as (folder, _):
        entries = list((folder / "indexes").iterdir())
        if len(entries) > MAX_INVENTORY:
            raise CaseError("Index recovery inventory too large")
        ids: list[str] = []
        unmatched = 0
        for entry in entries:
            match = JOURNAL_NAME.fullmatch(entry.name)
            if match is not None:
                _owned_file(entry)
                ids.append(match.group(1))
            elif entry.name.startswith(".tmp-"):
                unmatched += 1
        return {"status": "PARTIAL" if unmatched else "PASS", "case_id": case_id,
                "index_work_ids": sorted(ids), "unmatched_temp_entries": unmatched}


def _scan(folder: Path, manifest: dict[str, Any], case_id: str, work_id: str,
          older_hours: int, now_ns: int) -> tuple[dict[str, Any], list[tuple[Path, list[int]]]]:
    if not isinstance(work_id, str) or ID.fullmatch(work_id) is None:
        raise CaseError("Invalid index work identifier")
    if type(older_hours) is not int or not 24 <= older_hours <= MAX_AGE_HOURS:
        raise CaseError("Index recovery age must be 24 through 8760 whole hours")
    indexes = folder / "indexes"
    journal = indexes / (".tmp-" + work_id + ".index.json")
    temp = indexes / (".tmp-" + work_id + ".sqlite3")
    final_prefix = ".tmp-" + work_id
    obj, journal_identity, journal_hash = _journal(journal)
    if (obj["case_id"] != case_id or
            obj["temp_name"] != temp.name):
        raise CaseError("Private index journal identity mismatch")
    item = manifest["artifacts"].get(obj["artifact_id"])
    if (not isinstance(item, dict) or item.get("sha256") != obj["source_sha256"]
            or item.get("type") != "text"):
        raise CaseError("Index recovery has no matching original source")
    # No unrelated .tmp files are implicitly swept. For this ONE journal, all
    # associated SQLite names must be exact and known.
    entries = list(indexes.iterdir())
    if len(entries) > MAX_INVENTORY:
        raise CaseError("Index recovery inventory too large")
    allowed = {journal.name, temp.name, temp.name + "-journal"}
    for entry in entries:
        if entry.name.startswith(final_prefix) and entry.name not in allowed:
            raise CaseError("Unrecognized index recovery sidecar")
    final = indexes / (obj["artifact_id"] + ".sqlite3")
    temp_present = temp.exists() or temp.is_symlink()
    final_present = final.exists() or final.is_symlink()
    if temp_present and final_present:
        raise CaseError("Index recovery has both unpublished and published databases")
    disposition = "COMMITTED" if final_present else "INTERRUPTED"
    observations = [{"name": journal.name, "identity": journal_identity,
                     "sha256": journal_hash}]
    remove: list[tuple[Path, list[int]]] = []
    last_ns = journal_identity[3]
    if temp_present:
        meta, digest = _hashed(temp)
        remove.append((temp, meta))
        observations.append({"name": temp.name, "identity": meta, "sha256": digest})
        last_ns = max(last_ns, meta[3])
    sidecar = indexes / (temp.name + "-journal")
    if sidecar.exists() or sidecar.is_symlink():
        if not temp_present:
            raise CaseError("Orphan SQLite journal needs independent investigation")
        meta, digest = _hashed(sidecar)
        remove.append((sidecar, meta))
        observations.append({"name": sidecar.name, "identity": meta,
                             "sha256": digest})
        last_ns = max(last_ns, meta[3])
    if final_present:
        metadata = _owned_file(final)
        if metadata.st_size > MAX_CASE_STORAGE:
            raise CaseError("Committed SQLite index is too large")
        # A journal that survived a post-rename fsync failure may be retired,
        # but NEVER by deleting or rewriting the published index itself.
        try:
            db = sqlite3.connect("file:" + str(final) + "?mode=ro", uri=True)
            try:
                facts = dict(db.execute("SELECT name,value FROM facts"))
            finally:
                db.close()
        except (sqlite3.Error, ValueError) as exc:
            raise CaseError("Committed index identity cannot be verified") from exc
        if facts.get("artifact_sha256") != obj["source_sha256"]:
            raise CaseError("Committed SQLite index belongs to another source")
        observations.append({"name": final.name, "identity": _identity(metadata),
                             "source_sha256": facts["artifact_sha256"]})
        last_ns = max(last_ns, metadata.st_mtime_ns)
    if now_ns - last_ns < older_hours * 3600 * 1_000_000_000:
        raise CaseError("Index recovery transaction is too recent")
    statement = {
        "case_id": case_id, "work_id": work_id,
        "source_artifact_id": obj["artifact_id"],
        "source_sha256": obj["source_sha256"],
        "disposition": disposition,
        "observed_files": observations,
        "scratch_bytes": sum(x["identity"][2] for x in observations
                             if x["name"] in (temp.name, sidecar.name)),
    }
    plan_sha = hashlib.sha256(json.dumps(statement, sort_keys=True,
                                        separators=(",", ":")).encode("ascii")).hexdigest()
    return {"status": "PREVIEW_ONLY", **statement, "plan_sha256": plan_sha,
            "requires_explicit_confirmation": True,
            "registered_originals_removed": 0, "committed_indexes_removed": 0}, remove


def recover(store: CaseStore, case_id: str, work_id: str, *,
            older_hours: int = 24, confirm: bool = False,
            plan_sha256: str | None = None, now_ns: int | None = None) -> dict[str, Any]:
    if confirm and (not isinstance(plan_sha256, str)
                    or SHA256.fullmatch(plan_sha256) is None):
        raise CaseError("Index cleanup requires a preview SHA-256")
    if not confirm and plan_sha256 is not None:
        raise CaseError("Index cleanup preview cannot accept confirmation hash")
    now_ns = time.time_ns() if now_ns is None else now_ns
    if type(now_ns) is not int or now_ns < 0:
        raise CaseError("Index recovery clock invalid")
    with admission_lock(store):
        with store._locked(case_id) as (folder, manifest):
            plan, targets = _scan(folder, manifest, case_id, work_id,
                                  older_hours, now_ns)
            if not confirm:
                return plan
            if plan["plan_sha256"] != plan_sha256:
                raise CaseError("Index recovery plan changed; inspect again")
            # Delete SQLite rollback sidecars BEFORE the database. If the
            # operator process is SIGKILLed midway, a subsequent preview can
            # still safely inspect the remaining main file and its journal.
            for path, ident in sorted(
                    targets, key=lambda row: row[0].name.endswith("-journal"),
                    reverse=True):
                if _identity(_owned_file(path)) != ident:
                    raise CaseError("Index recovery file changed after approval")
                path.unlink()
            sync_index_directory(folder / "indexes")
            journal = folder / "indexes" / (".tmp-" + work_id + ".index.json")
            _owned_file(journal)
            journal.unlink()
            sync_index_directory(folder / "indexes")
            return {"status": ("COMMITTED_JOURNAL_CLEARED"
                               if plan["disposition"] == "COMMITTED"
                               else "INTERRUPTED_TEMP_CLEARED"),
                    "case_id": case_id, "work_id": work_id,
                    "removed_unpublished_files": len(targets),
                    "reclaimed_bytes": plan["scratch_bytes"],
                    "registered_originals_removed": 0,
                    "committed_indexes_removed": 0,
                    "plan_sha256": plan_sha256}
