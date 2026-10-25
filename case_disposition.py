"""Operator-only, dual-signed retirement, recovery and final case-file deletion.

Retirement is one same-filesystem directory rename. Final deletion is a separate
freshly signed operation with durable per-file intent; it never recurses, follows
links, erases metadata, releases holds, exports bytes or claims secure erasure.
Production is disabled unless a fixed root-owned policy and two keys are enrolled.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import time

from capacitywork import admission_lock, outstanding_reservations, verify_committed_reserve
from casework import (CASE_ID, CaseError, CaseStore, MAX_MANIFEST, MAX_CASE_STORAGE,
                      _private_directory, _read_json_private, _regular_open)
from case_handoff import (_snapshot, _canonical, _identity, _private_optional,
                          _sync_directory)
from preservationwork import _load_locked
from retentionwork import _handoff_inventory
import disposition_grants as grants

OUT_DIR = "case-dispositions"
MAX_INVENTORY = 8 * 1024 * 1024
MAX_FILES = 4608
MAX_EVENTS = 12000
MAX_TRANSACTIONS = 1024
ZERO = "0" * 64
EVENT_NAME = re.compile(r"[0-9]{6}[.]json\Z")
INIT_NAME = re.compile(r"[.]init-([a-f0-9]{32})-[a-f0-9]{16}\Z")
SAFE_INDEX = re.compile(r"(?:[a-f0-9]{32}[.]sqlite3|evtx-[a-f0-9]{32}[.]sqlite3|"
                        r"protocol-[a-f0-9]{32}[.]json|timeline[.]sqlite3|correlation[.]sqlite3|"
                        r"recipe-(?:vmware|veeam|hyperv|nutanix)[.]json)\Z")


def _checkpoint(name: str) -> None:
    """Named durability seam for synthetic fault injection, never a CLI flag."""


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _entries(folder: Path, limit: int) -> list[Path]:
    result = []
    with os.scandir(folder) as scan:
        for entry in scan:
            if len(result) >= limit:
                raise CaseError("Disposition directory inventory exceeds bound")
            result.append(folder / entry.name)
    return sorted(result)


def _dir_identity(folder: Path) -> list[int]:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise CaseError("Disposition directory identity unsafe")
    return [info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)]


def _file_record(path: Path, relative: str, *, expected: dict | None = None,
                 link_count: int = 1, maximum: int = MAX_CASE_STORAGE) -> dict:
    fd, before = _regular_open(path)
    if before.st_nlink != link_count or before.st_size > maximum:
        os.close(fd)
        raise CaseError("Disposition evidence identity unsafe")
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            count += len(block)
            if count > before.st_size:
                raise CaseError("Disposition evidence grew during verification")
            digest.update(block)
        if (_identity(before) != _identity(os.fstat(fd))
                or _identity(before) != _identity(path.lstat()) or count != before.st_size):
            raise CaseError("Disposition evidence changed during verification")
    finally:
        os.close(fd)
    result = {"path": relative, "bytes": count, "sha256": digest.hexdigest(),
              "identity": list(_identity(before))}
    if expected is not None and result != expected:
        raise CaseError("Disposition inventory changed")
    return result


class _LockedView:
    """Reuse existing snapshot validation while already holding the case lock."""
    def __init__(self, store, folder, manifest):
        self.base, self.inbox = store.base, store.inbox
        self.folder, self.manifest = folder, manifest

    @contextmanager
    def _locked(self, case_id):
        if case_id != self.manifest["id"]:
            raise CaseError("Disposition case mismatch")
        yield self.folder, self.manifest


@contextmanager
def _case_lock(store: CaseStore, folder: Path, case_id: str):
    before = _dir_identity(folder)
    fd = os.open(folder / ".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise CaseError("Disposition case lock unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if before != _dir_identity(folder):
            raise CaseError("Disposition case moved while waiting for lock")
        current = (folder / ".lock").lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise CaseError("Disposition lock path changed")
        manifest = _read_json_private(folder / "manifest.json")
        if manifest.get("id") != case_id:
            raise CaseError("Disposition manifest case mismatch")
        yield manifest
    finally:
        os.close(fd)


def _root(store: CaseStore) -> Path:
    location = store.base / OUT_DIR
    _private_optional(location, "Disposition")
    return location


def _reserve_transaction_slot(store: CaseStore) -> None:
    """Admission lock held: reserve space for one staging/new-cycle entry.

Existing case recovery uses its exact path and remains accessible even if an
older interrupted implementation or an external writer filled the root.
"""
    root = _root(store)
    if root.exists() and len(_entries(root, MAX_TRANSACTIONS)) >= MAX_TRANSACTIONS:
        raise CaseError("Disposition transaction capacity exhausted; recover existing work first")


def _location(store: CaseStore, case_id: str):
    root = _root(store)
    transaction = root / case_id
    present = _private_optional(transaction, "Disposition transaction") if root.exists() else False
    active = store.cases / case_id
    active_exists = _private_optional(active, "Active case")
    retired = transaction / "quarantine"
    retired_exists = _private_optional(retired, "Quarantined case") if present else False
    if active_exists == retired_exists:
        raise CaseError("Disposition case location is missing or ambiguous")
    return transaction, active if active_exists else retired, retired_exists


def _history(transaction: Path) -> dict:
    if not transaction.exists():
        return {"events": [], "head": ZERO, "pending": None, "used": set(),
                "intents": set(), "done": set(), "terminal": None}
    if set(p.name for p in _entries(transaction, 4)) - {"inventory.json", "events", "quarantine"}:
        raise CaseError("Unknown disposition transaction entry")
    events = transaction / "events"
    if not _private_optional(events, "Disposition events"):
        raise CaseError("Disposition event directory missing")
    paths = _entries(events, MAX_EVENTS + 1)
    pending = None
    linked_final = None
    if (events / ".pending").exists() or (events / ".pending").is_symlink():
        info = (events / ".pending").lstat()
        if info.st_nlink == 2:
            matches = [p for p in paths if EVENT_NAME.fullmatch(p.name)
                       and (p.lstat().st_dev, p.lstat().st_ino) == (info.st_dev, info.st_ino)]
            if len(matches) != 1:
                raise CaseError("Disposition pending hardlink does not identify one journal record")
            linked_final = matches[0]
        elif info.st_nlink != 1:
            raise CaseError("Disposition pending journal links unsafe")
        pending = _file_record(events / ".pending", ".pending", link_count=info.st_nlink,
                               maximum=grants.MAX_BYTES)
        paths = [p for p in paths if p.name != ".pending"]
    if len(paths) > MAX_EVENTS or any(not EVENT_NAME.fullmatch(p.name) for p in paths):
        raise CaseError("Disposition journal inventory invalid")
    head, records, used, intents, done, terminal = ZERO, [], set(), set(), set(), None
    for sequence, path in enumerate(paths, 1):
        if path.name != f"{sequence:06d}.json":
            raise CaseError("Disposition journal sequence gap")
        record = grants.decode(grants.private_read(path, grants.MAX_BYTES,
                               link_count=2 if path == linked_final else 1))
        if (set(record) != {"schema", "sequence", "previous", "kind", "detail", "at"}
                or type(record["schema"]) is not int or record["schema"] != 1
                or type(record["sequence"]) is not int or record["sequence"] != sequence
                or record["previous"] != head or type(record["at"]) is not int
                or record["kind"] not in ("AUTHORIZE", "RETIRED", "RESTORED", "PURGE_INTENT", "PURGE_DONE", "DELETED")
                or not isinstance(record["detail"], dict)):
            raise CaseError("Disposition journal record invalid")
        kind, detail = record["kind"], record["detail"]
        if terminal in ("RESTORED", "DELETED"):
            raise CaseError("Disposition records after terminal receipt")
        if kind == "AUTHORIZE":
            if set(detail) != {"signed_grants"}:
                raise CaseError("Disposition authorization journal invalid")
            payloads, _ = grants.verify_grants(_canonical(detail["signed_grants"]), check_time=False)
            for payload in payloads:
                if payload["nonce"] in used:
                    raise CaseError("Replayed disposition nonce in journal")
                used.add(payload["nonce"])
        elif kind in ("PURGE_INTENT", "PURGE_DONE"):
            index = detail.get("file_index")
            if set(detail) != {"file_index"} or type(index) is not int or not 0 <= index < MAX_FILES:
                raise CaseError("Disposition progress identity invalid")
            if kind == "PURGE_INTENT":
                if index in intents:
                    raise CaseError("Duplicate disposition deletion intent")
                intents.add(index)
            else:
                if index not in intents or index in done:
                    raise CaseError("Disposition completion lacks unique intent")
                done.add(index)
        else:
            if detail:
                raise CaseError("Disposition receipt schema invalid")
            terminal = kind
        records.append(record)
        head = _digest(record)
    return {"events": records, "head": head, "pending": pending, "used": used,
            "intents": intents, "done": done, "terminal": terminal}


def _append(transaction: Path, history: dict, kind: str, detail: dict) -> None:
    directory = transaction / "events"
    pending = directory / ".pending"
    if history["pending"] is not None:
        _file_record(pending, ".pending", expected=history["pending"],
                     link_count=history["pending"]["identity"][4], maximum=grants.MAX_BYTES)
        pending.unlink()
        _sync_directory(directory)
        history["pending"] = None
    seq = len(history["events"]) + 1
    if seq > MAX_EVENTS:
        raise CaseError("Disposition journal capacity exhausted")
    record = {"schema": 1, "sequence": seq, "previous": history["head"],
              "kind": kind, "detail": detail, "at": int(time.time())}
    raw = _canonical(record)
    if len(raw) > grants.MAX_BYTES:
        raise CaseError("Disposition record exceeds bound")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    final = directory / f"{seq:06d}.json"
    os.link(pending, final, follow_symlinks=False)
    _sync_directory(directory)
    _checkpoint("AFTER_JOURNAL_LINK")
    pending.unlink()
    _sync_directory(directory)
    if grants.private_read(final) != raw:
        raise CaseError("Disposition journal readback mismatch")
    history["events"].append(record)
    history["head"] = _digest(record)
    if kind == "PURGE_INTENT":
        history["intents"].add(detail["file_index"])
    if kind == "PURGE_DONE":
        history["done"].add(detail["file_index"])
    if kind in ("RETIRED", "RESTORED", "DELETED"):
        history["terminal"] = kind


def _closed_cycles(store: CaseStore, case_id: str) -> tuple[list[str], set[str]]:
    """Keep consumed grants bound across every archive/new-cycle crash gap.

The unchanged restored case may produce the same source snapshot again. Its
earlier grants must remain consumed even before a new inventory is published.
"""
    root = _root(store)
    heads, used = [], set()
    if not root.exists():
        return heads, used
    prefix = "restored-" + case_id + "-"
    for candidate in _entries(root, MAX_TRANSACTIONS + 1):
        if not candidate.name.startswith(prefix):
            continue
        suffix = candidate.name[len(prefix):]
        if not grants.HEX64.fullmatch(suffix) or not _private_optional(candidate, "Closed disposition cycle"):
            raise CaseError("Disposition closed-cycle identity invalid")
        previous = _history(candidate)
        if (previous["terminal"] != "RESTORED" or previous["head"] != suffix
                or (candidate / "quarantine").exists() or (candidate / "quarantine").is_symlink()
                or used & previous["used"]):
            raise CaseError("Disposition closed-cycle history invalid or replayed")
        for event in previous["events"]:
            if event["kind"] == "AUTHORIZE":
                envelopes = event["detail"]["signed_grants"]["grants"]
                if any(g["payload"]["plan"]["case_id"] != case_id for g in envelopes):
                    raise CaseError("Disposition closed-cycle authorization case mismatch")
        heads.append(previous["head"])
        used.update(previous["used"])
    return sorted(heads), used


def _inventory(store: CaseStore, folder: Path, manifest: dict) -> dict:
    if set(p.name for p in _entries(folder, 7)) - {".lock", "manifest.json", "originals", "indexes", "scratch", "preservation"}:
        raise CaseError("Disposition blocked by unknown case directory content")
    # Bound children before legacy snapshot validation materializes its lists.
    # Admission/case locks exclude cooperative writers during both inspections.
    for name in ("originals", "indexes", "scratch", "preservation"):
        location = folder / name
        if _private_optional(location, "Disposition case child"):
            _entries(location, MAX_FILES)
    snapshot = _snapshot(_LockedView(store, folder, manifest), manifest["id"])
    controls = _load_locked(folder, manifest["id"])
    if controls["active_hold_count"]:
        raise CaseError("Active preservation hold blocks disposition; no override exists")
    files, retained, dirs = [], [], {}
    for name in ("originals", "indexes", "scratch", "preservation"):
        location = folder / name
        if not _private_optional(location, "Disposition case child"):
            continue
        dirs[name] = _dir_identity(location)
        children = _entries(location, MAX_FILES)
        if len(children) > MAX_FILES or (name == "scratch" and children):
            raise CaseError("Disposition blocked by unsafe or unfinished case work")
        for path in children:
            if name == "indexes" and not SAFE_INDEX.fullmatch(path.name):
                raise CaseError("Disposition blocked by unknown or unfinished index")
            target = retained if name == "preservation" else files
            target.append(_file_record(path, name + "/" + path.name))
    retained.append(_file_record(folder / "manifest.json", "manifest.json"))
    if len(files) + len(retained) > MAX_FILES:
        raise CaseError("Disposition inventory too large")
    return {"schema": 1, "case_id": manifest["id"], "snapshot": snapshot,
            "files": files, "retained": retained, "directories": dirs,
            "case_directory_identity": _dir_identity(folder),
            "preservation_head": controls["head_sha256"],
            "minimum_retention_days": controls["minimum_retention_days"] or 0}


def _stored_inventory(transaction: Path) -> dict:
    data = grants.decode(grants.private_read(transaction / "inventory.json", MAX_INVENTORY), MAX_INVENTORY)
    if (set(data) != {"schema", "case_id", "snapshot", "files", "retained", "directories",
                      "case_directory_identity", "preservation_head", "minimum_retention_days"}
            or data.get("schema") != 1 or not isinstance(data["files"], list)
            or not isinstance(data["retained"], list) or not isinstance(data["directories"], dict)
            or not 0 < len(data["files"]) <= MAX_FILES):
        raise CaseError("Disposition saved inventory invalid")
    for record in data["files"] + data["retained"]:
        if (not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256", "identity"}
                or not isinstance(record["path"], str)
                or record["path"].startswith("/") or ".." in record["path"].split("/")
                or "\\" in record["path"] or len(record["path"].split("/")) > 2
                or type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_CASE_STORAGE
                or not isinstance(record["sha256"], str) or not grants.HEX64.fullmatch(record["sha256"])
                or not isinstance(record["identity"], list) or len(record["identity"]) != 8
                or any(type(v) is not int for v in record["identity"])):
            raise CaseError("Disposition saved file record invalid")
    return data


def _verify_remaining(folder: Path, manifest: dict, saved: dict, history: dict) -> list[int]:
    if _dir_identity(folder) != saved["case_directory_identity"]:
        raise CaseError("Disposition quarantine directory changed")
    controls = _load_locked(folder, saved["case_id"])
    if controls["active_hold_count"]:
        raise CaseError("Active preservation hold blocks disposition")
    if (controls["head_sha256"] != saved["preservation_head"]
            or (controls["minimum_retention_days"] or 0) != saved["minimum_retention_days"]):
        raise CaseError("Disposition preservation policy changed")
    allowed_top = {".lock", "manifest.json", *saved["directories"]}
    if set(p.name for p in _entries(folder, 7)) != allowed_top:
        raise CaseError("Disposition quarantine contains unexpected paths")
    for name, identity in saved["directories"].items():
        if name not in ("originals", "indexes", "scratch", "preservation") or _dir_identity(folder / name) != identity:
            raise CaseError("Disposition quarantine child changed")
    for record in saved["retained"]:
        _file_record(folder / record["path"], record["path"], expected=record)
    remaining, actual_names = [], set()
    for name in saved["directories"]:
        actual_names.update(name + "/" + p.name for p in _entries(folder / name, MAX_FILES))
    expected_names = {r["path"] for r in saved["retained"] if "/" in r["path"]}
    for index, record in enumerate(saved["files"]):
        relative = record["path"]
        # Only exact originals/index names from the immutable inventory may be erased.
        parts = relative.split("/")
        if len(parts) != 2 or parts[0] not in ("originals", "indexes"):
            raise CaseError("Disposition saved erase path invalid")
        if parts[0] == "originals" and not CASE_ID.fullmatch(parts[1]):
            raise CaseError("Disposition saved original identifier invalid")
        if parts[0] == "indexes" and not SAFE_INDEX.fullmatch(parts[1]):
            raise CaseError("Disposition saved index identifier invalid")
        path = folder / relative
        if path.exists() or path.is_symlink():
            if index in history["done"]:
                raise CaseError("Previously deleted evidence reappeared")
            _file_record(path, relative, expected=record)
            expected_names.add(relative)
            remaining.append(index)
        elif index not in history["intents"]:
            raise CaseError("Evidence missing without durable deletion intent")
    if actual_names != expected_names:
        raise CaseError("Disposition quarantine file inventory mismatch")
    return remaining


def _retention(inventory: dict, minimum: int, start: str) -> None:
    if type(minimum) is not int or not 1 <= minimum <= 3650:
        raise CaseError("Disposition minimum age invalid")
    if not isinstance(start, str) or len(start) != 20:
        raise CaseError("Disposition retention start requires exact UTC timestamp")
    try:
        source_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        created = datetime.fromisoformat(inventory["snapshot"]["created_at"])
        if created.tzinfo is None:
            raise ValueError("timezone")
    except (ValueError, TypeError, KeyError) as exc:
        raise CaseError("Disposition retention clock invalid") from exc
    floor = max(minimum, inventory["minimum_retention_days"])
    if datetime.now(timezone.utc) - max(source_start, created) < timedelta(days=floor):
        raise CaseError("Disposition minimum age or preservation floor unmet")


def _context(store, case_id, action, minimum, start, transaction, folder, retired, manifest):
    if action not in ("RETIRE", "RESTORE", "FINAL_DELETE"):
        raise CaseError("Disposition action invalid")
    history = _history(transaction)
    closed_heads, closed_nonces = _closed_cycles(store, case_id)
    if history["used"] & closed_nonces:
        raise CaseError("Disposition grant nonce replayed across cycles")
    history["used"].update(closed_nonces)
    new_cycle = history["terminal"] == "RESTORED" and action == "RETIRE" and not retired
    if history["terminal"] == "DELETED" or (history["terminal"] == "RESTORED" and not new_cycle):
        raise CaseError("Disposition transaction already completed")
    if action == "RETIRE" and retired and history["terminal"] == "RETIRED":
        raise CaseError("Case already retired; use restore or separately approved final deletion")
    if action == "FINAL_DELETE" and not retired:
        raise CaseError("Final deletion requires a retired case")
    if action == "RESTORE" and not transaction.exists():
        raise CaseError("No retired or interrupted transaction to restore")
    # No intake session, including a fully uploaded but unfinalized session,
    # may remain while a case's evidence lifecycle changes.
    outstanding_reservations(store)
    if any(p.name.endswith(".session") for p in _entries(store.inbox, 4096)):
        raise CaseError("Disposition blocked by unfinished global intake")
    _, active, unknown = _handoff_inventory(store, case_id)
    if active or unknown:
        raise CaseError("Disposition blocked by unresolved private handoff")
    from redacted_export import _private_inventory
    _private_inventory(store)
    if transaction.exists() and not new_cycle:
        inventory = _stored_inventory(transaction)
        if inventory["case_id"] != case_id:
            raise CaseError("Disposition saved case mismatch")
        remaining = _verify_remaining(folder, manifest, inventory, history)
    else:
        inventory = _inventory(store, folder, manifest)
        remaining = list(range(len(inventory["files"])))
    if action == "RESTORE" and history["intents"]:
        raise CaseError("Partially deleted case requires independent backup recovery, not local restore")
    _retention(inventory, minimum, start)
    state = {"inventory": inventory, "remaining": remaining, "retired": retired}
    plan = {"schema": 1, "action": action, "case_id": case_id,
            "state_sha256": _digest(state),
            "history_sha256": _digest({"head": history["head"], "pending": history["pending"],
                                       "closed_cycle_heads": closed_heads}),
            "minimum_age_days": minimum, "retention_start_utc": start,
            "original_count": inventory["snapshot"]["artifact_count"],
            "original_bytes": inventory["snapshot"]["original_bytes_verified"],
            "remaining_evidence_files": len(remaining)}
    grants.validate_plan(plan)
    return plan, inventory, history, remaining


def preview(store: CaseStore, case_id: str, *, action: str,
            minimum_age_days: int, retention_start_utc: str) -> dict:
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise CaseError("Disposition case identifier invalid")
    with admission_lock(store):
        transaction, folder, retired = _location(store, case_id)
        # CaseStore always has a lock after registration; no new source is created here.
        with _case_lock(store, folder, case_id) as manifest:
            plan, _, _, _ = _context(store, case_id, action, minimum_age_days,
                                     retention_start_utc, transaction, folder, retired, manifest)
    return {"status": "UNSIGNED_DISPOSITION_PLAN", "plan": plan,
            "plan_sha256": _digest(plan), "deletion_authorized": False}


def _create_transaction(store, transaction, inventory):
    import secrets
    _reserve_transaction_slot(store)
    root = _root(store)
    _private_directory(root, strict=True)
    _sync_directory(store.base)
    staging = root / (".init-" + inventory["case_id"] + "-" + secrets.token_hex(8))
    staging.mkdir(mode=0o700)
    _sync_directory(root)
    _checkpoint("AFTER_INITIALIZATION_DIRECTORY")
    (staging / "events").mkdir(mode=0o700)
    raw = _canonical(inventory)
    if len(raw) > MAX_INVENTORY:
        raise CaseError("Disposition inventory exceeds bound")
    fd = os.open(staging / "inventory.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    _checkpoint("AFTER_INITIALIZATION_INVENTORY")
    _sync_directory(staging / "events")
    _sync_directory(staging)
    if grants.private_read(staging / "inventory.json", MAX_INVENTORY) != raw:
        raise CaseError("Disposition initialization inventory readback mismatch")
    if transaction.exists() or transaction.is_symlink():
        raise CaseError("Disposition transaction destination already exists")
    os.rename(staging, transaction)
    _sync_directory(root)
    _checkpoint("AFTER_INITIALIZATION_PUBLISH")


def abort_initialization(store: CaseStore, case_id: str) -> dict:
    """Explicit local cleanup of unpublished metadata only; never case evidence.

The unguessable staging directory is never a destination of the case rename.
Only two fixed metadata locations and empty directories can be removed.
"""
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise CaseError("Disposition initialization case identifier invalid")
    removed = 0
    with admission_lock(store):
        root = _root(store)
        if not root.exists():
            return {"status": "NO_UNPUBLISHED_INITIALIZATION", "metadata_initializations_removed": 0,
                    "originals_removed": 0}
        # One legacy over-capacity entry must not strand safe metadata cleanup.
        for candidate in _entries(root, MAX_TRANSACTIONS + 1):
            match = INIT_NAME.fullmatch(candidate.name)
            if match is None or match.group(1) != case_id:
                continue
            identity = _dir_identity(candidate)
            names = {p.name for p in _entries(candidate, 3)}
            if names - {"inventory.json", "events"}:
                raise CaseError("Disposition initialization has unknown content; manual review required")
            events = candidate / "events"
            if "events" in names:
                _dir_identity(events)
                if _entries(events, 1):
                    raise CaseError("Disposition initialization unexpectedly contains journal events")
            record = None
            if "inventory.json" in names:
                record = _file_record(candidate / "inventory.json", "inventory.json", maximum=MAX_INVENTORY)
            if identity != _dir_identity(candidate):
                raise CaseError("Disposition initialization changed")
            if record:
                _file_record(candidate / "inventory.json", "inventory.json", expected=record, maximum=MAX_INVENTORY)
                (candidate / "inventory.json").unlink()
                _sync_directory(candidate)
            if "events" in names:
                events.rmdir()
                _sync_directory(candidate)
            candidate.rmdir()
            _sync_directory(root)
            removed += 1
    return {"status": "UNPUBLISHED_METADATA_INITIALIZATION_ABORTED", "metadata_initializations_removed": removed,
            "originals_removed": 0}


def _unlink_exact(folder: Path, record: dict, directory_identity: list[int], *, before_unlink) -> None:
    parent, leaf = record["path"].split("/")
    directory = folder / parent
    if _dir_identity(directory) != directory_identity:
        raise CaseError("Disposition erase directory changed")
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(dfd)
        if [opened.st_dev, opened.st_ino, opened.st_uid, stat.S_IMODE(opened.st_mode)] != directory_identity:
            raise CaseError("Disposition directory changed during open")
        _file_record(directory / leaf, record["path"], expected=record)
        current = os.stat(leaf, dir_fd=dfd, follow_symlinks=False)
        if list(_identity(current)) != record["identity"]:
            raise CaseError("Disposition file changed before unlink")
        # Hashing a large original may outlast a grant. Authorization is checked
        # after that work and immediately before the destructive syscall.
        before_unlink()
        os.unlink(leaf, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def execute(store: CaseStore, signed_grants: bytes) -> dict:
    """Execute one exact dual-signed action. Checksums/booleans never authorize it."""
    grants.production_gate()
    payloads, fingerprints = grants.verify_grants(signed_grants)
    expected = payloads[0]["plan"]
    case_id, action = expected["case_id"], expected["action"]
    with admission_lock(store):
        transaction, folder, retired = _location(store, case_id)
        with _case_lock(store, folder, case_id) as manifest:
            plan, inventory, history, remaining = _context(
                store, case_id, action, expected["minimum_age_days"], expected["retention_start_utc"],
                transaction, folder, retired, manifest)
            if any(p["nonce"] in history["used"] for p in payloads):
                raise CaseError("Disposition grant nonce already consumed")
            if plan != expected:
                raise CaseError("Stale disposition plan; inspect and obtain fresh independent grants")
            grants.check_expiry(payloads)
            verify_committed_reserve(store, extra_bytes=MAX_INVENTORY + 1024 * 1024)
            if history["terminal"] == "RESTORED" or not transaction.exists():
                _reserve_transaction_slot(store)
            if history["terminal"] == "RESTORED":
                archived = transaction.parent / ("restored-" + case_id + "-" + history["head"])
                if archived.exists() or archived.is_symlink():
                    raise CaseError("Disposition closed-cycle receipt destination exists")
                os.rename(transaction, archived)
                _sync_directory(transaction.parent)
                _checkpoint("AFTER_CYCLE_ARCHIVE")
                history = _history(transaction)
            if not transaction.exists():
                _create_transaction(store, transaction, inventory)
            _append(transaction, history, "AUTHORIZE", {"signed_grants": grants.decode(signed_grants)})
            _checkpoint("AFTER_DURABLE_AUTHORIZATION")
            if action == "RETIRE":
                if not retired:
                    if (transaction / "quarantine").exists() or (transaction / "quarantine").is_symlink():
                        raise CaseError("Disposition quarantine destination exists")
                    grants.check_expiry(payloads)
                    os.rename(folder, transaction / "quarantine")
                    _sync_directory(store.cases)
                    _sync_directory(transaction)
                    folder = transaction / "quarantine"
                    _checkpoint("AFTER_RETIRE_RENAME")
                _verify_remaining(folder, manifest, inventory, history)
                _append(transaction, history, "RETIRED", {})
                status = "CASE_RETIRED_RECOVERABLE"
            elif action == "RESTORE":
                if retired:
                    active = store.cases / case_id
                    if active.exists() or active.is_symlink():
                        raise CaseError("Disposition restore destination exists")
                    grants.check_expiry(payloads)
                    os.rename(folder, active)
                    _sync_directory(transaction)
                    _sync_directory(store.cases)
                    folder = active
                    _checkpoint("AFTER_RESTORE_RENAME")
                _verify_remaining(folder, manifest, inventory, history)
                _append(transaction, history, "RESTORED", {})
                status = "CASE_RESTORED"
            else:
                # Reconcile only previously authorized intent/missing pairs.
                for index in sorted(history["intents"] - history["done"]):
                    if index not in remaining:
                        _append(transaction, history, "PURGE_DONE", {"file_index": index})
                for index in remaining:
                    grants.check_expiry(payloads)
                    record = inventory["files"][index]
                    if index not in history["intents"]:
                        _append(transaction, history, "PURGE_INTENT", {"file_index": index})
                    _checkpoint("BEFORE_EVIDENCE_UNLINK")
                    _unlink_exact(folder, record, inventory["directories"][record["path"].split("/")[0]],
                                  before_unlink=lambda: grants.check_expiry(payloads))
                    _checkpoint("AFTER_EVIDENCE_UNLINK")
                    _append(transaction, history, "PURGE_DONE", {"file_index": index})
                if _verify_remaining(folder, manifest, inventory, history):
                    raise CaseError("Disposition deletion incomplete")
                _append(transaction, history, "DELETED", {})
                status = "EVIDENCE_FILES_DELETED_METADATA_RETAINED"
            return {"status": status, "case_id": case_id, "action": action,
                    "receipt_sha256": history["head"], "two_distinct_role_signatures_verified": True,
                    "signer_key_sha256": fingerprints,
                    "originals_removed": plan["original_count"] if action == "FINAL_DELETE" else 0,
                    "evidence_files_removed": len(inventory["files"]) if action == "FINAL_DELETE" else 0,
                    "external_authority_and_backup_are_signed_attestations": True,
                    "legal_authority_independently_verified": False,
                    "backup_custody_independently_verified": False,
                    "restore_test_independently_verified": False,
                    "latest_external_checkpoint_independently_verified": False,
                    "hostile_same_uid_rollback_resistance_verified": False,
                    "secure_erase_verified": False, "hold_release_supported": False,
                    "raw_originals_exported": 0, "external_transmission_performed": False}
