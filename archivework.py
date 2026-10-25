#!/usr/bin/env python3
"""Bounded archive analysis and vault integrity for locally registered case evidence.

This module never extracts to a caller-provided path and never opens arbitrary
paths from the archive. All outputs use random opaque IDs in a private scratch
area before manifest commit. No shells, networks, subprocesses, or upload APIs.
"""
from __future__ import annotations

from contextlib import closing
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import tarfile
import zipfile
from typing import Any, BinaryIO, Callable

from casework import CaseError, CaseStore, _private_directory, _regular_open, _read_json_private, _utc, _write_json_atomic, FREE_RESERVE, MAX_CASE_STORAGE
from capacitywork import admission_lock, verify_committed_reserve

# Deliberately provisional until actual Rocky01 host and SSD measurements.
MAX_MEMBERS = 2048
MAX_MEMBER_BYTES = 2 * 1024 ** 3
MAX_UNPACKED_BYTES = 8 * 1024 ** 3
MAX_EXPANSION_RATIO = 500
MAX_ARCHIVE_NAME = 512
BUFFER = 1024 * 1024


def _safe_member(name: str) -> str:
    if (not isinstance(name, str) or not name or len(name) > MAX_ARCHIVE_NAME or
            name.startswith('/') or '\\' in name or ':' in name or '\x00' in name or
            any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise CaseError('Unsafe archive member name')
    components = PurePosixPath(name.rstrip('/')).parts
    if (not components or len(components) > 16 or
            any(c in ('.', '..', '') for c in name.rstrip('/').split('/'))):
        raise CaseError('Unsafe archive member path')
    if components[0].startswith('~'):
        raise CaseError('Unsafe archive member path')
    return name.rstrip('/')



def _sync_private_directory(path: Path) -> None:
    """Make an archive directory entry transition durable on Linux.

    Atomic os.replace protects visibility, not power-loss persistence. The
    worker must sync both source/destination directories before claiming the
    manifest committed. Refuse unexpected ownership, permissions or symlinks.
    """
    flags = (os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or
                opened.st_uid != os.getuid() or opened.st_mode & 0o077 or
                current.st_dev != opened.st_dev or
                current.st_ino != opened.st_ino or
                not stat.S_ISDIR(current.st_mode)):
            raise CaseError('Archive directory durability boundary is unsafe')
        os.fsync(fd)
    finally:
        os.close(fd)


def _digest_file(path: Path, *, should_cancel=None) -> str:
    digest = hashlib.sha256()
    fd, _ = _regular_open(path)
    try:
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            while True:
                if should_cancel:
                    should_cancel()
                block = stream.read(BUFFER)
                if not block:
                    break
                digest.update(block)
    finally:
        if fd >= 0:
            os.close(fd)
    return digest.hexdigest()


def verify_case(store: CaseStore, case_id: str, *, should_cancel=None) -> dict[str, Any]:
    """Hash each registered original and detect unregistered files without mutating them."""
    with store._locked(case_id) as (folder, manifest):
        missing: list[str] = []
        mismatched: list[str] = []
        validated = 0
        sources = manifest['artifacts']
        for artifact_id in sorted(sources):
            if should_cancel:
                should_cancel()
            try:
                path, item = store._artifact(folder, manifest, artifact_id)
                if _digest_file(path, should_cancel=should_cancel) != item['sha256']:
                    mismatched.append(artifact_id)
                else:
                    validated += 1
            except (CaseError, OSError, ValueError, KeyError):
                missing.append(artifact_id)
        originals = folder / 'originals'
        _private_directory(originals, strict=True)
        orphaned = 0
        for entry in originals.iterdir():
            if should_cancel:
                should_cancel()
            if entry.name not in sources:
                orphaned += 1
        scratch = folder / 'scratch'
        scratch_stale = 0
        if scratch.is_symlink():
            raise CaseError('Case scratch directory symlink refused')
        if scratch.exists():
            _private_directory(scratch, strict=True)
            scratch_stale = sum(1 for _ in scratch.iterdir())
        status = 'PASS' if not missing and not mismatched and not orphaned and not scratch_stale else 'PARTIAL'
        return {
            'case_id': case_id, 'status': status, 'checked_at': _utc(),
            'registered_count': len(sources), 'verified_count': validated,
            'missing_or_unsafe_count': len(missing), 'digest_mismatch_count': len(mismatched),
            'unregistered_entry_count': orphaned, 'stale_scratch_entry_count': scratch_stale,
            'problem_artifact_ids': (missing + mismatched)[:20],
            'problems_truncated': len(missing) + len(mismatched) > 20,
            'note': 'Integrity reflects observed files; it is not a write-once storage guarantee.',
        }


def _copy_stream(src: BinaryIO, dst: Path, expected: int | None, budget: dict[str, int],
                 *, should_cancel=None, before_write: Callable[[int], None] | None = None) -> tuple[str, int, bytes]:
    if expected is not None and (expected < 0 or expected > MAX_MEMBER_BYTES):
        raise CaseError('Archive member exceeds size limit')
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    digest = hashlib.sha256()
    total = 0
    head = b''
    try:
        with os.fdopen(fd, 'wb') as result:
            fd = -1
            while True:
                if should_cancel:
                    should_cancel()
                chunk = src.read(BUFFER)
                if not chunk:
                    break
                total += len(chunk)
                budget['total'] += len(chunk)
                if total > MAX_MEMBER_BYTES or budget['total'] > MAX_UNPACKED_BYTES:
                    raise CaseError('Archive expanded beyond allowed data limit')
                if budget['compressed'] and budget['total'] > budget['compressed'] * MAX_EXPANSION_RATIO:
                    raise CaseError('Archive expansion ratio exceeds safety limit')
                if expected is not None and total > expected:
                    raise CaseError('Archive member exceeds declared size')
                # Check the actual filesystem BEFORE allocating the next
                # decompressed chunk; the case's admission lock excludes
                # concurrent gateway uploads and case-vault copies.
                if before_write is not None:
                    before_write(len(chunk))
                if not head:
                    head = chunk[:4096]
                digest.update(chunk)
                result.write(chunk)
            result.flush()
            os.fsync(result.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    if expected is not None and total != expected:
        raise CaseError('Archive member size mismatch')
    return digest.hexdigest(), total, head


def _members_zip(archive: Path, add: Callable[[str, BinaryIO, int | None], None]) -> None:
    fd, _ = _regular_open(archive)
    try:
        with os.fdopen(fd, 'rb') as input_file:
            fd = -1
            try:
                with zipfile.ZipFile(input_file, mode='r') as zipped:
                    infos = zipped.infolist()
                    if len(infos) > MAX_MEMBERS:
                        raise CaseError('Archive contains too many members')
                    for info in infos:
                        name = _safe_member(info.filename)
                        mode = (info.external_attr >> 16) & 0o170000
                        if mode not in (0, stat.S_IFDIR, stat.S_IFREG):
                            raise CaseError('Archive links or special files are forbidden')
                        if info.flag_bits & 1:
                            raise CaseError('Encrypted archive entries are unsupported')
                        if info.is_dir():
                            continue
                        if info.file_size > MAX_MEMBER_BYTES:
                            raise CaseError('Archive member exceeds allowed size')
                        if info.file_size > max(1, info.compress_size) * MAX_EXPANSION_RATIO:
                            raise CaseError('Archive expansion ratio exceeds safety limit')
                        with zipped.open(info, 'r') as src:
                            add(name, src, info.file_size)
            except (zipfile.BadZipFile, EOFError, ValueError, NotImplementedError) as exc:
                raise CaseError('Archive data cannot be safely decoded') from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _members_tar(archive: Path, add: Callable[[str, BinaryIO, int | None], None]) -> None:
    fd, _ = _regular_open(archive)
    try:
        with os.fdopen(fd, 'rb') as input_file:
            fd = -1
            try:
                with tarfile.open(fileobj=input_file, mode='r|*') as tar:
                    count = 0
                    for info in tar:
                        count += 1
                        if count > MAX_MEMBERS:
                            raise CaseError('Archive contains too many members')
                        name = _safe_member(info.name)
                        if info.isdir():
                            continue
                        if not info.isfile():
                            raise CaseError('Archive links or special files are forbidden')
                        if info.size > MAX_MEMBER_BYTES:
                            raise CaseError('Archive member exceeds allowed size')
                        source = tar.extractfile(info)
                        if source is None:
                            raise CaseError('Archive member cannot be read')
                        with closing(source):
                            add(name, source, info.size)
            except (tarfile.TarError, EOFError, OSError) as exc:
                raise CaseError('Archive data cannot be safely decoded') from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _members_gzip(archive: Path, original_name: str,
                  add: Callable[[str, BinaryIO, int | None], None]) -> None:
    name = original_name[:-3] if original_name.endswith('.gz') else original_name + '.expanded'
    _safe_member(name)
    fd, _ = _regular_open(archive)
    try:
        with os.fdopen(fd, 'rb') as input_file:
            fd = -1
            try:
                with gzip.GzipFile(fileobj=input_file, mode='rb') as source:
                    add(name, source, None)
            except (gzip.BadGzipFile, EOFError, OSError, ValueError) as exc:
                raise CaseError('Gzip data cannot be safely decoded') from exc
    finally:
        if fd >= 0:
            os.close(fd)


def unpack_case_archive(store: CaseStore, case_id: str, artifact_id: str,
                        *, should_cancel=None) -> dict[str, Any]:
    """Decode ZIP, TAR or GZIP only with capacity committed for other uploads.

    Match CaseStore.register's global lock ordering: admission -> case.
    Holding the admission lock throughout streaming serializes cooperating
    upload writes, at the cost of some throughput, until real-host validation.
    """
    with admission_lock(store):
        pending = verify_committed_reserve(store)
        return _unpack_with_admission(store, case_id, artifact_id,
                                      pending_bytes=pending, should_cancel=should_cancel)


def _unpack_with_admission(store: CaseStore, case_id: str, artifact_id: str,
                           *, pending_bytes: int, should_cancel=None) -> dict[str, Any]:
    with store._locked(case_id) as (folder, manifest):
        path, parent = store._artifact(folder, manifest, artifact_id)
        if parent['type'] not in ('zip', 'gzip', 'tar'):
            raise CaseError('Only recognized ZIP/TAR/GZIP input can be expanded')
        if any(isinstance(info, dict) and info.get('derived_from') == artifact_id
               for info in manifest['artifacts'].values()):
            raise CaseError('Archive already expanded in this case')
        if parent['bytes'] > 8 * 1024 ** 3:
            raise CaseError('Archive exceeds worker input limit')
        if _digest_file(path, should_cancel=should_cancel) != parent['sha256']:
            raise CaseError('Archive source hash changed since registration')
        used = sum(int(x['bytes']) for x in manifest['artifacts'].values())
        budget = {'total': 0, 'compressed': max(1, parent['bytes'])}
        working = folder / 'scratch'
        _private_directory(working, strict=True)
        workdir = working / ('expand-' + secrets.token_hex(16))
        workdir.mkdir(mode=0o700)
        # A process SIGKILL during extraction can strand private scratch and
        # already-moved opaque originals. Persist the source-bound journal
        # before writing any decoded bytes. Manual recovery requires a fresh
        # operator-reviewed exact identity plan; no automatic originals purge.
        journal = {
            'version': 1, 'case_id': case_id,
            'source_artifact_id': artifact_id,
            'source_sha256': parent['sha256'],
            'phase': 'STAGING', 'outputs': [],
        }
        try:
            _write_json_atomic(workdir / 'journal.json', journal)
            # Flush the journal's new name and its parent workdir entry
            # before any decoded member can be written to scratch.
            _sync_private_directory(workdir)
            _sync_private_directory(working)
        except BaseException:
            # Ordinary initial journaling errors must not strand a workdir.
            # SIGKILL cannot execute cleanup and remains a visible case
            # scratch integrity issue for later operator investigation.
            shutil.rmtree(workdir)
            raise
        artifacts: dict[str, dict[str, Any]] = {}
        moved: list[Path] = []
        preserve_journal_for_review = False
        count = 0

        def check_before_write(chunk_bytes: int) -> None:
            # budget.total already includes this chunk, but it has NOT been
            # written yet. Never allocate into the fixed reserve or bytes
            # promised to concurrently staged/resumable SSH evidence.
            if used + budget['total'] > MAX_CASE_STORAGE:
                raise CaseError('Case storage quota exceeded during expansion')
            if shutil.disk_usage(folder).free < FREE_RESERVE + pending_bytes + chunk_bytes:
                raise CaseError('Insufficient reserved scratch space')

        def add(name: str, src: BinaryIO, declared: int | None) -> None:
            nonlocal count
            if should_cancel:
                should_cancel()
            count += 1
            if count > MAX_MEMBERS:
                raise CaseError('Archive contains too many members')
            _safe_member(name)
            aid = secrets.token_hex(16)
            dest = workdir / aid
            digest, length, prefix = _copy_stream(
                src, dest, declared, budget,
                should_cancel=should_cancel, before_write=check_before_write)
            artifacts[aid] = {
                'sha256': digest, 'bytes': length, 'type': store._classify(prefix),
                'registered_at': _utc(), 'intake_name': name,
                'derived_from': artifact_id,
            }

        try:
            if parent['type'] == 'zip':
                _members_zip(path, add)
            elif parent['type'] == 'tar':
                _members_tar(path, add)
            else:
                # Gzip may be tar.gz or a single compressed file. Detect tar
                # header from the decompressed stream; never rely on extension.
                fd, _ = _regular_open(path)
                try:
                    with os.fdopen(fd, 'rb') as source:
                        fd = -1
                        with gzip.GzipFile(fileobj=source) as gz:
                            header = gz.read(512)
                except (gzip.BadGzipFile, EOFError, OSError) as exc:
                    raise CaseError('Invalid gzip payload') from exc
                finally:
                    if fd >= 0:
                        os.close(fd)
                if len(header) >= 262 and header[257:262] == b'ustar':
                    _members_tar(path, add)
                else:
                    _members_gzip(path, parent.get('intake_name', 'evidence.gz'), add)
            if not artifacts:
                raise CaseError('Archive contains no regular-file evidence')
            if should_cancel:
                should_cancel()
            if _digest_file(path, should_cancel=should_cancel) != parent['sha256']:
                raise CaseError('Archive source modified during expansion')
            # Atomically persist the COMPLETE proposed output manifest before
            # moving the first scratch file into case originals. SIGKILL
            # recovery can then identify only this transaction's exact IDs.
            journal['phase'] = 'MOVING'
            journal['outputs'] = [
                {'artifact_id': aid, 'sha256': meta['sha256'], 'bytes': meta['bytes']}
                for aid, meta in artifacts.items()
            ]
            _write_json_atomic(workdir / 'journal.json', journal)
            # The MOVING ledger must be durable BEFORE the first member can
            # appear in originals. Persist both sides of the move BEFORE the
            # case manifest can reference those new originals.
            _sync_private_directory(workdir)
            # Files cannot overwrite a registered original: all are random IDs.
            for aid in artifacts:
                target = folder / 'originals' / aid
                if target.exists() or target.is_symlink():
                    raise CaseError('Generated evidence ID collision')
                os.replace(workdir / aid, target)
                moved.append(target)
            _sync_private_directory(folder / 'originals')
            _sync_private_directory(workdir)
            proposed = dict(manifest)
            proposed['artifacts'] = {**manifest['artifacts'], **artifacts}
            _write_json_atomic(folder / 'manifest.json', proposed)
            # A successful rename alone cannot certify a durable manifest.
            # If directory sync reports an error, rollback detects whether
            # the persisted manifest already references these originals.
            _sync_private_directory(folder)
            return {
                'case_id': case_id, 'source_artifact_id': artifact_id,
                'status': 'PASS', 'derived_artifact_count': len(artifacts),
                'expanded_bytes': budget['total'],
                'artifact_ids': list(artifacts)[:32],
                'list_truncated': len(artifacts) > 32,
                'note': 'Non-recursive expansion; originals and compressed input are retained.',
            }
        except BaseException:
            # An atomic manifest writer can replace manifest.json and then
            # raise (e.g. a late close/cleanup/FS error). Never unlink files
            # already referenced by a durable manifest. If the persisted
            # manifest cannot be read, also preserve moved bytes and journal
            # for explicit source-bound operator recovery rather than guessing.
            rollback_safe = True
            if moved:
                try:
                    stored = _read_json_private(folder / 'manifest.json')
                    durable = stored['artifacts']
                    if any(aid in durable for aid in artifacts):
                        rollback_safe = False
                except (CaseError, OSError, ValueError, KeyError, TypeError):
                    rollback_safe = False
            if rollback_safe:
                for target in moved:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        # Cleanup failure may leave an unregistered case
                        # original. Retain the exact MOVING journal so an
                        # operator can identify and recover it safely.
                        preserve_journal_for_review = True
                        break
                if moved and not preserve_journal_for_review:
                    try:
                        # Rollback removal must also be durable before
                        # dropping the only source-bound recovery journal.
                        _sync_private_directory(folder / 'originals')
                    except (OSError, CaseError):
                        preserve_journal_for_review = True
            else:
                preserve_journal_for_review = True
            raise
        finally:
            if not preserve_journal_for_review:
                shutil.rmtree(workdir)
                _sync_private_directory(working)
