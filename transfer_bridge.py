#!/usr/bin/env python3
"""Minimal SSH-invoked companion for a Windows-to-case SFTP/SCP file handoff.

Not an MCP upload endpoint. This script handles only an opaque temporary basename
inside the existing user-owned private inbox. It exposes no generic remote path,
no overwrite option, no HTTP server and no shell interpreter.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from casework import CaseStore, CaseError, FILE_NAME, FREE_RESERVE, MAX_WORKER_ARTIFACT
import resumable_transfer
import transfer_retention
from capacitywork import admission_lock, new_upload_capacity

TEMP = re.compile(r'^\.upload-[a-f0-9]{32}$')
SHA256 = re.compile(r'^[a-f0-9]{64}$')
CHUNK = 1024 * 1024


def _safe_temp(name: str) -> str:
    if not isinstance(name, str) or not TEMP.fullmatch(name):
        raise CaseError('Invalid upload token')
    return name


def prepare(store: CaseStore, proposed_size: int | None = None) -> dict:
    with admission_lock(store):
        free = shutil.disk_usage(store.inbox).free
        capacity = new_upload_capacity(store)
        if free <= FREE_RESERVE:
            raise CaseError('Insufficient upload storage capacity')
        if proposed_size is not None and (
                type(proposed_size) is not int or proposed_size < 0
                or proposed_size > MAX_WORKER_ARTIFACT or proposed_size > capacity):
            raise CaseError('Insufficient safe capacity after concurrent reservations')
        return {'status': 'READY', 'inbox': str(store.inbox),
                'max_artifact_bytes': MAX_WORKER_ARTIFACT,
                'safe_available_bytes': capacity,
                'capacity_applies_to': 'new_upload_only',
                'protocol': 'scp/sftp-over-ssh; optional ssh-stream-resume'}


def finalize(store: CaseStore, temp: str, destination: str, expected_size: int,
             expected_sha256: str) -> dict:
    prepare(store)
    _safe_temp(temp)
    if (not isinstance(destination, str) or not FILE_NAME.fullmatch(destination) or
            destination in ('.', '..')):
        raise CaseError('Destination filename is invalid')
    if (not isinstance(expected_size, int) or expected_size < 0 or
            expected_size > MAX_WORKER_ARTIFACT or
            not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256)):
        raise CaseError('Declared evidence identity is invalid')
    target = store.inbox / destination
    source = store.inbox / temp
    fd = -1
    try:
        fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaseError('Upload is busy; cannot finalize while writing') from exc
        session = resumable_transfer.read_meta(store, temp, missing_ok=True)
        if session is not None and (
                session["size"] != expected_size or
                session["sha256"] != expected_sha256):
            raise CaseError('Resumable upload identity does not match finalization')
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or before.st_size != expected_size or
                before.st_mode & 0o022):
            raise CaseError('Uploaded evidence type, ownership, length or permissions are invalid')
        # SFTP sometimes delivers mode 0644; hardlinks and non-user-owned files
        # are refused before changing the mode, in a private directory.
        os.fchmod(fd, 0o600)
        before = os.fstat(fd)
        digest = hashlib.sha256()
        seen = 0
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            seen += len(block)
            if seen > expected_size:
                raise CaseError('Upload changed during verification')
            digest.update(block)
        after = os.fstat(fd)
        if (seen != expected_size or digest.hexdigest() != expected_sha256 or
                after.st_mtime_ns != before.st_mtime_ns or
                after.st_ctime_ns != before.st_ctime_ns or
                after.st_size != expected_size):
            raise CaseError('Upload digest/identity verification failed')
        if shutil.disk_usage(store.inbox).free < FREE_RESERVE:
            raise CaseError('Required storage reserve unavailable')
        # POSIX hardlink is an atomic create-without-overwrite, unlike replace.
        # Link count is checked above; the private temporary name is removed on
        # success so the final inbox file is still single-linked.
        try:
            os.link(source, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise CaseError('Destination exists; explicit rename is required') from exc
        try:
            source.unlink()
        except OSError:
            # A successful link that cannot be cleaned up must not claim
            # finalized single-link evidence. Undo the new name only.
            target.unlink(missing_ok=True)
            raise CaseError('Could not complete upload cleanup')
        # The final basename is now a verified, single-linked 0600 file.
        # Orphaned metadata after a sudden SIGKILL remains private and is
        # explicitly removable via abort; no overwrite is permitted.
        if session is not None:
            resumable_transfer.remove_meta(store, temp)
        return {'status': 'STAGED', 'filename': destination, 'bytes': seen,
                'sha256': expected_sha256, 'ready_for_case_import': True}
    except (OSError, ValueError) as exc:
        raise CaseError('Evidence staging failed') from exc
    finally:
        if fd >= 0:
            os.close(fd)


def abort(store: CaseStore, temp: str) -> dict:
    with admission_lock(store):
        return _abort_locked(store,temp)


def _abort_locked(store: CaseStore, temp: str) -> dict:
    store._ensure_store()
    _safe_temp(temp)
    source = store.inbox / temp
    try:
        state = source.lstat()
    except FileNotFoundError:
        cleaned = resumable_transfer.clear_orphan_meta(store, temp)
        return {'status': 'ORPHAN_SESSION_REMOVED' if cleaned else 'NO_TEMPORARY_FILE'}
    if state.st_uid != os.getuid() or not (stat.S_ISREG(state.st_mode) or stat.S_ISLNK(state.st_mode)):
        raise CaseError('Upload temporary file ownership/type unsafe')
    if stat.S_ISREG(state.st_mode):
        fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
        try:
            if os.fstat(fd).st_nlink != 1:
                raise CaseError('Upload temporary file is hardlinked')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CaseError('Upload is busy; abort refused') from exc
            source.unlink()
        finally:
            os.close(fd)
    else:
        source.unlink()  # Deletes only the symlink, never its target.
    resumable_transfer.remove_meta(store, temp)
    return {'status': 'TEMPORARY_FILE_REMOVED'}


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print('Upload helper refuses root', file=sys.stderr)
        return 2
    p = argparse.ArgumentParser(description='Private SSH evidence file-stage companion')
    commands = p.add_subparsers(dest='action', required=True)
    pre = commands.add_parser('prepare')
    pre.add_argument('--size', type=int)
    start = commands.add_parser('begin')
    start.add_argument('--temp', required=True)
    start.add_argument('--size', required=True, type=int)
    start.add_argument('--sha256', required=True)
    resume = commands.add_parser('status')
    resume.add_argument('--temp', required=True)
    upload = commands.add_parser('append')
    upload.add_argument('--temp', required=True)
    upload.add_argument('--offset', required=True, type=int)
    fin = commands.add_parser('finalize')
    fin.add_argument('--temp', required=True)
    fin.add_argument('--filename', required=True)
    fin.add_argument('--size', required=True, type=int)
    fin.add_argument('--sha256', required=True)
    cleanup = commands.add_parser('abort')
    cleanup.add_argument('--temp', required=True)
    retention = commands.add_parser('retention')
    retention.add_argument('--older-hours', type=int, default=72)
    retention.add_argument('--confirm', action='store_true')
    retention.add_argument('--plan-sha256')
    args = p.parse_args(argv)
    try:
        store = CaseStore(Path.home())
        if args.action == 'prepare':
            result = prepare(store, args.size)
        elif args.action == 'begin':
            result = resumable_transfer.begin(store, args.temp, args.size, args.sha256)
        elif args.action == 'status':
            result = resumable_transfer.status(store, args.temp)
        elif args.action == 'append':
            result = resumable_transfer.append(store, args.temp, args.offset)
        elif args.action == 'finalize':
            result = finalize(store, args.temp, args.filename, args.size, args.sha256)
        elif args.action == 'retention':
            result = transfer_retention.inventory(store, older_hours=args.older_hours,
                      expected_plan_sha256=args.plan_sha256, confirm=args.confirm)
        else:
            result = abort(store, args.temp)
    except (CaseError, OSError) as exc:
        print(str(exc) if isinstance(exc, CaseError) else 'File transfer failed', file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
