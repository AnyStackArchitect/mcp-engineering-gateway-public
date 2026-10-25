"""Stage/verify/rollback review payloads in a NEW offline directory, never a host root."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

import site_plan

JOURNAL = '.engbox-offline-stage.json'
MAX_BYTES = 16 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bundle(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    site_plan.require(len(raw) <= MAX_BYTES, 'bundle_size')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        rows = archive.infolist()
        names = [r.filename for r in rows]
        site_plan.require(len(names) <= 128 and len(names) == len(set(names))
                          and sum(r.file_size for r in rows) <= MAX_BYTES, 'archive_bounds')
        for row in rows:
            name = PurePosixPath(row.filename)
            site_plan.require(str(name) == row.filename and not name.is_absolute()
                              and '..' not in name.parts and '\\' not in row.filename
                              and stat.S_IFMT(row.external_attr >> 16) == stat.S_IFREG
                              and row.compress_type == zipfile.ZIP_STORED, 'archive_member')
        metadata = json.loads(archive.read('bundle.json'), object_pairs_hook=site_plan.duplicate_safe)
        site_plan.require(metadata['schema'] == 1 and metadata['kind'] == 'OFFLINE_REVIEW_PAYLOAD'
                          and metadata['deployment_ready'] is False, 'bundle_kind')
        site_plan.validate_site(metadata['site'])
        site_plan.require(metadata['site_sha256'] == site_plan.digest(metadata['site']), 'site_identity')
        site_plan.require(metadata['source_commit'] == metadata['site']['source_commit'], 'source_commit_binding')
        files = metadata['files']
        site_plan.require(type(files) is dict and 1 <= len(files) <= 100, 'payload_count')
        payload = {}
        for path, entry in files.items():
            site_plan.require(site_plan.linux_path(path) and path != '/'
                              and path.split('/')[1] in {'opt', 'etc'}, 'payload_path')
            site_plan.keys(entry, 'sha256 bytes mode owner', 'payload_metadata')
            site_plan.require(entry['mode'] == 0o644 and entry['owner'] == 'root:root'
                              and type(entry['bytes']) is int and 0 <= entry['bytes'] <= MAX_BYTES, 'payload_permissions')
            data = archive.read('payload' + path)
            site_plan.require(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'payload_digest')
            payload[path.lstrip('/')] = data
        review = metadata['review_policy_sha256']
        site_plan.require(type(review) is dict and len(review) == 4, 'review_policy_count')
        for name, digest in review.items():
            site_plan.require(name.startswith('review/policy/') and sha(archive.read(name)) == digest, 'review_policy_digest')
        site_plan.require(set(names) == {'bundle.json', *('payload' + path for path in files), *review}, 'archive_coverage')
    return sha(raw), payload, metadata


def safe_root(value):
    site_plan.require('..' not in Path(value).parts, 'stage_root_traversal')
    root = Path(value).absolute()
    site_plan.require(root.name and root.parent != root and root != Path(root.anchor), 'not_a_filesystem_root')
    # This backend is a local staging exercise, not a chroot-based installer.
    # Explicitly refuse the conventional live system prefixes on Linux.
    if os.name != 'nt':
        site_plan.require(root.parts[1] not in {'etc', 'opt', 'usr', 'run', 'home', 'var', 'boot', 'sys', 'proc', 'dev'}, 'not_live_system_path')
    for ancestor in reversed([root, *root.parents]):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        site_plan.require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'stage_ancestor_type')
    return root


def target(root, relative):
    path = PurePosixPath(relative)
    site_plan.require(relative not in {'', '.'} and not path.is_absolute() and str(path) == relative and '..' not in path.parts
                      and '\\' not in relative and relative != JOURNAL, 'stage_relative_path')
    destination = root.joinpath(*path.parts)
    site_plan.require(destination.is_relative_to(root), 'stage_containment')
    for parent in [*destination.parents]:
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise site_plan.InputError('stage_parent_link')
    return destination


def save(root, journal):
    path = root/JOURNAL
    pending = root/(JOURNAL + '.pending')
    data = (json.dumps(journal, sort_keys=True, indent=2) + '\n').encode()
    with pending.open('xb') as stream:
        os.chmod(pending, 0o600)
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(pending, path)


def journal_for(root, digest, payload):
    path = root/JOURNAL
    site_plan.require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_BYTES, 'stage_journal')
    journal = json.loads(path.read_text(encoding='utf8'), object_pairs_hook=site_plan.duplicate_safe)
    expected = {name: sha(data) for name, data in payload.items()}
    site_plan.require(journal['schema'] == 1 and journal['kind'] == 'OFFLINE_STAGE_ONLY'
                      and journal['bundle_sha256'] == digest and journal['files'] == expected
                      and type(journal['created_dirs']) is list and len(journal['created_dirs']) <= 200, 'stage_journal_binding')
    for name in journal['created_dirs']:
        target(root, name)
        site_plan.require(any(key.startswith(name + '/') for key in payload), 'stage_directory_binding')
    return journal


def verify(root, digest, payload):
    root = safe_root(root)
    journal_for(root, digest, payload)
    for name, data in payload.items():
        path = target(root, name)
        info = path.lstat()
        site_plan.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                          and sha(path.read_bytes()) == sha(data), 'staged_file_changed')
    return {'status': 'OFFLINE_STAGE_VERIFIED', 'files': len(payload), 'host_installed': False, 'deployment_ready': False}


def rollback(root, digest, payload):
    root = safe_root(root)
    journal = journal_for(root, digest, payload)
    # Precheck the ENTIRE set before deleting anything. Foreign or modified data
    # blocks rollback; never remove a case, journal, key or human-edited file.
    expected = {JOURNAL, *payload, *journal['created_dirs']}
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory)/name
            site_plan.require(not path.is_symlink(), 'rollback_link')
            actual.add(path.relative_to(root).as_posix())
    site_plan.require(actual <= expected, 'rollback_foreign_data')
    for name, data in payload.items():
        path = target(root, name)
        if path.exists():
            info = path.lstat()
            site_plan.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                              and sha(path.read_bytes()) == sha(data), 'rollback_modified_data')
    for name in payload:
        path = target(root, name)
        if path.exists():
            path.unlink()
    for name in sorted(journal['created_dirs'], key=lambda name: len(PurePosixPath(name).parts), reverse=True):
        path = target(root, name)
        if path.exists():
            path.rmdir()
    (root/JOURNAL).unlink()
    root.rmdir()
    return {'status': 'OFFLINE_STAGE_ROLLED_BACK', 'host_installed': False, 'deployment_ready': False}


def stage(root, digest, payload, *, fail_after=None):
    root = safe_root(root)
    root.mkdir(mode=0o700)  # exclusive; never adopt an existing directory
    journal = {'schema': 1, 'kind': 'OFFLINE_STAGE_ONLY', 'bundle_sha256': digest,
               'files': {name: sha(data) for name, data in payload.items()}, 'created_dirs': [], 'state': 'STAGING'}
    save(root, journal)
    try:
        for index, (name, data) in enumerate(sorted(payload.items())):
            destination = target(root, name)
            for parent in reversed(destination.parents):
                if parent.is_relative_to(root) and parent != root and not parent.exists():
                    # Journal intent before creation makes interruption recoverable.
                    journal['created_dirs'].append(parent.relative_to(root).as_posix())
                    save(root, journal)
                    parent.mkdir(mode=0o700)
            with destination.open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.chmod(destination, 0o644)
            if fail_after is not None and index + 1 == fail_after:
                raise OSError('synthetic_stage_failure')
        journal['state'] = 'STAGED'
        save(root, journal)
        return verify(root, digest, payload)
    except Exception:
        # Failure recovery preserves ambiguous/changed data rather than forcing
        # recursive deletion. A failed rollback leaves its journal for review.
        rollback(root, digest, payload)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['stage', 'verify', 'rollback'])
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--root', required=True, type=Path, help='NEW offline staging directory, never / or an installed host tree')
    args = parser.parse_args(argv)
    try:
        digest, payload, metadata = bundle(args.bundle)
        result = {'stage': stage, 'verify': verify, 'rollback': rollback}[args.operation](args.root, digest, payload)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, zipfile.BadZipFile):
        print('{"status":"STAGE_OPERATION_REFUSED","host_installed":false,"deployment_ready":false}')
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
