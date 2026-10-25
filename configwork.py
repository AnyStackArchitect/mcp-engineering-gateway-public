#!/usr/bin/env python3
"""Bounded read-only semantic configuration comparison of case artifacts.

Never return raw settings values, paths, addresses, tokens or customer names.
The report is intended to direct local investigation, not establish drift root cause.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from typing import Any

from casework import CaseError, CaseStore, _regular_open

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_FIELDS = 4096
MAX_RESULTS = 40
MAX_DEPTH = 12
MAX_CONFIG_ARRAY = 4096
MAX_CONFIG_NODES = 32768
SAFE_NAMES = {
    'enabled', 'disabled', 'mode', 'version', 'timeout', 'retry', 'retry_count',
    'port', 'protocol', 'transport', 'priority', 'status', 'headroom', 'replication',
    'immutability', 'multipath', 'quorum', 'compression', 'retention', 'backup',
    'max_connections', 'max_retries', 'wait_seconds', 'interval', 'block_size',
    'mtu', 'lifecycle', 'heartbeat_timeout', 'ssl_enabled', 'tls_enabled',
}
SENSITIVE = re.compile(r'(?i)(pass|secret|token|key|cred|host|user|address|url|ip|domain|cert|serial|tenant|account|name|location|path|id$)')
KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,60}$')


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaseError('Configuration contains duplicate JSON keys')
        result[key] = value
    return result


def _validate_json_structure(obj: Any) -> None:
    """Bound every descendant, including members of opaque comparison arrays."""
    if not isinstance(obj, dict):
        raise CaseError('Top-level JSON configuration must be an object')
    nodes = fields = 0

    def visit(value: Any, depth: int) -> None:
        nonlocal nodes, fields
        nodes += 1
        if depth > MAX_DEPTH:
            raise CaseError('Configuration exceeds nesting depth limit')
        if nodes > MAX_CONFIG_NODES:
            raise CaseError('Configuration exceeds total node limit')
        if isinstance(value, dict):
            fields += len(value)
            if fields > MAX_CONFIG_FIELDS:
                raise CaseError('Configuration exceeds bounded field count')
            for key, child in value.items():
                if not isinstance(key, str) or len(key) > 160:
                    raise CaseError('Unbounded or invalid configuration key')
                visit(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > MAX_CONFIG_ARRAY:
                raise CaseError('Configuration array exceeds analysis limit')
            for child in value:
                visit(child, depth + 1)
        elif type(value) is float:
            if not math.isfinite(value):
                raise CaseError('Configuration contains a nonfinite number')
        elif value is not None and type(value) not in (str, int, bool):
            raise CaseError('Unsupported configuration value type')

    visit(obj, 0)


def _flatten_json(obj: Any, modes: set[str] | None = None) -> dict[tuple[str, ...], str]:
    """Normalize JSON with explicit, privacy-safe array identity semantics.

    Tagged path components prevent a JSON field named like an internal layout
    or member selector from impersonating an analyzer-generated key.
    Arrays of objects are keyed only when every item has the same supported
    unique scalar identity field. Order is independently compared. Unkeyed
    arrays remain opaque ordered values; no guessed identity or index pairing.
    """
    _validate_json_structure(obj)
    values: dict[tuple[str, ...], str] = {}
    if modes is None:
        modes = set()

    def walk(value: Any, path: tuple[str, ...], depth: int) -> None:
        if depth > MAX_DEPTH or len(values) >= MAX_CONFIG_FIELDS:
            raise CaseError('Configuration structure exceeds bounded comparison limits')
        if isinstance(value, dict):
            if not value and path:
                values[path] = hashlib.sha256(b'{}').hexdigest()
            for key in sorted(value):
                if not isinstance(key, str) or len(key) > 160:
                    raise CaseError('Unsupported JSON configuration key')
                walk(value[key], (*path, 'field:' + key), depth + 1)
            return
        if not path:
            raise CaseError('Top-level JSON configuration must be an object')
        if isinstance(value, list) and value and len(value) <= 512 and all(
                isinstance(item, dict) for item in value):
            for identifier in ('id', 'uuid', 'name'):
                if not all(identifier in item and type(item[identifier]) in (str, int)
                           and len(str(item[identifier])) <= 128 for item in value):
                    continue
                seen: set[str] = set()
                ordered: list[str] = []
                for item in value:
                    raw_identity = json.dumps(
                        [type(item[identifier]).__name__, item[identifier]],
                        ensure_ascii=True, separators=(',', ':'), allow_nan=False)
                    token = '@' + hashlib.sha256(
                        (identifier + ':' + raw_identity).encode('utf-8')).hexdigest()[:24]
                    if token in seen:
                        raise CaseError('Configuration array has ambiguous duplicate identities')
                    seen.add(token)
                    ordered.append(token)
                    walk({k: v for k, v in item.items() if k != identifier},
                         (*path, 'member:' + token), depth + 1)
                if len(values) >= MAX_CONFIG_FIELDS:
                    raise CaseError('Configuration array identity index exceeds field limit')
                values[(*path, 'layout:order')] = hashlib.sha256(
                    json.dumps(ordered, separators=(',', ':')).encode()).hexdigest()
                modes.add('unique_identity_array')
                return
        if isinstance(value, list):
            modes.add('unidentified_array_compared_as_ordered_atomic_value')
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False)
        values[path] = hashlib.sha256(canonical.encode()).hexdigest()

    if not isinstance(obj, dict):
        raise CaseError('Top-level JSON configuration must be an object')
    walk(obj, (), 0)
    return values


def _parse_properties(text: str) -> dict[tuple[str, ...], str]:
    entries: dict[tuple[str, ...], str] = {}
    for row in text.splitlines():
        row = row.strip()
        if not row or row.startswith(('#',';')):
            continue
        sep = '=' if '=' in row else ':' if ':' in row else None
        if sep is None:
            raise CaseError('Unsupported property row; use JSON or key=value')
        key, value = (p.strip() for p in row.split(sep, 1))
        if not KEY_RE.fullmatch(key) or (key,) in entries:
            raise CaseError('Ambiguous or unsupported configuration keys')
        if len(entries) >= MAX_CONFIG_FIELDS:
            raise CaseError('Configuration key count exceeds limit')
        entries[(key,)] = hashlib.sha256(value.encode()).hexdigest()
    return entries


def _safe_label(key: tuple[str, ...]) -> str:
    # Do not export uncontrolled key names: some key names encode hostnames,
    # domains, usernames or internal paths even when the value is masked.
    part = key[-1][6:] if key[-1].startswith('field:') else key[-1]
    if part.lower() in SAFE_NAMES and not SENSITIVE.search(part):
        return part.lower()
    return 'field-' + hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest()[:12]


def _read_case_config(store: CaseStore, folder, manifest, artifact_id: str) -> bytes:
    path, item = store._artifact(folder, manifest, artifact_id)
    if item.get('type') != 'text' or item['bytes'] > MAX_CONFIG_BYTES:
        raise CaseError('Only small registered text configurations can be compared')
    fd, info = _regular_open(path)
    try:
        if info.st_nlink != 1 or info.st_size != item['bytes']:
            raise CaseError('Configuration source identity changed')
        with os.fdopen(fd, 'rb') as inp:
            fd = -1
            data = inp.read(MAX_CONFIG_BYTES + 1)
        after = path.lstat()
        if len(data) != item['bytes'] or after.st_mtime_ns != info.st_mtime_ns or \
                after.st_ino != info.st_ino or after.st_dev != info.st_dev or \
                hashlib.sha256(data).hexdigest() != item['sha256']:
            raise CaseError('Configuration source changed or checksum disagrees')
        return data
    finally:
        if fd >= 0:
            os.close(fd)


def compare(store: CaseStore, case_id: str, before_id: str, after_id: str,
            *, fmt: str = 'json') -> dict[str, Any]:
    if fmt not in ('json', 'properties'):
        raise CaseError('Unsupported configuration format; JSON and properties only')
    if before_id == after_id:
        raise CaseError('Select two different registered artifacts')
    with store._locked(case_id) as (folder, manifest):
        original = _read_case_config(store, folder, manifest, before_id)
        updated = _read_case_config(store, folder, manifest, after_id)
    try:
        a, b = original.decode('utf-8', 'strict'), updated.decode('utf-8', 'strict')
    except UnicodeDecodeError as exc:
        raise CaseError('Configuration requires UTF-8; no lossy parsing') from exc
    array_modes: set[str] = set()
    if fmt == 'json':
        try:
            left = _flatten_json(json.loads(a, object_pairs_hook=_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite value'))), array_modes)
            right = _flatten_json(json.loads(b, object_pairs_hook=_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite value'))), array_modes)
        except (ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise CaseError('Configuration JSON is malformed or unsupported') from exc
    else:
        left, right = _parse_properties(a), _parse_properties(b)
    keys = sorted(set(left) | set(right))
    changes = []
    total = 0
    count = {'ADDED': 0, 'REMOVED': 0, 'CHANGED': 0}
    for key in keys:
        kind = 'ADDED' if key not in left else 'REMOVED' if key not in right else \
               'CHANGED' if left[key] != right[key] else None
        if kind is not None:
            count[kind] += 1
            total += 1
            if len(changes) < MAX_RESULTS:
                label = 'array_layout' if key[-1] == 'layout:order' else _safe_label(key)
                entry = {'field': label, 'change': kind}
                if any(component.startswith('member:') for component in key):
                    entry['field_ref'] = hashlib.sha256(
                        json.dumps(key, separators=(',', ':')).encode()).hexdigest()[:24]
                changes.append(entry)
    return {'status': 'PARTIAL' if total > MAX_RESULTS else 'PASS',
            'case_id': case_id, 'format': fmt,
            'before_artifact_id': before_id, 'after_artifact_id': after_id,
            'changed_fields': total, 'change_totals': count, 'changes': changes,
            'results_truncated': total > MAX_RESULTS,
            'before_sha256': hashlib.sha256(original).hexdigest(),
            'after_sha256': hashlib.sha256(updated).hexdigest(),
            'identity_array_mode': ('unique_scalar_identity_with_order_tracking' if
                                    'unique_identity_array' in array_modes else 'NOT_USED'),
            'array_modes_encountered': sorted(array_modes),
            'change_time_known': False,
            'same_system_verified': False,
            'values_exposed': False, 'causality_established': False,
            'limitations': ['values_redacted', 'comparison_is_not_causality',
                            'snapshot_change_time_unknown',
                            'same_system_not_verified'] +
                           (['unidentified_arrays_opaque_ordered_comparison']
                            if 'unidentified_array_compared_as_ordered_atomic_value'
                            in array_modes else [])}
