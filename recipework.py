#!/usr/bin/env python3
"""Versioned, non-causal offline diagnostic recipes over verified text timelines.

No vendor credentials, network connections, executable inputs, or raw log export.
A marker is a reason to investigate, not a root-cause determination.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sqlite3
from typing import Any

from casework import CaseError, CaseStore, _regular_open, _utc, _write_json_atomic
from timelinework import _checked_timeline, _index_path
from recipeguidance import EXTRA_PACKS, GUIDANCE
from recipeversionwork import checked_declaration

VERSION = '0.52.0-dev.1'
MAX_SCAN = 250_000
MAX_HITS_PER_MARKER = 2
MAX_MARKERS = 8
MAX_REPORT = 64 * 1024

# These deliberately conservative text markers are evidence prompts, NOT
# vendor diagnostics or vendor-specific automatic repair instructions.
# Source references document the evidence families to inspect; the literal
# strings must be verified against actual versions before they become a rule pack.
PACKS: dict[str, dict[str, Any]] = {
    'vmware': {
        'components': ('ESXi', 'vCenter Server', 'vSphere snapshots', 'VMware Cloud Foundation'),
        'reference': 'https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html',
        'secondary_reference': 'https://knowledge.broadcom.com/external/article/385749/collecting-sddc-manager-and-vmsp-logs.html',
        'markers': (
            ('esxi_storage_paths', ('all paths down',), 'Inspect vmkernel/storage multipath and datastore accessibility'),
            ('esxi_datastore_loss', ('lost access to volume',), 'Correlate datastore, network and array events'),
            ('snapshot_consolidation', ('consolidation is needed',), 'Check VM snapshots, capacity, locks and Veeam job timing'),
            ('vcenter_host_agent', ('vpxa', 'disconnected'), 'Correlate hostd, vpxa, vCenter management and DNS/TLS'),
            ('esxi_hostd', ('hostd', 'not responding'), 'Check ESXi management health and hostd timing'),
            ('vcf_lifecycle', ('vcf', 'precheck', 'failed'), 'Compare VCF/SDDC Manager lifecycle logs and prerequisites'),
            ('vcf_domain_manager', ('domainmanager', 'failed'), 'Inspect VCF management-domain workflow evidence'),
        ),
    },
    'veeam': {
        'components': ('Veeam Backup & Replication', 'proxy', 'repository', 'Cloud Connect'),
        'reference': 'https://helpcenter.veeam.com/docs/vbr/userguide/logging.html',
        'markers': (
            ('snapshot_failure', ('failed to create vm snapshot',), 'Check hypervisor snapshot operation and job session context'),
            ('repository_unavailable', ('repository', 'unavailable'), 'Inspect repository connectivity, service and free capacity'),
            ('proxy_connection', ('proxy', 'failed to connect'), 'Inspect proxy selection, routing and service logs'),
            ('vss_failure', ('vss', 'failed'), 'Inspect guest writers, application logs and backup processing mode'),
            ('cloud_connect_gateway', ('cloud connect', 'gateway', 'failed'), 'Correlate tenant/provider gateway and repository logs'),
        ),
    },
    'hyperv': {
        'components': ('Hyper-V', 'Failover Clustering', 'Cluster Shared Volumes', 'Live Migration'),
        'reference': 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/high-availability-virtual-machine-troubleshooting-guidance',
        'markers': (
            ('cluster_node_removed', ('cluster node', 'removed'), 'Check FailoverClustering event 1135 and node communication'),
            ('csv_unavailable', ('cluster shared volume', 'unavailable'), 'Correlate CSV ownership and storage paths'),
            ('vmms_failure', ('vmms', 'failed'), 'Inspect Hyper-V management and host service events'),
            ('live_migration', ('live migration', 'failed'), 'Check host network, authentication and VM state'),
            ('cluster_resource_failure', ('resource', 'failed to come online'), 'Inspect cluster dependencies and resource diagnostics'),
        ),
    },
    'nutanix': {
        'components': ('Nutanix AHV', 'Foundation/Phoenix', 'CVM', 'Genesis'),
        'reference': 'https://www.nutanix.dev/api_reference/apis/foundation.html',
        'markers': (
            ('foundation_heartbeat', ('foundation', 'heartbeat', 'timeout'), 'Check Phoenix boot, management VLAN and Foundation reachability'),
            ('phoenix_boot', ('phoenix', 'failed'), 'Correlate virtual media boot staging, hardware and foundation logs'),
            ('cvm_unreachable', ('cvm', 'unreachable'), 'Check CVM/host connectivity and startup readiness'),
            ('genesis_service', ('genesis', 'failed'), 'Inspect CVM services and cluster health with vendor guidance'),
            ('storage_timeout', ('storage', 'timeout'), 'Correlate AHV storage, network, and controller evidence'),
        ),
    },
}
PACKS.update(EXTRA_PACKS)
FAMILIES = tuple(sorted(PACKS))
RECIPE_JOBS = tuple('recipe_' + family for family in FAMILIES)


def recipe_digest(family: str) -> str:
    return hashlib.sha256(json.dumps({'version': VERSION, 'family': family,
        'pack': PACKS[family], 'guidance': GUIDANCE[family]},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def catalog() -> dict[str, Any]:
    return {'status': 'PASS', 'recipe_version': VERSION,
            'families': [{'family': key, 'components': list(data['components']),
                          'marker_count': len(data['markers']),
                          'reference': data['reference'],
                          'recipe_sha256': recipe_digest(key),
                          'reference_context': GUIDANCE[key]['reference_context'],
                          'platform_version_support': 'UNVERIFIED'}
                         for key, data in sorted(PACKS.items())],
            'rules_are': 'heuristic_evidence_prompts', 'root_cause_established': False,
            'requires': 'fresh_build_timeline'}


def _report_path(folder: Path, family: str) -> Path:
    return folder / 'indexes' / ('recipe-' + family + '.json')


def _source_stats(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute('''SELECT COUNT(*), COALESCE(SUM(skipped),0),
        COALESCE(SUM(unanchored),0), COALESCE(SUM(decode_errors),0),
        COALESCE(SUM(preview_truncated),0) FROM sources''').fetchone()
    return {'source_count': row[0], 'skipped_lines': row[1],
            'unanchored_lines': row[2], 'invalid_utf8_lines': row[3],
            'truncated_previews': row[4]}


def evaluate(store: CaseStore, case_id: str, family: str, *, should_cancel=None) -> dict[str, Any]:
    if type(family) is not str or family not in PACKS:
        raise CaseError('Unknown approved diagnostic recipe family')
    with store._locked(case_id) as (folder, manifest):
        conn = _checked_timeline(folder, manifest)
        try:
            timeline_info = _index_path(folder).lstat()
            stats = _source_stats(conn)
            source_hashes = {row['artifact_id']: row['sha256'] for row in
                             conn.execute('SELECT artifact_id,sha256 FROM sources')}
            source_set_sha = hashlib.sha256(json.dumps(sorted(source_hashes.items()),
                separators=(',', ':')).encode()).hexdigest()
            count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            rules = PACKS[family]['markers']
            hits: dict[str, list[dict[str, Any]]] = {r[0]: [] for r in rules}
            totals = {r[0]: 0 for r in rules}
            scanned = 0
            cursor = conn.execute('''SELECT artifact_id,line_no,timestamp_utc,excerpt FROM events
                                     ORDER BY id LIMIT ?''', (MAX_SCAN + 1,))
            while scanned < MAX_SCAN:
                batch = cursor.fetchmany(min(256, MAX_SCAN-scanned))
                if not batch:
                    break
                if should_cancel:
                    should_cancel()
                for row in batch:
                    scanned += 1
                    text = row['excerpt'].lower()
                    for marker, tokens, _ in rules:
                        if all(token in text for token in tokens):
                            totals[marker] += 1
                            if len(hits[marker]) < MAX_HITS_PER_MARKER:
                                hits[marker].append({'artifact_id': row['artifact_id'],
                                    'source_sha256': source_hashes[row['artifact_id']],
                                    'line_no': row['line_no'], 'utc': row['timestamp_utc']})
            incomplete = scanned < count or any(stats[k] for k in
                ('skipped_lines','unanchored_lines','invalid_utf8_lines','truncated_previews'))
            findings = [{'marker_id': marker, 'observed': total,
                         'evidence': hits[marker], 'next_check': next_check}
                        for marker, _, next_check in rules if (total := totals[marker])]
            findings = findings[:MAX_MARKERS]
            result = {
                'status': 'NOT_APPLICABLE' if count == 0 else 'PARTIAL',
                'case_id': case_id, 'family': family, 'recipe_version': VERSION,
                'recipe_sha256': recipe_digest(family), 'source_set_sha256': source_set_sha,
                'scan_complete': not incomplete, 'platform_version_support': 'UNVERIFIED',
                'reference_context': GUIDANCE[family]['reference_context'],
                'required_evidence': list(GUIDANCE[family]['required_evidence']),
                'candidate_explanations': list(GUIDANCE[family]['candidate_explanations']),
                'falsification_checks': list(GUIDANCE[family]['falsification_checks']),
                'candidate_explanations_validated': False,
                'secondary_source_reference': PACKS[family].get('secondary_reference'),
                'built_at': _utc(), 'events_examined': scanned,
                'events_available': count, 'coverage': stats, 'findings': findings,
                'markers_found': len(findings), 'source_reference': PACKS[family]['reference'],
                'root_cause_established': False, 'no_markers_does_not_mean_healthy': True,
                'limitations': (['scan_cap_reached'] if scanned < count else []) +
                    (['unknown_time_or_incomplete_log_index'] if incomplete else []) +
                    ['text_preview_only', 'signatures_need_version_validation',
                     'platform_version_unverified', 'evidence_prompts_not_executable_remediation'],
                '_timeline_identity': {'inode': timeline_info.st_ino,
                    'mtime_ns': timeline_info.st_mtime_ns, 'bytes': timeline_info.st_size},
            }
            if should_cancel:
                should_cancel()
            target = _report_path(folder, family)
            # The fixed recipe name is the only selectable output path.
            if target.is_symlink():
                raise CaseError('Recipe report path is unsafe')
            if target.exists():
                fd, _ = _regular_open(target)
                os.close(fd)
            _write_json_atomic(target, result)
            public = dict(result)
            public.pop('_timeline_identity', None)
            return public
        finally:
            conn.close()


def report(store: CaseStore, case_id: str, family: str, *, product=None,
           platform_version=None, version_artifact_id=None) -> dict[str, Any]:
    if type(family) is not str or family not in PACKS:
        raise CaseError('Unknown approved diagnostic recipe family')
    with store._locked(case_id) as (folder, manifest):
        applicability=checked_declaration(store,folder,manifest,family,recipe_digest(family),
            product,platform_version,version_artifact_id)
        if applicability['status']=='DECLARATION_MISMATCH_DO_NOT_APPLY':
            return {'status':'NOT_APPLICABLE_TO_REQUESTED_DECLARATION','family':family,
                'recipe_version':VERSION,'recipe_sha256':recipe_digest(family),
                'version_applicability':applicability,'root_cause_established':False}
        conn = _checked_timeline(folder, manifest)
        try:
            timeline_info = _index_path(folder).lstat()
            target = _report_path(folder, family)
            if not target.exists() or target.is_symlink():
                raise CaseError('Diagnostic recipe not run; submit approved job')
            fd, info = _regular_open(target)
            try:
                if info.st_size > MAX_REPORT or info.st_nlink != 1:
                    raise CaseError('Recipe report storage unsafe')
                with os.fdopen(fd, 'rb') as inp:
                    fd = -1
                    data = json.loads(inp.read(MAX_REPORT + 1))
            except (UnicodeError, json.JSONDecodeError, TypeError, RecursionError) as exc:
                raise CaseError('Recipe report invalid') from exc
            finally:
                if fd >= 0:
                    os.close(fd)
            identity = data.pop('_timeline_identity', None)
            if not isinstance(identity, dict) or any(identity.get(k) != actual for k, actual in
                    (('inode', timeline_info.st_ino), ('mtime_ns', timeline_info.st_mtime_ns),
                     ('bytes', timeline_info.st_size))):
                raise CaseError('Recipe report stale; rerun after timeline rebuild')
            if (data.get('family') != family or data.get('case_id') != case_id or
                    data.get('recipe_version') != VERSION or
                    data.get('recipe_sha256') != recipe_digest(family)):
                raise CaseError('Recipe report version or case mismatch')
            data['version_applicability']=applicability
            return data
        finally:
            conn.close()
