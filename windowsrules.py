"""Fixed, versioned EVTX metadata observations; no executable user rules or Sigma."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from casework import CaseStore
from evtxwork import EvtxError, MAX_EVENTS, _get_index

PACK_ID = 'windows-metadata-observations'
PACK_VERSION = '1.1.0'
RULES = (
    {'id': 'WIN-LOGON-FAILURE', 'channel': 'Security',
     'provider': 'Microsoft-Windows-Security-Auditing', 'event_id': 4625,
     'observation': 'logon_failure_record',
     'next_check': 'review_local_status_substatus_and_expected_logon_context',
     'reference': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625'},
    {'id': 'WIN-AUDIT-CLEARED', 'channel': 'Security',
     'provider': 'Microsoft-Windows-Eventlog', 'event_id': 1102,
     'observation': 'security_audit_log_cleared_record',
     'next_check': 'verify_operator_change_history_and_collection_gaps',
     'reference': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102'},
    {'id': 'WIN-SERVICE-TERMINATION', 'channel': 'System',
     'provider': 'Service Control Manager', 'event_id': 7031,
     'observation': 'service_termination_record',
     'next_check': 'review_local_service_details_and_expected_maintenance',
     'reference': 'https://learn.microsoft.com/en-us/troubleshoot/exchange/administration/frontend-transport-service-terminate-run-set-servercomponentstate'},
    {'id': 'WIN-LOGON-SUCCESS', 'channel': 'Security',
     'provider': 'Microsoft-Windows-Security-Auditing', 'event_id': 4624,
     'observation': 'logon_session_created_record',
     'next_check': 'verify_expected_logon_type_actor_and_authentication_context_locally',
     'reference': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624'},
)


def pack_digest() -> str:
    return hashlib.sha256(json.dumps(
        {'id': PACK_ID, 'version': PACK_VERSION, 'rules': RULES},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def report(store: CaseStore, case_id: str, artifact_id: str, *,
           pack: str = PACK_ID, offset: int = 0) -> dict[str, Any]:
    if type(pack) is not str or pack != PACK_ID:
        raise EvtxError('Unknown Windows metadata rule pack')
    if type(offset) is not int or not 0 <= offset < MAX_EVENTS:
        raise EvtxError('Invalid Windows rule report offset')
    db, facts = _get_index(store, case_id, artifact_id)
    try:
        channels = {row[0] for row in db.execute('SELECT DISTINCT channel FROM records')
                    if row[0] in ('System', 'Security', 'Application')}
        missing_channel = db.execute('SELECT COUNT(*) FROM records WHERE channel IS NULL').fetchone()[0]
        rule_rows = []
        predicates = []
        parameters: list[Any] = []
        for rule in RULES:
            args = (rule['channel'], rule['provider'], rule['event_id'])
            count = db.execute('SELECT COUNT(*) FROM records WHERE channel=? AND provider=? AND event_id=?', args).fetchone()[0]
            rule_rows.append({**rule, 'matches': count,
                'state': ('MATCHES_OBSERVED' if count else
                          'CHANNEL_NOT_OBSERVED' if rule['channel'] not in channels else
                          'NO_MATCHES_OBSERVED')})
            predicates.append('(channel=? AND provider=? AND event_id=?)')
            parameters.extend(args)
        matches = db.execute('SELECT record_num,event_id,provider,channel,utc FROM records WHERE ' +
                             ' OR '.join(predicates) + ' ORDER BY ordinal LIMIT 21 OFFSET ?',
                             (*parameters, offset)).fetchall()
        # Rows originate exclusively from the fixed tuple allowlist. Never echo
        # an arbitrary provider/channel or EventData from the private database.
        visible = []
        for record, event_id, provider, channel, utc in matches[:20]:
            if type(record) is not int or record < 0:
                raise EvtxError('Invalid Windows record reference')
            rule = next(r for r in RULES if (r['channel'], r['provider'], r['event_id']) ==
                        (channel, provider, event_id))
            visible.append({'artifact_id': artifact_id, 'locator_type': 'record',
                            'record': record, 'rule_id': rule['id'], 'event_id': event_id,
                            'channel': channel, 'utc': utc})
        # Revalidate original/index identity after scanning before publishing.
        checked, _ = _get_index(store, case_id, artifact_id)
        checked.close()
        return {'status': 'PARTIAL', 'case_id': case_id, 'artifact_id': artifact_id,
            'pack': PACK_ID, 'pack_version': PACK_VERSION, 'pack_sha256': pack_digest(),
            'parser': 'python-evtx', 'parser_version': facts['provider_version'],
            'rules': rule_rows, 'observed_channels': sorted(channels),
            'records_without_allowlisted_channel': missing_channel,
            'records_examined': int(facts['records_examined']),
            'records_skipped': int(facts['records_skipped']),
            'records_without_utc': int(facts['records_without_utc']),
            'matches': visible, 'offset': offset, 'has_more': len(matches) > 20,
            'next_offset': offset + 20 if len(matches) > 20 else None,
            'collection_completeness_verified': False, 'audit_policy_verified': False,
            'eventdata_evaluated': False, 'sigma_engine_available': False,
            'root_cause_established': False, 'malicious_activity_established': False,
            'source_integrity_basis': 'analysis_source_sha256_and_current_file_identity',
            'limitations': ['fixed_metadata_pack_only', 'no_clean_system_verdict',
                'absent_channel_is_missing_evidence', 'no_rule_evaluation_over_eventdata',
                'no_host_identity_or_clock_alignment', 'no_windows_server_version_attestation',
                'etl_registry_memory_dump_not_supported_by_evtx_adapter']}
    except (sqlite3.Error, ValueError, KeyError, StopIteration) as exc:
        raise EvtxError('Windows metadata rule report unavailable; rebuild EVTX index') from exc
    finally:
        db.close()
