"""Read-only clock-offset sensitivity model; operator assumptions are unverified."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import heapq
import json
import sqlite3
from typing import Any

from casework import CASE_ID, CaseError, CaseStore
from correlationwork import (REVISION, MAX_CORRELATED_EVENTS, MAX_QUERY_OFFSET,
                             _checked_correlation)
from eventmodel import (MODEL_VERSION, MAX_WINDOW_MS, checked_time_basis,
                        parse_declared_utc, observed_delta_ms)

MAX_SOURCE_MODELS = 8
MAX_OFFSET_MS = 3_600_000


def _declarations(values: Any) -> dict[str, dict[str, int]]:
    if type(values) is not list or not 2 <= len(values) <= MAX_SOURCE_MODELS:
        raise CaseError('Declare two to eight source clock assumptions')
    result = {}
    for value in values:
        if type(value) is not dict or set(value) != {'artifact_id', 'offset_to_add_ms', 'uncertainty_ms'}:
            raise CaseError('Clock declaration fields invalid')
        aid, shift, uncertainty = (value['artifact_id'], value['offset_to_add_ms'], value['uncertainty_ms'])
        if (type(aid) is not str or not CASE_ID.fullmatch(aid) or aid in result or
                type(shift) is not int or not -MAX_OFFSET_MS <= shift <= MAX_OFFSET_MS or
                type(uncertainty) is not int or not 0 <= uncertainty <= MAX_WINDOW_MS):
            raise CaseError('Clock declaration identity or bounds invalid')
        result[aid] = {'offset_to_add_ms': shift, 'uncertainty_ms': uncertainty}
    return result


def adjusted_window(store: CaseStore, case_id: str, *, index_revision: str,
                    anchor_event_id: int, source_clocks: list[dict],
                    before_ms: int = 5000, after_ms: int = 5000,
                    offset: int = 0, limit: int = 20) -> dict[str, Any]:
    models = _declarations(source_clocks)
    if type(index_revision) is not str or not REVISION.fullmatch(index_revision):
        raise CaseError('Invalid correlation revision')
    if type(anchor_event_id) is not int or not 1 <= anchor_event_id <= MAX_CORRELATED_EVENTS:
        raise CaseError('Invalid correlation anchor event')
    if (type(before_ms) is not int or type(after_ms) is not int or
            not 0 <= before_ms <= MAX_WINDOW_MS or not 0 <= after_ms <= MAX_WINDOW_MS):
        raise CaseError('Clock-model window duration invalid')
    if type(offset) is not int or not 0 <= offset <= MAX_QUERY_OFFSET:
        raise CaseError('Clock-model window offset invalid')
    if type(limit) is not int or not 1 <= limit <= 20:
        raise CaseError('Clock-model window page limit invalid')
    with store._locked(case_id) as (folder, manifest):
        db, facts = _checked_correlation(folder, manifest)
        try:
            if facts.get('index_revision') != index_revision or facts.get('model_version') != MODEL_VERSION:
                raise CaseError('Clock model event revision stale')
            sources = {row['artifact_id'] for row in db.execute('SELECT artifact_id FROM sources')}
            if not set(models) <= sources:
                raise CaseError('Clock declaration source not present in pinned index')
            anchor = db.execute('''SELECT id AS event_id,artifact_id,kind,utc,time_quality,
                time_basis,locator_type,locator_number FROM events WHERE id=?''', (anchor_event_id,)).fetchone()
            if anchor is None or anchor['utc'] is None:
                raise CaseError('A timed source event is required as model anchor')
            if anchor['artifact_id'] not in models:
                raise CaseError('Anchor source clock declaration required')
            if checked_time_basis(anchor['utc'], anchor['time_quality']) != anchor['time_basis']:
                raise CaseError('Clock-model anchor quality inconsistent')
            anchor_model = models[anchor['artifact_id']]
            try:
                adjusted_anchor = parse_declared_utc(anchor['utc']) + timedelta(milliseconds=anchor_model['offset_to_add_ms'])
                window_start = adjusted_anchor - timedelta(milliseconds=before_ms)
                window_end = adjusted_anchor + timedelta(milliseconds=after_ms)
            except OverflowError as exc:
                raise CaseError('Clock model exceeds representable UTC') from exc
            counts = {'matching': 0, 'scanned': 0}

            def candidates():
                for aid, model in sorted(models.items()):
                    if aid == anchor['artifact_id']:
                        continue
                    uncertainty = anchor_model['uncertainty_ms'] + model['uncertainty_ms']
                    try:
                        low = window_start - timedelta(milliseconds=uncertainty + model['offset_to_add_ms'])
                        high = window_end + timedelta(milliseconds=uncertainty - model['offset_to_add_ms'])
                    except OverflowError as exc:
                        raise CaseError('Clock model source range exceeds UTC bounds') from exc
                    rows = db.execute('''SELECT id AS event_id,artifact_id,kind,utc,time_quality,
                        time_basis,locator_type,locator_number FROM events
                        WHERE artifact_id=? AND utc>=? AND utc<=? ORDER BY id''',
                        (aid, low.isoformat(timespec='microseconds'), high.isoformat(timespec='microseconds')))
                    for row in rows:
                        counts['scanned'] += 1
                        if counts['scanned'] > MAX_CORRELATED_EVENTS:
                            raise CaseError('Clock model event scan exceeds fixed bound')
                        if checked_time_basis(row['utc'], row['time_quality']) != row['time_basis']:
                            raise CaseError('Clock model source quality inconsistent')
                        try:
                            shifted = parse_declared_utc(row['utc']) + timedelta(milliseconds=model['offset_to_add_ms'])
                        except OverflowError as exc:
                            raise CaseError('Clock model event exceeds UTC bounds') from exc
                        modeled = shifted.isoformat(timespec='microseconds')
                        delta = observed_delta_ms(adjusted_anchor.isoformat(timespec='microseconds'), modeled)
                        if delta + uncertainty < -before_ms or delta - uncertainty > after_ms:
                            continue
                        counts['matching'] += 1
                        yield {**dict(row), 'modeled_utc': modeled,
                            'source_observed_delta_ms': observed_delta_ms(anchor['utc'], row['utc']),
                            'modeled_delta_ms': delta,
                            'declared_delta_uncertainty_ms': uncertainty,
                            'membership': 'MODELED_CENTER_INSIDE' if -before_ms <= delta <= after_ms else 'DECLARED_UNCERTAINTY_OVERLAP_ONLY'}

            ordered = heapq.nsmallest(offset + limit + 1, candidates(), key=lambda row:
                (row['modeled_utc'], row['kind'], row['artifact_id'], row['locator_number'], row['event_id']))
            slots = ','.join('?' for _ in models)
            unknown = db.execute(f'SELECT COUNT(*) FROM events WHERE utc IS NULL AND artifact_id IN ({slots})',
                                 tuple(models)).fetchone()[0]
            declarations = [{'artifact_id': aid, **model} for aid, model in sorted(models.items())]
            plan = {'case_id': case_id, 'index_revision': index_revision, 'anchor_event_id': anchor_event_id,
                    'source_clocks': declarations, 'before_ms': before_ms, 'after_ms': after_ms}
            more = counts['matching'] > offset + limit
            next_page = offset + limit
            pagination_limited = more and next_page > MAX_QUERY_OFFSET
            return {'status': 'PARTIAL', 'case_id': case_id, 'index_revision': index_revision,
                'model': 'OPERATOR_DECLARED_CLOCK_SENSITIVITY_V1',
                'model_sha256': hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'source_clocks': declarations, 'anchor': dict(anchor),
                'modeled_anchor_utc': adjusted_anchor.isoformat(timespec='microseconds'),
                'modeled_window_start_utc': window_start.isoformat(timespec='microseconds'),
                'modeled_window_end_utc': window_end.isoformat(timespec='microseconds'),
                'before_ms': before_ms, 'after_ms': after_ms,
                'offset': offset, 'limit': limit, 'matching_events_in_declared_model': counts['matching'],
                'events': ordered[offset:offset + limit],
                'next_offset': next_page if more and not pagination_limited else None,
                'has_more': more and not pagination_limited,
                'pagination_bound_reached': pagination_limited,
                'more_matching_events_outside_pagination_bound': pagination_limited,
                'maximum_page_offset': MAX_QUERY_OFFSET,
                'selected_sources_unknown_utc_events': unknown,
                'unselected_source_count': len(sources - set(models)),
                'missing_indexes': int(facts['missing_indexes']),
                'excluded_artifacts': int(facts['excluded_artifacts']),
                'clock_offsets_applied_to_model': True, 'original_source_times_modified': False,
                'declared_uncertainty_verified': False, 'clock_alignment_verified': False,
                'cross_source_identity_inferred': False, 'causality_inferred': False,
                'limitations': ['operator_assumptions_not_verified_measurements',
                    'uncertainty_bounds_are_declared_not_proven', 'selected_sources_only',
                    'untimed_events_excluded_not_synthetically_anchored',
                    'cross_source_adjacency_is_not_event_order_or_causality']}
        except sqlite3.Error as exc:
            raise CaseError('Clock-model source index invalid') from exc
        finally:
            db.close()
