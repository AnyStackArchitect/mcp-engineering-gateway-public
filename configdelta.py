#!/usr/bin/env python3
"""Bounded, private, source-hash-verified semantic configuration drift review.

Compares two operator-registered text artifacts by structure and value *type*,
without returning any configuration values, uncontrolled names, original source
paths, secrets, raw hashes or inferred change times. No configuration is written.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from typing import Any

from casework import CASE_ID, CaseError, CaseStore
from configwork import (_read_case_config, _duplicates, _parse_properties,
                        _safe_label, _validate_json_structure,
                        MAX_CONFIG_FIELDS, MAX_DEPTH)

VERSION = "1"
MAX_OFFSET = 10_000
MAX_PAGE = 20
MAX_ARRAY_ELEMENTS = 4096


def _signature(value: Any) -> tuple[str, str, str | None, int | None]:
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ELEMENTS:
            raise CaseError("Configuration array exceeds analysis limit")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False)
        # Sorting digests detects identical members in a different order;
        # identities or member values are never returned.
        each = [hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False).encode()).hexdigest() for v in value]
        multiset = hashlib.sha256(json.dumps(sorted(each),separators=(",",":")).encode()).hexdigest()
        return ("ARRAY",hashlib.sha256(canonical.encode()).hexdigest(),multiset,len(value))
    if isinstance(value, dict):
        if value:
            raise CaseError("Internal nonempty object must be flattened")
        return ("EMPTY_OBJECT", hashlib.sha256(b"{}").hexdigest(),None,None)
    kind = ("NULL" if value is None else "BOOLEAN" if isinstance(value,bool) else
            "NUMBER" if isinstance(value,(int,float)) else "STRING" if isinstance(value,str) else
            "UNSUPPORTED")
    if kind == "UNSUPPORTED":
        raise CaseError("Unsupported configuration value type")
    canonical=json.dumps(value,separators=(",",":"),ensure_ascii=True,allow_nan=False)
    return (kind,hashlib.sha256(canonical.encode()).hexdigest(),None,None)


def _flatten(value: Any) -> dict[tuple[str,...], tuple[str,str,str|None,int|None]]:
    _validate_json_structure(value)
    if not isinstance(value,dict):
        raise CaseError("Configuration root must be a JSON object")
    result: dict[tuple[str,...],tuple[str,str,str|None,int|None]]={}
    def walk(node:Any,path:tuple[str,...],depth:int)->None:
        if depth > MAX_DEPTH:
            raise CaseError("Configuration exceeds nesting depth limit")
        if isinstance(node,dict) and node:
            for key in sorted(node):
                if not isinstance(key,str) or len(key)>160:
                    raise CaseError("Unbounded or invalid configuration key")
                walk(node[key],(*path,key),depth+1)
            return
        if not path:
            return
        if len(result)>=MAX_CONFIG_FIELDS:
            raise CaseError("Configuration exceeds bounded field count")
        result[path]=_signature(node)
    walk(value,(),0)
    return result


def _decode(data: bytes, fmt: str) -> dict[tuple[str,...],tuple[str,str,str|None,int|None]]:
    try:
        text=data.decode("utf-8","strict")
    except UnicodeDecodeError as exc:
        raise CaseError("Configuration must use strict UTF-8") from exc
    if fmt=="properties":
        fields=_parse_properties(text)
        return {path:("STRING",digest,None,None) for path,digest in fields.items()}
    try:
        object_=json.loads(text,object_pairs_hook=_duplicates,
                           parse_constant=lambda _:(_ for _ in ()).throw(ValueError("nonfinite")))
        return _flatten(object_)
    except (ValueError,OverflowError,RecursionError) as exc:
        raise CaseError("Configuration JSON malformed or exceeds safe bounds") from exc


def report(store:CaseStore,case_id:str,before_artifact_id:str,after_artifact_id:str,*,
           fmt:str="json",offset:int=0,limit:int=20)->dict[str,Any]:
    if fmt not in ("json","properties") or type(fmt) is not str:
        raise CaseError("Unsupported configuration format")
    if (type(before_artifact_id) is not str or not CASE_ID.fullmatch(before_artifact_id)
            or type(after_artifact_id) is not str or not CASE_ID.fullmatch(after_artifact_id)
            or before_artifact_id==after_artifact_id):
        raise CaseError("Two distinct case artifact IDs required")
    if type(offset) is not int or not 0<=offset<=MAX_OFFSET:
        raise CaseError("Invalid configuration drift offset")
    if type(limit) is not int or not 1<=limit<=MAX_PAGE:
        raise CaseError("Invalid configuration drift page limit")
    # Source bytes are fully SHA-256 rehashed under the same per-case lock.
    # Registration time/mtime is NOT a trusted change or commit timestamp.
    with store._locked(case_id) as (folder,manifest):
        original=_read_case_config(store,folder,manifest,before_artifact_id)
        updated=_read_case_config(store,folder,manifest,after_artifact_id)
    left,right=_decode(original,fmt),_decode(updated,fmt)
    changes=[]
    totals:Counter[str]=Counter()
    all_keys=sorted(set(left)|set(right))
    for key in all_keys:
        a,b=left.get(key),right.get(key)
        if a==b:
            continue
        if a is None:
            kind="ADDED"
        elif b is None:
            kind="REMOVED"
        elif a[0]!=b[0]:
            kind="TYPE_CHANGED"
        elif a[0]=="ARRAY":
            if a[3]!=b[3]:
                kind="ARRAY_LENGTH_CHANGED"
            elif a[2]==b[2]:
                kind="ARRAY_ORDER_CHANGED"
            else:
                kind="ARRAY_CONTENT_CHANGED"
        else:
            kind="VALUE_CHANGED"
        totals[kind]+=1
        # The shared label helper consumes tagged internal paths. Raw input
        # keys beginning with "field:" must not impersonate safe field names.
        safe=_safe_label(tuple('field:' + component for component in key))
        # Key hashes are dictionary-attackable. Unknown field labels are
        # *report-local* ordinal aliases, not reusable public identifiers.
        alias=safe if not safe.startswith("field-") else "field-%04d" % (len(changes)+1)
        changes.append({"ordinal":len(changes)+1,"field":alias,
                        "change":kind,"type_before":a[0] if a else None,
                        "type_after":b[0] if b else None})
    visible=changes[offset:offset+limit]
    return {
        "status":"PASS","model_version":VERSION,
        "case_id":case_id,"format":fmt,
        "before_artifact_id":before_artifact_id,
        "after_artifact_id":after_artifact_id,
        "before_fields":len(left),"after_fields":len(right),
        "changed_fields":len(changes),
        "change_totals":dict(sorted(totals.items())),
        "offset":offset,"limit":limit,"results":visible,
        "next_offset":offset+limit if offset+limit<len(changes) else None,
        "has_more":offset+limit<len(changes),
        "values_exposed":False,"uncontrolled_key_names_exposed":False,
        "source_originals_sha256_verified":True,
        "change_time_verified":False,"clock_alignment_verified":False,
        "causality_established":False,
        "array_order_semantically_significant":None,
        "array_order_semantic_significance_verified":False,
        "no_live_configuration_polled":True,
        "limitations":["comparison_of_two_supplied_snapshots_only",
            "import_order_not_proven_change_order",
            "source_timestamps_not_trusted_change_times",
            "no_application_or_platform_semantic_equivalence_inferred",
            "configuration_value_and_sensitive_path_redaction",
            "result_pagination_is_not_partial_source_coverage"],
    }
