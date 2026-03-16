from __future__ import annotations

import hashlib
from typing import Any

from shared.signatures import stable_signature_ref, stable_trace_ref


def build_trace_priority_key(
    *,
    bug_trace_length: int,
    trace_file: str,
    best_flow_type: str,
    procedure: str | None,
) -> tuple[Any, ...]:
    return (
        -int(bug_trace_length or 0),
        stable_trace_ref(trace_file),
        str(best_flow_type or ''),
        str(procedure or ''),
    )


def make_pair_id(
    *,
    testcase_key: str,
    b2b_payload: dict[str, Any],
    b2b_trace_file: str,
    b2b_flow_type: str,
    counterpart_payload: dict[str, Any],
    counterpart_trace_file: str,
    counterpart_flow_type: str,
    dataset_namespace: str | None = None,
) -> str:
    seed_parts = [
        testcase_key,
        b2b_flow_type,
        stable_signature_ref(b2b_payload, b2b_trace_file),
        counterpart_flow_type,
        stable_signature_ref(counterpart_payload, counterpart_trace_file),
    ]
    if dataset_namespace:
        seed_parts.append(dataset_namespace)
    seed = '||'.join(seed_parts)
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]


def build_signature_meta(
    *,
    payload: dict[str, Any],
    trace_file: str,
    best_flow_type: str,
    bug_trace_length: int,
    procedure: str | None = None,
    primary_file: str | None = None,
    primary_line: int | None = None,
) -> dict[str, Any]:
    return {
        'trace_file': str(trace_file),
        'best_flow_type': str(best_flow_type),
        'bug_trace_length': int(bug_trace_length or 0),
        'procedure': procedure,
        'primary_file': primary_file,
        'primary_line': primary_line,
        'signature_key': payload.get('key'),
        'signature_hash': payload.get('hash'),
    }


def build_pairing_meta(
    *,
    pair_id: str,
    testcase_key: str,
    role: str,
    selection_reason: str,
    trace_file: str,
    best_flow_type: str,
    bug_trace_length: int,
    source_primary_pair_id: str | None = None,
    leftover_rank: int | None = None,
    leftover_candidates_total: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'pair_id': pair_id,
        'testcase_key': testcase_key,
        'role': role,
        'selection_reason': selection_reason,
        'trace_file': str(trace_file),
        'best_flow_type': str(best_flow_type),
        'bug_trace_length': int(bug_trace_length or 0),
    }
    if source_primary_pair_id is not None:
        payload['source_primary_pair_id'] = source_primary_pair_id
    if leftover_rank is not None:
        payload['leftover_rank'] = leftover_rank
    if leftover_candidates_total is not None:
        payload['leftover_candidates_total'] = leftover_candidates_total
    return payload
