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
