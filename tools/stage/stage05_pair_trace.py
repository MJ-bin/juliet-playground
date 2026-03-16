from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_pair_trace_paths, path_strings
from shared.fs import prepare_output_dir
from shared.jsonio import write_json, write_jsonl, write_stage_summary
from shared.pairing import build_trace_priority_key, make_pair_id
from shared.paths import RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir
from shared.signatures import load_signature_payload

COUNTERPART_FLOW_TYPES = {
    'g2b',
    'g2b1',
    'g2b2',
    'b2g',
    'b2g1',
    'b2g2',
}


@dataclass(frozen=True)
class StrictTraceRecord:
    testcase_key: str
    trace_file: Path
    best_flow_type: str
    bug_trace_length: int
    procedure: str | None
    raw: dict[str, Any]


def infer_run_dir_from_trace_jsonl(trace_jsonl: Path) -> Path | None:
    if trace_jsonl.name != 'trace_flow_match_strict.jsonl':
        return None
    if trace_jsonl.parent.name != '04_trace_flow':
        return None
    return trace_jsonl.parent.parent


def resolve_paths(
    *,
    trace_jsonl: Path | None = None,
    output_dir: Path | None = None,
    pipeline_root: Path = Path(RESULT_DIR) / 'pipeline-runs',
    run_dir: Path | None = None,
) -> tuple[Path, Path, Path | None]:
    resolved_run_dir = run_dir.resolve() if run_dir is not None else None

    if trace_jsonl is None:
        if resolved_run_dir is None:
            resolved_run_dir = find_latest_pipeline_run_dir(pipeline_root.resolve())
        resolved_trace_jsonl = resolved_run_dir / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    else:
        resolved_trace_jsonl = trace_jsonl.resolve()
        if resolved_run_dir is None:
            resolved_run_dir = infer_run_dir_from_trace_jsonl(resolved_trace_jsonl)

    if output_dir is None:
        if resolved_run_dir is None:
            raise ValueError(
                '--output-dir is required when --trace-jsonl is outside the standard '
                'pipeline run layout.'
            )
        resolved_output_dir = resolved_run_dir / '05_pair_trace_ds'
    else:
        resolved_output_dir = output_dir.resolve()

    return resolved_trace_jsonl, resolved_output_dir, resolved_run_dir


def validate_args(trace_jsonl: Path) -> None:
    if not trace_jsonl.exists():
        raise FileNotFoundError(f'Strict trace JSONL not found: {trace_jsonl}')
    if not trace_jsonl.is_file():
        raise FileNotFoundError(f'Strict trace JSONL is not a file: {trace_jsonl}')


def load_strict_records(trace_jsonl: Path) -> list[StrictTraceRecord]:
    records: list[StrictTraceRecord] = []
    with trace_jsonl.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            testcase_key = (obj.get('testcase_key') or '').strip()
            trace_file_raw = (obj.get('trace_file') or '').strip()
            best_flow_type = (obj.get('best_flow_type') or '').strip()
            if not testcase_key or not trace_file_raw or not best_flow_type:
                raise ValueError(f'Missing required keys at line {lineno} in {trace_jsonl}: {obj}')
            records.append(
                StrictTraceRecord(
                    testcase_key=testcase_key,
                    trace_file=Path(trace_file_raw),
                    best_flow_type=best_flow_type,
                    bug_trace_length=int(obj.get('bug_trace_length', 0) or 0),
                    procedure=obj.get('procedure'),
                    raw=obj,
                )
            )
    return records


def group_by_testcase(records: list[StrictTraceRecord]) -> dict[str, list[StrictTraceRecord]]:
    grouped: dict[str, list[StrictTraceRecord]] = defaultdict(list)
    for record in records:
        grouped[record.testcase_key].append(record)
    return grouped


def record_sort_key(record: StrictTraceRecord) -> tuple[Any, ...]:
    return build_trace_priority_key(
        bug_trace_length=record.bug_trace_length,
        trace_file=str(record.trace_file),
        best_flow_type=record.best_flow_type,
        procedure=record.procedure,
    )


def select_best_record(records: list[StrictTraceRecord]) -> StrictTraceRecord | None:
    if not records:
        return None
    return sorted(records, key=record_sort_key)[0]


def _build_pair_record(
    *,
    pair_id: str,
    testcase_key: str,
    counterpart_flow_type: str,
    b2b_path: Path,
    counterpart_path: Path,
) -> dict[str, str]:
    return {
        'pair_id': pair_id,
        'testcase_key': testcase_key,
        'counterpart_flow_type': counterpart_flow_type,
        'b2b_path': str(b2b_path),
        'counterpart_path': str(counterpart_path),
    }


def build_paired_trace_dataset(
    *,
    trace_jsonl: Path,
    output_dir: Path,
    overwrite: bool = False,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    validate_args(trace_jsonl)
    prepare_output_dir(output_dir, overwrite)

    pair_paths = build_pair_trace_paths(output_dir)
    paired_signatures_dir = pair_paths['paired_signatures_dir']
    paired_signatures_dir.mkdir(parents=True, exist_ok=True)

    strict_records = load_strict_records(trace_jsonl)
    grouped = group_by_testcase(strict_records)

    pair_candidates: list[dict[str, Any]] = []
    summary_counter = Counter()
    counterpart_flow_counter = Counter()

    for testcase_key, records in sorted(grouped.items()):
        summary_counter['testcases_total'] += 1

        b2b_records = [record for record in records if record.best_flow_type == 'b2b']
        counterpart_records = [
            record for record in records if record.best_flow_type in COUNTERPART_FLOW_TYPES
        ]

        if not b2b_records:
            summary_counter['testcases_without_b2b'] += 1
            continue
        if not counterpart_records:
            summary_counter['testcases_without_counterpart'] += 1
            continue

        selected_b2b = select_best_record(b2b_records)
        assert selected_b2b is not None
        sorted_counterparts = sorted(counterpart_records, key=record_sort_key)
        selected_counterpart = sorted_counterparts[0]

        pair_candidates.append(
            {
                'testcase_key': testcase_key,
                'b2b': selected_b2b,
                'counterpart': selected_counterpart,
                'leftovers': sorted_counterparts[1:],
            }
        )
        counterpart_flow_counter[selected_counterpart.best_flow_type] += 1

    final_pairs: list[dict[str, str]] = []
    leftovers: list[dict[str, Any]] = []
    for pair in pair_candidates:
        testcase_key = str(pair['testcase_key'])
        b2b_record: StrictTraceRecord = pair['b2b']
        counterpart_record: StrictTraceRecord = pair['counterpart']

        b2b_payload = load_signature_payload(b2b_record.trace_file)
        counterpart_payload = load_signature_payload(counterpart_record.trace_file)
        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_payload=b2b_payload,
            b2b_trace_file=str(b2b_record.trace_file),
            b2b_flow_type=b2b_record.best_flow_type,
            counterpart_payload=counterpart_payload,
            counterpart_trace_file=str(counterpart_record.trace_file),
            counterpart_flow_type=counterpart_record.best_flow_type,
        )

        testcase_dir = paired_signatures_dir / testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)
        b2b_output_path = testcase_dir / 'b2b.json'
        counterpart_output_path = testcase_dir / f'{counterpart_record.best_flow_type}.json'

        write_json(b2b_output_path, b2b_payload)
        write_json(counterpart_output_path, counterpart_payload)
        final_pairs.append(
            _build_pair_record(
                pair_id=pair_id,
                testcase_key=testcase_key,
                counterpart_flow_type=counterpart_record.best_flow_type,
                b2b_path=b2b_output_path,
                counterpart_path=counterpart_output_path,
            )
        )

        for leftover in pair['leftovers']:
            leftovers.append(
                {
                    'testcase_key': testcase_key,
                    'trace_file': str(leftover.trace_file),
                    'best_flow_type': leftover.best_flow_type,
                    'bug_trace_length': leftover.bug_trace_length,
                }
            )

    write_jsonl(pair_paths['pairs_jsonl'], final_pairs)
    write_jsonl(pair_paths['leftover_counterparts_jsonl'], leftovers)

    artifacts = path_strings(pair_paths)
    stats = {
        'records_total': len(strict_records),
        'paired_testcases': len(final_pairs),
        'leftover_counterparts': len(leftovers),
        'selected_counterpart_flow_counts': dict(counterpart_flow_counter),
    }
    write_stage_summary(pair_paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}
