#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / 'tools'
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from shared.dataset_normalize import normalize_slice_function_names, normalized_code_md5
from shared.dataset_sources import (
    build_source_file_candidates,
    collect_defined_function_names,
    load_tree_sitter_parsers,
)
from shared.pairing import build_trace_priority_key
from shared.signatures import stable_signature_ref, stable_trace_ref
from shared.traces import extract_std_bug_trace

DEFAULT_RUN_DIR = REPO_ROOT / 'artifacts' / 'pipeline-runs' / 'run-2026.03.17-11:28:48'
DEFAULT_OUTPUT_ROOT = REPO_ROOT / 'experiments' / 'epic003' / 'outputs'
TOKENIZER_MODEL = 'microsoft/codebert-base'
MAX_LENGTH = 512
CONTENT_TOKEN_LIMIT = MAX_LENGTH - 2


@dataclass(frozen=True)
class StrictTraceRecord:
    testcase_key: str
    trace_file: Path
    best_flow_type: str
    bug_trace_length: int
    procedure: str | None


@dataclass(frozen=True)
class CandidateRow:
    trace_id: str
    testcase_key: str
    best_flow_type: str
    target: int
    trace_file: str
    bug_trace_length: int
    procedure: str | None
    normalized_code_hash: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Analyze trace-first row deltas from an existing pipeline run.'
    )
    parser.add_argument(
        '--run-dir',
        type=Path,
        default=DEFAULT_RUN_DIR,
        help='Existing pipeline run directory to analyze.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help='Directory to write summary.json and label_collisions.jsonl.',
    )
    return parser.parse_args()


def resolve_output_dir(run_dir: Path, output_dir: Path | None) -> Path:
    if output_dir is not None:
        return output_dir.resolve()
    return (DEFAULT_OUTPUT_ROOT / run_dir.name).resolve()


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f'{label} not found: {path}')
    if not path.is_file():
        raise FileNotFoundError(f'{label} is not a file: {path}')


def read_json(path: Path) -> Any:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for idx, row in enumerate(rows):
            if idx:
                f.write('\n')
            f.write(json.dumps(row, ensure_ascii=False))
        if rows:
            f.write('\n')


def read_strict_trace_records(path: Path) -> list[StrictTraceRecord]:
    records: list[StrictTraceRecord] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            testcase_key = str(obj.get('testcase_key') or '').strip()
            trace_file_raw = str(obj.get('trace_file') or '').strip()
            best_flow_type = str(obj.get('best_flow_type') or '').strip()
            if not testcase_key or not trace_file_raw or not best_flow_type:
                raise ValueError(f'Invalid strict trace record at line {lineno}: {obj}')
            records.append(
                StrictTraceRecord(
                    testcase_key=testcase_key,
                    trace_file=Path(trace_file_raw),
                    best_flow_type=best_flow_type,
                    bug_trace_length=int(obj.get('bug_trace_length', 0) or 0),
                    procedure=obj.get('procedure'),
                )
            )
    return records


def build_trace_id(record: StrictTraceRecord, signature_payload: dict[str, Any]) -> str:
    seed = '||'.join(
        [
            record.testcase_key,
            record.best_flow_type,
            str(record.bug_trace_length),
            str(record.procedure or ''),
            stable_signature_ref(signature_payload, record.trace_file),
            stable_trace_ref(record.trace_file),
        ]
    )
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]


def read_source_line(filepath: Path, line_number: int) -> str | None:
    try:
        with filepath.open('r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    except Exception:
        return None
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return None


def build_slice_content(std_bug_trace: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    slice_lines: list[str] = []
    seen: set[tuple[str, int]] = set()

    for node in std_bug_trace:
        filename = node.get('filename')
        line_number = int(node.get('line_number', 0) or 0)
        if not filename or line_number <= 0:
            return None, 'invalid_trace_node'

        file_path = Path(str(filename))
        key = (str(file_path), line_number)
        if key in seen:
            continue
        seen.add(key)

        source_line = read_source_line(file_path, line_number)
        if source_line is None:
            return None, 'missing_source_line'
        slice_lines.append(source_line)

    return ''.join(slice_lines), None


def load_signature_payload(path: Path) -> dict[str, Any]:
    require_file(path, 'signature JSON')
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f'Expected signature payload JSON object: {path}')
    return payload


def load_tokenizer():
    from transformers import RobertaTokenizer

    try:
        return RobertaTokenizer.from_pretrained(TOKENIZER_MODEL, local_files_only=True)
    except Exception:
        return RobertaTokenizer.from_pretrained(TOKENIZER_MODEL)


def count_code_tokens(tokenizer: object, code: str) -> int:
    return len(tokenizer.tokenize(str(code)))


def compute_baseline_summary(run_dir: Path) -> dict[str, Any]:
    pairs_jsonl = run_dir / '05_pair_trace_ds' / 'pairs.jsonl'
    csv_path = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    require_file(pairs_jsonl, 'pairs.jsonl')
    require_file(csv_path, 'Real_Vul_data.csv')

    with pairs_jsonl.open('r', encoding='utf-8') as f:
        pairs_total = sum(1 for line in f if line.strip())

    rows_total = 0
    rows_by_target: Counter[str] = Counter()
    with csv_path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows_total += 1
            rows_by_target[str(row.get('target') or '')] += 1

    return {
        'pairs_total': pairs_total,
        'rows_total': rows_total,
        'rows_by_target': dict(rows_by_target),
    }


def trace_sort_key(row: CandidateRow) -> tuple[Any, ...]:
    return (
        row.testcase_key,
        build_trace_priority_key(
            bug_trace_length=row.bug_trace_length,
            trace_file=row.trace_file,
            best_flow_type=row.best_flow_type,
            procedure=row.procedure,
        ),
        row.trace_id,
    )


def build_candidate_rows(
    strict_records: list[StrictTraceRecord],
) -> tuple[list[CandidateRow], Counter[str]]:
    print(f'Loading tokenizer: {TOKENIZER_MODEL}...')
    tokenizer = load_tokenizer()
    print('Loading tree-sitter parsers...')
    parsers = load_tree_sitter_parsers()

    source_func_cache: dict[str, set[str]] = {}
    filtered_by_reason: Counter[str] = Counter()
    candidates: list[CandidateRow] = []

    for index, record in enumerate(strict_records, start=1):
        if index % 1000 == 0:
            print(f'Processed {index}/{len(strict_records)} strict traces...')

        signature_payload = load_signature_payload(record.trace_file)
        trace_id = build_trace_id(record, signature_payload)

        std_bug_trace = extract_std_bug_trace(signature_payload.get('bug_trace', []))
        if not std_bug_trace:
            filtered_by_reason['empty_bug_trace'] += 1
            continue

        slice_content, slice_skip_reason = build_slice_content(std_bug_trace)
        if slice_content is None:
            filtered_by_reason[str(slice_skip_reason)] += 1
            continue

        primary_file_hint = str(signature_payload.get('file') or '') or None
        source_candidates = build_source_file_candidates(signature_payload, primary_file_hint)

        user_defined_function_names: set[str] = set()
        for source_path in source_candidates:
            source_key = str(source_path)
            if source_key not in source_func_cache:
                if source_path.exists():
                    names, _error = collect_defined_function_names(source_path, parsers)
                else:
                    names = set()
                source_func_cache[source_key] = names
            user_defined_function_names.update(source_func_cache[source_key])

        normalized_code, _placeholder_map, _replacements = normalize_slice_function_names(
            slice_content, user_defined_function_names
        )
        token_count = count_code_tokens(tokenizer, normalized_code)
        if token_count > CONTENT_TOKEN_LIMIT:
            filtered_by_reason['over_limit'] += 1
            continue

        candidates.append(
            CandidateRow(
                trace_id=trace_id,
                testcase_key=record.testcase_key,
                best_flow_type=record.best_flow_type,
                target=1 if record.best_flow_type == 'b2b' else 0,
                trace_file=str(record.trace_file),
                bug_trace_length=record.bug_trace_length,
                procedure=record.procedure,
                normalized_code_hash=normalized_code_md5(normalized_code),
            )
        )

    return candidates, filtered_by_reason


def dedupe_candidates(
    candidates: list[CandidateRow],
) -> tuple[list[CandidateRow], list[dict[str, Any]], Counter[str], dict[str, Any]]:
    ordered = sorted(candidates, key=trace_sort_key)
    rows_by_hash: dict[str, list[CandidateRow]] = defaultdict(list)
    for row in ordered:
        rows_by_hash[row.normalized_code_hash].append(row)

    collision_hashes = {
        code_hash
        for code_hash, rows in rows_by_hash.items()
        if len({row.target for row in rows}) > 1
    }

    kept_rows: list[CandidateRow] = []
    label_collisions: list[dict[str, Any]] = []
    filtered_by_reason: Counter[str] = Counter()
    kept_hashes: set[str] = set()

    for row in ordered:
        if row.normalized_code_hash in collision_hashes:
            filtered_by_reason['cross_label_collision'] += 1
            group = rows_by_hash[row.normalized_code_hash]
            label_collisions.append(
                {
                    'trace_id': row.trace_id,
                    'testcase_key': row.testcase_key,
                    'best_flow_type': row.best_flow_type,
                    'target': row.target,
                    'normalized_code_hash': row.normalized_code_hash,
                    'trace_file': row.trace_file,
                    'collision_group_size': len(group),
                    'collision_targets': sorted({int(candidate.target) for candidate in group}),
                }
            )
            continue

        if row.normalized_code_hash in kept_hashes:
            filtered_by_reason['same_label_duplicate'] += 1
            continue

        kept_hashes.add(row.normalized_code_hash)
        kept_rows.append(row)

    dedup_summary = {
        'same_label_duplicate_groups': sum(
            1
            for code_hash, rows in rows_by_hash.items()
            if code_hash not in collision_hashes and len(rows) > 1
        ),
        'same_label_duplicates_removed': int(filtered_by_reason['same_label_duplicate']),
        'cross_label_collision_groups': len(collision_hashes),
        'cross_label_collision_rows': int(filtered_by_reason['cross_label_collision']),
        'unique_hashes_total': len(rows_by_hash),
    }
    return kept_rows, label_collisions, filtered_by_reason, dedup_summary


def build_summary(
    *,
    run_dir: Path,
    output_dir: Path,
    baseline: dict[str, Any],
    strict_traces_total: int,
    pre_dedup_rows_total: int,
    kept_rows: list[CandidateRow],
    preprocessing_filtered: Counter[str],
    dedup_filtered: Counter[str],
    dedup_summary: dict[str, Any],
) -> dict[str, Any]:
    rows_by_target: Counter[str] = Counter(str(row.target) for row in kept_rows)
    filtered = Counter()
    filtered.update(preprocessing_filtered)
    filtered.update(dedup_filtered)

    return {
        'run_dir': str(run_dir),
        'baseline': baseline,
        'simulated': {
            'strict_traces_total': strict_traces_total,
            'rows_before_dedup': pre_dedup_rows_total,
            'rows_survived': len(kept_rows),
            'rows_by_target': dict(rows_by_target),
        },
        'filtered': {
            'by_reason': dict(filtered),
        },
        'dedup': dedup_summary,
        'delta': {
            'rows_total': len(kept_rows) - int(baseline['rows_total']),
        },
        'artifacts': {
            'label_collisions_jsonl': str(output_dir / 'label_collisions.jsonl'),
        },
    }


def print_console_summary(summary: dict[str, Any]) -> None:
    baseline = summary['baseline']
    simulated = summary['simulated']
    dedup = summary['dedup']
    print('')
    print(f'Run dir: {summary["run_dir"]}')
    print(f'Strict traces: {simulated["strict_traces_total"]}')
    print(f'Baseline pairs: {baseline["pairs_total"]}')
    print(f'Baseline CSV rows: {baseline["rows_total"]}')
    print(f'Simulated rows survived: {simulated["rows_survived"]}')
    print(f'Row delta: {summary["delta"]["rows_total"]:+d}')
    print(f'Same-label duplicates removed: {dedup["same_label_duplicates_removed"]}')
    print(f'Cross-label collision groups: {dedup["cross_label_collision_groups"]}')
    print(f'Cross-label collision rows: {dedup["cross_label_collision_rows"]}')
    print(f'Collision file: {summary["artifacts"]["label_collisions_jsonl"]}')


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    output_dir = resolve_output_dir(run_dir, args.output_dir)

    os.chdir(REPO_ROOT)

    strict_jsonl = run_dir / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    require_file(strict_jsonl, 'trace_flow_match_strict.jsonl')

    baseline = compute_baseline_summary(run_dir)
    strict_records = read_strict_trace_records(strict_jsonl)
    candidates, preprocessing_filtered = build_candidate_rows(strict_records)
    kept_rows, label_collisions, dedup_filtered, dedup_summary = dedupe_candidates(candidates)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / 'label_collisions.jsonl', label_collisions)
    summary = build_summary(
        run_dir=run_dir,
        output_dir=output_dir,
        baseline=baseline,
        strict_traces_total=len(strict_records),
        pre_dedup_rows_total=len(candidates),
        kept_rows=kept_rows,
        preprocessing_filtered=preprocessing_filtered,
        dedup_filtered=dedup_filtered,
        dedup_summary=dedup_summary,
    )
    write_json(output_dir / 'summary.json', summary)
    print_console_summary(summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
