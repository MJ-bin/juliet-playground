from __future__ import annotations

import csv
import json

from tests.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    write_json,
    write_jsonl,
    write_text,
)


def test_trace_dataset_export_prunes_multi_b2b_and_writes_trace_split_manifest(
    tmp_path,
    monkeypatch,
):
    module = load_module_from_path(
        'test_stage07_trace_dataset_export',
        REPO_ROOT / 'tools/stage/stage07_trace_dataset_export.py',
    )

    monkeypatch.setattr(module, 'build_source_file_candidates', lambda payload, hint: [])
    monkeypatch.setattr(
        module, 'collect_defined_function_names', lambda path, parsers: (set(), None)
    )
    monkeypatch.setattr(module, 'load_tree_sitter_parsers', lambda: {})

    sig_dir = tmp_path / 'signatures'
    slice_dir = tmp_path / 'slice'
    output_dir = tmp_path / 'out'
    sig_dir.mkdir()
    slice_dir.mkdir()

    trace_rows = []
    for trace_id in [
        'b2b-long',
        'b2b-short',
        'cp-one',
        'cp-two',
        'cp-dup',
        'collide-bad',
        'collide-good',
    ]:
        signature_path = sig_dir / f'{trace_id}.json'
        write_json(signature_path, {'file': ''})
        trace_rows.append(
            {
                'trace_id': trace_id,
                'testcase_key': {
                    'b2b-long': 'CASE1',
                    'b2b-short': 'CASE1',
                    'cp-one': 'CASE1',
                    'cp-two': 'CASE1',
                    'cp-dup': 'CASE2',
                    'collide-bad': 'CASE3',
                    'collide-good': 'CASE4',
                }[trace_id],
                'best_flow_type': {
                    'b2b-long': 'b2b',
                    'b2b-short': 'b2b',
                    'cp-one': 'g2b',
                    'cp-two': 'g2b2',
                    'cp-dup': 'g2b',
                    'collide-bad': 'b2b',
                    'collide-good': 'g2b',
                }[trace_id],
                'target': {
                    'b2b-long': 1,
                    'b2b-short': 1,
                    'cp-one': 0,
                    'cp-two': 0,
                    'cp-dup': 0,
                    'collide-bad': 1,
                    'collide-good': 0,
                }[trace_id],
                'trace_file': str(signature_path),
                'bug_trace_length': {
                    'b2b-long': 7,
                    'b2b-short': 3,
                    'cp-one': 2,
                    'cp-two': 4,
                    'cp-dup': 5,
                    'collide-bad': 6,
                    'collide-good': 1,
                }[trace_id],
                'procedure': 'demo_proc',
            }
        )

    write_jsonl(tmp_path / 'traces.jsonl', trace_rows)

    write_text(slice_dir / 'slice_b2b-long.c', 'bad_long();\n')
    write_text(slice_dir / 'slice_b2b-short.c', 'bad_short();\n')
    write_text(slice_dir / 'slice_cp-one.c', 'good_one();\n')
    write_text(slice_dir / 'slice_cp-two.c', 'good_two();\n')
    write_text(slice_dir / 'slice_cp-dup.c', 'good_one();\n')
    write_text(slice_dir / 'slice_collide-bad.c', 'shared();\n')
    write_text(slice_dir / 'slice_collide-good.c', 'shared();\n')

    with deterministic_tokenizer_context():
        module.export_trace_dataset_from_pipeline(
            traces_jsonl=tmp_path / 'traces.jsonl',
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    with (output_dir / 'summary.json').open('r', encoding='utf-8') as f:
        summary = json.load(f)
    with (output_dir / 'split_manifest.json').open('r', encoding='utf-8') as f:
        split_manifest = json.load(f)
    with (output_dir / 'Real_Vul_data.csv').open('r', encoding='utf-8', newline='') as f:
        csv_rows = list(csv.DictReader(f))
    dropped_rows = [
        json.loads(line)
        for line in (output_dir / 'trace_dedup_dropped.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
        if line.strip()
    ]

    assert split_manifest['counts']['traces_total'] == 3
    assert split_manifest['counts']['train_val_traces'] == 3
    assert split_manifest['trace_ids']['train_val'] == ['b2b-short', 'cp-one', 'cp-two']
    assert split_manifest['testcase_keys']['train_val'] == ['CASE1']
    assert 'pair_ids' not in split_manifest

    assert summary['stats']['counts']['traces_total'] == 7
    assert summary['stats']['counts']['traces_survived'] == 3
    assert summary['stats']['filtered_trace_reasons'] == {
        'same_label_duplicate': 1,
        'cross_label_collision': 2,
        'multi_b2b_pruned': 1,
    }
    assert summary['stats']['structural_pruning']['b2b_rows_pruned'] == 1

    assert len(csv_rows) == 3
    assert [row['target'] for row in csv_rows] == ['1', '0', '0']
    assert {row['drop_reason'] for row in dropped_rows} == {
        'same_label_duplicate',
        'cross_label_collision',
        'multi_b2b_pruned',
    }
