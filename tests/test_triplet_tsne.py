from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pytest

from tests.helpers import REPO_ROOT, load_module_from_path


def _write_source_csv(
    path: Path,
    *,
    project: str,
    test_rows: list[tuple[str, int, str]],
    include_train_row: bool = False,
) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
    rows: list[dict[str, str]] = []
    if include_train_row:
        rows.append(
            {
                'file_name': 'train',
                'unique_id': 'train',
                'target': '1',
                'vulnerable_line_numbers': '7',
                'project': project,
                'source_signature_path': 'sig-train.json',
                'commit_hash': 'train-hash',
                'dataset_type': 'train_val',
                'processed_func': 'int train_only(void) { return 1; }',
            }
        )
    for unique_id, target, processed_func in test_rows:
        rows.append(
            {
                'file_name': unique_id,
                'unique_id': unique_id,
                'target': str(target),
                'vulnerable_line_numbers': '11' if target == 1 else '',
                'project': project,
                'source_signature_path': f'{unique_id}.json',
                'commit_hash': f'commit-{unique_id}',
                'dataset_type': 'test',
                'processed_func': processed_func,
            }
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_pdbert_prediction_csv(path: Path) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'dataset_type',
        'model_predict',
        'confusion_matrix',
    ]
    rows = [
        {
            'file_name': 'train',
            'unique_id': 'train',
            'target': '1',
            'dataset_type': 'train_val',
            'model_predict': '',
            'confusion_matrix': '',
        },
        {
            'file_name': 'j0',
            'unique_id': 'j0',
            'target': '0',
            'dataset_type': 'test',
            'model_predict': '0',
            'confusion_matrix': 'TN',
        },
        {
            'file_name': 'j1',
            'unique_id': 'j1',
            'target': '1',
            'dataset_type': 'test',
            'model_predict': '1',
            'confusion_matrix': 'TP',
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_linevul_prediction_csv(path: Path, *, rows: list[tuple[int, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['label', 'pred'])
        writer.writeheader()
        for label, pred in rows:
            writer.writerow({'label': str(label), 'pred': str(pred)})


def _write_feature_npz(path: Path, *, features: list[list[float]], labels: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        features=np.asarray(features, dtype=np.float32),
        labels=np.asarray(labels, dtype=np.int64),
    )


def _load_points_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def test_export_triplet_tsne_writes_image_cache_and_point_manifest(tmp_path):
    module = load_module_from_path(
        'test_triplet_tsne_export',
        REPO_ROOT / 'tools/shared/triplet_tsne.py',
    )

    juliet_csv = tmp_path / 'datasets' / 'juliet.csv'
    cve_csv = tmp_path / 'datasets' / 'cve.csv'
    _write_source_csv(
        juliet_csv,
        project='Juliet',
        include_train_row=True,
        test_rows=[
            ('j0', 0, 'int juliet_good(void) { return 0; }'),
            ('j1', 1, 'int juliet_bad(void) { return 1; }'),
        ],
    )
    _write_source_csv(
        cve_csv,
        project='CVEProject',
        test_rows=[
            ('c0', 0, 'int cve_patch(void) { return 0; }'),
            ('c1', 1, 'int cve_vuln(void) { return 1; }'),
        ],
    )

    juliet_npz = tmp_path / 'features' / 'juliet_after.npz'
    cve_before_npz = tmp_path / 'features' / 'cve_before.npz'
    cve_after_npz = tmp_path / 'features' / 'cve_after.npz'
    _write_feature_npz(
        juliet_npz,
        features=[[-3.0, -3.0, -3.0, -3.0], [3.0, 3.0, 3.0, 3.0]],
        labels=[0, 1],
    )
    _write_feature_npz(
        cve_before_npz,
        features=[[-2.0, 2.0, -2.0, 2.0], [2.0, -2.0, 2.0, -2.0]],
        labels=[0, 1],
    )
    _write_feature_npz(
        cve_after_npz,
        features=[[-1.0, -1.0, 1.0, 1.0], [1.0, 1.0, -1.0, -1.0]],
        labels=[0, 1],
    )

    juliet_pred_csv = tmp_path / 'pred' / 'juliet_eval_result.csv'
    cve_before_pred_csv = tmp_path / 'pred' / 'cve_before_test_pred.csv'
    _write_pdbert_prediction_csv(juliet_pred_csv)
    _write_linevul_prediction_csv(cve_before_pred_csv, rows=[(0, 1), (1, 0)])

    request = module.TripletTSNERequest(
        model_name='PDBERT',
        plot_title='PDBERT Triplet t-SNE on Juliet/CVE Trace Pair',
        output_dir=tmp_path / 'triplet-output',
        cohorts=(
            module.TripletCohortSpec(
                cohort_key='juliet_after_fine_tuned',
                feature_npz_path=juliet_npz,
                source_csv_path=juliet_csv,
                prediction_csv_path=juliet_pred_csv,
                prediction_kind=module.PDBERT_PREDICTION_KIND,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_before_fine_tuned',
                feature_npz_path=cve_before_npz,
                source_csv_path=cve_csv,
                prediction_csv_path=cve_before_pred_csv,
                prediction_kind=module.LINEVUL_PREDICTION_KIND,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_after_fine_tuned',
                feature_npz_path=cve_after_npz,
                source_csv_path=cve_csv,
            ),
        ),
        overwrite=False,
    )

    result = module.export_triplet_tsne(request)

    assert result.image_path.exists()
    assert result.cache_path.exists()
    assert result.points_jsonl_path.exists()

    cache_payload = json.loads(result.cache_path.read_text(encoding='utf-8'))
    assert set(cache_payload) >= {
        'embedding',
        'labels',
        'cohort_source',
        'cohort_names',
        'class_names',
        'feature_paths',
        'source_csv_paths',
        'points_jsonl',
    }
    assert len(cache_payload['embedding']) == 6
    assert cache_payload['cohort_names']['juliet_after_fine_tuned'] == 'Juliet / After Fine-tuned'
    assert cache_payload['class_names']['0'] == 'Patched (Non-Vulnerable)'

    point_rows = _load_points_jsonl(result.points_jsonl_path)
    assert len(point_rows) == 6
    assert {row['cohort_key'] for row in point_rows} == {
        'juliet_after_fine_tuned',
        'cve_before_fine_tuned',
        'cve_after_fine_tuned',
    }
    assert {row['class_value'] for row in point_rows} == {0, 1}
    assert point_rows[0]['processed_func_excerpt'].startswith('int juliet_good')

    juliet_row = next(row for row in point_rows if row['unique_id'] == 'j0')
    assert juliet_row['prediction'] == 0
    assert juliet_row['confusion_matrix'] == 'TN'

    cve_before_row = next(
        row
        for row in point_rows
        if row['cohort_key'] == 'cve_before_fine_tuned' and row['unique_id'] == 'c0'
    )
    assert cve_before_row['prediction'] == 1
    assert cve_before_row['confusion_matrix'] == 'FP'

    cve_after_row = next(
        row
        for row in point_rows
        if row['cohort_key'] == 'cve_after_fine_tuned' and row['unique_id'] == 'c1'
    )
    assert cve_after_row['prediction'] is None
    assert cve_after_row['confusion_matrix'] is None


def test_export_triplet_tsne_requires_both_classes_per_cohort(tmp_path):
    module = load_module_from_path(
        'test_triplet_tsne_requires_both_classes',
        REPO_ROOT / 'tools/shared/triplet_tsne.py',
    )

    juliet_csv = tmp_path / 'datasets' / 'juliet.csv'
    cve_csv = tmp_path / 'datasets' / 'cve.csv'
    _write_source_csv(
        juliet_csv,
        project='Juliet',
        test_rows=[
            ('j0', 0, 'int juliet_good(void) { return 0; }'),
            ('j1', 1, 'int juliet_bad(void) { return 1; }'),
        ],
    )
    _write_source_csv(
        cve_csv,
        project='CVEProject',
        test_rows=[
            ('c0', 0, 'int cve_patch(void) { return 0; }'),
            ('c1', 1, 'int cve_vuln(void) { return 1; }'),
        ],
    )
    invalid_cve_csv = tmp_path / 'datasets' / 'cve_invalid.csv'
    _write_source_csv(
        invalid_cve_csv,
        project='CVEProject',
        test_rows=[
            ('c0bad', 1, 'int cve_invalid_one(void) { return 1; }'),
            ('c1bad', 1, 'int cve_invalid_two(void) { return 1; }'),
        ],
    )

    _write_feature_npz(
        tmp_path / 'features' / 'juliet_after.npz',
        features=[[-3.0, -3.0], [3.0, 3.0]],
        labels=[0, 1],
    )
    _write_feature_npz(
        tmp_path / 'features' / 'cve_before.npz',
        features=[[-2.0, 2.0], [2.0, -2.0]],
        labels=[0, 1],
    )
    invalid_npz = tmp_path / 'features' / 'cve_after_invalid.npz'
    _write_feature_npz(
        invalid_npz,
        features=[[-1.0, -1.0], [1.0, 1.0]],
        labels=[1, 1],
    )

    request = module.TripletTSNERequest(
        model_name='LineVul',
        plot_title='LineVul Triplet t-SNE on Juliet/CVE Trace Pair',
        output_dir=tmp_path / 'triplet-output',
        cohorts=(
            module.TripletCohortSpec(
                cohort_key='juliet_after_fine_tuned',
                feature_npz_path=tmp_path / 'features' / 'juliet_after.npz',
                source_csv_path=juliet_csv,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_before_fine_tuned',
                feature_npz_path=tmp_path / 'features' / 'cve_before.npz',
                source_csv_path=cve_csv,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_after_fine_tuned',
                feature_npz_path=invalid_npz,
                source_csv_path=invalid_cve_csv,
            ),
        ),
        overwrite=False,
    )

    with pytest.raises(ValueError, match='requires both Patched and Vulnerable samples'):
        module.export_triplet_tsne(request)


def test_export_triplet_tsne_requires_matching_feature_dimensions(tmp_path):
    module = load_module_from_path(
        'test_triplet_tsne_requires_matching_dims',
        REPO_ROOT / 'tools/shared/triplet_tsne.py',
    )

    juliet_csv = tmp_path / 'datasets' / 'juliet.csv'
    cve_csv = tmp_path / 'datasets' / 'cve.csv'
    _write_source_csv(
        juliet_csv,
        project='Juliet',
        test_rows=[
            ('j0', 0, 'int juliet_good(void) { return 0; }'),
            ('j1', 1, 'int juliet_bad(void) { return 1; }'),
        ],
    )
    _write_source_csv(
        cve_csv,
        project='CVEProject',
        test_rows=[
            ('c0', 0, 'int cve_patch(void) { return 0; }'),
            ('c1', 1, 'int cve_vuln(void) { return 1; }'),
        ],
    )

    juliet_npz = tmp_path / 'features' / 'juliet_after.npz'
    cve_before_npz = tmp_path / 'features' / 'cve_before.npz'
    cve_after_npz = tmp_path / 'features' / 'cve_after.npz'
    _write_feature_npz(juliet_npz, features=[[-3.0, -3.0], [3.0, 3.0]], labels=[0, 1])
    _write_feature_npz(cve_before_npz, features=[[-2.0, 2.0], [2.0, -2.0]], labels=[0, 1])
    _write_feature_npz(
        cve_after_npz,
        features=[[-1.0, -1.0, 1.0], [1.0, 1.0, -1.0]],
        labels=[0, 1],
    )

    request = module.TripletTSNERequest(
        model_name='PDBERT',
        plot_title='PDBERT Triplet t-SNE on Juliet/CVE Trace Pair',
        output_dir=tmp_path / 'triplet-output',
        cohorts=(
            module.TripletCohortSpec(
                cohort_key='juliet_after_fine_tuned',
                feature_npz_path=juliet_npz,
                source_csv_path=juliet_csv,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_before_fine_tuned',
                feature_npz_path=cve_before_npz,
                source_csv_path=cve_csv,
            ),
            module.TripletCohortSpec(
                cohort_key='cve_after_fine_tuned',
                feature_npz_path=cve_after_npz,
                source_csv_path=cve_csv,
            ),
        ),
        overwrite=False,
    )

    with pytest.raises(ValueError, match='feature dimensions must match'):
        module.export_triplet_tsne(request)
