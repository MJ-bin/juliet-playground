from __future__ import annotations

from pathlib import Path
from typing import Iterable

TRAIN_PATCHED_COUNTERPARTS_BASENAME = 'train_patched_counterparts'


def build_dataset_export_paths(
    output_dir: Path,
    dataset_basename: str | None = None,
) -> dict[str, Path]:
    output_dir = Path(output_dir)
    if dataset_basename:
        return {
            'output_dir': output_dir,
            'csv_path': output_dir / f'{dataset_basename}.csv',
            'normalized_slices_dir': output_dir / f'{dataset_basename}_slices',
            'split_manifest_json': output_dir / f'{dataset_basename}_split_manifest.json',
            'summary_json': output_dir / f'{dataset_basename}_summary.json',
        }
    return {
        'output_dir': output_dir,
        'csv_path': output_dir / 'Real_Vul_data.csv',
        'normalized_slices_dir': output_dir / 'normalized_slices',
        'split_manifest_json': output_dir / 'split_manifest.json',
        'summary_json': output_dir / 'summary.json',
    }


def build_pair_trace_paths(pair_dir: Path) -> dict[str, Path]:
    pair_dir = Path(pair_dir)
    return {
        'output_dir': pair_dir,
        'pairs_jsonl': pair_dir / 'pairs.jsonl',
        'leftover_counterparts_jsonl': pair_dir / 'leftover_counterparts.jsonl',
        'paired_signatures_dir': pair_dir / 'paired_signatures',
        'summary_json': pair_dir / 'summary.json',
    }


def build_patched_pairing_paths(
    pair_dir: Path,
    dataset_basename: str = TRAIN_PATCHED_COUNTERPARTS_BASENAME,
) -> dict[str, Path]:
    pair_dir = Path(pair_dir)
    return {
        'output_dir': pair_dir,
        'pairs_jsonl': pair_dir / f'{dataset_basename}_pairs.jsonl',
        'signatures_dir': pair_dir / f'{dataset_basename}_signatures',
    }


def build_slice_stage_paths(stage_dir: Path) -> dict[str, Path]:
    stage_dir = Path(stage_dir)
    return {
        'output_dir': stage_dir,
        'slice_dir': stage_dir / 'slice',
        'summary_json': stage_dir / 'summary.json',
    }


def path_strings(paths: dict[str, Path], *, include: Iterable[str] | None = None) -> dict[str, str]:
    include_set = set(include) if include is not None else None
    payload: dict[str, str] = {}
    for key, value in paths.items():
        if include_set is not None and key not in include_set:
            continue
        if isinstance(value, Path):
            payload[key] = str(value)
    return payload
