from __future__ import annotations

from pathlib import Path

TRAIN_PATCHED_COUNTERPARTS_BASENAME = 'train_patched_counterparts'


def build_dataset_export_paths(
    output_dir: Path, dataset_basename: str | None = None
) -> dict[str, Path]:
    if dataset_basename:
        return {
            'csv_path': output_dir / f'{dataset_basename}.csv',
            'dedup_dropped_csv': output_dir / f'{dataset_basename}_dedup_dropped.csv',
            'normalized_slices_dir': output_dir / f'{dataset_basename}_slices',
            'token_counts_csv': output_dir / f'{dataset_basename}_token_counts.csv',
            'token_distribution_png': output_dir / f'{dataset_basename}_token_distribution.png',
            'split_manifest_json': output_dir / f'{dataset_basename}_split_manifest.json',
            'summary_json': output_dir / f'{dataset_basename}_summary.json',
        }
    return {
        'csv_path': output_dir / 'Real_Vul_data.csv',
        'dedup_dropped_csv': output_dir / 'Real_Vul_data_dedup_dropped.csv',
        'normalized_slices_dir': output_dir / 'normalized_slices',
        'token_counts_csv': output_dir / 'normalized_token_counts.csv',
        'token_distribution_png': output_dir / 'slice_token_distribution.png',
        'split_manifest_json': output_dir / 'split_manifest.json',
        'summary_json': output_dir / 'summary.json',
    }


def build_pair_trace_paths(pair_dir: Path) -> dict[str, Path]:
    return {
        'pairs_jsonl': pair_dir / 'pairs.jsonl',
        'leftover_counterparts_jsonl': pair_dir / 'leftover_counterparts.jsonl',
        'paired_signatures_dir': pair_dir / 'paired_signatures',
        'summary_json': pair_dir / 'summary.json',
    }


def build_patched_pairing_paths(
    pair_dir: Path,
    dataset_basename: str = TRAIN_PATCHED_COUNTERPARTS_BASENAME,
) -> dict[str, Path]:
    return {
        'pairs_jsonl': pair_dir / f'{dataset_basename}_pairs.jsonl',
        'signatures_dir': pair_dir / f'{dataset_basename}_signatures',
        'selection_summary_json': pair_dir / f'{dataset_basename}_selection_summary.json',
    }


def build_slice_stage_paths(stage_dir: Path) -> dict[str, Path]:
    return {
        'slice_dir': stage_dir / 'slice',
        'summary_json': stage_dir / 'summary.json',
    }
