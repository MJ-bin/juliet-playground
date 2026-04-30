#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import run_linevul as _run_linevul
from shared import bench_runner as _bench_runner

EXTERNAL_LINEVUL_NAMESPACE = 'juliet-playground-external'
EVAL_ONLY_TARGET_NAME = 'eval_only'


@dataclass(frozen=True)
class LineVulEvalOnlyConfig:
    dataset_csv: Path
    model_dir: Path
    vpbench_root: Path
    container_name: str
    eval_name: str
    overwrite: bool
    dry_run: bool
    tokenizer_name: str = _run_linevul.DEFAULT_TOKENIZER_NAME
    model_name: str = _run_linevul.DEFAULT_MODEL_NAME
    eval_batch_size: int = _run_linevul.DEFAULT_EVAL_BATCH_SIZE
    num_train_epochs: int = _run_linevul.DEFAULT_NUM_TRAIN_EPOCHS
    storage_path_parts: tuple[str, ...] = ()
    output_name: str = 'finetuned'


@dataclass(frozen=True)
class LineVulEvalOnlyPaths:
    target_name: str
    display_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_test_log: Path
    host_test_dataset_pkl: Path
    host_best_model_dir: Path
    host_test_predictions_csv: Path
    host_line_vul_script: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_dataset_csv: Path
    container_best_model_dir: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run LineVul prepare/test for an external test-only dataset CSV using an '
        'existing trained model.'
    )
    parser.add_argument('--dataset-csv', type=Path, required=True)
    parser.add_argument('--model-dir', type=Path, required=True)
    parser.add_argument('--vpbench-root', type=Path, default=_run_linevul.DEFAULT_VPBENCH_ROOT)
    parser.add_argument('--container-name', type=str, default=_run_linevul.DEFAULT_CONTAINER_NAME)
    parser.add_argument('--eval-name', type=str, default=None)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args()


def _default_eval_name(dataset_csv: Path) -> str:
    if dataset_csv.parent.name == '07_dataset_export':
        return dataset_csv.parent.parent.name
    return dataset_csv.parent.name or dataset_csv.stem


def normalize_config(config: LineVulEvalOnlyConfig) -> LineVulEvalOnlyConfig:
    return LineVulEvalOnlyConfig(
        dataset_csv=config.dataset_csv.resolve(),
        model_dir=config.model_dir.resolve(),
        vpbench_root=config.vpbench_root.resolve(),
        container_name=config.container_name,
        eval_name=config.eval_name,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
        tokenizer_name=config.tokenizer_name,
        model_name=config.model_name,
        eval_batch_size=config.eval_batch_size,
        num_train_epochs=config.num_train_epochs,
        storage_path_parts=tuple(config.storage_path_parts),
        output_name=config.output_name,
    )


def validate_config(config: LineVulEvalOnlyConfig) -> None:
    if not config.dataset_csv.exists():
        raise ValueError(f'Dataset CSV not found: {config.dataset_csv}')
    if not config.vpbench_root.exists():
        raise ValueError(f'VP-Bench root not found: {config.vpbench_root}')
    if not config.model_dir.exists():
        raise ValueError(f'LineVul model dir not found: {config.model_dir}')
    if config.eval_batch_size <= 0:
        raise ValueError(f'eval_batch_size must be > 0: {config.eval_batch_size}')
    if config.num_train_epochs <= 0:
        raise ValueError(f'num_train_epochs must be > 0: {config.num_train_epochs}')


def build_eval_only_paths(config: LineVulEvalOnlyConfig) -> LineVulEvalOnlyPaths:
    storage_path_parts = (
        tuple(config.storage_path_parts)
        if config.storage_path_parts
        else (EXTERNAL_LINEVUL_NAMESPACE, config.eval_name)
    )

    base_host_dataset_dir = config.vpbench_root / 'downloads' / 'RealVul' / 'datasets'
    base_host_output_dir = config.vpbench_root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul'
    for path_part in storage_path_parts:
        base_host_dataset_dir /= path_part
        base_host_output_dir /= path_part

    host_dataset_dir = base_host_dataset_dir
    host_output_dir = base_host_output_dir / config.output_name
    container_dataset_dir = _run_linevul.CONTAINER_DATASET_BASE.joinpath(*storage_path_parts)
    container_output_dir = _run_linevul.CONTAINER_EXPERIMENT_BASE.joinpath(
        *storage_path_parts,
        config.output_name,
    )

    return LineVulEvalOnlyPaths(
        target_name=config.output_name if config.storage_path_parts else EVAL_ONLY_TARGET_NAME,
        display_name=config.output_name if config.storage_path_parts else config.eval_name,
        source_csv=config.dataset_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_output_dir / 'prepare.log',
        host_test_log=host_output_dir / 'test.log',
        host_test_dataset_pkl=host_dataset_dir / 'test_dataset.pkl',
        host_best_model_dir=host_output_dir / 'best_model',
        host_test_predictions_csv=host_output_dir / 'test_pred_with_code.csv',
        host_line_vul_script=(
            config.vpbench_root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul' / 'line_vul.py'
        ),
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
        container_best_model_dir=container_output_dir / 'best_model',
    )


def validate_paths(paths: LineVulEvalOnlyPaths) -> None:
    if not paths.host_line_vul_script.exists():
        raise ValueError(f'VP-Bench line_vul.py not found: {paths.host_line_vul_script}')


def ensure_output_targets(paths: LineVulEvalOnlyPaths, *, overwrite: bool) -> None:
    _bench_runner.ensure_output_targets(
        [paths], overwrite=overwrite, runner_name='LineVul eval-only'
    )


def _remove_output_targets_via_container(container_name: str, paths: LineVulEvalOnlyPaths) -> None:
    _bench_runner.remove_output_targets_via_container(
        container_name=container_name,
        paths=paths,
        runner_name='LineVul eval-only',
    )


def cleanup_output_targets(paths: LineVulEvalOnlyPaths, *, container_name: str) -> None:
    _bench_runner.cleanup_output_targets(
        [paths],
        remove_host_output_path_fn=_bench_runner.remove_host_output_path,
        remove_container_targets_fn=lambda selected: _remove_output_targets_via_container(
            container_name,
            selected,
        ),
    )


def stage_model_artifacts(model_dir: Path, target_dir: Path) -> None:
    _run_linevul.require_model_artifacts(model_dir, label=str(model_dir))
    if target_dir.is_symlink() or target_dir.is_file():
        target_dir.unlink()
    elif target_dir.exists():
        _bench_runner.remove_host_output_path(target_dir)
    _run_linevul._copy_directory_contents(model_dir, target_dir)
    _run_linevul.require_model_artifacts(target_dir, label=str(target_dir))


def _base_command_args(
    config: LineVulEvalOnlyConfig,
    paths: LineVulEvalOnlyPaths,
) -> list[str]:
    return [
        'docker',
        'exec',
        config.container_name,
        'python',
        str(_run_linevul.CONTAINER_LINE_VUL_SCRIPT),
        '--dataset_csv_path',
        str(paths.container_dataset_csv),
        '--dataset_path',
        str(paths.container_dataset_dir),
        '--output_dir',
        str(paths.container_output_dir),
        '--tokenizer_name',
        config.tokenizer_name,
        '--model_name',
        config.model_name,
        '--per_device_train_batch_size',
        str(config.eval_batch_size),
        '--per_device_eval_batch_size',
        str(config.eval_batch_size),
        '--num_train_epochs',
        str(config.num_train_epochs),
    ]


def build_prepare_command(
    config: LineVulEvalOnlyConfig,
    paths: LineVulEvalOnlyPaths,
) -> list[str]:
    return [
        *_base_command_args(config, paths),
        '--prepare_dataset',
        '--single_tail510_test',
    ]


def build_test_command(
    config: LineVulEvalOnlyConfig,
    paths: LineVulEvalOnlyPaths,
) -> list[str]:
    return [
        *_base_command_args(config, paths),
        '--test_predict',
        '--eval_model_name',
        str(paths.container_best_model_dir),
    ]


def print_planned_commands(config: LineVulEvalOnlyConfig, paths: LineVulEvalOnlyPaths) -> None:
    print(f'Dataset CSV: {paths.source_csv}')
    print(f'Model dir: {config.model_dir}')
    print(f'Host dataset dir: {paths.host_dataset_dir}')
    print(f'Host output dir: {paths.host_output_dir}')
    for phase, command in (
        ('prepare', build_prepare_command(config, paths)),
        ('test', build_test_command(config, paths)),
    ):
        print(f'[{paths.target_name}/{phase}] {" ".join(command)}')


def print_completion_summary(paths: LineVulEvalOnlyPaths) -> None:
    print('LineVul eval-only run completed.')
    print(f'  - staged_csv: {paths.host_dataset_csv}')
    print(f'  - best_model: {paths.host_best_model_dir}')
    print(f'  - test_predictions: {paths.host_test_predictions_csv}')
    feature_npz = _run_linevul.find_latest_hidden_state_output(paths.host_output_dir)
    if feature_npz is not None:
        print(f'  - feature_npz: {feature_npz}')
        image_path, cache_path = _run_linevul._artifact_image_and_cache(feature_npz)
        if image_path.exists():
            print(f'  - tsne_image: {image_path}')
        if cache_path.exists():
            print(f'  - tsne_cache: {cache_path}')
    print(f'  - logs: {paths.host_output_dir}')


def run_linevul_eval_only(config: LineVulEvalOnlyConfig) -> int:
    validate_config(config)
    paths = build_eval_only_paths(config)
    validate_paths(paths)
    _run_linevul.require_model_artifacts(config.model_dir, label=str(config.model_dir))
    _bench_runner.validate_stage07_csv(
        paths.source_csv,
        required_dataset_types=_run_linevul.TEST_ONLY_REQUIRED_DATASET_TYPES,
    )
    ensure_output_targets(paths, overwrite=config.overwrite)

    if config.dry_run:
        print_planned_commands(config, paths)
        return 0

    _run_linevul.check_container_running(config.container_name)
    if config.overwrite:
        cleanup_output_targets(paths, container_name=config.container_name)

    _run_linevul.stage_source_csv(paths)
    stage_model_artifacts(config.model_dir, paths.host_best_model_dir)

    prepare_command = build_prepare_command(config, paths)
    print(f'Running LineVul prepare for {paths.display_name}...')
    _run_linevul.run_logged_command(prepare_command, paths.host_prepare_log)
    _run_linevul.require_exists(paths.host_test_dataset_pkl, 'test_dataset.pkl')

    test_command = build_test_command(config, paths)
    print(f'Running LineVul test for {paths.display_name}...')
    _run_linevul.run_logged_command(test_command, paths.host_test_log)
    _run_linevul.require_exists(paths.host_test_predictions_csv, 'test_pred_with_code.csv')
    feature_npz = _run_linevul.find_latest_hidden_state_output(paths.host_output_dir)
    if feature_npz is None:
        raise RuntimeError(
            f'Expected LineVul test hidden-state export not found: {paths.host_output_dir}'
        )
    _run_linevul.require_exists(feature_npz, str(feature_npz))

    print_completion_summary(paths)
    return 0


def main() -> int:
    args = parse_args()
    eval_name = args.eval_name or _default_eval_name(args.dataset_csv.resolve())
    config = normalize_config(
        LineVulEvalOnlyConfig(
            dataset_csv=args.dataset_csv,
            model_dir=args.model_dir,
            vpbench_root=args.vpbench_root,
            container_name=args.container_name,
            eval_name=eval_name,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        return run_linevul_eval_only(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
