from __future__ import annotations

import csv
import os
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_vpbench_root(root: Path) -> Path:
    (root / 'downloads' / 'RealVul' / 'datasets').mkdir(parents=True, exist_ok=True)
    experiments_dir = root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul'
    experiments_dir.mkdir(parents=True, exist_ok=True)
    write_text(experiments_dir / 'line_vul.py', '# stub line_vul entrypoint\n')
    return root


def _write_stage07_csv(
    path: Path,
    *,
    include_processed_func: bool = True,
    include_test_rows: bool = True,
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
    ]
    if include_processed_func:
        fieldnames.append('processed_func')

    rows = [
        {
            'file_name': '1',
            'unique_id': '1',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-a.json',
            'commit_hash': '',
            'dataset_type': 'train_val',
            'processed_func': 'int bad(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '2',
            'unique_id': '2',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'Juliet',
            'source_signature_path': 'sig-b.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int good(void) {\n    return 0;\n}\n',
        },
    ]
    if not include_test_rows:
        rows = rows[:1]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            payload = dict(row)
            if not include_processed_func:
                payload.pop('processed_func')
            writer.writerow(payload)


def test_run_linevul_uses_latest_run_in_dry_run_mode(tmp_path, capsys):
    module = load_module_from_path('test_run_linevul_dry_run', REPO_ROOT / 'tools/run_linevul.py')

    pipeline_root = tmp_path / 'pipeline-runs'
    older_csv = pipeline_root / 'run-older' / '07_dataset_export' / 'Real_Vul_data.csv'
    newer_csv = pipeline_root / 'run-newer' / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(older_csv)
    _write_stage07_csv(newer_csv)
    os.utime(older_csv.parent.parent, (1, 1))
    os.utime(newer_csv.parent.parent, (2, 2))

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--pipeline-root',
            str(pipeline_root),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert 'run-newer' in captured.out
    assert '--prepare_dataset' in captured.out
    assert '--train' in captured.out
    assert '--test_predict' in captured.out
    assert not (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-newer'
    ).exists()


def test_run_linevul_stages_csv_and_runs_prepare_train_test(tmp_path, monkeypatch):
    module = load_module_from_path('test_run_linevul_execute', REPO_ROOT / 'tools/run_linevul.py')

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    host_dataset_dir = (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-demo'
    )
    host_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-demo'
    )

    commands: list[tuple[list[str], Path]] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if '--prepare_dataset' in command:
            write_text(host_dataset_dir / 'train_dataset.pkl', 'train\n')
            write_text(host_dataset_dir / 'val_dataset.pkl', 'val\n')
            write_text(host_dataset_dir / 'test_dataset.pkl', 'test\n')
        elif '--train' in command:
            write_text(host_output_dir / 'best_model' / 'config.json', '{}\n')
        elif '--test_predict' in command:
            write_text(host_output_dir / 'test_pred_with_code.csv', 'label,pred\n1,1\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert commands and len(commands) == 3
    assert commands[0][1] == host_output_dir / 'prepare.log'
    assert commands[1][1] == host_output_dir / 'train.log'
    assert commands[2][1] == host_output_dir / 'test.log'

    prepare_command = commands[0][0]
    train_command = commands[1][0]
    test_command = commands[2][0]
    assert '--prepare_dataset' in prepare_command
    assert '--train' in train_command
    assert '--test_predict' in test_command
    assert '--model_name' in train_command
    assert train_command[train_command.index('--model_name') + 1] == 'microsoft/codebert-base'
    assert train_command[train_command.index('--per_device_train_batch_size') + 1] == '64'
    assert train_command[train_command.index('--per_device_eval_batch_size') + 1] == '64'
    assert test_command[test_command.index('--per_device_eval_batch_size') + 1] == '8'

    assert host_dataset_dir.joinpath('Real_Vul_data.csv').exists()
    assert host_dataset_dir.joinpath('Real_Vul_data.csv').read_text(encoding='utf-8') == (
        source_csv.read_text(encoding='utf-8')
    )
    assert host_output_dir.joinpath('best_model', 'config.json').exists()
    assert host_output_dir.joinpath('test_pred_with_code.csv').exists()


def test_run_linevul_requires_processed_func_column(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_processed_func',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-bad'
    _write_stage07_csv(
        run_dir / '07_dataset_export' / 'Real_Vul_data.csv',
        include_processed_func=False,
    )
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'missing required columns' in captured.err
    assert 'processed_func' in captured.err


def test_run_linevul_requires_test_split_rows(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_test_rows',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-no-test'
    _write_stage07_csv(
        run_dir / '07_dataset_export' / 'Real_Vul_data.csv',
        include_test_rows=False,
    )
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'must contain both train_val and test rows' in captured.err


def test_run_linevul_requires_overwrite_for_existing_targets(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_existing_targets',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-existing'
    _write_stage07_csv(run_dir / '07_dataset_export' / 'Real_Vul_data.csv')
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    existing_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-existing'
    )
    existing_output_dir.mkdir(parents=True, exist_ok=True)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'use --overwrite to replace it' in captured.err
