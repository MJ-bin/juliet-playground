from __future__ import annotations

import csv
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_vpbench_root(root: Path) -> Path:
    (root / 'downloads' / 'RealVul' / 'datasets').mkdir(parents=True, exist_ok=True)
    experiments_dir = root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul'
    experiments_dir.mkdir(parents=True, exist_ok=True)
    write_text(experiments_dir / 'line_vul.py', '# stub line_vul entrypoint\n')
    return root


def _make_model_dir(root: Path) -> Path:
    write_text(root / 'config.json', '{}\n')
    write_text(root / 'pytorch_model.bin', 'weights\n')
    write_text(root / 'training_args.bin', 'args\n')
    return root


def _write_test_only_csv(path: Path) -> None:
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
    rows = [
        {
            'file_name': '1',
            'unique_id': '1',
            'target': '1',
            'vulnerable_line_numbers': '2',
            'project': 'DemoProject',
            'source_signature_path': 'sig-a.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int bad(void) {\n    return 1;\n}\n',
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_run_linevul_eval_only_dry_run_prints_prepare_and_test(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_eval_only_dry_run',
        REPO_ROOT / 'tools/run_linevul_eval_only.py',
    )

    dataset_csv = tmp_path / 'dataset' / 'Real_Vul_data.csv'
    _write_test_only_csv(dataset_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    model_dir = _make_model_dir(tmp_path / 'model')

    result = run_module_main(
        module,
        [
            '--dataset-csv',
            str(dataset_csv),
            '--model-dir',
            str(model_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert '[eval_only/prepare]' in captured.out
    assert '[eval_only/test]' in captured.out
    assert '[eval_only/train]' not in captured.out
    assert '--eval_model_name' in captured.out


def test_run_linevul_eval_only_executes_prepare_and_test(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_run_linevul_eval_only_execute',
        REPO_ROOT / 'tools/run_linevul_eval_only.py',
    )

    dataset_csv = tmp_path / 'dataset' / 'Real_Vul_data.csv'
    _write_test_only_csv(dataset_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    model_dir = _make_model_dir(tmp_path / 'model')

    config = module.normalize_config(
        module.LineVulEvalOnlyConfig(
            dataset_csv=dataset_csv,
            model_dir=model_dir,
            vpbench_root=vpbench_root,
            container_name='linevul',
            eval_name='demo-eval',
            overwrite=False,
            dry_run=False,
        )
    )
    paths = module.build_eval_only_paths(config)

    commands: list[tuple[list[str], Path]] = []
    hidden_state_output = (
        paths.host_output_dir / '20260401-000000-000000_test_last_hidden_state_vectors.npz'
    )

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if '--prepare_dataset' in command:
            write_text(paths.host_test_dataset_pkl, 'test\n')
        elif '--test_predict' in command:
            write_text(paths.host_test_predictions_csv, 'label,pred\n1,1\n')
            write_text(hidden_state_output, 'npz\n')

    monkeypatch.setattr(module._run_linevul, 'check_container_running', lambda _name: None)
    monkeypatch.setattr(module._run_linevul, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--dataset-csv',
            str(dataset_csv),
            '--model-dir',
            str(model_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--eval-name',
            'demo-eval',
        ],
    )

    assert result == 0
    assert [log_path for _, log_path in commands] == [
        paths.host_prepare_log,
        paths.host_test_log,
    ]
    prepare_command = commands[0][0]
    test_command = commands[1][0]
    assert '--prepare_dataset' in prepare_command
    assert '--test_predict' in test_command
    assert '--eval_model_name' in test_command
    assert test_command[test_command.index('--eval_model_name') + 1] == str(
        paths.container_best_model_dir
    )
    assert '--train' not in prepare_command
    assert '--train' not in test_command
    assert paths.host_dataset_csv.read_text(encoding='utf-8') == dataset_csv.read_text(
        encoding='utf-8'
    )
    assert paths.host_best_model_dir.joinpath('config.json').exists()
    assert paths.host_best_model_dir.joinpath('pytorch_model.bin').exists()
    assert module._run_linevul.find_latest_hidden_state_output(paths.host_output_dir) == (
        hidden_state_output
    )
