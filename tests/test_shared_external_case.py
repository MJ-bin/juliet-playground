from __future__ import annotations

import os

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_infer_project_name_from_repo_reads_origin_from_submodule_gitdir(tmp_path):
    module = load_module_from_path(
        'test_shared_external_case',
        REPO_ROOT / 'tools/shared/external_case.py',
    )
    repo_dir = tmp_path / 'cases' / 'demo-project__CVE-2099-0001' / 'vulnerable' / 'repo'
    git_dir = tmp_path / '.git' / 'modules' / 'cases' / 'demo-project__CVE-2099-0001' / 'repo'

    write_text(
        git_dir / 'config',
        '[remote "origin"]\n\turl = https://github.com/rsyslog/rsyslog.git\n',
    )
    relative_git_dir = os.path.relpath(git_dir, repo_dir)
    write_text(repo_dir / '.git', f'gitdir: {relative_git_dir}\n')

    assert module.infer_project_name_from_repo(repo_dir) == 'rsyslog'
