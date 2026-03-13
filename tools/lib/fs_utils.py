from __future__ import annotations

import shutil
from pathlib import Path


def remove_target(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_target(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(
                f'Target already exists: {path}. Re-run with --overwrite to replace it.'
            )
        remove_target(path)
