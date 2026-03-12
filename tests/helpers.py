from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.golden import helpers as golden_helpers

REPO_ROOT = golden_helpers.REPO_ROOT
deterministic_tokenizer_context = golden_helpers.deterministic_tokenizer_context
load_module_from_path = golden_helpers.load_module_from_path
run_module_main = golden_helpers.run_module_main


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
