from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable


def write_csv_rows(
    path: Path,
    header: list[str],
    rows: Iterable[Iterable[Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
