from __future__ import annotations

from shared.csvio import write_csv_rows


def test_write_csv_rows_creates_parent_and_writes_header(tmp_path):
    path = tmp_path / 'nested' / 'payload.csv'

    write_csv_rows(path, ['count', 'name'], [[1, 'alpha'], [2, 'beta']])

    assert path.read_text(encoding='utf-8') == 'count,name\n1,alpha\n2,beta\n'
