from __future__ import annotations

import json

import pytest
from shared.jsonio import load_json, load_jsonl, write_json, write_jsonl


def test_load_json_reads_object(tmp_path):
    path = tmp_path / 'payload.json'
    path.write_text(json.dumps({'name': 'demo'}) + '\n', encoding='utf-8')

    assert load_json(path) == {'name': 'demo'}


def test_load_json_rejects_non_object_payload(tmp_path):
    path = tmp_path / 'payload.json'
    path.write_text(json.dumps(['not', 'an', 'object']) + '\n', encoding='utf-8')

    with pytest.raises(ValueError, match='Expected JSON object'):
        load_json(path)


def test_load_jsonl_reads_object_rows(tmp_path):
    path = tmp_path / 'payload.jsonl'
    path.write_text('{"id": 1}\n\n{"id": 2}\n', encoding='utf-8')

    assert load_jsonl(path) == [{'id': 1}, {'id': 2}]


def test_load_jsonl_rejects_non_object_row(tmp_path):
    path = tmp_path / 'payload.jsonl'
    path.write_text('{"id": 1}\n["bad"]\n', encoding='utf-8')

    with pytest.raises(ValueError, match='Expected JSON object at line 2'):
        load_jsonl(path)


def test_write_json_creates_parent_and_appends_newline(tmp_path):
    path = tmp_path / 'nested' / 'payload.json'

    write_json(path, {'name': 'demo'})

    assert path.read_text(encoding='utf-8') == '{\n  "name": "demo"\n}\n'


def test_write_jsonl_honors_trailing_newline_flag(tmp_path):
    path = tmp_path / 'nested' / 'payload.jsonl'

    write_jsonl(path, [{'id': 1}, {'id': 2}], trailing_newline=False)

    assert path.read_text(encoding='utf-8') == '{"id": 1}\n{"id": 2}'
