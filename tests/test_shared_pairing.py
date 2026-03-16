from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_make_pair_id_is_stable_without_namespace():
    module = load_module_from_path(
        'test_shared_pairing_module',
        REPO_ROOT / 'tools/shared/pairing.py',
    )

    left = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='/tmp/run-a/non_empty/CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='/tmp/run-a/non_empty/CASE001/2.json',
        counterpart_flow_type='g2b',
    )
    right = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='/tmp/run-b/non_empty/CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='/tmp/run-b/non_empty/CASE001/2.json',
        counterpart_flow_type='g2b',
    )

    assert left == right


def test_make_pair_id_changes_when_dataset_namespace_changes():
    module = load_module_from_path(
        'test_shared_pairing_namespace_module',
        REPO_ROOT / 'tools/shared/pairing.py',
    )

    base = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='CASE001/2.json',
        counterpart_flow_type='g2b',
    )
    namespaced = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='CASE001/2.json',
        counterpart_flow_type='g2b',
        dataset_namespace='train_patched_counterparts',
    )

    assert base != namespaced


def test_build_signature_meta_and_pairing_meta_preserve_optional_fields():
    module = load_module_from_path(
        'test_shared_pairing_meta_module',
        REPO_ROOT / 'tools/shared/pairing.py',
    )

    signature_meta = module.build_signature_meta(
        payload={'key': 'sig-key', 'hash': 'sig-hash'},
        trace_file='CASE001/1.json',
        best_flow_type='b2b',
        bug_trace_length=3,
        procedure='bad',
        primary_file='file.c',
        primary_line=17,
    )
    pairing_meta = module.build_pairing_meta(
        pair_id='pair-1',
        testcase_key='CASE001',
        role='counterpart',
        selection_reason='top_leftover_train_val',
        trace_file='CASE001/2.json',
        best_flow_type='g2b',
        bug_trace_length=2,
        source_primary_pair_id='pair-0',
        leftover_rank=1,
        leftover_candidates_total=4,
    )
    minimal_pairing_meta = module.build_pairing_meta(
        pair_id='pair-1',
        testcase_key='CASE001',
        role='b2b',
        selection_reason='longest_bug_trace',
        trace_file='CASE001/1.json',
        best_flow_type='b2b',
        bug_trace_length=3,
    )

    assert signature_meta == {
        'trace_file': 'CASE001/1.json',
        'best_flow_type': 'b2b',
        'bug_trace_length': 3,
        'procedure': 'bad',
        'primary_file': 'file.c',
        'primary_line': 17,
        'signature_key': 'sig-key',
        'signature_hash': 'sig-hash',
    }
    assert pairing_meta['source_primary_pair_id'] == 'pair-0'
    assert pairing_meta['leftover_rank'] == 1
    assert pairing_meta['leftover_candidates_total'] == 4
    assert 'source_primary_pair_id' not in minimal_pairing_meta
    assert 'leftover_rank' not in minimal_pairing_meta
    assert 'leftover_candidates_total' not in minimal_pairing_meta
