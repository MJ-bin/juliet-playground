#!/usr/bin/env python3
from __future__ import annotations

from lib import rerun_step07 as _rerun_step07

choose_run_config = _rerun_step07.choose_run_config
infer_suffix_from_output_dir = _rerun_step07.infer_suffix_from_output_dir
parse_args = _rerun_step07.parse_args
rerun_step07 = _rerun_step07.rerun_step07
rerun_step07b = _rerun_step07.rerun_step07b
resolve_output_dir = _rerun_step07.resolve_output_dir
resolve_run_dir = _rerun_step07.resolve_run_dir
validate_args = _rerun_step07.validate_args
validate_step07_output_dir = _rerun_step07.validate_step07_output_dir
write_rerun_metadata = _rerun_step07.write_rerun_metadata


def main() -> int:
    return _rerun_step07.main()


if __name__ == '__main__':
    raise SystemExit(main())
