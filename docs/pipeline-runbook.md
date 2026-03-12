# Pipeline runbook

파이프라인 운영, 산출물 확인, 재실행, 경로 이식, 디버깅 시 참고하는 문서입니다.
빠른 시작은 루트 [`README.md`](../README.md)를 먼저 보세요.

## 문서 역할

- 루트 `README.md`: 프로젝트 개요와 빠른 시작
- 이 문서: 운영 가이드, 산출물 구조, 재실행/재현성 주의사항
- `experiments/*/README.md`: 각 단계의 세부 동작 규칙

## 주요 스크립트와 역할

- `tools/run-infer-all-juliet.py`
  - CWE 단위 또는 파일 단위로 Infer 실행
  - `analysis/result.csv`, `analysis/no_issue_files.txt` 생성
  - 실행 후 `tools/generate-signature.py`를 호출해 signature도 생성
- `tools/generate-signature.py`
  - `infer-out/report.json`에서 `bug_type == TAINT_ERROR`이고 `bug_trace`가 non-empty인 이슈만 JSON으로 저장
  - `non_empty/analysis/signature_counts.csv` 생성
- `tools/run-epic001-pipeline.py`
  - Step 01~07b를 한 번에 실행
  - `logs/`와 `run_summary.json`까지 포함해 run 단위 산출물을 정리
- `tools/build-paired-trace-signatures.py`
  - strict trace 중 testcase별 `b2b`와 counterpart를 1:1 선택
  - 후보가 여러 개면 `bug_trace_length`가 가장 긴 trace를 선택하고 나머지는 `leftover_counterparts.jsonl`로 보관
- `tools/generate_slices.py`
  - paired signature JSON의 `bug_trace`에서 소스 라인을 읽어 slice 생성
  - `bug_trace`가 `list[list[dict]]`이면 가장 긴 subtrace를 사용
- `tools/export_train_patched_counterparts.py`
  - 기존 `07_dataset_export/split_manifest.json`의 `train_val` pair만 대상으로
    testcase별 최상위 leftover counterpart 1개를 골라 평가용 export 생성
- `tools/rerun-step07.py`
  - 기존 run의 Step 05/06 산출물을 재사용해 Step 07, 07b를 다시 생성
- `tools/tokenize_slices.py`
  - slice 디렉터리를 독립적으로 토큰화하고 분포 plot을 생성하는 보조 스크립트
  - 메인 파이프라인은 이 스크립트를 직접 호출하지 않고, 내부 유틸리티를 재사용합니다.

## 단일 Infer / Signature 산출물

`python tools/run-infer-all-juliet.py ...` 또는
`python tools/generate-signature.py ...`를 독립 실행하면 기본적으로 아래 위치를 사용합니다.

```text
artifacts/
├── infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       ├── CWE.../infer-out/
│       └── analysis/
│           ├── result.csv
│           └── no_issue_files.txt
└── signatures/
    └── infer-YYYY.MM.DD-HH:MM:SS/
        └── signature-YYYY.MM.DD-HH:MM:SS/
            ├── non_empty/
            │   ├── CWE.../*.json
            │   └── analysis/signature_counts.csv
            └── flow_matched/
```

추가로 `run-infer-all-juliet.py --summary-json <path>`를 주면 아래 내용을 포함한 요약 JSON을 별도로 저장합니다.

- `infer_run_dir`, `infer_run_name`
- `signature_output_dir`, `signature_non_empty_dir`
- `analysis_result_csv`, `analysis_no_issue_files`
- target별 결과와 총합 통계

`--global-result`를 주면 infer 결과 root는
`artifacts/infer-results/` 대신 `/data/pattern/result/infer-results/`를 사용합니다.
이 경로는 `tools/paths.py`의 환경 전제입니다.

## 파이프라인 run 산출물

`python tools/run-epic001-pipeline.py ...`는 `artifacts/pipeline-runs/run-.../` 아래에 아래 구조를 만듭니다.

```text
artifacts/pipeline-runs/run-YYYY.MM.DD-HH:MM:SS/
├── 01_manifest/
│   └── manifest_with_comments.xml
├── 02a_taint/
│   ├── code_unique.txt
│   ├── code_frequency.csv
│   ├── source_sink_candidate_map.json
│   ├── function_name_frequency.csv
│   ├── function_name_unique.txt
│   ├── function_name_macro_resolution.csv
│   ├── global_macro_definitions_by_name.json
│   ├── global_macro_definitions_by_name.jsonl
│   ├── pulse-taint-config.json
│   └── summary.json
├── 02b_flow/
│   ├── function_names_unique.csv
│   ├── function_inventory_summary.json
│   ├── function_names_categorized.jsonl
│   ├── grouped_family_role.json
│   ├── category_summary.json
│   ├── manifest_with_testcase_flows.xml
│   └── testcase_flow_summary.json
├── 03_infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
├── 03_signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/signature-YYYY.MM.DD-HH:MM:SS/non_empty/
├── 03_infer_summary.json
├── 04_trace_flow/
│   ├── trace_flow_match_all.jsonl
│   ├── trace_flow_match_strict.jsonl
│   ├── trace_flow_match_partial_or_strict.jsonl
│   └── summary.json
├── 05_pair_trace_ds/
│   ├── pairs.jsonl
│   ├── leftover_counterparts.jsonl
│   ├── paired_signatures/<testcase_key>/{b2b.json,g2b.json,...}
│   ├── summary.json
│   ├── train_patched_counterparts_pairs.jsonl
│   ├── train_patched_counterparts_selection_summary.json
│   └── train_patched_counterparts_signatures/<testcase_key>/{b2b.json,g2b.json,...}
├── 06_slices/
│   ├── slice/*.c|*.cpp
│   ├── summary.json
│   └── train_patched_counterparts/
│       ├── slice/*.c|*.cpp
│       └── summary.json
├── 07_dataset_export/
│   ├── normalized_slices/*.c|*.cpp
│   ├── Real_Vul_data.csv
│   ├── Real_Vul_data_dedup_dropped.csv
│   ├── normalized_token_counts.csv
│   ├── slice_token_distribution.png
│   ├── split_manifest.json
│   ├── summary.json
│   ├── train_patched_counterparts.csv
│   ├── train_patched_counterparts_dedup_dropped.csv
│   ├── train_patched_counterparts_slices/*.c|*.cpp
│   ├── train_patched_counterparts_token_counts.csv
│   ├── train_patched_counterparts_token_distribution.png
│   ├── train_patched_counterparts_split_manifest.json
│   └── train_patched_counterparts_summary.json
├── logs/
│   ├── 01_manifest_comment_scan.stdout.log
│   ├── 01_manifest_comment_scan.stderr.log
│   ├── ...
│   ├── 07_dataset_export.stdout.log
│   └── 07_dataset_export.stderr.log
└── run_summary.json
```

`run_summary.json`에는 run의 mode, 선택된 taint config, step별 stdout/stderr 로그 경로,
대표 산출물 경로, infer summary가 함께 저장됩니다.

## 자주 쓰는 명령

### 1) Infer / Signature

```bash
# Infer만 빠르게 실행
python tools/run-infer-all-juliet.py 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run-infer-all-juliet.py --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/generate-signature.py --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18
```

### 2) 전체 파이프라인

```bash
# CWE 여러 개
python tools/run-epic001-pipeline.py 78 89

# 전체 CWE
python tools/run-epic001-pipeline.py --all

# 재현성 옵션 예시
python tools/run-epic001-pipeline.py 78 \
  --run-id run-my-fixed-id \
  --pair-split-seed 1234 \
  --pair-train-ratio 0.8 \
  --dedup-mode row
```

### 3) Pair / Slice만 따로 실행

```bash
# strict trace 결과만으로 paired trace dataset 생성
python tools/build-paired-trace-signatures.py \
  --trace-jsonl artifacts/pipeline-runs/run-2026.03.09-22:18:32/04_trace_flow/trace_flow_match_strict.jsonl \
  --output-dir /tmp/paired-trace-ds

# 옵션 없이 실행하면 최신 pipeline run의 strict trace를 찾아
# 같은 run 아래 05_pair_trace_ds/ 로 출력
python tools/build-paired-trace-signatures.py

# paired_signatures로부터 slice 생성
python tools/generate_slices.py \
  --signature-db-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32/05_pair_trace_ds/paired_signatures \
  --output-dir /tmp/paired-slices

# 옵션 없이 실행하면 최신 pipeline run의 paired_signatures를 찾아
# 같은 run 아래 06_slices/ 로 출력
python tools/generate_slices.py
```

### 4) Patched counterpart export / Step 07 재실행

```bash
# 기존 train_val 샘플들에 대응하는 patched counterpart 평가셋 생성
python tools/export_train_patched_counterparts.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21

# 기존 run의 Step 07 + 07b를 새 timestamped 폴더로 다시 생성 (기본)
python tools/rerun-step07.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21

# Step 07만 다시 생성
python tools/rerun-step07.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21 \
  --only-07

# Step 07b만 다시 생성
python tools/rerun-step07.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21 \
  --overwrite \
  --only-07b
```

### 5) Tokenize 보조 유틸리티

```bash
python tools/tokenize_slices.py \
  --slice-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21/06_slices/slice \
  --output-dir /tmp/tokenized-slices
```

## 운영 메모

### `generate-signature.py`의 추출 대상

- `infer-out/report.json`의 모든 이슈를 저장하지 않습니다.
- 현재 구현은 `bug_type == TAINT_ERROR`만 대상으로 하며,
  그중 `bug_trace`가 empty가 아닌 레코드만 `non_empty/`에 저장합니다.

### Step 07 / 07b의 tokenizer 의존성

- `run-epic001-pipeline.py`의 Step 07과
  `export_train_patched_counterparts.py`는 내부적으로
  `microsoft/codebert-base` tokenizer를 로드합니다.
- 먼저 로컬 캐시를 찾고, 캐시가 없으면 원격 다운로드를 시도합니다.
- 네트워크가 제한된 환경에서는 **미리 모델 캐시를 준비해 두는 것**이 안전합니다.

### `--overwrite`가 필요한 경우

다음 스크립트는 출력 디렉터리/파일이 이미 존재하면 기본적으로 실패합니다.

- `tools/build-paired-trace-signatures.py`
- `tools/generate_slices.py`
- `tools/export_train_patched_counterparts.py`
- `tools/tokenize_slices.py`
- `tools/rerun-step07.py` (`--output-dir` 또는 대상 경로가 이미 있는 경우)

재실행 시 기존 산출물을 교체하려면 `--overwrite`를 명시하세요.

### 경로를 옮긴 뒤 재사용할 때

signature의 `bug_trace[].filename`은 원래 경로를 포함할 수 있습니다.
아티팩트를 다른 머신/다른 루트 경로로 옮긴 뒤 slice를 다시 만들면
원본 경로를 못 찾아 실패할 수 있습니다.

이 경우 아래 옵션을 사용합니다.

- `tools/generate_slices.py --old-prefix ... --new-prefix ...`
- `tools/export_train_patched_counterparts.py --old-prefix ... --new-prefix ...`
- `tools/rerun-step07.py --old-prefix ... --new-prefix ...` (`--only-07b` 포함)

### 재현성 옵션

- `--run-id`: pipeline run 디렉터리 이름을 고정
- `--pair-split-seed`: pair-level train/test split 난수 시드
- `--pair-train-ratio`: train_val 비율 (`0 < ratio < 1`)
- `--dedup-mode`:
  - `row`: normalized slice 기준 row-level dedup 적용
  - `none`: dedup 비활성화

현재 구현에서 `row` 모드는
`md5("".join(normalized_code.split()))` 기준으로 해시를 만들고,
중복 또는 label collision이 발생한 pair를 걸러냅니다.

## `rerun-step07.py` 동작 정리

- 기본 모드:
  - `<run-dir>/07_dataset_export_<YYYYMMDD_HHMMSS>/`를 새로 만듭니다.
  - Step 07과 07b를 함께 다시 생성합니다.
- `--only-07`:
  - Step 07만 다시 생성합니다.
- `--only-07b`:
  - 기본적으로 기존 `<run-dir>/07_dataset_export/`를 사용합니다.
  - 새 Step 07 결과에 붙이려면 `--output-dir`로 대상 export 디렉터리를 직접 지정해야 합니다.

07b 재실행 시에는 추가로 아래 suffixed 산출물이 생길 수 있습니다.

- `05_pair_trace_ds/train_patched_counterparts_pairs_<suffix>.jsonl`
- `05_pair_trace_ds/train_patched_counterparts_selection_summary_<suffix>.json`
- `05_pair_trace_ds/train_patched_counterparts_signatures_<suffix>/`
- `06_slices/train_patched_counterparts_<suffix>/`
- `<output-dir>/rerun_step07_metadata.json`

## 디버깅 팁

- 파이프라인 실패 시 가장 먼저 볼 곳:
  - `run_summary.json`
  - `logs/<step>.stderr.log`
  - `logs/<step>.stdout.log`
- Step 03 이후 흐름이 꼬이면:
  - `03_infer_summary.json`
  - `04_trace_flow/summary.json`
  - `05_pair_trace_ds/summary.json`
  - `07_dataset_export/summary.json`
  - `07_dataset_export/train_patched_counterparts_summary.json`
- 개별 experiment를 직접 실행할 때는 각 `experiments/*/README.md`를 따르세요.
