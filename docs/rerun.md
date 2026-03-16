# Re-run and operations guide

재실행, 자주 쓰는 명령, 운영상 주의사항을 정리한 문서입니다.
산출물 구조는 [`artifacts.md`](artifacts.md), 전체 문서 맵은 [`pipeline-runbook.md`](pipeline-runbook.md), 현재 단계 계약은 [`stage-contracts.md`](stage-contracts.md)를 참고하세요.
아래 예시는 현재 `tools/run_pipeline.py full --help` / `tools/compare-artifacts.py --help` 기준입니다.

## 자주 쓰는 명령

### 1) 전체 파이프라인

```bash
# CWE 여러 개
python tools/run_pipeline.py full 78 89

# 전체 CWE
python tools/run_pipeline.py full --all

# 재현성 옵션 예시
python tools/run_pipeline.py full 78 \
  --run-id run-my-fixed-id \
  --pair-split-seed 1234 \
  --pair-train-ratio 0.8 \
  --dedup-mode row
```

### 2) 산출물 비교

```bash
# 두 pipeline run 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before \
  artifacts/pipeline-runs/run-after

# 두 dataset export 디렉터리만 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before/07_dataset_export \
  artifacts/pipeline-runs/run-after/07_dataset_export
```

## 운영 메모

### Step 07 / 07b의 tokenizer 의존성

- dataset export 단계는 내부적으로 `microsoft/codebert-base` tokenizer를 로드합니다.
- 먼저 로컬 캐시를 찾고, 캐시가 없으면 원격 다운로드를 시도합니다.
- 네트워크가 제한된 환경에서는 **미리 모델 캐시를 준비해 두는 것**이 안전합니다.

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

## Stage 단위 재실행 메모

- `tools/run_pipeline.py`는 이제 `full`만 공식 지원합니다.
- stage 단위 재실행이 필요하면 `tools/stage/*.py`의 importable 함수나
  `experiments/*/scripts/*.py` wrapper를 사용하세요.
- Step 07b는 표준 pipeline run layout(`run_dir/05_pair_trace_ds`, `run_dir/06_slices`, `run_dir/07_dataset_export`)을 전제로 동작합니다.
