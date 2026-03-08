# juliet-playground

Juliet C/C++ 테스트 스위트에 대해 Infer를 실험적으로 실행해보는 저장소입니다.

## 현재 핵심 스크립트

- `tools/run-infer-all-juliet.py`
  - 지정한 CWE 목록에 대해 Juliet 테스트케이스를 순회하며 `infer run`을 실행합니다.
  - 결과를 `issue / no_issue / error`로 집계합니다.
  - 옵션으로 `result.csv`, `no_issue_files.txt`를 생성합니다.

- `tools/generate-signature.py`
  - `artifacts`의 최신 `juliet-result-*`를 자동 선택해 signature JSON을 생성합니다.
  - 기본적으로 `TAINT_ERROR`만 추출합니다.
  - 결과를 `artifacts/signatures/signatures-result-*` 아래에 저장합니다.

- `tools/paths.py`
  - 프로젝트 루트, Juliet testcase 경로, 결과 경로, infer 바이너리 경로를 정의합니다.

## 디렉토리 구조(중요한 것만)

- `juliet-test-suite-v1.3/C/testcases`: Juliet 테스트케이스 원본
- `juliet-test-suite-v1.3/C/testcasesupport`: `io.c` 등 공통 지원 코드
- `tools/`: 실행 스크립트
- `artifacts/`: 실행 결과 저장 위치(기본)

## 환경 설정

`clang/clang++`, `infer v1.2.0`, Python venv 까지 준비(최초 1회 실행):

```bash
# python 및 clang 설치
sudo apt-get update && \
sudo apt-get install -y python3 python3-venv python3-pip clang curl xz-utils libunwind8

# infer 설치
cd /tmp && \
curl -fL -o infer-linux-x86_64-v1.2.0.tar.xz https://github.com/facebook/infer/releases/download/v1.2.0/infer-linux-x86_64-v1.2.0.tar.xz && \
tar -xf infer-linux-x86_64-v1.2.0.tar.xz && \
sudo rm -rf /opt/infer-linux-x86_64-v1.2.0 && sudo mv infer-linux-x86_64-v1.2.0 /opt/ && \
sudo ln -sf /opt/infer-linux-x86_64-v1.2.0/bin/infer /usr/local/bin/infer && \
infer --version

# python venv 준비
cd /home/sojeon/Desktop/juliet-playground && \
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

## 실행 예시

### 1) 빠른 스모크 실행 (CWE-78, 3개 그룹만)

```bash
python tools/run-infer-all-juliet.py 78 --max-cases 3
```

### 1-1) 원하는 파일 직접 실행

```bash
python tools/run-infer-all-juliet.py --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c
```

> Juliet 파일명 규칙(정규식)으로 그룹을 파싱해 같은 flow variant를 함께 실행합니다.  
> 예: `..._81_bad.cpp`를 지정하면 `..._81a.cpp`, `..._81_goodG2B.cpp` 등 같은 `81` 그룹이 같이 컴파일됩니다.

### 2) CSV까지 생성

```bash
python tools/run-infer-all-juliet.py 78 --max-cases 3 --generate-csv
```

### 3) CWE-78 전체 실행 (시간 오래 걸릴 수 있음)

```bash
python tools/run-infer-all-juliet.py 78
```

### 4) Signature 생성 (기본: 최신 결과 + TAINT_ERROR만)

```bash
python tools/generate-signature.py
```

### 5) Signature 생성 옵션

```bash
# 입력 결과 폴더 명시
python tools/generate-signature.py --input-dir artifacts/juliet-result-2026.03.08-18:04:18

# 모든 이슈 타입 추출(TAINT_ERROR 필터 해제)
python tools/generate-signature.py --all-issues
```

## 결과 위치

기본적으로 실행마다 아래가 새로 생성됩니다.

- `artifacts/juliet-result-YYYY.MM.DD-HH:MM:SS/`
  - `CWE.../infer-out` (케이스별 Infer 산출물)
  - `no_issue_files.txt`
  - `result.csv` (`--generate-csv` 사용 시)

- `artifacts/signatures/signatures-result-YYYY.MM.DD-HH:MM:SS/`
  - `CWE.../*.json` (alarm별 분리된 signature JSON)

## 동작 메모

- `.cpp` 파일은 `clang++`, `.c` 파일은 `clang`을 사용합니다.
- testcase 그룹핑은 Juliet 파일명 정규식 기반으로 수행합니다.
- 같은 flow variant 그룹(예: `_52a/_52b/_52c`, `_81a/_81_bad/_81_goodG2B`)은 한 번만 실행하고 함께 컴파일합니다.
- `--files`를 주면 `cwes` 인자는 무시되고, 지정 파일 모드로 실행됩니다.
- `--files`에서도 동일한 그룹핑 로직이 적용됩니다(단일 파일 지정 시에도 같은 flow variant 파일들을 자동 포함).
- `--max-cases`는 CWE당 실행 그룹 수를 제한해 스모크 테스트에 유용합니다.
- Pulse taint 설정은 `tools/pulse-taint-config.json`을 고정 경로로 사용합니다.
