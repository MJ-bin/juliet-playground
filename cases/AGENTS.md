# Cases Guidance

이 문서는 `cases/<project>__<CVE>/vulnerable/trace_output/README.md` 작성 규칙을 다룹니다.
중심은 **특정 취약점의 vulnerable trace를 어떻게 구성했는지**를 짧고 분명하게 설명하는 데 있습니다.

## 작성 페르소나

- 작성자는 **정보보안 분야에서 취약점 탐지를 연구하는 박사**라고 가정합니다.
- 설명 수준은 **컴퓨터공학을 전공한 학부생이 이해할 수 있는 정도**로 맞춥니다.
- 따라서 보안 용어와 프로그램 분석 용어는 정확히 쓰되, 처음 나오는 개념은 짧게 풀어서 설명합니다.
- 독자가 자연스럽게 따라갈 수 있도록
  - 왜 이 함수가 source / sink인지
  - 왜 특정 구간에서 trace가 끊기는지
  - 왜 수동 분석으로 다음 callee를 연결하는지
  를 문장으로 분명하게 적습니다.
- 논문식으로 지나치게 압축한 표현, 설명 없는 약어, 배경지식을 과하게 요구하는 서술은 피합니다.

README 기본 순서는 아래와 같이 둡니다.
1. `## 취약점 요약`
2. `## 전체 vulnerable trace`
3. `## vulnerable trace 구성 방식`
4. `## fbinfer로 도출되지 않아 수동 분석한 구간`

## 원칙 1. `## 취약점 요약`에는 프로젝트, 취약점, source, sink를 먼저 적습니다.

- 근거: 독자는 먼저 어떤 취약점의 어떤 trace를 읽는지 알아야 합니다.
- 취약점 이름은 `CWE-78`보다 `OS Command Injection`처럼 의미가 바로 드러나는 이름을 우선 사용합니다.
- source, sink, middle은 가능한 한 함수 명으로 적습니다.
- middle은 source와 sink 사이의 핵심 단계 1~2개만 둡니다.

### 예제

```md
## 취약점 요약

이 케이스는 `radare2`의 `OS Command Injection` 취약점이다.

- source: `r_bin_get_symbols(...)`
- middle: `r_cons_printf(...)` 출력이 `r_core_cmd(...)` 계열에서 다시 해석됨
- sink: `system(x)`
```

## 원칙 2. `## 전체 vulnerable trace`에는 현재 기준 전체 trace를 번호와 함께 둡니다.

- 근거: 구간 설명은 전체 trace가 먼저 보일 때 가장 잘 읽힙니다.
- `## 전체 vulnerable trace`에는 현재 기준 전체 vulnerable trace를 두고, 각 step 앞에 `[1]`, `[2]`, `[3]`처럼 번호를 붙입니다.
- 이 번호는 아래 `## vulnerable trace 구성 방식`과 `## fbinfer로 도출되지 않아 수동 분석한 구간`에서 그대로 사용합니다.
- 이 trace는 README를 작성하면서 함께 갱신합니다.
- 각 step은 **해당 코드 라인을 생략 없이 전체 형태로 적습니다**.
- 따라서 함수 호출의 인자 목록, 대입문의 반환 변수, 캐스팅, 구조체 필드 접근 등은 줄이지 않고 그대로 적습니다.
- `## 전체 vulnerable trace`에서는 `@file:line` 형태의 anchor를 붙이지 않습니다.
  - line anchor는 아래 `## fbinfer로 도출되지 않아 수동 분석한 구간` 같은 설명 섹션에서 적습니다.
- `...`로 줄이거나, 핵심 함수명만 남기거나, 앞뒤 표현을 임의로 생략한 형태는 쓰지 않습니다.

### 예제

~~~md
## 전체 vulnerable trace

```c
[1] udscs_do_read(&conn);
[2] udscs_read_complete(connp);
[3] conn->read_callback(connp, &conn->header, conn->data.buf);
[4] vdagent_file_xfers_data(agent->xfers, (VDAgentFileXferDataMessage *)data);
[5] snprintf(buf, PATH_MAX, xdg-open '%s'&, xfers->save_dir);
[6] system(buf);
```
~~~

## 원칙 3. `## vulnerable trace 구성 방식`은 구간 trace 도출 방식과 근거를 표로 적습니다.

- 근거: 전체 trace는 `fbinfer`가 바로 주는 한 개의 trace보다, 여러 구간 trace와 수동 분석을 합쳐 구성되는 경우가 많습니다.
- 표는 아래 형식을 사용합니다.

| 전체 vulnerable trace 기준 위치 | 구간 trace 도출 방식 | 근거 | 비고 |
| --- | --- | --- | --- |

- `전체 vulnerable trace 기준 위치`와 `구간 trace 도출 방식` 값은 README에서 ``로 감싸지 않고 평문으로 적습니다.
- `구간 trace 도출 방식`은 아래 둘로 통일합니다.
  - fbinfer로 추출
  - 수동 분석
- `전체 vulnerable trace 기준 위치`는 실제 연결 설명이 여러 단계여도 항상 출발지와 목적지만 적습니다.
  - 예: `1 -> 2 -> 3`으로 설명되는 구간도 표에는 `1 -> 3`으로 적습니다.
- `fbinfer로 추출` 행의 근거에는 slice 파일의 상대 경로만 적습니다.
  - 예: `../runs/run-002/outputs/06_trace_slices/slice/slice_1f05e87c4707874c.c`
- `fbinfer로 추출` 행의 비고에는 해당 추출의 signature JSON 상대 경로를 적습니다.
  - 예: `../runs/run-002/outputs/03_signatures/infer-2026.04.14-14:27:53/signature-2026.04.14-14:28:00/non_empty/spice-vdagent/1.json`
  - 이 JSON에서는 `taint_source`, `taint_sink`, `tainted_expression`을 확인합니다.
- `수동 분석` 행의 근거에는 `fbinfer` 직접 제공이 끊긴 원인만 적습니다.
  - 예: 함수 포인터 필드의 concrete callee 복원 한계
  - 예: 간접 호출 해석 한계
  - 예: 전역 변수 handoff
- `수동 분석` 행의 비고는 비워 두거나 `-`로 둡니다.
- 함수 포인터 / 간접 호출 / dispatcher 구간도 2 -> 4처럼 실제 dispatch 단위의 출발지와 목적지만 적습니다.
- 근거 열은 경로 또는 원인만 적습니다.
- 비고 열의 경로는 README 기준 상대 경로로 적고, 실제로 열리는 경로를 사용합니다.

### 예제

```md
## vulnerable trace 구성 방식

| 전체 vulnerable trace 기준 위치 | 구간 trace 도출 방식 | 근거 | 비고 |
| --- | --- | --- | --- |
| 1 -> 2 | fbinfer로 추출 | `../runs/run-001/outputs/06_trace_slices/slice/slice_a1b2c3d4.c` | `../runs/run-001/outputs/03_signatures/infer-2026.04.14-14:28:35/signature-2026.04.14-14:28:42/non_empty/spice-vdagent/2.json` |
| 2 -> 4 | 수동 분석 | 함수 포인터 필드의 concrete callee 복원 한계 | - |
| 4 -> 5 | fbinfer로 추출 | `../runs/run-002/outputs/06_trace_slices/slice/slice_1f05e87c4707874c.c` | `../runs/run-002/outputs/03_signatures/infer-2026.04.14-14:27:53/signature-2026.04.14-14:28:00/non_empty/spice-vdagent/1.json` |
| 5 -> 6 | fbinfer로 추출 | `../runs/run-003/outputs/06_trace_slices/slice/slice_9e8d7c6b.c` | `../runs/run-003/outputs/03_signatures/infer-2026.04.14-14:27:01/signature-2026.04.14-14:27:08/non_empty/spice-vdagent/1.json` |
```

## 원칙 4. `## fbinfer로 도출되지 않아 수동 분석한 구간`은 실제 연결 구조와 `fbinfer` 한계를 함께 설명합니다.

- 근거: `수동 분석` 구간은 왜 그 연결을 최종 trace에 넣었는지까지 보여줘야 설득력이 생깁니다.
- `수동 분석` 표 행은 같은 위치 기준으로 바로 아래 `## fbinfer로 도출되지 않아 수동 분석한 구간`에서 이어서 설명합니다.
- 각 항목은 헤딩 3으로 표와 같은 위치를 먼저 적고 아래 순서로 설명합니다.
  1. 끊기는 구간
  2. `fbinfer` 한계
  3. 코드상 실제 연결 방식
- `fbinfer` 한계는 자동 추출이 멈춘 지점을 먼저 보여 주는 역할을 합니다.
- `코드상 실제 연결 방식`에는 다음 내용을 포함합니다.
  - 호출 위치
  - binding 또는 registration 위치
  - 중간 dispatcher 함수와 분기 위치
  - 실제 callee 위치
  - 왜 다음 callee를 그 함수로 보는지에 대한 설명
- 함수명과 실제 source code line anchor를 함께 적습니다.

### 예제

```md
## fbinfer로 도출되지 않아 수동 분석한 구간

### 2 -> 4

- 끊기는 구간:
  `udscs_read_complete(connp); @src/udscs.c:309`
  -> `conn->read_callback(connp, &conn->header, conn->data.buf); @src/udscs.c:269`
  -> `vdagent_file_xfers_data(...); @src/vdagent/vdagent.c:222`
- `fbinfer` 한계:
  함수 포인터 field의 concrete callee와
  그 내부 `VDAGENTD_FILE_XFER_DATA` 분기 복원 한계가 있다.
- 코드상 실제 연결 방식:
  `udscs_read_complete(...) @src/udscs.c:309`는
  `conn->read_callback(...) @src/udscs.c:269`를 호출한다.
  `udscs_connect(vdagentd_socket, daemon_read_complete, ...); @src/vdagent/vdagent.c:353-355`에서
  넘긴 callback 값이 `conn->read_callback = read_callback; @src/udscs.c:127`로 저장된다.
  실제로 바인딩된 `daemon_read_complete(...); @src/vdagent/vdagent.c:156`는
  `case VDAGENTD_FILE_XFER_DATA: @src/vdagent/vdagent.c:220-223`에서
  `vdagent_file_xfers_data(...); @src/vdagent/vdagent.c:222`를 호출한다.
  따라서 실제 dispatch는
  `conn->read_callback(...) -> daemon_read_complete(...) -> vdagent_file_xfers_data(...)`로 본다.
```

## Reference

- 단순한 흐름 정리:
  - `spice-vdagent__CVE-2017-15108/vulnerable/trace_output/README.md`
- 중간 interpreter / dispatcher 단계가 중요한 흐름:
  - `radare2__CVE-2019-16718/vulnerable/trace_output/README.md`
