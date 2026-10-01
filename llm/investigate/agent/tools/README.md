# agent/tools/

Tool 연결·실행 계층입니다. `registry.py`가 LLM이 고른 도구 이름을 실제 함수로 연결하고,
인자를 검증하고, 실행 결과를 Agent에 돌려줍니다.

## 폴더 구성

- **`registry.py`** — `ToolRegistry`/`ToolSpec`/`build_default_registry()`. 도구 우선순위는
  ① 명시적으로 넘긴 handler → ② `real/<도구이름>.py` 안의 동일 이름 함수(자동 탐색) →
  ③ `mock_tools.py`의 목업(폴백). 팀원은 `real/` 밑에 파일만 넣으면 되고 이 파일을
  직접 고칠 필요가 없습니다.
- **`real/`** — 실제 조사 도구 구현 5개(파일명 = 도구 이름, 자동 탐색 대상).
  자세한 규칙은 [real/README.md](real/README.md).
- **`log_source.py`** — `.env`의 계층별 로그 경로(`APACHE/AUTH/AUDIT/SURICATA_LOG_PATH`) 파일과 그 교체 파일(`.1`, `.N.gz` — 1차 탐지와 같은 `resolve_log_files` 규칙)을 읽고(`read_documents`), 정규화·시간창
  필터(`load_window_events`), 페이지네이션, 0건 안내를 제공하는 공용 계층. S3 읽기는 삭제됨(EC2 로컬 경로만 사용).
- **`normalizer_adapter.py`** — 우리(에이전트팀)가 짠 얇은 어댑터. 원본 텍스트를
  같은 저장소 루트의 1차 탐지 원본 `detection_pipeline/tools/`의 정규화 함수에 그대로 넘깁니다
  (`detection_pipeline/`을 `sys.path`에 올리고 `tools.fetch_*_log`로 import, 경로를 못 찾으면 ImportError).
  `real/*.py`가 `log_source.py`를 통해 여기를 거칩니다. `real/fetch_*_log.py`(조사 도구)와
  `detection_pipeline/tools/fetch_*_log.py`(정규화 함수)는 이름만 같고 다른 코드입니다.
- **`time_utils.py`** — 시간 문자열 파싱 등 공용 유틸.
- **`mock_tools.py`** — `real/`에 아직 구현이 없는 도구용 목업. 개발 초기 단계에서
  전체 파이프라인을 끊김 없이 돌리기 위한 폴백입니다.

## `parsers/` 폴더는 삭제됨

자체 파싱 로직 모음이던 `parsers/`는 완전히 없어졌습니다. 원래 남아있던 마지막 파일
`process_tree.py`(pid/ppid로 조상 체인을 엮는 헬퍼)까지 쓰는 곳이
`agent/tools/real/get_process_tree.py` 하나뿐이라, 별도 폴더로 분리해둘 이유가
없어져서 그 파일 안으로 합쳤습니다. 이제 "로그를 직접 파싱하는 코드"는 이 레포
어디에도 없고, 전부 `normalizer_adapter.py` → `detection_pipeline/tools/`(1차 탐지 원본)를
거칩니다.
