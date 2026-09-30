# 테스트 실행 안내

처음 받는 팀원은 [A·B·C·D 통합 안내](../docs/ABCD_TEST_GUIDE.md)의 설치 순서대로 실행하세요.
모든 명령은 **프로젝트 루트**에서 실행합니다. Python 3.10 이상이 필요합니다.

## 가장 짧은 실행 방법

가상환경을 활성화한 뒤:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m scripts.demo_abcd
```

전체 테스트는 AWS/LLM API를 호출하지 않습니다. `.env`도 필요하지 않습니다.
설치 시에는 패키지 다운로드 연결이 필요합니다. `pytest.ini`가 실제 Gemini를 호출하는
`test_consistency.py`를 자동 실행 대상에서 제외합니다.

ABCD 연결만 집중해서 확인하려면:

```bash
python -m pytest -v tests/test_abcd_pipeline.py tests/test_cd_normalizer_integration.py tests/test_event_window.py tests/test_provenance.py
```

## 무엇을 확인하는가

| 파일 | 확인 내용 |
| --- | --- |
| `test_abcd_pipeline.py` | 1차 탐지 형식 Incident 입력 → B 도구·프로세스 조회 → C 페이지 조회 → D 최종 보고서. 단일 계층 4개/4계층 통합, 가짜 증거 참조 incomplete, 환경변수 복원 |
| `test_cd_normalizer_integration.py` | A의 1차 탐지 원본(`detection_pipeline/tools/`) 직접 호출과 B 개별 도구/C 사건 조회 결과 비교(샘플은 `detection_pipeline/samples/`). 원본 함수 파일 위치, 도구 handler가 `agent.tools.real.*`인지, 원본 import 시 루트 `.env`가 새지 않는지(환경변수·`SERVER_PUBLIC_IP`·`sensor_id` 기본값), audit 분할 객체, gzip, 원본 위치·모호성 |
| `test_normalizer_parity.py` | 기존 A 어댑터 API와 1차 탐지 원본 결과 비교(raw_ref 포함). `_run()`을 위 통합 테스트에서 호출하므로 전체 pytest에도 포함 |
| `test_event_window.py` | C의 시간 양끝·시간대·연도 경계·필터·전역 페이지·입력 오류·파일 누락/권한 |
| `test_provenance.py` | D의 seed/지지·반박 증거/JSON·텍스트 참조 유지, audit 여러 줄, 미등록 참조, 도구 실패 이후 참조 유지, "조회 0건" 증거의 `empty_result_call` 확인(성공한 0건 호출만 인정) |
| `test_fetch_*_log.py`, `test_get_process_tree.py` | B의 계층별 필터와 프로세스 연결 |
| `test_incident_input.py` | 1차 탐지 Incident(실제 출력 `fixtures/primary_detection_incidents.jsonl`) → 조사 루프 입력 변환, 사건 파일 형식(JSONL·배열·객체) |
| `test_pipeline.py` | 사건 파일의 사건들이 받은 순서대로 조사되고 탐지 근거 참조가 결과까지 이어지는지, 결과 최상위 `incident_key`·`incident_snapshot`, 한 사건의 LLM API 일시 오류는 그 사건만 조사 미완료로 두고 나머지를 조사·즉시 전달하는지, 설정 오류는 멈추되 앞 사건은 이미 전달됐는지 |
| `test_claude_client.py` | Claude 클라이언트 호출 인자(sampling 인자 없음, 출력 한도, effort), API 키 선택(`INVESTIGATION_ANTHROPIC_API_KEY` 우선, 빈 값이면 `ANTHROPIC_API_KEY`, 키 이름만 출력), 보내는 인자가 설치된 anthropic SDK 시그니처에 있는지, 일시 오류 → `LLMUnavailableError`, 설정 오류는 그대로, 조사 루프에서 설명이 붙은 응답 해석·해석 실패 시 notes에 응답 앞부분, 안전 필터 거절 시 대체 모델 재요청·notes 기록·대체 불가 시 category 담은 실패 |
| `test_llm_json.py` | LLM 응답 JSON 꺼내기: 앞뒤 설명 문장·중간 코드 블록·trailing comma·markdown 키, 실패 시 오류 첫 줄에 응답 앞부분 |
| `test_llm_provider.py` | `LLM_PROVIDER` 기본값(Claude)·Gemini 선택·`GEMINI_MODEL`·알 수 없는 값 오류 |
| `test_gemini_client.py` | Gemini 재시도: 일시 오류(503·429·연결)는 재시도 후 `LLMUnavailableError`, 설정 오류(400·401·403)는 재시도 없이 그대로 |
| `test_loop.py` | 종료 조건·중복 호출 방지·최대 호출 수·도구 오류 처리 |

`test_abcd_pipeline.py`는 네트워크 연결을 차단한 상태에서 실행합니다. LLM 응답만
고정해 같은 순서로 조사하도록 하고, 로그 처리 함수나 조사 도구의 결과를 성공값으로
대체하지 않습니다. 도구 테스트는 `tests/_log_files.py`로 임시 로그 파일을 만들어 계층별 로그 경로(`APACHE/AUTH/AUDIT/SURICATA_LOG_PATH`)로 지정합니다(S3 읽기 코드와 S3 모사 테스트는 삭제됨).

## 실제 LLM 평가와의 차이

오프라인 테스트 통과는 데이터 흐름과 코드 동작을 확인한 결과입니다. 실제 공격 탐지율,
오탐/미탐, 모델 응답 안정성을 측정한 결과는 아닙니다.

실제 모델을 사용하려면 `requirements.txt` 설치 및 `.env` 설정 후 `python main.py`를 실행합니다.
판정 일관성을 반복 측정하는 기존 수동 스크립트는 다음과 같습니다.

```bash
python -m tests.test_consistency --runs 8
```

이 명령은 실제 API 사용량이 발생합니다. 해당 스크립트의 seed와 로그 설정을 사용할
시나리오에 맞추세요. 이번 ABCD 오프라인 검증에서는 실행하지 않았습니다.

새 코드 테스트는 `test_`로 시작하는 함수로 작성해 `python -m pytest -q`에 포함시키세요.
API 호출이 필요한 수동 평가와 오프라인 회귀 테스트를 구분해 유지합니다.
