# Agentic-SOC — 조사 에이전트 (Investigation Agent)

LLM 기반 보안관제(SOC) 파이프라인의 **조사 단계**다. 1차 탐지가 넘긴 사건(Incident)마다 LLM이 로그 조회
도구를 골라 가며 증거를 모아 `THREAT_CONFIRMED` / `FALSE_POSITIVE` / `INCONCLUSIVE`로 판정하고 결과 JSON을 만든다.
사건을 찾고 고르는 일(로그 수집·탐지·사건 묶기·우선순위)은 1차 탐지가 한다.

- **동작 흐름(파일·함수 순서, 코드 주석 `[N]` 번호 대응)**: [docs/AGENT_FLOW.md](docs/AGENT_FLOW.md)
- **조사 프롬프트 설명(원칙별 역할·생긴 이유·코드 대응)**: [docs/PROMPT_GUIDE.md](docs/PROMPT_GUIDE.md)
- 변경 이력과 검증 결과: [docs/CHANGES_0918_TO_0925.md](docs/CHANGES_0918_TO_0925.md)
- A·B·C·D 연결과 테스트 안내: [docs/ABCD_TEST_GUIDE.md](docs/ABCD_TEST_GUIDE.md), [docs/C_D_IMPLEMENTATION.md](docs/C_D_IMPLEMENTATION.md)
- 작업 규칙: [AGENTS.md](AGENTS.md)

## 전체 흐름

```
사건 파일 (1차 탐지 Incident JSONL 또는 직접 작성한 사건 JSON)
  → agent/incident_input.py      사건 읽기 → 조사 루프 입력으로 변환 (IP·구간·탐지 근거 원본 참조·탐지 사유)
  → agent/pipeline.py            받은 순서대로 사건마다 조사 루프 실행
  → agent/loop.py                LLM 판단 → 도구 실행(.env의 로그 파일을 다시 읽음) → 결과 관찰 반복, 종료 관문 통과 시 종료
  → agent/report.py              결과 JSON(results/investigation_agent/*.json)
```

| 역할 | 쉽게 말하면 | 위치 |
| --- | --- | --- |
| A: 공통 정규화 | 서로 다른 로그를 같은 형식으로 번역 (1차 탐지팀 코드) | 저장소 루트 `detection_pipeline/tools/`, `agent/tools/normalizer_adapter.py` |
| B: 조사 도구 | 계층별 로그 검색 + 코드가 센 집계·판정 기준 | `agent/tools/real/fetch_*_log.py`, `get_process_tree.py` |
| C: 사건 구간 조회 | 사건 시간대의 여러 계층 로그를 시간순으로 | `agent/tools/real/fetch_event_logs.py` |
| D: 원본 추적 | 원본 파일·줄 번호를 증거와 보고서까지 유지·검증 | `agent/provenance.py` |

## 폴더 구조

```
agent/
  incident_input.py      사건 파일 읽기 + 1차 탐지 Incident → 조사 루프 입력 변환
  pipeline.py            사건별 조사 실행
  loop.py                조사 루프 + 종료 관문 + 원본 참조 검증
  models.py              조사 상태(AgentState)·증거 구조
  prompts/               조사 프롬프트 — 판정 원칙 본문은 investigation.yaml
  gemini_client.py       LLM 호출 (기본) / claude_client.py
  provenance.py          원본 참조 전달·검증
  report.py              결과 JSON 조립
  tools/
    registry.py          도구 등록·실행 (real/<도구이름>.py 자동 연결)
    log_source.py        로그 파일 읽기·정규화·시간창 필터 (수집과 도구 공용)
    normalizer_adapter.py 1차 탐지팀 정규화 코드(저장소 루트 detection_pipeline/tools/)와의 유일한 연결 지점
    real/                실제 조사 도구 (1차 탐지 정규화 함수와 이름만 같고 다른 코드)
scenarios/               로컬 재현 시험용 합성 공격 로그 생성
scripts/                 점검·데모 스크립트 (verify_all_tools, demo_abcd 등)
tests/                   오프라인 테스트 (test_consistency.py = 실제 LLM 재현성 측정)
docs/                    설명 문서
main.py                  실행 진입점
```

## 설치와 실행

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # 키와 로그 경로를 채운다
```

`.env` 최소 설정 (자세한 설명은 `.env.example`):

```
GEMINI_API_KEY=발급받은_키
HOST=<수집 서버 이름, EC2는 hostname 결과>
APACHE_LOG_PATH=/var/log/apache2/access.log
AUTH_LOG_PATH=/var/log/auth.log
AUDIT_LOG_PATH=/var/log/audit/audit.log
SURICATA_LOG_PATH=/var/log/suricata/eve.json
```

```bash
python main.py <사건 파일>                      # 사건별 조사 → results/investigation_agent/에 JSON 저장 (콘솔에는 경로만)
python main.py tests/fixtures/primary_detection_incidents.jsonl   # 예: 1차 탐지 샘플 출력 (로그 경로는 저장소 루트 detection_pipeline/samples/)
python -m pytest -q                             # 오프라인 테스트 (API 키 불필요)
python -m tests.test_normalizer_parity          # 1차 탐지 정규화 결과와 동일성 검증
python -m scripts.verify_all_tools              # .env 로그 경로로 도구 일괄 점검
python -m tests.test_consistency --runs 3 --seed-json seed.json   # 같은 seed 반복 판정 재현성 (실제 LLM)
```

로컬 PC에서는 로그 경로를 `sample_logs/*.log`로 둔다. `sample_logs/`는 실제 트래픽이 들어 있어 저장소에
없다 — 팀원에게 받거나 `scripts/fetch_sample_from_ec2.py`로 받는다. 합성 공격 시나리오는 `scenarios/README.md`.

## LLM

기본은 Claude다(키는 조사 전용 `INVESTIGATION_ANTHROPIC_API_KEY`를 먼저 읽고 비어 있으면 1차 탐지와 공용인
`ANTHROPIC_API_KEY`, 모델은 `CLAUDE_MODEL`, 기본 `claude-sonnet-5`). 어느 이름의 키를 썼는지는 실행 시
`[Claude] API 키: <이름> 사용`으로 표시된다(키 값은 출력하지 않음).
`LLM_PROVIDER=gemini` + `GEMINI_API_KEY`로 Gemini(무료 티어)로 바꿀 수 있다(모델은 `GEMINI_MODEL`, 기본
`gemini-3.5-flash-lite`). Gemini 무료 티어의 429(요청 한도)·503(일시 과부하)은 코드가 기다렸다 재시도하며,
하루 한도를 넘으면 다음 날(한국 시간 오후 4시경) 초기화된다. 특정 모델이 과부하면 `GEMINI_MODEL`을 바꾼다.
Claude 출력 한도는 16000(claude-sonnet-5는 thinking 토큰 포함)이고, 추론 강도는 선택 `CLAUDE_EFFORT`로 정한다.
Claude가 공격 로그를 사이버 공격 요청으로 오인해 거절(refusal)하면 같은 요청을 `CLAUDE_REFUSAL_FALLBACK_MODEL`
(기본 `claude-sonnet-4-6`)로 한 번 다시 보내고 결과 notes에 남긴다.
`temperature`는 보내지 않는다(anthropic SDK 1.x에서 삭제, sonnet-5도 받지 않음). 429·5xx·529·연결 오류는 SDK가 재시도한다.
두 LLM 모두 재시도 뒤에도 일시 오류면 그 사건만 조사 미완료(`investigation_status: INCOMPLETE`)로 저장하고
다음 사건을 계속 조사한다. 시스템 프롬프트는
캐시로 표시해 반복 비용을 줄이고, 호출별 토큰 사용량은 `ClaudeClient.usage_totals`에 누적된다.
실제 Claude로 판정 재현성은 아직 검증하지 않았다 — 전환 시 같은 seed로 재검증할 것.

## 판정을 안정시키는 장치 (요약)

- 셀 수 있는 것은 도구가 센다: 로그인 실패 횟수(원칙 7), 인증 엔드포인트 POST 횟수·경로 수(원칙 9),
  웹 서버 계정의 셸·의심 명령(웹셸 신호), 구간 전체 건수(로그 미확보 판단).
- 조회 구간은 코드가 정한다: 계층별 첫 조회 구간(web ±1시간, audit -30분~+1시간, network ±30분, auth 24시간).
- 종료 관문: 도구 1종류만 보고 끝내기, 로그인 성공 뒤 audit 미확인, 도구가 계산한 기준과 어긋난 판정을 거부한다.
- 원본 추적: 증거가 인용한 원본 줄이 실제로 조회된 로그인지 확인한다.

자세한 조건과 이유는 [docs/AGENT_FLOW.md](docs/AGENT_FLOW.md)에 있다.
