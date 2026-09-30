# A·B·C·D 통합 테스트와 쉬운 설명

> **S3 읽기 코드는 삭제됐다.** 로그는 `.env`의 계층별 로그 경로(`APACHE/AUTH/AUDIT/SURICATA_LOG_PATH`) 파일(EC2는 `/var/log/...`)에서만 읽는다. 아래의 S3 객체·`s3://` 참조·S3 모사 테스트 설명은 기록으로만 남아 있고 현재 코드에는 해당하지 않는다. 현재 동작 흐름은 [AGENT_FLOW.md](AGENT_FLOW.md).

이 문서는 `codex/merge-cd-investigation` 브랜치의 코드 기준이다.
먼저 아래 명령으로 실행해 보고, 동작 원리가 궁금하면 뒤의 설명을 읽으면 된다.

## 1. 팀원이 그대로 따라 하는 테스트

준비물은 Git과 Python 3.10 이상이다. 모든 명령은 저장소 루트에서 실행한다.
패키지 설치에는 인터넷 연결이 필요하지만 테스트와 데모에는 `.env`, AWS 계정, LLM API 키가 필요 없다.

처음 내려받는 경우:

```bash
git clone --branch codex/merge-cd-investigation --single-branch https://github.com/Reia0409/Agentic-SOC-integration.git
cd Agentic-SOC-integration
```

이미 이 저장소의 해당 브랜치에서 작업 중이면 작업을 저장한 뒤 `git pull --ff-only`로 갱신한다.

**Windows PowerShell:** 가상환경 활성화 없이 아래 명령을 실행하면 된다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.demo_abcd
```

**macOS/Linux:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m scripts.demo_abcd
```

2026-09-23 검증 시 전체 테스트 결과는 **`97 passed`**였다.
데모의 정상 출력은 아래와 같다. 실행 환경에 따라 저장 경로는 달라진다.

```text
[A] Incident input: 4 detections / 4 raw references
[B] Real investigation tools: 5 calls
[C] Incident window query: 4 events / 2 pages
[D] Provenance: passed / 5 raw references
LLM: scripted offline responses; threat classification not evaluated.
Saved: .../results/investigation_agent/abcd_demo.json
```

- **탐지 4건:** 1차 탐지 Incident 형식의 데모 사건이 web/auth/audit/network 첫 이벤트를 하나씩 탐지 근거로 넘긴다.
- **B 도구 5회:** 계층별 조회 4회와 audit 기반 프로세스 조회 1회다.
- **C 페이지 2개:** 전체 4개 이벤트를 2개씩 나눠 조회했다. 전체 도구 호출 수는 B 5회 + C 2회 = 7회다.
- **원본 참조 5개:** audit은 원본 2줄을 합쳐 이벤트 한 개로 만들므로 총 5줄이다.
- **`passed`:** 원본 참조 전달·인용 검사가 통과했다. 공격 여부가 확정됐다는 뜻은 아니다.

JSON에는 입력 사건(`incident_input`), 도구별 응답(`tool_observations`), 최종 보고서(`results[0]`)가 들어 있다.
`results[0].raw_refs`, `raw_ref_locations`, `evidence_chain`, `provenance`를 보면 원본 추적 결과를 확인할 수 있다.
실행 시각·증거 ID·절대경로는 매 실행 또는 컴퓨터에 따라 달라질 수 있다.

웹 계층만 조사하려면 마지막 명령 대신 다음을 실행한다.

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_abcd --layers web --output results/investigation_agent/abcd_web_demo.json
```

이 경우 데모 사건의 탐지 근거와 조사가 web만 포함한다.
B 1회, C 1개 이벤트/1페이지, 원본 참조 1개가 정상이다.

## 2. A·B·C·D는 무슨 일을 하나?

로그를 **사건의 원본 기록**, 1차 탐지가 넘긴 Incident를 **조사할 사건의 메모**라고 생각하면 쉽다.

| 역할 | 하는 일 | 예시 |
| --- | --- | --- |
| A: 공통 정규화 | 서로 다른 형식의 기록을 공통 항목으로 정리한다. | Apache 문자열을 `timestamp`, `src_ip`, `path`, `raw_ref` 등으로 변환 |
| B: 조사 도구 | 필요한 계층의 로그를 찾아준다. 읽은 로그의 해석은 A에 맡긴다. | 인증 기록에서 특정 IP/사용자의 로그인 조회, audit에서 PID 추적 |
| C: 사건 구간 조회 | 사건 시간 구간의 여러 계층 로그를 한 번에 모은다. | 09:00~09:01의 web/auth/audit/network를 시간순으로 조회 |
| D: 원본 추적 | 결과가 어느 원본 파일의 몇 번째 줄에서 나왔는지 보존·검사한다. | 보고서의 증거에서 `auth.txt:1`을 따라 원본 첫 줄 확인 |

A/B는 공통 정규화 작업을 담당하고, C/D가 그 결과를 재사용한다.
A·B·C·D를 따로 실행하는 네 개의 서버가 있는 구조는 아니다.
한 Python 파이프라인 안에서 아래처럼 연결된다.

```text
1차 탐지 Incident (entity·window·seeds[].evidence_refs)
    ↓ incident_input: 조사 루프 입력(host·src_ip·window·evidence_refs)으로 변환
InvestigationAgent 조사 루프
    ├─ B: 계층별 조회 / 프로세스 조회
    └─ C: 사건 시간 구간으로 여러 계층 조회
          ↓ 두 경로 모두 log_source(원본 이름·줄 위치 확보) → A 공통 정규화를 재사용
D: 조회한 원본 참조를 모으고 증거의 인용을 검증
    ↓
최종 JSON
```

실제 실행에서는 LLM이 어떤 도구를 호출하고 어떻게 판정할지 결정한다.
데모에서는 그 선택만 Python의 고정 응답으로 바꿔 누구나 같은 흐름을 재현하게 했다.
사건 변환·파일 읽기·정규화·조회·조사 루프·보고서 생성은 실제 구현을 사용한다.

## 3. 통합할 때 무엇을 바꿨나?

기존 C/D 구현을 최신 A/B 변경(`cb5005d`)에 연결한 통합 커밋은 `6f02eb6`이다.
원래 C/D 이력과 문서 수정 이력도 부모 커밋으로 남겨 두었다.

**① 정규화하는 곳을 하나로 맞췄다.**

`primary_detection/normalizer/`의 1차 탐지팀 코드는 그대로 유지했다.
수집과 조사에서 별도 파서를 다시 만들지 않고, `normalize_log_documents()`를 통해 같은
공통 함수를 호출한다. 삭제됐던 `agent/tools/parsers/`도 복구하지 않았다.
정규화된 `layer_data`는 조사 도구가 읽기 쉽게 펼치고, 원본 추적 정보만 추가한다.

**② 최신 입력 형식과 필드명에 맞췄다.**

웹은 공통 함수가 지원하는 Apache access 형식이다. 인증 결과의 `event`/`src_ip`,
네트워크 결과의 `signature`/`dest_ip` 등 최신 필드에 맞춰 조회 필터를 연결했다.
네트워크는 공통 함수의 http/alert 선택 및 XFF 원본 IP 처리 정책을 유지한다.
`examples/cd/`에도 이 형식에 맞는 합성 로그를 넣었다.

**③ 사건 시간을 도구에 전달했다.**

`fetch_event_logs`는 `window=[시작, 끝]` 또는 `event.window`를 받는다.
사건 시각만 주면 기본 전후 300초를 사용한다. 조사 루프에서 이 도구를 부르면 seed의
수집 서버 `host`와 사건 정보를 기본값으로 전달한다. 조회 결과는 시간순으로 합쳐 한 번에
페이지를 나눈다. 시간 구간의 양 끝은 포함하며, 한국 시간(`+09:00`) 입력도 지원한다.
IP 등의 조건은 계층별 `filters`로 지정한다. 사건 메모의 IP를 자동 필터로 적용하지는 않는다.

**④ 원본 참조를 덮어쓰지 않고 실제 위치를 보충했다.**

```json
{
  "raw_ref": "audit.txt:1",
  "raw_refs": ["audit.txt:1", "audit.txt:2"],
  "raw_ref_locations": {
    "audit.txt:1": ["/프로젝트/examples/cd/audit.txt:1"],
    "audit.txt:2": ["/프로젝트/examples/cd/audit.txt:2"]
  }
}
```

로컬 `raw_ref`는 1차 탐지와 비교할 수 있도록 공통 함수의 파일명·줄 번호를 유지한다.
실제 전체 경로는 `raw_ref_locations`에 별도로 둔다. S3는 임시 파일 이름 대신
`s3://버킷/객체키:줄번호`로 연결한다. audit처럼 여러 줄이 한 이벤트가 되면 모든 원본 줄을
`raw_refs`에 보존한다. 모델이 대표 참조 한 개만 인용해도 조사 루프가 해당 그룹을 복원한다.

1차 탐지가 넘긴 참조는 고쳐 쓰지 않고 관측된 참조로 그대로 등록한다.
조사 증거의 참조가 누락·미등록·모호하면 검증 결과를 `incomplete`로 표시하고
해당 증거의 신뢰도 기여를 제외한다. 실제 보안 판정 문장의 참/거짓까지 확인하는 기능은 아니다.

## 4. 파일을 어디부터 보면 되나?

```text
Agentic-SOC/
├─ (저장소 루트) detection_pipeline/tools/  A의 공통 정규화 원본(1차 탐지팀 코드, 어댑터가 직접 import)
├─ agent/
│  ├─ incident_input.py                1차 탐지 Incident → 조사 루프 입력 (0927 추가)
│  ├─ pipeline.py                      사건별 조사 실행
│  ├─ loop.py                          도구 호출·C 기본 인자·D 참조 누적
│  ├─ models.py                        조사 상태와 증거에 참조 저장
│  ├─ provenance.py                    D 참조 검증
│  ├─ report.py                        최종 보고서에 참조·검증 결과 포함
│  └─ tools/
│     ├─ normalizer_adapter.py         A 호출 + 원본 위치 매핑
│     ├─ log_source.py                 조사 도구가 공유하는 읽기/필터/페이지 처리
│     ├─ registry.py                   실제 도구 등록 및 인자 검사
│     └─ real/
│        ├─ fetch_web_log.py           B 웹 조회
│        ├─ fetch_auth_log.py          B 인증 조회
│        ├─ fetch_audit_log.py         B 시스템 감사 조회
│        ├─ fetch_network_log.py       B 네트워크 조회
│        ├─ get_process_tree.py        B audit 기반 프로세스 연결
│        └─ fetch_event_logs.py        C 사건 시간 구간 조회
├─ examples/cd/                       재현 가능한 합성 로그
├─ scripts/demo_abcd.py               [이번 추가] 전체 파이프라인 데모
├─ tests/test_abcd_pipeline.py        [이번 추가] 전체 연결 테스트 9개
├─ tests/test_cd_normalizer_integration.py [이번 수정] B 개별 도구까지 동일성 비교
├─ docs/ABCD_TEST_GUIDE.md             [이번 추가] 이 안내
├─ docs/C_D_IMPLEMENTATION.md         [이번 수정] 상세 문서에 최신 테스트 안내 연결
├─ tests/README.md                    [이번 수정] pytest 실행·검증 범위 안내
├─ README.md                          [이번 수정] 역할·동작 설명과 문서 링크 정정
└─ .env.example                      [이번 수정] Apache 경로·연도·호스트·샘플 수 설정
```

트리의 `[이번 추가/수정]`은 이번 통합 검증 작업 기준이다. 그 외 코드의 C/D 통합은
기존 `6f02eb6`에 들어 있다. 이번 검증에서 운영 코드나 공통 정규화 원본은 변경하지 않았다.

## 5. 어떤 테스트를 실제로 했나?

2026-09-23, Windows / Python 3.14.6 / pytest 9.1.1에서 새 가상환경을 만들고
`requirements-dev.txt`만 설치해 **97개 전체 테스트 통과**를 확인했다.
기존 88개에 전체 흐름 테스트 9개를 추가했고, 기존 4계층 동일성 테스트에는 B 도구 비교를 보강했다.

| 검증 | 확인한 결과 |
| --- | --- |
| A 정규화 동일성 | 동일 샘플을 1차 탐지 원본(`detection_pipeline/tools`) 직접 호출·수집·B 도구·C 조회에 넣었을 때 정규화 필드와 로컬 `raw_ref` 일치. 비교 시 추가 추적 메타데이터만 제외 |
| B 실제 도구 연결 | 실제 `real/` 구현 사용 확인, 4계층 조회·PID 200 프로세스 조회 실행 |
| C 단일/다계층 | 각 계층 단독 및 4계층 동시 조사, 2개씩 페이지 조회 시 중복·누락 없음 |
| C 경계/오류 | 시간 양끝·한국 시간·연도 경계·조건 필터·잘못된 인자·파일 누락·읽기 권한 처리 |
| D 원본 추적 | 입력·seed·도구·증거·JSON/텍스트까지 참조 유지, 최종 위치를 실제 샘플 줄까지 따라가 확인 |
| D 잘못된 참조 | 가짜 seed 참조는 조사 전 거부, 가짜 증거 참조는 incomplete/신뢰도 증가 0 |
| S3 모사 전체 흐름 | 4계층 객체 읽기부터 보고서까지 실행. 두 객체로 나뉜 audit과 gzip auth의 원본 객체·줄 번호 유지 |
| 환경 독립성 | 기존 host/경로/연도/제한 설정이 달라도 데모가 같은 샘플을 쓰고 실행 후 설정 복원 |
| 기존 회귀 검사 | seed 우선순위·종료 조건·중복 호출·오류 처리 등 기존 테스트도 통과 |

벤더 코드는 대상 조사 브랜치의 `cb5005d`와 비교해 변경이 없음을 확인했다.
실시간 1차 탐지 브랜치의 최신 상태를 새로 동기화했다는 뜻은 아니다.

## 6. 내 로그로 실제 LLM까지 실행하려면

1. `python -m pip install -r requirements.txt`로 운영 의존성을 설치한다.
2. `.env.example`을 `.env`로 복사하고 선택한 모델의 API 키를 입력한다.
3. `HOST`, `LOG_LOCAL_HOST`, 계층별 `*_LOG_PATH`를 내 수집 서버와 파일에 맞춘다.
4. auth가 연도 없는 syslog이면 `AUTH_LOG_YEAR`를 실제 로그 연도로 맞춘다.
5. `python main.py <사건 파일>`을 실행한다(1차 탐지 Incident JSONL 또는 사건 JSON). 사건마다 `results/investigation_agent/`에 JSON이 저장된다.

Windows의 복사 명령은 `Copy-Item .env.example .env`, macOS/Linux는 `cp .env.example .env`다.
이미 `.env`가 있으면 필요한 항목만 수정한다. 키가 들어간 `.env`는 커밋하지 않는다.

| 설정 | 의미 |
| --- | --- |
| `LLM_PROVIDER` | `gemini` 또는 `anthropic` |
| `GEMINI_API_KEY` / `INVESTIGATION_ANTHROPIC_API_KEY`(조사 전용, 먼저 읽음) / `ANTHROPIC_API_KEY` | 선택한 모델의 실제 API 키 |
| `HOST` / `LOG_LOCAL_HOST` | 수집 서버 이름. 웹 요청의 도메인 이름과 구분 |
| `APACHE_LOG_PATH` | 현재 템플릿은 존재하는 `sample_logs/sample_apache_web.log`를 사용 |
| `AUTH_LOG_PATH`, `AUDIT_LOG_PATH`, `SURICATA_LOG_PATH` | 해당 원본 로그 파일 경로 |
| `AUTH_LOG_YEAR` | 연도 없는 인증 로그 해석에 사용할 실제 연도 |

B/C 조회에는 사건 시간이 적용되므로 내 샘플의 날짜에 맞는 사건 window가 필요하다. 직접 Python에서 도구를 호출할 때는
`.env`를 자동으로 읽지 않으므로 환경변수를 지정하거나 `load_dotenv()`를 호출한다.

`*_LOG_PATH`는 필수다(S3 읽기는 삭제됨). 경로가 비어 있으면 설정 오류로 알린다.
객체 경로는 `raw/source_type=<apache|auth|auditd|suricata>/host=<서버>/dt=<UTC 날짜>/...`다.
상세 호출 예시는 [C/D 구현 안내](C_D_IMPLEMENTATION.md)에 있다.

**이번 검증의 범위:** 실제 AWS 권한·버킷 연결과 실제 LLM의 공격 판단 정확도는 검증하지 않았다.
네트워크 flow만 있는 로그는 공통 함수의 http/alert 대상에서 제외된다. audit serial 재사용과
프로세스 PID 재사용의 모호성은 기존 공통 모듈/도구의 제한이며 [상세 문서](C_D_IMPLEMENTATION.md)에 남겼다.

## 7. 잘 안 될 때 먼저 볼 것

- `No module named pytest`: 위 설치 명령과 테스트 명령이 같은 가상환경의 Python을 사용하는지 확인한다.
- `No module named agent` / `scripts`: 저장소 루트에서 `python -m ...` 형태로 실행한다.
- 직접 조회했는데 0건: 경로·Apache 형식·사건 날짜·`AUTH_LOG_YEAR`·필터를 확인한다.
- `partial: true`: `errors`에서 실패한 계층을 본다. `not_found`는 파일 없음, `permission_denied`는 읽기 권한 문제다.
- `provenance.status: incomplete`: `issues`, `evidence_without_raw_refs`, `ambiguous_raw_refs`를 확인한다.
- LLM 결과가 실행마다 다름: 실제 모델의 판단과 고정 응답을 쓰는 오프라인 데이터 흐름 검증은 범위가 다르다.
