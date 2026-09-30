# 조사 에이전트 동작 흐름

`python main.py <사건 파일>` 한 번이 어떤 파일·함수를 어떤 순서로 거치는지 정리한 문서다.
코드 주석의 `[1]`, `[2]` … 번호가 이 문서의 번호와 같다. 코드를 읽을 때 번호를 따라가면 된다.
하위 단계는 `[25-1]`처럼 붙였다. `[7]`~`[15]`는 삭제된 로그 수집·seed 생성 단계의 번호라 비워 두었다(0927, 사건 입력은 1차 탐지가 넘긴다).

기준: `integrate-investigation` 브랜치(= 팀 저장소 `feature/Agentic-SOC-Investigation-Agent`), 2026-09-25.

---

## 1. 한눈에 보기

```
main.py
 ├─ [2]  도구 레지스트리 만들기            agent/tools/registry.py
 ├─ [3]  LLM 클라이언트 만들기             agent/gemini_client.py (또는 claude_client.py)
 ├─ [4]  사건 파일 읽기                    agent/incident_input.py load_incidents()
 └─ [5]  사건별 조사 실행                  agent/pipeline.py
          ├─ [6]  조사 입력으로 변환         agent/incident_input.py to_investigation_seed()
          └─ [16] 사건마다 조사 루프         agent/loop.py
                   ├─ [18]   조사 상태 만들기            agent/models.py
                   ├─ [19-1] network 사전 조회           (src_ip가 있을 때, 코드가 직접)
                   └─ [20]~[40] 반복 (최대 도구 8회)
                         ├─ [20]~[23] LLM 판단 1회        gemini_client.py + prompts/
                         ├─ [24]      판단 결과 반영       (증거 원본 참조 검증, 신뢰도 누적)
                         ├─ [25]      종료 요청이면 → 종료 관문 → 통과하면 끝
                         └─ [27]~[39] 도구 요청이면 → 도구 실행 → 결과를 다음 턴에 LLM에게
                   └─ [41] 결과 JSON 만들기                agent/report.py
 └─ [45] results/investigation_agent/*.json 저장 (콘솔에는 경로만)
```

LLM은 **"무엇을 조회할지"와 "어떻게 판정할지"를 제안**하고, 코드는 **조회 실행·숫자 세기·기준 계산·조기 종료 차단**을 맡는다.
판정 재현성을 위해 셀 수 있는 것은 전부 코드가 센다(실패 횟수, POST 횟수, 의심 명령 수 등).

---

## 2. 단계별 상세

### 준비 — `main.py`

| 번호 | 위치 | 하는 일 |
|---|---|---|
| [1] | `main.py` 맨 아래 | `python main.py <사건 파일>` → `main()` |
| [2] | `registry.build_default_registry()` | 7개 도구 등록. `agent/tools/real/<도구이름>.py`에 같은 이름 함수가 있으면 그걸 쓰고, 없으면 목업. `resolve_ip_geo`는 제외 |
| [3] | `agent/llm_provider.build_llm_client()` | 루트 `.env`의 `INVESTIGATION_LLM_PROVIDER`(기본 anthropic = Claude)로 클라이언트 생성 |
| [4] | `incident_input.load_incidents()` | 사건 파일 읽기. JSON 객체 하나, JSON 배열, 한 줄에 한 건인 JSONL(1차 탐지 출력)을 받음. 각 사건에 `incident_id` 필수 |
| [5] | `pipeline.run_investigation_pipeline()` | 사건을 받은 순서대로 조사. `network_precheck=True`, `strict_termination=True`, `max_calls=8`, `confidence_threshold=0.85` |

### 사건 입력 — `agent/incident_input.py`

사건을 찾고 고르는 일(로그 수집·Sigma 탐지·사건 묶기·우선순위)은 1차 탐지가 한다. 조사 에이전트는 받은 사건만 조사한다.

| 번호 | 위치 | 하는 일 |
|---|---|---|
| [6] | `to_investigation_seed()` | 1차 탐지 Incident → 조사 루프 입력(아래 표). `entity`·`seeds`가 없는 dict(직접 작성한 사건 JSON)는 `host`만 채워 그대로 씀 |

| 조사 루프 입력 | 1차 탐지 Incident에서 가져오는 값 |
|---|---|
| `incident_id` | `incident_id` (`incident_key`·`updated_at`이 있으면 함께 보관 → 결과 최상위 `incident_key`·`incident_snapshot`) |
| `host` | 사건에 없으면 `.env`의 `HOST` |
| `src_ip` | `entity.type == "src_ip"`이면 그 값, 아니면 탐지 결과 중 IP entity. pid 사건은 없음(network 사전 조회 안 함) |
| `window` / `trigger_time` | `window` / 가장 이른 탐지 이벤트 시각(`seeds[].detail.timestamp`) |
| `evidence_refs` | 모든 `seeds[].evidence_refs`. 탐지가 없는 사건만 `members` 앞 50개 |
| `trigger_description`, `severity_hint` | `seeds[].reason`들 / `rule_severity` 최댓값 |
| `detection` | 계층, 멤버 수, 연결 종류별 개수, 탐지 룰별 이름·사유·원본 참조·`detail`(최대 20개) |
| `llm_reason` | 있으면 그대로 |

`members`(최대 500개)와 `join_path` 원본은 프롬프트 크기 때문에 싣지 않는다. `triage_score`·`priority`·`route`·`llm_investigate`는 조사할 사건을 고르는 데 쓰는 값이라 보지 않는다.

### 조사 루프 — `agent/loop.py` `InvestigationAgent.run(seed)`

**시작**

| 번호 | 하는 일 |
|---|---|
| [16]·[17] | pipeline이 seed마다 `InvestigationAgent`를 만들어 `run(seed)` |
| [18]·[19] | `AgentState` 생성: seed, 시작 신뢰도(`confidence_initial`), seed의 원본 참조 등록 |
| [19-1] | **network 사전 조회**: seed에 src_ip가 있으면 첫 LLM 턴 전에 코드가 `fetch_network_log(ip=src_ip, 사건 구간 ±30분, limit=20)` 실행. 결과는 첫 턴 관측으로. LLM이 고른 도구 수에는 세지 않음 |

**반복 한 바퀴** (최대 `max_calls + 3` 바퀴)

| 번호 | 위치 | 하는 일 |
|---|---|---|
| [20] | `_safe_reason()` → `gemini_client.reason()` | LLM 호출. 응답 해석 실패는 1회 재시도, 또 실패하면 이 사건만 폴백 판정 |
| [21] | `prompts.build_system_prompt()` / `build_user_prompt()` | 시스템: `investigation.yaml` 원칙 + 도구 목록 + 출력 형식. 사용자: 현재 State + **지금까지 부른 도구의 결과 요약**(`already_called_tools`, 매 턴 유지) + **코드가 계산한 조회 구간**(`query_windows`, `auth_lookback_window`) + 직전 거부 사유. 도구 결과 원문(records)은 직후 한 턴에만 |
| [22]·[23] | `complete_json()` | Gemini 호출(429·503·연결 끊김은 재시도) → JSON 결정 |
| [24] | `_apply_decision()` | facts/가설/unknowns 갱신. 새 증거마다 **원본 참조 검증** 후 신뢰도에 더함(반박이면 뺌). "조회 0건" 증거는 `empty_result_call`이 성공한 0건 호출인지 `_verified_empty_call()`로 확인 |
| [25] | | LLM이 `terminate`면 → |
| [25-1] | `_termination_rejections()` | **종료 관문** (아래 표). 거부 사유가 있으면 다음 턴에 사유를 알려 주고 계속 조사 |
| [25-2] | `_verdict_conflicts()` | 판정이 도구가 계산한 기준과 어긋나는지 |
| [25-3] | `_settle_forced_verdict()` | 같은 사유로 2회 연속 거부되면 강제 종료 턴(판정만 요청). 이때 판정이 원칙과 어긋나게 뒤집히면 LLM이 앞서 낸 원칙에 맞는 판정을 씀 |
| [26] | | 도구 호출이 8회에 도달하면 마무리 턴(판정만 요청) |
| [27] | | 그 외 = LLM이 도구를 요청 → |
| [28] | `_execute_tool_call()` | 같은 도구+인자 재호출 차단 |
| [29] | `registry.validate_args()` | 필수·허용 인자 검사 |
| [30]·[31] | `registry.call()` | `agent/tools/real/<도구>.py` 실행 |
| [32]~[35] | 도구 → `log_source.load_window_events()` → 정규화 → 필터·페이지·요약 | 아래 "도구 내부" 참고 |
| [36]·[37] | | 결과 dict가 loop로 돌아옴. 관측된 원본 참조 등록 |
| [37-1] | | 결과의 `rule_checks`(원칙 7·9, 웹셸 신호)와 `window_total`(구간 전체 건수), 로그인 성공 기록을 State에 저장 → 종료 관문이 씀 |
| [38] | | 호출 기록(`tools_called`) 저장 |
| [39] | | 결과를 다음 턴 관측(`raw_observations_since_last_turn`)으로 |
| [40] | | 신뢰도가 임계값을 넘어도 여기서 끝내지 않음 — 종료는 [25] 관문 통과로만 |

**끝**

| 번호 | 하는 일 |
|---|---|
| [41] | `report.build_investigation_result()`로 결과 JSON. 증거마다 `provenance.evidence_ref_sources()`가 `supporting_tool_calls`(그 raw_refs를 관측한 도구 호출 sequence, 0건 증거는 `empty_result_call`)와 `seed_only_raw_refs`(1차 탐지 참조 중 도구로 관측되지 않은 것)를 붙이고, `provenance.seed_only_evidence`에 해당 증거 id를 모은다(status에는 영향 없음) |
| [42]·[43]·[44] | loop → pipeline → main으로 반환 |
| [45] | 사건 하나가 끝날 때마다 `pipeline`의 `on_result`로 `main.save_investigation_result()`가 JSON을 `results/investigation_agent/<investigation_id>_<UTC시각>.json`에 바로 저장하고 경로만 출력. LLM API 일시 오류로 조사 미완료(`investigation_status: INCOMPLETE`)인 사건은 마지막에 사건 id로 모아 보여 준다. 사람이 읽는 텍스트 보고서는 만들지 않는다 |

### 도구 내부 — `agent/tools/real/fetch_*_log.py`

| 번호 | 하는 일 |
|---|---|
| [32] | `registry.call()`에서 도구 함수 실행 |
| [33] | `log_source.load_window_events(계층, host, start, end)`: 파일 읽기 → 정규화 → **조회 구간 안** 이벤트만, 시각순 |
| [34] | `normalizer_adapter.normalize_log_documents()` → 1차 탐지팀 정규화(저장소 루트 `detection_pipeline/tools/fetch_*_log.py` 원본을 직접 import. 이 표의 조사 도구 `real/fetch_*_log.py`와 이름만 같고 다른 코드) |
| [35] | 도구 인자로 필터 → 페이지(기본 `limit` 200) → `summary` 작성. summary에는 페이지와 무관한 **`[조회 구간 전체 집계]`**와 원칙 기준 계산 결과가 붙음 |

도구가 돌려주는 주요 값:

| 값 | 뜻 | 누가 쓰나 |
|---|---|---|
| `records` | 페이지만큼의 이벤트 (각각 `raw_ref`) | LLM이 증거로 인용 |
| `summary` | 사람이 읽는 요약 + `[조회 구간 전체 집계]` + `[원칙 7 기준]`/`[원칙 9 기준]`/`[후속 침해 확인]` | LLM |
| `window_total` | 필터 전 구간 전체 건수. 모두 0이면 "로그 미확보" | 종료 관문 |
| `rule_checks` | 원칙 기준을 코드가 계산한 결과 | 종료 관문 |

도구별 코드 계산:

| 도구 | 코드가 계산하는 것 |
|---|---|
| `fetch_auth_log` | 로그인 실패 횟수(ssh_failed+ssh_invalid_user), 실패 대상 계정 수, 성공 수. IP 하나로 거르고 성공이 없으면 **원칙 7**: 실패 5회 이상 또는 계정 2개 이상 → 무차별 대입 / 1~4회·1계정 → 단발성 / 실패 0회·접속 흔적(`ssh_probe`) 1~4건 → 스캐너 탐침 |
| `fetch_web_log` | 요청 수, 메서드·상태코드 계열·경로·User-Agent 분포. IP 하나로 거르면 **원칙 9**: 인증·XML-RPC 엔드포인트 POST 10회 이상 → 대입 공격 / 서로 다른 경로 20개 이상 + 4xx 과반 → 경로 스캔 |
| `fetch_audit_log` | 계정·명령 분포, **[후속 침해 확인]**: 웹 서버 계정(www-data 등)의 셸·의심 명령, 전체 의심 명령(cron `sh -c`, EC2 Instance Connect 제외) |
| `fetch_network_log` | 이벤트 종류, Suricata 경보 signature, http 상태·경로, 목적지. `ip` 필터는 방향 무관 |

---

## 3. 종료 관문 — 언제 조사를 끝낼 수 있나

LLM이 "끝내자"고 해도 아래에 걸리면 거부하고 사유를 다음 턴에 알려 준다.

| 조건 | 적용 | 내용 |
|---|---|---|
| (a) 신뢰도 | `confidence_sufficient` | 누적 신뢰도 < 0.85면 거부. **단, 판정이 코드 기준으로 정해지는 판정과 같으면 면제** |
| (b) 도구 수 | `confidence_sufficient` | LLM이 직접 고른 도구가 1종류 이하 (사전 조회는 세지 않음) |
| (c) network | `confidence_sufficient` | seed에 src_ip가 있는데 network 조회를 시도하지 않음 (사전 조회도 인정) |
| (d) 도구 1개로 끝내기 | `no_more_evidence`, strict | 도구 1종류만 보고, 안 본 로그 도구가 남아 있음 |
| (e) 로그인 후 행위 | strict | seed src_ip의 로그인 성공이 보이는데 audit을 안 봄. 사유에 `ppid=<sshd pid>` 안내 |
| (f) 명령의 외부 IP | strict | audit 명령 인자에 나온 공인 IP(`fetch_audit_log.command_external_ips()`, 최대 3개)를 network로 조회하지 않음. 사유에 `fetch_network_log(ip=<IP>)` 안내 |
| (g) 1차 탐지 참조 확인 | strict | 증거가 인용한 1차 탐지 참조(`detection.rules[].evidence_refs`)를 도구로 관측하지 않았고 그 계층(system = audit)을 한 번도 조회하지 않음. 사유에 계층별 도구 안내. 직접 작성한 사건(계층 정보 없음)은 제외 |
| (h) 1차 탐지 룰별 확인 | strict | 1차 탐지 룰 중 탐지 근거 원본을 도구 결과에서 하나도 관측하지 못했고 `unknowns`에도 룰 이름·참조가 없는 것이 있음. 사유에 룰 이름·계층·pid/ppid 안내 |
| 판정-원칙 충돌 | strict | 아래 표 |

판정-원칙 충돌 (`_verdict_conflicts`):

| 도구가 계산한 사실 | 허용 판정 |
|---|---|
| 조회한 모든 계층의 `window_total`이 0 (로그 미확보) | INCONCLUSIVE만 |
| 원칙 9 충족 (seed src_ip) | FALSE_POSITIVE 불가 |
| audit에 웹 서버 계정 셸·의심 명령 | THREAT_CONFIRMED + severity HIGH 이상 |
| 원칙 7 무차별 대입 | FALSE_POSITIVE·INCONCLUSIVE 불가 |
| 원칙 7 단발성·탐침이고 다른 위협 기준 없음 | THREAT_CONFIRMED·INCONCLUSIVE 불가 |

- 같은 사유(숫자만 다른 것 포함)로 **연속 2회** 거부되면 강제 종료 턴. 사이에 새 도구를 실행하면 횟수 초기화.
- 강제 종료 후에도 충돌이 남으면 판정은 그대로 두고 notes에 `⚠ 판정-원칙 불일치`를 남긴다.
- 강제 종료 턴에서 LLM이 원칙과 어긋나게 판정을 뒤집으면, 앞서 LLM이 낸 원칙에 맞는 판정을 쓴다.

---

## 4. 조회 구간 — 계층별로 어디까지 보나

코드가 사건 구간(1차 탐지 Incident의 `window`) 기준으로 계산해 프롬프트(`query_windows`)로 준다. 각 계층의 **첫 조회는 이 구간 그대로** 쓰고, 다른 구간은 두 번째 호출부터 실제 기록 시각을 근거로 바꾼다.

| 계층 | 첫 조회 구간 |
|---|---|
| network | 사건 앞뒤 30분 (사전 조회와 동일) |
| web | 사건 앞뒤 1시간 |
| audit | 사건 30분 전 ~ 1시간 후 (넓은 구간 무필터 조회 금지) |
| auth | 사건 24시간 전 ~ 1시간 후 (src_ip가 있을 때) |
| `get_process_tree` | 기준 시각부터 24시간 전까지 |

---

## 5. 원본 추적(provenance) — 증거가 진짜 로그에서 왔는지

1. 도구 결과의 모든 `raw_ref`를 "관측된 참조"로 등록한다([37]).
2. LLM이 증거에 인용한 `raw_refs`를 그 목록과 대조한다([24]).
   - 관측되지 않은 참조를 지어냄 → 그 증거의 신뢰도 기여 0
   - 참조 누락·형식 오류 → 기여는 반영, provenance만 "미완료"
   - "조회 0건" 증거의 `empty_result_call`이 성공한 0건 호출이 아님(없는 번호·실패·결과 있음) → 기여 0, provenance "미완료"
   - 이미 인용한 참조만 다시 인용 → 기여 0(같은 사실 중복 반영 방지)
   - audit처럼 여러 줄이 한 이벤트면 한 줄만 인용해도 나머지 줄이 함께 연결
3. 최종 보고서의 `provenance.status`는 `passed`/`incomplete`/`unavailable`. **참조가 유효했는지**의 검사이지 판정이 맞는지의 검사가 아니다.

---

## 6. 판정 기준이 있는 곳

| 무엇 | 파일 |
|---|---|
| 판정 원칙 본문 (원칙 1~9, 출력 형식, 규칙) | `agent/prompts/investigation.yaml` |
| 원칙 7 숫자 기준 계산 | `agent/tools/real/fetch_auth_log.py` `principle7_check()` |
| 원칙 9 숫자 기준 계산 | `agent/tools/real/fetch_web_log.py` `principle9_check()` |
| 웹셸 신호 계산 | `agent/tools/real/fetch_audit_log.py` `audit_rule_check()` |
| 기준과 판정의 일치 검사 | `agent/loop.py` `_verdict_conflicts()`, `_rule_determined_verdict()` |

**원칙을 바꿀 때는 세 곳을 함께 맞춰야 한다** — yaml의 문장, 도구의 숫자 계산, loop의 일치 검사. 한 곳만 바꾸면 관문이 LLM 판정을 계속 거부한다.
원칙별 내용과 생긴 이유는 [PROMPT_GUIDE.md](PROMPT_GUIDE.md).

---

## 7. 결과 JSON 주요 필드 (`results/investigation_agent/*.json`)

| 필드 | 내용 |
|---|---|
| `initial_seed` | 조사한 seed 원본 (같은 사건을 `tests.test_consistency --seed-json`으로 다시 돌릴 때 이걸 쓰면 된다) |
| `final_verdict` | verdict(THREAT_CONFIRMED/FALSE_POSITIVE/INCONCLUSIVE), severity, attack_type, confidence(LLM 판정 확신도), summary, reasoning |
| `evidence_chain`, `contradicting_evidence` | 증거와 인용한 `raw_refs` |
| `attack_timeline` | 사건 흐름 |
| `tools_called` | 도구·인자·결과 건수·summary (사전 조회 포함) |
| `confidence_progression` | 증거마다 신뢰도 변화 |
| `investigation_notes` | 사전 조회, 종료 관문 거부, 판정-원칙 불일치 등 기록 |
| `remaining_unknowns` | 끝까지 확인하지 못한 것 (후속 조사 과제) |
| `statistics.investigation_confidence` | 증거 누적 신뢰도(코드 계산) |
| `provenance`, `raw_refs`, `raw_ref_locations` | 원본 추적 |

---

## 8. 설정 (저장소 루트 `.env`)

조사 에이전트는 저장소 루트 `.env` 하나만 경로로 직접 읽는다(`agent/settings.load_root_env()`, `llm/investigate/.env`는 무시).
LLM 설정은 `INVESTIGATION_` 접두어 이름만 읽고, 접두어 없는 옛 이름은 무시하며 이름만 안내한다.

| 변수 | 뜻 |
|---|---|
| `INVESTIGATION_ANTHROPIC_API_KEY`(조사 전용, 먼저 읽음) → `ANTHROPIC_API_KEY` / `INVESTIGATION_GEMINI_API_KEY` → `GEMINI_API_KEY` | API 키 (역할 키가 비면 공용 키) |
| `INVESTIGATION_LLM_PROVIDER`, `INVESTIGATION_CLAUDE_MODEL`, `INVESTIGATION_CLAUDE_EFFORT`, `INVESTIGATION_CLAUDE_REFUSAL_FALLBACK_MODEL`, `INVESTIGATION_GEMINI_MODEL` | LLM (기본 anthropic, Claude 모델 기본 claude-sonnet-5 — EC2는 claude-haiku-4-5-20251001, 거절 시 대체 모델 기본 claude-sonnet-4-6, Gemini 모델 기본 gemini-3.5-flash-lite). 공용 이름으로 대체하지 않는다 |
| `HOST` | 사건에 host가 없을 때 채우는 수집 서버 이름 (비우면 web-01). 1차 탐지 Incident에는 host가 없다 |
| `APACHE/AUTH/AUDIT/SURICATA_LOG_PATH` | 읽을 로그 파일 경로 (EC2: `/var/log/...`). **필수** |
| `AUTH_LOG_YEAR`, `LOG_LOCAL_HOST` | 선택 (로컬 샘플용) |

---

## 9. 알려진 한계

- `INVESTIGATION_LLM_PROVIDER=anthropic`(Claude)은 오프라인 테스트로만 확인했다. 실제 Claude의 판정 재현성·비용은 API 키로 측정해야 한다(`ClaudeClient.usage_totals`에 토큰 합계).
- 조사 도구는 `.env`의 로그 파일 하나만 읽는다. 1차 탐지가 로테이트된 파일(`access.log.1`, `.N.gz`)에서 찾은 사건은 그 참조를 도구로 다시 조회하지 못해 원본 추적이 `incomplete`가 될 수 있다. 이제 1차 탐지 원본 정규화 함수(`detection_pipeline/tools/`)를 직접 쓰지만, 로테이트 파일을 찾아 함께 읽는 부분(`detection_pipeline/tools/log_sources.py`)은 조사 도구의 `log_source.py`에 연결하지 않았다(남은 과제).
- 어떤 사건을 어떤 순서로 조사할지(우선순위, 조사 상태 관리)는 1차 탐지·사건 저장소 방식이 정해지면 붙인다. 지금은 사건 파일에 적힌 순서대로 전부 조사한다.
- `get_process_tree`는 관측된 audit 기반 추정이라 확정된 프로세스 트리가 아니다.
- 원칙 9 기준값(POST 10회, 경로 20개)과 `.git/config` 같은 민감 파일 탐색의 판정은 팀 정책으로 정할 사항이다.
- 원칙 9 미충족(소량 웹 요청)인데 다른 계층 로그가 그 시간대에 없으면 FALSE_POSITIVE와 INCONCLUSIVE가 실행마다 갈린다(원칙 1과 9의 충돌). 1차 탐지 통합 회의에서 정할 사항 — 경위와 고칠 곳은 [PROMPT_GUIDE.md](PROMPT_GUIDE.md) 8장.
