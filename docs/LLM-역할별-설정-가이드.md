# LLM 역할별 설정 가이드

| 항목 | 내용 |
| --- | --- |
| 작성 | 희진 (2026-10-02) |
| 적용 브랜치 | `feature/integrate-detection-investigate` (develop 병합 전) |
| 관련 팀 | 1차 탐지(트리아지), ATT&CK 매핑, 조사 에이전트 |

## 한 줄 요약

**LLM을 쓰는 단계 3개가 각자 자기 이름(접두어)의 설정만 읽습니다.** 루트 `.env` 하나를 같이 쓰지만,
한 단계의 모델을 바꿔도 다른 단계는 영향을 받지 않습니다.

| 단계 | 접두어 | 코드 위치 | 모델 기본값 | 계획 |
| --- | --- | --- | --- | --- |
| 1차 탐지 트리아지 (LLM 재검토) | `TRIAGE_` | `llm/triage_review/llm_review.py` | `claude-haiku-4-5` | 경량 모델 |
| ATT&CK 매핑 | `MAPPING_` | `llm/investigate/attack_mapping/` | `claude-haiku-4-5` | 경량 모델 (트리아지와 같은 등급) |
| 조사 에이전트 | `INVESTIGATION_` | `llm/investigate/agent/` | `claude-sonnet-5` | 고성능 모델 |

`.env`에 줄이 없으면 위 기본값으로 돕니다. 그래서 매핑 줄을 빼먹어도 비싼 모델로 돌지 않습니다.

## 왜 나눴나

나누기 전에는 이런 문제가 있었습니다.

1. **매핑이 조사 에이전트 LLM을 같이 썼습니다.** `main.py`가 조사용으로 만든 LLM을 매핑에 그대로 넘겨서,
   조사 모델을 고성능으로 올리면 매핑도 같이 고성능(비싼 모델)으로 올라갔습니다.
2. **트리아지 모델은 코드에 고정돼 있었습니다.** `claude-haiku-4-5`가 코드에 박혀 있어서 `.env`로 바꿀 수 없었습니다.
3. **이름만 보고는 어느 단계 설정인지 알 수 없었습니다.** 예전 `CLAUDE_MODEL`, `CLAUDE_REFUSAL_FALLBACK_MODEL`은
   1차 탐지 설정처럼 보였지만 실제로는 조사 에이전트만 읽고 있었습니다(2026-09-30 확인).

트리아지와 매핑은 지금 같은 모델을 쓰지만 접두어는 따로 둡니다. 관리하는 팀이 다르고, 나중에 한쪽만 바꿀 수도
있어서입니다. `.env`에 같은 값을 한 줄 더 적으면 됩니다.

## `.env` 예시

### LLM 모델 비교 테스트 기간 (모든 단계 같은 모델)

```
# 공용 키 — 역할 전용 키가 없으면 모든 단계가 이 키를 씀
ANTHROPIC_API_KEY=발급받은_키

# 1차 탐지 트리아지
TRIAGE_CLAUDE_MODEL=claude-haiku-4-5

# ATT&CK 매핑
MAPPING_LLM_PROVIDER=anthropic
MAPPING_CLAUDE_MODEL=claude-haiku-4-5
MAPPING_CLAUDE_REFUSAL_FALLBACK_MODEL=none

# 조사 에이전트
INVESTIGATION_LLM_PROVIDER=anthropic
INVESTIGATION_CLAUDE_MODEL=claude-haiku-4-5
INVESTIGATION_CLAUDE_REFUSAL_FALLBACK_MODEL=none
```

### 테스트가 끝난 뒤 (조사 에이전트만 고성능)

조사 에이전트 줄 하나만 바꾸면 됩니다. 트리아지와 매핑은 그대로입니다.

```
INVESTIGATION_CLAUDE_MODEL=<고성능 모델>
```

## 설정 이름 규칙

`<접두어>` 자리에 `TRIAGE_`, `MAPPING_`, `INVESTIGATION_` 중 하나가 들어갑니다.

| 이름 | 뜻 | 비우면 | 트리아지 | 매핑·조사 |
| --- | --- | --- | --- | --- |
| `<접두어>ANTHROPIC_API_KEY` | 그 단계 전용 키 | 공용 `ANTHROPIC_API_KEY` | O | O |
| `<접두어>CLAUDE_MODEL` | Claude 모델 | 단계별 기본값(위 표) | O | O |
| `<접두어>LLM_PROVIDER` | `anthropic` 또는 `gemini` | `anthropic` | X (Claude만) | O |
| `<접두어>CLAUDE_REFUSAL_FALLBACK_MODEL` | 안전 필터 거절 시 다시 보낼 모델, `none`이면 끔 | `claude-sonnet-4-6` | X | O |
| `<접두어>CLAUDE_EFFORT` | 추론 강도 `low`~`max` | 보내지 않음 | X | O |
| `<접두어>GEMINI_API_KEY`, `<접두어>GEMINI_MODEL` | Gemini를 쓸 때 | `GEMINI_API_KEY`, `gemini-3.5-flash-lite` | X | O |
| `<접두어>OPENAI_API_KEY` | GPT를 쓸 때 그 단계 전용 키 (`<접두어>LLM_PROVIDER=openai`) | 공용 `OPENAI_API_KEY` | X | O |
| `<접두어>OPENAI_MODEL` | GPT 모델 — **기본값 없음, 반드시 지정** | (없으면 설정 오류) | X | O |
| `<접두어>OPENAI_REASONING_EFFORT` | GPT 추론 강도 `minimal`~`high` | 보내지 않음 | X | O |

- **API 키만 공용 키로 넘어갑니다.** 모델이나 provider는 다른 단계 값을 절대 빌려 오지 않습니다.
- **역할 전용 키는 선택입니다.** 넣으면 Anthropic 콘솔에서 키마다 사용량이 따로 보여 단계별 비용을 비교하기 쉽습니다.
- **`none`(거절 시 재요청 끄기)은 실험용입니다.** 모델 비교 테스트에서는 다른 모델이 섞이지 않게 `none`으로 두고,
  운영에서는 비워 두는 걸 권장합니다.

### 접두어 없는 옛 이름은 읽지 않습니다

`LLM_PROVIDER`, `CLAUDE_MODEL`, `CLAUDE_EFFORT`, `CLAUDE_REFUSAL_FALLBACK_MODEL`, `GEMINI_MODEL`은 어느 단계도 읽지
않습니다. `.env`에 남아 있으면 조사·매핑 실행 시 이렇게 이름만 안내합니다(값은 출력하지 않음).

```
[설정] CLAUDE_MODEL는 읽지 않습니다 — 조사 에이전트는 INVESTIGATION_CLAUDE_MODEL, ATT&CK 매핑은 MAPPING_CLAUDE_MODEL에 두십시오
```

기존 `.env`에 옛 이름이 있다면, 값은 그대로 두고 이름만 바꾸면 됩니다.

```bash
sed -i -E 's/^(LLM_PROVIDER|CLAUDE_MODEL|CLAUDE_REFUSAL_FALLBACK_MODEL)=/INVESTIGATION_\1=/' .env
```

그다음 매핑(`MAPPING_`)과 트리아지(`TRIAGE_`) 줄을 위 예시처럼 추가합니다.

## 실행할 때 어떤 모델이 도는지 확인하기

**1차 탐지 (`run_pipeline.py`)**
```
[triage] LLM 재검토 모델 claude-haiku-4-5 (API 키: ANTHROPIC_API_KEY)
```

**조사 에이전트 + 매핑 (`main.py`, `run_investigation_queue.py`)**
```
[Claude] API 키: ANTHROPIC_API_KEY 사용 (INVESTIGATION, 모델 claude-haiku-4-5)
[Claude] API 키: ANTHROPIC_API_KEY 사용 (MAPPING, 모델 claude-haiku-4-5)
[agent] 사건 1건, 도구 6개, 조사 LLM ClaudeClient(claude-haiku-4-5), 매핑 LLM ClaudeClient(claude-haiku-4-5)
```

키 값은 어디에도 출력되지 않고, 어떤 이름의 키를 썼는지만 나옵니다.

## 팀별로 바뀐 코드

### 1차 탐지 팀 — `llm/triage_review/llm_review.py`

- 모델을 `TRIAGE_CLAUDE_MODEL`에서 읽습니다. 비어 있으면 예전 고정값 `claude-haiku-4-5`를 씁니다.
- 키는 `TRIAGE_ANTHROPIC_API_KEY`를 먼저 읽고, 비어 있으면 예전처럼 `ANTHROPIC_API_KEY`를 씁니다.
- **`.env`에 아무것도 추가하지 않으면 예전과 똑같이 동작합니다.** 바뀐 출력은 재검토 전에 찍히는 모델·키 이름 한 줄뿐입니다.
- 트리아지는 지금 Claude만 지원합니다. GPT 등 다른 회사 모델을 쓰려면 이 파일을 따로 고쳐야 합니다.

### ATT&CK 매핑 팀 — `llm/investigate/main.py`, `attack_mapping/cli.py`

- `main.py`가 매핑용 LLM을 조사용과 따로 만들어 `run_attack_mapping()`에 넘깁니다.
- 매핑용 LLM을 만들지 못해도(예: `MAPPING_LLM_PROVIDER` 오타) 조사는 계속됩니다. 이 경우 매핑 단계가 다시 만들어 보고,
  그래도 안 되면 그 사건 매핑 결과에 설정 오류로 남깁니다.
- 매핑 CLI(`python -m attack_mapping.cli`)를 따로 돌릴 때도 `MAPPING_` 설정을 쓰고, `.env`는 저장소 루트 파일 하나만 읽습니다.
  예전 `load_dotenv()`는 `llm/investigate/.env`가 있으면 그걸 먼저 읽었습니다.
- 매핑 로직, 프롬프트, 결과 형식은 바뀌지 않았습니다.
- `tests/test_main_attack_mapping.py`의 가짜 `build_llm_client`가 역할 인자를 받게 고쳤습니다.
  매핑에 매핑용 객체가 넘어가는지 확인하는 테스트도 추가했습니다.

### 조사 에이전트 — `llm/investigate/agent/`

- `settings.py`: 역할별로 설정을 읽는 `role_setting(role, name)`을 추가했습니다. 예전 `investigation_setting()`도 그대로 동작합니다.
- `llm_provider.py`: `build_llm_client(role)`로 역할을 받습니다. 기본은 조사(`INVESTIGATION`)입니다.
- `claude_client.py`, `gemini_client.py`: 역할을 받아 그 역할의 키·모델을 읽고, 역할별 기본 모델을 둡니다.

## 자주 묻는 질문

**Q. 기존 `.env`를 그대로 두면 어떻게 되나요?**
- 트리아지: 예전과 같습니다(haiku, 공용 키).
- 매핑: 매핑 줄이 없으면 기본값 `claude-haiku-4-5`로 돕니다.
- 조사 에이전트: `INVESTIGATION_` 이름이 없으면 기본값 `claude-sonnet-5`로 돕니다. 옛 `CLAUDE_MODEL`은 읽지 않으니 꼭 이름을 바꿔 주세요.

**Q. 단계마다 비용을 따로 보고 싶어요.**
역할 전용 키(`TRIAGE_ANTHROPIC_API_KEY`, `MAPPING_ANTHROPIC_API_KEY`, `INVESTIGATION_ANTHROPIC_API_KEY`)를 따로 발급해 넣으면,
Anthropic 콘솔에서 키별 사용량으로 나눠 볼 수 있습니다.

**Q. GPT 모델은요?**
조사 에이전트와 매핑은 지원합니다(`agent/gpt_client.py`, 2026-10-02). `.env`에 `OPENAI_API_KEY`와
`INVESTIGATION_LLM_PROVIDER=openai`, `INVESTIGATION_OPENAI_MODEL=<모델>`을 넣으면 됩니다(매핑은 `MAPPING_`).
모델 기본값은 없어서 반드시 지정해야 합니다. ChatGPT 구독이 아니라 platform.openai.com의 API 키가 필요합니다.
트리아지는 Claude 전용 코드라 1차 탐지 팀과 따로 상의가 필요합니다.

**Q. 대응 권고 단계가 생기면요?**
같은 규칙으로 `RESPONSE_` 접두어를 씁니다.

## 추후 과제

### 1. ATT&CK 매핑을 `llm/mapping/`으로 옮기기 (LLM 테스트 이후, 매핑 팀과 함께)

지금 매핑 코드는 조사 에이전트 폴더 안(`llm/investigate/attack_mapping/` 등 47개 파일)에 있습니다.
9/30 폴더 재배치 때 매핑 자리로 잡아 둔 `llm/mapping/`(현재 `.gitkeep`만 있음)으로 옮기는 게 맞다고 봅니다.
담당 팀이 폴더로 나뉘고, `MAPPING_` 설정 규칙과도 맞습니다.

**지금 옮기지 않는 이유**
- 매핑 팀이 develop을 받아 작업 중이라, 파일 위치가 바뀌면 그쪽 작업과 충돌이 큽니다.
- LLM 모델 비교 테스트 직전이라 구조를 크게 바꾸면 위험합니다.

**옮길 때 같이 정리할 것**

| 얽힌 부분 | 내용 |
| --- | --- |
| 매핑 → 조사 코드 import | `agent.llm_provider`, `agent.settings`(LLM 생성·설정), `agent.tools.time_utils` |
| 조사 → 매핑 import | `llm/investigate/main.py`가 `attack_mapping.cli.process_file`을 직접 import |
| `reporting/` | 최종 보고서 생성(매핑만 씀) — 같이 옮김 |
| 데이터 | `data/attack/`(카탈로그 약 54MB·벡터 캐시, git 미추적) — **EC2 서버 파일도 옮겨야 함** |
| 테스트 | 매핑 테스트 22개가 `llm/investigate`의 pytest 설정·import 방식에 의존 |
| 실행·문서 | `python -m attack_mapping.cli` 실행 위치, `docs/AGENT_ATTACK_MAPPING_FLOW.md` 등, `scripts/fetch_attack_*.py` |

**먼저 정할 것: LLM 공용 코드를 어디에 둘지**
매핑이 LLM 클라이언트를 조사 에이전트 폴더(`llm/investigate/agent/`)에서 빌려 쓰고 있습니다.
- **추천:** `settings.py`, `llm_provider.py`, `claude_client.py`, `gemini_client.py`, `llm_errors.py`, `llm_json.py`를
  공용 폴더(예: `llm/common/`)로 분리합니다. 조사·매핑이 같이 쓰고, 나중에 트리아지가 다른 회사 모델을 쓸 때도 재사용할 수 있습니다.
  GPT 클라이언트를 이 공용 폴더에 한 번만 만들면 세 단계가 모두 쓸 수 있습니다.
- **대안:** 공용 코드는 조사 폴더에 두고 매핑이 경로를 추가해 빌려 씁니다(조사 에이전트가 1차 탐지 코드를 쓰는
  `normalizer_adapter` 방식). 빠르지만 의존 관계가 남습니다.

**진행 방식:** 매핑 팀이 작업을 정리한 시점에 별도 PR로 진행합니다. "폴더 이동만" 커밋과 "import·경로 수정" 커밋을
나누면 리뷰하기 쉽습니다. 작업량은 코드 이동과 테스트에 반나절 정도로 보고, 여기에 팀 간 일정 조율과 EC2 데이터 이동이 더해집니다.

### 2. 트리아지 다른 회사 모델 지원

트리아지(`llm/triage_review/llm_review.py`)는 Anthropic SDK를 직접 씁니다. GPT mini 등과 비교하려면 provider를 고를 수
있게 바꿔야 합니다. 1번의 LLM 공용 코드가 생기면 그걸 쓰는 게 가장 간단합니다. 1차 탐지 팀 코드라 같이 상의합니다.
