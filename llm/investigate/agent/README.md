# agent/

조사 에이전트(Investigation Agent) 패키지 본체입니다. 역할 분담 문서의 5개 항목이
아래 모듈에 각각 대응합니다.

| 역할 | 모듈 |
| --- | --- |
| Agent Loop 총괄 | `loop.py` (`InvestigationAgent`) |
| State / Evidence 관리 | `models.py` (`AgentState`, `Evidence`, `Hypothesis`) |
| Tool 연결·실행 계층 | `tools/` (`ToolRegistry`, `ToolSpec`, `build_default_registry`) — 자세한 건 [tools/README.md](tools/README.md) |
| Agent 판단·Prompt | `prompts.py`, `claude_client.py` (Claude), `gemini_client.py` (Gemini) |
| Agent 제어 + 최종 산출물 | `loop.py` 내 종료/중복/실패 처리 + `report.py` |
| 결과 JSON | `report.py` (`build_investigation_result`) |

조사 입력 (사건을 찾고 고르는 일은 1차 탐지가 한다):

| 역할 | 모듈 |
| --- | --- |
| 사건 파일 읽기·조사 입력 변환 | `incident_input.py` (`load_incidents`, `to_investigation_seed`) |
| 사건별 조사 실행 | `pipeline.py` (`run_investigation_pipeline`) |

## 로그 정규화는 여기서 직접 안 합니다

`tools/real/*.py`(조사 도구)는 로그를 자기가 직접 파싱하지 않고, 1차 탐지팀이 만든 공통 정규화 함수를 가져다 씁니다.
그 함수들은 같은 저장소 루트의 1차 탐지 코드 `detection_pipeline/tools/`에 있고(복사본 없이 원본을 직접 import),
`agent/tools/normalizer_adapter.py`가 그걸 가져다 쓰는 유일한 연결 지점입니다.
`tools/real/fetch_*_log.py`(조사 도구)와 `detection_pipeline/tools/fetch_*_log.py`(정규화 함수)는 이름만 같고 다른 코드입니다.
왜 이렇게 나눴는지는 [docs/normalizer-migration.md](../docs/normalizer-migration.md)에
정리돼 있습니다. (자체 파서 폴더 `tools/parsers/`는 완전히 없어졌습니다 —
마지막 남은 헬퍼 `process_tree.py`도 `tools/real/get_process_tree.py` 안으로 합쳤습니다.)

## 실행

```bash
python main.py <사건 파일>   # 1차 탐지 Incident JSONL 또는 직접 작성한 사건 JSON
```

설정은 저장소 루트 `.env` 하나에 둔다(필요한 값은 저장소 루트 `.env.example`의 조사 에이전트 부분, 읽는 규칙은 `settings.py`). 테스트는 [tests/README.md](../tests/README.md).
