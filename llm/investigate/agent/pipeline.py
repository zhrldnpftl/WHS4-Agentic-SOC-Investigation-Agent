"""조사 파이프라인 — 1차 탐지가 넘긴 사건들을 받은 순서대로 하나씩 끝까지 조사한다.

역할
  사건(Incident)마다 조사 루프 입력으로 바꾸고(incident_input.to_investigation_seed),
  InvestigationAgent(조사 루프)를 돌려 결과를 모은다. 사건을 찾고 고르는 일(로그 수집·탐지·
  사건 묶기·우선순위)은 1차 탐지가 하므로 여기서는 하지 않는다. 받은 순서가 곧 조사 순서다.

누가 부르나
  [5]  main.py main()                      → run_investigation_pipeline()
  tests/test_pipeline.py, tests/test_abcd_pipeline.py, scripts/demo_abcd.py

무엇을 부르나
  [6]  agent/incident_input.py     to_investigation_seed()    1차 탐지 Incident → 조사 루프 입력
  [16] agent/loop.py               InvestigationAgent.run()   사건 하나를 끝까지 조사
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional

from .incident_input import to_investigation_seed
from .loop import InvestigationAgent

# [5] ← main.py에서 호출됨
def run_investigation_pipeline(
    incidents: Iterable[Dict[str, Any]],
    llm_client: Any,
    tool_registry: Any,
    host: Optional[str] = None,
    max_calls: int = 8,
    confidence_threshold: float = 0.85,
    network_precheck: bool = False,
    strict_termination: bool = False,
    on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """사건들을 받은 순서대로 조사하고, 사건별 조사 결과(investigation_result)를 같은 순서로 돌려준다.

    host는 사건에 수집 서버 이름이 없을 때 채울 값이다(1차 탐지 Incident에는 host가 없다).
    on_result는 사건 하나의 조사가 끝날 때마다 바로 불린다(main.py는 여기서 결과를 저장한다).
    progress는 조사 진행(LLM 호출·도구 실행·종료 관문)을 한 줄씩 받는 콜백이다(None이면 출력 없음).
    다 모은 뒤 저장하던 때는 뒤 사건에서 예외가 나면 앞서 끝난 사건 결과까지 사라졌다(2026-09-28 EC2).
    LLM API 일시 오류는 조사 루프가 그 사건만 조사 미완료로 돌려주므로 여기서 멈추지 않는다.
    """
    results: List[Dict[str, Any]] = []
    for incident in incidents:
        # [6] → agent/incident_input.py to_investigation_seed() — 조사 루프가 읽는 필드로 옮긴다
        seed = to_investigation_seed(incident, host=host)
        # [16] → agent/loop.py InvestigationAgent.run(seed) — 사건마다 새 조사 루프를 만들어 끝까지 조사
        agent = InvestigationAgent(
            llm_client,
            tool_registry,
            max_calls=max_calls,
            confidence_threshold=confidence_threshold,
            network_precheck=network_precheck,  # src_ip 사건은 network를 코드가 먼저 조회 (loop.py 참고)
            strict_termination=strict_termination,  # 조기 종료 관문 강화 (loop.py _termination_rejections)
            progress=progress,
        )
        result = agent.run(seed)  # [42] ← 조사 결과 JSON(dict) 하나
        results.append(result)
        if on_result is not None:
            on_result(result)  # [45] main.py: 끝난 사건은 다음 사건 조사 전에 바로 저장
    # [43] → main.py로 사건별 결과 리스트를 돌려준다
    return results
