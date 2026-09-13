"""raw log -> seed 생성 -> 우선순위 정렬 -> 심층 조사(InvestigationAgent) 전체 파이프라인.

main.py가 예전에는 seed 하나를 직접 만들어서 InvestigationAgent.run(seed)를
한 번 불렀는데, 이제는 Triage/감지 에이전트가 파이프라인에서 빠졌기 때문에
그 앞단(raw log -> seed 후보 생성 -> 우선순위)까지 이 모듈이 담당한다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .loop import InvestigationAgent
from .raw_log_ingestion import fetch_recent_raw_logs
from .seed_generation import SeedGenerator


def run_investigation_pipeline(
    host: str,
    llm_client: Any,
    tool_registry: Any,
    minutes: int = 10,
    max_seeds: Optional[int] = None,
    max_calls: int = 8,
    confidence_threshold: float = 0.85,
    seed_generator: Optional[SeedGenerator] = None,
) -> List[Dict[str, Any]]:
    """전체 파이프라인을 한 번 돌린다.

    1. 최근 `minutes`분 raw log를 host 기준으로 긁어옴
    2. seed_generator(기본: llm_client와 동일한 모델)가 후보 seed를 뽑고 우선순위 정렬
    3. 우선순위 순서대로 (max_seeds개까지) 각 seed를 InvestigationAgent.run()에 넣어 심층 조사
    4. 각 조사 결과(investigation_result)를 우선순위 순서 그대로 리스트로 반환

    seed_generator를 따로 넘기면(예: 더 가벼운 모델의 GeminiClient) triage 단계와
    조사 단계에 서로 다른 모델을 쓸 수 있다. 안 넘기면 llm_client를 그대로 재사용한다.
    """
    raw_logs = fetch_recent_raw_logs(host=host, minutes=minutes)

    generator = seed_generator or SeedGenerator(llm_client)
    seeds = generator.generate(raw_logs, host=host)

    if max_seeds is not None:
        seeds = seeds[:max_seeds]

    results: List[Dict[str, Any]] = []
    for seed in seeds:
        agent = InvestigationAgent(
            llm_client,
            tool_registry,
            max_calls=max_calls,
            confidence_threshold=confidence_threshold,
        )
        results.append(agent.run(seed))

    return results