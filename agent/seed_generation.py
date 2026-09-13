"""seed 생성(경량 LLM triage) 담당 모듈.

raw log 더미를 받아서 LLM(보통 가벼운 모델, 예: gemini-flash-lite)에게
"조사할 가치가 있는 후보"를 뽑고 우선순위를 매기게 한 뒤, 그 결과를
InvestigationAgent.run(seed)에 바로 넣을 수 있는 seed 리스트로 돌려준다.

llm_client는 .complete_json(system_prompt, user_prompt) 인터페이스만 있으면
되므로, agent/claude_client.py의 ClaudeClient든 agent/gemini_client.py의
GeminiClient든 그대로 넣을 수 있다. 조사 단계와 다른(더 가벼운) 모델을 쓰고
싶으면 그냥 별도의 GeminiClient(model="...") 인스턴스를 만들어서 넘기면 된다.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .seed_prompts import SEED_SYSTEM_PROMPT, build_seed_user_prompt


class SeedGenerator:
    def __init__(self, llm_client: Any) -> None:
        self.llm_client = llm_client

    def generate(self, raw_logs: List[Dict[str, Any]], host: str) -> List[Dict[str, Any]]:
        """raw_logs를 스캔해서 seed 후보 리스트를 우선순위(priority 오름차순)로 정렬해 반환.
        candidates가 없으면 빈 리스트를 반환한다 (이상 없음으로 처리).
        """
        if not raw_logs:
            return []

        user_prompt = build_seed_user_prompt(raw_logs, host)
        decision = self.llm_client.complete_json(SEED_SYSTEM_PROMPT, user_prompt)

        candidates = decision.get("candidates") or []
        # priority가 없거나 이상한 값이면 가장 낮은 우선순위(맨 뒤)로 보낸다.
        candidates.sort(key=lambda c: c.get("priority", 999))
        return candidates