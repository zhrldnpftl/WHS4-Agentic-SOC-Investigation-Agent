"""SeedGenerator(agent/seed_generation.py) 단독 테스트.

실제 LLM을 부르지 않고, .complete_json()만 흉내내는 가짜 클라이언트로
- 우선순위(priority) 정렬
- candidates가 비어있을 때(이상 없음) 빈 리스트 반환
- raw_logs 자체가 비어있으면 LLM 호출 없이 바로 빈 리스트 반환
를 검증한다.

pytest 없이도 저장소 루트에서 `python -m tests.test_seed_generation`으로 실행 가능.
"""

from __future__ import annotations

from typing import Any, Dict, List

from agent.seed_generation import SeedGenerator


class FakeSeedLLMClient:
    """complete_json() 호출 시 미리 정해둔 decision을 그대로 반환."""

    def __init__(self, decision: Dict[str, Any]) -> None:
        self.decision = decision
        self.call_count = 0
        self.last_user_prompt = None

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        self.call_count += 1
        self.last_user_prompt = user_prompt
        return self.decision


def test_generate_sorts_by_priority() -> None:
    decision = {
        "candidates": [
            {"incident_id": "INC-B", "priority": 2, "trigger_description": "b"},
            {"incident_id": "INC-A", "priority": 1, "trigger_description": "a"},
            {"incident_id": "INC-C", "priority": 3, "trigger_description": "c"},
        ]
    }
    llm = FakeSeedLLMClient(decision)
    generator = SeedGenerator(llm)

    raw_logs: List[Dict[str, Any]] = [{"_source_type": "auditd", "timestamp": "2026-09-09T10:00:00Z"}]
    seeds = generator.generate(raw_logs, host="web-01")

    assert [s["incident_id"] for s in seeds] == ["INC-A", "INC-B", "INC-C"]
    assert llm.call_count == 1
    print("[PASS] test_generate_sorts_by_priority")


def test_generate_handles_no_candidates() -> None:
    llm = FakeSeedLLMClient({"candidates": []})
    generator = SeedGenerator(llm)

    seeds = generator.generate([{"timestamp": "2026-09-09T10:00:00Z"}], host="web-01")

    assert seeds == []
    print("[PASS] test_generate_handles_no_candidates")


def test_generate_skips_llm_call_when_no_raw_logs() -> None:
    llm = FakeSeedLLMClient({"candidates": [{"incident_id": "SHOULD-NOT-APPEAR", "priority": 1}]})
    generator = SeedGenerator(llm)

    seeds = generator.generate([], host="web-01")

    assert seeds == []
    assert llm.call_count == 0, "raw_logs가 비어있으면 LLM을 부를 필요가 없다"
    print("[PASS] test_generate_skips_llm_call_when_no_raw_logs")


def test_generate_treats_missing_priority_as_lowest() -> None:
    decision = {
        "candidates": [
            {"incident_id": "INC-NO-PRIORITY"},  # priority 키 자체가 없는 경우
            {"incident_id": "INC-HIGH", "priority": 1},
        ]
    }
    llm = FakeSeedLLMClient(decision)
    generator = SeedGenerator(llm)

    seeds = generator.generate([{"timestamp": "2026-09-09T10:00:00Z"}], host="web-01")

    assert [s["incident_id"] for s in seeds] == ["INC-HIGH", "INC-NO-PRIORITY"]
    print("[PASS] test_generate_treats_missing_priority_as_lowest")


if __name__ == "__main__":
    test_generate_sorts_by_priority()
    test_generate_handles_no_candidates()
    test_generate_skips_llm_call_when_no_raw_logs()
    test_generate_treats_missing_priority_as_lowest()
    print("\n모든 테스트 통과.")