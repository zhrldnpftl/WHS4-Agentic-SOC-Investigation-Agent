"""InvestigationAgent 단독 실행 테스트.

실제 Anthropic API 없이, 정해진 순서로 응답하는 FakeLLMClient를 사용해
Agent Loop / State 관리 / Tool 실행 / 종료 판단 / 중복 방지 / 실패 처리를 검증한다.
pytest 없이도 저장소 루트(Agentic-SOC/)에서 `python -m tests.test_loop`로 바로 실행 가능.
"""

from __future__ import annotations

import pathlib
from typing import Any, Dict, List

from agent.loop import InvestigationAgent
from agent.report import format_text_report
from agent.tools import ToolRegistry, ToolSpec, build_default_registry
from agent.tools.mock_tools import MOCK_HANDLERS


def _mock_only_registry() -> ToolRegistry:
    """항상 목업 6종만 등록한 레지스트리를 만든다.

    agent/tools/real/ 폴더에 실제 구현이 추가돼도(자동 탐색 대상이라도), 이 테스트는
    FakeLLMClient의 스크립트된 각본대로만 진행되는 순수 단위 테스트라 실제 tool
    코드가 끼어들면 안 된다 — 특히 S3를 보는 real 구현이 잡히면 로컬 환경변수/AWS
    자격 증명 상태에 따라 테스트가 네트워크를 타거나 결과가 흔들릴 수 있다.
    handlers=MOCK_HANDLERS로 명시하면 real/ 자동 탐색보다 우선순위가 높아서
    (build_default_registry 우선순위 1번) 항상 목업만 쓰인다.
    """
    return build_default_registry(handlers=MOCK_HANDLERS)


class FakeLLMClient:
    """호출될 때마다 미리 정의된 decision을 순서대로 반환하는 테스트용 클라이언트."""

    def __init__(self, scripted_decisions: List[Dict[str, Any]]) -> None:
        self._decisions = scripted_decisions
        self.call_count = 0

    def reason(self, state: Any, tool_registry: Any) -> Dict[str, Any]:
        decision = self._decisions[min(self.call_count, len(self._decisions) - 1)]
        self.call_count += 1
        return decision


SEED = {
    "incident_id": "INC-001",
    "detection_source": "sigma_rule",
    "rule_id": "RULE-0042",
    "trigger_time": "2026-09-09T10:01:12Z",
    "trigger_description": "Suspicious file upload to /upload.php",
    "confidence_initial": 0.55,
    "host": "library-web-01",
    "src_ip": "203.0.113.45",
}


def _happy_path_decisions() -> List[Dict[str, Any]]:
    """문서 7번 시나리오(웹셸 업로드 -> RCE)와 동일한 3사이클 스크립트."""
    return [
        {
            "facts": ["203.0.113.45가 /upload.php에 POST 요청, HTTP 200 응답"],
            "hypotheses": [
                {"hyp_id": "H1", "title": "웹셸 업로드 후 RCE", "description": "...", "confidence": 0.55, "status": "active"}
            ],
            "unknowns": ["파일이 실행되었는가?"],
            "new_evidence": [],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log", "args": {"host": "library-web-01", "start_time": "09:50", "end_time": "10:10"}, "reasoning": "로그인 흔적 확인"},
            "termination_reason": None,
            "final_verdict": None,
            "investigation_notes": [],
        },
        {
            "facts": ["www-data의 정상 로그인 확인됨"],
            "hypotheses": [{"hyp_id": "H1", "title": "웹셸 업로드 후 RCE", "description": "...", "confidence": 0.65, "status": "active"}],
            "unknowns": ["파일이 실행되었는가?"],
            "new_evidence": [
                {
                    "description": "www-data 정상 로그인 1건",
                    "layer": "auth",
                    "event_type": "user_activity",
                    "source_log": "auth.log",
                    "time": "2026-09-09T10:05:30Z",
                    "supporting_hypothesis": ["H1"],
                    "contradicting_hypothesis": [],
                    "confidence_contribution": 0.10,
                    "contradicting": False,
                }
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_audit_log", "args": {"host": "library-web-01", "start_time": "09:50", "end_time": "10:10"}, "reasoning": "프로세스 실행 확인"},
            "termination_reason": None,
            "final_verdict": None,
            "investigation_notes": [],
        },
        {
            "facts": ["웹셸 실행 확인됨 (PID 3812)"],
            "hypotheses": [{"hyp_id": "H1", "title": "웹셸 업로드 후 RCE", "description": "...", "confidence": 0.90, "status": "confirmed"}],
            "unknowns": ["실제 서버 침해 여부"],
            "new_evidence": [
                {
                    "description": "/bin/sh 실행 (PID 3812)",
                    "layer": "process",
                    "event_type": "process_exec",
                    "source_log": "audit.log",
                    "time": "2026-09-09T10:05:45Z",
                    "supporting_hypothesis": ["H1"],
                    "contradicting_hypothesis": [],
                    "confidence_contribution": 0.25,
                    "contradicting": False,
                }
            ],
            "next_action": "terminate",
            "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "attack_timeline": [
                {"time": "2026-09-09T10:01:12Z", "event": "파일 업로드 시작", "source": "203.0.113.45"},
                {"time": "2026-09-09T10:05:45Z", "event": "웹셸 실행 (PID 3812)", "source": "apache worker"},
            ],
            "final_verdict": {
                "verdict": "THREAT_CONFIRMED",
                "confidence": 0.90,
                "severity": "CRITICAL",
                "attack_type": "Web Shell Upload + RCE",
                "affected_systems": ["library-web-01"],
                "summary": "웹셸 업로드 후 원격 코드 실행 공격 가능성이 높습니다.",
            },
            "investigation_notes": ["IP baseline 조회 권장"],
        },
    ]


def test_happy_path_terminates_with_threat_confirmed() -> None:
    """문서 7번 시나리오와 동일하게 3회 도구 호출 후 THREAT_CONFIRMED로 종료되는지 확인."""
    decisions = _happy_path_decisions()
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    assert result["statistics"]["tool_calls_count"] == 2
    assert result["statistics"]["evidence_count"] == 2
    assert result["statistics"]["tool_calls_max"] == 8
    assert result["remaining_unknowns"] == ["실제 서버 침해 여부"]
    assert len(result["attack_timeline"]) == 2
    print("[PASS] test_happy_path_terminates_with_threat_confirmed")


def test_format_text_report_renders_expected_sections() -> None:
    """format_text_report()가 사용자 예시 포맷(E1.., Timeline, Provisional Conclusion 등)대로 나오는지 확인."""
    llm = FakeLLMClient(_happy_path_decisions())
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)
    text = format_text_report(result)

    assert "INVESTIGATION RESULT" in text
    assert "Incident INC-001" in text
    assert "Initial Hypothesis" in text
    assert "E1 [" in text and "E2 [" in text
    assert "Timeline" in text and "10:01" in text
    assert "Provisional Conclusion" in text
    assert "웹셸 업로드 후 원격 코드 실행" in text
    assert "Supporting Evidence 2" in text
    assert "Contradicting Evidence 0" in text
    assert "Unresolved 실제 서버 침해 여부" in text
    assert "Investigation Confidence 0.90" in text
    print("[PASS] test_format_text_report_renders_expected_sections")


def test_duplicate_tool_call_is_skipped() -> None:
    """동일 tool+args를 반복 요청해도 실제 도구 호출은 1회만 일어나는지 확인."""
    same_call = {"tool_name": "fetch_auth_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "재확인"}
    decisions = [
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "call_tool", "tool_call": same_call, "termination_reason": None, "final_verdict": None, "investigation_notes": []},
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "call_tool", "tool_call": same_call, "termination_reason": None, "final_verdict": None, "investigation_notes": []},
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "terminate", "tool_call": None, "termination_reason": "no_more_evidence", "final_verdict": {"verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "unknown", "affected_systems": []}, "investigation_notes": []},
    ]
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert result["statistics"]["tool_calls_count"] == 1, "중복 호출은 실행되지 않아야 한다"
    assert any("중복 호출 스킵" in n for n in result["investigation_notes"])
    print("[PASS] test_duplicate_tool_call_is_skipped")


def test_max_call_forces_termination() -> None:
    """LLM이 계속 call_tool만 반환해도 max_calls에서 강제 종료되는지 확인."""

    def make_call(i: int) -> Dict[str, Any]:
        return {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_web_log", "args": {"host": "h", "start_time": str(i), "end_time": str(i)}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        }

    decisions = [make_call(i) for i in range(20)]  # 절대 terminate 하지 않음
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=3, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert result["statistics"]["tool_calls_count"] == 3
    assert result["statistics"]["termination_reason"] == "max_call_reached"
    print("[PASS] test_max_call_forces_termination")


def test_tool_failure_does_not_stop_investigation() -> None:
    """도구 호출이 실패해도 조사가 중단되지 않고 계속 진행되는지 확인."""

    def failing_handler(args: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("log source unreachable")

    registry = ToolRegistry()
    registry.register(ToolSpec("fetch_web_log", "실패하는 목업", ["host"], [], handler=failing_handler))

    decisions = [
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_web_log", "args": {"host": "h"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "no_more_evidence",
            "final_verdict": {"verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "unknown", "affected_systems": []},
            "investigation_notes": [],
        },
    ]
    llm = FakeLLMClient(decisions)
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert result["statistics"]["tool_calls_count"] == 1
    assert result["tools_called"][0]["result_summary"] in ("예외 발생", "호출 실패")
    assert result["investigation_status"] == "COMPLETE"
    print("[PASS] test_tool_failure_does_not_stop_investigation")


def test_real_tool_auto_discovery() -> None:
    """agent/tools/real/<도구이름>.py에 같은 이름의 함수를 넣으면 자동으로 연결되는지 확인.
    실제 팀원이 파일을 추가하는 상황을 그대로 재현: 파일을 실제로 썼다가 테스트 후 원복한다.
    """
    import importlib
    import sys

    agent_dir = pathlib.Path(__file__).resolve().parent.parent / "agent"
    target_path = agent_dir / "tools" / "real" / "resolve_ip_geo.py"
    module_name = "agent.tools.real.resolve_ip_geo"

    backup = target_path.read_text(encoding="utf-8") if target_path.exists() else None

    try:
        target_path.write_text(
            "def resolve_ip_geo(args):\n"
            "    return {'count': 1, 'summary': 'REAL-TOOL-USED', 'records': []}\n",
            encoding="utf-8",
        )
        sys.modules.pop(module_name, None)
        importlib.invalidate_caches()

        registry = build_default_registry()  # 이 테스트는 자동 탐색 자체를 검증하는 거라 목업 고정 X
        result = registry.call("resolve_ip_geo", {"ip": "1.2.3.4"})

        assert result["summary"] == "REAL-TOOL-USED", "real/ 폴더의 실제 함수가 사용되어야 한다"
        print("[PASS] test_real_tool_auto_discovery")
    finally:
        sys.modules.pop(module_name, None)
        if backup is not None:
            target_path.write_text(backup, encoding="utf-8")
        elif target_path.exists():
            target_path.unlink()
        importlib.invalidate_caches()


if __name__ == "__main__":
    test_happy_path_terminates_with_threat_confirmed()
    test_format_text_report_renders_expected_sections()
    test_duplicate_tool_call_is_skipped()
    test_max_call_forces_termination()
    test_tool_failure_does_not_stop_investigation()
    test_real_tool_auto_discovery()
    print("\n모든 테스트 통과.")