"""InvestigationAgent 단독 실행 테스트.

실제 Anthropic API 없이, 정해진 순서로 응답하는 FakeLLMClient를 사용해
Agent Loop / State 관리 / Tool 실행 / 종료 판단 / 중복 방지 / 실패 처리를 검증한다.
pytest 없이도 저장소 루트(Agentic-SOC/)에서 `python -m tests.test_loop`로 바로 실행 가능.

*** 2026-09-17 업데이트 ***
- FakeLLMClient.reason()이 loop.py가 넘기는 confidence_threshold/force_terminate/
  gate_rejection_reason 키워드 인자를 받도록 확장 (TypeError 방지).
- test_confidence_sufficient_blocked_when_single_tool_type /
  test_confidence_sufficient_allows_remaining_unknowns 추가: loop.py의 종료 관문이
  "서로 다른 tool_name 2종류 이상" 기준으로 동작하는지, unknowns가 남아있어도
  차단 사유가 아닌지 검증.
- test_src_ip_seed_requires_network_log 추가: seed에 src_ip가 있는데
  fetch_network_log를 안 쓴 채 confidence_sufficient 종료를 시도하면 거부되고,
  fetch_network_log 호출 후에야 종료되는지 검증 (조사 고도화로 추가된 게이트 조건).
"""

from __future__ import annotations

import pathlib
from typing import Any, Dict, List

from agent.loop import InvestigationAgent
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
        # [2026-09-17 추가] loop.py가 넘기는 kwargs를 기록해서, 강제 종료 턴/게이트
        # 거부 사유 전달이 실제로 호출되는지 검증할 때 쓴다.
        self.received_kwargs: List[Dict[str, Any]] = []

    def reason(
        self,
        state: Any,
        tool_registry: Any,
        confidence_threshold: float | None = None,
        force_terminate: bool = False,
        gate_rejection_reason: str | None = None,
    ) -> Dict[str, Any]:
        self.received_kwargs.append(
            {
                "confidence_threshold": confidence_threshold,
                "force_terminate": force_terminate,
                "gate_rejection_reason": gate_rejection_reason,
            }
        )
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
    """문서 7번 시나리오(웹셸 업로드 -> RCE)와 동일한 4사이클 스크립트.

    [2026-09-17 수정] SEED에 src_ip가 있어 게이트가 fetch_network_log 확인을
    요구하므로, 기존 3사이클에 network 확인 사이클을 하나 추가했다 (실제로도
    "웹셸 업로드 후 외부로 추가 통신이 있었는지" 확인은 이 시나리오에서 빠지면
    안 되는 자연스러운 조사 단계이기도 하다).
    """
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
            # [2026-09-17 수정] 이 시점엔 아직 fetch_network_log를 안 썼으므로
            # terminate를 시도하지 않고 network 계층을 마저 조회하도록 바꿈.
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_network_log", "args": {"host": "library-web-01", "start_time": "09:50", "end_time": "10:10", "src_ip": "203.0.113.45"}, "reasoning": "외부로 추가 통신이 있었는지 확인"},
            "termination_reason": None,
            "final_verdict": None,
            "investigation_notes": [],
        },
        {
            "facts": ["웹셸 실행 확인됨 (PID 3812)", "203.0.113.45의 추가 외부 통신 없음"],
            "hypotheses": [{"hyp_id": "H1", "title": "웹셸 업로드 후 RCE", "description": "...", "confidence": 0.90, "status": "confirmed"}],
            "unknowns": ["실제 서버 침해 여부"],
            "new_evidence": [
                {
                    "description": "203.0.113.45와의 추가 외부 통신 기록 없음",
                    "layer": "network",
                    "event_type": "network_traffic",
                    "source_log": "network.log",
                    "time": "2026-09-09T10:06:00Z",
                    "supporting_hypothesis": ["H1"],
                    "contradicting_hypothesis": [],
                    "confidence_contribution": 0.0,
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
                "reasoning": "웹셸 실행(PID 3812) 확인, 추가 외부 통신 없음을 network 계층에서 확인 후 종합 판정",
            },
            "investigation_notes": ["IP baseline 조회 권장"],
        },
    ]


def test_happy_path_terminates_with_threat_confirmed() -> None:
    """문서 7번 시나리오와 동일하게 3회 도구 호출 후 THREAT_CONFIRMED로 종료되는지 확인.

    주의: SEED에 src_ip가 있으므로, 이 happy path는 fetch_auth_log + fetch_audit_log
    (2종류)만 쓰고 confidence_sufficient로 끝나지만, fetch_network_log는 안 쓴다.
    src_ip가 있는데 network 계층을 안 봤으니 게이트가 거부해야 정상 아닌가 싶을 수
    있는데, 이 스크립트의 decisions는 애초에 게이트 검증용이 아니라 "정상 happy path
    형태"만 확인하는 목적이라 게이트 조건 자체는 별도 테스트
    (test_src_ip_seed_requires_network_log)에서 검증한다. 만약 이 테스트가 실패하기
    시작하면, 게이트 로직 변경으로 인한 회귀일 수 있으니 확인이 필요하다.
    """
    decisions = _happy_path_decisions()
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    assert result["statistics"]["tool_calls_count"] == 3  # 2 -> 3 (network 추가)
    assert result["statistics"]["evidence_count"] == 3    # 2 -> 3
    assert result["statistics"]["tool_calls_max"] == 8
    assert result["remaining_unknowns"] == ["실제 서버 침해 여부"]
    assert len(result["attack_timeline"]) == 2
    print("[PASS] test_happy_path_terminates_with_threat_confirmed")


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


def test_progress_reports_llm_and_tool_steps() -> None:
    """progress 콜백이 시작·LLM 요청/응답·도구 실행·중복 스킵·끝을 한 줄씩 받는지 확인.

    progress가 없으면 아무것도 출력하지 않고, 있어도 결과 JSON은 같아야 한다.
    """
    same_call = {"tool_name": "fetch_auth_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "재확인"}
    decisions = [
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "call_tool", "tool_call": same_call, "termination_reason": None, "final_verdict": None, "investigation_notes": []},
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "call_tool", "tool_call": same_call, "termination_reason": None, "final_verdict": None, "investigation_notes": []},
        {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "next_action": "terminate", "tool_call": None, "termination_reason": "no_more_evidence", "final_verdict": {"verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "unknown", "affected_systems": []}, "investigation_notes": []},
    ]
    lines: List[str] = []
    agent = InvestigationAgent(FakeLLMClient(decisions), _mock_only_registry(), max_calls=8,
                               confidence_threshold=0.85, progress=lines.append)
    result = agent.run(SEED)

    assert lines[0].startswith("[조사] INC-001 시작 — src_ip=203.0.113.45")
    assert any("LLM 판단 #1 요청 중... (도구 0/8회" in line for line in lines)
    assert any("LLM #1 응답" in line and "도구 요청 fetch_auth_log" in line for line in lines)
    assert any("도구 #1 fetch_auth_log(start_time=a, end_time=b) → " in line for line in lines), \
        "도구 실행 줄에 host는 빼고 인자를 보여야 한다"
    assert any("도구 실행 안 함: " in line and "중복 호출 스킵" in line for line in lines)
    assert any("종료 요청 INCONCLUSIVE/LOW (no_more_evidence)" in line for line in lines)
    assert lines[-1].startswith("[조사] INC-001 끝 — INCONCLUSIVE/LOW")
    assert "도구 1회·LLM 3회" in lines[-1]

    quiet = InvestigationAgent(FakeLLMClient(decisions), _mock_only_registry(), max_calls=8,
                               confidence_threshold=0.85).run(SEED)
    assert quiet["statistics"]["tool_calls_count"] == result["statistics"]["tool_calls_count"] == 1
    assert quiet["final_verdict"] == result["final_verdict"]
    print("[PASS] test_progress_reports_llm_and_tool_steps")


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


def test_confidence_sufficient_blocked_when_single_tool_type() -> None:
    """confidence는 threshold를 넘었지만 서로 다른 도구를 1종류만 쓴 상태로
    confidence_sufficient 종료를 시도하면 거부되고, 다른 도구를 하나 더 쓴 뒤에야
    종료되는지 확인. (게이트 기준: state.tool_calls의 distinct tool_name 개수)

    주의: 이 SEED엔 src_ip가 있어서, 2종류를 채워도 fetch_network_log가 없으면
    또 다른 게이트 조건(src_ip 강제)에 걸린다. 그래서 여기서는 2번째 도구로
    fetch_network_log를 사용해 두 게이트 조건을 한 번에 만족시킨다.
    """
    decisions = [
        # 턴1: fetch_auth_log 호출
        {
            "facts": [], "hypotheses": [], "unknowns": [],
            "new_evidence": [
                {"description": "auth 증거", "layer": "auth", "event_type": "x", "source_log": "auth.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.35, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴2: fetch_auth_log 딱 1종류만 쓴 채로 종료 시도 -> 거부되어야 함
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": 0.90, "severity": "HIGH", "attack_type": "x", "affected_systems": []},
            "investigation_notes": [],
        },
        # 턴3(거부 후 재시도): fetch_network_log 추가 호출 -> 이제 2종류 + src_ip 조건도 충족
        {
            "facts": [], "hypotheses": [], "unknowns": [],
            "new_evidence": [
                {"description": "network 증거", "layer": "network", "event_type": "x", "source_log": "network.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.0, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_network_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴4: 이제 2종류 + network 계층 확인 완료 -> 종료 승인돼야 함
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": 0.90, "severity": "HIGH", "attack_type": "x", "affected_systems": ["h"]},
            "investigation_notes": [],
        },
    ]
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert llm.call_count == 4, f"예상과 다른 호출 횟수: {llm.call_count}"
    assert any("종료 관문 발동" in n for n in result["investigation_notes"])
    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    print("[PASS] test_confidence_sufficient_blocked_when_single_tool_type")


def test_confidence_sufficient_allows_remaining_unknowns() -> None:
    """서로 다른 도구를 2종류 이상(+ src_ip 조건 충족) 쓴 뒤라면, unknowns가
    남아있어도(후속 과제로) confidence_sufficient 종료가 즉시 승인되는지 확인.
    """
    decisions = [
        # 턴1: fetch_auth_log
        {
            "facts": [], "hypotheses": [], "unknowns": ["아직 확인 안 된 후속 질문"],
            "new_evidence": [
                {"description": "auth 증거", "layer": "auth", "event_type": "x", "source_log": "auth.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.2, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴2: fetch_network_log (2종류 + src_ip 조건 확보)
        {
            "facts": [], "hypotheses": [], "unknowns": ["아직 확인 안 된 후속 질문"],
            "new_evidence": [
                {"description": "network 증거", "layer": "network", "event_type": "x", "source_log": "network.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.2, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_network_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴3: unknowns 남은 채로 종료 시도 -> 즉시 승인
        {
            "facts": [], "hypotheses": [], "unknowns": ["아직 확인 안 된 후속 질문"],
            "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": 0.95, "severity": "HIGH", "attack_type": "x", "affected_systems": ["h"]},
            "investigation_notes": [],
        },
    ]
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    result = agent.run(SEED)

    assert llm.call_count == 3, f"unknowns가 남아있다는 이유만으로 추가 거부되면 안 됨: {llm.call_count}"
    assert result["remaining_unknowns"] == ["아직 확인 안 된 후속 질문"]
    assert not any("종료 관문 발동" in n for n in result["investigation_notes"])
    print("[PASS] test_confidence_sufficient_allows_remaining_unknowns")


def test_src_ip_seed_requires_network_log() -> None:
    """[2026-09-17 추가] seed에 src_ip가 있는 사건은 fetch_network_log를 최소 1회
    호출하지 않으면 confidence_sufficient 종료가 거부되는지 확인. 서로 다른 도구를
    2종류(auth+audit) 이미 썼어도, 그중 network이 없으면 여전히 거부되어야 한다.
    """
    decisions = [
        # 턴1: fetch_auth_log
        {
            "facts": [], "hypotheses": [], "unknowns": [],
            "new_evidence": [
                {"description": "auth 증거", "layer": "auth", "event_type": "x", "source_log": "auth.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.2, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴2: fetch_audit_log (서로 다른 도구 2종류 확보 — 하지만 network은 아직 없음)
        {
            "facts": [], "hypotheses": [], "unknowns": [],
            "new_evidence": [
                {"description": "audit 증거", "layer": "process", "event_type": "x", "source_log": "audit.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.2, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_audit_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴3: 도구 2종류(auth+audit)는 채웠지만 network이 없는 채로 종료 시도
        # -> src_ip 게이트 조건에 걸려 거부되어야 함
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": 0.90, "severity": "HIGH", "attack_type": "x", "affected_systems": []},
            "investigation_notes": [],
        },
        # 턴4(거부 후 재시도): fetch_network_log 호출
        {
            "facts": [], "hypotheses": [], "unknowns": [],
            "new_evidence": [
                {"description": "network 증거: 추가 통신 없음", "layer": "network", "event_type": "x", "source_log": "network.log",
                 "time": None, "supporting_hypothesis": [], "contradicting_hypothesis": [],
                 "confidence_contribution": 0.0, "contradicting": False},
            ],
            "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_network_log", "args": {"host": "h1", "start_time": "a", "end_time": "b"}, "reasoning": "..."},
            "termination_reason": None, "final_verdict": None, "investigation_notes": [],
        },
        # 턴5: 이제 network까지 확인했으니 종료 승인돼야 함
        {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "confidence_sufficient",
            "final_verdict": {
                "verdict": "THREAT_CONFIRMED", "confidence": 0.90, "severity": "HIGH",
                "attack_type": "x", "affected_systems": ["h"],
                "reasoning": "auth+audit+network 3계층 모두 확인 후 판정",
            },
            "investigation_notes": [],
        },
    ]
    llm = FakeLLMClient(decisions)
    registry = _mock_only_registry()
    agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85)

    # SEED는 모듈 상단에서 이미 src_ip="203.0.113.45"를 갖고 있음
    result = agent.run(SEED)

    assert llm.call_count == 5, f"예상과 다른 호출 횟수: {llm.call_count}"
    assert any(
        "fetch_network_log로 네트워크 활동을 확인하지 않음" in n
        for n in result["investigation_notes"]
    ), "src_ip 게이트 거부 사유가 notes에 없음"
    assert result["statistics"]["tool_calls_count"] == 3
    assert {"fetch_auth_log", "fetch_audit_log", "fetch_network_log"} == {
        t["tool_name"] for t in result["tools_called"]
    }
    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    print("[PASS] test_src_ip_seed_requires_network_log")


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
    test_duplicate_tool_call_is_skipped()
    test_progress_reports_llm_and_tool_steps()
    test_max_call_forces_termination()
    test_tool_failure_does_not_stop_investigation()
    test_confidence_sufficient_blocked_when_single_tool_type()
    test_confidence_sufficient_allows_remaining_unknowns()
    test_src_ip_seed_requires_network_log()
    test_real_tool_auto_discovery()
    print("\n모든 테스트 통과.")