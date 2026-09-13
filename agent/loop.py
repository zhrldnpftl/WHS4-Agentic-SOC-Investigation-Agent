"""Agent Loop 총괄 + Agent 제어 담당 모듈.

Seed -> LLM 판단 -> Tool 선택/실행 -> 결과 관찰 -> 재판단 -> 종료 흐름을
구현하고, 그 안에서 아래 제어 로직을 함께 수행한다.
  - 중복 호출 방지 (동일 tool+args 재호출 차단)
  - max_call 도달 시 강제 종료
  - 도구 호출 실패 시에도 조사 전체를 중단하지 않고 계속 진행
  - 3가지 종료 조건(confidence_sufficient / no_more_evidence / max_call) 판단
"""

from __future__ import annotations

from typing import Any, Dict

from .models import AgentState, Evidence, Hypothesis, TerminationReason, ToolCallRecord
from .report import build_investigation_result
from .tools import ToolRegistry, ToolValidationError


class InvestigationAgent:
    def __init__(
        self,
        llm_client: Any,
        tool_registry: ToolRegistry,
        max_calls: int = 8,
        confidence_threshold: float = 0.85,
    ) -> None:
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.max_calls = max_calls
        self.confidence_threshold = confidence_threshold

    def run(self, seed: Dict[str, Any]) -> Dict[str, Any]:
        state = AgentState(incident_id=seed["incident_id"], seed=seed)
        state.current_confidence = float(seed.get("confidence_initial", 0.5))
        state.record_confidence("initial", seed.get("trigger_description", "Triage 판정"))

        termination_reason = None
        final_verdict = None
        max_cycles = self.max_calls + 3  # LLM이 종료 판단을 안 내려도 무한루프에 빠지지 않도록 하는 안전장치

        for _ in range(max_cycles):
            decision = self.llm_client.reason(state, self.tool_registry)
            self._apply_decision(state, decision)
            state.pending_observations = []

            if decision.get("next_action") == "terminate":
                termination_reason = (
                    decision.get("termination_reason") or TerminationReason.NO_MORE_EVIDENCE.value
                )
                final_verdict = decision.get("final_verdict")
                break

            if len(state.tool_calls) >= self.max_calls:
                termination_reason = TerminationReason.MAX_CALL_REACHED.value
                final_verdict = decision.get("final_verdict")
                break

            self._execute_tool_call(state, decision.get("tool_call") or {})

            if state.current_confidence >= self.confidence_threshold:
                state.notes.append("신뢰도 임계값 도달 — 다음 사이클에서 종료 여부 재확인 필요")
        else:
            termination_reason = TerminationReason.MAX_CALL_REACHED.value

        result = build_investigation_result(state, termination_reason, final_verdict)
        result["statistics"]["tool_calls_max"] = self.max_calls
        return result

    # ------------------------------------------------------------------
    # LLM 판단 결과를 State에 반영 (State / Evidence 관리 영역과 맞닿는 지점)
    # ------------------------------------------------------------------
    def _apply_decision(self, state: AgentState, decision: Dict[str, Any]) -> None:
        if "facts" in decision:
            state.facts = decision["facts"]
        if "unknowns" in decision:
            state.unknowns = decision["unknowns"]

        for h in decision.get("hypotheses", []) or []:
            state.hypotheses[h["hyp_id"]] = Hypothesis(
                hyp_id=h["hyp_id"],
                title=h.get("title", ""),
                description=h.get("description", ""),
                confidence=h.get("confidence", 0.0),
                status=h.get("status", "active"),
            )

        for ev in decision.get("new_evidence", []) or []:
            contradicting = bool(ev.get("contradicting", False))
            contribution = float(ev.get("confidence_contribution", 0.0))
            sequence = len(state.evidence) + len(state.contradicting_evidence) + 1
            evidence = Evidence.new(
                sequence=sequence,
                time=ev.get("time"),
                layer=ev.get("layer", "unknown"),
                event_type=ev.get("event_type", ""),
                description=ev.get("description", ""),
                source_log=ev.get("source_log", ""),
                supporting_hypothesis=ev.get("supporting_hypothesis", []),
                contradicting_hypothesis=ev.get("contradicting_hypothesis", []),
                confidence_contribution=contribution,
            )
            state.add_evidence(evidence, contradicting=contradicting)

            delta = -abs(contribution) if contradicting else contribution
            stage_label = f"after_tool_{len(state.tool_calls)}"
            state.update_confidence(delta, stage_label, evidence.description)

        if decision.get("investigation_notes"):
            state.notes.extend(decision["investigation_notes"])

        if decision.get("attack_timeline"):
            state.attack_timeline = decision["attack_timeline"]

    # ------------------------------------------------------------------
    # Tool 연결·실행 계층 호출 + 제어(중복 방지, 실패 처리)
    # ------------------------------------------------------------------
    def _execute_tool_call(self, state: AgentState, tool_call: Dict[str, Any]) -> None:
        name = tool_call.get("tool_name")
        args = tool_call.get("args") or {}

        if not name:
            state.notes.append("LLM이 next_action=call_tool을 선택했지만 tool_call을 채우지 않았습니다.")
            return

        if state.already_called(name, args):
            state.notes.append(f"중복 호출 스킵: {name}({args}) — 이미 조회된 조합입니다.")
            return

        try:
            self.tool_registry.validate_args(name, args)
            result = self.tool_registry.call(name, args)
            state.mark_called(name, args)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=result.get("count", 0),
                    result_summary=result.get("summary", ""),
                    success=True,
                )
            )
            state.pending_observations.append({"tool_name": name, "args": args, "result": result})
        except (ToolValidationError, KeyError, NotImplementedError) as exc:
            state.mark_called(name, args)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="호출 실패",
                    success=False,
                    error=str(exc),
                )
            )
            state.notes.append(f"도구 호출 실패({name}): {exc} — 조사는 계속 진행됩니다.")
        except Exception as exc:  # 예상치 못한 오류도 조사 전체를 중단시키지 않는다
            state.mark_called(name, args)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="예외 발생",
                    success=False,
                    error=str(exc),
                )
            )
            state.notes.append(f"도구 호출 중 예외({name}): {exc}")
