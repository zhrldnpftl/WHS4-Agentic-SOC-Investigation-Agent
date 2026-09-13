"""보고서 출력 담당 모듈.

문서 7번 "조사 에이전트의 최종 산출물 구조"와 동일한 필드 구성으로
investigation_result JSON을 조립한다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_investigation_result(
    state: Any,
    termination_reason: str,
    final_verdict: Optional[Dict[str, Any]],
    investigation_id: Optional[str] = None,
) -> Dict[str, Any]:
    investigation_id = investigation_id or (
        f"INV-{state.incident_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
    )

    leading_hyp = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)

    evidence_chain = [
        {
            "sequence": e.sequence,
            "time": e.time,
            "layer": e.layer,
            "event_type": e.event_type,
            "description": e.description,
            "evidence_id": e.evidence_id,
            "supporting_hypothesis": e.supporting_hypothesis,
            "confidence_contribution": e.confidence_contribution,
            "source_log": e.source_log,
        }
        for e in state.evidence
    ]

    contradicting_evidence = [
        {
            "evidence_id": e.evidence_id,
            "description": e.description,
            "confidence_reduction": abs(e.confidence_contribution),
            "explanation": e.description,
        }
        for e in state.contradicting_evidence
    ]

    tools_called = [
        {
            "sequence": t.sequence,
            "tool_name": t.tool_name,
            "input": t.input,
            "result_count": t.result_count,
            "result_summary": t.result_summary,
            **({"error": t.error} if not t.success else {}),
        }
        for t in state.tool_calls
    ]

    confidence_progression = [
        {"stage": c.stage, "confidence": c.confidence, "reason": c.reason}
        for c in state.confidence_progression
    ]

    initial_confidence = (
        state.confidence_progression[0].confidence if state.confidence_progression else 0.0
    )

    verdict = final_verdict or {
        "verdict": "INCONCLUSIVE",
        "confidence": round(state.current_confidence, 3),
        "severity": "UNKNOWN",
        "attack_type": leading_hyp.title if leading_hyp else "unknown",
        "affected_systems": [],
        "summary": "증거가 충분하지 않아 결론을 내리지 못했습니다.",
    }
    verdict.setdefault(
        "summary",
        f"{verdict.get('attack_type', '알 수 없는 공격')} 가능성이 있으며, "
        f"신뢰도는 {verdict.get('confidence', state.current_confidence):.2f}입니다.",
    )

    return {
        "incident_id": state.incident_id,
        "investigation_id": investigation_id,
        "investigation_status": "COMPLETE",
        "timestamp": _now_iso(),
        "initial_seed": state.seed,
        "hypothesis": {
            "title": leading_hyp.title if leading_hyp else None,
            "description": leading_hyp.description if leading_hyp else None,
            "confidence_initial": initial_confidence,
        },
        "evidence_chain": evidence_chain,
        "contradicting_evidence": contradicting_evidence,
        "attack_timeline": getattr(state, "attack_timeline", []),
        "confidence_progression": confidence_progression,
        "final_verdict": verdict,
        "tools_called": tools_called,
        "statistics": {
            "tool_calls_count": len(state.tool_calls),
            "tool_calls_max": None,  # InvestigationAgent.run()에서 채워 넣음
            "confidence_increase": round(state.current_confidence - initial_confidence, 3),
            "evidence_count": len(state.evidence),
            "contradicting_evidence_count": len(state.contradicting_evidence),
            "termination_reason": termination_reason,
        },
        "remaining_unknowns": state.unknowns,
        "investigation_notes": state.notes,
    }


# ----------------------------------------------------------------------
# 사람이 읽는 텍스트 리포트 (대시보드/디스코드 등에 그대로 출력하는 용도)
# ----------------------------------------------------------------------
_SOURCE_LABELS = (
    ("suricata", "Suricata"),
    ("apache", "Apache"),
    ("nginx", "Nginx"),
    ("auth", "Auth"),
    ("audit", "Audit"),
    ("eve.json", "Suricata"),
)


def _source_label(evidence: Dict[str, Any]) -> str:
    """source_log 문자열에서 [Suricata]/[Apache]/[Auth]/[Audit] 같은 표시 라벨을 뽑는다.
    매칭되는 키워드가 없으면 layer 값을 그대로 대문자화해서 사용한다.
    """
    source_log = (evidence.get("source_log") or "").lower()
    for keyword, label in _SOURCE_LABELS:
        if keyword in source_log:
            return label
    return (evidence.get("layer") or "unknown").capitalize()


def _hhmm(time_str: Optional[str]) -> str:
    """'2026-09-09T10:05:45Z' -> '10:05'. 파싱 실패 시 원본을 그대로 반환한다."""
    if not time_str:
        return "--:--"
    try:
        cleaned = time_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).strftime("%H:%M")
    except ValueError:
        # 이미 'HH:MM' 형태 등 ISO가 아닌 경우 그대로 사용
        return time_str


def format_text_report(result: Dict[str, Any]) -> str:
    """investigation_result(JSON)를 대시보드/Discord 등에 바로 붙여넣을 텍스트 리포트로 변환한다."""
    lines = []
    lines.append("INVESTIGATION RESULT")
    lines.append("━" * 28)
    lines.append(f"Incident {result['incident_id']}")
    lines.append("")

    lines.append("Initial Hypothesis")
    lines.append(result["hypothesis"].get("title") or "(가설 없음)")
    lines.append("")

    # 지지/반박 증거를 시간(sequence) 순으로 합쳐서 E1, E2... 로 번호를 매긴다.
    all_evidence = sorted(
        result["evidence_chain"] + result["contradicting_evidence"],
        key=lambda e: e.get("sequence", 0),
    )
    if all_evidence:
        lines.append("Investigation Findings")
        for ev in all_evidence:
            label = _source_label(ev)
            lines.append(f"E{ev.get('sequence', '?')} [{label}] {ev['description']}")
        lines.append("")

    timeline = result.get("attack_timeline") or []
    if timeline:
        lines.append("Timeline")
        for t in timeline:
            lines.append(f"{_hhmm(t.get('time'))} {t.get('event', '')}")
        lines.append("")

    verdict = result["final_verdict"]
    lines.append("Provisional Conclusion")
    lines.append(verdict.get("summary", ""))
    lines.append("")

    lines.append(f"Supporting Evidence {len(result['evidence_chain'])}")
    lines.append(f"Contradicting Evidence {len(result['contradicting_evidence'])}")
    unresolved = result.get("remaining_unknowns") or []
    lines.append("Unresolved " + (unresolved[0] if unresolved else "없음"))
    for extra in unresolved[1:]:
        lines.append("           " + extra)
    lines.append("")

    lines.append(f"Investigation Confidence {verdict.get('confidence', 0):.2f}")

    return "\n".join(lines)
