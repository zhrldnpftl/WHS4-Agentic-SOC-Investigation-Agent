"""State / Evidence 관리 담당 모듈.

조사 과정에서 쌓이는 facts / hypothesis / unknowns / evidence / 조사 이력을
하나의 AgentState 객체로 관리한다. Agent Loop(loop.py)는 매 사이클마다
이 State를 읽고, LLM 판단 결과로 갱신한다.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class VerdictType(str, Enum):
    THREAT_CONFIRMED = "THREAT_CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class TerminationReason(str, Enum):
    CONFIDENCE_SUFFICIENT = "confidence_sufficient"
    NO_MORE_EVIDENCE = "no_more_evidence"
    MAX_CALL_REACHED = "max_call_reached"


_evidence_counter = itertools.count(1)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Evidence:
    """조사 중 확보한 증거 하나. 지지/반박 증거 모두 이 클래스로 표현한다."""

    evidence_id: str
    sequence: int
    time: Optional[str]
    layer: str
    event_type: str
    description: str
    source_log: str
    supporting_hypothesis: List[str] = field(default_factory=list)
    contradicting_hypothesis: List[str] = field(default_factory=list)
    confidence_contribution: float = 0.0

    @classmethod
    def new(cls, sequence: int, **kwargs: Any) -> "Evidence":
        eid = f"EVID-{next(_evidence_counter):03d}"
        return cls(evidence_id=eid, sequence=sequence, **kwargs)


@dataclass
class Hypothesis:
    hyp_id: str
    title: str
    description: str
    confidence: float
    status: str = "active"  # active | confirmed | rejected


@dataclass
class ToolCallRecord:
    sequence: int
    tool_name: str
    input: Dict[str, Any]
    result_count: int
    result_summary: str
    success: bool = True
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now_iso)


@dataclass
class ConfidenceStep:
    stage: str
    confidence: float
    reason: str


@dataclass
class AgentState:
    """조사 진행 상태 전체를 담는 컨테이너.

    facts / hypotheses / unknowns 는 문서의 Stage 1 산출물에 대응하고,
    evidence / tool_calls / confidence_progression 은 Stage 3 및 반복 결과를 누적한다.
    """

    incident_id: str
    seed: Dict[str, Any]

    facts: List[str] = field(default_factory=list)
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
    unknowns: List[str] = field(default_factory=list)

    evidence: List[Evidence] = field(default_factory=list)
    contradicting_evidence: List[Evidence] = field(default_factory=list)

    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    called_signatures: Set[Tuple[str, Tuple[Tuple[str, Any], ...]]] = field(default_factory=set)

    confidence_progression: List[ConfidenceStep] = field(default_factory=list)
    current_confidence: float = 0.0

    investigated_layers: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    attack_timeline: List[Dict[str, Any]] = field(default_factory=list)

    # 직전 tool call 결과 중 아직 LLM이 해석(증거화)하지 않은 원본 결과.
    # 매 reason() 호출 뒤 loop.py에서 비운다.
    pending_observations: List[Dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 중복 조사 방지
    # ------------------------------------------------------------------
    @staticmethod
    def _signature(tool_name: str, args: Dict[str, Any]) -> Tuple[str, Tuple[Tuple[str, Any], ...]]:
        return (tool_name, tuple(sorted(args.items())))

    def already_called(self, tool_name: str, args: Dict[str, Any]) -> bool:
        return self._signature(tool_name, args) in self.called_signatures

    def mark_called(self, tool_name: str, args: Dict[str, Any]) -> None:
        self.called_signatures.add(self._signature(tool_name, args))

    # ------------------------------------------------------------------
    # 증거 / 신뢰도 관리
    # ------------------------------------------------------------------
    def add_evidence(self, ev: Evidence, contradicting: bool = False) -> None:
        if contradicting:
            self.contradicting_evidence.append(ev)
        else:
            self.evidence.append(ev)
        self.investigated_layers.add(ev.layer)

    def record_confidence(self, stage: str, reason: str) -> None:
        self.confidence_progression.append(
            ConfidenceStep(stage=stage, confidence=round(self.current_confidence, 3), reason=reason)
        )

    def update_confidence(self, delta: float, stage: str, reason: str) -> None:
        self.current_confidence = max(0.0, min(1.0, self.current_confidence + delta))
        self.record_confidence(stage, reason)
