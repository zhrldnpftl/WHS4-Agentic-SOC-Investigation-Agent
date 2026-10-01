"""조사 루프(ReAct) — seed 하나를 끝까지 조사해 판정과 보고서 JSON을 만든다.

역할
  seed → (network 사전 조회) → [LLM 판단 → 도구 실행 → 결과 관찰]을 반복 → 종료 → 결과 JSON.
  매 사이클 LLM 호출 1회로 facts/가설/증거를 갱신하고 다음 행동(도구 호출 | 종료)을 정한다.
  루프는 LLM이 정한 것을 그대로 따르지 않고 아래를 코드로 통제한다.
    - 같은 도구+인자 재호출 차단, 도구 실패해도 조사 계속(오류를 다음 턴 관측으로 전달)
    - 증거의 원본 참조(raw_ref) 검증과 신뢰도 누적 (_apply_decision)
    - 종료 관문: 신뢰도·도구 수·network 확인·판정-원칙 일치를 확인해 조기 종료를 거부
      (_termination_rejections, _verdict_conflicts). 같은 사유로 연속 2회 거부되면 강제 종료 턴.
    - max_calls 도달 시 판정만 요청하는 마무리 턴, 그래도 판정이 없으면 수치 기반 폴백 판정

누가 부르나
  [16] agent/pipeline.py run_investigation_pipeline()  → InvestigationAgent(...).run(seed)
  tests/test_consistency.py(재현성 측정), 여러 오프라인 테스트

무엇을 부르나
  [18] agent/models.py         AgentState                 조사 상태 컨테이너
  [19-1] 사전 조회              _run_network_precheck()     → [28] _execute_tool_call()
  [20] llm_client.reason()      gemini_client.py / claude_client.py (프롬프트는 agent/prompts/)
  [30] agent/tools/registry.py ToolRegistry.call()         → agent/tools/real/*.py 도구
  agent/provenance.py          validate_citations() 등     원본 참조 검증
  [41] agent/report.py         build_investigation_result() 최종 JSON

설계 이유(요약 — 자세한 경위는 docs/CHANGES_0918_TO_0925.md)
  - network 사전 조회: 프롬프트로 "network를 보라"고 해도 LLM이 web 1회만 보고 끝내는 일이
    EC2에서 반복돼, src_ip가 있으면 첫 턴 전에 코드가 직접 조회한다. LLM 호출 수는 늘지 않는다.
  - no_more_evidence에도 관문 적용(strict): 경고만 남기던 시절 도구 1개로 끝나는 조사가 계속 나왔다.
  - 판정-원칙 일치 검사: 도구가 계산한 기준(원칙 7·9, 로그 미확보 등)과 다른 판정은 거부하고,
    기준과 같은 판정은 신뢰도 숫자 미달로는 거부하지 않는다(숫자를 채우려는 조사가 판정을 흔들었다).
"""

from __future__ import annotations

import re
import time
from datetime import timedelta, timezone
from typing import Any, Callable, Dict, Optional

from .llm_errors import LLMUnavailableError
from .models import AgentState, Evidence, Hypothesis, TerminationReason, ToolCallRecord, VerdictType
from .report import build_investigation_result
from .provenance import observed_references, observed_reference_groups, observed_locations, references, validate_citations
from .tools import ToolRegistry, ToolValidationError
from .tools.time_utils import parse_iso

NETWORK_PRECHECK_PAD = timedelta(minutes=30)
# IP 사건에서 audit의 웹 서버 계정 명령을 이 사건의 침해 신호로 보려면, seed src_ip의 웹 요청 뒤 이 시간 안에
# 실행돼야 한다(웹셸은 요청 직후 명령이 실행된다). 멀리 떨어진 명령은 같은 호스트의 별도 사건일 수 있다.
WEB_EXEC_LINK = timedelta(seconds=120)
NETWORK_PRECHECK_LIMIT = 20
# no_more_evidence 관문에서 "아직 안 본 계층이 남았는가"를 따질 때 세는 로그 조회 도구
LOG_TOOLS = frozenset({"fetch_web_log", "fetch_auth_log", "fetch_audit_log", "fetch_network_log",
                       "fetch_event_logs", "get_process_tree"})
# 로그인 성공 뒤 후속 행위를 볼 수 있는 도구 (종료 관문 (e))
AUDIT_TOOLS = frozenset({"fetch_audit_log", "get_process_tree"})
# 1차 탐지 탐지 계층(detection.rules[].layer, system = audit) → 그 계층 원본을 확인하는 도구 (종료 관문 (g))
DETECTION_LAYER_TOOLS = {
    "web": ("fetch_web_log",), "auth": ("fetch_auth_log",),
    "audit": ("fetch_audit_log", "get_process_tree"), "network": ("fetch_network_log",),
}


def network_precheck_args(seed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """seed에 host/src_ip/시각이 있으면 사전 network 조회 인자를 만든다 (없으면 None).

    구간은 seed window(없으면 trigger_time/timestamp 한 점)의 앞뒤로 30분씩 넓힌다.
    """
    window = seed.get("window") or []
    anchor = seed.get("trigger_time") or seed.get("timestamp")
    start = window[0] if len(window) == 2 else anchor
    end = window[1] if len(window) == 2 else anchor
    if not seed.get("src_ip") or not seed.get("host") or not start or not end:
        return None
    try:
        start_dt = parse_iso(start).astimezone(timezone.utc) - NETWORK_PRECHECK_PAD
        end_dt = parse_iso(end).astimezone(timezone.utc) + NETWORK_PRECHECK_PAD
    except (TypeError, ValueError):
        return None
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    # ip = 방향 무관(출발지·목적지 양쪽). src_ip로만 조회하면 서버→공격자 outbound(역방향 셸,
    # 유출)가 0건으로 나오고, LLM은 network를 "이미 확인함"으로 여겨 다시 보지 않았다
    # (0918 시나리오 03 비교에서 Metasploit alert 누락).
    # limit: 사전 조회는 규모 파악용이라 대표 레코드만 받는다. 전체 규모·경보·목적지는 도구 summary의
    # [조회 구간 전체 집계]가 페이지와 무관하게 준다. 150건을 통째로 넘기다 LLM 응답이 잘린 적이 있다.
    return {
        "host": seed["host"],
        "start_time": start_dt.strftime(fmt),
        "end_time": end_dt.strftime(fmt),
        "ip": seed["src_ip"],
        "limit": NETWORK_PRECHECK_LIMIT,
    }


def _parse_utc(value: Any) -> Optional[Any]:
    try:
        return parse_iso(value).astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        return None


def _verified_empty_call(state: AgentState, value: Any) -> Optional[int]:
    """0건 증거가 가리킨 도구 호출이 실제로 성공한 0건 조회면 그 sequence, 아니면 None.

    실패한 호출(로그 미확보·인자 오류)은 "활동 없음"의 근거가 아니고, 결과가 있었던 호출은 0건이 아니다.
    """
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value)
    if type(value) is not int:
        return None
    call = next((c for c in state.tool_calls if c.sequence == value), None)
    return value if call is not None and call.success and call.result_count == 0 else None

# [17] ← agent/pipeline.py [16]이 seed마다 하나씩 만들어 run(seed)을 부른다.
#      "충분하다"는 판단(종료 관문 통과)이 나올 때까지 LLM 판단 → 도구 실행을 반복한다.
class InvestigationAgent:
    def __init__(
        self,
        llm_client: Any,
        tool_registry: ToolRegistry,
        max_calls: int = 8,
        confidence_threshold: float = 0.85,
        network_precheck: bool = False,
        strict_termination: bool = False,
        progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.max_calls = max_calls
        self.confidence_threshold = confidence_threshold
        # 진행 상황 한 줄씩 받는 콜백(main.py는 print). None이면 아무것도 출력하지 않는다 — 결과 JSON과 무관.
        # 사건 하나에 LLM·도구 호출이 여러 번이라 수 분 걸리는데, 결과 파일 경로만 찍던 때는 그동안
        # 커서만 깜빡여 멈춘 건지 알 수 없었다(2026-09-30 EC2).
        self.progress = progress
        self._llm_calls = 0  # 진행 표시용 LLM 호출 번호 (run()마다 0으로 되돌림)
        # 둘 다 main.py(pipeline) 경로에서 켠다. 기본값 False는 각본대로 흘러가는 기존
        # 단위 테스트·C/D 데모(도구 1회 후 no_more_evidence)를 그대로 두기 위함.
        self.network_precheck = network_precheck
        self.strict_termination = strict_termination

    # 응답 해석 실패 시 재시도 횟수. 해석 실패 예외(GeminiDecisionError, ClaudeDecisionError)는
    # 클라이언트 모듈을 import하지 않으려고 클래스 이름("...DecisionError")으로 판별한다.
    LLM_RESPONSE_RETRIES = 1

    def _emit(self, message: str) -> None:
        if self.progress is not None:
            self.progress(message)

    @staticmethod
    def _short_args(args: Dict[str, Any]) -> str:
        """진행 표시용 도구 인자 요약 — host·사건 전체(event)는 빼고 100자로 자른다."""
        text = ", ".join(f"{k}={v}" for k, v in args.items() if k not in ("host", "event"))
        return text if len(text) <= 100 else text[:97] + "..."

    def _report_tool_call(self, state: AgentState, calls_before: int, started: float, label: str) -> None:
        """방금 실행한 도구 호출 한 건을 진행 표시로 알린다."""
        if self.progress is None:
            return
        if len(state.tool_calls) <= calls_before:
            # 중복 호출 스킵·tool_call 누락 — 사유는 방금 남긴 notes 마지막 줄에 있다
            self._emit(f"[조사]   {label} 실행 안 함: {state.notes[-1][:100] if state.notes else '-'}")
            return
        call = state.tool_calls[-1]
        outcome = f"{call.result_count}건" if call.success else f"실패: {str(call.error)[:80]}"
        self._emit(f"[조사]   {label} #{call.sequence} {call.tool_name}({self._short_args(call.input)})"
                   f" → {outcome} ({time.monotonic() - started:.1f}s)")

    def _safe_reason(self, state: AgentState, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """[20] → llm_client.reason() 호출. 응답 해석 실패는 1회 재시도하고, 그래도 실패하면 None.

        EC2에서 LLM 응답이 출력 한도에서 잘려 JSON 파싱이 실패했을 때, 그 예외 하나로 main.py 전체
        (다른 seed 조사 포함)가 멈췄다. 이제는 그 사건만 폴백 판정으로 마무리한다.
        API 키·권한 같은 설정 오류는 그대로 올려 보내 원인이 가려지지 않게 한다.
        """
        for attempt in range(self.LLM_RESPONSE_RETRIES + 1):
            self._llm_calls += 1
            number = self._llm_calls
            kind = "마무리 판정" if kwargs.get("force_terminate") else "판단"
            self._emit(f"[조사]   LLM {kind} #{number} 요청 중... "
                       f"(도구 {len(state.tool_calls)}/{self.max_calls}회, 신뢰도 {state.current_confidence:.2f})")
            started = time.monotonic()
            try:
                decision = self.llm_client.reason(state, self.tool_registry, **kwargs)
                self._emit(f"[조사]   LLM #{number} 응답 ({time.monotonic() - started:.1f}s) → "
                           + self._describe_decision(decision))
                return decision
            except Exception as exc:
                if not type(exc).__name__.endswith("DecisionError"):
                    raise
                self._emit(f"[조사]   LLM #{number} 응답 해석 실패 ({time.monotonic() - started:.1f}s)")
                # 첫 줄에 오류와 응답 앞부분이 있다(agent/llm_json.py) — 원인을 나중에 확인할 수 있게 남긴다
                first_line = str(exc).splitlines()[0][:400]
                state.notes.append(f"LLM 응답 해석 실패({attempt + 1}회차): {first_line}")
        state.notes.append("LLM 응답을 연속으로 해석하지 못해, 지금까지의 증거로 자동 폴백 판정했습니다.")
        return None

    @staticmethod
    def _describe_decision(decision: Any) -> str:
        """진행 표시용 LLM 결정 요약: 다음 행동과 새 증거 수."""
        if not isinstance(decision, dict):
            return "결정 없음"
        evidence = len(decision.get("new_evidence") or [])
        suffix = f" (새 증거 {evidence}건)" if evidence else ""
        if decision.get("next_action") == "terminate" or decision.get("final_verdict"):
            verdict = decision.get("final_verdict") or {}
            return (f"종료 요청 {verdict.get('verdict', '?')}/{verdict.get('severity', '?')} "
                    f"({decision.get('termination_reason') or '-'})" + suffix)
        tool = (decision.get("tool_call") or {}).get("tool_name") or "?"
        return f"도구 요청 {tool}" + suffix

    def _run_network_precheck(self, state: AgentState) -> None:
        """[19-1] seed에 src_ip가 있으면 첫 LLM 턴 전에 fetch_network_log를 코드가 직접 한 번 실행한다.

        결과는 [28] _execute_tool_call()을 거쳐 첫 턴 관측(pending_observations)으로 들어간다.
        LLM이 고른 도구가 아니므로 system_call_sequences에 기록해 "도구 종류 수" 관문에서 뺀다.
        """
        args = network_precheck_args(state.seed)
        if args is None or "fetch_network_log" not in {s.name for s in self.tool_registry.list_tools()}:
            return
        calls_before, started = len(state.tool_calls), time.monotonic()
        self._execute_tool_call(state, {"tool_name": "fetch_network_log", "args": args})
        self._report_tool_call(state, calls_before, started, "사전 조회")
        if state.tool_calls:
            state.system_call_sequences.append(state.tool_calls[-1].sequence)
        state.notes.append(
            f"시스템 사전 조회: seed의 src_ip({args['ip']})가 출발지 또는 목적지인 network 이벤트를 "
            f"{args['start_time']}~{args['end_time']} 구간에서 fetch_network_log로 자동 조회했습니다."
        )

    def run(self, seed: Dict[str, Any]) -> Dict[str, Any]:
        # [18] → agent/models.py AgentState: 이 사건의 조사 상태(사실·가설·증거·도구 호출·신뢰도)를 담는 그릇
        state = AgentState(incident_id=seed["incident_id"], seed=seed)
        state.raw_refs = references(seed, seed=True)   # seed가 인용한 원본 참조도 "관측됨"으로 등록
        state.current_confidence = float(seed.get("confidence_initial", 0.5))
        state.record_confidence("initial", seed.get("trigger_description", "Triage 판정"))
        self._llm_calls = 0
        run_started = time.monotonic()
        rules = (seed.get("detection") or {}).get("rules") or []
        self._emit(f"[조사] {seed['incident_id']} 시작 — src_ip={seed.get('src_ip') or '-'}, "
                   f"window={seed.get('window') or seed.get('trigger_time') or '-'}, 1차 탐지 룰 {len(rules)}건")
        if seed.get("src_ip"):
            # IP 사건의 window·trigger_time은 1차 탐지가 본 그 IP의 요청 시각이다 (웹 서버 명령 연결 근거)
            state.src_ip_request_times = list(dict.fromkeys(
                t for t in [seed.get("trigger_time"), *(seed.get("window") or [])] if isinstance(t, str)))
        # [19-1] → _run_network_precheck(): src_ip가 있으면 첫 LLM 턴 전에 network를 코드가 먼저 조회
        if self.network_precheck:
            self._run_network_precheck(state)

        incomplete_reason = None
        try:
            # [20]~[40] → _investigate(): LLM 판단 → 도구 실행 반복, 종료 관문, 마무리 판정
            termination_reason, final_verdict = self._investigate(state)
        except LLMUnavailableError as exc:
            # 재시도 뒤에도 LLM API가 일시 오류(과부하·한도·연결)면 이 사건만 조사 미완료로 끝낸다.
            # 2026-09-28 EC2: Gemini 503 한 번으로 main.py 전체가 멈추고 앞서 끝난 사건 결과까지 저장되지 않았다.
            # API 키·권한 오류는 LLMUnavailableError가 아니라 그대로 올라가 전체 실행을 멈춘다.
            incomplete_reason = str(exc)
            termination_reason = TerminationReason.LLM_UNAVAILABLE.value
            final_verdict = self._incomplete_verdict(state, incomplete_reason)
            state.notes.append(f"⚠ 조사 미완료 — LLM API 일시 오류로 조사를 끝내지 못했습니다: {incomplete_reason}")

        if state.unlinked_web_exec:
            count = sum(c.get("web_server_suspicious", 0) for c in state.unlinked_web_exec)
            examples = [e for c in state.unlinked_web_exec for e in c.get("examples", [])][:2]
            state.notes.append(
                f"같은 시간대 audit에 웹 서버 계정의 셸·의심 명령 {count}건이 있었지만 seed src_ip"
                f"({state.seed.get('src_ip')})의 웹 요청 직후({int(WEB_EXEC_LINK.total_seconds())}초 이내)에 실행된 것이 "
                f"아니라 이 사건의 판정 기준으로 쓰지 않았습니다 — 같은 호스트의 별도 사건일 수 있음"
                + (f" (예: {' / '.join(examples)})" if examples else "")
            )

        # [41] → agent/report.py build_investigation_result(): state에 쌓인 조사 내용으로 최종 JSON 생성
        result = build_investigation_result(state, termination_reason, final_verdict,
                                            incomplete_reason=incomplete_reason)
        result["statistics"]["tool_calls_max"] = self.max_calls
        self._emit(f"[조사] {seed['incident_id']} 끝 — {(final_verdict or {}).get('verdict')}/"
                   f"{(final_verdict or {}).get('severity')} 신뢰도 {state.current_confidence:.2f}, "
                   f"종료 사유 {termination_reason}, 도구 {len(state.tool_calls)}회·LLM {self._llm_calls}회, "
                   f"{time.monotonic() - run_started:.1f}s")
        # [42] → agent/pipeline.py [16]으로 조사 결과를 돌려준다
        return result

    def _incomplete_verdict(self, state: AgentState, reason: str) -> Dict[str, Any]:
        """조사 미완료 사건의 판정. 폴백 판정(수치로 계산한 판정)과 달리 판정을 내리지 않는다 — INCONCLUSIVE.
        ATT&CK 매핑은 INCONCLUSIVE를 deferred로 두므로, 미완료 조사에 기법 번호가 붙지 않는다."""
        return {
            "verdict": VerdictType.INCONCLUSIVE.value,
            "confidence": round(state.current_confidence, 3),
            "severity": "UNKNOWN",
            "attack_type": "unknown",
            "affected_systems": [],
            "summary": "LLM API 일시 오류로 조사를 끝내지 못했습니다. 다시 조사해야 합니다.",
            "reasoning": f"[조사 미완료 — LLM API 일시 오류] {reason}",
        }

    def _investigate(self, state: AgentState) -> tuple:
        """[20]~[40] 조사 루프 본문. (termination_reason, final_verdict)를 돌려준다."""
        termination_reason = None
        final_verdict = None
        max_cycles = self.max_calls + 3  # LLM이 종료 판단을 안 내려도 무한루프에 빠지지 않도록 하는 안전장치

        # 직전 턴에 종료 관문이 거부한 사유. 다음 reason() 호출에 실어 보내 LLM이 "왜 거부당했는지"를
        # 알게 한다. 한 번 전달하면 초기화한다.
        gate_rejection_reason = None
        # 같은 사유로 연속 거부되면 사이클 낭비 없이 강제 종료 턴으로 넘어가기 위한 카운터.
        consecutive_rejections = 0
        MAX_CONSECUTIVE_REJECTIONS = 2
        # "같은 사유"로 연속 거부될 때만 센다(숫자는 빼고 비교 — 신뢰도 값만 바뀐 건 같은 사유).
        # 사유가 달라도 세던 때는 0918 시나리오 01이 (d) → (b) 두 번 만에 강제 종료돼 audit을 못 봤다.
        # 사유가 계속 바뀌며 끝나지 않는 경우는 max_cycles가 막는다.
        last_rejection_kind = None
        # 거부된 종료 요청 중 판정 자체는 원칙 기준과 맞았던 마지막 판정. 강제 종료 턴에서 LLM이 판정을
        # 새로 내며 원칙과 어긋나게 뒤집으면 이 판정을 쓴다 (_settle_forced_verdict).
        last_consistent_verdict = None

        # [20] 조사 루프 시작 — 한 바퀴 = LLM 판단 1회 (+ 필요하면 도구 1회)
        for _ in range(max_cycles):
            # [20] → _safe_reason() → llm_client.reason() (gemini_client.py / claude_client.py)
            #        → [21] agent/prompts/ 로 프롬프트 조립 → [22] LLM API 호출
            # [23] ← LLM 결정(JSON dict): facts/가설/새 증거 + next_action(call_tool | terminate)
            #        신뢰도 임계값과 직전 거부 사유를 매 턴 함께 보내 LLM이 스스로 확인하게 한다.
            decision = self._safe_reason(
                state,
                confidence_threshold=self.confidence_threshold,
                gate_rejection_reason=gate_rejection_reason,
            )
            gate_rejection_reason = None  # 이번 턴 프롬프트에 이미 실어 보냈으니 초기화
            if decision is None:
                # LLM 응답을 두 번 연속 해석하지 못함 — 이 사건만 지금까지의 증거로 마무리한다
                termination_reason = TerminationReason.NO_MORE_EVIDENCE.value
                final_verdict = self._derive_fallback_verdict(state, cause="LLM 응답을 해석하지 못해 조사를 중단함")
                break

            # [24] → _apply_decision(): LLM 결정을 state에 반영 (증거의 원본 참조 검증 + 신뢰도 누적)
            self._apply_decision(state, decision)
            state.pending_observations = []

            # [25] 종료 조건 1: LLM이 "이제 끝내자(terminate)"고 했는가?
            if decision.get("next_action") == "terminate":
                termination_reason = (
                    decision.get("termination_reason") or TerminationReason.NO_MORE_EVIDENCE.value
                )

                # [25-1] → _termination_rejections(): 종료 관문. 거부 사유가 있으면 종료하지 않고 계속 조사.
                #        (strict면 [25-2] _verdict_conflicts()로 판정-원칙 일치도 확인)
                reasons = self._termination_rejections(state, termination_reason, decision.get("final_verdict"))
                if reasons:
                    reason_text = ", ".join(reasons)
                    state.notes.append(f"종료 관문 발동 — 종료 거부: {reason_text}")
                    self._emit(f"[조사]   종료 관문 거부 → 조사 계속: "
                               + (reason_text if len(reason_text) <= 120 else reason_text[:117] + "..."))
                    proposed = decision.get("final_verdict")
                    if self.strict_termination and proposed and not self._verdict_conflicts(state, proposed):
                        last_consistent_verdict = proposed  # 판정은 원칙과 맞았고 다른 사유로 거부됨

                    rejection_kind = re.sub(r"[\d.]+", "", reason_text)
                    consecutive_rejections = consecutive_rejections + 1 if rejection_kind == last_rejection_kind else 1
                    last_rejection_kind = rejection_kind
                    if consecutive_rejections >= MAX_CONSECUTIVE_REJECTIONS:
                        # [25-3] 강제 종료 턴: 도구 없이 판정만 요청 → _settle_forced_verdict()
                        state.notes.append(
                            f"연속 {consecutive_rejections}회 종료 거부 후에도 진전이 없어 "
                            "강제 종료 턴으로 전환합니다."
                        )
                        termination_reason = TerminationReason.NO_MORE_EVIDENCE.value
                        final_decision = self._safe_reason(
                            state, confidence_threshold=self.confidence_threshold, force_terminate=True
                        ) or {}
                        self._apply_decision(state, final_decision)
                        final_verdict = self._settle_forced_verdict(
                            state, final_decision.get("final_verdict") or self._derive_fallback_verdict(state),
                            last_consistent_verdict)
                        break

                    gate_rejection_reason = reason_text  # 다음 턴 프롬프트에 실어 보냄
                    continue  # 종료 거부 — 다음 사이클로 넘어가 계속 조사

                # 관문 통과 — 정상 종료. network_precheck=False일 때는 src_ip가 있는데 network를 한 번도
                # 안 본 채 no_more_evidence로 끝날 수 있어 기록으로 남긴다.
                if (
                    termination_reason == TerminationReason.NO_MORE_EVIDENCE.value
                    and state.seed.get("src_ip")
                    and "fetch_network_log" not in {t.tool_name for t in state.tool_calls}
                    and not any("network" in t.queried_layers for t in state.tool_calls)
                ):
                    state.notes.append(
                        "⚠ src_ip가 있는 사건이 network 계층 확인 없이 no_more_evidence로 종료됨 — 검토 권장"
                    )

                consecutive_rejections = 0  # 정상 종료 승인 — 카운터 리셋
                final_verdict = decision.get("final_verdict") or self._derive_fallback_verdict(state)
                break

            # [26] 종료 조건 2: 도구 호출 횟수 상한(max_calls, 기본 8)에 도달했는가?
            if len(state.tool_calls) >= self.max_calls:
                termination_reason = TerminationReason.MAX_CALL_REACHED.value

                # 도구 호출 없이 판정만 요청하는 마무리 턴을 1회 추가한다. 이 시점 decision은 도구 호출
                # 요청이라 final_verdict가 없기 때문이다. 그래도 없으면 수치 기반 폴백 판정.
                final_decision = self._safe_reason(
                    state, confidence_threshold=self.confidence_threshold, force_terminate=True
                ) or {}
                self._apply_decision(state, final_decision)
                final_verdict = self._settle_forced_verdict(
                    state, final_decision.get("final_verdict") or self._derive_fallback_verdict(state),
                    last_consistent_verdict)
                break

            # [27] 종료가 아니면 = LLM이 "이 도구를 부르자"고 한 것 → [28] _execute_tool_call()로 실제 실행
            # [39] ← 도구 결과는 state.pending_observations에 담겨 다음 턴 프롬프트로 LLM에게 간다
            calls_before, started = len(state.tool_calls), time.monotonic()
            self._execute_tool_call(state, decision.get("tool_call") or {})
            self._report_tool_call(state, calls_before, started, "도구")
            if len(state.tool_calls) > calls_before:
                # 새 도구를 실행했으면 진전이 있는 것 — 연속 거부 횟수를 다시 센다. EC2 xmlrpc 사건에서
                # 거부 → web 조회 → 거부가 "연속 2회"로 세어져 강제 종료된 적이 있다.
                consecutive_rejections = 0
                last_rejection_kind = None
            # [40] 신뢰도 확인 — 임계값을 넘어도 여기서 끝내지 않는다. 종료는 LLM이 terminate를 요청하고
            #      [25-1] 관문을 통과할 때만 한다. 메모만 남기고 다시 [20]으로 돌아간다.
            if state.current_confidence >= self.confidence_threshold:
                state.notes.append("신뢰도 임계값 도달 — 다음 사이클에서 종료 여부 재확인 필요")
        else:
            termination_reason = TerminationReason.MAX_CALL_REACHED.value
            # 안전장치(max_cycles 전부 소진)로 빠진 경우도 마무리 턴을 한 번 시도한다.
            final_decision = self._safe_reason(
                state, confidence_threshold=self.confidence_threshold, force_terminate=True
            ) or {}
            self._apply_decision(state, final_decision)
            final_verdict = self._settle_forced_verdict(
                state, final_decision.get("final_verdict") or self._derive_fallback_verdict(state),
                last_consistent_verdict)

        # 거부·강제 종료를 거치고도 원칙 기준과 다른 판정이 남으면 판정은 바꾸지 않고 드러내 기록한다
        if self.strict_termination:
            for conflict in self._verdict_conflicts(state, final_verdict):
                state.notes.append("⚠ 판정-원칙 불일치: " + conflict + " (최종 판정은 LLM 결과 그대로 둠)")
        return termination_reason, final_verdict

    def _termination_rejections(self, state: AgentState, termination_reason: str,
                                final_verdict: Optional[Dict[str, Any]] = None) -> list:
        """[25-1] 종료 관문 — 종료 요청을 거부할 사유 목록 (비어 있으면 승인). run() [25]에서 호출.

        confidence_sufficient: (a) 실제 신뢰도 < threshold (단, 판정이 도구 계산 기준과 같으면 면제),
          (b) 서로 다른 도구 1종류 이하, (c) seed에 src_ip가 있는데 network 조회를 시도하지 않음.
        strict_termination=True일 때 두 종료 사유 모두에 추가:
          [25-2] _verdict_conflicts(): 판정이 도구가 계산한 원칙 기준과 어긋남
          (d) no_more_evidence인데 도구를 1종류 이하만 시도했고, 아직 시도하지 않은 로그 조회
              도구가 남아 있음. 경고만 남기던 방식으로는 EC2 main.py에서도 도구 1개로 끝나는
              사건이 계속 나왔다. 등록된 도구를 다 써봤다면 "정말 더 볼 게 없음"이므로 승인한다.
          (e) 도구 결과에서 seed src_ip의 로그인 성공이 관측됐는데 audit(fetch_audit_log/
              get_process_tree/fetch_event_logs)을 한 번도 시도하지 않음. 침해 판정 자체는 원칙 7이
              Q1+Q2로 확정하지만, 로그인 후 무엇을 했는지(피해 범위)는 audit으로만 알 수 있다.
              0918 시나리오 비교에서 network alert로 신뢰도가 먼저 차 audit 없이 끝나는 사례가 나왔다.
          (f) audit 명령 인자에 등장한 외부 IP(state.command_external_ips)를 network로 조회하지 않음
              (fetch_network_log의 ip/src_ip/dst_ip 또는 fetch_event_logs의 filters.network).
              로그인 IP와 유출 목적지가 다른 시나리오에서 새 목적지를 "추가 조회 권장"으로만 남겼다(3/3).
          (g) 1차 탐지가 넘긴 참조(seed detection.rules[].evidence_refs)를 도구 결과에서 관측하지 않은 채
              증거로 인용했고, 그 참조의 계층을 도구로 한 번도 조회하지 않음(_unverified_detection_refs).
              1차 탐지 Incident로 바꾼 첫 실제 실행(2026-09-27)에서 LLM이 detection의 명령 인자를 그대로
              증거로 옮겨 audit을 한 번도 보지 않고 THREAT_CONFIRMED로 끝냈다.
          (h) 1차 탐지 룰(seed detection.rules) 중 탐지 근거 참조를 도구 결과에서 하나도 관측하지 못했고,
              unknowns에 그 룰 이름이나 참조를 남기지도 않은 룰이 있음(_unverified_detection_rules).
              (g) 수정 뒤 재실행에서 audit은 봤지만 sudo 자식인 useradd(계정 생성) 룰 2개를 확인하지 않고 끝냈다.
        """
        attempted = {t.tool_name for t in state.tool_calls}
        queried_layers = {layer for t in state.tool_calls for layer in t.queried_layers}
        # 도구 종류 수((b), (d))는 LLM이 직접 고른 호출만 센다. 시스템 사전 조회까지 세면 LLM이
        # 도구 1개만 고르고도 관문을 통과해, 0918 웹셸 시나리오에서 audit(명령 실행 확인) 없이
        # 끝났다. network 확인 여부((c))는 사전 조회도 인정한다.
        chosen = [t for t in state.tool_calls if t.sequence not in state.system_call_sequences]
        chosen_tools = {t.tool_name for t in chosen}
        chosen_layers = {layer for t in chosen for layer in t.queried_layers}
        reasons = []

        if self.strict_termination:
            reasons.extend(self._verdict_conflicts(state, final_verdict))

        if self.strict_termination and state.login_successes:
            registered = {spec.name for spec in self.tool_registry.list_tools()}
            audit_tools = registered & AUDIT_TOOLS
            if audit_tools and not (attempted & audit_tools) and "audit" not in queried_layers:
                # audit의 user는 명령 실행 계정(sudo 뒤엔 root)이라 로그인 계정 이름으로는 세션
                # 명령이 안 잡힌다(0918 시나리오 비교에서 user=ubuntu 조회 0건). 세션 pid로 안내한다.
                hints = [f"ppid={login['pid']}({login['user']}, {login['timestamp']})"
                         for login in state.login_successes[:3] if login.get("pid") is not None]
                reasons.append(
                    f"seed의 src_ip({state.seed.get('src_ip')}) 로그인 성공이 확인됐는데 로그인 후 행위를 "
                    "audit으로 확인하지 않음. fetch_audit_log를 로그인 세션의 sshd pid로 조회하십시오: "
                    + (", ".join(hints) or "ppid=<auth 레코드의 sshd pid>")
                )

        # (f) audit 명령에 등장한 외부 IP(다운로드·전송·역방향 셸 대상)를 network로 조회하지 않음.
        # 로그인 IP와 유출 목적지가 다른 시나리오에서 LLM이 notes에 "추가 조회 권장"만 남기고 끝냈다(3/3).
        unchecked = self._unchecked_command_ips(state)
        if self.strict_termination and unchecked and "fetch_network_log" in {
                spec.name for spec in self.tool_registry.list_tools()}:
            reasons.append(
                f"audit 명령에 등장한 외부 IP({', '.join(unchecked)})의 network 기록을 확인하지 않음. 권장으로 남기지 말고 "
                + " / ".join(f"fetch_network_log(ip={ip})" for ip in unchecked)
                + "로 조회해 경보·통신을 확인하십시오"
            )

        # (g) 1차 탐지 정보는 조사 단서다. 그 참조를 인용한 증거는 해당 계층 원본을 도구로 본 뒤에만 인정한다.
        unverified = self._unverified_detection_refs(state)
        if self.strict_termination and unverified:
            reasons.append(
                "1차 탐지가 넘긴 참조를 도구로 조회하지 않고 증거로 인용함("
                + ", ".join(f"{layer}: {', '.join(refs[:3])}" for layer, refs in unverified.items())
                + "). detection 정보는 단서일 뿐이므로 "
                + " / ".join(DETECTION_LAYER_TOOLS[layer][0] for layer in unverified)
                + "로 그 원본을 조회해 raw_observations에서 확인한 뒤 판단하십시오"
            )

        # (h) 1차 탐지 룰마다 원본을 확인했거나, 확인하지 못한 사실을 unknowns에 남겼어야 한다
        unchecked_rules = self._unverified_detection_rules(state)
        if self.strict_termination and unchecked_rules:
            reasons.append(
                "1차 탐지 룰 중 탐지 근거 원본을 도구로 확인하지 않은 것이 있음: "
                + "; ".join(unchecked_rules[:5])
                + (f" 외 {len(unchecked_rules) - 5}개" if len(unchecked_rules) > 5 else "")
                + ". 그 원본을 도구로 조회해 확인하거나(자식 프로세스는 fetch_audit_log ppid=<부모 pid>), "
                "조회해도 찾을 수 없으면 unknowns에 룰 이름과 이유를 남기십시오"
            )

        if termination_reason == TerminationReason.CONFIDENCE_SUFFICIENT.value:
            successful = {t.tool_name for t in chosen if t.success}
            distinct = max(len(successful), len(chosen_layers))
            # 판정이 도구가 계산한 원칙 기준과 같으면 신뢰도 숫자 미달로는 거부하지 않는다. EC2 SSH 탐침
            # 사건에서 FALSE_POSITIVE가 0.80으로 5회 거부되자 도구를 더 부르다 강제 종료 턴에서
            # THREAT_CONFIRMED로 뒤집혔다. 사실이 다 확인된 사건에 0.05를 채우는 조사는 판정을 흔들기만 한다.
            determined = self.strict_termination and self._rule_determined_verdict(state) == (
                (final_verdict or {}).get("verdict"))
            if state.current_confidence < self.confidence_threshold and not determined:
                reasons.append(
                    f"실제 신뢰도({state.current_confidence:.2f})가 임계값({self.confidence_threshold}) 미달"
                )
            if distinct <= 1:
                reasons.append(f"서로 다른 도구 {distinct}종류만 사용됨(1개 이하). "
                               + self._untried_tool_hint(attempted))
            # 실패한 호출도 "조회 시도"로 인정 — network 데이터 소스 장애 시 종료 불가를 막는다
            if state.seed.get("src_ip") and "fetch_network_log" not in attempted and "network" not in queried_layers:
                reasons.append(
                    f"seed에 src_ip({state.seed.get('src_ip')})가 있는데 "
                    "fetch_network_log로 네트워크 활동을 확인하지 않음"
                )
        elif termination_reason == TerminationReason.NO_MORE_EVIDENCE.value and self.strict_termination:
            registered = {spec.name for spec in self.tool_registry.list_tools()}
            remaining = sorted((registered & LOG_TOOLS) - attempted)
            if max(len(chosen_tools), len(chosen_layers)) <= 1 and remaining:
                reasons.append(
                    f"도구를 {len(chosen_tools)}종류만 직접 확인하고 no_more_evidence로 종료하려 함. "
                    + self._untried_tool_hint(attempted)
                )
        return reasons

    def _unverified_detection_refs(self, state: AgentState) -> Dict[str, list]:
        """종료 관문 (g): 증거가 인용한 1차 탐지 참조 중, 도구 결과에서 관측되지 않았고 그 계층을
        도구로 한 번도 조회하지 않은 것을 계층별로 돌려준다. 계층을 알 수 없는 참조(직접 작성한 사건의
        evidence_refs)나 등록되지 않은 도구의 계층은 보지 않는다. 조회는 시도만 해도 인정한다(조건이
        맞지 않아 원본이 안 보여도 LLM이 결과를 보고 판단한 것으로 본다)."""
        ref_layers: Dict[str, str] = {}
        for rule in (state.seed.get("detection") or {}).get("rules") or []:
            layer = "audit" if rule.get("layer") == "system" else rule.get("layer")
            for ref in rule.get("evidence_refs") or []:
                ref_layers.setdefault(ref, layer)
        if not ref_layers:
            return {}
        registered = {spec.name for spec in self.tool_registry.list_tools()}
        attempted = {t.tool_name for t in state.tool_calls}
        queried_layers = {layer for t in state.tool_calls for layer in t.queried_layers}
        observed = {ref for t in state.tool_calls for ref in t.raw_refs}
        unverified: Dict[str, list] = {}
        for evidence in state.evidence + state.contradicting_evidence:
            for ref in evidence.raw_refs:
                layer = ref_layers.get(ref)
                tools = DETECTION_LAYER_TOOLS.get(layer, ())
                if (ref in observed or not (registered & set(tools))
                        or attempted & set(tools) or layer in queried_layers):
                    continue
                if ref not in unverified.setdefault(layer, []):
                    unverified[layer].append(ref)
        return unverified

    @staticmethod
    def _unverified_detection_rules(state: AgentState) -> list:
        """종료 관문 (h): 탐지 근거 참조를 도구 결과에서 하나도 관측하지 못했고 unknowns에도 언급되지 않은
        1차 탐지 룰의 안내 문구 목록. 같은 룰 이름·참조 조합이 여러 번 탐지됐으면 한 번만 적는다."""
        observed = {ref for t in state.tool_calls for ref in t.raw_refs}
        unknowns = " ".join(str(u) for u in state.unknowns)
        hints, seen = [], set()
        for rule in (state.seed.get("detection") or {}).get("rules") or []:
            refs = [ref for ref in rule.get("evidence_refs") or [] if isinstance(ref, str)]
            name = rule.get("rule_name") or rule.get("reason") or "?"
            key = (name, tuple(refs))
            if not refs or key in seen or observed & set(refs):
                continue
            seen.add(key)
            if name in unknowns or any(ref in unknowns for ref in refs):
                continue
            layer = "audit" if rule.get("layer") == "system" else rule.get("layer")
            detail = rule.get("detail") or {}
            where = ", ".join(f"{k}={detail[k]}" for k in ("pid", "ppid", "user", "src_ip") if detail.get(k) is not None)
            hints.append(f"{name}({layer}, {refs[0]}" + (f", {where}" if where else "") + ")")
        return hints

    # 거부 사유에 붙이는 "다음에 볼 도구" 안내. 예전 문구("도구 1종류만 사용됨")만으로는 LLM이
    # 무엇을 더 봐야 할지 몰라 같은 종료를 반복했다(EC2 xmlrpc 사건).
    UNTRIED_TOOL_PURPOSE = {
        "fetch_audit_log": "서버에서 실행된 명령·파일 변경(웹 서버 프로세스 www-data/apache2의 셸·다운로드 실행, "
                           "로그인 세션의 명령) — 공격이 서버 안까지 이어졌는지 확인",
        "fetch_auth_log": "같은 IP·계정의 로그인 시도와 성공 여부",
        "fetch_web_log": "같은 IP의 웹 요청(경로·상태코드)",
        "fetch_network_log": "같은 IP의 외부 통신과 Suricata 경보",
    }

    def _settle_forced_verdict(self, state: AgentState, verdict: Dict[str, Any],
                               last_consistent: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """[25-3] 강제 종료 턴 판정이 원칙과 어긋나면, 앞서 LLM이 낸 원칙에 맞는 판정을 쓴다.

        강제 종료 턴은 LLM이 판정을 처음부터 다시 쓰는 호출이라, 거부 전까지 유지하던 판정이
        뒤집힐 수 있다(EC2 SSH 탐침 사건: FALSE_POSITIVE로 5회 종료 요청 → 강제 종료 턴에서
        THREAT_CONFIRMED). 코드가 판정을 새로 만들지는 않고, LLM 자신의 앞선 판정 중에서만 고른다.
        """
        if not (self.strict_termination and last_consistent and self._verdict_conflicts(state, verdict)):
            return verdict
        state.notes.append(
            f"강제 종료 턴 판정({verdict.get('verdict')})이 원칙 기준과 어긋나, 직전에 LLM이 낸 원칙에 맞는 "
            f"판정({last_consistent.get('verdict')})을 최종 판정으로 사용함"
        )
        return last_consistent

    @staticmethod
    def _rule_determined_verdict(state: AgentState) -> Optional[str]:
        """도구가 계산한 기준만으로 판정이 정해지는 경우 그 판정 (아니면 None).

        로그 미확보 → INCONCLUSIVE, 원칙 9 충족·웹 서버 계정 의심 명령 → THREAT_CONFIRMED,
        그 외 원칙 7(로그인 성공 없음)만 있으면 무차별 대입 → THREAT_CONFIRMED, 단발성·탐침 → FALSE_POSITIVE.
        """
        if state.window_totals and not any(state.window_totals):
            return VerdictType.INCONCLUSIVE.value
        if any(c.get("rule") != "principle_7" for c in state.rule_floors):
            return VerdictType.THREAT_CONFIRMED.value
        p7 = [c for c in state.rule_floors if c.get("rule") == "principle_7"]
        if p7:
            bruteforce = any(c["bruteforce"] for c in p7)
            return (VerdictType.THREAT_CONFIRMED if bruteforce else VerdictType.FALSE_POSITIVE).value
        return None

    @staticmethod
    def _verdict_conflicts(state: AgentState, final_verdict: Optional[Dict[str, Any]]) -> list:
        """[25-2] 도구가 계산한 사실(rule_floors, window_totals)과 어긋나는 판정 사유 목록.

        [25-1] 종료 관문과 run() 끝의 "⚠ 판정-원칙 불일치" 기록, [25-3] 강제 종료 판정 확인에서 쓴다.

        - 조회한 모든 로그가 구간 전체 0건(로그 미확보)인데 INCONCLUSIVE가 아님
        - 원칙 9 기준 충족(seed src_ip)인데 FALSE_POSITIVE
        - 웹 서버 계정의 의심 명령 실행이 있는데 FALSE_POSITIVE이거나 severity가 HIGH 미만
        - 원칙 7(로그인 성공 없음) 무차별 대입 기준 충족인데 FALSE_POSITIVE/INCONCLUSIVE, 또는 단발성
          실패·접속 탐침뿐이고 다른 위협 기준도 없는데 THREAT_CONFIRMED/INCONCLUSIVE
        - 원칙 7 무차별 대입(로그인 성공 없음)이고 다른 위협 기준도 없는데 severity가 HIGH 이상
        """
        verdict = (final_verdict or {}).get("verdict")
        severity = str((final_verdict or {}).get("severity") or "").upper()
        conflicts = []
        if verdict and verdict != VerdictType.INCONCLUSIVE.value and state.window_totals and not any(state.window_totals):
            conflicts.append(
                "조회한 모든 로그에 이 시간대 기록 자체가 없음(로그 미확보 — 수집 누락·로그 교체 가능). "
                "기록이 없다는 것은 '활동 없음'의 증거가 아니므로 INCONCLUSIVE로 판정하고 unknowns에 "
                "'원본 로그 미확보'를 남기십시오"
            )
        for check in state.rule_floors:
            if check.get("rule") == "principle_9" and verdict == VerdictType.FALSE_POSITIVE.value:
                met = (f"인증·원격호출 엔드포인트 POST {check['auth_posts']}회(기준 10회 이상)" if check.get("auth_bruteforce")
                       else f"서로 다른 경로 {check['distinct_paths']}개·4xx {check['four_xx']}건(경로 스캔 기준)")
                conflicts.append(
                    f"원칙 9 기준 충족({check['src_ip']}: {met})인데 FALSE_POSITIVE로 판정함. User-Agent(Jetpack 등)와 "
                    "응답 코드(2xx/5xx)는 이 판정을 바꾸지 않으므로 원칙 9에 따라 THREAT_CONFIRMED로 판정하십시오"
                )
            if check.get("rule") == "audit_post_exploitation" and (
                    verdict == VerdictType.FALSE_POSITIVE.value or severity not in ("HIGH", "CRITICAL")):
                conflicts.append(
                    f"웹 서버 계정의 의심 명령 실행 {check['web_server_suspicious']}건이 audit에 있음"
                    f"({' / '.join(check['examples'])}). 원칙 9 [침해 신호]에 따라 THREAT_CONFIRMED, "
                    "severity HIGH 이상으로 판정하고 그 명령을 evidence로 기록하십시오"
                )
        p7 = [c for c in state.rule_floors if c.get("rule") == "principle_7"]
        other_threat = any(c.get("rule") != "principle_7" for c in state.rule_floors)
        if p7:
            worst = max(p7, key=lambda c: (c["bruteforce"], c["failures"]))
            if worst["bruteforce"] and verdict == VerdictType.FALSE_POSITIVE.value:
                conflicts.append(
                    f"원칙 7 기준 충족({worst['src_ip']}: 로그인 성공 0회, 실패 {worst['failures']}회·계정 "
                    f"{worst['accounts']}개)인데 FALSE_POSITIVE로 판정함. 원칙 7에 따라 THREAT_CONFIRMED"
                    "(SSH 무차별 대입 시도)로 판정하십시오"
                )
            if not worst["bruteforce"] and not other_threat and verdict in (
                    VerdictType.THREAT_CONFIRMED.value, VerdictType.INCONCLUSIVE.value):
                kind = (f"로그인 시도 없이 접속만 {worst.get('probes', 0)}건 — 스캐너 탐침" if worst["failures"] == 0
                        else "단발성 실패")
                conflicts.append(
                    f"원칙 7 기준 미충족({worst['src_ip']}: 로그인 성공 0회, 실패 {worst['failures']}회·계정 "
                    f"{worst['accounts']}개 — {kind})인데 {verdict}로 판정함. 판정에 필요한 사실(실패 횟수·계정 수·"
                    "성공 여부)은 모두 확인됐으므로, 다른 계층의 공격 정황이 없으면 원칙 7에 따라 FALSE_POSITIVE로 "
                    "판정하십시오"
                )
            if worst["bruteforce"] and verdict == VerdictType.INCONCLUSIVE.value:
                conflicts.append(
                    f"원칙 7 기준 충족({worst['src_ip']}: 실패 {worst['failures']}회·계정 {worst['accounts']}개)인데 "
                    "INCONCLUSIVE로 판정함. 원칙 7에 따라 THREAT_CONFIRMED(SSH 무차별 대입 시도)로 판정하십시오"
                )
            # 로그인 성공이 없는 무차별 대입은 계정 수·횟수가 많아도 침해가 일어나지 않았으므로 LOW~MEDIUM.
            # EC2 사건(31개 계정·76회 실패, 성공 0회)에서 LLM이 규모만 보고 HIGH를 매겼다. HIGH 이상은 다른
            # 계층에서 침해 기준(웹셸 신호 등)이 확인된 사건에만 쓴다.
            if (worst["bruteforce"] and not other_threat and verdict == VerdictType.THREAT_CONFIRMED.value
                    and severity in ("HIGH", "CRITICAL")):
                conflicts.append(
                    f"원칙 7: 로그인 성공이 없는 무차별 대입({worst['src_ip']}: 실패 {worst['failures']}회·계정 "
                    f"{worst['accounts']}개)인데 severity를 {severity}로 판정함. 침해가 일어나지 않았으므로 계정 수·"
                    "횟수와 관계없이 severity는 LOW 또는 MEDIUM으로 판정하십시오"
                )
        return conflicts

    @staticmethod
    def _link_web_exec(state: AgentState) -> None:
        """seed src_ip의 요청 직후(WEB_EXEC_LINK 이내)에 실행된 웹 서버 계정 명령이 있는 audit 집계만
        rule_floors(이 사건의 침해 신호)로 옮긴다. 요청 시각은 도구 결과가 더 쌓이면 늘어나므로 매 호출 뒤 다시 본다.
        웹셸은 요청 하나에 명령 하나가 바로 실행되므로 짧은 간격으로 잇는다(0918 웹셸 시나리오: 1초 이내)."""
        requests = [t for t in (_parse_utc(v) for v in state.src_ip_request_times) if t]
        for check in list(state.unlinked_web_exec):
            commands = [t for t in (_parse_utc(v) for v in check.get("web_suspicious_times") or []) if t]
            if any(timedelta(0) <= c - r <= WEB_EXEC_LINK for c in commands for r in requests):
                state.unlinked_web_exec.remove(check)
                if check not in state.rule_floors:
                    state.rule_floors.append(check)

    @staticmethod
    def _unchecked_command_ips(state: AgentState) -> list:
        """audit 명령에 등장한 외부 IP 중 아직 network 조회(ip/src_ip/dst_ip 인자)를 시도하지 않은 것."""
        queried = set()
        for call in state.tool_calls:
            if call.tool_name == "fetch_network_log":
                queried.update(str(call.input.get(key)) for key in ("ip", "src_ip", "dst_ip") if call.input.get(key))
            elif call.tool_name == "fetch_event_logs":
                network_filters = (call.input.get("filters") or {}).get("network") or {}
                queried.update(str(network_filters.get(key)) for key in ("ip", "src_ip", "dst_ip")
                               if network_filters.get(key))
        return [ip for ip in state.command_external_ips if ip not in queried]

    def _untried_tool_hint(self, attempted: set) -> str:
        registered = {spec.name for spec in self.tool_registry.list_tools()}
        options = [f"{name}: {purpose}" for name, purpose in self.UNTRIED_TOOL_PURPOSE.items()
                   if name in registered and name not in attempted]
        if not options:
            return "등록된 로그 도구를 모두 확인했습니다."
        return "아직 확인하지 않은 도구 중 사건과 관련된 것을 최소 1회 호출하십시오 — " + " / ".join(options)

    # ------------------------------------------------------------------
    # 폴백 판정 — LLM이 강제 종료 턴(force_terminate=True)에서도 final_verdict를 못 주거나
    # 응답을 연속으로 해석하지 못한 경우의 최후 안전망. 누적 신뢰도 수치만으로 판정한다.
    # ------------------------------------------------------------------
    def _derive_fallback_verdict(self, state: AgentState, cause: Optional[str] = None) -> Dict[str, Any]:
        if state.current_confidence >= self.confidence_threshold:
            verdict_type = VerdictType.THREAT_CONFIRMED.value
        elif state.contradicting_evidence and not state.evidence:
            verdict_type = VerdictType.FALSE_POSITIVE.value
        else:
            verdict_type = VerdictType.INCONCLUSIVE.value

        leading_hyp = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)

        if state.current_confidence >= 0.7:
            severity = "HIGH"
        elif state.current_confidence >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        affected_systems = sorted(state.investigated_layers) if state.investigated_layers else []

        supporting = "; ".join(e.description for e in state.evidence[-3:]) or "충분한 지지 증거를 확보하지 못함"
        used_tools = sorted({t.tool_name for t in state.tool_calls if t.success})

        return {
            "verdict": verdict_type,
            "confidence": round(state.current_confidence, 3),
            "severity": severity,
            "attack_type": leading_hyp.title if leading_hyp else "unknown",
            "affected_systems": affected_systems,
            "summary": (
                f"{cause or f'최대 조사 횟수({self.max_calls}회) 또는 최대 사이클에 도달해 강제 종료됨'}. "
                f"현재 신뢰도 {state.current_confidence:.2f} 기준 잠정 판단: {verdict_type}. "
                f"최근 근거: {supporting}"
            ),
            "reasoning": (
                f"[자동 폴백 판정 — LLM이 final_verdict를 제공하지 않아 시스템이 자체 계산함] "
                f"사용된 도구: {', '.join(used_tools) if used_tools else '없음'}. "
                f"누적 confidence({state.current_confidence:.2f})와 threshold({self.confidence_threshold}) "
                f"비교만으로 verdict_type을 결정했으며, 개별 신호 확인 과정은 거치지 않았습니다."
            ),
        }

    # ------------------------------------------------------------------
    # [24] LLM 판단 결과를 State에 반영 — run() [24]에서 매 턴 호출
    #   facts/unknowns/가설을 덮어쓰고, 새 증거마다 원본 참조를 검증한 뒤 신뢰도에 더한다(반박이면 뺀다).
    #   → agent/provenance.py validate_citations(), agent/models.py AgentState.update_confidence()
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
            # raw_ref를 빠뜨리거나 형식이 틀린 것은 LLM의 복사 실수라서, 기여를 0으로 만들면 같은
            # 증거라도 실행마다 confidence가 달라져 재현성이 무너졌다. 그 경우엔 기여를 그대로 반영하고
            # provenance에만 기록한다. 관측되지 않은 참조를 지어낸 경우(unknown)와 위치가 모호한
            # 경우만 0으로 막는다.
            try:
                raw_refs, unknown_refs = validate_citations(ev, state.raw_refs)
            except ValueError as exc:
                raw_refs, unknown_refs = [], []
                state.provenance_issues.append({"sequence": sequence, "error": str(exc)})
            if unknown_refs:
                contribution = 0.0
                state.provenance_issues.append({"sequence": sequence, "unknown_raw_refs": unknown_refs})
            raw_refs = list(dict.fromkeys(source for ref in raw_refs
                                          for source in state.raw_ref_groups.get(ref, [ref])))
            if any(len(state.raw_ref_locations.get(ref, [])) > 1 for ref in raw_refs):
                contribution = 0.0
            # "조회 결과 0건" 증거는 인용할 원본 줄이 없다. LLM이 적은 empty_result_call이 실제로
            # 성공한 0건 조회인지 코드가 확인한 경우에만 원본 누락으로 세지 않는다(2026-09-27: 이 증거들
            # 때문에 원본 추적에 문제가 없는데도 provenance가 incomplete로 나왔다).
            # 확인에 실패한 번호(없는 호출·실패한 호출·결과가 있던 호출)는 지어낸 참조와 같이 기여를 0으로
            # 막는다 — 2026-09-27 실제 실행에서 호출하지 않은 fetch_auth_log의 "0건"을 없는 번호로 인용해
            # 신뢰도를 임계값까지 채우고 FALSE_POSITIVE로 끝냈다. 번호를 아예 안 적은 경우는 복사 실수로 보고
            # 위 raw_ref 누락과 같이 기여를 반영한다.
            empty_call = None
            if not raw_refs and not unknown_refs and ev.get("empty_result_call") is not None:
                empty_call = _verified_empty_call(state, ev["empty_result_call"])
                if empty_call is None:
                    contribution = 0.0
                    state.provenance_issues.append(
                        {"sequence": sequence, "unverified_empty_result_call": ev["empty_result_call"]})
                    state.notes.append(f"증거 {sequence}: empty_result_call={ev['empty_result_call']!r}은 "
                                       "성공한 0건 조회가 아니어서 신뢰도 기여를 제외했습니다(provenance 미완료).")
            if (not raw_refs and not unknown_refs and ev.get("empty_result_call") is None
                    and state.raw_refs):
                state.notes.append(f"증거 {sequence}: raw_ref 인용이 없습니다(신뢰도 기여는 반영, provenance 미완료).")
            # 같은 로그를 다시 인용한 증거는 신뢰도에 두 번 반영하지 않는다. 종료 관문이 거부된 뒤 LLM이
            # 이미 기록한 사실을 새 evidence로 다시 만들어 임계값을 채우는 사례가 main.py 실행에서
            # 확인됐다(원칙: 한 관찰 사실은 한 번만).
            cited = {ref for e in state.evidence + state.contradicting_evidence for ref in e.raw_refs}
            if raw_refs and set(raw_refs) <= cited and contribution:
                contribution = 0.0
                state.notes.append(f"증거 {sequence}: 이미 인용된 raw_ref만 다시 인용해 신뢰도 기여를 제외했습니다.")
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
                raw_refs=raw_refs,
                empty_result_call=empty_call,
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
    # [28] 도구 실행 — run() [27]과 network 사전 조회 [19-1]에서 호출
    #   중복 호출 차단 → [29] 인자 검사 → [30] registry.call() → [37] 결과 수집 → [38]·[39] 기록.
    #   도구가 실패해도 예외를 올리지 않고 오류를 다음 턴 관측으로 넘겨 조사를 계속한다.
    # ------------------------------------------------------------------
    def _execute_tool_call(self, state: AgentState, tool_call: Dict[str, Any]) -> None:
        name = tool_call.get("tool_name")
        args = tool_call.get("args") or {}
        if name == "fetch_event_logs":
            args = dict(args)
            args.setdefault("host", state.seed.get("host"))
            if "event" not in args and "window" not in args:
                args["event"] = state.seed

        if not name:
            state.notes.append("LLM이 next_action=call_tool을 선택했지만 tool_call을 채우지 않았습니다.")
            return

        if state.already_called(name, args):
            state.notes.append(f"중복 호출 스킵: {name}({args}) — 이미 조회된 조합입니다.")
            return

        try:
            # [29] → agent/tools/registry.py validate_args(): 필수 인자·형식 검사
            self.tool_registry.validate_args(name, args)
            # [30] → agent/tools/registry.py ToolRegistry.call(): 실제 도구 함수 실행
            #        → [31]~[36] agent/tools/real/<도구>.py → log_source → normalizer_adapter → 1차 탐지팀 정규화
            # [37] ← 도구 결과 dict (count, summary, records, window_total, rule_checks ...)
            result = self.tool_registry.call(name, args)
            # 도구 결과에서 관측된 원본 참조를 모은다 — 이후 LLM이 증거에 인용한 raw_ref를 이 집합과 대조한다
            raw_refs = observed_references(result)
            state.raw_refs = list(dict.fromkeys(state.raw_refs + raw_refs))
            for ref, group in observed_reference_groups(result).items():
                state.raw_ref_groups[ref] = list(dict.fromkeys(state.raw_ref_groups.get(ref, []) + group))
            for ref, sources in observed_locations(result).items():
                state.raw_ref_locations[ref] = list(dict.fromkeys(state.raw_ref_locations.get(ref, []) + sources))
            queried_layers = [layer for layer in result.get("layer_counts", {})
                              if layer not in result.get("errors", {})]
            # [37-1] 종료 관문 [25-2]용: 도구가 계산한 원칙 기준(rule_checks) 중 seed src_ip에 해당하는 것
            src_ip = state.seed.get("src_ip")
            # seed src_ip의 요청 시각 — 아래 웹 서버 계정 명령과 이 사건을 잇는 근거
            for record in result.get("records") or []:
                if (isinstance(record, dict) and src_ip and record.get("src_ip") == src_ip
                        and record.get("timestamp") and record["timestamp"] not in state.src_ip_request_times):
                    state.src_ip_request_times.append(record["timestamp"])
            for check in result.get("rule_checks") or []:
                principle9_met = (check.get("rule") == "principle_9" and src_ip and check.get("src_ip") == src_ip
                                  and (check.get("auth_bruteforce") or check.get("path_scan")))
                web_exec_met = check.get("rule") == "audit_post_exploitation" and check.get("web_server_suspicious")
                # 원칙 7은 충족(무차별 대입)·미충족(단발성 실패) 모두 판정 기준이라 둘 다 기록한다.
                principle7_seen = check.get("rule") == "principle_7" and src_ip and check.get("src_ip") == src_ip
                if web_exec_met and src_ip and "web_suspicious_times" in check:
                    # IP 사건: 같은 시간대 audit에 웹 서버 계정 명령이 있다는 것만으로는 이 IP의 침해가 아니다.
                    # 2026-09-29 EC2: /.git/config 404 한 건(06:39)인 IP 사건이, 무관한 다른 IP의 웹셸
                    # 명령(06:58)을 근거로 THREAT_CONFIRMED CRITICAL이 됐다 — 이 관문이 FALSE_POSITIVE를 거부했다.
                    if check not in state.unlinked_web_exec:
                        state.unlinked_web_exec.append(check)
                elif (principle9_met or web_exec_met or principle7_seen) and check not in state.rule_floors:
                    state.rule_floors.append(check)
                # 종료 관문 (f)용: audit 명령에 등장한 외부 IP
                for ip in check.get("external_ips") or []:
                    if ip not in state.command_external_ips:
                        state.command_external_ips.append(ip)
            self._link_web_exec(state)
            # 필터 전 구간 전체 건수 — 모두 0이면 로그 미확보로 보고 [25-2]가 INCONCLUSIVE만 허용한다
            if "window_total" in result:
                state.window_totals.append(result["window_total"])
            # 종료 관문 (e)용: seed src_ip의 로그인 성공이 결과에 있었는지 기록
            seen = {login["raw_ref"] for login in state.login_successes}
            for record in result.get("records") or []:
                if (isinstance(record, dict) and src_ip and record.get("event") == "ssh_accepted"
                        and record.get("src_ip") == src_ip and record.get("raw_ref") not in seen):
                    state.login_successes.append({key: record.get(key) for key in ("raw_ref", "pid", "user", "timestamp")})
                    seen.add(record.get("raw_ref"))
            # [38] 이 도구 + 이 조건 조합은 이미 썼다고 표시(중복 방지)하고, 호출 기록을 남긴다
            #      (최종 JSON의 tools_called[]에 그대로 나오는 부분)
            state.mark_called(name, args)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=result.get("count", 0),
                    result_summary=result.get("summary", ""),
                    success=not bool(result.get("error") or result.get("partial")),
                    error=result.get("error") or (str(result["errors"]) if result.get("partial") else None),
                    raw_refs=raw_refs,
                    queried_layers=queried_layers,
                )
            )

            # [39] 결과를 다음 턴 LLM 관측(raw_observations_since_last_turn)으로 넘긴다 → run() [27] 뒤로 복귀
            #      sequence는 0건 증거의 empty_result_call로 인용하는 번호다
            state.pending_observations.append({"sequence": state.tool_calls[-1].sequence,
                                               "tool_name": name, "args": args, "result": result})
        except (ToolValidationError, KeyError, NotImplementedError) as exc:
            state.mark_called(name, args)
            error_msg = str(exc)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="호출 실패",
                    success=False,
                    error=error_msg,
                )
            )
            state.pending_observations.append(
                {
                    "sequence": state.tool_calls[-1].sequence,
                    "tool_name": name,
                    "args": args,
                    "result": {
                        "count": 0,
                        "summary": f"도구 호출 실패: {error_msg}",
                        "records": [],
                        "error": error_msg,
                    },
                }
            )
            state.notes.append(f"도구 호출 실패({name}): {error_msg} — 조사는 계속 진행됩니다.")
        except Exception as exc:  # 예상치 못한 오류도 조사 전체를 중단시키지 않는다
            state.mark_called(name, args)
            error_msg = str(exc)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="예외 발생",
                    success=False,
                    error=error_msg,
                )
            )
            state.pending_observations.append(
                {
                    "sequence": state.tool_calls[-1].sequence,
                    "tool_name": name,
                    "args": args,
                    "result": {
                        "count": 0,
                        "summary": f"도구 호출 중 예외 발생: {error_msg}",
                        "records": [],
                        "error": error_msg,
                    },
                }
            )
            state.notes.append(f"도구 호출 중 예외({name}): {error_msg}")
