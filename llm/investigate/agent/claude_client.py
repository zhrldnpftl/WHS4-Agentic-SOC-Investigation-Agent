"""Claude(Anthropic API) LLM 클라이언트 — 기본 LLM(INVESTIGATION_LLM_PROVIDER가 비었거나 anthropic일 때).

역할
  프롬프트를 받아 Claude를 호출하고 응답을 JSON(dict)으로 파싱해 돌려준다. GeminiClient와 같은
  인터페이스라 INVESTIGATION_LLM_PROVIDER만 바꾸면 그대로 교체된다.
  temperature는 보내지 않는다: anthropic SDK 1.x에서 인자가 삭제됐고(보내면 TypeError), 기본 모델
  claude-sonnet-5도 sampling 인자를 받지 않는다(400). 판정 재현성은 프롬프트 원칙과 코드 관문이 맡는다.
  claude-sonnet-5는 thinking이 기본으로 켜져 있어 thinking 토큰도 max_tokens에 포함된다 → 출력 한도 16000.
  일시 오류(429 한도, 5xx·529 과부하, 연결 끊김·시간 초과)는 anthropic SDK가 서버 안내 시간만큼 기다렸다
  재시도하고, 그래도 실패하면 LLMUnavailableError로 올린다(조사 루프가 그 사건만 조사 미완료로 처리).
  시스템 프롬프트는 매 턴 같으므로 프롬프트 캐싱으로 표시해 반복 호출 비용을 줄이고, 호출마다 쓴 토큰을
  usage_totals에 누적한다(조사 1건 비용 측정용).

누가 부르나
  agent/llm_provider.py build_llm_client()   → ClaudeClient()    생성 (기본, INVESTIGATION_LLM_PROVIDER=anthropic)
  [20] agent/loop.py _safe_reason()          → reason()          조사 루프 매 턴

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()
  [22] anthropic  messages.create()

필요 환경변수: INVESTIGATION_ANTHROPIC_API_KEY(조사 에이전트 전용 키, 먼저 읽음) 또는 ANTHROPIC_API_KEY.
  1차 탐지(llm/triage_review)도 ANTHROPIC_API_KEY를 쓰므로 키를 나누려면 전용 키를 둔다. 빈 값은 없는 것으로
  보고 ANTHROPIC_API_KEY로 넘어간다. 어느 이름을 썼는지는 키 값 없이 콘솔("[Claude] API 키: <이름> 사용")과
  api_key_source 속성에 남긴다.
모델 설정은 INVESTIGATION_ 접두어 이름만 읽는다(루트 .env를 다른 역할과 같이 쓰므로, agent/settings.py).
  접두어 없는 옛 이름(CLAUDE_MODEL 등)은 무시하고 이름만 안내한다.
  INVESTIGATION_CLAUDE_MODEL — 없으면 claude-sonnet-5. EC2는 비용 때문에 claude-haiku-4-5-20251001을 쓴다.
  INVESTIGATION_CLAUDE_EFFORT(low|medium|high|xhigh|max) — 없으면 보내지 않음(API 기본값).
  INVESTIGATION_CLAUDE_REFUSAL_FALLBACK_MODEL — 안전 필터 거절(stop_reason=refusal) 시 같은 요청을 다시 보낼
  모델. 없거나 비우면 claude-sonnet-4-6. 재요청을 끄는 none/off는 실험용이며 운영에서는 쓰지 않는다(켜면
  경고 출력). 대체 호출은 결과 notes에 남는다.
테스트에서는 같은 인터페이스의 가짜 클라이언트로 바꿔 쓴다(tests/test_loop.py, tests/test_claude_client.py).
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .llm_errors import LLMUnavailableError
from .llm_json import parse_llm_json
from .prompts import build_system_prompt, build_user_prompt
from .settings import investigation_setting

DEFAULT_MODEL = "claude-sonnet-5"
# 거절 시 대체 모델: sonnet-5는 sonnet-4.6보다 사이버 보안 주제를 더 엄격하게 거른다(Anthropic 문서).
DEFAULT_REFUSAL_FALLBACK_MODEL = "claude-sonnet-4-6"
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
# 앞에서부터 값이 있는 첫 이름의 키를 쓴다 (조사 전용 키 → 1차 탐지와 공용 키)
API_KEY_ENV_NAMES = ("INVESTIGATION_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
# SDK 재시도 뒤에도 이 상태 코드면 일시 오류로 본다(429 한도, 5xx·529 과부하, 408 시간 초과)
TRANSIENT_STATUS = frozenset({408, 429, 500, 502, 503, 504, 529})


def _is_transient(exc: Exception) -> bool:
    import anthropic

    connection_error = getattr(anthropic, "APIConnectionError", None)  # APITimeoutError 포함
    status_error = getattr(anthropic, "APIStatusError", None)
    if connection_error is not None and isinstance(exc, connection_error):
        return True
    return status_error is not None and isinstance(exc, status_error) and (
        getattr(exc, "status_code", None) in TRANSIENT_STATUS)


def _refusal_category(response: Any) -> Optional[str]:
    """거절 분류(cyber 등). 정보용이라 없을 수 있다(None)."""
    return getattr(getattr(response, "stop_details", None), "category", None)


class ClaudeDecisionError(Exception):
    """LLM 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생 (loop.py가 1회 재시도 후 폴백)."""


class ClaudeClient:
    # SDK 재시도 횟수 (429·529·연결 오류). SDK는 retry-after 안내를 따르고, 없으면 지수 백오프한다.
    MAX_RETRIES = 4

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        # 2000이면 LLM이 원본 참조를 옮겨 적다 응답이 잘려 조사가 멈췄다(Gemini는 8192).
        # claude-sonnet-5는 thinking 토큰도 이 한도에 들어가므로 더 크게 잡는다. 스트리밍 없이 부를 수 있는
        # 범위(SDK의 10분 제한 안)로 둔다.
        max_tokens: int = 16000,
        effort: Optional[str] = None,
    ) -> None:
        # anthropic 패키지는 실제 API 호출 시에만 필요하므로 지연 import한다.
        from anthropic import Anthropic

        # 어느 이름의 키를 썼는지(키 값 아님) — 1차 탐지(llm/triage_review)와 키를 나눴는지 확인용
        self.api_key_source = "api_key 인자" if api_key else next(
            (name for name in API_KEY_ENV_NAMES if os.environ.get(name)), None)
        resolved_key = api_key or (os.environ.get(self.api_key_source) if self.api_key_source else None)
        if not resolved_key:
            raise ValueError(
                f"{' 또는 '.join(API_KEY_ENV_NAMES)}가 설정되지 않았습니다. .env 파일에 "
                "INVESTIGATION_ANTHROPIC_API_KEY=발급받은_키(조사 에이전트 전용, 권장) 또는 "
                "ANTHROPIC_API_KEY=발급받은_키 를 추가하거나 ClaudeClient(api_key=...)로 "
                "직접 전달하십시오."
            )
        print(f"[Claude] API 키: {self.api_key_source} 사용")
        self._client = Anthropic(api_key=resolved_key, max_retries=self.MAX_RETRIES)
        # 모델 설정은 INVESTIGATION_ 이름만 읽는다(옛 CLAUDE_* 이름은 무시하고 안내, agent/settings.py)
        self.model = model or investigation_setting("CLAUDE_MODEL") or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.effort = (effort or investigation_setting("CLAUDE_EFFORT") or "").strip().lower() or None
        if self.effort is not None and self.effort not in EFFORT_LEVELS:
            raise ValueError(
                f"INVESTIGATION_CLAUDE_EFFORT는 {', '.join(EFFORT_LEVELS)} 중 하나여야 합니다: {self.effort}")
        # 안전 필터 거절(refusal) 시 같은 요청을 다시 보낼 모델. 비우면 기본 대체 모델(재요청을 끄지 않는다).
        # none/off는 실험용으로만 남긴 끄기 — 운영에서는 쓰지 않는다(켜져 있지 않음을 알린다).
        fallback = investigation_setting("CLAUDE_REFUSAL_FALLBACK_MODEL") or DEFAULT_REFUSAL_FALLBACK_MODEL
        self.refusal_fallback_model = None if fallback.lower() in ("none", "off") else fallback
        if self.refusal_fallback_model is None:
            print("[Claude] 경고: 거절 시 대체 모델 재요청이 꺼져 있습니다(INVESTIGATION_CLAUDE_REFUSAL_FALLBACK_MODEL)")
        # 이 클라이언트로 한 모든 호출의 토큰 합계 (비용 추정용)와 거절·대체 호출 횟수
        self.usage_totals: Dict[str, int] = {
            "calls": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            "refusals": 0, "fallback_calls": 0,
        }

    # [21] ← agent/loop.py [20] _safe_reason()에서 매 턴 호출 (GeminiClient.reason과 같은 인자)
    def reason(
        self,
        state: Any,
        tool_registry: Any,
        confidence_threshold: Optional[float] = None,
        force_terminate: bool = False,
        gate_rejection_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """조사 루프 전용: agent/prompts/의 조사 프롬프트를 만들어 호출한다.

        confidence_threshold: 시스템의 종료 임계값을 프롬프트에 노출해 LLM이 스스로 확인하게 한다.
        force_terminate: 강제 종료·max_call 마무리 턴에서 True — 도구 없이 판정만 요청한다.
        gate_rejection_reason: 직전 턴에 종료 관문이 거부한 사유 — LLM이 같은 종료를 반복하지 않게 한다.
        """
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        # [22] → complete_json()으로 실제 호출 / [23] ← 파싱된 결정 dict를 loop.py로 돌려준다
        return self.complete_json(system_prompt, user_prompt)

    # [22] 실제 Claude 호출 — 조사 루프의 reason()이 여기로 온다
    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다."""
        notes = []
        response = self._create(self.model, system_prompt, user_prompt, effort=self.effort)
        if getattr(response, "stop_reason", None) == "refusal":
            # 안전 분류기가 공격 로그(웹셸 명령 등)를 사이버 공격 요청으로 오인해 거절할 수 있다(2026-09-29
            # 재현성 측정: 웹셸 시나리오 4회 중 1회 연속 2번 거절 → 폴백 판정). sonnet-5는 서버 측 fallbacks
            # 대상 모델이 없어(allowed_fallback_models 빈 목록) 같은 요청을 대체 모델로 한 번 직접 다시 보낸다.
            category = _refusal_category(response)
            self.usage_totals["refusals"] += 1
            fallback = self.refusal_fallback_model
            if not fallback or fallback == self.model:
                raise ClaudeDecisionError(
                    f"Claude가 응답을 거절했습니다(refusal, category={category}, 대체 모델 없음)")
            notes.append(f"Claude({self.model})가 안전 필터로 응답을 거절해(refusal, category={category}) "
                         f"같은 요청을 {fallback}로 다시 보냄")
            # effort 단계는 모델마다 달라(xhigh는 4.7 이후) 대체 모델에는 보내지 않는다
            response = self._create(fallback, system_prompt, user_prompt, effort=None)
            self.usage_totals["fallback_calls"] += 1
            if getattr(response, "stop_reason", None) == "refusal":
                raise ClaudeDecisionError(
                    f"Claude가 응답을 거절했습니다(refusal, category={category}, 대체 모델 {fallback}도 거절: "
                    f"category={_refusal_category(response)})")
        text = "".join(getattr(block, "text", "") for block in response.content if block.type == "text")
        if getattr(response, "stop_reason", None) == "max_tokens":
            # 잘린 JSON은 고칠 수 없다 — loop.py가 해석 실패로 보고 1회 재시도, 그래도 실패하면 폴백 판정
            raise ClaudeDecisionError(
                f"Claude 응답이 출력 한도({self.max_tokens} 토큰)에서 잘렸습니다.\n원본 응답(앞부분):\n{text[:500]}"
            )
        if not text.strip():
            raise ClaudeDecisionError(f"Claude가 빈 응답을 반환했습니다. (stop_reason={getattr(response, 'stop_reason', None)})")
        # Gemini와 달리 JSON만 내보내게 강제하는 설정이 없어 앞뒤에 설명 문장이 붙을 수 있다 — 공용 파서가 꺼낸다
        decision = parse_llm_json(text, ClaudeDecisionError, label="Claude")
        if notes:
            # 결과 JSON의 investigation_notes에 남도록 결정에 붙인다(loop.py가 notes에 더한다)
            decision["investigation_notes"] = list(decision.get("investigation_notes") or []) + notes
        return decision

    def _create(self, model: str, system_prompt: str, user_prompt: str, effort: Optional[str]) -> Any:
        extra: Dict[str, Any] = {"output_config": {"effort": effort}} if effort else {}
        try:
            response = self._client.messages.create(
                model=model,
                max_tokens=self.max_tokens,
                # 시스템 프롬프트(원칙·도구 목록·출력 형식)는 매 턴 같아서 캐시해 두고 다시 읽는다.
                system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user_prompt}],
                **extra,
            )
        except Exception as exc:
            if _is_transient(exc):
                raise LLMUnavailableError(
                    f"Claude API 일시 오류({type(exc).__name__}, 재시도 {self.MAX_RETRIES}회 후): {str(exc)[:200]}"
                ) from exc
            raise
        self._add_usage(getattr(response, "usage", None))
        return response

    def _add_usage(self, usage: Any) -> None:
        self.usage_totals["calls"] += 1
        if usage is None:
            return
        for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            self.usage_totals[key] += int(getattr(usage, key, 0) or 0)
