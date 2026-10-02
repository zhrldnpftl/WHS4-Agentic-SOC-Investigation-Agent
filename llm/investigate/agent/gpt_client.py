"""GPT(OpenAI API) LLM 클라이언트 — <역할>_LLM_PROVIDER=openai(또는 gpt)일 때.

역할
  프롬프트를 받아 OpenAI Chat Completions를 호출하고 응답을 JSON(dict)으로 파싱해 돌려준다. ClaudeClient·
  GeminiClient와 인터페이스(.reason / .complete_json / .model / .usage_totals)가 같아 조사 에이전트(INVESTIGATION)와
  ATT&CK 매핑(MAPPING) 어느 역할에도 그대로 쓴다. 2026-10-02 LLM 모델 비교(Claude vs GPT)용으로 추가했다.
  - JSON 모드(response_format=json_object)로 JSON 객체만 받는다. 조사·매핑 프롬프트 모두 "JSON 객체 하나만"을
    요구하므로 이 모드의 조건(프롬프트에 JSON이라는 말)이 맞는다. 그래도 응답 해석은 공용 parse_llm_json이 한다.
  - temperature는 보내지 않는다 — 추론(reasoning) 계열 모델은 추론을 켜면 기본값 외 값을 거부한다. 추론 강도는 선택
    <역할>_OPENAI_REASONING_EFFORT(보낼 때만 reasoning_effort로 전달). 안 보내면 모델 기본값이라 모델마다 다르다
    (OpenAI 공식 모델 페이지 기준 gpt-5.5 medium, gpt-5.4-mini none — 2026-10-02 확인). 추론 토큰은 출력 요금이다.
  - 출력 한도 16000(max_completion_tokens) — 추론 토큰도 이 한도에 들어간다. 잘리면(finish_reason=length) 해석 실패.
  - 일시 오류(429 요청 한도, 5xx, 연결 끊김·시간 초과)는 SDK가 재시도하고, 그래도 실패하면 LLMUnavailableError로
    올린다(조사 루프가 그 사건만 조사 미완료로 처리). 단 429라도 잔액 부족(insufficient_quota)은 기다려도 풀리지
    않으므로 감싸지 않고 그대로 올려 전체 실행을 멈춘다.
  - 거절(message.refusal 또는 finish_reason=content_filter)은 해석 실패로 처리하고 refusals에 센다. Claude처럼 다른
    모델로 다시 보내지는 않는다.
  - 호출마다 쓴 토큰을 usage_totals에 Claude와 같은 키로 누적한다(input_tokens는 캐시에서 읽은 토큰을 뺀 값).

누가 부르나
  agent/llm_provider.py build_llm_client(role)   → GPTClient(role=...)   (<역할>_LLM_PROVIDER=openai)
  [20] agent/loop.py _safe_reason()              → reason()             조사 루프 매 턴
  attack_mapping/mapper.py                       → complete_json()      ATT&CK 매핑 (role=MAPPING 객체)

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()
  [22] openai  chat.completions.create()

필요 환경변수: <역할>_OPENAI_API_KEY(역할 전용, 먼저 읽음) 또는 OPENAI_API_KEY(공용).
모델: <역할>_OPENAI_MODEL — **기본값 없음.** 계정마다 쓸 수 있는 모델이 달라 이름을 짐작하지 않는다. 비어 있으면
  설정 오류로 알린다(모델 목록은 OpenAI 계정의 Models API로 조회).
테스트에서는 가짜 openai 모듈로 바꿔 쓴다(tests/test_gpt_client.py).
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .llm_errors import LLMUnavailableError
from .llm_json import parse_llm_json
from .prompts import build_system_prompt, build_user_prompt
from .settings import INVESTIGATION, role_setting

# gpt-5.4·5.5 계열은 none~xhigh(기본값은 모델마다 다름: gpt-5.5 medium, gpt-5.4-mini none), 이전 gpt-5는 minimal
REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh")
# SDK 재시도 뒤에도 이 상태 코드면 일시 오류로 본다(429 한도, 5xx, 408 시간 초과)
TRANSIENT_STATUS = frozenset({408, 429, 500, 502, 503, 504})


def api_key_env_names(role: str = INVESTIGATION) -> tuple:
    """앞에서부터 값이 있는 첫 이름의 키를 쓴다 (역할 전용 키 → 공용 키)."""
    return (f"{role}_OPENAI_API_KEY", "OPENAI_API_KEY")


def _error_code(exc: Exception) -> Optional[str]:
    """OpenAI 오류 본문의 code(예: insufficient_quota). 없으면 None."""
    code = getattr(exc, "code", None)
    if code:
        return str(code)
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        inner = body.get("error") if isinstance(body.get("error"), dict) else body
        return inner.get("code")
    return None


def _is_transient(exc: Exception) -> bool:
    import openai

    if _error_code(exc) == "insufficient_quota":
        return False   # 잔액 부족 — 재시도해도 풀리지 않는 설정 문제
    connection_error = getattr(openai, "APIConnectionError", None)  # APITimeoutError 포함
    status_error = getattr(openai, "APIStatusError", None)
    if connection_error is not None and isinstance(exc, connection_error):
        return True
    return status_error is not None and isinstance(exc, status_error) and (
        getattr(exc, "status_code", None) in TRANSIENT_STATUS)


class GPTDecisionError(Exception):
    """GPT 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생 (loop.py가 1회 재시도 후 폴백)."""


class GPTClient:
    # SDK 재시도 횟수 (429·5xx·연결 오류). SDK는 retry-after 안내를 따르고, 없으면 지수 백오프한다.
    MAX_RETRIES = 4

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_completion_tokens: int = 16000,
        reasoning_effort: Optional[str] = None,
        role: str = INVESTIGATION,
    ) -> None:
        # openai 패키지는 실제 API 호출 시에만 필요하므로 지연 import한다.
        from openai import OpenAI

        self.role = role
        key_names = api_key_env_names(role)
        self.api_key_source = "api_key 인자" if api_key else next(
            (name for name in key_names if (os.environ.get(name) or "").strip()), None)
        resolved_key = api_key or (os.environ.get(self.api_key_source) if self.api_key_source else None)
        if not resolved_key:
            raise ValueError(
                f"{' 또는 '.join(key_names)}가 설정되지 않았습니다. 저장소 루트 .env에 "
                f"{key_names[0]}=발급받은_키(역할 전용) 또는 OPENAI_API_KEY=발급받은_키(공용)를 추가하십시오 "
                "(ChatGPT 구독이 아니라 platform.openai.com API 키)."
            )
        self.model = model or role_setting(role, "OPENAI_MODEL")
        if not self.model:
            raise ValueError(
                f"{role}_OPENAI_MODEL이 설정되지 않았습니다 — GPT는 기본 모델을 두지 않습니다. "
                "OpenAI 계정에서 쓸 수 있는 모델 이름을 .env 또는 실행 시 환경변수로 지정하십시오.")
        self.max_completion_tokens = max_completion_tokens
        self.reasoning_effort = (reasoning_effort or role_setting(role, "OPENAI_REASONING_EFFORT")
                                 or "").strip().lower() or None
        if self.reasoning_effort is not None and self.reasoning_effort not in REASONING_EFFORTS:
            raise ValueError(f"{role}_OPENAI_REASONING_EFFORT는 {', '.join(REASONING_EFFORTS)} 중 하나여야 "
                             f"합니다: {self.reasoning_effort}")
        self._client = OpenAI(api_key=resolved_key, max_retries=self.MAX_RETRIES)
        print(f"[GPT] API 키: {self.api_key_source} 사용 ({role}, 모델 {self.model})")
        # 이 클라이언트로 한 모든 호출의 토큰 합계 (ClaudeClient.usage_totals와 같은 키 — main.py 사용량 기록용)
        self.usage_totals: Dict[str, int] = {
            "calls": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            "refusals": 0, "fallback_calls": 0, "reasoning_tokens": 0,
        }

    # [21] ← agent/loop.py [20] _safe_reason()에서 매 턴 호출 (ClaudeClient.reason과 같은 인자)
    def reason(
        self,
        state: Any,
        tool_registry: Any,
        confidence_threshold: Optional[float] = None,
        force_terminate: bool = False,
        gate_rejection_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """조사 루프 전용: agent/prompts/의 조사 프롬프트를 만들어 호출한다."""
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        return self.complete_json(system_prompt, user_prompt)

    # [22] 실제 GPT 호출 — 조사 루프의 reason()과 ATT&CK 매핑이 여기로 온다
    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다."""
        response = self._create(system_prompt, user_prompt)
        choice = response.choices[0]
        message = choice.message
        refusal = getattr(message, "refusal", None)
        if refusal or choice.finish_reason == "content_filter":
            self.usage_totals["refusals"] += 1
            # "refusal"은 eval/eval_tool.py가 거절 횟수를 세는 표시라 문구에 남긴다(Claude와 같음)
            raise GPTDecisionError(f"GPT가 응답을 거절했습니다(refusal, finish_reason={choice.finish_reason}): "
                                   f"{str(refusal or '')[:200]}")
        text = message.content or ""
        if choice.finish_reason == "length":
            # 잘린 JSON은 고칠 수 없다 — loop.py가 해석 실패로 보고 1회 재시도, 그래도 실패하면 폴백 판정
            raise GPTDecisionError(
                f"GPT 응답이 출력 한도({self.max_completion_tokens} 토큰, 추론 토큰 포함)에서 잘렸습니다.\n"
                f"원본 응답(앞부분):\n{text[:500]}")
        if not text.strip():
            raise GPTDecisionError(f"GPT가 빈 응답을 반환했습니다. (finish_reason={choice.finish_reason})")
        return parse_llm_json(text, GPTDecisionError, label="GPT")

    def _create(self, system_prompt: str, user_prompt: str) -> Any:
        extra: Dict[str, Any] = {"reasoning_effort": self.reasoning_effort} if self.reasoning_effort else {}
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system_prompt},
                          {"role": "user", "content": user_prompt}],
                response_format={"type": "json_object"},
                max_completion_tokens=self.max_completion_tokens,
                **extra,
            )
        except Exception as exc:
            if _is_transient(exc):
                raise LLMUnavailableError(
                    f"GPT API 일시 오류({type(exc).__name__}, 재시도 {self.MAX_RETRIES}회 후): {str(exc)[:200]}"
                ) from exc
            raise
        self._add_usage(getattr(response, "usage", None))
        return response

    def _add_usage(self, usage: Any) -> None:
        self.usage_totals["calls"] += 1
        if usage is None:
            return
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        cached = int(getattr(getattr(usage, "prompt_tokens_details", None), "cached_tokens", 0) or 0)
        reasoning = int(getattr(getattr(usage, "completion_tokens_details", None), "reasoning_tokens", 0) or 0)
        # Claude의 input_tokens처럼 캐시에서 읽지 않은 입력만 센다(OpenAI prompt_tokens는 캐시 포함)
        self.usage_totals["input_tokens"] += prompt - cached
        self.usage_totals["cache_read_input_tokens"] += cached
        self.usage_totals["output_tokens"] += int(getattr(usage, "completion_tokens", 0) or 0)
        self.usage_totals["reasoning_tokens"] += reasoning
