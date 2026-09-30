"""Gemini API LLM 클라이언트 (INVESTIGATION_LLM_PROVIDER=gemini일 때, 기본은 Claude).

역할
  조사 루프와 seed 생성에서 LLM을 부르는 창구. 프롬프트를 받아 Gemini를 호출하고,
  응답을 JSON(dict)으로 파싱해 돌려준다. temperature 0.0 — 같은 증거에 같은 판정이 나오도록
  창의성보다 결정성을 우선한다. 일시적 오류(429 한도, 503 과부하, 연결 끊김)는 기다렸다 재시도한다.

누가 부르나
  [20] agent/loop.py _safe_reason()         → reason()          조사 루프 매 턴
  agent/llm_provider.py build_llm_client()   → GeminiClient()    생성 (INVESTIGATION_LLM_PROVIDER=gemini)

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()   조사 프롬프트 조립
  [22] google-genai  models.generate_content()                                 실제 API 호출

claude_client.py의 ClaudeClient와 인터페이스(.reason / .complete_json)가 같아서
INVESTIGATION_LLM_PROVIDER 환경변수로 서로 바꿔 쓸 수 있다. 필요 환경변수: INVESTIGATION_GEMINI_API_KEY
(조사 전용, 먼저 읽음) 또는 GEMINI_API_KEY — 쓴 이름만 "[Gemini] API 키: <이름> 사용"으로 출력한다.
모델은 INVESTIGATION_GEMINI_MODEL(없으면 gemini-3.5-flash-lite). 옛 이름 GEMINI_MODEL은 읽지 않는다(agent/settings.py).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

from .llm_errors import LLMUnavailableError
from .llm_json import parse_llm_json
from .prompts import build_system_prompt, build_user_prompt
from .settings import investigation_setting


DEFAULT_MODEL = "gemini-3.5-flash-lite"  # 무료 티어 실습에서 지정한 모델
# 앞에서부터 값이 있는 첫 이름의 키를 쓴다 (조사 전용 키 → 공용 키)
API_KEY_ENV_NAMES = ("INVESTIGATION_GEMINI_API_KEY", "GEMINI_API_KEY")


class GeminiDecisionError(Exception):
    """Gemini 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생."""


class GeminiClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        # 없으면 INVESTIGATION_GEMINI_MODEL 환경변수, 그것도 없으면 DEFAULT_MODEL. 특정 모델이 과부하(503)일 때
        # .env만 바꿔 다른 모델로 돌릴 수 있게 한다(2026-09-28 EC2).
        model: Optional[str] = None,
        # 2000이던 값을 8192로 올렸다. EC2에서 LLM이 raw_ref 109개를 evidence에 옮겨 적다
        # 2000 토큰에서 응답이 잘려 JSON 파싱이 실패했고, 그 예외로 main.py 전체가 멈췄다.
        max_output_tokens: int = 8192,
        temperature: float = 0.0,
    ) -> None:
        # google-genai 패키지는 실제 호출 시에만 필요하므로 지연 import한다.
        from google import genai

        # 어느 이름의 키를 썼는지(키 값 아님). 조사 전용 키 → 공용 키 순서(ClaudeClient와 같은 규칙)
        self.api_key_source = "api_key 인자" if api_key else next(
            (name for name in API_KEY_ENV_NAMES if os.environ.get(name)), None)
        resolved_key = api_key or (os.environ.get(self.api_key_source) if self.api_key_source else None)
        if not resolved_key:
            raise ValueError(
                f"{' 또는 '.join(API_KEY_ENV_NAMES)}가 설정되지 않았습니다. 저장소 루트 .env에 "
                "INVESTIGATION_GEMINI_API_KEY=발급받은_키 를 추가하거나 GeminiClient(api_key=...)로 "
                "직접 전달하십시오."
            )
        print(f"[Gemini] API 키: {self.api_key_source} 사용")

        self._client = genai.Client(api_key=resolved_key)
        self.model = model or investigation_setting("GEMINI_MODEL") or DEFAULT_MODEL
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature

    # [21] ← agent/loop.py [20] _safe_reason()에서 매 턴 호출
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
        # [21] → agent/prompts/__init__.py: 시스템 프롬프트(원칙·도구 목록·출력 형식) + 사용자 프롬프트(현재 State)
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        # [22] → complete_json()으로 실제 호출 / [23] ← 파싱된 결정 dict를 loop.py로 돌려준다
        return self.complete_json(system_prompt, user_prompt)

    # [22] 실제 Gemini 호출 — 조사 루프의 reason()이 여기로 온다
    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다."""
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",  # Gemini가 JSON만 반환하도록 강제
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
        )
        response = self._generate_with_retry(user_prompt, config)
        text = response.text
        if not text:
            raise GeminiDecisionError(
                f"Gemini가 빈 응답을 반환했습니다. (finish_reason 등을 확인하십시오)\n원본 응답: {response}"
            )
        # 응답 형식 보정(trailing comma, markdown 리스트로 깨진 키 등)은 공용 파서가 한다
        return parse_llm_json(text, GeminiDecisionError, label="Gemini")

    # 503(서버 과부하)/429(분당 한도)는 일시적인 오류인데, 예전엔 한 번만 나도
    # main.py 전체가 예외로 끝났다(seed 생성 단계에서 연속 발생 확인). 이 코드(와 다른 5xx)만
    # 기다렸다가 다시 시도하고, 그 외 오류(400·401·403 등 설정·요청 오류)는 바로 올려 보낸다.
    # 재시도를 다 써도 일시 오류면 LLMUnavailableError로 감싸 올린다 — 조사 루프가 그 사건만
    # 조사 미완료로 저장하고 다음 사건을 계속한다(2026-09-28 EC2: 503 3회 연속으로 전체 실행·결과 유실).
    _RETRYABLE_STATUS = {429, 500, 502, 503, 504}
    _RETRY_DELAY_RE = re.compile(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)s")
    MAX_ATTEMPTS = 4
    BASE_DELAY_SECONDS = 15.0

    def _generate_with_retry(self, user_prompt: str, config: Any) -> Any:
        import time

        from google.genai import errors

        # 연결이 중간에 끊기는 오류(SSL EOF, WinError 10053 등)도 일시적이라 재시도한다.
        # 재현성 실행 중 두 번 발생해 그 조사 1건이 통째로 실패했다.
        # google-genai는 httpx를 쓰므로 httpx.TransportError도 함께 잡는다.
        try:
            import httpx
            transport_errors: tuple = (OSError, httpx.TransportError)
        except ImportError:  # pragma: no cover - httpx는 google-genai 의존성
            transport_errors = (OSError,)

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                return self._client.models.generate_content(
                    model=self.model, contents=user_prompt, config=config
                )
            except transport_errors as exc:
                if attempt == self.MAX_ATTEMPTS:
                    raise LLMUnavailableError(
                        f"Gemini 연결 오류({type(exc).__name__}, {self.MAX_ATTEMPTS}회 시도 후): {str(exc)[:200]}"
                    ) from exc
                delay = 5.0 * attempt
                print(f"[Gemini 연결 오류: {type(exc).__name__}] {delay:.0f}초 후 재시도 ({attempt}/{self.MAX_ATTEMPTS - 1})")
                time.sleep(delay)
            except errors.APIError as exc:
                if exc.code not in self._RETRYABLE_STATUS:
                    raise
                if attempt == self.MAX_ATTEMPTS:
                    raise LLMUnavailableError(
                        f"Gemini API 일시 오류({exc.code}, {self.MAX_ATTEMPTS}회 시도 후): {str(exc)[:200]}"
                    ) from exc
                # 429는 서버가 알려준 retryDelay를 따르고, 없으면 지수 백오프(15s, 30s, 60s)
                match = self._RETRY_DELAY_RE.search(str(exc))
                delay = float(match.group(1)) + 2.0 if match else self.BASE_DELAY_SECONDS * 2 ** (attempt - 1)
                print(f"[Gemini {exc.code}] {delay:.0f}초 후 재시도 ({attempt}/{self.MAX_ATTEMPTS - 1})")
                time.sleep(delay)
        raise AssertionError("unreachable")