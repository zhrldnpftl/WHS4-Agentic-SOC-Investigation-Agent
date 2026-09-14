"""Gemini API를 사용하는 LLM 클라이언트.

claude_client.py의 ClaudeClient(Anthropic)와 동일하게 .reason(state, tool_registry) 인터페이스를
제공하므로, agent/loop.py의 InvestigationAgent(llm_client=...)에 이 클래스를 그대로
넣어 쓸 수 있다. 즉 Claude ↔ Gemini는 이 클라이언트만 교체하면 된다.

사전 준비:
    pip install google-genai
    export GEMINI_API_KEY=...   (Google AI Studio에서 발급한 무료 티어 키도 가능)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional

from .prompts import build_system_prompt, build_user_prompt


class GeminiDecisionError(Exception):
    """Gemini 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생."""


class GeminiClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.5-flash-lite",  # 무료 티어 실습에서 지정한 모델
        max_output_tokens: int = 2000,
        temperature: float = 0.2,
    ) -> None:
        # google-genai 패키지는 실제 호출 시에만 필요하므로 지연 import한다.
        from google import genai

        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "GEMINI_API_KEY가 설정되지 않았습니다. .env 파일에 "
                "GEMINI_API_KEY=발급받은_키 를 추가하거나 GeminiClient(api_key=...)로 "
                "직접 전달하십시오."
            )

        self._client = genai.Client(api_key=resolved_key)
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature

    def reason(self, state: Any, tool_registry: Any) -> Dict[str, Any]:
        """조사 루프(agent/loop.py) 전용: prompts.py의 investigation 프롬프트로 호출."""
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(state)
        return self.complete_json(system_prompt, user_prompt)

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다.
        seed_generation.py(경량 LLM triage)처럼 조사 루프가 아닌 다른 용도에서도 재사용한다.
        """
        from google.genai import types

        response = self._client.models.generate_content(
            model=self.model,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",  # Gemini가 JSON만 반환하도록 강제
                max_output_tokens=self.max_output_tokens,
                temperature=self.temperature,
            ),
        )
        text = response.text
        if not text:
            raise GeminiDecisionError(
                f"Gemini가 빈 응답을 반환했습니다. (finish_reason 등을 확인하십시오)\n원본 응답: {response}"
            )
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            # Gemini가 response_mime_type="application/json"을 줘도 가끔 배열/객체
            # 마지막 항목 뒤에 trailing comma(",]"/",}")를 남길 때가 있다. 표준 JSON
            # 파서는 이걸 문법 오류로 거부하니, 딱 그 패턴만 제거하고 한 번 더 시도한다.
            fixed = re.sub(r",\s*([\]}])", r"\1", cleaned)
            if fixed != cleaned:
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass  # 고쳐도 안 되면 원래 예외를 그대로 보고한다
            raise GeminiDecisionError(
                f"Gemini 응답을 JSON으로 파싱하지 못했습니다: {exc}\n원본 응답:\n{text}"
            ) from exc