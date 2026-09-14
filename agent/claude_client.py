"""LLM 호출 및 JSON 파싱 담당 모듈.

실제 Anthropic API를 호출해 조사 판단(JSON)을 받아온다.
loop.py는 이 클래스의 .reason(state, tool_registry) 인터페이스에만 의존하므로,
테스트 시에는 동일한 인터페이스를 가진 FakeLLMClient로 자유롭게 교체할 수 있다.
(tests/test_loop.py 참고)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from .prompts import build_system_prompt, build_user_prompt


class ClaudeDecisionError(Exception):
    """LLM 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생."""


class ClaudeClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5-20250929",  # 실제 사용 모델명으로 교체
        max_tokens: int = 2000,
    ) -> None:
        # anthropic 패키지는 실제 API 호출 시에만 필요하므로 지연 import한다.
        from anthropic import Anthropic

        self._client = Anthropic(api_key=api_key)  # api_key=None이면 ANTHROPIC_API_KEY 환경변수 사용
        self.model = model
        self.max_tokens = max_tokens

    def reason(self, state: Any, tool_registry: Any) -> Dict[str, Any]:
        """조사 루프(agent/loop.py) 전용: prompts.py의 investigation 프롬프트로 호출."""
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(state)
        return self.complete_json(system_prompt, user_prompt)

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다.
        seed_generation.py(경량 LLM triage)처럼 조사 루프가 아닌 다른 용도에서도 재사용한다.
        """
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")
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
            # trailing comma(",]"/",}") 같은 사소한 문법 오류만 고쳐서 한 번 더 시도한다.
            fixed = re.sub(r",\s*([\]}])", r"\1", cleaned)
            if fixed != cleaned:
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            raise ClaudeDecisionError(
                f"LLM 응답을 JSON으로 파싱하지 못했습니다: {exc}\n원본 응답:\n{text}"
            ) from exc