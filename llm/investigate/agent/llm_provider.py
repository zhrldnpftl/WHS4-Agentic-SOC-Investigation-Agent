"""LLM 클라이언트 선택 — INVESTIGATION_LLM_PROVIDER 환경변수로 Claude/Gemini 중 하나를 만든다.

역할
  main.py와 반복 측정(tests/test_consistency.py)이 같은 규칙으로 LLM을 고르게 한다.
  기본값은 anthropic(Claude)이다(2026-09-28 전환 — Gemini 무료 티어의 503·일일 한도로 EC2 실행이 계속 멈췄다).
  Gemini는 INVESTIGATION_LLM_PROVIDER=gemini로 쓸 수 있다. 옛 이름 LLM_PROVIDER는 읽지 않는다(agent/settings.py).

누가 부르나
  [3] main.py main()                    → build_llm_client()
  tests/test_consistency.py             → build_llm_client()

무엇을 부르나
  agent/claude_client.py ClaudeClient()   INVESTIGATION_ANTHROPIC_API_KEY → 없으면 ANTHROPIC_API_KEY,
                                          모델 INVESTIGATION_CLAUDE_MODEL(기본 claude-sonnet-5)
  agent/gemini_client.py GeminiClient()   INVESTIGATION_GEMINI_API_KEY → 없으면 GEMINI_API_KEY,
                                          모델 INVESTIGATION_GEMINI_MODEL(기본 gemini-3.5-flash-lite)
"""

from __future__ import annotations

from typing import Any

from .settings import investigation_setting

DEFAULT_PROVIDER = "anthropic"
PROVIDERS = ("anthropic", "gemini")


def build_llm_client() -> Any:
    """INVESTIGATION_LLM_PROVIDER 환경변수(비어 있으면 anthropic)로 LLM 클라이언트를 만든다."""
    provider = (investigation_setting("LLM_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    if provider == "anthropic":
        from .claude_client import ClaudeClient

        return ClaudeClient()  # INVESTIGATION_ANTHROPIC_API_KEY 또는 ANTHROPIC_API_KEY 필요
    if provider == "gemini":
        from .gemini_client import GeminiClient

        return GeminiClient()  # INVESTIGATION_GEMINI_API_KEY 또는 GEMINI_API_KEY 필요 (무료 티어 가능)
    raise ValueError(
        f"알 수 없는 INVESTIGATION_LLM_PROVIDER입니다: {provider} ({' 또는 '.join(PROVIDERS)}만 지원)")
