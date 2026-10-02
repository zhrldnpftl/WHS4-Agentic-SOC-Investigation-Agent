"""LLM 클라이언트 선택 — 역할(조사/매핑)마다 <역할>_LLM_PROVIDER로 Claude/Gemini 중 하나를 만든다.

역할
  main.py, ATT&CK 매핑(attack_mapping/cli.py), 반복 측정(tests/test_consistency.py)이 같은 규칙으로 LLM을 고르게 한다.
  역할은 두 가지다(agent/settings.py).
    INVESTIGATION  조사 에이전트 — 설정 INVESTIGATION_*, 기본 모델 claude-sonnet-5(고성능)
    MAPPING        ATT&CK 매핑   — 설정 MAPPING_*,       기본 모델 claude-haiku-4-5(경량, 트리아지와 같은 등급)
  역할마다 객체를 따로 만들므로 조사 모델을 바꿔도 매핑 모델은 그대로다(2026-10-02 분리 — 그전에는 main.py가
  조사용 객체를 매핑에 그대로 넘겨, 조사 모델을 올리면 매핑도 같이 올라갔다).
  provider 기본값은 anthropic(Claude)이다(2026-09-28 전환 — Gemini 무료 티어의 503·일일 한도로 EC2 실행이 계속 멈췄다).
  옛 이름 LLM_PROVIDER는 읽지 않는다.

누가 부르나
  [3] main.py main()                    → build_llm_client(), build_llm_client(MAPPING)
  attack_mapping/cli.py process_file()  → build_llm_client(MAPPING)   (매핑 CLI를 따로 돌릴 때)
  tests/test_consistency.py             → build_llm_client()

무엇을 부르나
  agent/claude_client.py ClaudeClient(role)   <역할>_ANTHROPIC_API_KEY → 없으면 ANTHROPIC_API_KEY,
                                              모델 <역할>_CLAUDE_MODEL
  agent/gemini_client.py GeminiClient(role)   <역할>_GEMINI_API_KEY → 없으면 GEMINI_API_KEY,
                                              모델 <역할>_GEMINI_MODEL(기본 gemini-3.5-flash-lite)
  agent/gpt_client.py    GPTClient(role)      <역할>_OPENAI_API_KEY → 없으면 OPENAI_API_KEY,
                                              모델 <역할>_OPENAI_MODEL(기본값 없음 — 반드시 지정). provider 이름 openai(별칭 gpt)
"""

from __future__ import annotations

from typing import Any

from .settings import INVESTIGATION, role_setting

DEFAULT_PROVIDER = "anthropic"
PROVIDERS = ("anthropic", "gemini", "openai")
PROVIDER_ALIASES = {"gpt": "openai"}


def build_llm_client(role: str = INVESTIGATION) -> Any:
    """<role>_LLM_PROVIDER 환경변수(비어 있으면 anthropic)로 그 역할의 LLM 클라이언트를 만든다."""
    provider = (role_setting(role, "LLM_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    provider = PROVIDER_ALIASES.get(provider, provider)
    if provider == "openai":
        from .gpt_client import GPTClient

        return GPTClient(role=role)  # <역할>_OPENAI_API_KEY 또는 OPENAI_API_KEY, <역할>_OPENAI_MODEL 필요
    if provider == "anthropic":
        from .claude_client import ClaudeClient

        return ClaudeClient(role=role)  # <역할>_ANTHROPIC_API_KEY 또는 ANTHROPIC_API_KEY 필요
    if provider == "gemini":
        from .gemini_client import GeminiClient

        return GeminiClient(role=role)  # <역할>_GEMINI_API_KEY 또는 GEMINI_API_KEY 필요 (무료 티어 가능)
    raise ValueError(
        f"알 수 없는 {role}_LLM_PROVIDER입니다: {provider} ({' 또는 '.join(PROVIDERS)}만 지원)")
