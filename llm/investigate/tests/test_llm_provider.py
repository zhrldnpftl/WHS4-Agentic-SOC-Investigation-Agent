"""agent/llm_provider.py — LLM_PROVIDER로 LLM 클라이언트 고르기(기본 Claude)와 모델 환경변수.

클라이언트 생성만 확인한다(API 호출 없음). 가짜 키를 쓰므로 네트워크가 필요 없다.
"""
import pytest

from agent.llm_provider import build_llm_client


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in ("LLM_PROVIDER", "CLAUDE_MODEL", "CLAUDE_EFFORT", "GEMINI_MODEL", "INVESTIGATION_ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")


@pytest.mark.parametrize("value", [None, "", "anthropic", " Anthropic "])
def test_default_provider_is_claude(monkeypatch, value):
    pytest.importorskip("anthropic")
    from agent.claude_client import DEFAULT_MODEL, ClaudeClient

    if value is not None:
        monkeypatch.setenv("LLM_PROVIDER", value)
    client = build_llm_client()
    assert isinstance(client, ClaudeClient) and client.model == DEFAULT_MODEL


def test_gemini_model_from_env(monkeypatch):
    pytest.importorskip("google.genai")
    from agent.gemini_client import DEFAULT_MODEL, GeminiClient

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    assert build_llm_client().model == DEFAULT_MODEL
    # 특정 모델이 과부하(503)일 때 .env만 바꿔 다른 모델로 돌린다(2026-09-28 EC2)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-other")
    client = build_llm_client()
    assert isinstance(client, GeminiClient) and client.model == "gemini-other"


def test_unknown_provider_is_clear_error(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    with pytest.raises(ValueError, match="LLM_PROVIDER"):
        build_llm_client()
