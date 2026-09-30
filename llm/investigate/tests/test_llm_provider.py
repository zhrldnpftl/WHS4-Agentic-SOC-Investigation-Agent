"""agent/llm_provider.py — INVESTIGATION_LLM_PROVIDER로 LLM 클라이언트 고르기(기본 Claude)와 모델 환경변수.

클라이언트 생성만 확인한다(API 호출 없음). 가짜 키를 쓰므로 네트워크가 필요 없다.
조사 에이전트는 INVESTIGATION_ 접두어 이름만 읽는다 — 옛 이름(LLM_PROVIDER, GEMINI_MODEL)은 무시한다.
"""
import pytest

from agent.llm_provider import build_llm_client


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in ("LLM_PROVIDER", "CLAUDE_MODEL", "CLAUDE_EFFORT", "GEMINI_MODEL",
                 "INVESTIGATION_LLM_PROVIDER", "INVESTIGATION_CLAUDE_MODEL", "INVESTIGATION_CLAUDE_EFFORT",
                 "INVESTIGATION_GEMINI_MODEL", "INVESTIGATION_ANTHROPIC_API_KEY", "INVESTIGATION_GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr("agent.settings._notified", set())


@pytest.mark.parametrize("value", [None, "", "anthropic", " Anthropic "])
def test_default_provider_is_claude(monkeypatch, value):
    pytest.importorskip("anthropic")
    from agent.claude_client import DEFAULT_MODEL, ClaudeClient

    if value is not None:
        monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", value)
    client = build_llm_client()
    assert isinstance(client, ClaudeClient) and client.model == DEFAULT_MODEL


def test_legacy_llm_provider_is_ignored(monkeypatch, capsys):
    # 옛 이름 LLM_PROVIDER=gemini가 루트 .env에 남아 있어도 조사 에이전트는 기본값(Claude)을 쓴다
    pytest.importorskip("anthropic")
    from agent.claude_client import ClaudeClient

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    assert isinstance(build_llm_client(), ClaudeClient)
    assert "LLM_PROVIDER는 조사 에이전트에서 읽지 않습니다" in capsys.readouterr().out


def test_gemini_model_from_env(monkeypatch):
    pytest.importorskip("google.genai")
    from agent.gemini_client import DEFAULT_MODEL, GeminiClient

    monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", "gemini")
    assert build_llm_client().model == DEFAULT_MODEL
    # 특정 모델이 과부하(503)일 때 .env만 바꿔 다른 모델로 돌린다(2026-09-28 EC2)
    monkeypatch.setenv("INVESTIGATION_GEMINI_MODEL", "gemini-other")
    monkeypatch.setenv("GEMINI_MODEL", "legacy-model")  # 옛 이름은 무시
    client = build_llm_client()
    assert isinstance(client, GeminiClient) and client.model == "gemini-other"


def test_gemini_key_prefers_investigation_key(monkeypatch, capsys):
    pytest.importorskip("google.genai")
    monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("INVESTIGATION_GEMINI_API_KEY", "inv-secret")
    client = build_llm_client()
    assert client.api_key_source == "INVESTIGATION_GEMINI_API_KEY"
    out = capsys.readouterr().out
    assert "API 키: INVESTIGATION_GEMINI_API_KEY 사용" in out and "secret" not in out


def test_unknown_provider_is_clear_error(monkeypatch):
    monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", "openai")
    with pytest.raises(ValueError, match="INVESTIGATION_LLM_PROVIDER"):
        build_llm_client()
