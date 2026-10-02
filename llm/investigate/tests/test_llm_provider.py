"""agent/llm_provider.py — INVESTIGATION_LLM_PROVIDER로 LLM 클라이언트 고르기(기본 Claude)와 모델 환경변수.

클라이언트 생성만 확인한다(API 호출 없음). 가짜 키를 쓰므로 네트워크가 필요 없다.
조사 에이전트는 INVESTIGATION_ 접두어 이름만 읽는다 — 옛 이름(LLM_PROVIDER, GEMINI_MODEL)은 무시한다.
"""
import pytest

from agent.llm_provider import build_llm_client


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in ("LLM_PROVIDER", "CLAUDE_MODEL", "CLAUDE_EFFORT", "GEMINI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    for role in ("INVESTIGATION", "MAPPING"):
        for name in ("LLM_PROVIDER", "CLAUDE_MODEL", "CLAUDE_EFFORT", "CLAUDE_REFUSAL_FALLBACK_MODEL",
                     "GEMINI_MODEL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(f"{role}_{name}", raising=False)
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
    assert "LLM_PROVIDER는 읽지 않습니다" in capsys.readouterr().out


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
    monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", "llama")
    with pytest.raises(ValueError, match="INVESTIGATION_LLM_PROVIDER"):
        build_llm_client()
    monkeypatch.setenv("MAPPING_LLM_PROVIDER", "llama")
    with pytest.raises(ValueError, match="MAPPING_LLM_PROVIDER"):
        build_llm_client("MAPPING")


def test_mapping_client_does_not_follow_investigation_settings(monkeypatch, capsys):
    # 2026-10-02: 매핑이 조사 LLM을 같이 써서, 조사 모델을 올리면 매핑도 같이 올라가던 문제
    pytest.importorskip("anthropic")
    from agent.claude_client import DEFAULT_MODELS, ClaudeClient

    monkeypatch.setenv("INVESTIGATION_CLAUDE_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("INVESTIGATION_CLAUDE_REFUSAL_FALLBACK_MODEL", "none")
    investigation, mapping = build_llm_client(), build_llm_client("MAPPING")
    assert isinstance(mapping, ClaudeClient) and mapping is not investigation
    assert investigation.model == "claude-sonnet-5" and investigation.refusal_fallback_model is None
    # 매핑 설정이 비어 있으면 경량 기본값(트리아지와 같은 등급) — 조사 설정을 따라가지 않는다
    assert mapping.model == DEFAULT_MODELS["MAPPING"] == "claude-haiku-4-5"
    assert mapping.refusal_fallback_model == "claude-sonnet-4-6"
    assert "(MAPPING, 모델 claude-haiku-4-5)" in capsys.readouterr().out

    monkeypatch.setenv("MAPPING_CLAUDE_MODEL", "claude-other")
    monkeypatch.setenv("MAPPING_ANTHROPIC_API_KEY", "mapping-secret")
    mapping = build_llm_client("MAPPING")
    assert mapping.model == "claude-other" and mapping.api_key_source == "MAPPING_ANTHROPIC_API_KEY"
    assert build_llm_client().api_key_source == "ANTHROPIC_API_KEY"  # 매핑 전용 키는 조사가 쓰지 않는다
    assert "secret" not in capsys.readouterr().out


def test_mapping_gemini_settings(monkeypatch):
    pytest.importorskip("google.genai")
    from agent.gemini_client import GeminiClient

    monkeypatch.setenv("MAPPING_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("MAPPING_GEMINI_MODEL", "gemini-mapping")
    client = build_llm_client("MAPPING")
    assert isinstance(client, GeminiClient) and client.model == "gemini-mapping" and client.role == "MAPPING"
    assert build_llm_client().__class__.__name__ == "ClaudeClient"  # 조사는 그대로 Claude
