"""GeminiClient 재시도 오프라인 테스트 — 실제 API 없이 가짜 generate_content로 확인한다.

- 일시 오류(503·429·연결 끊김)는 재시도하고, 재시도를 다 써도 계속되면 LLMUnavailableError
  (2026-09-28 EC2: 503 3회 연속 뒤 원래 예외가 그대로 올라가 main.py 전체가 멈췄다)
- 권한·요청 오류(401·400)는 재시도 없이 원래 예외 그대로
"""
from __future__ import annotations

import types

import pytest

errors = pytest.importorskip("google.genai.errors")

from agent.gemini_client import GeminiClient  # noqa: E402
from agent.llm_errors import LLMUnavailableError  # noqa: E402


def _client(monkeypatch, outcomes):
    """outcomes를 순서대로 돌려주거나(예외면 raise) 하는 가짜 generate_content를 단 클라이언트."""
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    calls = []

    def generate_content(**kwargs):
        calls.append(kwargs)
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    client = object.__new__(GeminiClient)
    client._client = types.SimpleNamespace(models=types.SimpleNamespace(generate_content=generate_content))
    client.model = "gemini-test"
    client.max_output_tokens, client.temperature = 8192, 0.0   # complete_json()이 설정을 만들 때 쓴다
    return client, calls


def _api_error(code):
    return errors.APIError(code, {"error": {"code": code, "message": "test", "status": "TEST"}})


@pytest.mark.parametrize("error", [_api_error(503), _api_error(429), ConnectionResetError("reset")])
def test_transient_error_after_all_retries_becomes_llm_unavailable(monkeypatch, error):
    client, calls = _client(monkeypatch, [error])
    with pytest.raises(LLMUnavailableError, match="Gemini"):
        client._generate_with_retry("prompt", config=None)
    assert len(calls) == GeminiClient.MAX_ATTEMPTS


def test_transient_error_then_success_returns_response(monkeypatch):
    client, calls = _client(monkeypatch, [_api_error(503), "ok"])
    assert client._generate_with_retry("prompt", config=None) == "ok"
    assert len(calls) == 2


def _response(text, finish="STOP"):
    usage = types.SimpleNamespace(prompt_token_count=1000, cached_content_token_count=300,
                                  candidates_token_count=150, thoughts_token_count=50)
    return types.SimpleNamespace(text=text, usage_metadata=usage,
                                 candidates=[types.SimpleNamespace(finish_reason=finish)])


def test_usage_is_recorded_like_claude(monkeypatch):
    # 모델 비교용(main.py results/llm_usage): Claude·GPT와 같은 키, 입력은 캐시 제외, 생각 토큰은 출력에 포함
    client, _ = _client(monkeypatch, [_response('{"a": 1}'), _response('{"b": 2}')])
    assert client.complete_json("JSON", "x") == {"a": 1}
    client.complete_json("JSON", "y")
    totals = client.usage_totals
    assert totals["calls"] == 2 and totals["input_tokens"] == 1400 and totals["cache_read_input_tokens"] == 600
    assert totals["output_tokens"] == 400 and totals["reasoning_tokens"] == 100


def test_safety_block_counts_as_refusal(monkeypatch):
    client, _ = _client(monkeypatch, [_response(None, finish="FinishReason.SAFETY")])
    with pytest.raises(Exception, match="refusal"):
        client.complete_json("JSON", "x")
    assert client.usage_totals["refusals"] == 1


@pytest.mark.parametrize("code", [400, 401, 403])
def test_config_errors_are_raised_without_retry(monkeypatch, code):
    client, calls = _client(monkeypatch, [_api_error(code)])
    with pytest.raises(errors.APIError):
        client._generate_with_retry("prompt", config=None)
    assert len(calls) == 1
