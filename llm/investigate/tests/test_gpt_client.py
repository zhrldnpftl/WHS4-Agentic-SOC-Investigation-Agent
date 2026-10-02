"""GPTClient 오프라인 테스트 — 가짜 openai 모듈로 실제 API 없이 확인한다.

- 조사 루프 인자를 받아 InvestigationAgent가 끝까지 도는지, ATT&CK 매핑용 complete_json
- 호출 설정: JSON 모드, max_completion_tokens 16000, temperature 없음, reasoning_effort는 설정할 때만
- 보내는 인자가 설치된 실제 openai SDK의 chat.completions.create()가 받는 인자인지
- 잘림(length)·거절(refusal)·빈 응답은 GPTDecisionError, 토큰 사용량(캐시 제외 입력)
- 일시 오류는 LLMUnavailableError, 잔액 부족(insufficient_quota)·권한 오류는 그대로
- 역할별 키·모델(INVESTIGATION_/MAPPING_), 모델 미설정은 설정 오류
"""
from __future__ import annotations

import inspect
import json
import sys
import types
from typing import Any, Dict, List

import pytest

from agent.gpt_client import GPTClient, GPTDecisionError
from agent.llm_errors import LLMUnavailableError
from agent.llm_provider import build_llm_client
from agent.loop import InvestigationAgent
from agent.tools import build_default_registry


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for role in ("INVESTIGATION", "MAPPING"):
        for name in ("LLM_PROVIDER", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT"):
            monkeypatch.delenv(f"{role}_{name}", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("agent.settings._notified", set())


class FakeStatusError(Exception):
    def __init__(self, status_code: int, code: str = None) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code
        self.code = code


class FakeConnectionError(Exception):
    pass


class _FakeCompletions:
    def __init__(self, replies: List[Any]) -> None:
        self.replies = replies
        self.calls: List[Dict[str, Any]] = []

    def create(self, **kwargs: Any):
        self.calls.append(kwargs)
        reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
        if isinstance(reply, Exception):
            raise reply
        usage = types.SimpleNamespace(
            prompt_tokens=1000, completion_tokens=200,
            prompt_tokens_details=types.SimpleNamespace(cached_tokens=600),
            completion_tokens_details=types.SimpleNamespace(reasoning_tokens=150))
        message = types.SimpleNamespace(content=reply.get("text"), refusal=reply.get("refusal"))
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=message, finish_reason=reply.get("finish_reason", "stop"))],
            usage=usage)


def _install_fake_openai(monkeypatch, replies):
    created = {}

    class FakeOpenAI:
        def __init__(self, api_key=None, max_retries=None):
            created["api_key"], created["max_retries"] = api_key, max_retries
            self.chat = types.SimpleNamespace(completions=_FakeCompletions(replies))
            created["completions"] = self.chat.completions

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(
        OpenAI=FakeOpenAI, APIStatusError=FakeStatusError, APIConnectionError=FakeConnectionError))
    return created


def _decision(**overrides):
    base = {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "attack_timeline": [],
            "investigation_notes": [], "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log",
                          "args": {"host": "web-01", "start_time": "2026-09-24T00:00:00Z",
                                   "end_time": "2026-09-24T01:00:00Z"}},
            "termination_reason": None, "final_verdict": None}
    base.update(overrides)
    return {"text": json.dumps(base, ensure_ascii=False)}


SEED = {"incident_id": "INC-GPT", "host": "web-01", "trigger_time": "2026-09-24T00:30:00Z",
        "trigger_description": "SSH 로그인 실패", "confidence_initial": 0.6}


def test_gpt_client_runs_investigation_loop_with_json_mode(monkeypatch):
    verdict = {"verdict": "FALSE_POSITIVE", "confidence": 0.8, "severity": "LOW", "attack_type": "x",
               "affected_systems": [], "summary": "s", "reasoning": "r"}
    terminate = _decision(next_action="terminate", tool_call=None,
                          termination_reason="no_more_evidence", final_verdict=verdict)
    created = _install_fake_openai(monkeypatch, [_decision(), terminate])
    client = GPTClient(api_key="test-key", model="gpt-test")
    result = InvestigationAgent(client, build_default_registry()).run(SEED)

    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    call = created["completions"].calls[0]
    assert call["model"] == "gpt-test" and call["response_format"] == {"type": "json_object"}
    assert call["max_completion_tokens"] == 16000
    assert "temperature" not in call and "reasoning_effort" not in call
    assert [m["role"] for m in call["messages"]] == ["system", "user"]
    assert "JSON" in call["messages"][0]["content"]   # JSON 모드의 조건: 프롬프트에 JSON이라는 말
    assert created["max_retries"] == GPTClient.MAX_RETRIES
    # input_tokens는 캐시에서 읽은 600을 뺀 400 (Claude usage와 같은 뜻)
    assert client.usage_totals["calls"] == 2
    assert client.usage_totals["input_tokens"] == 800 and client.usage_totals["cache_read_input_tokens"] == 1200
    assert client.usage_totals["output_tokens"] == 400 and client.usage_totals["reasoning_tokens"] == 300


def test_request_arguments_are_accepted_by_installed_sdk():
    openai = pytest.importorskip("openai")
    from openai.resources.chat.completions import Completions

    params = inspect.signature(Completions.create).parameters
    for name in ("model", "messages", "response_format", "max_completion_tokens", "reasoning_effort"):
        assert name in params, f"설치된 openai {openai.__version__}가 {name} 인자를 받지 않음"
    assert all(hasattr(openai, n) for n in ("OpenAI", "APIStatusError", "APIConnectionError"))


def test_complete_json_for_mapping_and_reasoning_effort(monkeypatch):
    created = _install_fake_openai(monkeypatch, [{"text": '{"technique_id": "T1505.003"}'}])
    monkeypatch.setenv("MAPPING_OPENAI_MODEL", "gpt-mini-test")
    monkeypatch.setenv("MAPPING_OPENAI_REASONING_EFFORT", "Low")
    client = GPTClient(api_key="k", role="MAPPING")
    assert client.complete_json("JSON 객체 하나만 반환", "데이터") == {"technique_id": "T1505.003"}
    call = created["completions"].calls[0]
    assert call["model"] == "gpt-mini-test" and call["reasoning_effort"] == "low"


@pytest.mark.parametrize("reply,match", [
    ({"text": '{"a": 1', "finish_reason": "length"}, "출력 한도"),
    ({"text": None, "refusal": "I can't help with that"}, "거절"),
    ({"text": "", "finish_reason": "content_filter"}, "거절"),
    ({"text": "   "}, "빈 응답"),
])
def test_unusable_replies_are_decision_errors(monkeypatch, reply, match):
    _install_fake_openai(monkeypatch, [reply])
    client = GPTClient(api_key="k", model="m")
    with pytest.raises(GPTDecisionError, match=match):
        client.complete_json("JSON", "x")
    assert client.usage_totals["refusals"] == (1 if match == "거절" else 0)


def test_transient_errors_and_quota(monkeypatch):
    for error in (FakeStatusError(429), FakeStatusError(503), FakeConnectionError("reset")):
        _install_fake_openai(monkeypatch, [error])
        with pytest.raises(LLMUnavailableError):
            GPTClient(api_key="k", model="m").complete_json("JSON", "x")
    # 잔액 부족은 기다려도 안 풀린다 — 그대로 올려 실행을 멈춘다(사건마다 미완료로 쌓이지 않게)
    for error in (FakeStatusError(429, code="insufficient_quota"), FakeStatusError(401)):
        _install_fake_openai(monkeypatch, [error])
        with pytest.raises(FakeStatusError):
            GPTClient(api_key="k", model="m").complete_json("JSON", "x")


def test_role_settings_and_required_model(monkeypatch, capsys):
    _install_fake_openai(monkeypatch, [{"text": "{}"}])
    monkeypatch.setenv("OPENAI_API_KEY", "shared-secret")
    with pytest.raises(ValueError, match="INVESTIGATION_OPENAI_MODEL"):
        GPTClient()   # 모델 기본값 없음
    monkeypatch.setenv("INVESTIGATION_LLM_PROVIDER", "gpt")   # 별칭
    monkeypatch.setenv("INVESTIGATION_OPENAI_MODEL", "gpt-big")
    monkeypatch.setenv("MAPPING_OPENAI_API_KEY", "mapping-secret")
    investigation = build_llm_client()
    assert isinstance(investigation, GPTClient) and investigation.model == "gpt-big"
    assert investigation.api_key_source == "OPENAI_API_KEY"
    # 매핑은 MAPPING_ 설정만 본다 — 조사 모델(gpt-big)을 따라가지 않고, 매핑 전용 키를 쓴다
    monkeypatch.setenv("MAPPING_LLM_PROVIDER", "openai")
    with pytest.raises(ValueError, match="MAPPING_OPENAI_MODEL"):
        build_llm_client("MAPPING")
    monkeypatch.setenv("MAPPING_OPENAI_MODEL", "gpt-mini")
    mapping = build_llm_client("MAPPING")
    assert mapping.model == "gpt-mini" and mapping.api_key_source == "MAPPING_OPENAI_API_KEY"
    out = capsys.readouterr().out
    assert "[GPT] API 키: OPENAI_API_KEY 사용 (INVESTIGATION, 모델 gpt-big)" in out and "secret" not in out


def test_missing_key_is_clear_error(monkeypatch):
    _install_fake_openai(monkeypatch, [{"text": "{}"}])
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        GPTClient(model="m")
