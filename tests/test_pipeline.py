"""run_investigation_pipeline(agent/pipeline.py) 통합 테스트.

실제 AWS/LLM 없이, raw log ingestion용 가짜 S3 + seed 생성/조사 판단용 가짜 LLM
클라이언트를 하나로 묶어서 전체 파이프라인(raw log -> seed 후보 -> 우선순위 ->
InvestigationAgent 반복 실행)이 끝까지 도는지 확인한다.
"""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    def __init__(self, objects_by_prefix: Dict[str, Dict[str, bytes]]) -> None:
        self._objects_by_prefix = objects_by_prefix

    def get_paginator(self, name: str):
        def _paginate(**kwargs: Any):
            objects = self._objects_by_prefix.get(kwargs["Prefix"], {})
            return [{"Contents": [{"Key": k} for k in objects]}]

        p = types.SimpleNamespace()
        p.paginate = _paginate
        return p

    def get_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        for objects in self._objects_by_prefix.values():
            if Key in objects:
                return {"Body": _FakeBody(objects[Key])}
        raise KeyError(Key)


def _ndjson(records: List[Dict[str, Any]]) -> bytes:
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in records).encode("utf-8")


class _FakeCombinedLLMClient:
    """seed 생성(complete_json)과 조사 루프(reason)를 둘 다 흉내내는 가짜 클라이언트.

    seed 생성은 1번만 호출되고(파이프라인 진입 시), 조사 루프는 seed 하나당 여러 번
    호출되므로 reason()은 항상 "즉시 종료" 결정을 돌려주는 단순한 형태로 둔다
    (Agent Loop 자체 검증은 tests/test_loop.py가 이미 충분히 하고 있으므로, 여기서는
    "파이프라인이 seed를 우선순위대로 InvestigationAgent에 잘 넘기는지"만 본다).
    """

    def __init__(self) -> None:
        self.reason_call_count = 0

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        return {
            "candidates": [
                {
                    "incident_id": "INC-LOW",
                    "trigger_time": "2026-09-09T10:00:00Z",
                    "trigger_description": "낮은 우선순위 후보",
                    "confidence_initial": 0.4,
                    "priority": 2,
                    "host": "web-01",
                },
                {
                    "incident_id": "INC-HIGH",
                    "trigger_time": "2026-09-09T10:05:00Z",
                    "trigger_description": "높은 우선순위 후보",
                    "confidence_initial": 0.6,
                    "priority": 1,
                    "host": "web-01",
                },
            ]
        }

    def reason(self, state: Any, tool_registry: Any) -> Dict[str, Any]:
        self.reason_call_count += 1
        return {
            "facts": [],
            "hypotheses": [],
            "unknowns": [],
            "new_evidence": [],
            "next_action": "terminate",
            "tool_call": None,
            "termination_reason": "no_more_evidence",
            "attack_timeline": [],
            "final_verdict": {
                "verdict": "INCONCLUSIVE",
                "confidence": state.current_confidence,
                "severity": "LOW",
                "attack_type": "unknown",
                "affected_systems": [],
                "summary": "테스트용 즉시 종료",
            },
            "investigation_notes": [],
        }


def test_pipeline_runs_seeds_in_priority_order() -> None:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    recent_epoch = int((now - timedelta(minutes=2)).timestamp())
    audit_prefix = f"raw/source_type=auditd/host=web-01/dt={today}/"

    audit_text = f'type=SYSCALL msg=audit({recent_epoch}.100:9001): pid=3812 uid=33 comm="sh" key="susp_exec"\n'.encode(
        "utf-8"
    )
    fake_s3 = _FakeS3Client({audit_prefix: {"audit.log": audit_text}})
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service_name, **kwargs: fake_s3  # type: ignore[attr-defined]
    sys.modules["boto3"] = fake_boto3
    sys.modules.pop("agent.raw_log_ingestion", None)
    sys.modules.pop("agent.pipeline", None)

    try:
        from agent.pipeline import run_investigation_pipeline
        from agent.raw_log_ingestion import fetch_recent_raw_logs
        from agent.seed_generation import SeedGenerator
        from agent.tools import build_default_registry

        llm = _FakeCombinedLLMClient()
        registry = build_default_registry()  # 목업 도구로 충분 (조사 루프는 즉시 종료하므로 도구 호출 없음)

        # --- 눈으로 확인용: seed 후보가 몇 개 뽑혔고, 우선순위가 어떻게 매겨졌는지 ---
        raw_logs = fetch_recent_raw_logs(host="web-01", minutes=10)
        print(f"\n[1단계] raw log {len(raw_logs)}건 수집됨")

        seeds = SeedGenerator(llm).generate(raw_logs, host="web-01")
        print(f"[2단계] seed 후보 {len(seeds)}개 생성, 우선순위 정렬 결과:")
        for s in seeds:
            print(f"  priority={s.get('priority')} | {s['incident_id']} | {s.get('trigger_description')}")

        # --- 실제 검증: 파이프라인이 우선순위 순서대로 도구(InvestigationAgent)에 넘기는지 ---
        results = run_investigation_pipeline(host="web-01", llm_client=llm, tool_registry=registry, minutes=10)

        print("[3단계] InvestigationAgent에 실제로 넘겨져 조사된 순서:")
        for i, r in enumerate(results, start=1):
            print(f"  {i}순위 조사 -> {r['incident_id']} (최종 verdict={r['final_verdict']['verdict']})")

        assert [r["incident_id"] for r in results] == ["INC-HIGH", "INC-LOW"], (
            "우선순위(priority=1)인 INC-HIGH가 먼저 조사되어야 한다"
        )
        assert llm.reason_call_count == 2, "seed 2개 각각에 대해 조사 루프가 최소 1번씩 돌아야 한다"
        print("[PASS] test_pipeline_runs_seeds_in_priority_order")
    finally:
        sys.modules.pop("boto3", None)
        sys.modules.pop("agent.raw_log_ingestion", None)
        sys.modules.pop("agent.pipeline", None)


if __name__ == "__main__":
    test_pipeline_runs_seeds_in_priority_order()
    print("\n모든 테스트 통과.")