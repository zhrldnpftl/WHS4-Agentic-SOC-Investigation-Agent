"""main.py [46]: 조사 결과 JSON 저장 직후 ATT&CK 매핑까지 이어지는지 (API 키 불필요).

조사 결과는 agent/report.py의 build_investigation_result()로 만들어, 실제 main.py가
저장하는 것과 같은 형식으로 어택 매핑 팀 규칙(ALL_RULES)을 통과시킨다.
2026-09-28: main.py가 1차 탐지 사건 파일을 받고 텍스트 보고서를 만들지 않는 구조로 바뀐 뒤
매핑 연결을 다시 붙였다. 콘솔에는 사건별 매핑 상태 한 줄(mapping_summary)만 나온다.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import main
from attack_mapping.cli import process_file as process_saved_file
from attack_mapping.rules import ALL_RULES
from agent.models import AgentState, Evidence
from agent.report import build_investigation_result


def investigation(verdict="THREAT_CONFIRMED", incident_id="INC-MAIN-01"):
    state = AgentState(incident_id=incident_id, seed={"raw_refs": ["web.log:10", "audit.log:3"]})
    state.raw_refs = ["web.log:10", "audit.log:3"]
    state.raw_ref_locations = {ref: [f"/var/log/{ref}"] for ref in state.raw_refs}
    state.add_evidence(Evidence(
        evidence_id="EVID-001", sequence=1, time="2026-09-27T01:00:05Z", layer="web",
        event_type="http_request", description="203.0.113.7이 shell.php에 cmd= 파라미터로 요청",
        source_log="web.log", raw_refs=["web.log:10"],
    ))
    state.add_evidence(Evidence(
        evidence_id="EVID-002", sequence=2, time="2026-09-27T01:02:00Z", layer="audit",
        event_type="process_exec", description="www-data가 /dev/tcp/203.0.113.7/4444로 역방향 셸 실행",
        source_log="audit.log", raw_refs=["audit.log:3"],
    ))
    return build_investigation_result(
        state, "no_more_evidence", {"verdict": verdict, "attack_type": "웹셸"}, f"INV-{incident_id}",
    )


def test_saved_investigation_is_mapped_into_kill_chain_and_final_report(tmp_path):
    source = investigation()
    saved = main.save_investigation_result(source, str(tmp_path))
    out_dir = tmp_path / "attack_mapping"

    mapping = main.run_attack_mapping(saved, str(out_dir), rule_baseline=True)

    assert mapping["mapping_status"] == "mapped"
    assert [step["technique_id"] for step in mapping["kill_chain"]] == ["T1505.003", "T1059.004"]
    assert sorted(p.name for p in out_dir.iterdir()) == [
        "INC-MAIN-01_attack_mapping.json", "INC-MAIN-01_final_report.json"]
    assert sorted(mapping["output_paths"]) == sorted(str(p) for p in out_dir.iterdir())
    report = json.loads((out_dir / "INC-MAIN-01_final_report.json").read_text(encoding="utf-8"))
    assert {k: v for k, v in report.items() if k != "attack_mapping"} == source
    assert report["attack_mapping"]["kill_chain"] == mapping["kill_chain"]

    assert main.mapping_summary(mapping) == "ATT&CK 매핑: mapped (기법 2개: T1505.003, T1059.004)"


def test_false_positive_is_saved_as_not_applicable(tmp_path):
    saved = main.save_investigation_result(investigation("FALSE_POSITIVE"), str(tmp_path))
    mapping = main.run_attack_mapping(saved, str(tmp_path / "attack_mapping"))
    assert mapping["mapping_status"] == "not_applicable"
    assert mapping["kill_chain"] == []
    assert len(mapping["output_paths"]) == 2
    assert main.mapping_summary(mapping) == "ATT&CK 매핑: not_applicable (기법 0개)"


def test_reinvestigated_incident_keeps_earlier_mapping_files(tmp_path):
    out_dir = tmp_path / "attack_mapping"
    first = main.run_attack_mapping(main.save_investigation_result(investigation(), str(tmp_path)), str(out_dir), rule_baseline=True)
    second = main.run_attack_mapping(main.save_investigation_result(investigation(), str(tmp_path)), str(out_dir), rule_baseline=True)
    assert len(list(out_dir.iterdir())) == 4
    assert all("__2" not in path for path in first["output_paths"])
    assert all("__2" in path for path in second["output_paths"])


def test_verified_empty_result_evidence_keeps_verdict_mapping(tmp_path):
    # EC2 XML-RPC 사건처럼 기법이 판정 문구로만 붙는 경우, "0건 → 활동 없음" 증거 하나 때문에
    # provenance가 incomplete면 판정 문구 매칭이 꺼져 기법이 0개가 된다. 확인된 0건 증거는 막지 않는다.
    def run(empty_result_call):
        state = AgentState(incident_id="INC-XMLRPC", seed={"raw_refs": ["web.log:1"]})
        state.raw_refs = ["web.log:1"]
        state.add_evidence(Evidence(
            evidence_id="EVID-101", sequence=1, time="2026-09-27T04:31:11Z", layer="web", event_type="web_access",
            description="/xmlrpc.php 경로로 POST 요청 150건", source_log="web.log", raw_refs=["web.log:1"]))
        state.add_evidence(Evidence(
            evidence_id="EVID-102", sequence=2, time=None, layer="network", event_type="none",
            description="network 조회 0건 — 추가 통신 없음", source_log="", empty_result_call=empty_result_call))
        source = build_investigation_result(
            state, "no_more_evidence", {"verdict": "THREAT_CONFIRMED", "attack_type": "웹 인증 무차별 대입"}, "INV-X")
        saved = main.save_investigation_result(source, str(tmp_path))
        return main.run_attack_mapping(saved, str(tmp_path / "attack_mapping"), rule_baseline=True)

    verified = run(2)
    assert verified["provenance_status"] == "passed" and verified["mapping_status"] == "mapped"
    assert [t["technique_id"] for t in verified["techniques"]] == ["T1110"]
    unverified = run(None)
    assert unverified["provenance_status"] == "incomplete"
    assert unverified["mapping_status"] == "no_techniques_matched"


def test_mapping_failure_does_not_stop_main(tmp_path, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("[]", encoding="utf-8")
    out_dir = tmp_path / "attack_mapping"
    assert main.run_attack_mapping(str(broken), str(out_dir)) is None
    assert "매핑 실패" in capsys.readouterr().out
    assert not out_dir.exists() or not list(out_dir.iterdir())
    assert main.mapping_summary(None) == "ATT&CK 매핑: 실패(위 안내 참고)"


def test_unexpected_mapping_failure_keeps_saved_investigation(tmp_path, monkeypatch):
    saved = main.save_investigation_result(investigation(), str(tmp_path))

    def broken_mapping(*args, **kwargs):
        raise TypeError("mapping output cannot be serialized")

    monkeypatch.setattr(main, "process_file", broken_mapping)
    assert main.run_attack_mapping(saved, str(tmp_path / "attack_mapping")) is None
    assert Path(saved).exists()


def test_main_saves_investigation_then_maps_each_incident(tmp_path, monkeypatch, capsys):
    # 사건 파일 → 조사(LLM 대신 준비된 결과) → 결과 JSON 저장 → 매핑·최종 보고서 저장까지 main() 전체
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_incidents", lambda path: [{"incident_id": "A"}, {"incident_id": "B"}])
    # 조사와 매핑은 역할별로 다른 LLM 객체를 쓴다(INVESTIGATION_* / MAPPING_* 설정, 2026-10-02 분리)
    clients = {"INVESTIGATION": object(), "MAPPING": object()}
    monkeypatch.setattr(main, "build_llm_client", lambda role="INVESTIGATION": clients[role])

    def baseline_spy(path, *, out_dir, llm_client):
        assert Path(path).exists() and llm_client is clients["MAPPING"]
        return process_saved_file(path, ALL_RULES, out_dir)

    def pipeline(incidents, **kwargs):
        assert kwargs["llm_client"] is clients["INVESTIGATION"]
        for result in (investigation(incident_id="INC-MAIN-A"),
                       investigation("FALSE_POSITIVE", incident_id="INC-MAIN-B")):
            kwargs["on_result"](result)
        return []

    monkeypatch.setattr(main, "process_file", baseline_spy)
    monkeypatch.setattr(main, "run_investigation_pipeline", pipeline)

    main.main(["incidents.jsonl"])

    out = capsys.readouterr().out
    assert "--- 저장된 조사 결과 JSON 2건 ---" in out
    assert "ATT&CK 매핑: mapped (기법 2개: T1505.003, T1059.004)" in out
    assert "ATT&CK 매핑: not_applicable (기법 0개)" in out
    assert "--- 저장된 ATT&CK 매핑·최종 보고서 JSON 4건 ---" in out
    assert len(list((tmp_path / "results" / "investigation_agent").iterdir())) == 2
    assert sorted(p.name for p in (tmp_path / "results" / "attack_mapping").iterdir()) == [
        "INC-MAIN-A_attack_mapping.json", "INC-MAIN-A_final_report.json",
        "INC-MAIN-B_attack_mapping.json", "INC-MAIN-B_final_report.json"]


def test_main_records_usage_per_incident_and_role(tmp_path, monkeypatch, capsys):
    # 모델 비교용: 사건마다 조사·매핑 토큰을 따로 계산해 results/llm_usage/에 남긴다(조사 결과 JSON은 그대로)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_incidents", lambda path: [{"incident_id": "A"}, {"incident_id": "B"}])

    class FakeClient:
        def __init__(self, model):
            self.model = model
            self.usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "refusals": 0}

        def spend(self, tokens):
            self.usage_totals["calls"] += 1
            self.usage_totals["input_tokens"] += tokens
            self.usage_totals["output_tokens"] += tokens // 10

    clients = {"INVESTIGATION": FakeClient("inv-model"), "MAPPING": FakeClient("map-model")}
    monkeypatch.setattr(main, "build_llm_client", lambda role="INVESTIGATION": clients[role])

    def mapping_spy(path, *, out_dir, llm_client):
        llm_client.spend(100)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"mapping_status": "mapped", "techniques": [], "kill_chain": []}

    def pipeline(incidents, **kwargs):
        for tokens, incident_id in ((1000, "INC-A"), (3000, "INC-B")):
            kwargs["llm_client"].spend(tokens)
            kwargs["on_result"](investigation(incident_id=incident_id))
        return []

    monkeypatch.setattr(main, "process_file", mapping_spy)
    monkeypatch.setattr(main, "run_investigation_pipeline", pipeline)
    main.main(["incidents.jsonl"])

    [usage_file] = (tmp_path / "results" / "llm_usage").iterdir()
    usage = json.loads(usage_file.read_text(encoding="utf-8"))
    assert usage["investigation_model"] == "inv-model" and usage["mapping_model"] == "map-model"
    assert [r["incident_id"] for r in usage["incidents"]] == ["INC-A", "INC-B"]
    assert [r["investigation_usage"]["input_tokens"] for r in usage["incidents"]] == [1000, 3000]
    assert [r["mapping_usage"]["input_tokens"] for r in usage["incidents"]] == [100, 100]
    assert usage["incidents"][0]["mapping_status"] == "mapped" and usage["incidents"][0]["verdict"] == "THREAT_CONFIRMED"
    assert usage["totals"]["investigation"]["input_tokens"] == 4000 and usage["totals"]["mapping"]["calls"] == 2
    out = capsys.readouterr().out
    assert "[agent] 토큰 — 조사 FakeClient(inv-model): 호출 2회, 입력 4000" in out
    assert "[agent] 토큰 — 매핑 FakeClient(map-model): 호출 2회, 입력 200" in out


def test_mapping_client_failure_does_not_stop_investigation(tmp_path, monkeypatch, capsys):
    # 매핑 LLM 설정이 잘못돼도(예: MAPPING_LLM_PROVIDER 오타) 조사는 계속하고, 매핑 단계가 다시 시도한다
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_incidents", lambda path: [{"incident_id": "A"}])

    def build(role="INVESTIGATION"):
        if role == "MAPPING":
            raise ValueError("알 수 없는 MAPPING_LLM_PROVIDER입니다: typo")
        return object()

    seen = []

    def mapping_spy(path, *, out_dir, llm_client):
        seen.append(llm_client)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"mapping_status": "not_applicable", "techniques": [], "kill_chain": []}

    monkeypatch.setattr(main, "build_llm_client", build)
    monkeypatch.setattr(main, "process_file", mapping_spy)
    monkeypatch.setattr(main, "run_investigation_pipeline",
                        lambda incidents, **kwargs: kwargs["on_result"](investigation()) or [])
    main.main(["incidents.jsonl"])
    assert seen == [None]  # 매핑 단계에 None → attack_mapping/cli.py가 MAPPING 설정으로 다시 만든다
    out = capsys.readouterr().out
    assert "매핑 LLM 준비 실패" in out and "--- 저장된 조사 결과 JSON 1건 ---" in out


def test_main_preserves_same_investigation_id_saved_in_one_second(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_incidents", lambda path: [{"incident_id": "A"}, {"incident_id": "B"}])
    monkeypatch.setattr(main, "build_llm_client", lambda role="INVESTIGATION": object())

    class FrozenDateTime:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(main, "datetime", FrozenDateTime)
    seen_paths = []

    def mapping_spy(path, *, out_dir, llm_client):
        seen_paths.append(Path(path))
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"mapping_status": "not_applicable", "techniques": [], "kill_chain": []}

    def pipeline(incidents, **kwargs):
        first, second = investigation(), investigation()
        first["save_marker"], second["save_marker"] = "first", "second"
        kwargs["on_result"](first)
        kwargs["on_result"](second)
        return []

    monkeypatch.setattr(main, "process_file", mapping_spy)
    monkeypatch.setattr(main, "run_investigation_pipeline", pipeline)
    main.main(["incidents.jsonl"])

    assert len(seen_paths) == 2 and seen_paths[0] != seen_paths[1]
    assert seen_paths[1].stem == seen_paths[0].stem + "__2"
    assert [json.loads(path.read_text(encoding="utf-8"))["save_marker"] for path in seen_paths] == [
        "first", "second"]
