"""조사 에이전트 실행 진입점 — `python main.py <사건 파일>`.

역할
  1차 탐지가 넘긴 사건(Incident) 파일을 읽고, 도구 레지스트리와 LLM 클라이언트를 만든 뒤
  사건마다 조사를 끝까지 실행한다(사건 파일 읽기 → 사건별 조사 → 결과 JSON → ATT&CK 매핑).
  결과 JSON은 results/investigation_agent/에 저장하고, 저장한 파일로 바로 ATT&CK 매핑을 돌린다.
  콘솔에는 저장한 파일 경로와 사건별 매핑 상태 한 줄만 보여 준다.
  사건을 찾고 고르는 일(로그 수집·탐지·사건 묶기·우선순위)은 1차 탐지가 한다.

누가 부르나
  사람이 직접 실행한다 (EC2: `python3 main.py <사건 파일>`).

무엇을 부르나
  [2] agent/tools/registry.py   build_default_registry()   조사 도구 목록 만들기
  [3] agent/llm_provider.py     build_llm_client()         LLM 클라이언트 — 조사용(INVESTIGATION_*)과 매핑용(MAPPING_*)을
                                                           따로 만든다 (기본 Claude, <역할>_LLM_PROVIDER=gemini면 Gemini)
  [4] agent/incident_input.py   load_incidents()           사건 파일 읽기 (JSON 객체·배열 또는 JSONL)
  [5] agent/pipeline.py         run_investigation_pipeline() 사건별 조사
  [45] main.py                  save_investigation_result() 결과 JSON 저장
  [46] attack_mapping/cli.py    process_file()             저장된 조사 JSON → ATT&CK 매핑·Kill Chain·최종 보고서

실행 준비
  1. `pip install -r requirements.txt`
  2. 저장소 루트 .env(루트 .env.example 참고)에 INVESTIGATION_ANTHROPIC_API_KEY(조사 전용, 먼저 읽음) 또는
     ANTHROPIC_API_KEY(공용), 모델 INVESTIGATION_CLAUDE_MODEL. Gemini는 INVESTIGATION_LLM_PROVIDER=gemini +
     INVESTIGATION_GEMINI_API_KEY. ATT&CK 매핑은 MAPPING_ 이름(MAPPING_CLAUDE_MODEL 등, 없으면 경량 기본값)을
     따로 읽는다. 접두어 없는 옛 이름은 읽지 않는다(agent/settings.py, 저장소 루트 docs/LLM-역할별-설정-가이드.md).
  3. 같은 루트 .env에 계층별 로그 파일 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH)와 HOST(수집 서버 이름)
     — EC2라면 /var/log/... 경로. 조사 도구가 원본 로그를 다시 읽을 때 쓴다.
  4. 사건 파일: 1차 탐지 출력(한 줄에 Incident 한 건인 JSONL) 또는 직접 작성한 사건 JSON

결과 저장
  사건마다 results/investigation_agent/<investigation_id>_<UTC시각>.json에 보관한다.
  저장 직후 그 파일로 ATT&CK 매핑을 돌려 results/attack_mapping/에
  <incident_id>_attack_mapping.json과 <incident_id>_final_report.json을 만든다
  (`python -m attack_mapping.cli`와 같은 처리, 같은 사건이면 __2, __3 …).
  매핑이 실패해도 조사 결과 JSON은 이미 저장돼 있어 CLI로 매핑만 다시 돌릴 수 있다.
  실행이 끝나면 사건별·역할별 토큰 사용량과 걸린 시간을 results/llm_usage/llm_usage_<UTC시각>.json에 남기고
  콘솔에 역할별 합계를 한 줄씩 보여 준다(모델 비교용, [47]). 조사 결과 JSON 형식은 그대로다.
  사람이 읽는 텍스트 보고서는 만들지 않는다 — 최종 보고서(final_report.json)는 조사 결과에
  매핑 결과를 붙인 JSON이고, 이후 대응 권고 결과도 여기에 합친다.
  전체 동작 흐름은 docs/AGENT_FLOW.md, 매핑 연결부는 docs/AGENT_ATTACK_MAPPING_FLOW.md 참고.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from typing import Optional

from agent import build_default_registry, load_incidents, run_investigation_pipeline
from agent.llm_provider import build_llm_client
from agent.settings import INVESTIGATION, MAPPING, load_root_env
from attack_mapping.cli import process_file

# 저장소 루트 .env(1차 탐지와 같이 쓰는 파일 하나)에서 API 키 / HOST / 로그 경로 등을 읽어온다.
# 경로로 직접 읽으므로 llm/investigate/.env는 읽지 않는다. 1차 탐지 원본의 import 시점 load_dotenv()는
# normalizer_adapter가 막는다.
load_root_env()

RESULTS_DIR = "results"
# 단계별 결과 폴더: 이후 단계(ATT&CK 매핑 등)가 붙으면 results/ 아래에 단계별 폴더를 나란히 둔다
INVESTIGATION_DIR = os.path.join(RESULTS_DIR, "investigation_agent")
ATTACK_MAPPING_DIR = os.path.join(RESULTS_DIR, "attack_mapping")
# 사건별·역할별 LLM 토큰 사용량과 걸린 시간 (모델 비교용, save_llm_usage)
LLM_USAGE_DIR = os.path.join(RESULTS_DIR, "llm_usage")


def save_investigation_result(result: dict, output_dir: str = INVESTIGATION_DIR) -> str:
    """조사 결과(investigation_result JSON)를 파일로 저장하고 저장된 경로를 반환한다.

    파일명은 {investigation_id}_{저장시각 UTC}.json 형태다. investigation_id만으로는
    같은 incident가 재조사될 경우 파일명이 겹칠 수 있어(build_investigation_result()가
    날짜 기준 "-001" 고정 접미사를 붙이는 방식이라 하루에 여러 번 조사되면 동일해짐),
    저장 시각(초 단위)을 붙이고 같은 초에 재조사되면 접미사로 구분한다.
    """
    os.makedirs(output_dir, exist_ok=True)

    investigation_id = result.get("investigation_id") or result.get("incident_id", "UNKNOWN")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{investigation_id}_{timestamp}"
    suffix = 1
    while True:
        filename = f"{stem}{f'__{suffix}' if suffix > 1 else ''}.json"
        filepath = os.path.join(output_dir, filename)
        try:
            output = open(filepath, "x", encoding="utf-8")
            break
        except FileExistsError:
            suffix += 1

    with output as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


def run_attack_mapping(saved_path: str, output_dir: str = ATTACK_MAPPING_DIR, *,
                       llm_client=None, rule_baseline: bool = False) -> Optional[dict]:
    """[46] 저장된 조사 결과 JSON 파일로 ATT&CK 매핑을 실행하고 매핑 결과를 반환한다.

    메모리의 dict가 아니라 저장된 파일을 넘겨, 나중에 CLI로 다시 돌린 결과와 같게 한다.
    매핑 결과에는 "kill_chain"과 이번에 만든 파일 경로 "output_paths"가 붙는다.
    매핑이 실패해도 조사 결과는 이미 저장돼 있으므로 안내만 하고 None을 반환한다
    (다음 사건 조사·매핑은 계속된다). 기본 경로는 RAG이고 Rule은 명시적 baseline이다.
    """
    before = set(os.listdir(output_dir)) if os.path.isdir(output_dir) else set()
    try:
        if rule_baseline:
            from attack_mapping.rules import ALL_RULES
            mapping_result = process_file(saved_path, ALL_RULES, output_dir)
        else:
            mapping_result = process_file(saved_path, out_dir=output_dir,
                                          llm_client=llm_client)
    except Exception as exc:
        print(f"[ATT&CK] 매핑 실패 — 조사 결과 JSON은 저장됨({saved_path}): {exc}")
        return None
    created = sorted(set(os.listdir(output_dir)) - before)
    mapping_result["output_paths"] = [os.path.join(output_dir, name) for name in created]
    return mapping_result


def mapping_summary(mapping_result: Optional[dict]) -> str:
    """사건별 매핑 상태 한 줄. 자세한 내용은 매핑 결과·최종 보고서 JSON에 있다."""
    if mapping_result is None:
        return "ATT&CK 매핑: 실패(위 안내 참고)"
    status = mapping_result["mapping_status"]
    if status == "error":
        return f"ATT&CK 매핑: error — {'; '.join(mapping_result['errors'])}"
    ids = ", ".join(step["technique_id"] for step in mapping_result.get("kill_chain", []))
    return f"ATT&CK 매핑: {status} (기법 {len(mapping_result['techniques'])}개{': ' + ids if ids else ''})"


def _build_mapping_client():
    """매핑용 LLM(MAPPING_* 설정)을 한 번 만든다. 실패해도 조사는 계속한다 — None을 넘기면 매핑 단계가
    다시 만들어 보고, 그래도 안 되면 그 사건 매핑 결과에 설정 오류로 남긴다(attack_mapping/cli.py)."""
    try:
        return build_llm_client(MAPPING)
    except Exception as exc:
        print(f"[ATT&CK] 매핑 LLM 준비 실패 — 매핑 단계에서 다시 시도합니다: {exc}")
        return None


def _describe_client(client) -> str:
    if client is None:
        return "-"
    return f"{type(client).__name__}({getattr(client, 'model', None) or '-'})"


def _usage_snapshot(client) -> dict:
    """LLM 클라이언트가 지금까지 쓴 토큰 합계(ClaudeClient.usage_totals). 없으면 빈 dict."""
    return dict(getattr(client, "usage_totals", None) or {})


def _usage_delta(after: dict, before: dict) -> dict:
    return {key: value - before.get(key, 0) for key, value in after.items()}


def _format_usage(usage: dict) -> str:
    if not usage:
        return "기록 없음"
    return (f"호출 {usage.get('calls', 0)}회, 입력 {usage.get('input_tokens', 0)}·출력 {usage.get('output_tokens', 0)}"
            f"·캐시 읽기 {usage.get('cache_read_input_tokens', 0)}·캐시 쓰기 {usage.get('cache_creation_input_tokens', 0)}"
            f" 토큰, 거절 {usage.get('refusals', 0)}회")


def save_llm_usage(records: list, llm_client, mapping_client, output_dir: str = LLM_USAGE_DIR) -> str:
    """[47] 사건별·역할별 토큰 사용량과 걸린 시간을 results/llm_usage/llm_usage_<UTC>.json에 저장한다.

    모델 비교(비용·시간)용이다. 조사 결과 JSON 형식은 바꾸지 않으려고 따로 둔다. 매핑 클라이언트를 못 만들어
    매핑 단계가 직접 만든 경우 그 사용량은 잡히지 않는다(mapping_usage가 빈 dict).
    """
    os.makedirs(output_dir, exist_ok=True)
    totals = {"investigation": _usage_snapshot(llm_client), "mapping": _usage_snapshot(mapping_client)}
    payload = {
        "investigation_model": getattr(llm_client, "model", None),
        "mapping_model": getattr(mapping_client, "model", None),
        "incidents": records,
        "totals": totals,
    }
    path = os.path.join(output_dir, f"llm_usage_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
    return path


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="1차 탐지 사건 파일을 읽어 사건마다 조사한다.")
    parser.add_argument("incidents", help="사건 파일 경로 (JSON 객체·배열 또는 한 줄에 한 건인 JSONL)")
    args = parser.parse_args(argv)

    # 조사 결과·사건에 기록되는 수집 서버 이름 (EC2: `hostname` 결과). 1차 탐지 Incident에는 host가 없다.
    host = os.environ.get("HOST") or "web-01"  # .env에 HOST= 로 비워 둔 경우도 기본값 사용

    # [4] → agent/incident_input.py load_incidents() — 파일 형식 오류는 LLM 클라이언트를 만들기 전에 알린다
    incidents = load_incidents(args.incidents)
    if not incidents:
        print(f"{args.incidents}에 조사할 사건이 없습니다.")
        return

    # [2] → agent/tools/registry.py build_default_registry()
    #     agent/tools/real/ 폴더에서 "파일명 == 함수명"인 도구를 자동으로 찾아 등록한다.
    #     resolve_ip_geo는 구현은 있지만 지금 우선순위가 아니라서 뺀다.
    tool_registry = build_default_registry(exclude=["resolve_ip_geo"])
    # [3] → agent/llm_provider.py build_llm_client(): 기본 Claude, INVESTIGATION_LLM_PROVIDER=gemini면 Gemini
    llm_client = build_llm_client(INVESTIGATION)
    # ATT&CK 매핑은 조사와 다른 LLM(MAPPING_* 설정, 경량 모델)을 쓴다. 예전에는 조사용 객체를 그대로 넘겨
    # 조사 모델을 올리면 매핑도 같이 올라갔다(2026-10-02 분리).
    mapping_client = _build_mapping_client()
    print(f"[agent] 사건 {len(incidents)}건, 도구 {len(tool_registry.list_tools())}개, "
          f"조사 LLM {_describe_client(llm_client)}, 매핑 LLM {_describe_client(mapping_client)}", flush=True)

    # [45] 결과 저장 — 사건 하나가 끝날 때마다 바로 저장한다. 뒤 사건에서 예외(API 키 오류 등)로
    #      실행이 멈춰도 앞서 끝난 사건 결과는 남는다.
    saved_paths = []
    mapping_paths = []
    incomplete = []
    # [47] 사건별 토큰·시간: 사건 하나의 조사가 끝날 때마다 save()가 불리므로, 직전 save 이후 늘어난 만큼이 그 사건 몫이다
    usage_records = []
    marks = {"investigation": _usage_snapshot(llm_client), "since": time.monotonic()}

    def save(result: dict) -> None:
        investigation_seconds = time.monotonic() - marks["since"]
        investigation_now = _usage_snapshot(llm_client)
        investigation_usage = _usage_delta(investigation_now, marks["investigation"])
        marks["investigation"] = investigation_now
        path = save_investigation_result(result)
        saved_paths.append(path)
        mapping_before, mapping_started = _usage_snapshot(mapping_client), time.monotonic()
        mapping_result = run_attack_mapping(path, llm_client=mapping_client)
        usage_records.append({
            "incident_id": result.get("incident_id"),
            "incident_key": result.get("incident_key"),
            "investigation_result": path,
            "verdict": (result.get("final_verdict") or {}).get("verdict"),
            "investigation_seconds": round(investigation_seconds, 1),
            "investigation_usage": investigation_usage,
            "mapping_status": (mapping_result or {}).get("mapping_status"),
            "mapping_seconds": round(time.monotonic() - mapping_started, 1),
            "mapping_usage": _usage_delta(_usage_snapshot(mapping_client), mapping_before),
        })
        marks["since"] = time.monotonic()
        if mapping_result is not None:
            mapping_paths.extend(mapping_result["output_paths"])
        key = result.get("incident_key") or result.get("incident_id")
        if result.get("investigation_status") == "INCOMPLETE":
            incomplete.append(key)
            print(f"[{len(saved_paths)}/{len(incidents)}] ⚠ 조사 미완료(다시 조사 필요) {key}: {path}\n    {mapping_summary(mapping_result)}")
        else:
            print(f"[{len(saved_paths)}/{len(incidents)}] {key}: {path}\n    {mapping_summary(mapping_result)}")

    # [5] → agent/pipeline.py run_investigation_pipeline() — 사건을 받은 순서대로 조사한다
    # [44] ← 사건별 조사 결과는 on_result(save)로 하나씩 받아 저장한다
    try:
        run_investigation_pipeline(
            incidents,
            host=host,
            llm_client=llm_client,
            tool_registry=tool_registry,
            max_calls=8,
            confidence_threshold=0.85,
            # 도구 1개만 보고 끝나는 조사를 막는 설정 (agent/loop.py 참고)
            network_precheck=True,      # 사건에 src_ip가 있으면 network를 코드가 먼저 조회
            strict_termination=True,    # 종료 관문 강화 + 판정이 도구 계산 기준과 어긋나면 종료 거부
            on_result=save,
            # 사건 하나에 수 분 걸리므로 LLM 호출·도구 실행을 한 줄씩 바로 보여 준다(폴러가 파이프로 받아도 즉시 보이게 flush)
            progress=lambda message: print(message, flush=True),
        )
    finally:
        # 뒤 사건에서 예외로 멈춰도 앞서 끝난 사건의 사용량은 남긴다
        if usage_records:
            usage_path = save_llm_usage(usage_records, llm_client, mapping_client)
            print(f"\n[agent] 토큰 — 조사 {_describe_client(llm_client)}: {_format_usage(_usage_snapshot(llm_client))}")
            print(f"[agent] 토큰 — 매핑 {_describe_client(mapping_client)}: {_format_usage(_usage_snapshot(mapping_client))}")
            print(f"[agent] 사건별 토큰·시간: {usage_path}")

    print(f"\n--- 저장된 조사 결과 JSON {len(saved_paths)}건 ---")
    for path in saved_paths:
        print(f"  {path}")
    print(f"\n--- 저장된 ATT&CK 매핑·최종 보고서 JSON {len(mapping_paths)}건 ---")
    for path in mapping_paths:
        print(f"  {path}")
    if incomplete:
        # 사건 id(incident_key, 없으면 incident_id)로 다시 조사할 사건을 고를 수 있게 모아 보여 준다
        print(f"\n⚠ LLM API 일시 오류로 조사 미완료 {len(incomplete)}건 — 다시 조사하십시오: {', '.join(incomplete)}")


# [1] 시작점 — `python main.py <사건 파일>`로 실행하면 main()이 불린다
if __name__ == "__main__":
    main()
