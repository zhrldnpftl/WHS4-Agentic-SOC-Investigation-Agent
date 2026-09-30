"""조사 에이전트 실행 진입점 — `python main.py <사건 파일>`.

역할
  1차 탐지가 넘긴 사건(Incident) 파일을 읽고, 도구 레지스트리와 LLM 클라이언트를 만든 뒤
  사건마다 조사를 끝까지 실행한다(사건 파일 읽기 → 사건별 조사 → 결과 JSON).
  결과 JSON은 results/investigation_agent/에 저장하고, 콘솔에는 저장한 파일 경로만 보여 준다.
  사건을 찾고 고르는 일(로그 수집·탐지·사건 묶기·우선순위)은 1차 탐지가 한다.

누가 부르나
  사람이 직접 실행한다 (EC2: `python3 main.py <사건 파일>`).

무엇을 부르나
  [2] agent/tools/registry.py   build_default_registry()   조사 도구 목록 만들기
  [3] agent/llm_provider.py     build_llm_client()         LLM 클라이언트 (기본 Claude, INVESTIGATION_LLM_PROVIDER=gemini면 Gemini)
  [4] agent/incident_input.py   load_incidents()           사건 파일 읽기 (JSON 객체·배열 또는 JSONL)
  [5] agent/pipeline.py         run_investigation_pipeline() 사건별 조사
  [45] main.py                  save_investigation_result() 결과 JSON 저장

실행 준비
  1. `pip install -r requirements.txt`
  2. 저장소 루트 .env(루트 .env.example 참고)에 INVESTIGATION_ANTHROPIC_API_KEY(조사 전용, 먼저 읽음) 또는
     ANTHROPIC_API_KEY(공용), 모델 INVESTIGATION_CLAUDE_MODEL. Gemini는 INVESTIGATION_LLM_PROVIDER=gemini +
     INVESTIGATION_GEMINI_API_KEY. LLM 설정은 INVESTIGATION_ 이름만 읽는다(agent/settings.py).
  3. 같은 루트 .env에 계층별 로그 파일 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH)와 HOST(수집 서버 이름)
     — EC2라면 /var/log/... 경로. 조사 도구가 원본 로그를 다시 읽을 때 쓴다.
  4. 사건 파일: 1차 탐지 출력(한 줄에 Incident 한 건인 JSONL) 또는 직접 작성한 사건 JSON

결과 저장
  사건마다 results/investigation_agent/<investigation_id>_<UTC시각>.json에 보관한다.
  사람이 읽는 텍스트 보고서는 만들지 않는다 — 최종 보고서는 이후 단계(ATT&CK 매핑·대응 권고)
  결과까지 합쳐 따로 만든다.
  전체 동작 흐름은 docs/AGENT_FLOW.md 참고.
"""

import argparse
import json
import os
from datetime import datetime, timezone

from agent import build_default_registry, load_incidents, run_investigation_pipeline
from agent.llm_provider import build_llm_client
from agent.settings import load_root_env

# 저장소 루트 .env(1차 탐지와 같이 쓰는 파일 하나)에서 API 키 / HOST / 로그 경로 등을 읽어온다.
# 경로로 직접 읽으므로 llm/investigate/.env는 읽지 않는다. 1차 탐지 원본의 import 시점 load_dotenv()는
# normalizer_adapter가 막는다.
load_root_env()

RESULTS_DIR = "results"
# 단계별 결과 폴더: 이후 단계(ATT&CK 매핑 등)가 붙으면 results/ 아래에 단계별 폴더를 나란히 둔다
INVESTIGATION_DIR = os.path.join(RESULTS_DIR, "investigation_agent")


def save_investigation_result(result: dict, output_dir: str = INVESTIGATION_DIR) -> str:
    """조사 결과(investigation_result JSON)를 파일로 저장하고 저장된 경로를 반환한다.

    파일명은 {investigation_id}_{저장시각 UTC}.json 형태다. investigation_id만으로는
    같은 incident가 재조사될 경우 파일명이 겹칠 수 있어(build_investigation_result()가
    날짜 기준 "-001" 고정 접미사를 붙이는 방식이라 하루에 여러 번 조사되면 동일해짐),
    저장 시각(초 단위)을 추가로 붙여 항상 고유하게 만든다.
    """
    os.makedirs(output_dir, exist_ok=True)

    investigation_id = result.get("investigation_id") or result.get("incident_id", "UNKNOWN")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{investigation_id}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


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
    llm_client = build_llm_client()

    # [45] 결과 저장 — 사건 하나가 끝날 때마다 바로 저장한다. 뒤 사건에서 예외(API 키 오류 등)로
    #      실행이 멈춰도 앞서 끝난 사건 결과는 남는다.
    saved_paths = []
    incomplete = []

    def save(result: dict) -> None:
        path = save_investigation_result(result)
        saved_paths.append(path)
        key = result.get("incident_key") or result.get("incident_id")
        if result.get("investigation_status") == "INCOMPLETE":
            incomplete.append(key)
            print(f"[{len(saved_paths)}/{len(incidents)}] ⚠ 조사 미완료(다시 조사 필요) {key}: {path}")
        else:
            print(f"[{len(saved_paths)}/{len(incidents)}] {key}: {path}")

    # [5] → agent/pipeline.py run_investigation_pipeline() — 사건을 받은 순서대로 조사한다
    # [44] ← 사건별 조사 결과는 on_result(save)로 하나씩 받아 저장한다
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
    )

    print(f"\n--- 저장된 조사 결과 JSON {len(saved_paths)}건 ---")
    for path in saved_paths:
        print(f"  {path}")
    if incomplete:
        # 사건 id(incident_key, 없으면 incident_id)로 다시 조사할 사건을 고를 수 있게 모아 보여 준다
        print(f"\n⚠ LLM API 일시 오류로 조사 미완료 {len(incomplete)}건 — 다시 조사하십시오: {', '.join(incomplete)}")


# [1] 시작점 — `python main.py <사건 파일>`로 실행하면 main()이 불린다
if __name__ == "__main__":
    main()