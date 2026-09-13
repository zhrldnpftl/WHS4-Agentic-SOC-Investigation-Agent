"""EC2에서 가져온 실제 raw log 샘플(4계층)로 전체 흐름을 검증하는 스크립트.

S3/AWS 자격 증명 없이, 로컬 파일 + 실제 Gemini API 키만으로:
1. EC2에서 받아온 web/auth/audit/network raw 로그(정규화 안 된 원본)를 전부 로드
2. 진짜 Gemini(SeedGenerator)에게 "여기서 수상한 거 있어?"라고 물어봐서 seed 후보 + 우선순위 확보
3. 가장 우선순위 높은 seed 하나를 골라, "로컬 파일에서 근거를 찾는 검증 도구" 4개
   (web/auth/audit/network 계층별)를 통해 InvestigationAgent로 심층 조사
   -> 여러 계층을 넘나드는 조사(예: audit의 pid를 auth 로그에서 다시 찾기)는
      별도 "조인" 코드 없이, LLM이 조사 루프 중 필요한 도구를 순서대로 불러가며
      raw 텍스트 안의 pid/IP 등을 스스로 연결해서 수행한다.
4. 최종 investigation_result를 사람이 읽는 텍스트로 출력

*** 주의 ***
- 여기서 등록하는 4개 도구는 S3용 실제 구현(agent/tools/real/*.py)이 아니라,
  이 스크립트 전용 "로컬 파일 검색" 버전이다. agent/tools/real/ 폴더에는 넣지
  않는다 — 거기 넣으면 자동 탐색 규칙 때문에 나중에 만들 S3 버전과 충돌한다.
- 샘플 파일이 없는 계층은 그 도구를 아예 등록하지 않는다 (LLM이 존재 자체를 모르게
  해서, 지난번처럼 아직 목업인 도구를 호출해 가짜 증거가 섞이는 걸 막는다).
- 지금은 raw 텍스트를 정규화 없이 그대로 LLM에게 준다. S3 access key가 나오면
  실제로는 인프라팀이 정규화한 JSON을 쓰게 되므로, 이 스크립트는 "임시 검증용"이다.
- 무료 티어 rate limit을 아끼기 위해 기본적으로 최우선순위 seed 1개만 조사한다.

사용법:
    # audit만 (예전과 동일하게 동작)
    python scripts/local_e2e_test.py --audit sample_audit.log

    # 4계층 다 있을 때
    python scripts/local_e2e_test.py \
        --web sample_web.log --auth sample_auth.log \
        --audit sample_audit.log --network sample_network.log
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import GeminiClient, InvestigationAgent, SeedGenerator
from agent.report import format_text_report
from agent.tools import ToolRegistry, ToolSpec

load_dotenv()

INVESTIGATE_TOP_N = 1  # 무료 티어 rate limit 고려해 우선 1개만. 여유 있으면 늘리기.
HOST = os.environ.get("HOST", "web-01")

# 계층 이름 -> (도구 이름, 도구 설명)
LAYER_TOOL_SPECS = {
    "web": ("fetch_web_log", "어떤 웹 요청이 있었는지 조회한다 (로컬 샘플 web log 검색)"),
    "auth": ("fetch_auth_log", "로그인·권한상승 흔적이 있었는지 조회한다 (로컬 샘플 auth log 검색)"),
    "audit": ("fetch_audit_log", "파일 생성·변조·명령 실행이 있었는지 조회한다 (로컬 샘플 audit log 검색)"),
    "network": ("fetch_network_log", "네트워크 후속 행위가 있었는지 조회한다 (로컬 샘플 network log 검색)"),
}


def load_local_raw_lines(path: str, max_lines: int = 500) -> List[str]:
    """EC2에서 받아온 raw 로그 파일을 줄 단위로 읽는다.
    정규화하지 않고 원본 텍스트 그대로 반환 — LLM이 직접 해석하게 둔다.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines[-max_lines:]


def build_local_search_tool(layer: str, raw_lines: List[str]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """계층 하나(web/auth/audit/network)에 대한 로컬 파일 검색 도구를 만든다.

    실제 S3 조회 대신, 로드해둔 raw_lines 안에서 seed/LLM이 요청한 pid/user 등이
    실제로 등장하는지 단순 텍스트 검색으로 확인한다. 정교한 파싱이 아니라 "이 계층에
    실제 근거가 있는지" 빠르게 확인하는 용도다.
    """

    def _local_fetch(args: Dict[str, Any]) -> Dict[str, Any]:
        pid = args.get("pid")
        user = args.get("user")
        src_ip = args.get("src_ip")

        matched = []
        for line in raw_lines:
            if pid is not None and f"pid={pid}" not in line and f"[{pid}]" not in line:
                continue
            if user is not None and str(user) not in line:
                continue
            if src_ip is not None and str(src_ip) not in line:
                continue
            matched.append(line)
            if pid is None and user is None and src_ip is None and len(matched) >= 20:
                # 필터가 전혀 없으면 너무 많이 매칭되니 상위 20줄만
                break

        return {
            "count": len(matched),
            "summary": f"로컬 샘플 {layer} 로그에서 조건에 맞는 {len(matched)}줄 발견 (검증용, 실제 S3 아님)",
            "records": [{"raw_line": line} for line in matched],
        }

    return _local_fetch


def build_local_registry(layer_lines: Dict[str, List[str]]) -> ToolRegistry:
    """샘플이 있는 계층만 도구로 등록한다 (없는 계층은 LLM이 존재 자체를 모르게 함)."""
    registry = ToolRegistry()
    for layer, raw_lines in layer_lines.items():
        tool_name, description = LAYER_TOOL_SPECS[layer]
        registry.register(
            ToolSpec(
                tool_name,
                description,
                ["host", "start_time", "end_time"],
                ["event_type", "pid", "user", "src_ip"],
                handler=build_local_search_tool(layer, raw_lines),
            )
        )
    return registry


def main() -> None:
    parser = argparse.ArgumentParser(description="로컬 샘플 로그(1~4계층)로 조사 에이전트 전체 흐름을 실제 Gemini로 검증한다")
    parser.add_argument("--web", default=None, help="web(nginx) 샘플 로그 파일 경로")
    parser.add_argument("--auth", default=None, help="auth 샘플 로그 파일 경로")
    parser.add_argument("--audit", default=None, help="audit(auditd) 샘플 로그 파일 경로")
    parser.add_argument("--network", default=None, help="network(suricata) 샘플 로그 파일 경로")
    parser.add_argument(
        "--max-lines-per-source",
        type=int,
        default=30,
        help="계층당 Gemini에 보낼 최대 줄 수 (파일 자체는 그대로 두고 일부만 잘라서 보냄). "
             "무료 티어 분당 토큰 한도(429 에러) 걸리면 이 값을 줄이세요.",
    )
    args = parser.parse_args()

    layer_paths = {
        "web": args.web,
        "auth": args.auth,
        "audit": args.audit,
        "network": args.network,
    }
    layer_paths = {k: v for k, v in layer_paths.items() if v}

    if not layer_paths:
        print("사용법: python scripts/local_e2e_test.py --audit sample_audit.log [--web ... --auth ... --network ...]")
        sys.exit(1)

    layer_lines: Dict[str, List[str]] = {}
    raw_logs: List[Dict[str, Any]] = []
    for layer, path in layer_paths.items():
        lines = load_local_raw_lines(path, max_lines=args.max_lines_per_source)
        layer_lines[layer] = lines
        raw_logs.extend({"_source_type": layer, "raw_line": line} for line in lines)
        print(f"[1단계] [{layer}] {path}에서 {len(lines)}줄 로드")

    llm_client = GeminiClient()  # 진짜 Gemini 호출 (.env의 GEMINI_API_KEY 사용)

    print("\n[2단계] Gemini에게 seed 후보 추출 요청 중... (모든 계층 통째로 넘김)")
    seeds = SeedGenerator(llm_client).generate(raw_logs, host=HOST)

    if not seeds:
        print("Gemini가 이 샘플에서 후보를 찾지 못했습니다 (정상일 수 있음 — 평범한 로그였을 수도 있음).")
        return

    print(f"[2단계 결과] seed 후보 {len(seeds)}개, 우선순위 순:")
    for s in seeds:
        print(
            f"  priority={s.get('priority')} | {s.get('incident_id')} | "
            f"{s.get('trigger_description')} (confidence_initial={s.get('confidence_initial')})"
        )

    # 샘플이 있는 계층만 도구로 등록 -> 없는 계층/아직 목업인 나머지 도구는 LLM이 아예 모름
    tool_registry = build_local_registry(layer_lines)
    print(f"\n[안내] 이번 조사에서 LLM이 쓸 수 있는 도구: {[LAYER_TOOL_SPECS[l][0] for l in layer_lines]}")

    top_seeds = seeds[:INVESTIGATE_TOP_N]
    for i, seed in enumerate(top_seeds, start=1):
        print(f"\n[3단계] {i}순위 seed({seed.get('incident_id')}) 심층 조사 시작...")
        agent = InvestigationAgent(llm_client, tool_registry, max_calls=8, confidence_threshold=0.85)
        result = agent.run(seed)

        print(f"\n{'='*10} 조사 결과: {result['incident_id']} {'='*10}")
        print(format_text_report(result))

        print("\n[검증용] 실제로 호출된 도구 목록 (계층 간 연결 확인용):")
        for t in result["tools_called"]:
            print(f"  - {t['tool_name']}: {t['result_summary']}")


if __name__ == "__main__":
    main()