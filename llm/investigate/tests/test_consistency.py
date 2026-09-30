"""동일 seed에 대한 InvestigationAgent 판정 재현성 검증.

실제 LLM API를 N번 호출해서(비용/시간 발생 주의) 재현성을 측정한다. LLM은 main.py와 같은 규칙으로
고른다(agent/llm_provider.py — 기본 Claude, INVESTIGATION_LLM_PROVIDER=gemini면 Gemini).
LLM API 일시 오류로 조사 미완료(INCOMPLETE)가 된 실행은 판정 분포에 넣지 않고 실패로 센다.

*** 2026-09-17 업데이트: 무료 티어 rate limit(15 RPM) 대응 ***
gemini-3.5-flash-lite 무료 티어는 분당 15회 제한이라, 조사 1건당 reason()을
2~3회씩 부르면 4~5건만에 한도를 넘는다. 429 에러의 retryDelay를 파싱해서
그만큼 대기 후 자동 재시도하도록 했다. run들 사이에도 기본 간격을 둔다.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from collections import Counter
from typing import Any, Dict, List

from agent.llm_provider import build_llm_client
from agent.loop import InvestigationAgent
from agent.settings import load_root_env
from agent.tools import build_default_registry

load_root_env()  # 저장소 루트 .env (main.py와 같은 파일)

SEED = {
    "incident_id": "CONSISTENCY-TEST-05",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T20:30:00+00:00",
    "trigger_description": "정상 인증된 SSH 세션에서 민감 디렉터리 압축 및 외부 서버로의 대용량 데이터 전송 발생",
    "confidence_initial": 0.6,
    "severity_hint": "CRITICAL",
    "priority": 1,
    "host": "web-01",
    "src_ip": "91.203.6.44",
    "reasoning": "정상 인증 이후 민감 디렉터리를 압축하고 외부 서버로 대용량 전송한 뒤 흔적을 삭제하려는 정황이 확인되어 데이터 유출 가능성이 높습니다.",
}



RETRY_DELAY_RE = re.compile(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)s")


def _extract_retry_delay(error_message: str, default: float = 45.0) -> float:
    """429 에러 메시지의 retryDelay(예: '41.98s')를 파싱한다. 못 찾으면 default 사용."""
    match = RETRY_DELAY_RE.search(error_message)
    if match:
        return float(match.group(1)) + 2.0  # 여유분 2초 추가
    return default


def run_once_with_retry(run_index: int, seed: Dict[str, Any], strict: bool = True,
                        max_retries: int = 3) -> Dict[str, Any] | None:
    for attempt in range(1, max_retries + 1):
        try:
            llm = build_llm_client()
            # main.py와 같은 조건: resolve_ip_geo는 목업이라 LLM에게 가짜 IP 정보를 줄 수 있어 제외
            registry = build_default_registry(exclude=["resolve_ip_geo"])
            # strict=True: main.py와 같은 조건. False(--legacy): 0918처럼 network 사전 조회와
            # no_more_evidence 관문 없이 LLM이 고르는 도구만 사용 (0918 대비 비교용)
            agent = InvestigationAgent(llm, registry, max_calls=8, confidence_threshold=0.85,
                                       network_precheck=strict, strict_termination=strict)

            result = agent.run(seed)
            verdict = result["final_verdict"]
            if result.get("investigation_status") == "INCOMPLETE":
                # 판정이 아니라 API 장애 — INCONCLUSIVE로 세면 재현성 수치가 왜곡된다
                print(f"--- Run {run_index} 조사 미완료(LLM API 일시 오류): {result.get('incomplete_reason')} ---")
                return None

            print(f"--- Run {run_index} ---")
            if getattr(llm, "usage_totals", None):
                print(f"  usage={llm.usage_totals}")  # Claude: 호출 수·토큰(캐시 포함) — 비용 추정용
            print(f"  verdict={verdict['verdict']}  confidence={verdict['confidence']}  "
                  f"tool_calls={result['statistics']['tool_calls_count']}  "
                  f"termination={result['statistics']['termination_reason']}")
            print(f"  summary: {verdict['summary']}")

            return {
                "run": run_index,
                "verdict": verdict["verdict"],
                "confidence": verdict["confidence"],
                "severity": verdict["severity"],
                "tool_calls_count": result["statistics"]["tool_calls_count"],
                "termination_reason": result["statistics"]["termination_reason"],
                "evidence_count": result["statistics"].get("evidence_count"),
                "summary": verdict["summary"],
                # [2026-09-17 추가] 종료 관문이 실제로 발동했는지 확인하기 위한 필드
                "investigation_notes": result.get("investigation_notes", []),
                "evidence_layers": [e["layer"] for e in result.get("evidence_chain", [])],
                # [2026-09-18 추가] 실제 tool 호출 인자를 확인하기 위해 저장
                "tools_called": result.get("tools_called", []),
            }
        except Exception as exc:
            error_str = str(exc)
            if "RESOURCE_EXHAUSTED" in error_str or "429" in error_str:
                delay = _extract_retry_delay(error_str)
                print(f"--- Run {run_index} 시도 {attempt}/{max_retries}: 429 rate limit, {delay:.0f}초 대기 후 재시도 ---")
                time.sleep(delay)
                continue
            print(f"--- Run {run_index} 실패(재시도 불가능한 오류): {exc} ---")
            return None
    print(f"--- Run {run_index} 최종 실패: {max_retries}회 재시도 모두 rate limit ---")
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--out", type=str, default="consistency_results.json")
    # [2026-09-17 추가] run 사이 기본 대기 시간(초). 15 RPM 한도를 안 넘기려면
    # 조사당 호출 수(보통 2~3회)를 고려해 여유 있게 잡는 게 안전하다.
    parser.add_argument("--interval", type=float, default=20.0)
    # [2026-09-24 추가] 시나리오 스크립트가 출력한 SEED를 파일에 저장해 넘기면 SEED 상수를
    # 손으로 고치지 않아도 된다. --legacy는 0918 동작(사전 조회·no_more_evidence 관문 없음).
    parser.add_argument("--seed-json", type=str, default=None)
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args()

    seed = SEED
    if args.seed_json:
        with open(args.seed_json, encoding="utf-8") as f:
            seed = json.load(f)
    print(f"seed={seed['incident_id']}  mode={'legacy(0918)' if args.legacy else 'strict(main.py)'}")

    runs: List[Dict[str, Any]] = []
    for i in range(1, args.runs + 1):
        result = run_once_with_retry(i, seed, strict=not args.legacy)
        if result:
            runs.append(result)
        if i < args.runs:
            time.sleep(args.interval)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(runs, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print(f"총 {len(runs)}/{args.runs}회 성공")

    if not runs:
        print("성공한 실행이 없어 통계를 계산할 수 없습니다.")
        return

    verdict_counts = Counter(r["verdict"] for r in runs)
    print("\n[Verdict 분포]")
    for verdict, count in verdict_counts.most_common():
        pct = 100 * count / len(runs)
        print(f"  {verdict}: {count}회 ({pct:.0f}%)")

    confidences = [r["confidence"] for r in runs]
    print("\n[Confidence 통계]")
    print(f"  평균: {statistics.mean(confidences):.3f}")
    print(f"  표준편차: {statistics.pstdev(confidences):.3f} (낮을수록 일관적)")
    print(f"  범위: {min(confidences):.2f} ~ {max(confidences):.2f}")

    tool_counts = [r["tool_calls_count"] for r in runs]
    print("\n[도구 호출 횟수 통계]")
    print(f"  평균: {statistics.mean(tool_counts):.1f}회")
    print(f"  범위: {min(tool_counts)} ~ {max(tool_counts)}회")

    majority_pct = 100 * verdict_counts.most_common(1)[0][1] / len(runs)
    print(f"\n[재현성 지표] 최다 verdict 비율: {majority_pct:.0f}%", end=" ")
    if majority_pct == 100:
        print("→ 완전 일관됨 ✅")
    elif majority_pct >= 80:
        print("→ 대체로 일관됨, 소수 이탈 있음 ⚠️")
    else:
        print("→ 재현성 낮음, 프롬프트/판단기준 추가 개선 필요 ❌")


if __name__ == "__main__":
    main()