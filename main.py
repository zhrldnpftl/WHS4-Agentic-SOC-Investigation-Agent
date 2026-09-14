"""조사 에이전트 실행 예시.

실제로 돌려보려면:
1. `pip install -r requirements.txt`
2. Gemini(기본값, 무료 티어 가능): Google AI Studio(aistudio.google.com)에서 API 키 발급 후
   `export GEMINI_API_KEY=...`
   Claude로 돌리고 싶으면 `export LLM_PROVIDER=anthropic` + `export ANTHROPIC_API_KEY=...`
3. build_default_registry(handlers={...})에 팀원들이 구현한 실제 fetch_* 함수를 연결
   (미연결 상태면 mock_tools.py의 목업 데이터로 동작)
4. .env에 AWS 자격 증명 + HOST(S3 파티션의 host= 값)를 채워야 raw log ingestion이 동작함

Triage/감지 에이전트가 파이프라인에서 빠졌기 때문에, seed를 직접 만들어 넣던 예전 방식
대신 raw log부터 시작하는 전체 파이프라인(agent.pipeline.run_investigation_pipeline)을 쓴다.
"""

import json
import os

from dotenv import load_dotenv

from agent import ClaudeClient, GeminiClient, build_default_registry, run_investigation_pipeline
from agent.report import format_text_report

load_dotenv()  # .env 파일에서 GEMINI_API_KEY / ANTHROPIC_API_KEY / HOST 등을 읽어온다


def build_llm_client():
    """LLM_PROVIDER 환경변수로 Gemini/Claude를 선택한다. 기본값은 gemini."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "anthropic":
        return ClaudeClient()  # ANTHROPIC_API_KEY 환경변수 필요
    if provider == "gemini":
        return GeminiClient()  # GEMINI_API_KEY 환경변수 필요 (무료 티어 가능)
    raise ValueError(f"알 수 없는 LLM_PROVIDER입니다: {provider} (gemini 또는 anthropic만 지원)")


def main() -> None:
    # S3 파티션의 host= 값과 반드시 일치해야 함 (예: "library-web-01"이 아니라 "web-01")
    host = os.environ.get("HOST", "web-01")
    minutes = int(os.environ.get("RAW_LOG_WINDOW_MINUTES", "10"))

    # resolve_ip_geo는 실제 구현은 있지만 지금 우선순위가 아니라서 제외해둔다.
    # get_process_tree는 2026-09-14에 실제 구현 완성돼서 제외 목록에서 뺐다.
    tool_registry = build_default_registry(exclude=["resolve_ip_geo"])
    llm_client = build_llm_client()

    results = run_investigation_pipeline(
        host=host,
        llm_client=llm_client,
        tool_registry=tool_registry,
        minutes=minutes,
        max_calls=8,
        confidence_threshold=0.85,
    )

    if not results:
        print(f"최근 {minutes}분 동안 {host}에서 조사할 만한 seed 후보가 없었습니다.")
        return

    for i, result in enumerate(results, start=1):
        print(f"\n{'='*10} 조사 {i}/{len(results)} — {result['incident_id']} {'='*10}")
        print(format_text_report(result))

    print("\n--- 원본 JSON (raw investigation_result 리스트) ---")
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()