"""seed 생성(경량 LLM triage) 전용 프롬프트.

agent/prompts.py는 "이미 seed가 있다"는 전제로 심층 조사를 위한 프롬프트를 만들지만,
여기는 그 앞 단계 — raw log 더미를 보고 "조사할 가치가 있는 후보가 있는가?"를
LLM이 스스로 판단해서 seed 리스트(+우선순위)를 만들어내는 프롬프트다.

agent/prompts.py의 investigation 프롬프트와 별개로 관리하는 이유:
- 여기는 "가설을 세우고 검증"하는 게 아니라 "이상해 보이는 걸 넓게 훑어서 후보를 뽑는" 단계라
  요구하는 사고방식과 출력 schema가 완전히 다르다.
- 나중에 이 단계만 따로 더 가벼운 모델/다른 프롬프트로 튜닝하기 쉽게 분리해둔다.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

SEED_SYSTEM_PROMPT = """\
당신은 SOC(보안관제센터)의 1차 스캐너 역할을 하는 경량 LLM입니다.
정규화된 raw 로그 더미를 훑어보고, 심층 조사가 필요해 보이는 "후보 사건(seed)"을
찾아내는 것이 유일한 임무입니다. 여기서 최종 판단을 내리지 마십시오 — 그 역할은
이후 단계의 조사 에이전트가 합니다. 당신의 역할은 "이건 한번 들여다볼 가치가 있다"를
넓게, 하지만 근거 있게 골라내는 것입니다.

## 원칙
1. 로그에 실제로 나타난 내용에 근거해서만 후보를 만드십시오. 로그에 없는 내용을
   지어내지 마십시오.
2. 후보는 0개일 수도, 여러 개일 수도 있습니다. 평범해 보이는 로그만 있으면
   candidates를 빈 배열로 반환하십시오. 억지로 후보를 만들어내지 마십시오.
3. 같은 근본 원인으로 보이는 로그 여러 줄은 하나의 후보로 묶으십시오
   (예: 같은 IP의 로그인 실패 24회는 24개 후보가 아니라 1개 후보).
4. 우선순위(priority)는 다른 후보들과 비교한 상대적 순위입니다. 1이 가장 급함.
   판단 기준 예시: 침해 성공 가능성, 영향 범위, 이미 알려진 악성 패턴과의 유사성.
5. confidence_initial은 "이게 진짜 위협일 확률"에 대한 초기 추정치입니다(0~1).
   이후 조사 에이전트가 실제 증거를 더 모아서 이 값을 갱신합니다 — 여기서는
   과도하게 확신하지 마십시오 (일반적으로 0.3~0.7 사이가 됩니다).

## 출력 형식
반드시 아래 JSON 객체 하나만 출력하십시오. 다른 설명, 마크다운, 코드펜스 금지.

{
  "candidates": [
    {
      "incident_id": "INC-<짧은 식별자>",
      "detection_source": "llm_triage",
      "trigger_time": "ISO8601 (후보의 근거가 된 로그 중 가장 이른 시각)",
      "trigger_description": "한 줄 요약 (예: 'admin 계정 로그인 실패 다수 발생')",
      "confidence_initial": 0.0,
      "severity_hint": "LOW|MEDIUM|HIGH|CRITICAL",
      "priority": 1,
      "host": "로그에서 확인된 호스트명",
      "src_ip": "관련 IP가 있으면 기입, 없으면 null",
      "reasoning": "왜 이걸 후보로 뽑았는지 1문장 (조사 에이전트에게 넘길 초기 힌트)"
    }
  ]
}
"""


def build_seed_user_prompt(raw_logs: List[Dict[str, Any]], host: str) -> str:
    payload = {
        "host": host,
        "raw_log_count": len(raw_logs),
        "raw_logs": raw_logs,
    }
    return (
        "다음은 최근 수집된 정규화 로그 더미입니다. 이 안에서 심층 조사가 필요한 "
        "후보를 찾아 시스템 프롬프트의 JSON 스키마로 응답하십시오.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )