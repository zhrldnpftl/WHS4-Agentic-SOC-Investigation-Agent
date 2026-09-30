"""조사 에이전트 설정 읽기 — 저장소 루트 .env 하나 + INVESTIGATION_ 접두어 규칙.

역할
  - load_root_env(): 저장소 루트 .env를 경로로 직접 읽는다. 예전처럼 파일 위치에서 위로 찾으면
    llm/investigate/.env가 있을 때 그것만 읽혀 설정이 두 곳으로 나뉘었다. 1차 탐지·조사가 한 서버에서
    같은 루트 .env를 쓴다(EC2도 루트 .env 하나). llm/investigate/.env가 있으면 읽지 않고 안내만 한다.
  - investigation_setting(name): LLM 설정은 역할(llm/ 아래 폴더)별 접두어로 나눈다. 조사 에이전트는
    INVESTIGATION_<name>만 읽는다. 접두어 없는 옛 이름(CLAUDE_MODEL 등)은 루트 .env를 함께 쓰는 다른 역할의
    설정과 섞이지 않게 **읽지 않고**, 남아 있으면 "새 이름으로 옮기라"는 안내를 이름만 넣어 한 번 출력한다
    (값은 출력하지 않는다). API 키만 역할 키가 비었을 때 공용 ANTHROPIC_API_KEY로 넘어간다(claude_client.py).

누가 부르나
  main.py, scripts/verify_all_tools.py, tests/test_consistency.py   → load_root_env()
  agent/llm_provider.py, claude_client.py, gemini_client.py         → investigation_setting()
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Set

# llm/investigate/agent/settings.py → 저장소 루트
REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_ENV_FILE = REPO_ROOT / ".env"
IGNORED_ENV_FILE = REPO_ROOT / "llm" / "investigate" / ".env"

PREFIX = "INVESTIGATION_"
# 조사 에이전트가 예전에 접두어 없이 읽던 LLM 설정 이름 — 이제 INVESTIGATION_<이름>만 읽는다
LEGACY_NAMES = ("LLM_PROVIDER", "CLAUDE_MODEL", "CLAUDE_EFFORT", "CLAUDE_REFUSAL_FALLBACK_MODEL", "GEMINI_MODEL")

_notified: Set[str] = set()


def load_root_env() -> bool:
    """저장소 루트 .env를 읽는다(이미 설정된 환경변수는 덮어쓰지 않음). 파일이 있어 읽었으면 True."""
    from dotenv import load_dotenv

    if IGNORED_ENV_FILE.exists():
        print(f"[설정] {IGNORED_ENV_FILE}는 읽지 않습니다 — 조사 에이전트 설정은 저장소 루트 .env에 둡니다")
    return load_dotenv(ROOT_ENV_FILE)


def investigation_setting(name: str) -> Optional[str]:
    """INVESTIGATION_<name> 값(빈 값은 None). 옛 이름 <name>은 읽지 않고, 남아 있으면 이름만 안내한다."""
    if name in LEGACY_NAMES and name in os.environ and name not in _notified:
        _notified.add(name)
        print(f"[설정] {name}는 조사 에이전트에서 읽지 않습니다 — 조사용 값은 {PREFIX}{name}에 두십시오")
    value = (os.environ.get(PREFIX + name) or "").strip()
    return value or None
