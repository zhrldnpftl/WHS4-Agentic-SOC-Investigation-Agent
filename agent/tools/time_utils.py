"""S3/로컬 여부와 무관하게 쓰이는 범용 시간 파싱 유틸.

원래 agent/tools/real/_s3_common.py 안에 있었는데, 이름 때문에 "S3 전용
함수"로 오해하기 쉬웠다 (실제로는 로컬 파일 모드에서도 항상 쓰이는 범용
유틸이었음 — parsers/*.py와 real/*.py 양쪽 다 이 함수가 필요해서, 어느 한쪽
서브패키지 안에 두면 반대쪽이 어색하게 그걸 import해야 하는 문제도 있었다).
그래서 agent/tools/ 바로 아래(real/도 parsers/도 아닌 공통 위치)로 분리했다.

2026-09-15: 실제 EC2 배포 중 Suricata의 콜론 없는 UTC 오프셋("+0000")을
Python 3.10에서 못 읽는 버그를 여기서 고쳤다 (Python 3.11+는 원래 읽을 수 있음).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Suricata 등 일부 소스는 UTC 오프셋을 "+0000"처럼 콜론 없이 준다. Python 3.11+의
# datetime.fromisoformat()은 이 형식도 읽지만, 3.10(예: EC2 기본 python3)은 못 읽고
# ValueError를 던진다 — 실제 EC2 배포 중 이 문제로 죽는 것을 발견해서 추가했다.
_OFFSET_NO_COLON_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso(value: str) -> datetime:
    """'2026-09-09T10:05:45Z' 또는 '...+0000'(콜론 없음) 같은 문자열을
    timezone-aware datetime으로 변환. Python 3.10에서도 동작하도록
    콜론 없는 오프셋은 콜론을 끼워넣어 정규화한다.
    """
    cleaned = value.replace("Z", "+00:00")
    cleaned = _OFFSET_NO_COLON_RE.sub(r"\1:\2", cleaned)
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt