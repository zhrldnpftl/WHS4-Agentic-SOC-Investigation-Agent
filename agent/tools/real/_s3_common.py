"""S3에서 로그를 읽는 공용 헬퍼 — 진짜 S3 전용 로직만 남긴다.

fetch_audit_log.py(agent/tools/real/)와 raw_log_ingestion.py(agent/) 양쪽에서
같은 S3 읽기 로직이 필요해서 여기로 분리했다.

(2026-09-13: auditd 멀티라인 그룹핑은 팀원이 만든 정식 파서로 교체되면서
_audit_parser.py로 옮겨갔다. 이 파일엔 더 이상 audit 전용 로직이 없다.)

(2026-09-15: parse_iso()를 agent/tools/time_utils.py로 옮겼다. 파일명이
"_s3_common"이라 S3 전용 함수만 있을 거라고 오해하기 쉬웠는데, parse_iso()는
로컬 파일 모드에서도 항상 쓰이는 범용 시간 파싱 유틸이라 이름과 실제 용도가
안 맞았다. 안 쓰이던 extract_timestamp()도 이 참에 같이 정리했다.)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List


def daterange(start: datetime, end: datetime) -> List[str]:
    """start~end 사이에 걸치는 모든 dt=YYYY-MM-DD 파티션 문자열 목록 (자정 넘는 구간 대비)."""
    days = []
    cur = start.date()
    last = end.date()
    while cur <= last:
        days.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return days


def list_and_read_ndjson(
    s3: Any,
    bucket: str,
    prefix: str,
) -> "tuple[List[Dict[str, Any]], int]":
    """prefix 아래 모든 오브젝트를 나열해서 NDJSON을 파싱해 반환.
    반환값: (파싱된 레코드 리스트, 스캔한 오브젝트 개수)

    정말 NDJSON인 소스(예: Suricata eve.json처럼 원래부터 한 줄 = 이벤트 하나인
    포맷)에만 쓴다. audit은 raw 텍스트라 list_and_read_text() + _audit_parser.py를 쓴다.
    """
    records: List[Dict[str, Any]] = []
    scanned_objects = 0

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            scanned_objects += 1
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            for line in body.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return records, scanned_objects


def list_and_read_text(
    s3: Any,
    bucket: str,
    prefix: str,
) -> "tuple[str, int]":
    """prefix 아래 모든 오브젝트를 나열해서 원본 텍스트 그대로 이어붙여 반환.
    JSON 파싱을 전혀 하지 않는다 — auditd처럼 정규화 이전의 raw 텍스트 로그용.
    반환값: (오브젝트들을 이어붙인 전체 텍스트, 스캔한 오브젝트 개수)
    """
    chunks: List[str] = []
    scanned_objects = 0

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            scanned_objects += 1
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            chunks.append(body.decode("utf-8", errors="replace"))

    return "\n".join(chunks), scanned_objects