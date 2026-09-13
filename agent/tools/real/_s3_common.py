"""S3에서 NDJSON 형태로 쌓인 로그를 읽는 공용 헬퍼.

fetch_audit_log.py(agent/tools/real/)와 raw_log_ingestion.py(agent/) 양쪽에서
같은 S3 읽기 로직이 필요해서 여기로 분리했다. 시간 파싱/날짜 파티션 계산/NDJSON
읽기처럼 "S3 + 정규화 로그 스키마"에 관한 로직만 여기 둔다.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


def parse_iso(value: str) -> datetime:
    """'2026-09-09T10:05:45Z' 같은 문자열을 timezone-aware datetime으로 변환."""
    cleaned = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def daterange(start: datetime, end: datetime) -> List[str]:
    """start~end 사이에 걸치는 모든 dt=YYYY-MM-DD 파티션 문자열 목록 (자정 넘는 구간 대비)."""
    days = []
    cur = start.date()
    last = end.date()
    while cur <= last:
        days.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return days


def extract_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    for key in ("timestamp", "time", "@timestamp"):
        value = record.get(key)
        if isinstance(value, str):
            try:
                return parse_iso(value)
            except ValueError:
                continue
    return None


def list_and_read_ndjson(
    s3: Any,
    bucket: str,
    prefix: str,
) -> "tuple[List[Dict[str, Any]], int]":
    """prefix 아래 모든 오브젝트를 나열해서 NDJSON을 파싱해 반환.
    반환값: (파싱된 레코드 리스트, 스캔한 오브젝트 개수)

    주의: 실측 결과(S3 raw/ 폴더 직접 확인) auditd 로그는 NDJSON이 아니라
    정규화 이전의 raw 텍스트(type=SYSCALL 멀티라인 구조)로 확인됐다.
    audit 로그는 이 함수 대신 list_and_read_text() + fetch_audit_log.py의
    group_raw_audit_events()를 쓴다. 이 함수는 정말 NDJSON인 소스(예: Suricata
    eve.json처럼 원래부터 한 줄 = 이벤트 하나인 포맷)에만 쓴다.
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