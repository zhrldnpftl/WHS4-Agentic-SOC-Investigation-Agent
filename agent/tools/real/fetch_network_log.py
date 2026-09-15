"""fetch_network_log 실제 구현 - Suricata eve.json을 읽어온다 (S3 또는 로컬 파일).

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_network_log.py 안의
fetch_network_log 함수만 있으면 agent/tools/registry.py의 build_default_registry()가
자동으로 이 함수를 mock_tools.py 대신 사용한다.

*** 2026-09-14 업데이트: 팀원이 만든 독립 배포용 fetch_network_log.py에서
    핵심 필터링 로직을 뽑아 parsers/network_parser.py로 만들고 그걸 감쌌다 ***
audit/web/auth와 같은 패턴: 파싱/필터링 로직은 팀원이 만든 걸 기반으로 하고
(parsers/network_parser.py), 이 파일은 S3/로컬 소스 선택 + 우리 tool 인터페이스
(args dict → {count, summary, records})만 담당한다.

원본과 달리 direction(internal/outbound/inbound) 계산은 안 한다 — 자세한 이유는
parsers/network_parser.py 상단 주석 참고 (호스트 IP 사전 등록 단계가 우리
시스템엔 없음).

*** limit/offset 페이지네이션 채택 (auth와 동일한 이유) ***

필요 환경변수: AWS_ACCESS_KEY_ID 등 + NETWORK_LOG_BUCKET (기본값 ogwanwan-shop-bucket)
로컬 테스트: .env에 NETWORK_LOG_LOCAL_PATH=sample_network.log
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

from ..parsers.network_parser import parse_network_events
from ._s3_common import daterange, list_and_read_text
from ..time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "suricata"
DEFAULT_LIMIT = 200


def _read_source_text(host: str, start: datetime, end: datetime) -> "tuple[str, int, str]":
    local_path = os.environ.get("NETWORK_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("NETWORK_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    chunks: List[str] = []
    scanned_objects = 0
    for date_str in daterange(start, end):
        prefix = f"raw/source_type={S3_SOURCE_TYPE}/host={host}/dt={date_str}/"
        text, count = list_and_read_text(s3, bucket, prefix)
        scanned_objects += count
        chunks.append(text)
    return (
        "\n".join(chunks),
        scanned_objects,
        f"s3://{bucket}/raw/source_type={S3_SOURCE_TYPE}/host={host}/",
    )


def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])
    limit = int(args.get("limit", DEFAULT_LIMIT))
    offset = int(args.get("offset", 0))

    text, scanned_objects, source_label = _read_source_text(host, start, end)

    all_events = parse_network_events(
        text,
        time_window=(start, end),
        src_ip=args.get("src_ip"),
        dst_ip=args.get("dst_ip"),
        src_port=args.get("src_port"),
        dst_port=args.get("dst_port"),
        protocol=args.get("protocol"),
        alert_only=bool(args.get("alert_only", False)),
    )

    total_matched = len(all_events)
    page = all_events[offset : offset + limit]
    has_more = (offset + limit) < total_matched

    if scanned_objects == 0:
        summary = (
            f"{source_label} 에서 {start.date()}~{end.date()} 구간에 데이터를 찾지 못했습니다. "
            "host 이름 또는 로컬 파일 경로가 맞는지 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={offset + limit})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 ({source_label}) "
            f"조건에 맞는 네트워크 이벤트 총 {total_matched}건 중 {page_desc} {len(page)}건 반환. "
            f"({more_desc})"
        )

    return {
        "count": len(page),
        "summary": summary,
        "records": page,
        "total_matched": total_matched,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }