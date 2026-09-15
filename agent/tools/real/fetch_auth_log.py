"""fetch_auth_log 실제 구현 - EC2의 auth.log(syslog)를 읽어온다.

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_auth_log.py 안의 fetch_auth_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다.

*** 2026-09-14 업데이트: 팀원(auth tool 담당)이 실제 auth.log로 만든
    정식 파서(parsers/auth_parser.py)로 교체 ***
audit/web과 같은 패턴: 파싱 로직(정규식 분류)은 팀원이 만든 걸 그대로 쓰고
(parsers/auth_parser.py), 이 파일은 그걸 감싸서 S3/로컬 소스 선택 + 우리 tool
인터페이스(args dict → {count, summary, records})만 담당한다.

*** limit/offset 페이지네이션 채택 ***
실제 auth.log는 SSH 브루트포스 하나로도 399건씩 매칭될 수 있다(직접 확인함).
한 번에 다 반환하면 LLM 컨텍스트가 커지므로, 팀원이 설계한 limit/offset 방식을
그대로 채택했다 — 결과가 많으면 has_more/next_offset을 보고 LLM이 필요하면
next_offset으로 이어서 더 조회할 수 있다. (다른 3개 tool은 결과가 상대적으로
적어서 아직 페이지네이션이 없다 — 필요해지면 같은 방식으로 추가하면 된다.)

*** syslog 연도 한계 ***
auth.log(syslog)엔 연도가 없어서, 조사 요청의 start_time 연도를 reference_year로
써서 절대 시각을 복원한다. 연말/연초 경계를 걸친 조회는 정확하지 않을 수 있다.

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  AUTH_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 (AWS 키 없을 때) ***
.env에 AUTH_LOG_LOCAL_PATH=sample_auth.log 처럼 넣어두면, S3를 아예 안 보고
그 로컬 파일을 읽는다. AWS 키가 생기면 .env에서 이 줄만 지우면 원래 S3 경로로
돌아간다.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

from ..parsers.auth_parser import parse_auth_events
from ._s3_common import daterange, list_and_read_text
from ..time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "auth"
DEFAULT_LIMIT = 200


def _read_source_text(host: str, start: datetime, end: datetime) -> "tuple[str, int, str]":
    """AUTH_LOG_LOCAL_PATH가 있으면 로컬 파일을, 없으면 S3를 읽는다."""
    local_path = os.environ.get("AUTH_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("AUTH_LOG_BUCKET", DEFAULT_BUCKET)
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


def fetch_auth_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])
    limit = int(args.get("limit", DEFAULT_LIMIT))
    offset = int(args.get("offset", 0))

    text, scanned_objects, source_label = _read_source_text(host, start, end)

    all_events = parse_auth_events(
        text,
        reference_year=start.year,
        time_window=(start, end),
        source_ip=args.get("src_ip"),
        user=args.get("user"),
        event_type=args.get("event_type"),
        result=args.get("result"),
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
            f"조건에 맞는 인증 이벤트 총 {total_matched}건 중 {page_desc} {len(page)}건 반환. "
            f"({more_desc}, event_type/result까지 구조화)"
        )

    return {
        "count": len(page),
        "summary": summary,
        "records": page,
        "total_matched": total_matched,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }