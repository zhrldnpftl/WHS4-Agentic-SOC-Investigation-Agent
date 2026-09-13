"""fetch_web_log 실제 구현 - nginx access.log를 읽어온다 (S3 또는 로컬 파일).

*** 왜 apache가 아니라 nginx인가 ***
실측 결과(2026-09-13) EC2에는 apache2와 nginx가 둘 다 있는데, nginx가 앞단 리버스
프록시다. apache는 nginx 뒤에 있어서 src_ip가 항상 loopback(127.0.0.1)로 찍혀
공격자 IP를 알 수 없다 (팀이 Suricata 조인 키로 src_ip 대신 http.xff를 쓰기로 한
것도 같은 이유). 그래서 실제 클라이언트 IP가 찍히는 nginx access.log를 쓴다.

*** 파싱 방침: audit과 동일하게 최소한만 ***
nginx access.log는 한 줄 = 요청 하나라 auditd처럼 여러 줄을 묶을 필요는 없지만,
"이 줄이 어떤 의미인지"(정상 요청/공격 시도 등) 해석은 하지 않는다. 각 줄에서
IP·시각만 뽑아 시간 필터링에 쓰고, 나머지 해석(메서드/경로/상태코드가 뭘 의미하는지)은
raw_line 그대로 LLM에게 넘긴다.

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  WEB_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 ***
.env에 WEB_LOG_LOCAL_PATH=sample_web.log 넣어두면 S3 대신 그 파일을 읽는다.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ._s3_common import daterange, list_and_read_text, parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "nginx"  # 인프라팀 확정 시 실제 S3 source_type 값으로 교체

# nginx combined log 시작 부분: "203.0.113.45 - - [10/Sep/2026:10:01:12 +0000] ..."
_IP_PREFIX_RE = re.compile(r"^(\S+)\s")
_TIME_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})")


def _parse_nginx_time(line: str) -> Optional[datetime]:
    match = _TIME_RE.search(line)
    if not match:
        return None
    try:
        dt = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _extract_src_ip(line: str) -> Optional[str]:
    match = _IP_PREFIX_RE.match(line)
    return match.group(1) if match else None


def _matches_filters(line: str, args: Dict[str, Any]) -> bool:
    if "src_ip" in args and str(args["src_ip"]) not in line:
        return False
    # web 로그엔 pid/user 개념이 없어서, 있어도 무시 (요청하면 항상 통과)
    return True


def _read_source_text(host: str) -> "tuple[str, int, str]":
    local_path = os.environ.get("WEB_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("WEB_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    prefix = f"raw/source_type={S3_SOURCE_TYPE}/host={host}/dt={today}/"
    text, count = list_and_read_text(s3, bucket, prefix)
    return text, count, f"s3://{bucket}/{prefix}"


def fetch_web_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])

    text, scanned_objects, source_label = _read_source_text(host)

    matched: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        ts = _parse_nginx_time(line)
        if ts is not None and not (start <= ts <= end):
            continue
        if not _matches_filters(line, args):
            continue
        matched.append(
            {
                "time": ts.isoformat() if ts else None,
                "src_ip": _extract_src_ip(line),
                "raw_line": line,
            }
        )

    if scanned_objects == 0:
        summary = f"{source_label} 에서 데이터를 찾지 못했습니다. host/경로를 확인하세요."
    else:
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 ({source_label}) "
            f"조건에 맞는 web 요청 {len(matched)}건 확인"
        )

    return {"count": len(matched), "summary": summary, "records": matched}