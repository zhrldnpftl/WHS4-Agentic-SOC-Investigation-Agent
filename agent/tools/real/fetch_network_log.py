"""fetch_network_log 실제 구현 - Suricata eve.json을 읽어온다 (S3 또는 로컬 파일).

*** 다른 3개 tool과 다른 점: eve.json은 이미 진짜 JSON이다 ***
audit/web/auth는 raw 텍스트라 파싱을 최소화했지만, Suricata eve.json은 원래부터
"한 줄 = JSON 이벤트 하나"인 정형 포맷이다. 그래서 json.loads()로 파싱하는 것 자체는
"정보를 지어내는 해석"이 아니라 이미 있는 구조를 그대로 읽는 것이라 문제없이 한다.
다만 alert.signature가 실제로 뭘 의미하는지, src_ip가 위협인지 같은 "의미 해석"은
여기서 하지 않고 LLM에게 그대로 넘긴다 (같은 원칙 유지).

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  NETWORK_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 ***
.env에 NETWORK_LOG_LOCAL_PATH=sample_network.log 넣어두면 S3 대신 그 파일을 읽는다.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ._s3_common import list_and_read_text, parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "suricata"


def _extract_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    value = record.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        # eve.json 타임스탬프 예: "2026-09-13T04:19:00.123456+0000"
        cleaned = value.replace("+0000", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _matches_filters(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    if "src_ip" in args and record.get("src_ip") != args["src_ip"]:
        return False
    if "event_type" in args and record.get("event_type") != args["event_type"]:
        return False
    return True


def _read_source_text(host: str) -> "tuple[str, int, str]":
    local_path = os.environ.get("NETWORK_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("NETWORK_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    prefix = f"raw/source_type={S3_SOURCE_TYPE}/host={host}/dt={today}/"
    text, count = list_and_read_text(s3, bucket, prefix)
    return text, count, f"s3://{bucket}/{prefix}"


def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])

    text, scanned_objects, source_label = _read_source_text(host)

    matched: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts = _extract_timestamp(record)
        if ts is not None and not (start <= ts <= end):
            continue
        if not _matches_filters(record, args):
            continue
        matched.append(record)

    if scanned_objects == 0:
        summary = f"{source_label} 에서 데이터를 찾지 못했습니다. host/경로를 확인하세요."
    else:
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 ({source_label}) "
            f"조건에 맞는 네트워크 이벤트 {len(matched)}건 확인"
        )

    return {"count": len(matched), "summary": summary, "records": matched}