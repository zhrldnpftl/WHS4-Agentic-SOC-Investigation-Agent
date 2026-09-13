"""fetch_auth_log 실제 구현 - /var/log/auth.log(syslog)를 읽어온다 (S3 또는 로컬 파일).

*** 파싱 방침: audit/web과 동일하게 최소한만 ***
syslog 형식(`Sep 9 10:05:30 web-01 sshd[3812]: Failed password ...`)은 연도가
없어서 정확한 절대시각 계산이 까다롭다. 지금은 시간 필터링을 시도하지 않고(줄
자체는 항상 반환), pid/user/src_ip는 문자열 검색으로만 거른다 — 정확한 해석은
LLM이 raw_line을 직접 읽고 판단한다. (audit/web과 동일한 "파싱 최소화" 원칙)

pid는 auditd처럼 "pid=1234"가 아니라 "sshd[1234]:"처럼 대괄호로 나오는 경우가
많아 두 형태를 다 검사한다.

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  AUTH_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 ***
.env에 AUTH_LOG_LOCAL_PATH=sample_auth.log 넣어두면 S3 대신 그 파일을 읽는다.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from ._s3_common import list_and_read_text

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "auth"  # 인프라팀 확정 시 실제 S3 source_type 값으로 교체


def _matches_filters(line: str, args: Dict[str, Any]) -> bool:
    if "pid" in args:
        pid = args["pid"]
        if f"pid={pid}" not in line and f"[{pid}]" not in line:
            return False
    if "user" in args and str(args["user"]) not in line:
        return False
    if "src_ip" in args and str(args["src_ip"]) not in line:
        return False
    return True


def _read_source_text(host: str) -> "tuple[str, int, str]":
    local_path = os.environ.get("AUTH_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("AUTH_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    prefix = f"raw/source_type={S3_SOURCE_TYPE}/host={host}/dt={today}/"
    text, count = list_and_read_text(s3, bucket, prefix)
    return text, count, f"s3://{bucket}/{prefix}"


def fetch_auth_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]

    text, scanned_objects, source_label = _read_source_text(host)

    matched: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not _matches_filters(line, args):
            continue
        matched.append({"time": None, "raw_line": line})

    if scanned_objects == 0:
        summary = f"{source_label} 에서 데이터를 찾지 못했습니다. host/경로를 확인하세요."
    else:
        summary = (
            f"{host}에서 ({source_label}) 조건에 맞는 인증 이벤트 {len(matched)}건 확인 "
            "(syslog 형식이라 연도 정보가 없어 시간 필터는 적용하지 않음)"
        )

    return {"count": len(matched), "summary": summary, "records": matched}