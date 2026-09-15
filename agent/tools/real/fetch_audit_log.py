"""fetch_audit_log 실제 구현 - EC2에서 S3로 쌓인 auditd 로그를 읽어온다.

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_audit_log.py 안의 fetch_audit_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다. (agent/tools/real/README.md 참고)

*** 2026-09-13 업데이트: 팀원이 실측(EC2 audit.log 16,904건) 기반으로 만든
    정식 파서(_audit_parser.py)로 교체 ***
이전 버전은 "여러 줄을 사건 번호로 묶기만 하고, uid/session_type 같은 의미 해석은
전부 LLM에게 넘긴다"는 최소 파싱 방침이었다. 그런데 실제 audit.log가
ENRICHED 포맷(0x1d 구분자로 raw/enriched가 붙어있음)이라는 걸 팀원이 실측으로
확인하고 정식 파서를 만들었고, 이게 uid/euid/session_type/exec_args/target_file
까지 전부 구조화해서 뽑아낸다. 그래서 이제는 "많이 파싱해서 구조화된 필드로
LLM에 준다" 쪽으로 설계를 바꿨다 — 이쪽이 실측 기반이라 더 정확하다.

파싱 로직 자체(_audit_parser.py)는 raw_log_ingestion.py(수집 계층)도 같이 쓴다.
이 파일은 그 파서를 감싸서 "S3/로컬 소스 선택 + 우리 tool 인터페이스
(args dict → {count, summary, records})"만 담당한다.

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  (또는 로컬에 `aws configure`로 자격 증명을 세팅해뒀으면 .env에 안 넣어도 boto3가 알아서 씀)
  AUDIT_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 (AWS 키 없을 때) ***
.env에 AUDIT_LOG_LOCAL_PATH=sample_audit.log 처럼 넣어두면, S3를 아예 안 보고
그 로컬 파일을 읽어서 동일한 파싱/필터링 로직을 그대로 태운다. AWS 키가 생기면
.env에서 이 줄만 지우면 원래 S3 경로로 돌아간다.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

from ..parsers.audit_parser import parse_audit_events
from ._s3_common import daterange, list_and_read_text
from ..time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"


def _read_source_text(host: str, start: datetime, end: datetime) -> "tuple[str, int, str]":
    """AUDIT_LOG_LOCAL_PATH가 있으면 로컬 파일을, 없으면 S3를 읽는다.
    반환값: (전체 텍스트, 스캔한 오브젝트/파일 개수, 어디서 읽었는지 설명용 소스 라벨)
    """
    local_path = os.environ.get("AUDIT_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), 1, f"local:{local_path}"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("AUDIT_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    chunks: List[str] = []
    scanned_objects = 0
    for date_str in daterange(start, end):
        prefix = f"raw/source_type=auditd/host={host}/dt={date_str}/"
        text, count = list_and_read_text(s3, bucket, prefix)
        scanned_objects += count
        chunks.append(text)
    return "\n".join(chunks), scanned_objects, f"s3://{bucket}/raw/source_type=auditd/host={host}/"


def fetch_audit_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])

    text, scanned_objects, source_label = _read_source_text(host, start, end)

    events = parse_audit_events(
        text,
        log_name="audit.log",
        time_window=(args["start_time"], args["end_time"]),
        pid=args.get("pid"),
        ppid=args.get("ppid"),
        key=args.get("event_type"),  # 우리 tool schema의 event_type == 파서의 audit key
        serial=args.get("serial"),
        exclude_interactive=args.get("exclude_interactive", False),
    )

    # 파서 자체엔 user 필터가 없어서(공통스키마엔 user 필드가 있지만 필터 옵션이 아님) 후처리
    if "user" in args:
        events = [e for e in events if e.get("user") == args["user"]]

    if scanned_objects == 0:
        summary = (
            f"{source_label} 에서 {start.date()}~{end.date()} 구간에 데이터를 찾지 못했습니다. "
            "host 이름 또는 로컬 파일 경로가 맞는지 확인하세요."
        )
    else:
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 "
            f"({source_label}) 조건에 맞는 audit 이벤트 {len(events)}건 확인 "
            "(uid/euid/session_type/exec_args까지 구조화해서 반환)"
        )

    return {"count": len(events), "summary": summary, "records": events}