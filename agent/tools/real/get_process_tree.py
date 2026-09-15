"""get_process_tree 실제 구현 - audit 이벤트의 pid/ppid로 조상 체인을 추적한다.

파일명 == 함수명 규칙에 따라 agent/tools/real/get_process_tree.py 안의
get_process_tree 함수만 있으면 agent/tools/registry.py의 build_default_registry()가
자동으로 이 함수를 mock_tools.py 대신 사용한다.

*** 2026-09-14: 드디어 실제 구현 완성 ***
이전엔 "살아있는 프로세스 상태가 필요해서 정적 로그로 흉내내기 어렵다"고 보류했던
도구다. 팀원이 만든 get_process_tree.py(독립 배포용)를 보고, audit 로그 자체에
pid/ppid가 이미 들어있어서(팀원이 만든 audit_parser.py로 이미 구조화해둔 값)
"살아있는 프로세스 목록"이 아니라 "과거에 관측된 pid/ppid 관계를 되짚는" 방식으로
가능하다는 걸 확인해서 완성했다. 그래서 fetch_audit_log.py와 정확히 같은 audit
로그 소스(S3/로컬)를 그대로 읽고, agent/tools/parsers/audit_parser.py로 파싱한 뒤
agent/tools/parsers/process_tree.py로 조상 체인만 추가로 추적한다.

*** 주의: "확정된 프로세스 생성 트리"가 아니라 "관측 기반 후보"다 ***
audit 로그에 그 pid의 syscall이 안 찍혀 있으면(로그 보관 기간 밖이거나, 아직 조회
범위에 없으면) 부모를 못 찾는다. PID는 재사용될 수 있어서, 같은 pid라도 시간이
멀리 떨어진 별개의 관측이 잘못 이어질 위험도 있다 — 그래서 이 tool의 결과에는
warnings에 이런 한계를 항상 명시한다.

필요 환경변수: fetch_audit_log.py와 동일 (AWS_ACCESS_KEY_ID 등, AUDIT_LOG_BUCKET)
로컬 테스트: .env에 AUDIT_LOG_LOCAL_PATH=sample_audit.log (fetch_audit_log.py와 공유)
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from ..parsers.audit_parser import parse_audit_events
from ..parsers.process_tree import build_ancestry_chain
from ._s3_common import daterange, list_and_read_text
from ..time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
DEFAULT_LOOKBACK_HOURS = 24  # 조상을 찾을 때 얼마나 과거까지 audit 로그를 훑을지


def _read_source_text(host: str, start: datetime, end: datetime) -> "tuple[str, int, str]":
    """fetch_audit_log.py와 동일한 소스(AUDIT_LOG_LOCAL_PATH 또는 S3)를 읽는다."""
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
    return (
        "\n".join(chunks),
        scanned_objects,
        f"s3://{bucket}/raw/source_type=auditd/host={host}/",
    )


def get_process_tree(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    pid = int(args["pid"])

    # timestamp(특정 시점) 또는 start_time/end_time(범위) 중 하나로 조회 구간을 잡는다.
    # 아무것도 안 주면 "이 tool이 fetch_audit_log와 같은 소스를 볼 수 있는 최대
    # 범위"로 넓게 잡는다 — 로컬 샘플 모드에선 어차피 파일 하나가 전부라 큰 의미
    # 없고, S3 모드에서 실제로 유효해진다.
    if "start_time" in args and "end_time" in args:
        start = parse_iso(args["start_time"])
        end = parse_iso(args["end_time"])
    elif "timestamp" in args:
        anchor = parse_iso(args["timestamp"])
        start = anchor - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
        end = anchor
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=DEFAULT_LOOKBACK_HOURS)

    text, scanned_objects, source_label = _read_source_text(host, start, end)

    events = parse_audit_events(text)  # 필터 없이 전부 파싱해서 pid/ppid 관계를 다 확보

    chain = build_ancestry_chain(events, target_pid=pid)

    if scanned_objects == 0:
        summary = (
            f"{source_label} 에서 데이터를 찾지 못했습니다. host 이름 또는 로컬 파일 경로를 확인하세요."
        )
        return {"count": 0, "summary": summary, "records": []}

    if chain is None:
        summary = f"pid={pid}에 대한 audit 관측 기록을 이 조회 구간에서 찾지 못했습니다."
        return {"count": 0, "summary": summary, "records": []}

    summary = (
        f"pid={pid}의 조상 체인 추적 완료: {chain['chain']} "
        f"(상태: {chain['lineage_status']}, 근거: 관측된 audit syscall 기반 — "
        "확정된 프로세스 생성 트리가 아닌 후보임)"
    )

    return {"count": 1, "summary": summary, "records": [chain]}