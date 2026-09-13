"""fetch_audit_log 실제 구현 - EC2에서 S3로 쌓인 auditd 로그를 읽어온다.

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_audit_log.py 안의 fetch_audit_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다. (agent/tools/real/README.md 참고)

*** 중요: S3 raw 데이터 실측 결과 반영 (2026-09-13) ***
S3의 raw/source_type=auditd/host=<host>/dt=YYYY-MM-DD/ 아래 파일은 NDJSON이 아니라
정규화 이전의 raw auditd 원본 그대로다 (type=SYSCALL/type=CWD/type=PATH/type=PROCTITLE가
여러 줄에 걸쳐 하나의 이벤트를 이룸, EXECVE/PROCTITLE 값은 hex 인코딩). 인프라팀의
정규화 파이프라인이 아직 이 데이터에 붙지 않은 상태로 확인됨(버킷에 raw/만 있고
processed/ 등은 없음).

*** 설계 방향: 파싱은 최소한만, 해석은 에이전트(LLM)에게 ***
이 tool은 uid/euid/session_type 같은 필드를 Python으로 직접 파싱해서 추출하지 않는다.
그 대신:
  1. 같은 이벤트에 속한 여러 줄(type=SYSCALL/CWD/PATH/PROCTITLE...)을 audit ID
     (예: audit(1694246745.123:5001)의 ":5001" 부분)로만 묶고
  2. 그 raw 텍스트 블록을 그대로 evidence 후보로 반환한다.
uid/euid/session_type 등 의미 해석(예: "이건 www-data의 non-interactive 세션이다")은
agent/prompts.py의 지시에 따라 LLM이 raw_block 텍스트를 직접 읽고 판단하게 한다.
이렇게 하면 정규화 스키마가 나중에 바뀌거나, 인프라팀 정규화가 완성되기 전이라도
이 tool을 고칠 필요가 없다. (scripts/local_e2e_test.py에서 검증한 것과 같은 설계)

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  (또는 로컬에 `aws configure`로 자격 증명을 세팅해뒀으면 .env에 안 넣어도 boto3가 알아서 씀)
  AUDIT_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 (AWS 키 없을 때) ***
.env에 AUDIT_LOG_LOCAL_PATH=sample_audit.log 처럼 넣어두면, S3를 아예 안 보고
그 로컬 파일을 읽어서 동일한 파싱/필터링 로직을 그대로 태운다. 이 tool 파일 자체가
로컬/S3 양쪽 다 지원하므로, scripts/ 안에 별도 "가짜 tool"을 만들 필요가 없다 —
AWS 키가 생기면 .env에서 이 줄만 지우면 원래 S3 경로로 돌아간다.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ._s3_common import daterange, list_and_read_text, parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"

# audit(1694246745.123:5001) 형태에서 (초.밀리초, serial번호)를 뽑는다.
_AUDIT_ID_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")


def group_raw_audit_events(text: str) -> List[Dict[str, Any]]:
    """raw auditd 텍스트를 audit ID(serial) 기준으로 묶어 이벤트 단위 리스트로 만든다.

    파싱은 "같은 이벤트인지 아닌지"와 "시간이 언제인지"까지만 한다. exe/comm/uid 같은
    필드 값 해석은 절대 여기서 하지 않는다 — raw_block을 통째로 넘겨서 LLM이 읽게 한다.
    """
    groups: Dict[str, List[str]] = {}
    order: List[str] = []

    for line in text.splitlines():
        match = _AUDIT_ID_RE.search(line)
        if not match:
            continue
        audit_id = f"{match.group(1)}.{match.group(2)}:{match.group(3)}"
        if audit_id not in groups:
            groups[audit_id] = []
            order.append(audit_id)
        groups[audit_id].append(line)

    events: List[Dict[str, Any]] = []
    for audit_id in order:
        epoch_str = audit_id.split(":")[0]
        try:
            ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
            time_iso: Optional[str] = ts.isoformat()
        except (ValueError, OSError):
            ts = None
            time_iso = None

        events.append(
            {
                "audit_id": audit_id,
                "time": time_iso,
                "raw_block": "\n".join(groups[audit_id]),
                "_ts": ts,  # 내부 필터링용, 반환 직전에 제거
            }
        )
    return events


def _matches_filters(raw_block: str, args: Dict[str, Any]) -> bool:
    """optional_args(pid/user/event_type)를 raw 텍스트에 대한 단순 문자열 검색으로 적용.
    구조화된 필드 추출을 안 하므로 정교하진 않지만, "이 블록에 그 값이 등장하는가" 정도의
    거친 필터로 충분하다 — 정확한 해석은 LLM이 evidence로 정리할 때 한다.
    """
    if "pid" in args and f"pid={args['pid']}" not in raw_block:
        return False
    if "user" in args and str(args["user"]) not in raw_block:
        return False
    if "event_type" in args and f'key="{args["event_type"]}"' not in raw_block:
        return False
    return True


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

    matched: List[Dict[str, Any]] = []
    for event in group_raw_audit_events(text):
        ts = event.pop("_ts")
        if ts is not None and not (start <= ts <= end):
            continue
        if not _matches_filters(event["raw_block"], args):
            continue
        matched.append(event)

    if scanned_objects == 0:
        summary = (
            f"{source_label} 에서 {start.date()}~{end.date()} 구간에 데이터를 찾지 못했습니다. "
            "host 이름 또는 로컬 파일 경로가 맞는지 확인하세요."
        )
    else:
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 "
            f"({source_label}) 조건에 맞는 audit 이벤트 {len(matched)}건 확인 "
            "(raw 텍스트 그대로, 해석은 에이전트가 수행)"
        )

    return {"count": len(matched), "summary": summary, "records": matched}

