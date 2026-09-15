"""raw log ingestion — seed 생성(경량 LLM triage) 전용 데이터 소스.

agent/tools/real/fetch_*.py들은 "이미 seed가 있고, 그 seed를 검증하기 위해
특정 조건(호스트+시간+필터)으로 좁혀서 조회"하는 조사 단계용 도구다.

이 모듈은 그 이전 단계다 — 아직 seed가 없는 상태에서, 최근 N분 동안 쌓인
web/auth/audit/network 로그를 필터 없이 통째로 긁어와서 LLM(seed_generation.py)에게
"여기서 수상한 거 있어?"라고 물어볼 재료를 만든다.

*** S3 raw 데이터 실측 결과 반영 (2026-09-13/14) ***
auditd 로그는 NDJSON이 아니라 정규화 이전의 raw 텍스트(ENRICHED 포맷 + 멀티라인
구조)로 확인됐다. audit 소스는 agent/tools/parsers/audit_parser.py의
parse_audit_events()(팀원이 실측 기반으로 만든 정식 파서)를 재사용해서
uid/euid/session_type/exec_args까지 구조화된 이벤트로 만든다. web 소스는
처음엔 web tool 담당 팀원의 apache_parser.py(공백 구분 14필드)를 썼는데, 실제
sample_web.log가 그 형식이 아니라 한 줄 = JSON 객체인 nginx JSON 로그로
확인돼서(2026-09-14) agent/tools/parsers/nginx_json_parser.py(실측 기반으로
새로 작성)로 교체했다. auth 소스도 agent/tools/parsers/auth_parser.py의
parse_auth_events()(auth tool 담당 팀원이 실제 auth.log로 만든 정식 파서)를
재사용해서 ssh_login/sudo/pam 이벤트로 구조화한다. network 소스도
agent/tools/parsers/network_parser.py의 parse_network_events()(조사 단계의
fetch_network_log.py와 동일한 파서)를 재사용해서 src/dst ip·port, protocol,
alert_signature까지 구조화한다 — 4계층 전부 조사 단계와 동일한 파서를 쓰는
상태다.

*** 현재 한계 ***
팀 결정사항 기준으로 S3 로그 수집이 실제로 켜져 있다고 확인된 건 auditd(audit) 뿐이다.
web/auth/network 파티션에 아직 데이터가 없으면 그냥 빈 리스트로 조용히 넘어간다
(에러 아님) — 인프라팀이 나머지도 연결하면 자동으로 같이 잡힌다.

*** 로컬 테스트 모드 ***
agent/tools/real/fetch_*.py와 동일한 환경변수(WEB_LOG_LOCAL_PATH,
AUTH_LOG_LOCAL_PATH, AUDIT_LOG_LOCAL_PATH, NETWORK_LOG_LOCAL_PATH)가 있으면
S3 대신 그 로컬 파일을 읽는다. AWS 키가 생기면 .env에서 이 줄들만 지우면 된다.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .tools.parsers.audit_parser import parse_audit_events
from .tools.parsers.auth_parser import parse_auth_events
from .tools.parsers.network_parser import parse_network_events
from .tools.parsers.nginx_json_parser import nginx_ts_to_dt, parse_nginx_json_line
from .tools.real._s3_common import daterange, list_and_read_text
from .tools.time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"

# S3 경로의 source_type= 값과, 결과 레코드에 태그로 남길 이름을 매핑.
SOURCE_TYPES = {
    "web": "nginx",
    "auth": "auth",
    "audit": "auditd",
    "network": "suricata",
}

# agent/tools/real/fetch_*.py와 동일한 이름의 로컬 대체 환경변수.
LOCAL_PATH_ENV = {
    "web": "WEB_LOG_LOCAL_PATH",
    "auth": "AUTH_LOG_LOCAL_PATH",
    "audit": "AUDIT_LOG_LOCAL_PATH",
    "network": "NETWORK_LOG_LOCAL_PATH",
}


def _events_from_text(source_key: str, text: str) -> List[Dict[str, Any]]:
    """소스 타입별로 raw 텍스트를 이벤트 단위 레코드로 가공한다.
    반환되는 각 이벤트는 내부 필터링용 "_ts"(datetime|None)를 포함한다 — 호출자가
    시간 범위로 거른 뒤 제거해야 한다.
    """
    if source_key == "audit":
        events = parse_audit_events(text)  # 필터 없이 전부 — 시간 필터는 이 함수 밖에서 적용
        for e in events:
            ts_str = e.get("timestamp")
            e["_ts"] = parse_iso(ts_str) if ts_str else None
        return events

    if source_key == "web":
        events = []
        for line in text.split("\n"):  # JSON 한 줄씩이라 split("\n")로 통일
            if not line.strip():
                continue
            event = parse_nginx_json_line(line)
            if event is None:
                continue
            dt = nginx_ts_to_dt(event.get("timestamp"))
            event["_ts"] = dt
            events.append(event)
        return events

    if source_key == "auth":
        # syslog는 연도가 없어서 "지금"의 연도를 기준으로 삼는다 (연말/연초 경계 한계 있음).
        events = parse_auth_events(text, reference_year=datetime.now(timezone.utc).year)
        for e in events:
            ts_str = e.get("timestamp")
            e["_ts"] = parse_iso(ts_str) if ts_str else None
        return events

    if source_key == "network":
        events = parse_network_events(text)  # 필터 없이 전부 — 시간 필터는 이 함수 밖에서 적용
        for e in events:
            ts_str = e.get("timestamp")
            e["_ts"] = parse_iso(ts_str) if ts_str else None
        return events

    # 여기 도달하면 알 수 없는 source_key다 (지금은 4계층 다 위에서 처리되므로
    # 실제로는 호출될 일이 없다) — 안전하게 빈 리스트를 반환한다.
    return []


def _read_layer_text(
    source_key: str,
    s3_source_type: str,
    host: str,
    bucket: str,
    start: datetime,
    end: datetime,
) -> str:
    """이 계층의 로컬 대체 경로가 있으면 그 파일을, 없으면 S3를 읽는다.
    로컬 파일일 때는 RAW_LOG_LOCAL_MAX_LINES(기본 30)만큼 마지막 줄만 잘라서
    반환한다 — 안 자르면 무료 티어 분당 토큰 한도(429 에러)를 바로 넘긴다.
    """
    local_path = os.environ.get(LOCAL_PATH_ENV[source_key])
    if local_path:
        if not os.path.exists(local_path):
            return ""
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        max_lines = int(os.environ.get("RAW_LOG_LOCAL_MAX_LINES", "30"))
        lines = [line for line in text.splitlines() if line.strip()]
        return "\n".join(lines[-max_lines:])

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))
    chunks: List[str] = []
    for date_str in daterange(start, end):
        prefix = f"raw/source_type={s3_source_type}/host={host}/dt={date_str}/"
        text, _ = list_and_read_text(s3, bucket, prefix)
        chunks.append(text)
    return "\n".join(chunks)


def fetch_recent_raw_logs(
    host: str,
    minutes: int = 10,
    source_types: Optional[List[str]] = None,
    bucket: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """최근 `minutes`분 동안의 raw log를 source_type 구분 없이 전부 긁어온다.

    반환되는 각 레코드에는 어느 소스에서 왔는지 알 수 있도록 "_source_type" 키를
    덧붙인다 (원본 필드와 충돌하지 않도록 언더스코어 프리픽스 사용).
    """
    source_types = source_types or list(SOURCE_TYPES.keys())
    bucket = bucket or os.environ.get("AUDIT_LOG_BUCKET", DEFAULT_BUCKET)

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)

    all_records: List[Dict[str, Any]] = []

    for source_key in source_types:
        # 로컬 샘플 모드(*_LOCAL_PATH)일 땐 "진짜 지금 기준 최근 N분" 필터를 끈다.
        # 샘플 로그는 실제 과거 시각(예: 2026-09-13 새벽)을 그대로 담고 있어서,
        # 이 필터를 그대로 적용하면 "지금(실행 시점)으로부터 10분 이내"가 아니라서
        # audit/web/auth가 실제 타임스탬프를 갖게 된 뒤로 전부 걸러져 버린다.
        # 로컬 모드에선 RAW_LOG_LOCAL_MAX_LINES(마지막 N줄)가 이미 "관심 구간"을
        # 정하는 역할을 하므로, 절대 시각 필터는 S3(실운영) 모드에서만 의미가 있다.
        is_local_mode = bool(os.environ.get(LOCAL_PATH_ENV[source_key]))

        s3_source_type = SOURCE_TYPES.get(source_key, source_key)
        text = _read_layer_text(source_key, s3_source_type, host, bucket, start, end)
        for record in _events_from_text(source_key, text):
            ts = record.pop("_ts", None)
            if not is_local_mode and ts is not None and not (start <= ts <= end):
                continue
            record["_source_type"] = source_key
            all_records.append(record)

    return all_records