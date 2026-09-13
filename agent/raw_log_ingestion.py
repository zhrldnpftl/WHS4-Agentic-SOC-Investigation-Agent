"""raw log ingestion — seed 생성(경량 LLM triage) 전용 데이터 소스.

agent/tools/real/fetch_*.py들은 "이미 seed가 있고, 그 seed를 검증하기 위해
특정 조건(호스트+시간+필터)으로 좁혀서 조회"하는 조사 단계용 도구다.

이 모듈은 그 이전 단계다 — 아직 seed가 없는 상태에서, 최근 N분 동안 쌓인
web/auth/audit/network 로그를 필터 없이 통째로 긁어와서 LLM(seed_generation.py)에게
"여기서 수상한 거 있어?"라고 물어볼 재료를 만든다.

*** S3 raw 데이터 실측 결과 반영 (2026-09-13) ***
auditd 로그는 NDJSON이 아니라 정규화 이전의 raw 텍스트(멀티라인 구조)로 확인됐다.
그래서 audit 소스는 fetch_audit_log.py의 group_raw_audit_events()를 그대로 재사용해서
같은 방식(최소한의 그룹핑만, 필드 해석은 LLM에게)으로 처리한다. web/auth/network는
아직 실제 데이터로 검증되지 않았으므로, 일단 원시 텍스트를 줄 단위로만 넘기는 보수적인
방식으로 처리한다 — 실제 포맷이 확인되면 그에 맞게 고치면 된다.

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

from .tools.real._s3_common import daterange, list_and_read_text
from .tools.real.fetch_audit_log import group_raw_audit_events

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
    """소스 타입별로 raw 텍스트를 이벤트 단위 레코드로 최소 가공한다.
    (구조화된 필드 추출은 하지 않는다 — 해석은 LLM 몫)
    반환되는 각 이벤트는 내부 필터링용 "_ts"(datetime|None)를 포함한다 — 호출자가
    시간 범위로 거른 뒤 제거해야 한다.
    """
    if source_key == "audit":
        return group_raw_audit_events(text)

    # web/auth/network: 실제 포맷 미확인 상태라 우선 줄 단위로만 넘긴다.
    # 아직 타임스탬프를 뽑아내는 규칙이 없어 _ts=None으로 두고, 시간 필터를 건너뛴다
    # (실제 포맷이 확인되면 여기서 timestamp를 파싱해 채우면 된다).
    return [
        {"time": None, "raw_line": line, "_ts": None}
        for line in text.splitlines()
        if line.strip()
    ]


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
        s3_source_type = SOURCE_TYPES.get(source_key, source_key)
        text = _read_layer_text(source_key, s3_source_type, host, bucket, start, end)
        for record in _events_from_text(source_key, text):
            ts = record.pop("_ts", None)
            if ts is not None and not (start <= ts <= end):
                continue
            record["_source_type"] = source_key
            all_records.append(record)

    return all_records