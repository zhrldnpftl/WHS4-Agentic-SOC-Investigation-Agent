"""로그 읽기·정규화 공용 계층 — 조사 도구들이 같은 경로로 로그를 읽게 한다.

역할
  .env의 계층별 로그 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH) 파일과 그 교체 파일(.1, .N.gz)을 원본 그대로(파일명·줄 번호 보존) 읽고, 1차 탐지팀 공통 정규화로
  구조화한 뒤 조회 구간 안의 이벤트만 돌려준다. 페이지네이션 인자 검사, 0건일 때 LLM에게 줄 안내문도
  여기서 만든다. 탐지 규칙이나 판정은 하지 않는다.

누가 부르나
  [33] agent/tools/real/fetch_*_log.py, get_process_tree.py → load_window_events(), pagination(), filtered_out_hint()
  agent/tools/real/fetch_event_logs.py        → event_time(), pagination(), query_window()

무엇을 부르나
  [34] agent/tools/normalizer_adapter.py normalize_log_documents()  → 1차 탐지팀 정규화 함수
  agent/tools/normalizer_adapter.py resolve_log_files()             → 1차 탐지팀 교체 로그 찾기
  agent/tools/time_utils.py parse_iso()
"""
from __future__ import annotations

import os
import gzip
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .normalizer_adapter import normalize_log_documents, resolve_log_files
from .time_utils import parse_iso

SOURCE_TYPES = {"web": "apache", "auth": "auth", "audit": "auditd", "network": "suricata"}
# 계층별 로그 경로 환경변수. 1차 탐지(run_pipeline.py)와 같은 이름을 써서 한 서버에서 .env 하나로 함께 돈다
# (2026-09-27 변경: 예전 이름은 WEB/AUTH/AUDIT/NETWORK_LOG_LOCAL_PATH).
LOCAL_PATH_ENV = {"web": "APACHE_LOG_PATH", "auth": "AUTH_LOG_PATH",
                  "audit": "AUDIT_LOG_PATH", "network": "SURICATA_LOG_PATH"}
IP_FILTER_KEYS = {"ip", "src_ip", "dest_ip"}


@dataclass(frozen=True)
class LogDocument:
    source: str
    text: str


class LogPathNotConfigured(RuntimeError):
    """계층별 로그 경로(LOCAL_PATH_ENV)가 설정되지 않음 — 설정 오류라 0건과 구분해 알린다."""


# [33] 경유 — 로그 파일 원본 텍스트를 읽는다
def read_documents(layer: str, host: str, start: datetime, end: datetime) -> List[LogDocument]:
    """`.env`의 계층별 로그 경로(LOCAL_PATH_ENV, EC2라면 /var/log/...) 파일과 그 교체 파일을 원본 그대로 읽는다.

    logrotate가 돌면 조회 구간의 기록이 access.log.1, access.log.2.gz 등으로 넘어간다. 예전에는 경로의 파일
    하나만 읽어, 교체 전 사건을 교체 뒤에 조사하면 원본이 0건이었다(2026-10-01 EC2: 전날 사건의 1차 탐지 근거
    access.log.1:1988을 못 읽어 INCONCLUSIVE). 1차 탐지와 같은 규칙(resolve_log_files)으로 조회 구간 시작
    이후 수정된 파일만 오래된 순으로 읽는다. 구간 뒤로 기록이 없어 현재 파일도 걸러지면 현재 파일을 읽는다
    (0건과 '파일 없음'을 구분하기 위해).

    LOG_LOCAL_HOST가 있으면 다른 host 조회를 거부한다. HOST는 여기서 쓰지 않는다 — main.py의
    수집 대상 이름이고, 합성 시나리오 seed(host=web-01)도 같은 로컬 파일을 읽어야 하기 때문이다.
    S3에서 읽던 분기는 운영이 EC2 로컬 경로로 정해져 삭제했다.
    """
    local_path = os.environ.get(LOCAL_PATH_ENV[layer])
    if not local_path:
        raise LogPathNotConfigured(f"{LOCAL_PATH_ENV[layer]}가 설정되지 않았습니다 (.env에 {layer} 로그 경로 필요, "
                                   f"예전 이름 {layer.upper()}_LOG_LOCAL_PATH에서 바뀜)")
    configured_host = os.environ.get("LOG_LOCAL_HOST")
    if configured_host and configured_host != host:
        raise ValueError(f"local host mismatch: expected {configured_host}, got {host}")
    base = Path(local_path).resolve()
    paths = [Path(found) for found in resolve_log_files(str(base), since_dt=start)]
    if not paths:
        if not base.is_file():
            raise FileNotFoundError(str(base))
        paths = [base]
    return [LogDocument(path.as_posix(), _read_text(path)) for path in paths]


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    return path.read_text(encoding="utf-8", errors="replace")


# [34] → normalizer_adapter.normalize_log_documents() → 1차 탐지팀 정규화, 결과를 한 단계 펼친다
def normalize_documents(layer: str, documents: Iterable[LogDocument],
                        start: datetime, end: datetime) -> List[Dict[str, Any]]:
    """Flatten the shared primary-detection schema, retaining trace metadata.

    파일마다 따로 정규화한다 — 한 번에 넘기면 어댑터가 합쳐서 raw_ref가 전체 경로가 되는데, 파일 하나씩이면
    1차 탐지와 같은 "<파일명(.gz 제거)>:<줄 번호>"(예: access.log.1:1988)라 종료 관문이 탐지 근거와 맞춰 본다.
    """
    events = []
    for doc in documents:
        events += normalize_log_documents(layer, [(doc.source, doc.text)], start, end)
    return [{**{key: value for key, value in event.items() if key != "layer_data"},
             **event.get("layer_data", {})} for event in events]


def event_time(event: Dict[str, Any]) -> datetime | None:
    try:
        return parse_iso(event["timestamp"]).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def query_window(start_time: str, end_time: str) -> tuple[datetime, datetime]:
    if any(not isinstance(value, str) or not value.strip() for value in (start_time, end_time)):
        raise ValueError("window boundaries must be non-empty ISO8601 strings")
    start = parse_iso(start_time).astimezone(timezone.utc)
    end = parse_iso(end_time).astimezone(timezone.utc)
    if end < start:
        raise ValueError("end_time must be greater than or equal to start_time")
    return start, end


def pagination(args: Dict[str, Any]) -> tuple[int, int]:
    values = []
    for name, default in (("limit", 200), ("offset", 0)):
        value = args.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if value < (1 if name == "limit" else 0):
            raise ValueError(f"invalid {name}: {value}")
        values.append(value)
    return values[0], values[1]


def filtered_out_hint(window_total: int, args: Dict[str, Any], filter_keys: Iterable[str]) -> str:
    """필터 결과가 0건인데 구간 안에는 이벤트가 있을 때 summary에 붙일 안내.

    LLM이 "필터에 안 맞음"을 "그 시간에 활동 없음"으로 읽고 조사를 끝내는 사례가 있었다
    (0918 지속성 시나리오: audit event_type="EXECVE" 0건 → INCONCLUSIVE).
    """
    if window_total == 0:
        # 필터와 무관하게 구간 자체에 기록이 없음 — 수집 누락·로그 교체일 수 있어 "활동 없음"과 다르다.
        # 로컬 재현에서 로그가 없는 날짜의 seed를 LLM이 3/4 FALSE_POSITIVE로 판정했다.
        return (" 이 구간에는 이 계층의 로그 기록 자체가 없습니다(수집 누락·로그 교체 가능). "
                "'활동이 없었다'는 증거로 쓰지 말고 unknowns에 '원본 로그 미확보'로 남기십시오.")
    used = [key for key in filter_keys if args.get(key) is not None]
    if not used:
        return ""
    if set(used) <= IP_FILTER_KEYS:
        # IP로만 거른 0건은 "그 IP의 활동이 이 계층에 없다"는 사실이다. 필터를 빼라고 하면 LLM이
        # 다른 IP의 이벤트까지 뒤지거나 "재확인 필요"로 남겼다(EC2 SSH 사건 network 사전 조회).
        return (f" 이 구간 전체 {window_total}건은 다른 대상의 이벤트이며, {', '.join(used)} 조건에 해당하는 "
                "이벤트는 없습니다 — '이 계층에서 해당 IP의 활동 없음'으로 기록하면 됩니다.")
    return (f" 단, 같은 구간에 필터 없이 보면 이벤트가 {window_total}건 있습니다 — 사용한 필터({', '.join(used)})가 "
            "맞지 않았을 수 있으니, 필터를 빼거나 바꿔서 다시 조회한 뒤 판단하십시오.")


# [33] ← agent/tools/real/fetch_*_log.py에서 호출: 읽기 → 정규화 → 조회 구간 안 이벤트만, 시각순
def load_window_events(layer: str, host: str, start_time: str, end_time: str) -> Dict[str, Any]:
    """Read one layer and normalize it with detection_pipeline/tools, keeping only in-window events.

    Tool-specific filters, pagination and summaries belong to agent/tools/real/*.py.
    A missing/unreadable source is reported in "error" instead of looking like 0 events.
    """
    start, end = query_window(start_time, end_time)
    error = None
    try:
        documents = read_documents(layer, host, start, end)
    except (FileNotFoundError, PermissionError, LogPathNotConfigured) as exc:
        documents = []
        error = ("permission_denied" if isinstance(exc, PermissionError)
                 else "not_configured" if isinstance(exc, LogPathNotConfigured) else "not_found")
    events = normalize_documents(layer, documents, start, end)
    invalid_timestamps = sum(event_time(event) is None for event in events)
    in_window = [event for event in events if (ts := event_time(event)) is not None and start <= ts <= end]
    in_window.sort(key=lambda event: (event_time(event), event["raw_ref"]))
    return {"events": in_window, "scanned_objects": len(documents),
            "invalid_timestamps": invalid_timestamps, "error": error}
