"""tools/parsers/apache_parser.py
Apache soc access 로그 한 줄 파싱 + 시각 변환.

팀원이 실서버 apache 로그로 만든 파싱 로직을 그대로 가져왔다 (원본이 이미
shlex/datetime만 써서 프레임워크 의존이 없어 audit 때와 달리 거의 그대로 옮김).

실서버 soc LogFormat 기준:
0 timestamp, 1 request_id, 2 src_ip, 3 connection_ip,
4 scheme, 5 host, 6 request_line, 7 status, 8 bytes,
9 duration_us, 10 worker_pid, 11 referer, 12 user_agent, 13 xff.

*** src_ip vs xff 주의 (agent/tools/real/fetch_web_log.py에서 실제로 씀) ***
팀 실측 결과, nginx가 앞단 리버스 프록시라 필드 2(src_ip)가 연결 IP(loopback일
수 있음)이고, 실제 클라이언트 IP는 필드 13(xff, X-Forwarded-For)에 있다. 이
파서는 둘 다 분리해서 반환하므로, 호출 쪽(fetch_web_log.py)이 필터링할 때
src_ip와 xff 둘 다 확인해야 한다.

기존 aggregate_logs가 사용하는 detail.method/uri/status/ua는 그대로 유지한다.
"""

import shlex
from datetime import datetime


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_apache_line(line: str) -> dict | None:
    """Apache soc 로그 한 줄을 구조화된 web 이벤트로 변환. 실패 시 None."""
    try:
        parts = shlex.split(line)
    except ValueError:
        return None

    # 현재 실서버 soc 포맷은 14개 필드
    if len(parts) < 14:
        return None

    ts = parts[0]
    request_id = parts[1]
    src_ip = parts[2]
    connection_ip = parts[3]
    scheme = parts[4]
    host = parts[5]
    req_line = parts[6]
    status = _to_int(parts[7])
    bytes_sent = _to_int(parts[8])
    duration_us = _to_int(parts[9])
    worker_pid = _to_int(parts[10])
    referer = parts[11]
    ua = parts[12]

    xff_raw = parts[13]
    xff = xff_raw[4:] if xff_raw.startswith("xff=") else xff_raw

    if xff == "-":
        xff = None

    req_parts = req_line.split()

    method = req_parts[0] if len(req_parts) >= 1 else ""
    uri = req_parts[1] if len(req_parts) >= 2 else ""
    protocol = req_parts[2] if len(req_parts) >= 3 else ""

    if status is None:
        status = 0

    return {
        "layer": "web",
        "ts": ts,
        "src_ip": src_ip,
        "event_type": "web_request",

        "detail": {
            # 기존 코드 호환
            "method": method,
            "uri": uri,
            "status": status,
            "ua": ua,

            # 실서버 soc 필드 추가
            "request_id": request_id,
            "connection_ip": connection_ip,
            "scheme": scheme,
            "host": host,
            "protocol": protocol,
            "bytes": bytes_sent,
            "duration_us": duration_us,
            "worker_pid": worker_pid,
            "referer": referer,
            "xff": xff,
        },

        "raw": line.rstrip("\n"),
    }


def apache_ts_to_dt(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None