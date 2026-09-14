"""nginx JSON access log 파서 — EC2 실측(2026-09-14) 기반.

*** 왜 apache_parser.py가 아니라 이 파일이 따로 있나 ***
처음엔 web 담당 팀원이 만든 apache_parser.py(공백 구분 14필드, shlex 기반)를
썼는데, 실제 sample_web.log를 열어보니 그 형식이 아니라 **한 줄 = JSON 객체
하나**인 nginx JSON 로그 포맷이었다 (Suricata eve.json과 같은 방식). 그래서
shlex.split()이 JSON을 엉뚱하게 쪼개서 전부 파싱 실패(count=0)로 나왔었다.
apache_parser.py는 그대로 남겨두되(다른 환경에서 그 형식을 실제로 쓸 수도
있으니 삭제하지 않음), fetch_web_log.py는 이 파일을 쓰도록 교체했다.

*** 실측 결과: xff 문제가 없다 ***
apache_parser.py 설계 당시엔 "nginx가 앞단 프록시라 src_ip가 loopback일 수
있다"고 가정했는데, 실제 nginx JSON 로그는 src_ip에 이미 진짜 클라이언트
IP(예: 54.180.11.0)가 찍혀 있고, dst_ip도 실제 서버 사설 IP(10.0.7.236)다.
xff_orig 필드도 있긴 하지만(다른 프록시 계층, 예: CDN이 있을 경우 대비),
지금 샘플에선 전부 빈 문자열이라 굳이 쓸 필요가 없었다.

실제 로그 한 줄 예시:
{"ts":"2026-09-13T00:01:55+00:00","msec":"1789257715.096",
 "req_id":"...", "src_ip":"54.180.11.0","src_port":"54786",
 "dst_ip":"10.0.7.236","dst_port":"443","scheme":"https",
 "host":"ogwanwan.shop","method":"POST","uri":"/wp-cron.php?...",
 "proto":"HTTP/1.1","status":"200","bytes":"0","rt":"0.001",
 "xff_orig":"","ref":"","ua":"...","upstream":"127.0.0.1:8080",
 "ustatus":"200"}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_nginx_json_line(line: str) -> Optional[Dict[str, Any]]:
    """nginx JSON 로그 한 줄을 구조화된 web 이벤트로 변환. 실패 시 None."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    return {
        "timestamp": record.get("ts"),
        "src_ip": record.get("src_ip"),
        "src_port": _to_int(record.get("src_port")),
        "dst_ip": record.get("dst_ip"),
        "dst_port": _to_int(record.get("dst_port")),
        "scheme": record.get("scheme"),
        "host": record.get("host"),
        "method": record.get("method"),
        "uri": record.get("uri"),
        "protocol": record.get("proto"),
        "status": _to_int(record.get("status")),
        "bytes": _to_int(record.get("bytes")),
        "response_time_sec": record.get("rt"),
        "xff": record.get("xff_orig") or None,
        "referer": record.get("ref") or None,
        "user_agent": record.get("ua"),
        "upstream": record.get("upstream"),
        "upstream_status": _to_int(record.get("ustatus")),
        "req_id": record.get("req_id"),
    }


def nginx_ts_to_dt(ts_str: Optional[str]) -> Optional[datetime]:
    if not isinstance(ts_str, str):
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt