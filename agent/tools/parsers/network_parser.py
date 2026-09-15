"""Suricata eve.json(NDJSON) 파서 — 이벤트 필터링 + 프로토콜 정규화.

팀원이 만든 fetch_network_log.py(독립 배포용, HostConfig/configure() 자체
프레임워크 포함)에서 "이벤트 필터링·프로토콜 정규화" 핵심 로직만 뽑아왔다.

*** 원본 대비 뺀 것: direction(internal/outbound/inbound) 계산 ***
원본은 HostConfig.ip_addresses(호스트 자신의 IP 목록)를 사전 등록해두고, 그
IP와 이벤트의 src/dst를 비교해서 "이 트래픽이 내부/나가는/들어오는 것"을
계산했다. 우리 시스템엔 그런 "호스트 IP 사전 등록" 단계가 없어서(각 tool 호출이
그때그때 host 이름만 받음) 이 계산을 하지 않는다 — 대신 src_ip/dst_ip를 그대로
반환하고, 어느 쪽이 공격자인지는 이미 seed 단계에서 IP를 알고 있는 LLM이
판단하게 둔다. (필요해지면 host->IP 매핑을 추가해서 되살릴 수 있다.)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..time_utils import parse_iso


def _normalize_protocol(protocol: Optional[str]) -> Optional[str]:
    if not protocol:
        return None
    protocol = protocol.upper()
    if protocol in {"IPV6-ICMP", "ICMP6"}:
        protocol = "ICMPV6"
    return protocol


def _extract_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    value = record.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        # _s3_common.parse_iso()는 "+0000"처럼 콜론 없는 오프셋(Suricata가
        # 실제로 이렇게 씀, Python 3.10에서는 이거 하나만으론 못 읽음)도
        # 정규화해서 읽는다 — 여기서도 그대로 재사용해서 같은 버그를 반복하지 않는다.
        return parse_iso(value)
    except ValueError:
        return None


def parse_network_events(
    text: str,
    time_window: "Optional[tuple]" = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    alert_only: bool = False,
) -> List[Dict[str, Any]]:
    """eve.json 텍스트(한 줄 = JSON 이벤트 하나)를 읽어 조건에 맞는 이벤트 리스트로 반환.

    eve.json은 원래부터 구조화된 포맷이라(팀 결정사항), json.loads()로 파싱하는 건
    "해석"이 아니라 "이미 있는 구조를 읽는 것"이다. alert.signature가 실제로 뭘
    뜻하는지 같은 의미 해석은 여기서 하지 않고 LLM에게 그대로 넘긴다.
    """
    protocol = _normalize_protocol(protocol)
    events: List[Dict[str, Any]] = []

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        event_type = record.get("event_type")
        if not event_type:
            continue
        # stats 등 IP가 없는 EVE 레코드는 트래픽 증거가 아니므로 제외.
        if "src_ip" not in record and "dest_ip" not in record:
            continue

        if alert_only and event_type != "alert":
            continue

        ts = _extract_timestamp(record)
        if ts is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if time_window is not None:
                start, end = time_window
                if not (start <= ts <= end):
                    continue

        record_protocol = _normalize_protocol(record.get("proto"))

        if src_ip and record.get("src_ip") != src_ip:
            continue
        if dst_ip and record.get("dest_ip") != dst_ip:
            continue
        if src_port is not None and record.get("src_port") != src_port:
            continue
        if dst_port is not None and record.get("dest_port") != dst_port:
            continue
        if protocol and record_protocol != protocol:
            continue

        alert = record.get("alert") or {}
        events.append(
            {
                "timestamp": ts.isoformat() if ts else record.get("timestamp"),
                "event_type": event_type,
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dest_ip"),
                "src_port": record.get("src_port"),
                "dst_port": record.get("dest_port"),
                "protocol": record_protocol,
                "alert_signature": alert.get("signature") if isinstance(alert, dict) else None,
                "flow_id": record.get("flow_id"),
            }
        )

    events.sort(key=lambda e: e.get("timestamp") or "")
    return events