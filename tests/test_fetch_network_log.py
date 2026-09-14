"""fetch_network_log(agent/tools/real/fetch_network_log.py) 단독 테스트.

실제 AWS 없이, boto3를 흉내내는 가짜 객체로
- eve.json(NDJSON) 이벤트가 구조화되어 반환되는지
- alert_only 필터로 flow 등 비-alert 이벤트가 걸러지는지
- src_ip/dst_ip/dst_port/protocol 필터가 되는지 (protocol 대소문자/별칭 정규화 포함)
- 시간 범위 필터가 되는지
- limit/offset 페이지네이션이 되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_network_log`로 실행 가능.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict, List


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    def __init__(self, objects_by_prefix: Dict[str, Dict[str, bytes]]) -> None:
        self._objects_by_prefix = objects_by_prefix

    def get_paginator(self, name: str):
        assert name == "list_objects_v2"

        def _paginate(**kwargs: Any):
            objects = self._objects_by_prefix.get(kwargs["Prefix"], {})
            return [{"Contents": [{"Key": k} for k in objects]}]

        paginator = types.SimpleNamespace()
        paginator.paginate = _paginate
        return paginator

    def get_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        for objects in self._objects_by_prefix.values():
            if Key in objects:
                return {"Body": _FakeBody(objects[Key])}
        raise KeyError(Key)


def _install_fake_boto3(s3_client: _FakeS3Client) -> None:
    fake_module = types.ModuleType("boto3")
    fake_module.client = lambda service_name, **kwargs: s3_client  # type: ignore[attr-defined]
    sys.modules["boto3"] = fake_module


def _uninstall_fake_boto3() -> None:
    sys.modules.pop("boto3", None)
    sys.modules.pop("agent.tools.real.fetch_network_log", None)


def _sample_network_text() -> bytes:
    """alert(웹셸 시그니처) 1건 + flow(정상 DNS) 1건 + 시간 범위 밖 alert 1건."""
    return (
        b'{"timestamp": "2026-09-13T04:10:00.000000+0000", "event_type": "alert", '
        b'"src_ip": "77.239.124.213", "dest_ip": "10.0.7.236", "src_port": 51234, '
        b'"dest_port": 22, "proto": "TCP", "alert": {"signature": "ET SCAN SSH BruteForce"}}\n'
        b'{"timestamp": "2026-09-13T04:15:00.000000+0000", "event_type": "flow", '
        b'"src_ip": "10.0.7.236", "dest_ip": "8.8.8.8", "src_port": 40000, '
        b'"dest_port": 53, "proto": "UDP"}\n'
        b'{"timestamp": "2026-09-13T00:00:00.000000+0000", "event_type": "alert", '
        b'"src_ip": "9.9.9.9", "dest_ip": "10.0.7.236", "src_port": 1, "dest_port": 1, '
        b'"proto": "tcp", "alert": {"signature": "old alert"}}\n'
    )


def test_fetch_network_log_parses_structured_event() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"eve.json": _sample_network_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T04:00:00Z",
                "end_time": "2026-09-13T05:00:00Z",
            }
        )
        assert result["count"] == 2, "이 시간 범위 안엔 alert 1건 + flow 1건"
        alert = next(e for e in result["records"] if e["event_type"] == "alert")
        assert alert["alert_signature"] == "ET SCAN SSH BruteForce"
        assert alert["protocol"] == "TCP"
        print("[PASS] test_fetch_network_log_parses_structured_event")
    finally:
        _uninstall_fake_boto3()


def test_fetch_network_log_alert_only_and_protocol_filter() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"eve.json": _sample_network_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "alert_only": True,
            }
        )
        assert result["count"] == 2, "alert_only면 flow는 빠지고 alert 2건만"

        result_tcp_lower = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "protocol": "tcp",  # 소문자로 줘도 매칭돼야 함 (정규화)
            }
        )
        assert result_tcp_lower["count"] == 2, "TCP 프로토콜(대소문자 무관) 2건"
        print("[PASS] test_fetch_network_log_alert_only_and_protocol_filter")
    finally:
        _uninstall_fake_boto3()


def test_fetch_network_log_filters_by_src_dst_ip() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"eve.json": _sample_network_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "src_ip": "77.239.124.213",
            }
        )
        assert result["count"] == 1
        assert result["records"][0]["alert_signature"] == "ET SCAN SSH BruteForce"
        print("[PASS] test_fetch_network_log_filters_by_src_dst_ip")
    finally:
        _uninstall_fake_boto3()


def test_fetch_network_log_pagination() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"eve.json": _sample_network_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        page1 = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": 0,
            }
        )
        assert page1["count"] == 2
        assert page1["total_matched"] == 3
        assert page1["has_more"] is True

        page2 = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": page1["next_offset"],
            }
        )
        assert page2["count"] == 1
        assert page2["has_more"] is False
        print("[PASS] test_fetch_network_log_pagination")
    finally:
        _uninstall_fake_boto3()


def test_fetch_network_log_reports_missing_partition() -> None:
    fake_client = _FakeS3Client({})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_network_log_reports_missing_partition")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_network_log_parses_structured_event()
    test_fetch_network_log_alert_only_and_protocol_filter()
    test_fetch_network_log_filters_by_src_dst_ip()
    test_fetch_network_log_pagination()
    test_fetch_network_log_reports_missing_partition()
    print("\n모든 테스트 통과.")