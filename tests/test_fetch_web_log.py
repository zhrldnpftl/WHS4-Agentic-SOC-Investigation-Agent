"""fetch_web_log(agent/tools/real/fetch_web_log.py) 단독 테스트.

실제 AWS에 붙지 않고, boto3를 흉내내는 가짜 객체를 sys.modules에 주입해서
- 실제 EC2 sample_web.log 형식(한 줄 = JSON 객체, nginx 로그)이 구조화되어
  반환되는지
- src_ip 필터가 되는지 (실측 결과 nginx가 이미 실제 클라이언트 IP를 로깅해서
  xff 문제 자체가 없었음 — 그래도 xff 필터는 안전망으로 유지)
- method/path/status_code 필터가 되는지
- 시간 범위 필터가 되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다. (2026-09-14: apache_parser.py -> nginx_json_parser.py로 교체됨,
실제 sample_web.log가 shlex 14필드가 아니라 JSON 한 줄짜리 포맷이었음을 실측으로 확인)

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_web_log`로 실행 가능.
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
    sys.modules.pop("agent.tools.real.fetch_web_log", None)


def _sample_web_text() -> bytes:
    """실제 EC2 sample_web.log 형식 그대로 재현: 웹셸 업로드 시도 1건(04:24) +
    정상 요청 1건(00:01, 시간 범위 밖) — 실측 결과 xff_orig는 항상 빈 문자열이었음.
    """
    return (
        b'{"ts":"2026-09-13T04:24:31+00:00","msec":"1789217071.733","req_id":"r1",'
        b'"src_ip":"77.239.124.213","src_port":"51234","dst_ip":"10.0.7.236","dst_port":"443",'
        b'"scheme":"https","host":"ogwanwan.shop","method":"POST",'
        b'"uri":"/wp-admin/install.php?step=1","proto":"HTTP/1.1","status":"200","bytes":"259",'
        b'"rt":"0.566","xff_orig":"","ref":"","ua":"curl/7.0","upstream":"127.0.0.1:8080",'
        b'"ustatus":"200"}\n'
        b'{"ts":"2026-09-13T00:01:55+00:00","msec":"1789257715.096","req_id":"r2",'
        b'"src_ip":"54.180.11.0","src_port":"54786","dst_ip":"10.0.7.236","dst_port":"443",'
        b'"scheme":"https","host":"ogwanwan.shop","method":"GET","uri":"/",'
        b'"proto":"HTTP/1.1","status":"200","bytes":"0","rt":"0.001","xff_orig":"","ref":"",'
        b'"ua":"WordPress/6.9.4","upstream":"127.0.0.1:8080","ustatus":"200"}\n'
    )


def test_fetch_web_log_parses_real_nginx_json_format() -> None:
    prefix = "raw/source_type=nginx/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"access.log": _sample_web_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )

        assert result["count"] == 2
        webshell = next(e for e in result["records"] if e["src_ip"] == "77.239.124.213")
        assert webshell["method"] == "POST"
        assert webshell["uri"] == "/wp-admin/install.php?step=1"
        assert webshell["status"] == 200
        assert webshell["dst_ip"] == "10.0.7.236", "실제 서버 IP가 그대로 찍혀야 함"
        print("[PASS] test_fetch_web_log_parses_real_nginx_json_format")
    finally:
        _uninstall_fake_boto3()


def test_fetch_web_log_filters_by_src_ip() -> None:
    prefix = "raw/source_type=nginx/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"access.log": _sample_web_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "src_ip": "77.239.124.213",
            }
        )
        assert result["count"] == 1
        assert result["records"][0]["method"] == "POST"
        print("[PASS] test_fetch_web_log_filters_by_src_ip")
    finally:
        _uninstall_fake_boto3()


def test_fetch_web_log_filters_by_method_path_status() -> None:
    prefix = "raw/source_type=nginx/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"access.log": _sample_web_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "method": "post",  # 대소문자 무관해야 함
                "path": "install.php",
                "status_code": 200,
            }
        )
        assert result["count"] == 1
        print("[PASS] test_fetch_web_log_filters_by_method_path_status")
    finally:
        _uninstall_fake_boto3()


def test_fetch_web_log_filters_by_time_range() -> None:
    prefix = "raw/source_type=nginx/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"access.log": _sample_web_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T04:00:00Z",
                "end_time": "2026-09-13T05:00:00Z",
            }
        )
        assert result["count"] == 1, "00:01:55(정상 요청)는 범위 밖이라 제외되어야 한다"
        assert result["records"][0]["method"] == "POST"
        print("[PASS] test_fetch_web_log_filters_by_time_range")
    finally:
        _uninstall_fake_boto3()


def test_fetch_web_log_reports_missing_partition() -> None:
    fake_client = _FakeS3Client({})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_web_log_reports_missing_partition")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_web_log_parses_real_nginx_json_format()
    test_fetch_web_log_filters_by_src_ip()
    test_fetch_web_log_filters_by_method_path_status()
    test_fetch_web_log_filters_by_time_range()
    test_fetch_web_log_reports_missing_partition()
    print("\n모든 테스트 통과.")