"""fetch_auth_log(agent/tools/real/fetch_auth_log.py) 단독 테스트.

실제 AWS에 붙지 않고, boto3를 흉내내는 가짜 객체를 sys.modules에 주입해서
- ssh_login(성공/실패)/sudo/pam 4종 이벤트가 정확히 분류되는지
- sudo/pam은 RHOST=/rhost=가 있을 때만 IP가 채워지고, 없으면 None인지
- src_ip/user/event_type/result 필터가 되는지
- limit/offset 페이지네이션이 팀원 설계대로(has_more/next_offset) 동작하는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_auth_log`로 실행 가능.
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
    sys.modules.pop("agent.tools.real.fetch_auth_log", None)


def _sample_auth_text() -> bytes:
    """ssh 실패(브루트포스) 2건 + ssh 성공(관리자) 1건 + sudo(RHOST 없음) 1건."""
    return (
        b"Sep 13 04:07:24 web-01 sshd[3001]: Failed password for root from 77.239.124.213 port 4001 ssh2\n"
        b"Sep 13 04:07:25 web-01 sshd[3002]: Failed password for invalid user testuser from 77.239.124.213 port 4002 ssh2\n"
        b"Sep 13 04:07:26 web-01 sshd[3003]: Accepted password for ubuntu from 112.148.16.1 port 22 ssh2\n"
        b"Sep 13 04:07:27 web-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail -n 500 audit.log\n"
    )


def test_fetch_auth_log_classifies_four_event_types() -> None:
    prefix = "raw/source_type=auth/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"auth.log": _sample_auth_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_auth_log import fetch_auth_log

        result = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )

        assert result["count"] == 4
        by_user = {r["user"]: r for r in result["records"] if r["event_type"] == "ssh_login"}
        assert by_user["root"]["result"] == "failure"
        assert by_user["testuser"]["result"] == "failure"
        assert by_user["ubuntu"]["result"] == "success"
        assert by_user["ubuntu"]["source_ip"] == "112.148.16.1"

        sudo_event = next(r for r in result["records"] if r["event_type"] == "sudo")
        assert sudo_event["source_ip"] is None, "RHOST=가 없으면 source_ip는 None이어야 한다"
        print("[PASS] test_fetch_auth_log_classifies_four_event_types")
    finally:
        _uninstall_fake_boto3()


def test_fetch_auth_log_filters_by_src_ip_user_event_type_result() -> None:
    prefix = "raw/source_type=auth/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"auth.log": _sample_auth_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_auth_log import fetch_auth_log

        by_ip = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "src_ip": "77.239.124.213",
            }
        )
        assert by_ip["count"] == 2, "브루트포스 IP로 걸러야 실패 2건만 남는다"

        by_result = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "result": "success",
            }
        )
        assert by_result["count"] == 2, "ssh 성공 1건 + sudo(성공 처리) 1건 = 2건"

        by_event_type = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "event_type": "sudo",
            }
        )
        assert by_event_type["count"] == 1
        print("[PASS] test_fetch_auth_log_filters_by_src_ip_user_event_type_result")
    finally:
        _uninstall_fake_boto3()


def test_fetch_auth_log_pagination_matches_teammate_design() -> None:
    """1차: limit=2,offset=0 -> has_more=True, next_offset=2.
    2차: 그 next_offset을 그대로 offset에 넣으면 나머지 2건이 나오고 has_more=False.
    """
    prefix = "raw/source_type=auth/host=web-01/dt=2026-09-13/"
    fake_client = _FakeS3Client({prefix: {"auth.log": _sample_auth_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_auth_log import fetch_auth_log

        page1 = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": 0,
            }
        )
        assert page1["count"] == 2
        assert page1["total_matched"] == 4
        assert page1["has_more"] is True
        assert page1["next_offset"] == 2

        page2 = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": page1["next_offset"],
            }
        )
        assert page2["count"] == 2
        assert page2["has_more"] is False
        assert page2["next_offset"] is None
        print("[PASS] test_fetch_auth_log_pagination_matches_teammate_design")
    finally:
        _uninstall_fake_boto3()


def test_fetch_auth_log_reports_missing_partition() -> None:
    fake_client = _FakeS3Client({})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_auth_log import fetch_auth_log

        result = fetch_auth_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_auth_log_reports_missing_partition")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_auth_log_classifies_four_event_types()
    test_fetch_auth_log_filters_by_src_ip_user_event_type_result()
    test_fetch_auth_log_pagination_matches_teammate_design()
    test_fetch_auth_log_reports_missing_partition()
    print("\n모든 테스트 통과.")