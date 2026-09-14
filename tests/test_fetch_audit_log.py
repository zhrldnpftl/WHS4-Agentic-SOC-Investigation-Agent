"""fetch_audit_log(agent/tools/real/fetch_audit_log.py) 단독 테스트.

실제 AWS에 붙지 않고, boto3를 흉내내는 가짜 객체를 sys.modules에 주입해서
- ENRICHED 포맷(0x1d 구분자)의 raw/enriched 필드가 병합되는지
- 같은 audit ID(serial)로 여러 줄(SYSCALL/EXECVE/CWD)이 하나의 구조화된
  이벤트로 조립되는지 (uid/euid/session_type/exec_args/target_file 등)
- audit(EPOCH:SERIAL)의 EPOCH로 시간 필터링이 되는지
- pid/user 필터가 되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다. (2026-09-13: 팀원이 만든 정식 파서(_audit_parser.py)로 교체됨)

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_audit_log`로 실행 가능.
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
    """key -> raw 텍스트 bytes 매핑으로 list_objects_v2 + get_object를 흉내낸다."""

    def __init__(self, objects_by_prefix: Dict[str, Dict[str, bytes]]) -> None:
        self._objects_by_prefix = objects_by_prefix
        self.requested_prefixes: List[str] = []

    def get_paginator(self, name: str):
        assert name == "list_objects_v2"

        def _paginate(**kwargs: Any):
            prefix = kwargs["Prefix"]
            self.requested_prefixes.append(prefix)
            objects = self._objects_by_prefix.get(prefix, {})
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
    sys.modules.pop("agent.tools.real.fetch_audit_log", None)


# 2026-09-09 10:05:45 UTC epoch: 1788948345 (실제 값은 중요치 않고, start/end 범위 계산에만 씀)
_EPOCH_IN_RANGE = 1788948345
_EPOCH_OUT_OF_RANGE = 1788926000  # 같은 날 훨씬 이른 시각 -> 좁은 범위 테스트에서 밖으로 밀려남

GS = "\x1d"  # ENRICHED 구분자


def _sample_audit_text() -> bytes:
    """ENRICHED 포맷 웹셸 이벤트(pid=3812, www-data, non_interactive) +
    관리자 SSH 이벤트(pid=1234, 시간 범위 밖, interactive) 2건.
    """
    return (
        f'type=SYSCALL msg=audit({_EPOCH_IN_RANGE}.123:5001): arch=c000003e syscall=59 '
        f'success=yes exit=0 pid=3812 ppid=3701 auid=4294967295 uid=33 euid=33 comm="sh" '
        f'exe="/bin/sh" key="susp_exec"{GS}SYSCALL SYSCALL=execve UID="www-data"\n'
        f'type=EXECVE msg=audit({_EPOCH_IN_RANGE}.123:5001): argc=1 a0="sh"\n'
        f'type=CWD msg=audit({_EPOCH_IN_RANGE}.123:5001):  cwd="/var/www/html"\n'
        f'type=SYSCALL msg=audit({_EPOCH_OUT_OF_RANGE}.001:4000): arch=c000003e syscall=59 '
        f'success=yes exit=0 pid=1234 ppid=1 auid=1000 uid=0 euid=0 comm="bash" '
        f'exe="/bin/bash" key="sensitive"{GS}SYSCALL SYSCALL=execve UID="root"\n'
    ).encode("utf-8")


def test_fetch_audit_log_assembles_structured_event_from_enriched_multiline() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-09/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_audit_log import fetch_audit_log

        result = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": "2026-09-09T00:00:00Z",
                "end_time": "2026-09-09T23:59:59Z",
            }
        )

        assert result["count"] == 2, "serial이 다른 두 이벤트로 조립되어야 한다"
        webshell = next(e for e in result["records"] if e["pid"] == 3812)
        assert webshell["syscall"] == "execve", "enriched(SYSCALL=execve)가 raw(syscall=59)보다 우선해야 한다"
        assert webshell["user"] == "www-data", "enriched(UID)가 사람이 읽는 이름으로 나와야 한다"
        assert webshell["uid"] == 33
        assert webshell["cwd"] == "/var/www/html", "같은 serial의 CWD 줄이 병합되어야 한다"
        assert webshell["exec_args"] == "sh", "EXECVE의 argv가 복원되어야 한다"
        assert webshell["session_type"] == "non_interactive", "auid=4294967295는 non_interactive"
        print("[PASS] test_fetch_audit_log_assembles_structured_event_from_enriched_multiline")
    finally:
        _uninstall_fake_boto3()


def test_fetch_audit_log_filters_by_time_range() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-09/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_audit_log import fetch_audit_log
        from datetime import datetime, timedelta, timezone

        # _EPOCH_IN_RANGE 근처 몇 초만 포함하는 좁은 범위 -> pid=3812 이벤트만 남아야 함
        center = datetime.fromtimestamp(_EPOCH_IN_RANGE, tz=timezone.utc)
        start = center - timedelta(seconds=1)
        end = center + timedelta(seconds=1)

        result = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": (start.isoformat()).replace("+00:00", "Z"),
                "end_time": (end.isoformat()).replace("+00:00", "Z"),
            }
        )

        assert result["count"] == 1, "시간 범위 밖(pid=1234)은 걸러져야 한다"
        assert result["records"][0]["pid"] == 3812
        print("[PASS] test_fetch_audit_log_filters_by_time_range")
    finally:
        _uninstall_fake_boto3()


def test_fetch_audit_log_filters_by_pid_and_user() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-09/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_audit_log import fetch_audit_log

        result_pid = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "pid": 1234,
            }
        )
        assert result_pid["count"] == 1
        assert result_pid["records"][0]["user"] == "root"

        result_user = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "user": "www-data",
            }
        )
        assert result_user["count"] == 1
        assert result_user["records"][0]["pid"] == 3812
        print("[PASS] test_fetch_audit_log_filters_by_pid_and_user")
    finally:
        _uninstall_fake_boto3()


def test_fetch_audit_log_exclude_interactive() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-09/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_audit_log import fetch_audit_log

        result = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "exclude_interactive": True,
            }
        )
        # root(auid=1000, interactive)는 빠지고 www-data(non_interactive)만 남아야 함
        assert result["count"] == 1
        assert result["records"][0]["session_type"] == "non_interactive"
        print("[PASS] test_fetch_audit_log_exclude_interactive")
    finally:
        _uninstall_fake_boto3()


def test_fetch_audit_log_reports_missing_partition() -> None:
    """해당 host/날짜 파티션에 오브젝트가 하나도 없을 때 안내 메시지가 나오는지 확인."""
    fake_client = _FakeS3Client({})  # 아무 오브젝트도 없음
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.fetch_audit_log import fetch_audit_log

        result = fetch_audit_log(
            {
                "host": "web-01",
                "start_time": "2026-09-09T09:50:00Z",
                "end_time": "2026-09-09T10:10:00Z",
            }
        )

        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_audit_log_reports_missing_partition")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_audit_log_assembles_structured_event_from_enriched_multiline()
    test_fetch_audit_log_filters_by_time_range()
    test_fetch_audit_log_filters_by_pid_and_user()
    test_fetch_audit_log_exclude_interactive()
    test_fetch_audit_log_reports_missing_partition()
    print("\n모든 테스트 통과.")