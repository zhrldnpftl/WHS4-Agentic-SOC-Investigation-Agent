"""get_process_tree(agent/tools/real/get_process_tree.py) 단독 테스트.

실제 AWS 없이, boto3를 흉내내는 가짜 객체로
- audit 이벤트의 pid/ppid를 따라 조상 체인이 올바른 순서로 추적되는지
  (leaf -> ... -> root, sshd -> bash -> sh -> id)
- 부모가 로그에 없으면(parent_not_observed) 거기서 멈추고 lineage_status="partial"인지
- 관측 자체가 없는 pid를 물어보면 count=0으로 안내되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

pytest 없이도 저장소 루트에서 `python -m tests.test_get_process_tree`로 실행 가능.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict


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
    sys.modules.pop("agent.tools.real.get_process_tree", None)


def _sample_audit_chain_text() -> bytes:
    """sshd(1500) -> bash(1600) -> sh(1700) -> id(1800), ppid=1(sshd의 부모)은 로그에 없음."""
    return (
        b'type=SYSCALL msg=audit(1789217000.100:1001): pid=1500 ppid=1 syscall=59 '
        b'success=yes comm="sshd" exe="/usr/sbin/sshd" key="exec"\n'
        b'type=SYSCALL msg=audit(1789217010.100:1002): pid=1600 ppid=1500 syscall=59 '
        b'success=yes comm="bash" exe="/bin/bash" key="exec"\n'
        b'type=SYSCALL msg=audit(1789217020.100:1003): pid=1700 ppid=1600 syscall=59 '
        b'success=yes comm="sh" exe="/bin/sh" key="susp_exec"\n'
        b'type=SYSCALL msg=audit(1789217030.100:1004): pid=1800 ppid=1700 syscall=59 '
        b'success=yes comm="id" exe="/usr/bin/id" key="susp_exec"\n'
    )


def test_get_process_tree_traces_full_chain() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-12/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_chain_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 1800,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )

        assert result["count"] == 1
        chain = result["records"][0]
        pids_in_order = [n["pid"] for n in chain["nodes"]]
        assert pids_in_order == [1800, 1700, 1600, 1500], "leaf(1800)부터 root 방향으로 순서대로여야 한다"
        assert chain["nodes"][0]["exe"] == "/usr/bin/id"
        assert chain["nodes"][-1]["exe"] == "/usr/sbin/sshd"
        assert chain["lineage_status"] == "partial", "ppid=1(sshd의 부모)은 로그에 없어서 partial이어야 한다"
        assert chain["stop_reason"] == "parent_not_observed"
        print("[PASS] test_get_process_tree_traces_full_chain")
    finally:
        _uninstall_fake_boto3()


def test_get_process_tree_pid_not_observed() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-12/"
    fake_client = _FakeS3Client({prefix: {"audit.log": _sample_audit_chain_text()}})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 99999,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "찾지 못했습니다" in result["summary"]
        print("[PASS] test_get_process_tree_pid_not_observed")
    finally:
        _uninstall_fake_boto3()


def test_get_process_tree_reports_missing_partition() -> None:
    fake_client = _FakeS3Client({})
    _install_fake_boto3(fake_client)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 1800,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_get_process_tree_reports_missing_partition")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_get_process_tree_traces_full_chain()
    test_get_process_tree_pid_not_observed()
    test_get_process_tree_reports_missing_partition()
    print("\n모든 테스트 통과.")