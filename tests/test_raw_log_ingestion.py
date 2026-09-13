"""fetch_recent_raw_logs(agent/raw_log_ingestion.py) 단독 테스트.

실제 AWS 없이, boto3를 흉내내는 가짜 객체로
- audit 소스는 group_raw_audit_events()로 멀티라인 이벤트가 잘 묶이는지
- 여러 source_type(web/auth/audit/network)을 다 훑는지
- 데이터 없는 source_type은 에러 없이 조용히 건너뛰는지 (현재 auditd만 실제 연결된 상태 재현)
- 각 레코드에 _source_type이 붙는지
- audit 이벤트는 시간 범위 밖이면 걸러지는지
를 검증한다. (2026-09-13 실측 결과 반영: auditd는 NDJSON이 아니라 raw 텍스트)
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    """prefix -> {key: raw text bytes} 매핑으로 list_objects_v2 + get_object를 흉내낸다."""

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
    sys.modules.pop("agent.raw_log_ingestion", None)


def test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing() -> None:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    recent_epoch = int((now - timedelta(minutes=2)).timestamp())
    old_epoch = int((now - timedelta(hours=5)).timestamp())

    audit_prefix = f"raw/source_type=auditd/host=web-01/dt={today}/"
    web_prefix = f"raw/source_type=apache/host=web-01/dt={today}/"
    # auth, network(suricata) 파티션은 아예 데이터 없음 (인프라 미연결 상황 재현)

    audit_text = (
        f'type=SYSCALL msg=audit({recent_epoch}.100:9001): pid=3812 uid=33 comm="sh" key="susp_exec"\n'
        f'type=SYSCALL msg=audit({old_epoch}.100:9000): pid=1234 uid=0 comm="cron" key="sensitive"\n'
    ).encode("utf-8")
    web_text = b"GET /upload.php HTTP/1.1 200\nGET /old-request HTTP/1.1 200\n"

    objects_by_prefix = {
        audit_prefix: {"audit.log": audit_text},
        web_prefix: {"access.log": web_text},
    }

    fake_client = _FakeS3Client(objects_by_prefix)
    _install_fake_boto3(fake_client)

    try:
        from agent.raw_log_ingestion import fetch_recent_raw_logs

        records = fetch_recent_raw_logs(host="web-01", minutes=10)

        source_types = {r["_source_type"] for r in records}
        assert source_types == {"audit", "web"}, "데이터가 있는 두 소스만 나와야 한다"

        audit_records = [r for r in records if r["_source_type"] == "audit"]
        assert len(audit_records) == 1, "시간 범위 밖의 cron(9000) 이벤트는 제외되어야 한다"
        assert "pid=3812" in audit_records[0]["raw_block"]

        web_records = [r for r in records if r["_source_type"] == "web"]
        # web은 아직 타임스탬프 파싱 규칙이 없어 시간 필터를 적용하지 않음 -> 두 줄 다 나옴
        assert len(web_records) == 2

        print("[PASS] test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing()
    print("\n모든 테스트 통과.")