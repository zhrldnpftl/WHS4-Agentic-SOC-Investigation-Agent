"""fetch_recent_raw_logs(agent/raw_log_ingestion.py) 단독 테스트.

실제 AWS 없이, boto3를 흉내내는 가짜 객체로
- audit 소스는 parsers/audit_parser.py의 parse_audit_events()로 구조화된 이벤트가 되는지
- web 소스는 parsers/nginx_json_parser.py의 parse_nginx_json_line()으로 구조화된 이벤트가 되는지
  (시간 필터까지 적용되는지)
- network 소스도 parsers/network_parser.py의 parse_network_events()로 구조화되는지
  (2026-09-14: network만 줄 단위 fallback이던 것을 나머지 계층과 동일하게 맞춤)
- 여러 source_type(web/auth/audit/network)을 다 훑는지
- 데이터 없는 source_type은 에러 없이 조용히 건너뛰는지 (현재 auditd/nginx만 연결된 상태 재현)
- 각 레코드에 _source_type이 붙는지
를 검증한다.
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


def now_minus(base: datetime, **kwargs) -> str:
    """base - timedelta(**kwargs)를 nginx JSON 로그의 ts 필드 형식(ISO+오프셋)으로."""
    dt = base - timedelta(**kwargs)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"


def test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing() -> None:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    recent_epoch = int((now - timedelta(minutes=2)).timestamp())
    old_epoch = int((now - timedelta(hours=5)).timestamp())

    audit_prefix = f"raw/source_type=auditd/host=web-01/dt={today}/"
    web_prefix = f"raw/source_type=nginx/host=web-01/dt={today}/"
    # auth, network(suricata) 파티션은 아예 데이터 없음 (인프라 미연결 상황 재현)

    audit_text = (
        f'type=SYSCALL msg=audit({recent_epoch}.100:9001): pid=3812 uid=33 comm="sh" key="susp_exec"\n'
        f'type=SYSCALL msg=audit({old_epoch}.100:9000): pid=1234 uid=0 comm="cron" key="sensitive"\n'
    ).encode("utf-8")

    recent_iso = now_minus(now, minutes=2)
    old_iso = now_minus(now, hours=5)
    # 실제 EC2 sample_web.log 형식(한 줄 = JSON 객체, nginx 로그) 그대로 재현.
    web_text = (
        '{"ts":"%s","req_id":"r1","src_ip":"77.239.124.213","src_port":"51234",'
        '"dst_ip":"10.0.7.236","dst_port":"443","scheme":"https","host":"ogwanwan.shop",'
        '"method":"POST","uri":"/wp-login.php","proto":"HTTP/1.1","status":"200","bytes":"259",'
        '"rt":"0.566","xff_orig":"","ref":"","ua":"curl/7.0","upstream":"127.0.0.1:8080",'
        '"ustatus":"200"}\n'
        '{"ts":"%s","req_id":"r2","src_ip":"9.9.9.9","src_port":"1","dst_ip":"10.0.7.236",'
        '"dst_port":"443","scheme":"https","host":"ogwanwan.shop","method":"GET",'
        '"uri":"/old-request","proto":"HTTP/1.1","status":"200","bytes":"100","rt":"0.05",'
        '"xff_orig":"","ref":"","ua":"Mozilla/5.0","upstream":"127.0.0.1:8080","ustatus":"200"}\n'
    ) % (recent_iso, old_iso)
    web_text = web_text.encode("utf-8")

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
        assert audit_records[0]["pid"] == 3812

        web_records = [r for r in records if r["_source_type"] == "web"]
        # 이제 web도 시간 필터가 적용됨 -> 5시간 전(old-request)은 제외되고 1건만 남아야 함
        assert len(web_records) == 1, "시간 범위 밖의 old-request는 제외되어야 한다"
        assert web_records[0]["src_ip"] == "77.239.124.213"

        print("[PASS] test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing")
    finally:
        _uninstall_fake_boto3()


def test_fetch_recent_raw_logs_structures_network_source() -> None:
    """network 소스도 audit/web/auth와 동일하게 network_parser.py로 구조화되는지,
    시간 필터가 적용되는지 확인한다. (2026-09-14: network만 줄 단위 fallback이던
    것을 audit/web/auth와 동일한 패턴으로 맞춤)
    """
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    network_prefix = f"raw/source_type=suricata/host=web-01/dt={today}/"

    recent_iso = now_minus(now, minutes=2)
    old_iso = now_minus(now, hours=5)
    network_text = (
        '{"timestamp":"%s","event_type":"alert","src_ip":"77.239.124.213",'
        '"dest_ip":"10.0.7.236","src_port":51234,"dest_port":22,"proto":"TCP",'
        '"alert":{"signature":"ET SCAN SSH BruteForce"}}\n'
        '{"timestamp":"%s","event_type":"alert","src_ip":"9.9.9.9",'
        '"dest_ip":"10.0.7.236","src_port":1,"dest_port":1,"proto":"TCP",'
        '"alert":{"signature":"old alert"}}\n'
    ) % (recent_iso, old_iso)
    network_text = network_text.encode("utf-8")

    fake_client = _FakeS3Client({network_prefix: {"eve.json": network_text}})
    _install_fake_boto3(fake_client)

    try:
        from agent.raw_log_ingestion import fetch_recent_raw_logs

        records = fetch_recent_raw_logs(host="web-01", minutes=10, source_types=["network"])

        assert len(records) == 1, "시간 범위 밖의 old alert(5시간 전)는 제외되어야 한다"
        record = records[0]
        assert record["_source_type"] == "network"
        assert record["src_ip"] == "77.239.124.213"
        assert record["alert_signature"] == "ET SCAN SSH BruteForce"
        print("[PASS] test_fetch_recent_raw_logs_structures_network_source")
    finally:
        _uninstall_fake_boto3()


if __name__ == "__main__":
    test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing()
    test_fetch_recent_raw_logs_structures_network_source()
    print("\n모든 테스트 통과.")