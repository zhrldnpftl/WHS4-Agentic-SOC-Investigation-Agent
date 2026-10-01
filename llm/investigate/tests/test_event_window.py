"""Offline C tests: real temporary files, no model or AWS credentials."""
import gzip
import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.real.fetch_event_logs import fetch_event_logs
from agent.tools.registry import build_default_registry


WINDOW = ["2026-09-21T00:00:00Z", "2026-09-21T00:01:00Z"]


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for key in [*LOCAL_PATH_ENV.values(), "HOST", "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(key, raising=False)


def local_log(tmp_path, monkeypatch, layer, text):
    path = tmp_path / f"{layer}.log"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv(LOCAL_PATH_ENV[layer], str(path))
    return path.name


def web_line(timestamp, ip="192.0.2.10"):
    return (f'{timestamp} r1 {ip} 127.0.0.1 https example.test '
            '"POST /login HTTP/1.1" 200 100 1000 42 "-" "test-agent" xff="-"')


def query(**kwargs):
    return fetch_event_logs({"host": "web-01", "window": WINDOW, "layers": ["web"], **kwargs})


def test_inclusive_window_offset_and_physical_lines(tmp_path, monkeypatch):
    text = "\n".join([web_line("2026-09-20T23:59:59Z"), "", "not json",
                       web_line(WINDOW[0]), web_line("2026-09-21T09:00:30+09:00"),
                       web_line(WINDOW[1]), web_line("2026-09-21T00:01:01Z")])
    path = local_log(tmp_path, monkeypatch, "web", text)
    result = query(limit=2)
    assert result["total_matched"] == 3
    assert [r["raw_ref"] for r in result["records"]] == [f"{path}:4", f"{path}:5"]
    assert result["next_offset"] == 2
    last = query(limit=2, offset=result["next_offset"])
    assert last["records"][0]["raw_ref"] == f"{path}:6"
    assert last["next_offset"] is None
    assert query(offset=99)["records"] == []


def test_timestamp_event_and_primary_detection_window(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    registry = build_default_registry()
    result = registry.call("fetch_event_logs", {"host": "web-01", "event": {
        "timestamp": WINDOW[0], "layer": "web", "raw_ref": "upstream:7"},
        "before_seconds": 0, "after_seconds": 0})
    assert result["count"] == 1
    result = registry.call("fetch_event_logs", {"host": "web-01", "event": {
        "entity": {"type": "src_ip", "value": "192.0.2.10"}, "window": WINDOW,
        "layer": "web", "evidence_refs": ["upstream:7"]}})
    assert result["count"] == 1


def test_cross_layer_global_pagination_and_filters(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line("2026-09-21T00:00:20Z"))
    local_log(tmp_path, monkeypatch, "network", json.dumps({
        "timestamp": "2026-09-21T00:00:10Z", "event_type": "http", "src_ip": "192.0.2.10"}))
    local_log(tmp_path, monkeypatch, "auth",
              "Sep 21 00:00:30 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n")
    args = {"layers": ["web", "network", "auth"], "limit": 1}
    pages = [query(**args, offset=i) for i in range(3)]
    assert [page["records"][0]["layer"] for page in pages] == ["network", "web", "auth"]
    assert all(page["total_matched"] == 3 for page in pages)
    assert query(layers=["auth"], filters={"auth": {"src_ip": "203.0.113.7"}})["count"] == 0


def test_audit_multiline_enriched_distinct_events(tmp_path, monkeypatch):
    epoch = int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())
    text = (f'type=SYSCALL msg=audit({epoch}.100:42): pid=5 syscall=59 uid=33\x1dSYSCALL SYSCALL=execve UID="www-data"\n'
            f'type=EXECVE msg=audit({epoch}.100:42): argc=1 a0="id"\n\n'
            f'type=SYSCALL msg=audit({epoch + 30}.100:43): pid=6 syscall=59\n')
    path = local_log(tmp_path, monkeypatch, "audit", text)
    result = query(layers=["system", "audit"])
    assert result["count"] == 2  # alias not queried twice; vendor owns event assembly
    event = result["records"][0]
    assert event["user"] == "www-data" and event["exec_args"] == "id"
    assert event["raw_refs"] == [f"{path}:1", f"{path}:2"]
    assert result["records"][1]["raw_ref"] == f"{path}:4"


def test_auth_new_year_window(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "auth",
              "Dec 31 23:59:59 web-01 sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
              "Jan  1 00:00:01 web-01 sshd[1]: Accepted password for root from 192.0.2.10 port 22 ssh2\n")
    result = query(layers=["auth"], window=["2026-12-31T23:59:58Z", "2027-01-01T00:00:02Z"])
    assert [r["timestamp"][:4] for r in result["records"]] == ["2026", "2027"]


@pytest.mark.parametrize("layer,text", [
    ("web", web_line("bad time")),
    ("network", '{"event_type":"http","src_ip":"192.0.2.10"}'),
])
def test_undated_logs_cannot_enter_window(tmp_path, monkeypatch, layer, text):
    local_log(tmp_path, monkeypatch, layer, text)
    assert query(layers=[layer])["count"] == 0


@pytest.mark.parametrize("args", [
    {"window": WINDOW[::-1]}, {"window": [WINDOW[0]]}, {"window": [None, WINDOW[1]]},
    {"limit": 0}, {"offset": -1}, {"limit": True}, {"limit": 1.5},
    {"layers": []}, {"layers": ["unknown"]}, {"layers": "web"},
    {"event": []}, {"filters": {"web": {"host": "other"}}}, {"host": ""},
])
def test_reject_invalid_query_before_io(args):
    with pytest.raises(ValueError):
        query(**args)


def test_missing_and_permission_errors_are_not_empty_success(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    monkeypatch.setenv("AUTH_LOG_PATH", str(tmp_path / "missing.log"))
    result = query(layers=["web", "auth"])
    assert result["partial"] is True and result["count"] == 1
    assert result["errors"] == {"auth": "not_found"}
    import agent.tools.log_source as source
    monkeypatch.setattr(source, "read_documents", lambda *a, **kw: (_ for _ in ()).throw(PermissionError()))
    assert query()["errors"] == {"web": "permission_denied"}


def _set_mtime(path, iso):
    stamp = datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    os.utime(path, (stamp, stamp))


def test_rotated_logs_are_read_with_primary_detection_refs(tmp_path, monkeypatch):
    # logrotate 뒤: 구간 기록이 web.log.1·web.log.2.gz로 넘어가고 web.log에는 다음 날 기록만 있다
    # (2026-10-01 EC2: 1차 탐지 근거 access.log.1:1988을 조사 도구가 못 읽어 0건)
    local_log(tmp_path, monkeypatch, "web", web_line("2026-09-22T00:00:00Z") + "\n")
    (tmp_path / "web.log.1").write_text(
        web_line("2026-09-20T23:00:00Z") + "\n" + web_line("2026-09-21T00:00:40Z") + "\n", encoding="utf-8")
    with gzip.open(tmp_path / "web.log.2.gz", "wt", encoding="utf-8") as stream:
        stream.write(web_line(WINDOW[0]) + "\n")
    # 구간 시작 전에 마지막으로 쓰인 교체 파일은 구간 기록이 있을 수 없어 읽지 않는다(1차 탐지와 같은 규칙)
    with gzip.open(tmp_path / "web.log.3.gz", "wt", encoding="utf-8") as stream:
        stream.write(web_line(WINDOW[0]) + "\n")
    _set_mtime(tmp_path / "web.log.3.gz", "2026-09-20T12:00:00Z")

    result = query()
    assert [r["raw_ref"] for r in result["records"]] == ["web.log.2:1", "web.log.1:2"]
    assert "errors" not in result or not result["errors"]


def test_rotated_logs_without_current_file(tmp_path, monkeypatch):
    # 교체 직후 새 파일이 아직 없을 때도 교체 파일을 읽는다
    monkeypatch.setenv(LOCAL_PATH_ENV["web"], str(tmp_path / "web.log"))
    (tmp_path / "web.log.1").write_text(web_line(WINDOW[0]) + "\n", encoding="utf-8")
    assert [r["raw_ref"] for r in query()["records"]] == ["web.log.1:1"]


def test_quiet_current_file_is_still_read(tmp_path, monkeypatch):
    # 구간 이후 기록이 없어 현재 파일 mtime이 구간 시작보다 이르면: '파일 없음'이 아니라 0건
    local_log(tmp_path, monkeypatch, "web", web_line("2026-09-20T00:00:00Z") + "\n")
    _set_mtime(tmp_path / "web.log", "2026-09-20T00:00:01Z")
    result = query()
    assert result["count"] == 0 and not result.get("errors")


def test_local_host_guard(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    monkeypatch.setenv("LOG_LOCAL_HOST", "web-02")
    with pytest.raises(ValueError, match="host mismatch"):
        query()


