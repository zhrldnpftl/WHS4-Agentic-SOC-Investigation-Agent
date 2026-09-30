"""fetch_auth_log(agent/tools/real/fetch_auth_log.py) 단독 테스트.

실제 AWS에 붙지 않고, 임시 로그 파일을 계층별 로그 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH)로 지정해서(tests/_log_files.py)
- ssh_failed(root/invalid user)/ssh_accepted/sudo_command 이벤트가 정확히 분류되는지
- sudo는 rhost가 없으면 src_ip가 None인지
- src_ip/user/event_type/result 필터가 되는지
- limit/offset 페이지네이션이 팀원 설계대로(has_more/next_offset) 동작하는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

2026-09-22 (B: 조사 도구 담당) 업데이트: fetch_auth_log가 자체 파서 대신 1차 탐지팀
공통 정규화 함수(agent/tools/normalizer_adapter.py)를 쓰도록 바뀌면서 필드명이
event_type→event, source_ip→src_ip로, 이벤트 값도 더 세분화됐다(예전 "ssh_login"
하나가 이제 "ssh_accepted"/"ssh_failed"로 나뉨, "sudo"는 "sudo_command"). 이 테스트도
그에 맞춰 갱신했다.

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_auth_log`로 실행 가능.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any, Dict, List

from tests._log_files import install_log_files, uninstall_log_files

# 1차 탐지 정규화 원본(저장소 루트 detection_pipeline/tools/fetch_auth_log.py)은
# 파일 맨 아래에서 무조건 load_dotenv()를 호출한다. 예전에는 이 import가 처음 실행되는 순간
# 로컬 .env에 적어둔 AUTH_LOG_PATH 같은 값이 os.environ에 들어와, 테스트가 만든 임시 로그 파일
# 대신 실제 로컬 파일을 읽어 count가 안 맞는 식으로 깨졌다(재현·확인함). 지금은
# normalizer_adapter가 import 중 load_dotenv()를 막지만(tests/test_cd_normalizer_integration.py
# test_adapter_import_does_not_load_root_dotenv), 셸에 이미 설정된 경로가 있을 수 있으므로
# 여기서 import를 한 번 트리거하고 곧바로 관련 환경변수를 비워서 이후 모든 테스트가 항상
# 테스트가 만든 임시 로그 파일만 읽도록 만든다.
import agent.tools.real.fetch_auth_log as _load_dotenv_trigger  # noqa: F401
for _env_name in ("AUTH_LOG_PATH", "AUDIT_LOG_PATH", "APACHE_LOG_PATH", "SURICATA_LOG_PATH"):
    os.environ.pop(_env_name, None)


def _install_log(pieces: Dict[str, Dict[str, bytes]]) -> None:
    install_log_files(pieces, layer="auth")


def _uninstall_log() -> None:
    uninstall_log_files(['agent.tools.real.fetch_auth_log'])


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
    pieces = ({prefix: {"auth.log": _sample_auth_text()}})
    _install_log(pieces)

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
        by_user = {r["user"]: r for r in result["records"] if r["event"] == "ssh_failed"}
        assert by_user["root"]["result"] == "failure"
        assert by_user["testuser"]["result"] == "failure"

        accepted = next(r for r in result["records"] if r["event"] == "ssh_accepted")
        assert accepted["user"] == "ubuntu"
        assert accepted["result"] == "success"
        assert accepted["src_ip"] == "112.148.16.1"

        sudo_event = next(r for r in result["records"] if r["event"] == "sudo_command")
        assert sudo_event["src_ip"] is None, "sudo 줄엔 rhost가 없으니 src_ip는 None이어야 한다"
        print("[PASS] test_fetch_auth_log_classifies_four_event_types")
    finally:
        _uninstall_log()


def test_fetch_auth_log_filters_by_src_ip_user_event_type_result() -> None:
    prefix = "raw/source_type=auth/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"auth.log": _sample_auth_text()}})
    _install_log(pieces)

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
                "event_type": "sudo_command",
            }
        )
        assert by_event_type["count"] == 1
        print("[PASS] test_fetch_auth_log_filters_by_src_ip_user_event_type_result")
    finally:
        _uninstall_log()


def test_fetch_auth_log_pagination_matches_teammate_design() -> None:
    """1차: limit=2,offset=0 -> has_more=True, next_offset=2.
    2차: 그 next_offset을 그대로 offset에 넣으면 나머지 2건이 나오고 has_more=False.
    """
    prefix = "raw/source_type=auth/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"auth.log": _sample_auth_text()}})
    _install_log(pieces)

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
        _uninstall_log()


def test_fetch_auth_log_reports_missing_partition() -> None:
    pieces = ({})
    _install_log(pieces)

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
        _uninstall_log()


if __name__ == "__main__":
    test_fetch_auth_log_classifies_four_event_types()
    test_fetch_auth_log_filters_by_src_ip_user_event_type_result()
    test_fetch_auth_log_pagination_matches_teammate_design()
    test_fetch_auth_log_reports_missing_partition()
    print("\n모든 테스트 통과.")