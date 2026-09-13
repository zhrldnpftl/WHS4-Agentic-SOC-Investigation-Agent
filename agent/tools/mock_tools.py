"""실제 팀원 구현 전 로컬 테스트용 목업 도구 핸들러.

fetch_web_log / fetch_auth_log 담당,
fetch_audit_log / fetch_network_log / get_process_tree 담당의
구현이 완성되면, build_default_registry(handlers={...})로 실제 함수를 넘겨
아래 목업을 교체하면 된다. 반환 형식(count/summary/records)은 그대로 유지해야
loop.py / prompts.py가 수정 없이 동작한다.

문서 7번(최종 산출물 예시)의 웹셸 업로드 시나리오 값을 기본 목업 데이터로 사용한다.
"""

from __future__ import annotations

from typing import Any, Dict


def _mock_fetch_web_log(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "1건의 파일 업로드 기록 (HTTP 200)",
        "records": [
            {
                "time": "2026-09-09T10:01:12Z",
                "src_ip": "203.0.113.45",
                "method": "POST",
                "path": "/upload.php",
                "status": 200,
            }
        ],
    }


def _mock_fetch_auth_log(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "www-data의 정상 로그인 1건, 이상 권한상승 없음",
        "records": [
            {"time": "2026-09-09T10:05:30Z", "user": "www-data", "result": "success"}
        ],
    }


def _mock_fetch_audit_log(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "웹셸 실행 명령어 및 PID 3812 확인",
        "records": [
            {
                "time": "2026-09-09T10:05:45Z",
                "pid": 3812,
                "ppid": 3701,
                "exe": "/bin/sh",
                "exec_args": "-i",
                "resolved_saddr": None,
            }
        ],
    }


def _mock_fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "외부 IP로의 역연결 시도, Reverse Shell 시그니처 감지",
        "records": [
            {
                "time": "2026-09-09T10:06:10Z",
                "dst_ip": "203.0.113.99",
                "dst_port": 4444,
                "signature": "reverse_shell",
            }
        ],
    }


def _mock_get_process_tree(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "PID 3812의 부모는 apache worker(PPID 3701)",
        "records": [{"pid": 3812, "ppid": 3701, "parent_process": "apache2"}],
    }


def _mock_resolve_ip_geo(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "count": 1,
        "summary": "해당 IP는 국내에서 잘 관측되지 않는 해외 IP",
        "records": [{"ip": args.get("ip"), "country": "XX", "is_known_bad": True}],
    }


MOCK_HANDLERS = {
    "fetch_web_log": _mock_fetch_web_log,
    "fetch_auth_log": _mock_fetch_auth_log,
    "fetch_audit_log": _mock_fetch_audit_log,
    "fetch_network_log": _mock_fetch_network_log,
    "get_process_tree": _mock_get_process_tree,
    "resolve_ip_geo": _mock_resolve_ip_geo,
}
