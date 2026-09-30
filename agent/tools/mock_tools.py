"""목업 도구 핸들러 — agent/tools/real/에 실제 구현이 없는 도구의 대체품.

누가 부르나
  agent/tools/registry.py build_default_registry()  실제 구현을 못 찾으면 여기로 폴백
  오프라인 테스트(tests/)                          가짜 도구 결과가 필요할 때

지금은 모든 도구에 실제 구현이 있어 운영(main.py)에서는 쓰이지 않는다.
반환 형식(count/summary/records)은 실제 도구와 같아야 loop.py·prompts가 수정 없이 동작한다.
값은 웹셸 업로드 시나리오 예시 데이터다.
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


MOCK_HANDLERS = {
    "fetch_web_log": _mock_fetch_web_log,
    "fetch_auth_log": _mock_fetch_auth_log,
    "fetch_audit_log": _mock_fetch_audit_log,
    "fetch_network_log": _mock_fetch_network_log,
    "get_process_tree": _mock_get_process_tree,
}
