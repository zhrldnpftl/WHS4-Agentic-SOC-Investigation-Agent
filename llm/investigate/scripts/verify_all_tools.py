"""5개 real tool이 전부 정상 동작하는지 한 번에 확인한다.

저장소 루트 .env의 계층별 로그 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH)를 그대로 사용한다 —
AWS 자격 증명이나 별도 설정 없이 llm/investigate/에서 바로 실행하면 된다. 이미 설정된 환경변수가 우선한다.

사용법:
    python -m scripts.verify_all_tools
"""

from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.settings import load_root_env  # noqa: E402

load_root_env()

WIDE_RANGE = {"start_time": "2020-01-01T00:00:00Z", "end_time": "2030-01-01T00:00:00Z"}


def _check(name: str, fn):
    print(f"\n{'=' * 10} {name} {'=' * 10}")
    try:
        result = fn()
    except Exception:
        print("[FAIL] 예외 발생:")
        traceback.print_exc()
        return False

    count = result.get("count")
    summary = result.get("summary")
    print(f"count = {count}")
    print(f"summary = {summary}")

    if count is None:
        print(f"[FAIL] {name}: 반환값에 count가 없음")
        return False
    if count == 0:
        print(f"[의심] {name}: count=0 — 샘플 파일 형식/경로/필터를 확인해보세요 (에러는 아님)")
        return True
    print(f"[PASS] {name}: {count}건 확인됨")
    return True


def check_fetch_audit_log() -> bool:
    from agent.tools.real.fetch_audit_log import fetch_audit_log

    return _check("fetch_audit_log", lambda: fetch_audit_log({"host": "web-01", **WIDE_RANGE}))


def check_fetch_web_log() -> bool:
    from agent.tools.real.fetch_web_log import fetch_web_log

    return _check("fetch_web_log", lambda: fetch_web_log({"host": "web-01", **WIDE_RANGE}))


def check_fetch_auth_log() -> bool:
    from agent.tools.real.fetch_auth_log import fetch_auth_log

    return _check("fetch_auth_log", lambda: fetch_auth_log({"host": "web-01", **WIDE_RANGE}))


def check_fetch_network_log() -> bool:
    from agent.tools.real.fetch_network_log import fetch_network_log

    return _check("fetch_network_log", lambda: fetch_network_log({"host": "web-01", **WIDE_RANGE}))


def check_get_process_tree() -> bool:
    # 2026-09-22 업데이트: 자체 파서(parsers/audit_parser.py) 대신 1차 탐지팀 공통
    # 정규화 함수(agent/tools/normalizer_adapter.py의 normalize_audit(),
    # get_process_tree.py가 실제로 쓰는 것과 동일)로 샘플 pid를 뽑도록 바꿨다 —
    # 이걸로 audit_parser.py를 부르는 코드가 프로젝트 전체에서 완전히 사라졌다
    # (진짜로 삭제해도 된다).
    from agent.tools.normalizer_adapter import normalize_audit
    from agent.tools.real.get_process_tree import get_process_tree

    # audit 샘플에서 실제로 존재하는 pid를 하나 뽑아서 그걸로 조회한다
    # (없는 pid로 조회하면 정상적으로 count=0이 나오는 거라 검증 의미가 없음).
    local_path = os.environ.get("AUDIT_LOG_PATH")
    if not local_path or not os.path.exists(local_path):
        print(f"\n{'=' * 10} get_process_tree {'=' * 10}")
        print("[건너뜀] AUDIT_LOG_PATH가 없어서 실제 pid를 못 뽑음")
        return True

    events = normalize_audit("web-01", WIDE_RANGE["start_time"], WIDE_RANGE["end_time"])
    # 공통스키마의 pid는 값이 없는 audit 이벤트 타입(예: pid 없는 항목)도 있어서
    # None일 수 있다 — pid가 실제로 찍힌 첫 이벤트를 찾는다.
    sample_pid = next((e["pid"] for e in events if e.get("pid") is not None), None)
    if sample_pid is None:
        print(f"\n{'=' * 10} get_process_tree {'=' * 10}")
        print("[의심] audit 샘플에서 pid가 있는 이벤트를 하나도 못 뽑음")
        return True

    return _check(
        f"get_process_tree (pid={sample_pid})",
        lambda: get_process_tree({"host": "web-01", "pid": sample_pid, **WIDE_RANGE}),
    )


def main() -> None:
    checks = [
        ("fetch_audit_log", check_fetch_audit_log),
        ("fetch_web_log", check_fetch_web_log),
        ("fetch_auth_log", check_fetch_auth_log),
        ("fetch_network_log", check_fetch_network_log),
        ("get_process_tree", check_get_process_tree),
    ]

    results = {}
    for name, fn in checks:
        results[name] = fn()

    print(f"\n\n{'#' * 15} 최종 요약 {'#' * 15}")
    for name, ok in results.items():
        print(f"  {'OK ' if ok else 'FAIL'} - {name}")

    if all(results.values()):
        print("\n예외 없이 전부 실행됨 (count=0/의심 항목은 위 로그에서 개별 확인)")
    else:
        print("\n일부 tool에서 예외 발생 — 위 traceback 확인 필요")


if __name__ == "__main__":
    main()