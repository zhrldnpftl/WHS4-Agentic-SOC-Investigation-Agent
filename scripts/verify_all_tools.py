"""5개 real tool + raw_log_ingestion(4계층 수집)이 전부 정상 동작하는지 한 번에 확인한다.

.env에 설정된 *_LOCAL_PATH(sample_*.log)를 그대로 사용한다 — AWS 자격 증명이나
별도 설정 없이 지금 프로젝트 루트에서 바로 실행하면 된다.

사용법:
    python scripts/verify_all_tools.py
"""

from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

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
    from agent.tools.parsers.audit_parser import parse_audit_events
    from agent.tools.real.get_process_tree import get_process_tree

    # audit 샘플에서 실제로 존재하는 pid를 하나 뽑아서 그걸로 조회한다
    # (없는 pid로 조회하면 정상적으로 count=0이 나오는 거라 검증 의미가 없음).
    local_path = os.environ.get("AUDIT_LOG_LOCAL_PATH")
    if not local_path or not os.path.exists(local_path):
        print(f"\n{'=' * 10} get_process_tree {'=' * 10}")
        print("[건너뜀] AUDIT_LOG_LOCAL_PATH가 없어서 실제 pid를 못 뽑음")
        return True

    with open(local_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    events = parse_audit_events(text)
    if not events:
        print(f"\n{'=' * 10} get_process_tree {'=' * 10}")
        print("[의심] audit 샘플에서 이벤트를 하나도 못 뽑음")
        return True

    sample_pid = events[0]["pid"]
    return _check(
        f"get_process_tree (pid={sample_pid})",
        lambda: get_process_tree({"host": "web-01", "pid": sample_pid, **WIDE_RANGE}),
    )


def check_raw_log_ingestion() -> bool:
    from agent.raw_log_ingestion import fetch_recent_raw_logs

    print(f"\n{'=' * 10} raw_log_ingestion (4계층 수집) {'=' * 10}")
    try:
        records = fetch_recent_raw_logs(host="web-01", minutes=10)
    except Exception:
        print("[FAIL] 예외 발생:")
        traceback.print_exc()
        return False

    by_source = {}
    for r in records:
        by_source[r["_source_type"]] = by_source.get(r["_source_type"], 0) + 1

    print(f"총 {len(records)}건, 소스별: {by_source}")
    missing = {"web", "auth", "audit", "network"} - set(by_source.keys())
    if missing:
        print(f"[의심] 이번에 0건인 소스: {missing} (에러는 아니지만 *_LOCAL_PATH 설정 확인해볼 것)")
    else:
        print("[PASS] 4계층 전부 최소 1건 이상 수집됨")
    return True


def main() -> None:
    checks = [
        ("fetch_audit_log", check_fetch_audit_log),
        ("fetch_web_log", check_fetch_web_log),
        ("fetch_auth_log", check_fetch_auth_log),
        ("fetch_network_log", check_fetch_network_log),
        ("get_process_tree", check_get_process_tree),
        ("raw_log_ingestion", check_raw_log_ingestion),
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