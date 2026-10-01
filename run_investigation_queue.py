"""run_investigation_queue.py — 조사 큐 폴러 (탐지 DB 큐 → 조사 에이전트 → 상태 되돌려쓰기)

탐지(run_pipeline 운영 모드)가 DB(soc.db)에 쌓은 pending 사건을, 조사 에이전트
(llm/investigate/main.py)에 하나씩 넘겨 조사하고 결과에 따라 done/재조사로 표시한다.
탐지와는 별도 프로세스로 돈다(설계: 탐지는 초 단위·타이머, 조사는 LLM이라 분 단위). 5분마다
한 번 실행하거나 수동 실행한다. 큐가 비면 아무것도 안 한다(첫·마지막 특별 처리 불필요).

  claim(pending→investigating) → 에이전트 실행 → 결과 status 로
    · 조사 완료      → done  (조사 중 새 활동 has_update 면 pending 재오픈)
    · 미완료/실패    → pending 재개(다음 틱 재시도, 누락보다 중복)
  도중에 죽어 investigating 에 낀 사건은 stale 시간이 지나면 pending 으로 회수한다.

에이전트는 블랙박스 CLI로 부른다(내부 import 안 함 — 프로세스 격리·설계 존중). 로그 경로·키는
.env 를 공유한다(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH, ANTHROPIC_API_KEY). 에이전트는 사건
파일만 받고 soc.db 는 건드리지 않는다 — 상태는 이 폴러만 쓴다.

예)
  python run_investigation_queue.py --state-dir /var/lib/agentic-soc
  python run_investigation_queue.py --state-dir /tmp/soc --limit 5
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_ROOT, "detection_pipeline"))

from store.db import DB_FILE, connect, migrate  # noqa: E402
from store.incidents import (  # noqa: E402
    claim_incident,
    finish_incident,
    get_incident,
    list_queue,
    reclaim_stale,
    release_incident,
)
from pipeline.state import run_lock  # noqa: E402

AGENT_MAIN = os.path.join(_ROOT, "llm", "investigate", "main.py")
RESULTS_DIR = os.path.join(_ROOT, "results", "investigation_agent")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _incident_from_row(row):
    """get_incident() 행 → 조사 에이전트가 읽는 Incident dict.

    에이전트의 incident_input.to_investigation_seed 가 쓰는 필드만 원래 모양으로 되돌린다
    (DB 는 entity/window 를 컬럼으로 펼쳐 저장하므로 다시 합친다)."""
    extra = row.get("extra") or {}
    inc = {
        "incident_id": row.get("incident_id"),
        "incident_key": row.get("incident_key"),
        "entity": {"type": row.get("entity_type"), "value": row.get("entity_value")},
        "window": [row.get("window_start"), row.get("window_end")],
        "layers": row.get("layers") or [],
        "members": row.get("members") or [],
        "seeds": row.get("seeds") or [],
        "join_path": row.get("join_path") or [],
        "member_count": row.get("member_count"),
        "oversized": extra.get("oversized", False),
    }
    if row.get("llm_reason"):
        inc["llm_reason"] = row["llm_reason"]
    if row.get("updated_at"):
        inc["updated_at"] = row["updated_at"]
    return inc


def _run_agent_subprocess(incident_file):
    """조사 에이전트를 블랙박스 CLI로 실행한다(cwd=repo 루트 — .env·로그 경로 공유).

    -u: 출력이 파이프(systemd 저널·tee)여도 에이전트 진행 줄([조사] ...)이 버퍼에 묶이지 않고 바로 보이게."""
    subprocess.run([sys.executable, "-u", AGENT_MAIN, incident_file], cwd=_ROOT, check=True)


def _result_status(results_dir, before, key, incident_id):
    """이번 실행으로 새로 생긴 결과 파일 중 이 사건 것을 찾아 investigation_status 를 돌려준다.

    반환: status 문자열(없으면 None = 결과 없음). 판정이 없는 완료 결과는 "DONE" 으로 본다."""
    if not os.path.isdir(results_dir):
        return None
    for name in os.listdir(results_dir):
        if not name.endswith(".json") or name in before:
            continue
        try:
            with open(os.path.join(results_dir, name), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if data.get("incident_key") == key or data.get("incident_id") == incident_id:
            return data.get("investigation_status") or "DONE"
    return None


def investigate_one(conn, key, run_agent=_run_agent_subprocess, results_dir=RESULTS_DIR):
    """사건 하나: claim → 에이전트 → 결과 status 로 done/재시도. 처리 결과 문자열 반환."""
    row = get_incident(conn, key)
    if row is None:
        return "missing"
    if not claim_incident(conn, key, _iso(datetime.now(timezone.utc))):
        return "skip"  # 다른 폴러가 이미 집었거나 상태가 바뀜
    inc = _incident_from_row(row)
    before = set(os.listdir(results_dir)) if os.path.isdir(results_dir) else set()
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="inc_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(inc, fh, ensure_ascii=False)
        try:
            run_agent(tmp)
        except (subprocess.CalledProcessError, OSError) as exc:
            release_incident(conn, key)
            return "agent_error: %s" % exc
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    status = _result_status(results_dir, before, key, inc.get("incident_id"))
    if status is None or status == "INCOMPLETE":
        release_incident(conn, key)   # 결과 없음·LLM 미완료 → 다음 틱 재시도
        return "retry(%s)" % (status or "no_result")
    finish_incident(conn, key)
    return "done(%s)" % status


def run(state_dir, limit=20, stale_minutes=30, run_agent=_run_agent_subprocess,
        results_dir=RESULTS_DIR, now=None):
    """큐 한 바퀴: stale 회수 → pending 을 급한 순으로 조사."""
    now = now or datetime.now(timezone.utc)
    db = os.path.join(state_dir, DB_FILE)
    if not os.path.exists(db):
        print("[investigate] DB 없음(%s) — 탐지 운영 모드가 한 번 돌면 생긴다" % db)
        return {"processed": 0}
    conn = connect(db)
    migrate(conn)
    with run_lock(os.path.join(state_dir, "investigate_lock")) as locked:
        if not locked:
            print("[investigate] 다른 폴러가 실행 중 — 이번 틱 건너뜀")
            return {"processed": 0, "skipped": True}
        reclaimed = reclaim_stale(conn, _iso(now - timedelta(minutes=stale_minutes)))
        if reclaimed:
            print("[investigate] stale 회수 %d건(investigating→pending)" % reclaimed)
        results = {}
        queue = list_queue(conn, limit=limit)
        print("[investigate] 대기열 %d건 조사 시작(limit %d)" % (len(queue), limit), flush=True)
        for index, row in enumerate(queue, 1):
            key = row["incident_key"]
            print("[investigate] (%d/%d) %s %s %s %s=%s — 조사 에이전트 실행"
                  % (index, len(queue), key, row.get("incident_id") or "-", row.get("priority") or "-",
                     row.get("entity_type") or "-", row.get("entity_value") or "-"), flush=True)
            started = time.monotonic()
            outcome = investigate_one(conn, key, run_agent=run_agent, results_dir=results_dir)
            results[key] = outcome
            print("[investigate] (%d/%d) %s → %s (%.1fs)"
                  % (index, len(queue), key, outcome, time.monotonic() - started), flush=True)
    print("[investigate] 처리 %d건" % len(results), flush=True)
    return {"processed": len(results), "results": results}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-dir", required=True,
                    help="soc.db 가 있는 디렉터리(탐지 운영 모드 --state-dir 와 동일)")
    ap.add_argument("--limit", type=int, default=20, help="한 번에 조사할 최대 사건 수")
    ap.add_argument("--stale-minutes", type=int, default=30,
                    help="investigating 에 이 시간 이상 낀 사건은 재시도 대상으로 회수")
    args = ap.parse_args()
    run(args.state_dir, limit=args.limit, stale_minutes=args.stale_minutes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
