"""run_investigation_queue.py 자가 점검 — 가짜 에이전트로 큐 상태 전이 검증.

실제 LLM/에이전트 없이 run_agent 를 주입해 claim→done, 미완료→pending 재시도,
에이전트 오류→pending, stale 회수, 빈 큐 no-op 을 확인한다.
실행: python tests/test_investigation_queue.py  또는  python -m unittest
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)                                      # run_investigation_queue
sys.path.insert(0, os.path.join(_ROOT, "detection_pipeline"))  # store, pipeline

import run_investigation_queue as q  # noqa: E402
from store.db import connect, migrate  # noqa: E402
from store.incidents import get_incident, record_run  # noqa: E402
from pipeline.state import diff_incidents, incident_key  # noqa: E402

NOW = datetime(2026, 9, 11, 3, 0, 0, tzinfo=timezone.utc)


def make_incident(iid="INC-1", ip="45.9.1.2"):
    return {
        "incident_id": iid,
        "entity": {"type": "src_ip", "value": ip},
        "window": ["2026-09-11T02:00:00Z", "2026-09-11T02:01:00Z"],
        "layers": ["web", "system"],
        "members": ["access.log:1"],
        "member_count": 1,
        "seeds": [{
            "reason": "웹셸 업로드", "evidence_refs": ["access.log:1"], "rule_name": "apache_x",
            "layer": "web", "score_parts": {"rule_severity": "high"},
            "detail": {"timestamp": "2026-09-11T02:00:03Z"},
        }],
        "join_path": [],
        "triage_score": 90, "priority": "P1", "route": "investigate", "llm_investigate": 1,
    }


class QueueTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "soc.db")
        self.results = os.path.join(self.dir, "results")
        conn = connect(self.db)
        migrate(conn)
        inc = make_incident()
        emits, state = diff_incidents([inc], {}, NOW)
        record_run(conn, emits, state, NOW)
        conn.close()
        self.key = incident_key(inc)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _fake(self, status):
        """사건 파일을 읽어 그 사건의 결과 JSON을 results_dir에 쓰는 가짜 에이전트."""
        def run(incident_file):
            with open(incident_file, encoding="utf-8") as fh:
                inc = json.load(fh)
            os.makedirs(self.results, exist_ok=True)
            out = os.path.join(self.results, inc["incident_id"] + "_r.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"incident_key": inc.get("incident_key"),
                           "incident_id": inc["incident_id"],
                           "investigation_status": status}, fh)
        return run

    def _status(self):
        conn = connect(self.db)
        row = get_incident(conn, self.key)
        conn.close()
        return row["status"]

    def test_complete_marks_done(self):
        q.run(self.dir, run_agent=self._fake("THREAT_CONFIRMED"), results_dir=self.results, now=NOW)
        self.assertEqual(self._status(), "done")

    def test_incomplete_returns_to_pending(self):
        q.run(self.dir, run_agent=self._fake("INCOMPLETE"), results_dir=self.results, now=NOW)
        self.assertEqual(self._status(), "pending")

    def test_agent_error_returns_to_pending(self):
        def boom(_f):
            raise OSError("boom")
        q.run(self.dir, run_agent=boom, results_dir=self.results, now=NOW)
        self.assertEqual(self._status(), "pending")

    def test_no_result_returns_to_pending(self):
        # 결과 파일을 안 쓰는 에이전트 → 미완료로 보고 재시도
        q.run(self.dir, run_agent=lambda _f: None, results_dir=self.results, now=NOW)
        self.assertEqual(self._status(), "pending")

    def test_empty_queue_noop(self):
        q.run(self.dir, run_agent=self._fake("DONE"), results_dir=self.results, now=NOW)
        res = q.run(self.dir, run_agent=self._fake("DONE"), results_dir=self.results, now=NOW)
        self.assertEqual(res["processed"], 0)

    def test_progress_lines(self):
        # 대기열 시작·사건별 (n/N) 실행/결과 줄이 찍혀야 한다 — 몇 번째 사건을 조사 중인지 보이게
        out = io.StringIO()
        with redirect_stdout(out):
            q.run(self.dir, run_agent=self._fake("THREAT_CONFIRMED"), results_dir=self.results, now=NOW)
        text = out.getvalue()
        self.assertIn("[investigate] 대기열 1건 조사 시작(limit 20)", text)
        self.assertIn("[investigate] (1/1) %s INC-1 P1 src_ip=45.9.1.2 — 조사 에이전트 실행" % self.key, text)
        self.assertRegex(text, r"\[investigate\] \(1/1\) %s → \S+ \(\d+\.\ds\)" % self.key)

    def test_stale_investigating_is_reclaimed(self):
        conn = connect(self.db)
        conn.execute("UPDATE incidents SET status='investigating', claimed_at=? WHERE incident_key=?",
                     ("2026-09-11T02:00:00Z", self.key))   # NOW-1h < stale cutoff
        conn.close()
        q.run(self.dir, run_agent=self._fake("DONE"), results_dir=self.results, now=NOW, stale_minutes=30)
        self.assertEqual(self._status(), "done")


if __name__ == "__main__":
    ok = unittest.main(exit=False).result.wasSuccessful()
    print("결과:", "전부 통과" if ok else "실패")
    sys.exit(0 if ok else 1)
