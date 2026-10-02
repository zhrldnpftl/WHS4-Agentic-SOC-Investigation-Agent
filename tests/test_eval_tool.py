"""eval/eval_tool.py — 모델 비교 결과 요약이 실제 결과 파일 형식을 읽는지 (API 호출 없음).

가짜 eval/ 폴더(후보 사건, 정답표, 조사·매핑·트리아지 실행 결과)를 임시 폴더에 만들어 pick·summarize를 돌린다.
실행: python -m unittest tests.test_eval_tool
"""
import contextlib
import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "eval"))

import eval_tool  # noqa: E402


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False))


def _read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _incident(iid, priority="P2"):
    return {"incident_id": iid, "priority": priority, "triage_score": 60,
            "entity": {"type": "src_ip", "value": "203.0.113.7"}, "layers": ["web"],
            "window": ["2026-10-01T00:00:00Z", "2026-10-01T00:01:00Z"], "seeds": [{"reason": "스캐너"}]}


class EvalToolTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.saved = (eval_tool.EVAL_DIR, eval_tool.INCIDENTS_DIR, eval_tool.RUNS_DIR)
        eval_tool.EVAL_DIR = self.dir
        eval_tool.INCIDENTS_DIR = os.path.join(self.dir, "incidents")
        eval_tool.RUNS_DIR = os.path.join(self.dir, "runs")
        candidates = "\n".join(json.dumps(_incident(i)) for i in ("INC-A", "INC-B", "INC-C")) + "\n"
        _write(os.path.join(self.dir, "incidents", "candidates.jsonl"), candidates)

    def tearDown(self):
        eval_tool.EVAL_DIR, eval_tool.INCIDENTS_DIR, eval_tool.RUNS_DIR = self.saved
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = eval_tool.main(list(argv))
        return code, out.getvalue()

    def _fill_labels(self):
        path = os.path.join(self.dir, "incidents", "labels.csv")
        with open(path, encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        answers = {"INC-A": ("true", "THREAT_CONFIRMED", "T1595.001;T1592"),
                   "INC-B": ("false", "FALSE_POSITIVE", "")}
        for row in rows:
            row["expected_investigate"], row["expected_verdict"], row["expected_techniques"] = answers[row["incident_id"]]
        with open(path, "w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=eval_tool.LABEL_FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def _investigation_run(self, model, run, verdicts):
        base = os.path.join(self.dir, "runs", "investigation", model, f"run{run}")
        _write(os.path.join(base, "meta.env"), f"MODEL={model}\nRUN={run}\nMAPPING_MODEL=claude-haiku-4-5\n")
        usage = {"incidents": []}
        for iid, verdict in verdicts.items():
            _write(os.path.join(base, "results", "investigation_agent", f"INV-{iid}.json"), {
                "incident_id": iid, "investigation_status": "COMPLETE",
                "final_verdict": {"verdict": verdict, "severity": "LOW", "confidence": 0.9},
                "provenance": {"status": "passed" if verdict == "THREAT_CONFIRMED" else "incomplete"},
                "statistics": {"tool_calls_count": 3, "termination_reason": "confidence_sufficient"},
                "investigation_notes": ["Claude가 응답을 거절했습니다(refusal, category=cyber)"] if iid == "INC-B" else []})
            _write(os.path.join(base, "results", "attack_mapping", f"{iid}_attack_mapping.json"), {
                "incident_id": iid, "mapping_status": "mapped",
                "techniques": [{"technique_id": "T1595.001"}, {"technique_id": "T1592"}] if iid == "INC-A" else []})
            usage["incidents"].append({"incident_id": iid, "investigation_seconds": 100.0,
                                       "investigation_usage": {"calls": 4, "input_tokens": 1000, "output_tokens": 200}})
        _write(os.path.join(base, "results", "llm_usage", "llm_usage_1.json"), usage)

    def test_pick_writes_eval_set_and_keeps_existing_labels(self):
        code, _ = self._run("pick", "INC-A", "INC-B")
        self.assertEqual(code, 0)
        self.assertEqual([i["incident_id"] for i in eval_tool.read_jsonl(
            os.path.join(self.dir, "incidents", "eval_set.jsonl"))], ["INC-A", "INC-B"])
        self._fill_labels()
        self._run("pick", "INC-A", "INC-B")   # 다시 골라도 적어 둔 정답은 남는다
        self.assertEqual(eval_tool.read_labels()["INC-A"]["expected_verdict"], "THREAT_CONFIRMED")
        self.assertEqual(self._run("pick", "INC-Z")[0], 1)

    def test_summarize_investigation_mapping_triage(self):
        self._run("pick", "INC-A", "INC-B")
        self._fill_labels()
        self._investigation_run("claude-haiku-4-5", 1, {"INC-A": "THREAT_CONFIRMED", "INC-B": "THREAT_CONFIRMED"})
        self._investigation_run("claude-haiku-4-5", 2, {"INC-A": "THREAT_CONFIRMED", "INC-B": "FALSE_POSITIVE"})
        mapping = os.path.join(self.dir, "runs", "mapping", "claude-haiku-4-5", "run1")
        _write(os.path.join(mapping, "meta.env"), "MODEL=claude-haiku-4-5\nRUN=1\nSOURCE=investigation/x/run1\n")
        _write(os.path.join(mapping, "attack_mapping", "INC-A_attack_mapping.json"),
               {"incident_id": "INC-A", "mapping_status": "partial", "techniques": [{"technique_id": "T1595.001"}]})
        triage = os.path.join(self.dir, "runs", "triage", "claude-haiku-4-5", "run1")
        _write(os.path.join(triage, "meta.env"), "MODEL=claude-haiku-4-5\nRUN=1\nELAPSED_SECONDS=12\n")
        _write(os.path.join(triage, "run.log"), "[triage] 토큰 입력 5000·출력 300 (모델 claude-haiku-4-5, stop_reason=end_turn)\n")
        _write(os.path.join(triage, "incidents.jsonl"), "\n".join(json.dumps(x) for x in (
            dict(_incident("INC-A"), llm_investigate=False, llm_reason="정상"),   # 놓친 공격
            dict(_incident("INC-B"), llm_investigate=False, llm_reason="정상"),
            _incident("INC-C", "P3"))) + "\n")

        code, out = self._run("summarize")
        self.assertEqual(code, 0)
        self.assertIn("## 조사 에이전트", out)
        self.assertIn("3/4 (75%)", out)    # 판정 일치: run1 INC-B 틀림
        self.assertIn("1/2 (50%)", out)    # 반복 일관: INC-B가 회차마다 다름 / 트리아지 일치도 1/2
        rows = _read_csv(os.path.join(self.dir, "summary_investigation.csv"))
        inc_b = [r for r in rows if r["incident_id"] == "INC-B"]
        self.assertEqual({r["refusal"] for r in inc_b}, {"1"})
        self.assertEqual({r["input_tokens"] for r in rows}, {"1000"})
        self.assertEqual([r["technique_match"] for r in rows if r["incident_id"] == "INC-A"], ["True", "True"])
        mapping_rows = _read_csv(os.path.join(self.dir, "summary_mapping.csv"))
        self.assertEqual(mapping_rows[0]["technique_overlap"], "0.5")
        triage_rows = _read_csv(os.path.join(self.dir, "summary_triage.csv"))
        self.assertEqual(len(triage_rows), 2)   # LLM 재검토 대상이 아니었던 P3은 빠진다
        self.assertEqual({r["input_tokens_run"] for r in triage_rows}, {"5000"})
        self.assertIn("놓친 공격", out)

    def test_labels_with_comma_in_note(self):
        # 메모에 쉼표가 들어가 칸이 넘쳐도 멈추지 않고 정답을 읽는다 (2026-10-03 EC2)
        _write(os.path.join(self.dir, "incidents", "labels.csv"),
               "incident_id,expected_investigate,expected_verdict,expected_techniques,note\n"
               "INC-A,false,FALSE_POSITIVE,,모두 404, 침해 신호 없음\n")
        label = eval_tool.read_labels()["INC-A"]
        self.assertEqual(label["expected_verdict"], "FALSE_POSITIVE")
        self.assertIn("침해 신호 없음", label["note"])

    def test_summarize_without_runs(self):
        code, out = self._run("summarize")
        self.assertEqual(code, 0)
        self.assertIn("정답표", out)


if __name__ == "__main__":
    unittest.main()
