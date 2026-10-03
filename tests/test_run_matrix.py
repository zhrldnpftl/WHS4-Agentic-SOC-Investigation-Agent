"""eval/run_matrix.py — models.yaml 설정을 run_eval.sh 환경변수로 바르게 넘기는지 (실제 실행·API 호출 없음).

실행: python -m unittest tests.test_run_matrix
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "eval"))

import run_matrix  # noqa: E402


class RunMatrixTest(unittest.TestCase):
    def test_repo_models_yaml_matches_team_matrix(self):
        settings = run_matrix.load_settings(os.path.join(_ROOT, "eval", "models.yaml"))
        names = [s["name"] for s in settings]
        self.assertEqual(len(names), 8)
        by_name = {s["name"]: run_matrix.setting_env(s) for s in settings}
        self.assertEqual(by_name["gpt54-none"]["EFFORT"], "none")      # yaml의 none이 null이 아니라 문자열
        self.assertEqual(by_name["haiku45-think"]["THINKING_BUDGET"], "4000")
        self.assertEqual(by_name["haiku45-off"], {"NAME": "haiku45-off", "EFFORT": "", "THINKING_BUDGET": ""})

    def test_duplicate_name_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.yaml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("settings:\n  - {name: a, model: x}\n  - {name: a, model: y}\n")
            with self.assertRaises(SystemExit):
                run_matrix.load_settings(path)

    def test_runs_only_selected_and_skips_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "runs", "mapping", "sonnet5-low", "run1"))
            calls = []

            def fake_call(cmd, env):
                calls.append((cmd, env))
                return 0

            with mock.patch.object(run_matrix, "EVAL", run_matrix.Path(tmp)), \
                    mock.patch.object(run_matrix.subprocess, "call", fake_call), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = run_matrix.main(["mapping", "--source", "investigation/x/run1",
                                        "--config", os.path.join(_ROOT, "eval", "models.yaml"),
                                        "--only", "sonnet5-low,haiku45-think"])
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)                              # sonnet5-low는 이미 있어 건너뜀
        cmd, env = calls[0]
        self.assertEqual(cmd[2:], ["mapping", "claude-haiku-4-5-20251001", "1"])
        self.assertEqual((env["NAME"], env["EFFORT"], env["THINKING_BUDGET"], env["SOURCE"]),
                         ("haiku45-think", "", "4000", "investigation/x/run1"))

    def test_mapping_needs_source(self):
        with mock.patch.dict(os.environ, {"SOURCE": ""}), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            run_matrix.main(["mapping"])


if __name__ == "__main__":
    unittest.main()
