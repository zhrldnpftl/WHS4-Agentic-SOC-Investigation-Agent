#!/usr/bin/env python3
"""eval/models.yaml의 설정들을 차례로 run_eval.sh에 넘겨 한 번에 비교 실행한다.

    python eval/run_matrix.py mapping --source investigation/claude-sonnet-5-5/run1
    python eval/run_matrix.py investigation --only sonnet5-low,haiku45-off
    python eval/run_matrix.py investigation --dry-run        # 무엇을 돌릴지만 보기

- 설정마다 NAME(결과 폴더 이름)·EFFORT·THINKING_BUDGET을 환경변수로 넘긴다. .env는 고치지 않는다.
- 결과 폴더가 이미 있으면 건너뛴다 → 중간에 멈춰도 같은 명령을 다시 실행하면 남은 설정만 돈다
  (멈춘 설정의 반쯤 찬 폴더는 지우고 다시 실행).
- 한 설정이 실패해도 다음 설정으로 넘어가고, 끝에 실패 목록을 보여 준다.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

EVAL = Path(__file__).resolve().parent
STAGES = ("triage", "investigation", "mapping")


def load_settings(path):
    """yaml을 읽어 설정 목록을 돌려준다. 이름 중복·모델 누락은 실행 전에 멈춘다."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    settings = data.get("settings") or []
    seen = set()
    for s in settings:
        if not s.get("name") or not s.get("model"):
            raise SystemExit(f"[matrix] name·model이 필요합니다: {s}")
        if s["name"] in seen:
            raise SystemExit(f"[matrix] 설정 이름이 겹칩니다: {s['name']}")
        seen.add(s["name"])
    return settings


def setting_env(s):
    """설정 하나를 run_eval.sh 환경변수로 바꾼다. 없는 값도 빈 값으로 넘겨 바깥 환경이 섞이지 않게 한다."""
    return {
        "NAME": str(s["name"]),
        "EFFORT": "" if s.get("effort") is None else str(s["effort"]),
        "THINKING_BUDGET": "" if s.get("thinking_budget") is None else str(s["thinking_budget"]),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="models.yaml의 설정을 차례로 비교 실행")
    p.add_argument("stage", choices=STAGES)
    p.add_argument("--run", default="1", help="회차 번호 (기본 1)")
    p.add_argument("--config", default=str(EVAL / "models.yaml"))
    p.add_argument("--only", default="", help="이 이름들만 (쉼표 구분)")
    p.add_argument("--source", default=os.environ.get("SOURCE", ""),
                   help="mapping 단계 입력 (예: investigation/claude-sonnet-5-5/run1)")
    p.add_argument("--dry-run", action="store_true", help="실행하지 않고 목록만")
    args = p.parse_args(argv)

    settings = load_settings(args.config)
    if args.only:
        wanted = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = set(wanted) - {s["name"] for s in settings}
        if unknown:
            raise SystemExit(f"[matrix] yaml에 없는 이름: {', '.join(sorted(unknown))}")
        settings = [s for s in settings if s["name"] in wanted]
    if args.stage == "mapping" and not args.source:
        raise SystemExit("[matrix] mapping 단계는 --source(조사 결과 폴더)가 필요합니다")

    failed, skipped = [], []
    for i, s in enumerate(settings, 1):
        env = setting_env(s)
        run_dir = EVAL / "runs" / args.stage / s["name"] / f"run{args.run}"
        desc = (f"{s['name']} ({s['model']}"
                f"{', effort=' + env['EFFORT'] if env['EFFORT'] else ''}"
                f"{', 생각 예산=' + env['THINKING_BUDGET'] if env['THINKING_BUDGET'] else ''})")
        if run_dir.exists():
            print(f"[matrix] ({i}/{len(settings)}) 건너뜀 — 이미 있음: {desc}", flush=True)
            skipped.append(s["name"])
            continue
        print(f"[matrix] ({i}/{len(settings)}) {desc}", flush=True)
        if args.dry_run:
            continue
        child_env = {**os.environ, **env}
        if args.stage == "mapping":
            child_env["SOURCE"] = args.source
        code = subprocess.call(["bash", str(EVAL / "run_eval.sh"), args.stage, s["model"], args.run],
                               env=child_env)
        if code != 0:
            print(f"[matrix] 실패({code}): {s['name']}", flush=True)
            failed.append(s["name"])

    print(f"[matrix] 끝 — {len(settings)}개 중 건너뜀 {len(skipped)}, 실패 {len(failed)}"
          f"{': ' + ', '.join(failed) if failed else ''}")
    print("[matrix] 요약: python eval/eval_tool.py summarize")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
