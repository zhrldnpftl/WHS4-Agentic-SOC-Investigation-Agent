"""LLM 모델 비교 도우미 — 후보 사건 보기, 평가 사건 고르기, 결과 요약.

    python eval/eval_tool.py candidates              # run_eval.sh detect 결과(후보 사건) 표로 보기
    python eval/eval_tool.py pick INC-a INC-b ...     # 평가 사건 고르기 → eval_set.jsonl + labels.csv(정답 칸 비움)
    python eval/eval_tool.py summarize               # eval/runs/ 결과를 단계·모델별로 요약 → eval/summary_<단계>.csv

정답표(eval/incidents/labels.csv) 열:
    incident_id, expected_investigate(true/false), expected_verdict(THREAT_CONFIRMED/FALSE_POSITIVE/INCONCLUSIVE),
    expected_techniques(세미콜론 구분, 예: T1595.001;T1592), note
    빈 칸은 "정답 없음"으로 보고 그 항목 일치율 계산에서 뺀다.

표준 라이브러리만 쓴다(Python 3.10).
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
INCIDENTS_DIR = os.path.join(EVAL_DIR, "incidents")
RUNS_DIR = os.path.join(EVAL_DIR, "runs")
LABEL_FIELDS = ["incident_id", "expected_investigate", "expected_verdict", "expected_techniques", "note"]
TRIAGE_TOKENS_RE = re.compile(r"\[triage\] 토큰 입력 (\d+)·출력 (\d+)")


# ── 공용 ───────────────────────────────────────────────

def read_jsonl(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read_json(path: str) -> Any:
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream)


def read_meta(run_dir: str) -> Dict[str, str]:
    meta = {}
    path = os.path.join(run_dir, "meta.env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                if "=" in line:
                    key, value = line.rstrip("\n").split("=", 1)
                    meta[key] = value
    return meta


def read_labels(path: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    path = path or os.path.join(INCIDENTS_DIR, "labels.csv")
    if not os.path.exists(path):
        return {}
    labels = {}
    with open(path, encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            # 메모에 쉼표를 넣으면 칸이 넘쳐 csv가 None 키에 리스트로 담는다 — 멈추지 않고 note 뒤에 붙인다
            extra = row.pop(None, None) or []
            if extra:
                row["note"] = ",".join([row.get("note") or ""] + list(extra))
            iid = (row.get("incident_id") or "").strip()
            if iid:
                labels[iid] = {k: (v or "").strip() for k, v in row.items()}
    return labels


def parse_bool(value: str) -> Optional[bool]:
    value = (value or "").strip().lower()
    if value in ("true", "t", "1", "yes", "y", "o"):
        return True
    if value in ("false", "f", "0", "no", "n", "x"):
        return False
    return None


def technique_set(value: Iterable[str]) -> set:
    return {item.strip().upper() for item in value if item and item.strip()}


def ratio(hits: int, total: int) -> str:
    return f"{hits}/{total} ({hits / total:.0%})" if total else "-"


def run_dirs(stage: str) -> List[str]:
    """eval/runs/<stage>/<모델>/run<N>/ 목록 (모델·회차 순)."""
    return sorted(glob.glob(os.path.join(RUNS_DIR, stage, "*", "run*")))


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    fields = list(rows[0].keys())
    with open(path, "w", encoding="utf-8-sig", newline="") as stream:   # 엑셀에서 한글이 깨지지 않게 BOM
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def print_table(rows: List[List[Any]], header: List[str]) -> None:
    table = [header] + [[str(cell) for cell in row] for row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for index, row in enumerate(table):
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if index == 0:
            print("  ".join("-" * width for width in widths))


# ── candidates / pick ─────────────────────────────────

def cmd_candidates(args: argparse.Namespace) -> int:
    path = os.path.join(INCIDENTS_DIR, "candidates.jsonl")
    if not os.path.exists(path):
        print("후보 사건이 없습니다 — 먼저 bash eval/run_eval.sh detect", file=sys.stderr)
        return 1
    incidents = read_jsonl(path)
    rows = []
    for inc in incidents:
        if args.min_priority and inc.get("priority", "P4") > args.min_priority:
            continue
        entity = inc.get("entity") or {}
        reasons = sorted({s.get("reason") or s.get("rule_name") or "?" for s in inc.get("seeds") or []})
        window = inc.get("window") or ["", ""]
        rows.append([inc.get("incident_id"), inc.get("priority"), inc.get("triage_score"),
                     f"{entity.get('type')}={entity.get('value')}", ",".join(sorted(inc.get("layers") or [])),
                     str(window[0])[:19], "; ".join(reasons)[:90]])
    print_table(rows, ["incident_id", "우선순위", "점수", "대상", "계층", "시작", "탐지 사유"])
    print(f"\n{len(rows)}건 / 전체 {len(incidents)}건 — 고르기: python eval/eval_tool.py pick <incident_id> ...")
    return 0


def cmd_pick(args: argparse.Namespace) -> int:
    incidents = {inc.get("incident_id"): inc for inc in read_jsonl(os.path.join(INCIDENTS_DIR, "candidates.jsonl"))}
    missing = [iid for iid in args.incident_ids if iid not in incidents]
    if missing:
        print(f"후보에 없는 사건: {', '.join(missing)}", file=sys.stderr)
        return 1
    eval_set = os.path.join(INCIDENTS_DIR, "eval_set.jsonl")
    with open(eval_set, "w", encoding="utf-8") as stream:
        for iid in args.incident_ids:
            stream.write(json.dumps(incidents[iid], ensure_ascii=False) + "\n")
    labels_path = os.path.join(INCIDENTS_DIR, "labels.csv")
    labels = read_labels(labels_path)   # 이미 적은 정답은 지우지 않는다
    for iid in args.incident_ids:
        labels.setdefault(iid, {field: "" for field in LABEL_FIELDS} | {"incident_id": iid})
    with open(labels_path, "w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=LABEL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(labels.values())
    print(f"평가 사건 {len(args.incident_ids)}건: {eval_set}")
    print(f"정답표: {labels_path} — expected_* 칸을 채우십시오(트리아지만 볼 사건은 행을 더 넣어도 됨)")
    return 0


# ── summarize ─────────────────────────────────────────

def _investigation_rows(labels: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    rows = []
    for run_dir in run_dirs("investigation"):
        meta = read_meta(run_dir)
        usage_by_id: Dict[str, Dict[str, Any]] = {}
        for usage_file in sorted(glob.glob(os.path.join(run_dir, "results", "llm_usage", "*.json"))):
            for record in read_json(usage_file).get("incidents", []):
                usage_by_id[record.get("incident_id")] = record
        mapping_by_id = {}
        for path in sorted(glob.glob(os.path.join(run_dir, "results", "attack_mapping", "*_attack_mapping*.json"))):
            data = read_json(path)
            mapping_by_id[data.get("incident_id")] = data
        for path in sorted(glob.glob(os.path.join(run_dir, "results", "investigation_agent", "*.json"))):
            result = read_json(path)
            iid = result.get("incident_id")
            verdict = result.get("final_verdict") or {}
            stats = result.get("statistics") or {}
            usage = usage_by_id.get(iid, {})
            inv_usage = usage.get("investigation_usage") or {}
            mapping = mapping_by_id.get(iid) or {}
            label = labels.get(iid, {})
            expected_verdict = label.get("expected_verdict", "")
            expected_tech = technique_set((label.get("expected_techniques") or "").split(";"))
            got_tech = technique_set(t.get("technique_id", "") for t in mapping.get("techniques") or [])
            notes = " ".join(str(n) for n in result.get("investigation_notes") or [])
            rows.append({
                "model": meta.get("MODEL") or os.path.basename(os.path.dirname(run_dir)),
                "run": meta.get("RUN") or os.path.basename(run_dir),
                "mapping_model": meta.get("MAPPING_MODEL", ""),
                "incident_id": iid,
                "status": result.get("investigation_status"),
                "verdict": verdict.get("verdict"),
                "expected_verdict": expected_verdict,
                "verdict_match": "" if not expected_verdict else verdict.get("verdict") == expected_verdict,
                "severity": verdict.get("severity"),
                "confidence": verdict.get("confidence"),
                "provenance": (result.get("provenance") or {}).get("status"),
                "termination": stats.get("termination_reason"),
                "tool_calls": stats.get("tool_calls_count"),
                "refusal": notes.count("refusal"),
                "parse_fail": notes.count("LLM 응답 해석 실패"),
                "seconds": usage.get("investigation_seconds", ""),
                "llm_calls": inv_usage.get("calls", ""),
                "input_tokens": inv_usage.get("input_tokens", ""),
                "output_tokens": inv_usage.get("output_tokens", ""),
                "cache_read_tokens": inv_usage.get("cache_read_input_tokens", ""),
                "mapping_status": mapping.get("mapping_status", ""),
                "techniques": ";".join(sorted(got_tech)),
                "expected_techniques": ";".join(sorted(expected_tech)),
                "technique_match": "" if not expected_tech else got_tech == expected_tech,
            })
    return rows


def _mapping_rows(labels: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    rows = []
    for run_dir in run_dirs("mapping"):
        meta = read_meta(run_dir)
        for path in sorted(glob.glob(os.path.join(run_dir, "attack_mapping", "*_attack_mapping*.json"))):
            data = read_json(path)
            iid = data.get("incident_id")
            expected = technique_set((labels.get(iid, {}).get("expected_techniques") or "").split(";"))
            got = technique_set(t.get("technique_id", "") for t in data.get("techniques") or [])
            rows.append({
                "model": meta.get("MODEL") or os.path.basename(os.path.dirname(run_dir)),
                "run": meta.get("RUN") or os.path.basename(run_dir),
                "source": meta.get("SOURCE", ""),
                "incident_id": iid,
                "mapping_status": data.get("mapping_status"),
                "techniques": ";".join(sorted(got)),
                "expected_techniques": ";".join(sorted(expected)),
                "technique_match": "" if not expected else got == expected,
                "technique_overlap": "" if not expected else round(len(got & expected) / len(got | expected), 2),
                "elapsed_seconds_run": meta.get("ELAPSED_SECONDS", ""),
            })
    return rows


def _triage_rows(labels: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    rows = []
    for run_dir in run_dirs("triage"):
        meta = read_meta(run_dir)
        tokens = ("", "")
        log = os.path.join(run_dir, "run.log")
        if os.path.exists(log):
            with open(log, encoding="utf-8", errors="replace") as stream:
                found = TRIAGE_TOKENS_RE.findall(stream.read())
            if found:
                tokens = (sum(int(i) for i, _ in found), sum(int(o) for _, o in found))
        path = os.path.join(run_dir, "incidents.jsonl")
        if not os.path.exists(path):
            continue
        for inc in read_jsonl(path):
            if "llm_investigate" not in inc:
                continue   # LLM 재검토 대상(P1~P2 상위)이 아니었던 사건
            iid = inc.get("incident_id")
            expected = parse_bool(labels.get(iid, {}).get("expected_investigate", ""))
            rows.append({
                "model": meta.get("MODEL") or os.path.basename(os.path.dirname(run_dir)),
                "run": meta.get("RUN") or os.path.basename(run_dir),
                "incident_id": iid,
                "priority": inc.get("priority"),
                "llm_investigate": inc.get("llm_investigate"),
                "expected_investigate": "" if expected is None else expected,
                "match": "" if expected is None else inc.get("llm_investigate") is expected,
                "llm_reason": inc.get("llm_reason", ""),
                "input_tokens_run": tokens[0],
                "output_tokens_run": tokens[1],
                "elapsed_seconds_run": meta.get("ELAPSED_SECONDS", ""),
            })
    return rows


def _consistency(rows: List[Dict[str, Any]], model: str, field: str) -> str:
    """같은 모델·같은 사건을 여러 회차 돌렸을 때 field 값이 모두 같은 사건 비율."""
    by_incident = defaultdict(set)
    runs = set()
    for row in rows:
        if row["model"] == model:
            by_incident[row["incident_id"]].add(str(row[field]))
            runs.add(row["run"])
    if len(runs) < 2:
        return "-(1회)"
    return ratio(sum(len(values) == 1 for values in by_incident.values()), len(by_incident))


def _avg(rows: List[Dict[str, Any]], field: str) -> str:
    values = [float(row[field]) for row in rows if row.get(field) not in ("", None)]
    return f"{mean(values):.0f}" if values else "-"


def summarize_investigation(rows: List[Dict[str, Any]]) -> None:
    print("\n## 조사 에이전트 (모델별)")
    table = []
    for model in sorted({row["model"] for row in rows}):
        mine = [row for row in rows if row["model"] == model]
        labeled = [row for row in mine if row["verdict_match"] != ""]
        tech_labeled = [row for row in mine if row["technique_match"] != ""]
        table.append([
            model, len({row["run"] for row in mine}), len(mine),
            ratio(sum(row["verdict_match"] is True for row in labeled), len(labeled)),
            _consistency(mine, model, "verdict"),
            ratio(sum(row["provenance"] == "passed" for row in mine), len(mine)),
            sum(row["status"] == "INCOMPLETE" for row in mine),
            sum(row["refusal"] for row in mine), sum(row["parse_fail"] for row in mine),
            _avg(mine, "seconds"), _avg(mine, "llm_calls"), _avg(mine, "input_tokens"), _avg(mine, "output_tokens"),
            ratio(sum(row["technique_match"] is True for row in tech_labeled), len(tech_labeled)),
        ])
    print_table(table, ["모델", "회차", "사건", "판정 일치", "반복 일관", "provenance 통과", "미완료", "거절",
                        "해석실패", "평균 초", "평균 LLM호출", "평균 입력토큰", "평균 출력토큰", "기법 일치(매핑)"])


def summarize_mapping(rows: List[Dict[str, Any]]) -> None:
    print("\n## ATT&CK 매핑 (모델별)")
    table = []
    for model in sorted({row["model"] for row in rows}):
        mine = [row for row in rows if row["model"] == model]
        labeled = [row for row in mine if row["technique_match"] != ""]
        statuses = Counter(row["mapping_status"] for row in mine)
        overlaps = [row["technique_overlap"] for row in labeled]
        table.append([
            model, len({row["run"] for row in mine}), len(mine),
            ratio(sum(row["technique_match"] is True for row in labeled), len(labeled)),
            f"{mean(overlaps):.2f}" if overlaps else "-",
            _consistency(mine, model, "techniques"),
            ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())),
        ])
    print_table(table, ["모델", "회차", "사건", "기법 완전 일치", "평균 겹침(Jaccard)", "반복 일관", "mapping_status"])


def summarize_triage(rows: List[Dict[str, Any]]) -> None:
    print("\n## 트리아지 (모델별)")
    table = []
    for model in sorted({row["model"] for row in rows}):
        mine = [row for row in rows if row["model"] == model]
        labeled = [row for row in mine if row["match"] != ""]
        missed = sum(row["match"] is False and row["expected_investigate"] is True for row in labeled)
        runs = {row["run"]: row for row in mine}
        table.append([
            model, len(runs), len(mine),
            ratio(sum(row["match"] is True for row in labeled), len(labeled)),
            missed,
            _consistency(mine, model, "llm_investigate"),
            _avg(list(runs.values()), "input_tokens_run"), _avg(list(runs.values()), "output_tokens_run"),
            _avg(list(runs.values()), "elapsed_seconds_run"),
        ])
    print_table(table, ["모델", "회차", "재검토 사건", "정답 일치", "놓친 공격(정답 true인데 false)", "반복 일관",
                        "회당 입력토큰", "회당 출력토큰", "회당 초"])


def cmd_summarize(args: argparse.Namespace) -> int:
    labels = read_labels()
    if not labels:
        print("정답표(eval/incidents/labels.csv)가 없거나 비어 있습니다 — 일치율은 '-'로 나옵니다.")
    for stage, build, show in (("investigation", _investigation_rows, summarize_investigation),
                               ("mapping", _mapping_rows, summarize_mapping),
                               ("triage", _triage_rows, summarize_triage)):
        rows = build(labels)
        if not rows:
            continue
        out = os.path.join(EVAL_DIR, f"summary_{stage}.csv")
        write_csv(out, rows)
        show(rows)
        print(f"(사건별 자세히: {out})")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    candidates = sub.add_parser("candidates", help="후보 사건 표")
    candidates.add_argument("--min-priority", choices=["P1", "P2", "P3", "P4"], help="이 우선순위 이상만")
    candidates.set_defaults(func=cmd_candidates)
    pick = sub.add_parser("pick", help="평가 사건 고르기")
    pick.add_argument("incident_ids", nargs="+")
    pick.set_defaults(func=cmd_pick)
    summarize = sub.add_parser("summarize", help="결과 요약")
    summarize.set_defaults(func=cmd_summarize)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
