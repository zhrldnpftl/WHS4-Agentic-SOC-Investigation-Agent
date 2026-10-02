#!/usr/bin/env bash
# LLM 모델 비교 실행기 — 고정한 로그(eval/logs)로 단계 하나를 모델 하나·회차 하나만큼 돌린다.
#
#   bash eval/run_eval.sh detect                         # 후보 사건 목록 (LLM 호출 없음)
#   bash eval/run_eval.sh triage        <모델> [회차]     # 1차 탐지 트리아지 LLM 재검토
#   bash eval/run_eval.sh investigation <모델> [회차]     # 조사 에이전트 (+ 매핑은 MAPPING_MODEL로 고정)
#   bash eval/run_eval.sh mapping       <모델> [회차]     # 매핑만 (SOURCE=조사 결과 폴더 필요)
#
# 결과: eval/runs/<단계>/<모델>/run<회차>/ — 같은 폴더가 있으면 덮어쓰지 않고 멈춘다.
# 모델·로그 경로는 .env를 고치지 않고 실행할 때 환경변수로 넘긴다(.env보다 실행 시 준 값이 우선).
# 비교 중에는 거절 시 다른 모델로 다시 보내지 않는다(*_CLAUDE_REFUSAL_FALLBACK_MODEL=none) — 거절도 그 모델의 결과다.
# 모델 이름이 gpt-* 또는 o<숫자>*이면 OpenAI(GPT)로, 그 밖은 Anthropic(Claude)으로 넘긴다(PROVIDER로 덮어쓰기 가능).
#   GPT는 .env의 OPENAI_API_KEY가 필요하다. 트리아지는 Claude만 지원한다.
# 환경변수: MAPPING_MODEL(investigation 단계의 매핑 모델, 기본 claude-haiku-4-5), SOURCE(mapping 단계 입력,
#           예: investigation/claude-sonnet-5/run1), PROVIDER(anthropic|openai), PYTHON(기본 python)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/eval"
PYTHON="${PYTHON:-python}"
STAGE="${1:-}"
MODEL="${2:-}"
RUN="${3:-1}"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ -n "$STAGE" ] || usage

SNAPSHOT="$EVAL/logs/snapshot.env"
if [ ! -f "$SNAPSHOT" ]; then
  echo "[eval] 로그 스냅샷이 없습니다 — 먼저 bash eval/snapshot_logs.sh" >&2
  exit 1
fi
set -a; . "$SNAPSHOT"; set +a   # APACHE/AUTH/AUDIT/SURICATA_LOG_PATH, SNAPSHOT_AT, SNAPSHOT_DAYS
SINCE_MINUTES=$((SNAPSHOT_DAYS * 1440))
DETECT_ARGS=(--apache "$APACHE_LOG_PATH" --auth "$AUTH_LOG_PATH" --network "$SURICATA_LOG_PATH"
             --audit "$AUDIT_LOG_PATH" --since-minutes "$SINCE_MINUTES" --now "$SNAPSHOT_AT")

start_run() {  # 실행 폴더 만들기 + 메타 정보
  RUN_DIR="$EVAL/runs/$STAGE/$MODEL/run$RUN"
  if [ -e "$RUN_DIR" ]; then
    echo "[eval] 이미 있습니다: $RUN_DIR — 회차 번호를 바꾸거나 지우십시오" >&2
    exit 1
  fi
  mkdir -p "$RUN_DIR"
  STARTED=$(date +%s)
  cat > "$RUN_DIR/meta.env" <<EOF
STAGE=$STAGE
MODEL=$MODEL
RUN=$RUN
MAPPING_MODEL=${MAPPING_MODEL:-}
SOURCE=${SOURCE:-}
SNAPSHOT_AT=$SNAPSHOT_AT
GIT_COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo -)
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  echo "[eval] $STAGE / $MODEL / run$RUN → $RUN_DIR"
}

finish_run() {
  echo "ELAPSED_SECONDS=$(( $(date +%s) - STARTED ))" >> "$RUN_DIR/meta.env"
  echo "[eval] 끝 ($(( $(date +%s) - STARTED ))초) — 요약: $PYTHON eval/eval_tool.py summarize"
}

need_model() { [ -n "$MODEL" ] || { echo "[eval] 모델 이름이 필요합니다" >&2; usage; }; }

# 모델 이름으로 provider를 고른다: gpt-*·o<숫자>* → openai, 그 밖은 anthropic. PROVIDER 환경변수로 덮어쓸 수 있다.
provider_of() {
  if [ -n "${PROVIDER:-}" ]; then echo "$PROVIDER"
  elif [[ "$1" =~ ^(gpt|o[0-9]) ]]; then echo openai
  else echo anthropic; fi
}

# 역할(INVESTIGATION/MAPPING)과 모델로 넘길 환경변수 목록을 만든다. 비교 중에는 거절 재요청을 끈다(Claude만 해당).
role_env() {  # $1=역할, $2=모델
  local role="$1" model="$2" provider
  provider="$(provider_of "$model")"
  if [ "$provider" = openai ]; then
    echo "${role}_LLM_PROVIDER=openai ${role}_OPENAI_MODEL=$model"
  else
    echo "${role}_LLM_PROVIDER=anthropic ${role}_CLAUDE_MODEL=$model ${role}_CLAUDE_REFUSAL_FALLBACK_MODEL=none"
  fi
}

case "$STAGE" in
  detect)
    # 후보 사건: LLM 재검토 없이(키를 빈 값으로) 고정 로그 전체 구간을 1차 탐지한다
    mkdir -p "$EVAL/incidents"
    TRIAGE_ANTHROPIC_API_KEY= ANTHROPIC_API_KEY= \
      "$PYTHON" -u "$ROOT/run_pipeline.py" "${DETECT_ARGS[@]}" --show 0 \
      --out-incidents "$EVAL/incidents/candidates.jsonl" 2>&1 | tee "$EVAL/incidents/detect.log"
    echo "[eval] 후보 목록: $PYTHON eval/eval_tool.py candidates"
    ;;
  triage)
    need_model
    [ "$(provider_of "$MODEL")" = anthropic ] || { echo "[eval] 트리아지는 Claude 모델만 지원합니다: $MODEL" >&2; exit 1; }
    start_run
    TRIAGE_CLAUDE_MODEL="$MODEL" \
      "$PYTHON" -u "$ROOT/run_pipeline.py" "${DETECT_ARGS[@]}" --show 0 \
      --out-incidents "$RUN_DIR/incidents.jsonl" 2>&1 | tee "$RUN_DIR/run.log"
    finish_run
    ;;
  investigation)
    need_model
    MAPPING_MODEL="${MAPPING_MODEL:-claude-haiku-4-5}"
    [ -f "$EVAL/incidents/eval_set.jsonl" ] || { echo "[eval] eval/incidents/eval_set.jsonl 없음 — eval_tool.py pick" >&2; exit 1; }
    start_run
    # main.py는 실행 폴더 아래 results/에 저장하므로 실행 폴더에서 돌린다
    # shellcheck disable=SC2046  # role_env는 공백으로 나뉜 NAME=값 목록(값에 공백 없음)
    (cd "$RUN_DIR" && \
      env $(role_env INVESTIGATION "$MODEL") $(role_env MAPPING "$MAPPING_MODEL") \
      "$PYTHON" -u "$ROOT/llm/investigate/main.py" "$EVAL/incidents/eval_set.jsonl" 2>&1 | tee run.log)
    finish_run
    ;;
  mapping)
    need_model
    : "${SOURCE:?SOURCE=조사 결과 폴더(예: investigation/claude-sonnet-5/run1)를 주십시오}"
    INPUT="$EVAL/runs/$SOURCE/results/investigation_agent"
    [ -d "$INPUT" ] || { echo "[eval] 조사 결과 폴더가 없습니다: $INPUT" >&2; exit 1; }
    start_run
    # 매핑 CLI는 llm/investigate에서 모듈로 실행한다. 입력·출력은 절대경로
    # shellcheck disable=SC2046
    (cd "$ROOT/llm/investigate" && \
      env $(role_env MAPPING "$MODEL") \
      "$PYTHON" -u -m attack_mapping.cli --all-in-dir "$INPUT" --out-dir "$RUN_DIR/attack_mapping" \
      2>&1 | tee "$RUN_DIR/run.log") || true   # 일부 사건 매핑 오류면 CLI가 1로 끝난다 — 요약에서 본다
    finish_run
    ;;
  *)
    usage
    ;;
esac
