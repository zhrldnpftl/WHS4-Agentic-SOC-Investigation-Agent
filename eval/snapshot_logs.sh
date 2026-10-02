#!/usr/bin/env bash
# 모델 비교용 로그 스냅샷 — /var/log의 4종 로그(교체 파일 포함)를 eval/logs/에 그대로 복사해 고정한다.
#
#   bash eval/snapshot_logs.sh [일수]      # 기본 4일: 최근 N일 안에 수정된 파일만 복사
#
# 왜: 실제 /var/log는 계속 쌓이고 교체돼, 모델마다 다른 시각에 돌리면 입력이 달라진다. 고정한 복사본을
#     쓰면 모든 모델이 같은 로그를 보고, 합성 시나리오도 실제 로그 대신 복사본에 붙일 수 있다.
# 파일 이름은 그대로 둔다(access.log.1 등) — 사건의 raw_ref(파일명:줄)가 그대로 맞는다.
# cp -p로 수정 시각을 보존한다 — 교체 파일을 고르는 규칙(resolve_log_files)이 수정 시각을 본다.
# 원본 경로는 SRC_APACHE/SRC_AUTH/SRC_AUDIT/SRC_SURICATA 환경변수로 바꿀 수 있다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/eval/logs"
DAYS="${1:-4}"
SRC_APACHE="${SRC_APACHE:-/var/log/apache2/access.log}"
SRC_AUTH="${SRC_AUTH:-/var/log/auth.log}"
SRC_AUDIT="${SRC_AUDIT:-/var/log/audit/audit.log}"
SRC_SURICATA="${SRC_SURICATA:-/var/log/suricata/eve.json}"

if [ -d "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
  echo "[snapshot] 이미 있습니다: $DEST — 다시 만들려면 먼저 지우십시오(그동안의 비교 결과와 입력이 달라집니다)" >&2
  exit 1
fi

SNAPSHOT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SINCE="$(date -u -d "$DAYS days ago" +%Y-%m-%dT%H:%M:%SZ)"

copy_layer() {  # $1=하위 폴더 이름, $2=원본 기준 파일 경로
  local name="$1" base="$2" dir file count=0
  dir="$(dirname "$base")"
  file="$(basename "$base")"
  mkdir -p "$DEST/$name"
  while IFS= read -r -d '' path; do
    cp -p "$path" "$DEST/$name/"
    count=$((count + 1))
  done < <(find "$dir" -maxdepth 1 -type f \( -name "$file" -o -name "$file.*" \) -newermt "$SINCE" -print0)
  echo "[snapshot] $name: $count개 파일 ($(du -sh "$DEST/$name" | cut -f1))"
  if [ "$count" -eq 0 ]; then
    echo "[snapshot] 경고: $base 와 교체 파일 중 $SINCE 이후 수정된 파일이 없습니다(경로·권한 확인)" >&2
  fi
}

copy_layer apache "$SRC_APACHE"
copy_layer auth "$SRC_AUTH"
copy_layer audit "$SRC_AUDIT"
copy_layer suricata "$SRC_SURICATA"

cat > "$DEST/snapshot.env" <<EOF
# eval/snapshot_logs.sh 가 만든 파일 — run_eval.sh 가 읽는다. 손으로 고치지 않는다.
SNAPSHOT_AT=$SNAPSHOT_AT
SNAPSHOT_SINCE=$SINCE
SNAPSHOT_DAYS=$DAYS
APACHE_LOG_PATH=$DEST/apache/$(basename "$SRC_APACHE")
AUTH_LOG_PATH=$DEST/auth/$(basename "$SRC_AUTH")
AUDIT_LOG_PATH=$DEST/audit/$(basename "$SRC_AUDIT")
SURICATA_LOG_PATH=$DEST/suricata/$(basename "$SRC_SURICATA")
EOF

echo "[snapshot] 고정 시각 $SNAPSHOT_AT (최근 ${DAYS}일, $SINCE 이후 수정된 파일)"
echo "[snapshot] 전체 $(du -sh "$DEST" | cut -f1) — 설정: $DEST/snapshot.env"
echo "[snapshot] 다음: bash eval/run_eval.sh detect   (후보 사건 목록 만들기)"
