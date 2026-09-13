"""
tools/fetch_audit_log.py
도구 본체. raw `audit.log`를 직접 읽어 조건에 맞는 시스템(audit) 이벤트를
공통스키마 dict 리스트로 반환한다. "가져오기 + 파싱"만 한다.

절대 원칙:
  - 판단/스코어링/에이전트화 금지. 결정론적 코드. LLM 호출 없음.
  - 로그 접근·필터는 도구 책임. raw를 통째로 에이전트에 넘기지 않는다.
  - audit 로그엔 IP가 없다(SOCKADDR가 전부 netlink) → src_ip 필터 없음.

우리 audit.log 특징(실데이터 기반):
  - ENRICHED 포맷: 한 줄 = [raw part] <0x1d(GS)> [enriched part].
    양쪽 다 key=value로 파싱해 병합. 0x1d 없으면 raw만.
  - 멀티라인 조립: msg=audit(EPOCH.mmm:SERIAL) 의 SERIAL로 한 사건을 묶는다.
  - hex 인코딩: PROCTITLE(항상 hex, 0x00 구분), USER_CMD cmd(hex),
    EXECVE aN(공백/특수문자면 hex, 아니면 "따옴표" 평문).
  - auid=4294967295 → non_interactive(웹발), else interactive(관리자 등).
"""

# ========= 지원님 코드 =============
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv

from tools.base import success, failure
from tools.registry import register

# 로그 경로 (.env)
load_dotenv()
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/audit/audit.log")


# --- 상수 --------------------------------------------------------------------
GS = "\x1d"  # 0x1d, enriched 구분자(비출력)

# msg=audit(EPOCH.mmm:SERIAL): <rest> 헤더
_HEADER_RE = re.compile(
    r"type=(?P<type>\S+)\s+"
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<rest>.*)$"
)
# key=value (값은 "따옴표" 또는 공백없는 토큰)
_FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

# enriched(0x1d 뒤)가 없는 줄을 위한 syscall 번호→이름 폴백 맵(최소셋 + 실측 관측치)
_SYSCALL_NAMES = {
    1: "write",
    2: "open",
    42: "connect",
    59: "execve",
    62: "kill",
    82: "rename",
    83: "mkdir",
    87: "unlink",
    90: "chmod",
    257: "openat",
    268: "fchmodat",
}


# --- 작은 헬퍼 ----------------------------------------------------------------
def _unquote(value):
    """양끝 큰따옴표만 벗긴다. bare 값/hex 값은 그대로."""
    if value is not None and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _get(fields, key, default=None):
    """fields에서 key를 꺼내 따옴표를 벗겨 반환."""
    v = fields.get(key)
    return _unquote(v) if v is not None else default


def _to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _epoch_to_iso(epoch_str):
    """'1789218445.832' → '2026-09-11T02:00:45.832Z' (UTC, 밀리 보존).

    float 변환 오차를 피하려고 밀리초는 원문 문자열에서 그대로 취한다.
    """
    if "." in epoch_str:
        sec, frac = epoch_str.split(".", 1)
    else:
        sec, frac = epoch_str, "0"
    dt = datetime.fromtimestamp(int(sec), tz=timezone.utc)
    millis = (frac + "000")[:3]
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + millis + "Z"


def _iso_to_dt(iso_str):
    """ISO8601(UTC, 'Z' 허용) → aware datetime. 비교용."""
    if iso_str is None:
        return None
    s = iso_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# --- 1. 한 줄 파싱 -------------------------------------------------------------
def parse_line(line):
    """audit.log 한 줄 → {type, epoch, serial, fields}. 파싱 불가 시 None.

    0x1d로 raw/enriched를 분리해 양쪽 다 key=value 파싱 후 fields로 병합한다.
    fields 값은 원문(따옴표 포함) 그대로 저장한다 — EXECVE aN의 평문/hex 판별에
    따옴표 유무가 필요하기 때문. 꺼내 쓸 때 _get()/_unquote()로 벗긴다.
    """
    line = line.rstrip("\n")
    if not line:
        return None

    raw_part, sep, enriched_part = line.partition(GS)

    m = _HEADER_RE.match(raw_part)
    if not m:
        return None

    fields = {}
    for k, v in _FIELD_RE.findall(m.group("rest")):
        fields[k] = v
    if sep:  # enriched가 있으면 병합(대문자 키라 raw와 충돌 없음)
        for k, v in _FIELD_RE.findall(enriched_part):
            fields[k] = v

    return {
        "type": m.group("type"),
        "epoch": m.group("epoch"),
        "serial": int(m.group("serial")),
        "fields": fields,
    }


# --- 2. 멀티라인 조립 ----------------------------------------------------------
def group_by_serial(lines):
    """줄들을 SERIAL로 묶는다 → {serial: [records...]} (등장 순서 보존)."""
    groups = {}
    for line in lines:
        rec = parse_line(line)
        if rec is None:
            continue
        groups.setdefault(rec["serial"], []).append(rec)
    return groups


# --- 3. hex 디코더 ------------------------------------------------------------
def decode_proctitle(hex_str):
    """PROCTITLE hex → 커맨드라인. 0x00 구분자를 공백으로 복원."""
    if hex_str is None:
        return None
    try:
        raw = bytes.fromhex(_unquote(hex_str))
    except ValueError:
        return None
    parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p != b""]
    return " ".join(parts)


def decode_execve(execve_rec):
    """EXECVE 레코드 → argv 문자열. aN이 "로 시작하면 평문, 아니면 hex."""
    if execve_rec is None:
        return None
    f = execve_rec["fields"]
    argc = _to_int(_unquote(f.get("argc", "0")), 0)
    args = []
    for i in range(argc):
        tok = f.get("a%d" % i)
        if tok is None:
            continue
        if tok.startswith('"'):
            args.append(_unquote(tok))          # 평문
        else:
            try:
                args.append(bytes.fromhex(tok).decode("utf-8", "replace"))  # hex
            except ValueError:
                args.append(tok)
    return " ".join(args)


# --- 4. session_type 도출 ------------------------------------------------------
def derive_session_type(auid):
    """auid 판별 → 'interactive' | 'non_interactive'.

    auid==4294967295(unset) → non_interactive(웹발/데몬 유래), 그 외 interactive.
    """
    if str(auid) == "4294967295":
        return "non_interactive"
    return "interactive"


# --- 5. 이벤트 조립(공통스키마 1건) --------------------------------------------
def assemble_event(records, log_name="audit.log", include_user_cmd=False):
    """한 SERIAL의 레코드들 → 공통스키마 dict. 앵커 없으면 None."""
    by_type = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)

    syscall_rec = by_type.get("SYSCALL", [None])[0]

    # D4: SYSCALL 앵커만 기본. USER_CMD는 옵션.
    if syscall_rec is None:
        if include_user_cmd and "USER_CMD" in by_type:
            return _assemble_user_cmd(by_type["USER_CMD"][0], log_name)
        return None

    sf = syscall_rec["fields"]
    serial = syscall_rec["serial"]

    # syscall 이름: enriched 우선, 없으면 번호 폴백맵
    syscall_name = _get(sf, "SYSCALL")
    if syscall_name is None:
        syscall_name = _SYSCALL_NAMES.get(_to_int(_get(sf, "syscall")), _get(sf, "syscall"))

    exe = _get(sf, "exe")
    key = _get(sf, "key")
    auid = _get(sf, "auid")

    # cwd
    cwd_rec = by_type.get("CWD", [None])[0]
    cwd = _get(cwd_rec["fields"], "cwd") if cwd_rec else None

    # exec_args: execve일 때만. EXECVE argv 우선, 없으면 PROCTITLE 폴백(D3).
    #            비-execve(파일 open 등)는 null(§5) — proctitle은 호출자 cmdline이므로 제외.
    exec_args = None
    if syscall_name == "execve":
        execve_rec = by_type.get("EXECVE", [None])[0]
        if execve_rec is not None:
            exec_args = decode_execve(execve_rec)
        else:
            proctitle_rec = by_type.get("PROCTITLE", [None])[0]
            if proctitle_rec is not None:
                exec_args = decode_proctitle(proctitle_rec["fields"].get("proctitle"))

    # target_file
    target_file = _resolve_target_file(syscall_name, exe, by_type.get("PATH", []))

    return {
        "timestamp": _epoch_to_iso(syscall_rec["epoch"]),
        "layer": "system",
        "serial": serial,
        "pid": _to_int(_get(sf, "pid")),
        "ppid": _to_int(_get(sf, "ppid")),
        "syscall": syscall_name,
        "key": key,
        "exe": exe,
        "comm": _get(sf, "comm"),
        "user": _get(sf, "UID"),          # enriched 해석값("root"/"www-data"/"ubuntu")
        "uid": _to_int(_get(sf, "uid")),
        "euid": _to_int(_get(sf, "euid")),
        "cwd": cwd,
        "exec_args": exec_args,
        "success": _get(sf, "success"),
        "session_type": derive_session_type(auid),
        "target_file": target_file,
        "raw_ref": "%s:%d" % (log_name, serial),
    }


def _resolve_target_file(syscall_name, exe, path_recs):
    """대상 파일 결정.
      - execve: argv[0] 바이너리 = exe(없으면 PATH item0).
      - 그 외(파일접근 키): PATH에서 PARENT 아닌 마지막 항목(ld-linux 제외).
    """
    if syscall_name == "execve":
        if exe:
            return exe
        return _get(path_recs[0]["fields"], "name") if path_recs else None

    if not path_recs:
        return None
    non_parent = [
        r for r in path_recs
        if _get(r["fields"], "nametype") != "PARENT"
        and "ld-linux" not in (_get(r["fields"], "name") or "")
    ]
    chosen = non_parent[-1] if non_parent else path_recs[0]
    return _get(chosen["fields"], "name")


def _assemble_user_cmd(user_cmd_rec, log_name):
    """USER_CMD(PAM sudo) 레코드 → 최소 공통스키마(옵션 D4)."""
    f = user_cmd_rec["fields"]
    auid = _get(f, "auid")
    cmd_hex = _get(f, "cmd")
    exec_args = decode_proctitle(cmd_hex) if cmd_hex else None
    return {
        "timestamp": _epoch_to_iso(user_cmd_rec["epoch"]),
        "layer": "system",
        "serial": user_cmd_rec["serial"],
        "pid": _to_int(_get(f, "pid")),
        "ppid": None,
        "syscall": "USER_CMD",
        "key": None,
        "exe": _get(f, "exe"),
        "comm": None,
        "user": _get(f, "UID"),
        "uid": _to_int(_get(f, "uid")),
        "euid": _to_int(_get(f, "euid")),
        "cwd": _get(f, "cwd"),
        "exec_args": exec_args,
        "success": _get(f, "res") or _get(f, "success"),
        "session_type": derive_session_type(auid),
        "target_file": None,
        "raw_ref": "%s:%d" % (log_name, user_cmd_rec["serial"]),
    }


# --- 6. 필터 매칭 -------------------------------------------------------------
def match_filter(event, filters):
    """event가 filters(AND 결합)를 모두 만족하면 True. (src_ip 없음)"""
    tw = filters.get("time_window")
    if tw:
        start, end = tw
        ev_dt = _iso_to_dt(event["timestamp"])
        if start is not None and ev_dt < _iso_to_dt(start):
            return False
        if end is not None and ev_dt > _iso_to_dt(end):
            return False

    if filters.get("pid") is not None and event["pid"] != filters["pid"]:
        return False
    if filters.get("ppid") is not None and event["ppid"] != filters["ppid"]:
        return False
    if filters.get("key") is not None and event["key"] != filters["key"]:
        return False
    if filters.get("serial") is not None and event["serial"] != filters["serial"]:
        return False
    if filters.get("exclude_interactive") and event["session_type"] == "interactive":
        return False

    return True


# --- 7. 오케스트레이터(순수 함수) ----------------------------------------------
def fetch_audit_log(
    log_path,
    time_window=None,
    pid=None,
    ppid=None,
    key=None,
    serial=None,
    exclude_interactive=False,
    include_user_cmd=False,
):
    """raw audit.log를 읽어 조건에 맞는 시스템 이벤트를 공통스키마 dict 리스트로 반환.

    필터는 전부 optional(log_path만 필수), 조합은 AND.
    """
    with open(log_path, encoding="utf-8", errors="replace") as f:
        groups = group_by_serial(f)

    log_name = os.path.basename(log_path)
    filters = {
        "time_window": time_window,
        "pid": pid,
        "ppid": ppid,
        "key": key,
        "serial": serial,
        "exclude_interactive": exclude_interactive,
    }

    events = []
    for _serial, records in groups.items():
        event = assemble_event(records, log_name=log_name, include_user_cmd=include_user_cmd)
        if event is None:
            continue
        if match_filter(event, filters):
            events.append(event)

    events.sort(key=lambda e: (e["timestamp"], e["serial"]))
    return events


# 도구 등록
@register(
    name="fetch_audit_log",
    description=(
        "raw audit.log를 읽어 조건에 맞는 시스템(audit) 이벤트를 공통스키마로 반환한다. "
        "필터: time_window/pid/ppid/key(exec|webroot|sensitive|cloud_creds)/serial/"
        "exclude_interactive. audit엔 IP가 없어 src_ip 필터는 없다."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "log_path": {"type": "string", "description": "audit.log 경로. 생략 시 .env AUDIT_LOG_PATH."},
            "time_window": {
                "type": "array",
                "items": {"type": "string"},
                "description": "[start_iso, end_iso] UTC(경계 포함).",
            },
            "pid": {"type": "integer"},
            "ppid": {"type": "integer"},
            "key": {"type": "string", "enum": ["exec", "webroot", "sensitive", "cloud_creds"]},
            "serial": {"type": "integer"},
            "exclude_interactive": {
                "type": "boolean",
                "description": "True면 session_type=interactive(관리자 노이즈) 제외.",
            },
        },
        "required": [],
    },
)
def fetch_audit_log_tool(log_path: str = None, **filters) -> dict:
    path = log_path or AUDIT_LOG_PATH
    try:
        events = fetch_audit_log(path, **filters)
    except FileNotFoundError:
        return failure("audit 로그 없음: %s" % path)
    except Exception as exc:  # 파싱 사고도 도구가 삼키지 않고 이유를 알린다
        return failure("audit 파싱 실패: %s" % exc)
    return success({"count": len(events), "events": events})
