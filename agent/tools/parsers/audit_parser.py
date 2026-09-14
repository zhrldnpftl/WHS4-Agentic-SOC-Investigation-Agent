"""audit.log 전용 파서 — ENRICHED 포맷 + 멀티라인(serial) 조립 + hex 디코딩.

팀원이 실제 EC2 audit.log(16,904건)로 검증한 파싱 로직을 그대로 가져왔다.
원본은 tools.base/tools.registry(팀원의 별도 프레임워크)에 의존했는데, 여기서는
프레임워크 의존을 떼어내고 순수 파싱 함수만 남겼다 — 이 프로젝트는
agent/tools/registry.py의 ToolRegistry(파일명=도구명 자동 탐색)를 쓰기 때문.

이 모듈은 agent/tools/real/fetch_audit_log.py(tool)와
agent/raw_log_ingestion.py(수집 계층) 양쪽에서 재사용한다.

원본 대비 바뀐 것: fetch_audit_log(log_path, ...)가 "파일 경로"만 받았는데,
parse_audit_events(text, ...)는 "텍스트"를 받는다 — S3에서 읽어온 텍스트도
파일 없이 바로 처리해야 하기 때문. 파싱 로직(parse_line/group_by_serial/
assemble_event/디코더/필터) 자체는 원본과 동일하다.

*** 중요한 함정: text.splitlines()를 쓰면 안 된다 ***
파이썬의 str.splitlines()는 '\n'뿐 아니라 \x1c/\x1d/\x1e 같은 제어 문자도
"줄바꿈"으로 취급해서 나눈다. ENRICHED 구분자(GS=\x1d)가 있는 줄을
splitlines()로 나누면 raw/enriched가 합쳐지기도 전에 둘로 쪼개져서 enriched
절반이 통째로 버려진다 (원본 코드는 파일 객체를 `for line in f`로 순회해서
'\n'으로만 나뉘었기 때문에 이 문제가 없었다). 그래서 여기서는 반드시
text.split("\n")을 쓴다 (parse_audit_events 안에서 실제로 그렇게 함).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

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
def parse_line(line: str) -> Optional[Dict[str, Any]]:
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

    fields: Dict[str, str] = {}
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
def group_by_serial(lines: Iterable[str]) -> Dict[int, List[Dict[str, Any]]]:
    """줄들을 SERIAL로 묶는다 → {serial: [records...]} (등장 순서 보존)."""
    groups: Dict[int, List[Dict[str, Any]]] = {}
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
            args.append(_unquote(tok))  # 평문
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
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)

    syscall_rec = by_type.get("SYSCALL", [None])[0]

    if syscall_rec is None:
        if include_user_cmd and "USER_CMD" in by_type:
            return _assemble_user_cmd(by_type["USER_CMD"][0], log_name)
        return None

    sf = syscall_rec["fields"]
    serial = syscall_rec["serial"]

    syscall_name = _get(sf, "SYSCALL")
    if syscall_name is None:
        syscall_name = _SYSCALL_NAMES.get(_to_int(_get(sf, "syscall")), _get(sf, "syscall"))

    exe = _get(sf, "exe")
    key = _get(sf, "key")
    auid = _get(sf, "auid")

    cwd_rec = by_type.get("CWD", [None])[0]
    cwd = _get(cwd_rec["fields"], "cwd") if cwd_rec else None

    exec_args = None
    if syscall_name == "execve":
        execve_rec = by_type.get("EXECVE", [None])[0]
        if execve_rec is not None:
            exec_args = decode_execve(execve_rec)
        else:
            proctitle_rec = by_type.get("PROCTITLE", [None])[0]
            if proctitle_rec is not None:
                exec_args = decode_proctitle(proctitle_rec["fields"].get("proctitle"))

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
        "user": _get(sf, "UID"),  # enriched 해석값("root"/"www-data"/"ubuntu")
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
        r
        for r in path_recs
        if _get(r["fields"], "nametype") != "PARENT" and "ld-linux" not in (_get(r["fields"], "name") or "")
    ]
    chosen = non_parent[-1] if non_parent else path_recs[0]
    return _get(chosen["fields"], "name")


def _assemble_user_cmd(user_cmd_rec, log_name):
    """USER_CMD(PAM sudo) 레코드 → 최소 공통스키마(옵션)."""
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
def match_filter(event, filters) -> bool:
    """event가 filters(AND 결합)를 모두 만족하면 True. (src_ip 없음 — audit엔 IP가 없음)"""
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


# --- 7. 오케스트레이터 ---------------------------------------------------------
def parse_audit_events(
    text: str,
    log_name: str = "audit.log",
    time_window=None,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    key: Optional[str] = None,
    serial: Optional[int] = None,
    exclude_interactive: bool = False,
    include_user_cmd: bool = False,
) -> List[Dict[str, Any]]:
    """audit.log 텍스트를 읽어 조건에 맞는 시스템 이벤트를 공통스키마 dict 리스트로 반환.

    원본(팀원 코드)은 파일 경로를 열어서 처리했는데, 여기서는 이미 읽어온 텍스트를
    받는다 — S3에서 읽어온 텍스트도 파일 없이 바로 처리해야 하기 때문이다.
    필터는 전부 optional, 조합은 AND.
    """
    groups = group_by_serial(text.split("\n"))  # splitlines()는 \x1d도 줄바꿈으로 취급해서 금지

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