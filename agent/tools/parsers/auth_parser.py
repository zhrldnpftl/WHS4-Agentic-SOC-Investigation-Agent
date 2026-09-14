"""auth.log(syslog) 파서 — ssh_login/sudo/pam 이벤트 분류 + IP/user/result 추출.

팀원이 실제 auth.log로 검증한 파싱 로직을 그대로 가져왔다. 원본은 파일을 직접
열어서 읽고(AUTH_LOG_PATH 하드코딩) limit/offset 페이지네이션까지 그 함수 안에서
담당했는데, 여기서는 순수 "텍스트 -> 분류된 이벤트 리스트" 파싱 로직만 남겼다.
파일 읽기(S3/로컬 선택)와 페이지네이션은 agent/tools/real/fetch_auth_log.py
(tool 파일)가 담당한다.

syslog 형식(auth.log)은 한 줄에 연도가 없어서("Sep 11 09:04:37"), 호출 시점에
reference_year를 넘겨줘야 절대 시각으로 변환할 수 있다. 조사 요청의 start_time
연도를 그대로 쓰면 되지만, 연말/연초 경계(12/31 -> 1/1)를 넘나드는 조회는
정확하지 않을 수 있다는 한계가 있다 (팀원 원본도 동일한 한계).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ============================================================
# 로그 한 줄 파싱용 정규식
# ============================================================

LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\w+)(\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)
#   "Sep 11 09:04:37 ip-10-0-7-236 sshd[2381]: Failed password for admin from 203.0.113.7 ..."
#   전체 줄을 timestamp / host / process / message 네 덩어리로 1차로 쪼개는 역할만 한다.
#   IP는 아직 message 안에 원문 그대로 남아있다.

# [IP를 어떻게 가져왔나] "Failed password for admin from 203.0.113.7 port 51122 ssh2"에서
# IP는 항상 "from " 다음, "port " 앞의 고정된 위치에 나온다. 그래서 (?P<ip>...)를
# "from " 뒤에 배치해서 그 자리의 숫자.점 문자열을 IP로 간주한다 (DNS 조회 없이 원문 그대로 신뢰).
SSH_FAILURE_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_SUCCESS_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)")

# [IP를 어떻게 가져왔나] "sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=..."
# 형태에서 COMMAND= 뒤 내용 길이가 제각각이라 위치를 고정할 수 없어서, RHOST=를 메시지
# 전체에서 별도 검색한다 (있으면 뽑고 없으면 None). 바깥 LOG_LINE_RE가 이미 "sudo:"를
# 떼어가므로, 이 정규식은 "sudo:"를 다시 찾지 않고 남은 형태에서 맨 앞 사용자명만 뽑는다.
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s+:.*COMMAND=")
SUDO_RHOST_RE = re.compile(r"RHOST=(?P<ip>[\d.]+)")

# [IP를 어떻게 가져왔나] "pam_unix(su:auth): authentication failure; ... user=root" 형태.
# su/콘솔 로그인처럼 로컬 인증은 IP가 안 찍히지만, sshd가 PAM을 거치는 경우
# "rhost=1.2.3.4"가 덧붙는 경우가 흔해서 sudo와 동일하게 있으면 뽑고 없으면 None.
# sudo는 대문자 "RHOST=", pam_unix는 소문자 "rhost="가 흔해서 re.IGNORECASE 사용.
PAM_RE = re.compile(r"pam_unix\(.*\):\s+(?P<result>authentication (failure|success)).*user=(?P<user>\S+)")
PAM_RHOST_RE = re.compile(r"rhost=(?P<ip>[\d.]+)", re.IGNORECASE)


def _classify_line(message: str) -> Optional[Dict[str, Any]]:
    """message를 위 정규식들로 순서대로 검사해서, 명세가 요구하는 4개 필드
    (event_type/user/source_ip/result)로 통일된 dict를 반환한다. 매칭 안 되면 None
    (아직 이름 붙지 않은 이벤트는 여기서 걸러짐).
    """
    if m := SSH_FAILURE_RE.search(message):
        return {"event_type": "ssh_login", "user": m.group("user"), "source_ip": m.group("ip"), "result": "failure"}

    if m := SSH_SUCCESS_RE.search(message):
        return {"event_type": "ssh_login", "user": m.group("user"), "source_ip": m.group("ip"), "result": "success"}

    if m := SUDO_RE.search(message):
        rhost_match = SUDO_RHOST_RE.search(message)
        ip = rhost_match.group("ip") if rhost_match else None
        return {"event_type": "sudo", "user": m.group("user"), "source_ip": ip, "result": "success"}

    if m := PAM_RE.search(message):
        result = "success" if "success" in m.group("result") else "failure"
        rhost_match = PAM_RHOST_RE.search(message)
        ip = rhost_match.group("ip") if rhost_match else None
        return {"event_type": "pam", "user": m.group("user"), "source_ip": ip, "result": result}

    return None


def _parse_timestamp(raw_timestamp: str, reference_year: int) -> Optional[datetime]:
    """"Sep 11 09:04:37" + 연도 -> datetime. 명세가 ISO8601을 요구하는데 원문엔
    연도가 없어서, 호출부(start_time)의 연도를 붙여줘야 절대 시각이 나온다.
    """
    try:
        return datetime.strptime(f"{reference_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_auth_events(
    text: str,
    reference_year: int,
    time_window: "Optional[tuple]" = None,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    event_type: Optional[str] = None,
    result: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """auth.log 텍스트를 읽어 조건에 맞는 인증 이벤트를 공통스키마 dict 리스트로 반환.

    limit/offset 페이지네이션은 여기서 하지 않는다 — 파서는 "필터에 맞는 전체 목록"까지만
    책임지고, 페이지 자르기는 호출부(agent/tools/real/fetch_auth_log.py)가 담당한다.
    """
    events: List[Dict[str, Any]] = []

    for raw_log_counter, line in enumerate(text.split("\n"), start=1):
        line = line.strip()
        if not line:
            continue

        match = LOG_LINE_RE.match(line)
        if not match:
            continue

        log_time = _parse_timestamp(match.group("timestamp"), reference_year)
        if log_time is None:
            continue
        if log_time.tzinfo is None:
            # syslog 원문엔 timezone이 없어서 naive datetime이 나온다. 우리 시스템은
            # 전부 UTC 기준(parse_iso 등)이라, 비교/직렬화 전에 UTC로 맞춰준다.
            log_time = log_time.replace(tzinfo=timezone.utc)
        if time_window is not None:
            start, end = time_window
            if not (start <= log_time <= end):
                continue

        classified = _classify_line(match.group("message"))
        if classified is None:
            continue

        if source_ip and classified["source_ip"] != source_ip:
            continue
        if user and classified["user"] != user:
            continue
        if event_type and classified["event_type"] != event_type:
            continue
        if result and classified["result"] != result:
            continue

        events.append(
            {
                "timestamp": log_time.isoformat(),
                "source_ip": classified["source_ip"],
                "user": classified["user"],
                "event_type": classified["event_type"],
                "result": classified["result"],
                "raw_log_ref": f"auth.log:{raw_log_counter}",
            }
        )

    return events