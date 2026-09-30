# agent/tools/real/

실제 로그 조회 구현을 넣는 폴더입니다. **파일 이름 = 도구 이름**, **함수 이름 = 도구 이름**
이 두 가지만 지키면 `agent/tools/registry.py`의 `build_default_registry()`가 자동으로
찾아서 씁니다. `main.py`나 `registry.py`를 고칠 필요가 없습니다.

## 등록해야 하는 6개 도구 이름 (agent/tools/registry.py의 tool_defs 참고)

- `fetch_event_logs`
- `fetch_web_log`
- `fetch_auth_log`
- `fetch_audit_log`
- `fetch_network_log`
- `get_process_tree`

## 규칙

1. 파일명: `agent/tools/real/<도구이름>.py` (예: `fetch_auth_log.py`)
2. 그 파일 안에 **똑같은 이름**의 함수를 정의: `def fetch_auth_log(args: dict) -> dict:`
3. 반환값은 반드시 아래 형태를 지켜야 합니다 (다른 모듈을 수정할 필요가 없어짐).

```python
{
    "count": 1,                 # 이번에 반환한 레코드 수 (int)
    "summary": "설명 한 줄",     # 사람이 읽는 요약 (str)
    "records": [ {...}, ... ],  # 실제 로그 레코드 목록 (LLM이 이 안의 내용을 evidence로 해석함)
    # 페이지네이션을 지원하는 경우(아래 참고) 추가로:
    "total_matched": 10,        # 필터에 맞는 전체 건수
    "has_more": True,           # 더 있는지
    "next_offset": 200,         # 있으면 다음 offset, 없으면 None
}
```

4. `args`는 `agent/tools/registry.py`의 `required_args`/`optional_args`에 정의된 키만
   들어옵니다. 정확한 입력 스펙은 `registry.py`의 `tool_defs`를 확인하세요.

## 파싱 로직은 여기 두지 마세요

이 폴더의 4개 tool 파일(`fetch_web_log.py`, `fetch_auth_log.py`, `fetch_audit_log.py`,
`fetch_network_log.py`)은 전부 **얇은 wrapper**입니다. 실제 "텍스트 → 구조화된
이벤트" 파싱 로직은 `agent/tools/parsers/`에 있고, 이 폴더의 파일은:

- `.env`에 지정된 로그 파일 경로 읽기
- 파서를 호출
- 페이지네이션(아래) 처리
- 권한 에러(`PermissionError`) 등 예외 처리

만 담당합니다. 새 로그 형식을 지원해야 한다면, 파싱 로직은
`agent/tools/parsers/README.md`를 참고해 그쪽에 만들고, 여기서는 그 파서를
불러다 쓰기만 하세요.

## 페이지네이션

`fetch_auth_log`/`fetch_network_log`는 실측 결과 한 번의 조회로 수백 건이
나올 수 있어(SSH 브루트포스 하나로 399건), `limit`/`offset` 페이지네이션을
채택했습니다. `fetch_audit_log`/`fetch_web_log`도 동일 패턴을 따릅니다.
`args`에 `limit`(기본 200)/`offset`(기본 0)이 있으면 그만큼 잘라 반환하고,
`total_matched`/`has_more`/`next_offset`으로 LLM이 필요하면 이어서 조회할 수
있게 합니다.

## 로그 파일 읽기

각 tool 파일은 `.env`의 `<도구명 대문자>_LOCAL_PATH`(예: `AUTH_LOG_PATH`)에
지정된 경로의 파일을 읽습니다. EC2에 배포된 상태에서는 이 경로가 실제 시스템
로그 경로(`/var/log/auth.log` 등)를 가리키고, 로컬 개발 중에는 샘플 로그 경로를
가리킵니다 — **코드는 동일하고 `.env`의 경로만 다릅니다.**

파일이 없으면 `not_found`, 읽기 권한이 없으면(`PermissionError`) `permission_denied`로
구분해 summary에 남기므로, "데이터가 없다"와 "권한이 없다"를 헷갈리지 않게 되어 있습니다.
EC2에서 실제 시스템 로그(예: `/var/log/audit/audit.log`)를 읽으려면 프로세스가
해당 파일을 읽을 권한(보통 root 또는 적절한 그룹)을 가지고 있어야 합니다.

## 예시 (fetch_auth_log.py, 골격만)

```python
import os
from ..parsers.auth_parser import parse_auth_events
from ..time_utils import parse_iso

def _read_source_text(path: str) -> tuple[str, str]:
    if not os.path.exists(path):
        return "", "not_found"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except PermissionError:
        return "", "permission_denied"

def fetch_auth_log(args: dict) -> dict:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])
    limit = int(args.get("limit", 200))
    offset = int(args.get("offset", 0))

    log_path = os.environ.get("AUTH_LOG_PATH")
    text, error = _read_source_text(log_path)

    all_events = parse_auth_events(text, reference_year=start.year, time_window=(start, end),
                                    source_ip=args.get("src_ip"), user=args.get("user"))

    total_matched = len(all_events)
    page = all_events[offset : offset + limit]
    return {
        "count": len(page),
        "summary": "...",
        "records": page,
        "total_matched": total_matched,
        "has_more": (offset + limit) < total_matched,
        "next_offset": offset + limit if (offset + limit) < total_matched else None,
    }
```

## 확인 방법

파일을 넣은 뒤 아래처럼 실행해서 목업이 아니라 실제 함수가 붙었는지 확인하세요.

```python
from agent import build_default_registry

registry = build_default_registry()
print(registry.get("fetch_auth_log").handler)
# <function fetch_auth_log at 0x...>  <- agent.tools.real.fetch_auth_log 쪽이면 성공
```

새 시나리오 로그를 넣고 도구가 제대로 찾는지 직접 확인하고 싶을 때는 (LLM을
거치지 않고) 이렇게 직접 호출해보는 것도 유용합니다:

```powershell
python -c "from agent.tools.real.fetch_auth_log import fetch_auth_log; import os; os.environ['AUTH_LOG_PATH']='sample_logs/sample_auth.log'; r = fetch_auth_log({'host':'web-01','start_time':'...','end_time':'...'}); print(r['count'])"
```

## 주의

- 파일명이나 함수명이 도구 이름과 하나라도 다르면(오타 포함) 자동 탐색에 실패하고
  **조용히 목업으로 폴백**합니다 (에러가 안 나서 오히려 눈치채기 어려우니, 위 확인 방법으로
  꼭 한 번 찍어보세요).
- 여러 명이 같은 이름의 파일을 만들면 마지막에 커밋된 것이 남으니, 도구별로 담당자를
  명확히 나눠서 각자 자기 파일만 건드리세요.
- 도구 인자에 리스트나 딕셔너리 값이 올 수 있는 경우, `agent/models.py`의
  `AgentState._to_hashable()`이 중복 호출 판단 시 이를 안전하게 처리하니 별도
  방어 코드는 필요 없습니다.