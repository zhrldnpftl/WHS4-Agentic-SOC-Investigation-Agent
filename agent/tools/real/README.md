# agent/tools/real/

실제 로그 조회 구현을 넣는 폴더입니다. **파일 이름 = 도구 이름**, **함수 이름 = 도구 이름**
이 두 가지만 지키면 `agent/tools/registry.py`의 `build_default_registry()`가 자동으로
찾아서 씁니다. `main.py`나 `registry.py`를 고칠 필요가 없습니다.

## 등록해야 하는 6개 도구 이름 (agent/tools/registry.py의 tool_defs 참고)

- `fetch_web_log`
- `fetch_auth_log`
- `fetch_audit_log` (내부에서 resolve_saddr 처리)
- `fetch_network_log`
- `get_process_tree`
- `resolve_ip_geo`

## 규칙

1. 파일명: `agent/tools/real/<도구이름>.py` (예: `fetch_auth_log.py`)
2. 그 파일 안에 **똑같은 이름**의 함수를 정의: `def fetch_auth_log(args: dict) -> dict:`
3. 반환값은 반드시 아래 형태를 지켜야 합니다 (다른 모듈을 수정할 필요가 없어짐).

```python
{
    "count": 1,                 # 조회된 레코드 수 (int)
    "summary": "설명 한 줄",     # 사람이 읽는 요약 (str)
    "records": [ {...}, ... ],  # 실제 로그 레코드 목록 (LLM이 이 안의 내용을 evidence로 해석함)
}
```

4. `args`는 `agent/tools/registry.py`의 `required_args`/`optional_args`에 정의된 키만
   들어옵니다 (예: `fetch_auth_log`는 `host`, `start_time`, `end_time`이 필수, `user`,
   `src_ip`가 선택). 도구의 정확한 입력 스펙은 `registry.py`의 `tool_defs`를 확인하세요.

## 예시 (fetch_auth_log.py)

```python
def fetch_auth_log(args: dict) -> dict:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]

    # ... 실제 auth.log 조회 로직 ...
    records = [...]

    return {
        "count": len(records),
        "summary": f"{host}에서 {len(records)}건의 로그인 시도 확인",
        "records": records,
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

## 주의

- 파일명이나 함수명이 도구 이름과 하나라도 다르면(오타 포함) 자동 탐색에 실패하고
  **조용히 목업으로 폴백**합니다 (에러가 안 나서 오히려 눈치채기 어려우니, 위 확인 방법으로
  꼭 한 번 찍어보세요).
- 여러 명이 같은 이름의 파일을 만들면 마지막에 커밋된 것이 남으니, 도구별로 담당자를
  명확히 나눠서 각자 자기 파일만 건드리세요.
