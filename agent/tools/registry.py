"""조사 도구 레지스트리 — LLM이 고른 도구 이름을 실제 함수로 연결하고 실행한다.

역할
  7개 조사 도구의 이름·설명·인자(ToolSpec)를 정의하고, 도구마다 실행할 함수를 찾아 붙인다.
  LLM에게 보여줄 도구 설명(schema_text)을 만들고, 호출 인자를 검사한 뒤 실제 함수를 실행한다.

누가 부르나
  [2]  main.py main()                       → build_default_registry()
  [21] agent/prompts/__init__.py            → schema_text()      시스템 프롬프트의 도구 목록
  [29]·[30] agent/loop.py _execute_tool_call() → validate_args(), call()

무엇을 부르나
  [31] agent/tools/real/<도구이름>.py 의 같은 이름 함수 (자동 탐색)
  agent/tools/mock_tools.py MOCK_HANDLERS   실제 구현이 없을 때 목업

실행 함수를 고르는 우선순위
  1. build_default_registry(handlers={...})로 명시적으로 넘긴 함수 (테스트용)
  2. agent/tools/real/<도구이름>.py 안의 같은 이름 함수 (파일명 == 함수명 == 도구명)
  3. mock_tools.py의 목업 — 에러 없이 조용히 폴백하므로, 새 도구를 붙인 뒤에는
     registry.get(name).handler로 실제 함수가 연결됐는지 확인할 것 (agent/tools/real/README.md)
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .mock_tools import MOCK_HANDLERS

ToolHandler = Callable[[Dict[str, Any]], Dict[str, Any]]


def _try_import_real_handler(tool_name: str) -> Optional[ToolHandler]:
    """agent/tools/real/<tool_name>.py에 동일한 이름의 함수가 있으면 가져온다.

    파일이 없거나, 파일은 있는데 함수 이름이 다르면 None을 반환하고
    (에러 없이) 목업으로 폴백한다.
    """
    try:
        module = importlib.import_module(f".real.{tool_name}", package=__package__)
    except ModuleNotFoundError:
        return None
    handler = getattr(module, tool_name, None)
    if handler is not None and not callable(handler):
        return None
    return handler


class ToolValidationError(Exception):
    """도구 호출 인자가 스키마와 맞지 않을 때 발생."""


@dataclass
class ToolSpec:
    name: str
    description: str
    required_args: List[str]
    optional_args: List[str] = field(default_factory=list)
    handler: Optional[ToolHandler] = None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"등록되지 않은 도구입니다: {name}")
        return self._tools[name]

    def list_tools(self) -> List[ToolSpec]:
        return list(self._tools.values())

    def schema_text(self) -> str:
        """LLM 시스템 프롬프트에 삽입할 도구 목록 설명."""
        lines = []
        for spec in self._tools.values():
            lines.append(
                f"- {spec.name}: {spec.description} "
                f"(필수 인자: {spec.required_args}, 선택 인자: {spec.optional_args})"
            )
        return "\n".join(lines)

    # [29] ← agent/loop.py _execute_tool_call(): 필수 인자 누락·모르는 인자 검사
    def validate_args(self, name: str, args: Dict[str, Any]) -> None:
        spec = self.get(name)
        missing = [a for a in spec.required_args if a not in args]
        if missing:
            raise ToolValidationError(f"{name} 호출에 필수 인자가 없습니다: {missing}")
        allowed = set(spec.required_args) | set(spec.optional_args)
        unknown = [a for a in args if a not in allowed]
        if unknown:
            raise ToolValidationError(f"{name} 호출에 알 수 없는 인자가 있습니다: {unknown}")

    # [30] ← agent/loop.py [28] _execute_tool_call()에서 호출 (예: name="fetch_auth_log")
    def call(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        spec = self.get(name)
        self.validate_args(name, args)
        if spec.handler is None:
            raise NotImplementedError(f"{name}의 handler가 아직 연결되지 않았습니다.")
        # [31] → agent/tools/real/<name>.py의 <name>(args) 실행
        # [36] ← 도구 결과 dict를 그대로 loop.py [37]로 돌려준다
        return spec.handler(args)


def build_default_registry(
    handlers: Optional[Dict[str, ToolHandler]] = None,
    exclude: Optional[List[str]] = None,
) -> ToolRegistry:
    """[2] ← main.py에서 호출. 기본 7개 조사 도구를 등록한 레지스트리를 생성한다.

    각 도구의 handler는 아래 우선순위로 결정된다.
      1. handlers 인자로 명시적으로 넘긴 함수
      2. agent/tools/real/<도구이름>.py 안의 동일한 이름의 함수 (자동 탐색)
      3. mock_tools.py의 목업 구현 (위 둘 다 없을 때 폴백)

    exclude에 도구 이름을 넣으면 그 도구는 아예 등록하지 않는다 — 목업으로도
    폴백하지 않고, LLM에게 존재 자체를 안 보여준다. 아직 실제 구현이 없어서
    목업이 섞이면 안 되는 도구를 잠시 빼둘 때 쓴다.
    """
    handlers = handlers or {}
    exclude_set = set(exclude or [])

    tool_defs = [
        ToolSpec(
            "fetch_event_logs",
            "사건 event/window로 원본 로그를 직접 조회한다. window=[시작,끝] 또는 "
            "event의 timestamp/window 필요. layers로 여러 계층 조회 가능. "
            "filters는 계층별 조건이며 raw_ref/raw_refs를 그대로 증거에 인용한다.",
            ["host"],
            ["event", "window", "layers", "filters", "before_seconds", "after_seconds", "limit", "offset"],
        ),
        ToolSpec(
            "fetch_web_log",
            "어떤 웹 요청이 있었는지 조회한다 (apache access 로그, method/path(쿼리 포함)/status/user_agent까지 구조화, "
            "결과가 많으면 has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["path", "src_ip", "method", "status_code", "exclude_self", "limit", "offset"],
        ),
        ToolSpec(
            "fetch_auth_log",
            "로그인·권한상승 흔적이 있었는지 조회한다 (결과의 event 필드: ssh_accepted/ssh_failed/"
            "ssh_invalid_user/sudo_command 등, 인증 방식은 method(password/publickey). event_type 인자는 "
            "event 값으로 거른다. 결과가 많으면 has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["user", "src_ip", "event_type", "result", "limit", "offset"],
        ),
        ToolSpec(
            "fetch_audit_log",
            "파일 생성·변조·명령 실행이 있었는지 조회한다 "
            "(uid/euid/session_type/exe/exec_args/path(대상 파일)까지 구조화해서 반환, event_type 인자는 "
            "auditd 룰 key로 거른다. 로그인 세션(auth 레코드의 sshd pid)에서 실행된 명령은 그 pid의 자식이므로 "
            "pid가 아니라 ppid=<세션 pid>로 조회. user는 명령을 실행한 계정(sudo 뒤에는 root)이라 로그인 "
            "계정 이름(예: ubuntu)으로 거르면 그 세션 명령이 빠질 수 있다. 결과가 많으면 "
            "has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["event_type", "pid", "ppid", "user", "serial", "exclude_interactive", "include_user_cmd", "limit", "offset"],
        ),
        ToolSpec(
            "fetch_network_log",
            "네트워크 후속 행위(외부 통신 등)가 있었는지 조회한다 (Suricata http/alert 이벤트만 반환, "
            "alert는 signature/category/severity, http는 url/method/status까지 구조화. flow 이벤트와 "
            "전송 바이트 수는 없음. src_ip는 패킷 출발지, dst_ip는 목적지와 비교하므로 서버에서 외부로 나간 "
            "통신은 dst_ip=<외부 IP>로 조회. 방향을 모르면 ip=<IP>로 출발지·목적지 양쪽을 한 번에 조회. "
            "결과가 많으면 has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["ip", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "alert_only", "limit", "offset"],
        ),
        ToolSpec(
            "get_process_tree",
            "이 프로세스가 어디에서 실행됐는지(부모/자식 관계) 조회한다 "
            "(audit 로그의 pid/ppid 관측 기반 추정, 확정된 생성 트리 아님)",
            ["host", "pid"],
            ["timestamp", "start_time", "end_time"],
        ),
    ]

    registry = ToolRegistry()
    for spec in tool_defs:
        if spec.name in exclude_set:
            continue
        handler = handlers.get(spec.name)
        if handler is None:
            handler = _try_import_real_handler(spec.name)
        if handler is None:
            handler = MOCK_HANDLERS[spec.name]
        spec.handler = handler
        registry.register(spec)
    return registry
