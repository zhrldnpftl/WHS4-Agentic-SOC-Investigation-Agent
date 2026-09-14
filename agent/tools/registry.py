"""Tool 연결·실행 계층 담당 모듈 (agent/tools/registry.py).

Tool registry/schema를 정의하고, Agent(LLM)가 선택한 도구를 실제로 실행하며,
인자를 검증하고 반환값을 Agent에 전달하는 역할을 한다.

실제 로그 조회 로직(fetch_web_log 등)은 다른 팀원들이 구현한다. 우선순위는:
  1. build_default_registry(handlers={...})로 명시적으로 넘긴 함수
  2. agent/tools/real/<도구이름>.py 안의 동일한 이름의 함수 (자동 탐색)
  3. mock_tools.py의 목업 (위 둘 다 없을 때 폴백)

즉 팀원은 build_default_registry() 호출부를 건드릴 필요 없이,
자기가 맡은 도구 이름과 똑같은 파일을 agent/tools/real/ 안에 넣기만 하면
자동으로 실제 구현이 쓰이게 된다. (agent/tools/real/README.md 참고)
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

    def validate_args(self, name: str, args: Dict[str, Any]) -> None:
        spec = self.get(name)
        missing = [a for a in spec.required_args if a not in args]
        if missing:
            raise ToolValidationError(f"{name} 호출에 필수 인자가 없습니다: {missing}")
        allowed = set(spec.required_args) | set(spec.optional_args)
        unknown = [a for a in args if a not in allowed]
        if unknown:
            raise ToolValidationError(f"{name} 호출에 알 수 없는 인자가 있습니다: {unknown}")

    def call(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        spec = self.get(name)
        self.validate_args(name, args)
        if spec.handler is None:
            raise NotImplementedError(f"{name}의 handler가 아직 연결되지 않았습니다.")
        return spec.handler(args)


def build_default_registry(
    handlers: Optional[Dict[str, ToolHandler]] = None,
    exclude: Optional[List[str]] = None,
) -> ToolRegistry:
    """기본 6개 조사 도구를 등록한 레지스트리를 생성한다.

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
            "fetch_web_log",
            "어떤 웹 요청이 있었는지 조회한다",
            ["host", "start_time", "end_time"],
            ["path", "src_ip", "method"],
        ),
        ToolSpec(
            "fetch_auth_log",
            "로그인·권한상승 흔적이 있었는지 조회한다 (ssh_login/sudo/pam 이벤트로 "
            "구조화, 결과가 많으면 has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["user", "src_ip", "event_type", "result", "limit", "offset"],
        ),
        ToolSpec(
            "fetch_audit_log",
            "파일 생성·변조·명령 실행이 있었는지 조회한다 "
            "(uid/euid/session_type/exec_args/target_file까지 구조화해서 반환)",
            ["host", "start_time", "end_time"],
            ["event_type", "pid", "ppid", "user", "serial", "exclude_interactive"],
        ),
        ToolSpec(
            "fetch_network_log",
            "네트워크 후속 행위(외부 통신 등)가 있었는지 조회한다 (alert_signature/"
            "protocol까지 구조화, 결과가 많으면 has_more/next_offset으로 이어서 조회 가능)",
            ["host", "start_time", "end_time"],
            ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "alert_only", "limit", "offset"],
        ),
        ToolSpec(
            "get_process_tree",
            "이 프로세스가 어디에서 실행됐는지(부모/자식 관계) 조회한다 "
            "(audit 로그의 pid/ppid 관측 기반 추정, 확정된 생성 트리 아님)",
            ["host", "pid"],
            ["timestamp", "start_time", "end_time"],
        ),
        ToolSpec(
            "resolve_ip_geo",
            "IP의 국가/평판 정보를 조회한다",
            ["ip"],
            [],
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