"""1차 탐지팀 공통 정규화 어댑터 — 조사 에이전트 코드와 1차 탐지 정규화 코드 사이의 유일한 연결 지점.

역할
  원본 로그 텍스트를 임시 파일로 써서 1차 탐지팀 정규화 함수(fetch_apache_log/fetch_auth_log/
  fetch_audit_log/fetch_network_log)에 그대로 넘기고, 결과 이벤트에 원본 추적 정보를 붙인다.
    - raw_ref: 1차 탐지와 같은 "<파일명>:<줄 번호>" (예: auth.log:9190)
    - raw_refs: audit처럼 여러 줄이 한 이벤트면 그 줄 전부
    - raw_ref_locations: 실제 전체 경로
  "같은 raw 로그에 대해 1차 탐지와 조사 도구가 같은 정규화 결과를 낸다"가 완료 기준이라,
  이 파일은 파싱 로직을 갖지 않는다. 1차 탐지팀 코드는 수정하지 않는다.

누가 부르나
  [34] agent/tools/log_source.py normalize_documents()   → normalize_log_documents()
  [33] agent/tools/log_source.py read_documents()        → resolve_log_files()
  agent/tools/real/fetch_web_log.py (exclude_self)       → server_public_ip()
  tests/test_normalizer_parity.py, scripts/verify_all_tools.py → normalize_auth/audit/web/network()

무엇을 부르나
  같은 저장소의 1차 탐지 원본 detection_pipeline/tools/fetch_apache_log.py, fetch_auth_log.py,
  fetch_audit_log.py, fetch_network_log.py (복사본 없이 직접 import, 1차 탐지팀 코드라 수정하지 않는다)
  detection_pipeline/tools/log_sources.py resolve_log_files() — 교체된 로그(base.1, base.N.gz) 찾기

주의 — 이름만 같고 다른 코드
  agent/tools/real/fetch_web_log.py·fetch_auth_log.py·fetch_audit_log.py·fetch_network_log.py는
  LLM이 부르는 "조사 도구"(필터·페이지네이션·summary·rule_checks)이고, detection_pipeline/tools/의
  fetch_*_log()는 원본 로그를 공통 Event로 바꾸는 "1차 탐지 정규화 함수"다. 이름이 같을 뿐 서로 다른
  코드다. 조사 도구는 이 어댑터를 거쳐 정규화 함수를 부를 뿐, 정규화 함수로 대체되지 않는다.
  조사 도구 레지스트리(agent/tools/registry.py)는 agent.tools.real.<도구이름>을 상대 import로 찾으므로
  여기서 올리는 최상위 이름 tools.*와 섞이지 않는다.

import 방식
  1차 탐지 코드는 내부에서 `from tools.base ...`, `from common.schema ...`처럼 최상위 이름으로 import한다.
  그래서 detection_pipeline/ 폴더를 sys.path에 올린 뒤 `tools.fetch_*_log`로 가져온다. 경로는 실행
  폴더(cwd)가 아니라 이 파일 위치 기준이다(run_investigation_queue.py가 main.py를 별도 프로세스로
  실행해도 같다). 폴더가 없거나 최상위 이름 tools가 다른 모듈을 가리키면 목업으로 넘어가지 않고
  ImportError를 낸다.

.env 격리
  1차 탐지 원본(fetch_apache_log/fetch_auth_log/fetch_network_log)은 import될 때 load_dotenv()를 부른다.
  python-dotenv는 인자가 없으면 "부른 파일 위치"부터 위로 .env를 찾으므로 저장소 루트 .env(1차 탐지 설정)를
  읽게 되고, 조사 쪽 .env(main.py가 먼저 읽음)에 없는 키(AUTH_LOG_YEAR, ANTHROPIC_API_KEY 등)를 조용히
  채운다. 또 SERVER_PUBLIC_IP, SURICATA_SENSOR_ID(함수 기본 인자로 고정됨)처럼 import 시점에 모듈 변수로
  저장되는 값은 import 뒤에 환경변수를 지워도 루트 값으로 남는다. 그래서 import하는 동안에는 원본의
  load_dotenv()를 아무것도 하지 않게 막고(_without_detection_dotenv), 그래도 새로 생긴 환경변수가 있으면
  되돌린다. .env는 진입점(main.py, scripts/verify_all_tools.py 등)이 스스로 읽는다.

참고
  - web은 nginx가 아니라 apache access.log를 쓴다. EC2에서 nginx(리버스 프록시)와 apache(백엔드,
    127.0.0.1:8080)가 같이 떠 있고, apache 로그가 1차 탐지팀 형식과 컬럼 단위로 일치했다.
  - network(suricata) 정규화 함수는 src_ip/event_type/flow_id/signature만 필터로 지원해서, dst_ip·포트·
    프로토콜 필터는 agent/tools/real/fetch_network_log.py가 결과를 받은 뒤 거른다.
  - 로그는 .env의 계층별 로그 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH) 파일과 그 교체 파일에서만 읽는다
    (S3 읽기는 삭제). 교체 파일을 고르는 규칙은 1차 탐지와 같다(resolve_log_files).
"""
from __future__ import annotations

import importlib
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

# llm/investigate/agent/tools/normalizer_adapter.py → 저장소 루트/detection_pipeline
DETECTION_PIPELINE_DIR = Path(__file__).resolve().parents[4] / "detection_pipeline"
DETECTION_TOOLS_DIR = DETECTION_PIPELINE_DIR / "tools"


def _load_detection_module(name: str):
    """detection_pipeline/tools/<name>.py를 최상위 이름 tools.<name>으로 가져온다."""
    if not (DETECTION_TOOLS_DIR / f"{name}.py").is_file():
        raise ImportError(
            f"1차 탐지 정규화 코드를 찾을 수 없습니다: {DETECTION_TOOLS_DIR / (name + '.py')} "
            "(조사 에이전트는 같은 저장소의 detection_pipeline/tools/를 직접 import한다 — "
            "llm/investigate/만 따로 복사해 실행하지 않았는지 확인하십시오)"
        )
    if str(DETECTION_PIPELINE_DIR) not in sys.path:
        sys.path.insert(0, str(DETECTION_PIPELINE_DIR))
    try:
        module = importlib.import_module(f"tools.{name}")
    except ModuleNotFoundError as exc:
        # registry.py는 ModuleNotFoundError를 "실제 구현 없음"으로 보고 목업으로 폴백하므로
        # 일반 ImportError로 바꿔 조사 도구 로드가 실패했음을 드러낸다.
        raise ImportError(f"1차 탐지 정규화 코드 tools.{name} import 실패: {exc}") from exc
    loaded_from = Path(module.__file__).resolve().parent
    if loaded_from != DETECTION_TOOLS_DIR:
        raise ImportError(
            f"최상위 이름 tools.{name}이 1차 탐지 원본이 아닌 {loaded_from}에서 로드되었습니다 "
            f"(기대: {DETECTION_TOOLS_DIR}). 다른 tools 패키지가 먼저 import되었거나 sys.path 앞에 있습니다."
        )
    return module


@contextmanager
def _without_detection_dotenv():
    """1차 탐지 원본을 import하는 동안 그 안의 load_dotenv()가 루트 .env를 읽지 못하게 한다(모듈 docstring 참조)."""
    try:
        import dotenv
    except ImportError:  # dotenv가 없으면 원본도 load_dotenv를 건너뛴다
        dotenv = None
    original = dotenv.load_dotenv if dotenv else None
    before = set(os.environ)
    if dotenv:
        # 원본은 import 중에 `from dotenv import load_dotenv`로 가져가므로 그동안만 바꿔 둔다
        dotenv.load_dotenv = lambda *args, **kwargs: False
    try:
        yield
    finally:
        if dotenv:
            dotenv.load_dotenv = original
        for key in set(os.environ) - before:  # 그래도 import 중에 새로 생긴 환경변수는 되돌린다
            del os.environ[key]


with _without_detection_dotenv():
    _apache_module = _load_detection_module("fetch_apache_log")
    _normalize_web_events = _apache_module.fetch_apache_log
    _normalize_auth_events = _load_detection_module("fetch_auth_log").fetch_auth_log
    _normalize_audit_events = _load_detection_module("fetch_audit_log").fetch_audit_log
    _normalize_network_events = _load_detection_module("fetch_network_log").fetch_network_log
    _resolve_log_files = _load_detection_module("log_sources").resolve_log_files


def resolve_log_files(base_path: str, since_dt=None) -> List[str]:
    """1차 탐지 resolve_log_files() 그대로 — base_path와 교체 파일 중 since_dt 이후 수정된 것을 오래된 순으로."""
    return _resolve_log_files(base_path, since_dt=since_dt)


def server_public_ip() -> str:
    """1차 탐지 fetch_apache_log의 SERVER_PUBLIC_IP(서버 자신의 공인 IP) — exclude_self 필터용."""
    return _apache_module.SERVER_PUBLIC_IP


# [34] ← log_source.normalize_documents()에서 호출: 원본 텍스트 → 1차 탐지팀 정규화 → 원본 추적 정보 부착
def normalize_log_documents(layer, documents, start, end):
    """C/D source adapter: call the primary-detection normalizers without changing them.

    Preserve local raw_ref values (basename:line). raw_ref_locations adds the
    absolute file location without replacing the basename references used by primary
    detection. Several documents are concatenated into one staging file and each
    line is mapped back to its own document.
    """
    documents = list(documents)
    if not documents:
        return []
    lines, locations = [], []
    for source, text in documents:
        physical_lines = text.split("\n")
        if physical_lines and physical_lines[-1] == "":
            physical_lines.pop()
        lines.extend(physical_lines)
        locations.extend(f"{source}:{number}" for number in range(1, len(physical_lines) + 1))

    local = len(documents) == 1
    name = Path(documents[0][0]).name.removesuffix(".gz") if local else "source.log"
    functions = {"web": _normalize_web_events, "auth": _normalize_auth_events,
                 "audit": _normalize_audit_events, "network": _normalize_network_events}
    kwargs = {}
    with tempfile.TemporaryDirectory(prefix="soc-normalize-") as staging:
        directory = Path(staging)
        if layer == "auth":
            # Let the primary-detection normalizer interpret yearless syslog using its existing dt/year
            # contract. Narrow incident windows must not depend on today's year.
            partition = re.search(r"(?:^|/)dt=(\d{4}-\d{2}-\d{2})(?:/|$)", documents[0][0])
            if partition:
                directory /= "dt=" + partition.group(1)
            elif not os.environ.get("AUTH_LOG_YEAR"):
                if start.year == end.year:
                    kwargs["year"] = start.year
                elif (end - start).days < 180:
                    directory /= "dt=" + end.date().isoformat()
            directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        events = functions[layer](str(path), **kwargs)

    for event in events:
        prefix, first_line = event["raw_ref"].rsplit(":", 1)
        numbers = event.get("layer_data", {}).get("raw_lines") or [int(first_line)]
        sources = [locations[number - 1] for number in numbers]
        refs = [f"{prefix}:{number}" for number in numbers] if local else sources
        event["raw_ref"] = refs[0]
        event["raw_refs"] = list(dict.fromkeys(refs))
        event["raw_ref_locations"] = {ref: [source] for ref, source in zip(refs, sources)}
    return events


def _local_path(env_name: str) -> str:
    path = os.environ.get(env_name)
    if not path:
        raise ValueError(f"{env_name}가 설정되지 않았습니다 (.env에 로그 파일 경로 필요)")
    return path


# 아래 normalize_* 4개는 계층별로 1차 탐지팀 함수를 필터 인자와 함께 직접 부르는 예전 진입점이다.
# 조사 도구는 normalize_log_documents()를 쓰고, 이 함수들은 정규화 동일성 검증
# (tests/test_normalizer_parity.py)과 scripts/verify_all_tools.py만 쓴다. 로컬 파일을 그대로
# 넘기므로 raw_ref가 실제 로그 파일 이름을 가리킨다.


def normalize_auth(
    host: str,
    start_time: str,
    end_time: str,
    *,
    user: Optional[str] = None,
    src_ip: Optional[str] = None,
    event: Optional[str] = None,
    result: Optional[str] = None,
    year: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_auth_log()를 그대로 호출 — 공통스키마(layer=auth) 이벤트 리스트 반환.

    time_window/user/src_ip/event/result/year 는 1차 탐지팀 fetch_auth_log()의 필터를
    그대로 전달한다(이름·의미 동일, 새로 정의하지 않음).
    """
    return _normalize_auth_events(
        _local_path("AUTH_LOG_PATH"), time_window=[start_time, end_time],
        user=user, src_ip=src_ip, event=event, result=result, year=year,
    )


def normalize_audit(
    host: str,
    start_time: str,
    end_time: str,
    *,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    key: Optional[str] = None,
    session_type: Optional[str] = None,
    exclude_interactive: bool = False,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_audit_log()를 그대로 호출 — 공통스키마(layer=system) 이벤트 리스트 반환."""
    return _normalize_audit_events(
        _local_path("AUDIT_LOG_PATH"), time_window=[start_time, end_time],
        pid=pid, ppid=ppid, key=key, session_type=session_type,
        exclude_interactive=exclude_interactive,
    )


def normalize_web(
    host: str,
    start_time: str,
    end_time: str,
    *,
    src_ip: Optional[str] = None,
    path_pattern: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    exclude_self: bool = False,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_apache_log()를 그대로 호출 — 공통스키마(layer=web) 이벤트 리스트 반환.

    APACHE_LOG_PATH는 apache의 access.log를 가리켜야 한다(nginx JSON 아님).
    time_window/src_ip/path_pattern/status/method/exclude_self 는 1차 탐지팀
    fetch_apache_log()의 필터를 그대로 전달한다.
    """
    return _normalize_web_events(
        _local_path("APACHE_LOG_PATH"), time_window=[start_time, end_time],
        src_ip=src_ip, path_pattern=path_pattern, status=status,
        method=method, exclude_self=exclude_self,
    )


def normalize_network(
    host: str,
    start_time: str,
    end_time: str,
    *,
    src_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    flow_id: Optional[int] = None,
    signature: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_network_log()를 그대로 호출 — 공통스키마(layer=network) 이벤트 리스트 반환.

    SURICATA_LOG_PATH는 Suricata eve.json(JSONL)을 가리킨다. time_window/src_ip/
    event_type(http|alert)/flow_id/signature 는 1차 탐지팀 fetch_network_log()의 필터를
    그대로 전달한다. dst_ip 등 이 함수가 지원하지 않는 필터는 호출부에서 후처리로 거른다.
    """
    return _normalize_network_events(
        _local_path("SURICATA_LOG_PATH"), time_window=[start_time, end_time],
        src_ip=src_ip, event_type=event_type, flow_id=flow_id, signature=signature,
    )
