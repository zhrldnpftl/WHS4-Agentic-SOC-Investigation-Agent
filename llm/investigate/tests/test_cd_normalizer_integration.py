"""Merge regression checks: C/D uses A/B's unchanged primary normalizers."""
import gzip
import os
import sys
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.real.fetch_event_logs import fetch_event_logs
from tests.test_event_window import WINDOW, local_log, query

from agent.tools.normalizer_adapter import DETECTION_PIPELINE_DIR

SAMPLES = DETECTION_PIPELINE_DIR / "samples"


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in [*LOCAL_PATH_ENV.values(), "HOST", "LOG_LOCAL_HOST", "AUTH_LOG_YEAR"]:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("layer,module,sample", [
    ("web", "fetch_apache_log", "sample_access.log"),
    ("auth", "fetch_auth_log", "sample_auth.log"),
    ("audit", "fetch_audit_log", "sample_audit.log"),
    ("network", "fetch_network_log", "sample_eve.json"),
])
def test_all_vendor_fields_and_refs_match_query_and_tools(monkeypatch, layer, module, sample):
    source = SAMPLES / sample
    monkeypatch.setenv(LOCAL_PATH_ENV[layer], str(source))
    monkeypatch.setenv("AUTH_LOG_YEAR", "2026")
    vendor = getattr(import_module(f"tools.{module}"), module)
    assert Path(vendor.__code__.co_filename).resolve().parent == DETECTION_PIPELINE_DIR / "tools"
    window = ["2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z"]
    expected = vendor(str(source), time_window=window)
    assert expected
    fetched = fetch_event_logs({"host": "web-01", "window": window, "layers": [layer]})["records"]
    from agent.tools import build_default_registry
    registry = build_default_registry()
    tool_name = f"fetch_{layer}_log"
    assert registry.get(tool_name).handler.__module__ == f"agent.tools.real.{tool_name}"
    individual = registry.call(tool_name, {"host": "web-01", "start_time": window[0],
                                           "end_time": window[1], "limit": 10000})["records"]

    def key(event):
        return event["timestamp"], event["raw_ref"]

    expected = [{**{k: v for k, v in e.items() if k != "layer_data"}, **e["layer_data"]} for e in expected]
    for actual in (fetched, individual):
        stripped = [{k: v for k, v in e.items() if k not in ("raw_refs", "raw_ref_locations", "_source_type")} for e in actual]
        assert sorted(stripped, key=key) == sorted(expected, key=key)
        for event in actual:
            assert event["raw_ref"] in event["raw_refs"]
            assert set(event["raw_refs"]) == set(event["raw_ref_locations"])
            assert all(location.startswith(source.as_posix() + ":")
                       for locations in event["raw_ref_locations"].values() for location in locations)


ROOT_DOTENV_VALUES = {"SERVER_PUBLIC_IP": "9.9.9.9", "SURICATA_SENSOR_ID": "root_sensor",
                      "AUTH_LOG_YEAR": "2026", "ANTHROPIC_API_KEY": "root-dummy"}


def test_adapter_import_does_not_load_root_dotenv(tmp_path):
    """1차 탐지 원본의 import 시점 load_dotenv()가 루트 .env 값을 채우지 못해야 한다.

    원본은 load_dotenv()를 자기 파일 위치 기준으로 불러 저장소 루트 .env를 읽는다. 가짜 dotenv 모듈의
    load_dotenv()가 "루트 .env를 읽은 것처럼" 값을 넣게 하고, 어댑터 import 뒤 환경변수와 import 시점에
    고정되는 모듈 값(SERVER_PUBLIC_IP, normalize_row의 sensor_id 기본값)을 새 프로세스에서 확인한다.
    """
    import json
    import subprocess

    fake = tmp_path / "dotenv"
    fake.mkdir()
    (fake / "__init__.py").write_text(
        "import os\n"
        f"VALUES = {ROOT_DOTENV_VALUES!r}\n"
        "def load_dotenv(*args, **kwargs):\n"
        "    os.environ.update(VALUES)\n"
        "    return True\n", encoding="utf-8")
    probe = (
        "import inspect, json, os, dotenv\n"
        "from agent.tools import normalizer_adapter as na\n"
        "import tools.fetch_network_log as fn\n"
        f"keys = {sorted(ROOT_DOTENV_VALUES)!r}\n"
        "leaked = {k: os.environ[k] for k in keys if k in os.environ}\n"
        "sensor = inspect.signature(fn.normalize_row).parameters['sensor_id'].default\n"
        "dotenv.load_dotenv()\n"  # import가 끝나면 load_dotenv는 원래대로 돌아와야 한다
        "print(json.dumps({'leaked': leaked, 'server_public_ip': na.server_public_ip(), 'sensor': sensor,\n"
        "                  'restored': os.environ.get('SERVER_PUBLIC_IP')}))\n"
    )
    env = {k: v for k, v in os.environ.items() if k not in ROOT_DOTENV_VALUES}
    env["PYTHONPATH"] = str(tmp_path)
    completed = subprocess.run([sys.executable, "-c", probe], cwd=Path(__file__).resolve().parents[1],
                               env=env, capture_output=True, text=True, check=True)
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["leaked"] == {}
    assert result["server_public_ip"] != ROOT_DOTENV_VALUES["SERVER_PUBLIC_IP"]
    assert result["sensor"] != ROOT_DOTENV_VALUES["SURICATA_SENSOR_ID"]
    assert result["restored"] == ROOT_DOTENV_VALUES["SERVER_PUBLIC_IP"]


def test_original_ab_adapter_parity_check():
    # The upstream parity script is not discovered by pytest (_run instead of test_*).
    from tests.test_normalizer_parity import _run
    with patch.dict(os.environ):
        _run()


def test_gzip_auth_original_name_and_location(tmp_path, monkeypatch):
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write("\nSep 21 00:00:00 web-01 sshd[1]: Accepted password for root from 192.0.2.10 port 22 ssh2\n")
    monkeypatch.setenv("AUTH_LOG_PATH", str(path))
    record = query(layers=["auth"])["records"][0]
    assert record["raw_ref"] == "auth.log.1:2"
    assert record["raw_ref_locations"] == {"auth.log.1:2": [path.as_posix() + ":2"]}


def test_raw_ref_locations_survive_final_report(tmp_path, monkeypatch):
    from agent.loop import InvestigationAgent
    from agent.tools.registry import build_default_registry
    from tests.test_event_window import web_line
    from tests.test_provenance import ScriptedInvestigator, evidence, terminate
    ref = local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0])) + ":1"
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {"layers": ["web"]}}},
        terminate([evidence(raw_ref=ref)]),
    ])
    result = InvestigationAgent(llm, build_default_registry()).run({
        "incident_id": "LOCATIONS", "host": "web-01", "window": WINDOW})
    assert result["raw_ref_locations"] == {ref: [(tmp_path / "web.log").as_posix() + ":1"]}
    assert result["provenance"]["status"] == "passed"


def test_same_basename_refs_from_different_sources_are_reported_as_ambiguous():
    from agent.loop import InvestigationAgent
    from agent.models import AgentState
    from agent.provenance import provenance_report
    from agent.tools.registry import ToolRegistry
    state = AgentState(incident_id="AMBIGUOUS", seed={}, raw_refs=["same.log:1"])
    state.raw_ref_locations = {"same.log:1": ["/a/same.log:1", "/b/same.log:1"]}
    InvestigationAgent(None, ToolRegistry())._apply_decision(state, {"new_evidence": [{
        "raw_refs": ["same.log:1"], "confidence_contribution": 0.3}]})
    assert state.current_confidence == 0
    report = provenance_report(state)
    assert report["status"] == "incomplete" and "same.log:1" in report["ambiguous_raw_refs"]
