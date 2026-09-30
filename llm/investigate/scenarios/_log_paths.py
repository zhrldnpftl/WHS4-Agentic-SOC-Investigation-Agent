"""시나리오 생성기들이 로그를 append할 파일 경로를 정한다.

[2026-09-24] 예전엔 생성기마다 sample_logs/sample_web.log·sample_network.log에 고정으로
썼는데, .env의 *_LOG_PATH가 다른 파일(sample_apache_web.log, sample_network_recent.log
등)을 가리키고 있으면 에이전트 도구가 시나리오 로그를 전혀 못 보는 문제가 있었다.
그래서 에이전트 도구와 똑같이 .env의 *_LOG_PATH를 우선 쓰고, 없을 때만 기본값을 쓴다.
"""

import os
from pathlib import Path

try:  # dotenv는 선택 의존성 — 없으면 이미 설정된 환경변수만 본다
    from dotenv import load_dotenv

    # 조사 에이전트(agent/settings.py load_root_env)와 같은 저장소 루트 .env를 경로로 직접 읽는다.
    # 시나리오는 `python scenarios/...py`로 실행되어 agent 패키지를 import하지 않고 경로만 같게 계산한다.
    load_dotenv(Path(__file__).resolve().parents[3] / ".env")
except ImportError:
    pass

# 에이전트 도구(agent/tools/log_source.py LOCAL_PATH_ENV)와 같은 이름 = 1차 탐지와 같은 이름
ENV_NAMES = {"web": "APACHE_LOG_PATH", "auth": "AUTH_LOG_PATH", "audit": "AUDIT_LOG_PATH", "network": "SURICATA_LOG_PATH"}

DEFAULTS = {
    "web": "sample_logs/sample_apache_web.log",
    "auth": "sample_logs/sample_auth.log",
    "audit": "sample_logs/sample_audit.log",
    "network": "sample_logs/sample_network.log",
}


def log_path(layer: str) -> str:
    return os.environ.get(ENV_NAMES[layer]) or DEFAULTS[layer]
