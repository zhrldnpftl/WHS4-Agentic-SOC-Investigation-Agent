"""EC2에서 SSH로 직접 샘플 로그를 받아오는 개발용 편의 스크립트.

*** 이건 프로덕션 코드가 아니다 ***
팀이 확정한 아키텍처는 "EC2 -> S3 -> 조사 에이전트"이고, 조사 에이전트가 운영 서버에
직접 SSH로 붙는 것은 의도된 설계가 아니다 (운영 서버 부하, 여러 서버 관리 복잡성,
SSH 키 노출 범위 확대 때문에 팀이 S3 방식으로 결정했음 — README 참고).

이 스크립트는 그것과 무관하게, AWS access key가 아직 없는 지금 상태에서
scripts/local_e2e_test.py에 넣을 "신선한 샘플 로그"를 매번 수동으로
(ssh 접속 -> sudo tail -> exit -> scp) 네 단계 거치지 않고 한 번에 받기 위한
개발자 편의 도구일 뿐이다. S3 access key가 나오면 이 스크립트는 더 이상 필요 없다.

사용법:
    python scripts/fetch_sample_from_ec2.py                      # audit만 (기존과 동일)
    python scripts/fetch_sample_from_ec2.py --all                # 4계층 전부
    python scripts/fetch_sample_from_ec2.py --lines 1000 --output my_sample.log

전제:
- ssh/scp가 실행 가능한 환경(주로 WSL)에서 실행해야 한다. Windows PowerShell에서
  돌리면 ssh 키 경로가 안 맞아서 실패할 수 있다 (지난번 겪은 문제와 동일).
- ubuntu 계정이 각 로그 파일 읽기용 sudo를 비밀번호 없이 쓸 수 있어야 한다
  (AWS 기본 ubuntu AMI는 보통 이렇게 설정돼 있음). 안 되면 -t 옵션 필요할 수 있음.
- --all의 기본 경로(nginx/auth.log/suricata)는 Ubuntu 기본값 + 팀 아키텍처 확인 결과다.
  실제 서버가 다르면 SSH 접속해서 `ls /var/log/apache2/ /var/log/nginx/
  /var/log/suricata/ /var/log/auth.log*`로 확인 후 --web-path 등으로 바꿔주면 된다.
  web은 nginx(리버스 프록시, 앞단이라 실제 클라이언트 IP가 찍힘)를 기본으로 썼다 —
  apache는 nginx 뒤에 있어서 src_ip가 항상 loopback(127.0.0.1)로만 찍혀 공격자 IP를
  알 수 없다 (팀 결정사항: Suricata 조인 키로 src_ip 대신 http.xff를 쓰는 것도 같은 이유).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict, Optional, Tuple


def fetch_sample_via_ssh(
    host: str,
    user: str,
    key_path: str,
    remote_log_path: str,
    lines: int,
    output_path: str,
) -> Optional[str]:
    """ssh로 원격 명령(sudo tail -n N <파일>)을 실행해 결과를 로컬 파일로 저장한다.
    scp로 파일을 통째로 옮기지 않고, ssh 파이프로 필요한 줄 수만 바로 받는다.
    실패하면(경로가 없거나 등) None을 반환한다 — --all 모드에서 하나 실패해도
    나머지는 계속 받기 위함.
    """
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        print(f"[에러] SSH 키를 찾을 수 없습니다: {key_path}")
        print("WSL에서 실행 중인지, 키 경로가 맞는지 확인하세요.")
        sys.exit(1)

    remote_command = f"sudo tail -n {lines} {remote_log_path}"
    ssh_cmd = ["ssh", "-i", key_path, f"{user}@{host}", remote_command]

    print(f"[실행] {' '.join(ssh_cmd)}")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[건너뜀] {remote_log_path} 못 받음: {result.stderr.strip()}")
        return None

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    line_count = len(result.stdout.splitlines())
    print(f"[완료] {output_path}에 {line_count}줄 저장됨")
    return output_path


def fetch_all_layers(
    host: str,
    user: str,
    key_path: str,
    lines: int,
    web_path: str,
    auth_path: str,
    audit_path: str,
    network_path: str,
) -> Dict[str, str]:
    """4계층(web/auth/audit/network) 샘플을 한 번에 받는다.
    반환값: {"web": "sample_web.log", ...} — 실제로 받아진 것만 포함.
    """
    layers: Tuple[Tuple[str, str, str], ...] = (
        ("web", web_path, "sample_web.log"),
        ("auth", auth_path, "sample_auth.log"),
        ("audit", audit_path, "sample_audit.log"),
        ("network", network_path, "sample_network.log"),
    )

    fetched: Dict[str, str] = {}
    for name, remote_path, output_path in layers:
        result = fetch_sample_via_ssh(host, user, key_path, remote_path, lines, output_path)
        if result:
            fetched[name] = result

    print(f"\n[요약] {len(fetched)}/4개 계층 수집 성공: {list(fetched.keys())}")
    missing = {n for n, _, _ in layers} - set(fetched.keys())
    if missing:
        print(f"[안내] 못 받은 계층: {missing} — 경로가 실제 서버와 다를 수 있습니다. SSH로 확인 후 --{list(missing)[0]}-path로 재시도하세요.")
    return fetched


def main() -> None:
    parser = argparse.ArgumentParser(description="EC2에서 샘플 로그를 SSH로 직접 받아온다 (개발용)")
    parser.add_argument("--host", default=os.environ.get("EC2_HOST", "ogwanwan.shop"))
    parser.add_argument("--user", default=os.environ.get("EC2_USER", "ubuntu"))
    parser.add_argument("--key", default=os.environ.get("EC2_SSH_KEY", "~/.ssh/agentic-soc"))
    parser.add_argument("--lines", type=int, default=500)
    parser.add_argument("--all", action="store_true", help="web/auth/audit/network 4계층 전부 받기")
    # --all 모드 전용 경로 (Ubuntu 기본값 추정 — 실제 서버 확인 후 필요시 조정)
    parser.add_argument("--web-path", default="/var/log/nginx/access.log")
    parser.add_argument("--auth-path", default="/var/log/auth.log")
    parser.add_argument("--network-path", default="/var/log/suricata/eve.json")
    # --all 아닐 때(단일 파일) 전용
    parser.add_argument("--remote-path", default="/var/log/audit/audit.log")
    parser.add_argument("--output", default="sample_audit.log")
    args = parser.parse_args()

    if args.all:
        fetch_all_layers(
            host=args.host,
            user=args.user,
            key_path=args.key,
            lines=args.lines,
            web_path=args.web_path,
            auth_path=args.auth_path,
            audit_path=args.remote_path,
            network_path=args.network_path,
        )
    else:
        fetch_sample_via_ssh(
            host=args.host,
            user=args.user,
            key_path=args.key,
            remote_log_path=args.remote_path,
            lines=args.lines,
            output_path=args.output,
        )


if __name__ == "__main__":
    main()