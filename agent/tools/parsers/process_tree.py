"""audit 이벤트(pid/ppid)로 프로세스 조상 체인을 추적한다.

팀원이 만든 get_process_tree.py(독립 배포용)는 raw audit 텍스트를 또 한 번
자체 정규식으로 파싱했는데, 우리는 이미 agent/tools/parsers/audit_parser.py의
parse_audit_events()가 pid/ppid/exe/user/timestamp까지 구조화해서 뽑아주므로
그 결과를 그대로 재사용한다 — audit 파싱 코드를 두 번 만들지 않기 위함이다.

*** 원본 대비 단순화한 것 ***
원본은 boot_id/scope(재부팅 경계) 구분, PID 재사용 방지, 동시 확보된 여러
후보 중 모호성 처리까지 정교하게 했다. 우리는 "가장 최근 관측된 그 pid의
부모를 시간 역순으로 따라간다"는 단순한 버전만 구현한다 — 이 정도로도 조사
목적(웹셸이 어떤 프로세스에서 실행됐는지 등)엔 충분하고, boot_id 같은 정보는
우리 audit_parser.py의 공통스키마에 애초에 없다. 원본처럼 "이건 확정된 프로세스
생성 트리가 아니라 관측 기반 후보"라는 한계는 동일하게 명시한다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

MAX_ANCESTORS = 32


def build_ancestry_chain(
    events: List[Dict[str, Any]],
    target_pid: int,
    max_ancestors: int = MAX_ANCESTORS,
) -> Optional[Dict[str, Any]]:
    """audit_parser.parse_audit_events()가 반환한 이벤트 리스트에서, target_pid의
    조상 체인(부모 -> 조부모 -> ...)을 시간 역순으로 추적한다.

    이벤트가 이미 timestamp 오름차순 정렬돼 있다고 가정한다(parse_audit_events가
    그렇게 반환함). target_pid가 하나도 관측 안 됐으면 None을 반환한다.
    """
    # pid별로 관측된 이벤트들을 시간순으로 모아둔다 (부모 찾을 때 "그 시점 이전의
    # 가장 최근 관측"을 써야 하므로).
    by_pid: Dict[int, List[Dict[str, Any]]] = {}
    for e in events:
        pid = e.get("pid")
        if pid is not None:
            by_pid.setdefault(pid, []).append(e)

    target_events = by_pid.get(target_pid)
    if not target_events:
        return None

    # target_pid의 가장 최근 관측을 시작점으로 삼는다.
    leaf = target_events[-1]

    chain: List[Dict[str, Any]] = [leaf]
    visited_pids = {target_pid}
    warnings: List[str] = [
        "PID_REUSE_NOT_RESOLVED",
        "관측된 syscall 기반 추정이며 실시간 프로세스 목록이 아님",
    ]
    stop_reason = "parent_pid_zero"

    current = leaf
    while True:
        ppid = current.get("ppid")
        if ppid is None or ppid == 0:
            stop_reason = "parent_pid_zero"
            break
        if ppid in visited_pids:
            stop_reason = "cycle_detected"
            warnings.append("PID_CYCLE_DETECTED")
            break
        if len(chain) >= max_ancestors:
            stop_reason = "depth_limit"
            warnings.append("ANCESTOR_DEPTH_LIMIT")
            break

        parent_events = by_pid.get(ppid)
        if not parent_events:
            stop_reason = "parent_not_observed"
            warnings.append("PARENT_NOT_OBSERVED_IN_LOG_WINDOW")
            break

        # 현재 노드 시점보다 이전(또는 같은) 시점의 가장 최근 관측을 부모로 삼는다.
        candidates = [p for p in parent_events if (p.get("timestamp") or "") <= (current.get("timestamp") or "")]
        parent = candidates[-1] if candidates else parent_events[0]

        chain.append(parent)
        visited_pids.add(ppid)
        current = parent

    return {
        "target_pid": target_pid,
        "chain": " -> ".join(f"{n.get('exe') or n.get('comm')}({n.get('pid')})" for n in chain),
        "nodes": [
            {
                "pid": n.get("pid"),
                "ppid": n.get("ppid"),
                "timestamp": n.get("timestamp"),
                "exe": n.get("exe"),
                "comm": n.get("comm"),
                "user": n.get("user"),
                "syscall": n.get("syscall"),
                "session_type": n.get("session_type"),
                "raw_ref": n.get("raw_ref"),
            }
            for n in chain
        ],
        "lineage_status": "inferred" if stop_reason == "parent_pid_zero" else "partial",
        "stop_reason": stop_reason,
        "warnings": warnings,
    }