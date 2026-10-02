"""
triage/llm_review.py — 트리아지 뒷단(LLM): 상위 Incident 를 경량 LLM(Claude Haiku)으로 재검토

트리아지는 2단이다: 앞단=결정론 점수(triage.py), 뒷단=LLM 재검토(이 파일). 파이프라인 기본 경로다.
앞단이 상위(P1~P2)로 올린 사건만 한 번의 호출로 Claude Haiku 에 보내
{investigate: bool, reason: 한 줄} 를 받아 각 Incident 에 llm_investigate·llm_reason 로 붙인다.
점수·정렬·priority 는 건드리지 않는다 — 결정론 라우팅이 진실원이고, LLM 은 "왜 봐야 하나" 한 줄과
의견만 얹는다(재현성 유지, 하류 조사 에이전트가 근거를 읽게).

안전장치(옵션 아님, 에러 처리): API 키 없거나 호출/파싱 실패 → 한 줄 알리고 결정론
결과만 그대로 통과. 파이프라인은 절대 안 죽는다.

설정(저장소 루트 .env, 역할 접두어 TRIAGE_ — 조사 에이전트 INVESTIGATION_, ATT&CK 매핑 MAPPING_과 같은 규칙):
  TRIAGE_CLAUDE_MODEL        모델. 없거나 비우면 claude-haiku-4-5(예전 고정값 그대로)
  TRIAGE_ANTHROPIC_API_KEY   트리아지 전용 키. 없거나 비우면 공용 ANTHROPIC_API_KEY
  .env 에 아무것도 안 넣으면 예전과 똑같이 동작한다. 키 값은 보지도 출력하지도 않는다(이름만 고른다).
"""
import json
import os

try:  # dotenv 선택 의존성 — 다른 도구 모듈과 같은 컨벤션
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

DEFAULT_MODEL = "claude-haiku-4-5"   # 경량 모델 (ATT&CK 매핑과 같은 등급)
API_KEY_ENV_NAMES = ("TRIAGE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")   # 앞에서부터 값이 있는 첫 이름
MAX_REVIEW = 20                      # 한 번에 검토할 상위 사건 수 상한(토큰·비용 방어)
REVIEW_PRIORITIES = ("P1", "P2")     # LLM 재검토 대상 우선순위

_SYSTEM = (
    "너는 SOC 트리아지 보조자다. 각 사건 요약(점수·계층·연결·탐지 사유)과 evidence(실제 실행 명령어·"
    "요청 원문)를 보고 보안 분석가가 심층 조사(investigate)해야 하는지 true/false 로 판단한다. "
    "evidence 의 실제 명령을 근거로 정상 동작(예: --version 체크, 정상 배포)인지 공격(예: 웹셸 명령·"
    "외부 다운로드·권한상승)인지 가려라. 이유는 한국어 한 줄. 반드시 JSON 배열만 출력한다: "
    '[{"incident_id": "...", "investigate": true, "reason": "..."}]. 그 외 텍스트 금지.'
)

_EVIDENCE_MAX = 6      # 사건당 LLM 에 줄 증거 줄 수
_LINE_MAX = 160        # 증거 한 줄 최대 길이


def _model():
    """TRIAGE_CLAUDE_MODEL (없거나 빈 값이면 DEFAULT_MODEL)."""
    return (os.getenv("TRIAGE_CLAUDE_MODEL") or "").strip() or DEFAULT_MODEL


def _api_key_name():
    """쓸 API 키의 환경변수 이름 (TRIAGE_ 전용 → 공용 순서). 둘 다 없으면 None."""
    return next((name for name in API_KEY_ENV_NAMES if (os.getenv(name) or "").strip()), None)


def _evidence_line(ev):
    """이벤트 → 판단용 한 줄(계층별 핵심 필드). exec_args 가 list 여도 안전 처리."""
    ld = ev.get("layer_data", {}) or {}
    layer = ev.get("layer", "?")
    if layer == "system":
        args = ld.get("exec_args") or ld.get("argv") or ""
        if isinstance(args, (list, tuple)):
            args = " ".join(str(a) for a in args)
        return ("[system] %s %s" % (ld.get("comm") or ld.get("exe") or "", args)).strip()
    if layer == "web":
        return ("[web] %s %s %s" % (ld.get("method", ""), ld.get("path", ""), ld.get("status", ""))).strip()
    if layer == "network":
        return ("[network] %s %s" % (ld.get("method", ""), ld.get("url_path") or ld.get("url", ""))).strip()
    if layer == "auth":
        return ("[auth] %s user=%s" % (ld.get("method", ""), ld.get("user") or ld.get("invalid_user", ""))).strip()
    return "[%s]" % layer


def _digest(inc, by_ref=None):
    """LLM 에 보낼 요약 + evidence(실제 명령어). by_ref(raw_ref→event) 있으면 원문 명령을 붙인다."""
    d = {
        "incident_id": inc.get("incident_id"),
        "score": inc.get("triage_score"),
        "priority": inc.get("priority"),
        "entity": inc.get("entity"),
        "layers": sorted(set(inc.get("layers", []) or [])),
        "joins": sorted({e.get("join") for e in inc.get("join_path", []) or [] if e.get("join")}),
        "detect_reasons": [s.get("reason") for s in inc.get("seeds", []) or [] if s.get("reason")][:5],
        "score_parts": inc.get("triage_parts"),
    }
    if by_ref:
        refs = []
        for s in inc.get("seeds", []) or []:      # 탐지 근거 줄 우선
            refs += (s.get("evidence_refs") or [])
        refs += (inc.get("members", []) or [])     # 그다음 나머지 멤버
        seen, cmds = set(), []
        for r in refs:
            if r in seen:
                continue
            seen.add(r)
            ev = by_ref.get(r)
            if not ev:
                continue
            line = _evidence_line(ev)[:_LINE_MAX]
            if line and line not in cmds:
                cmds.append(line)
            if len(cmds) >= _EVIDENCE_MAX:
                break
        d["evidence"] = cmds
    return d


def _parse(text):
    """관대한 JSON 파싱: 첫 '[' 부터 완결 배열을 디코드(뒤 설명·[1] 인용 무시).

    배열이 잘려(max_tokens 초과 등) 통째로는 못 읽으면, 완결된 {..} 객체만이라도 하나씩 긁어
    살린다(0건으로 전부 버리지 않게 — 배치 일부라도 판정 반영)."""
    i = text.find("[")
    if i == -1:
        return []
    dec = json.JSONDecoder()
    try:
        arr, _ = dec.raw_decode(text[i:])
        if isinstance(arr, list):
            return arr
    except ValueError:
        pass
    # 구제: 잘린 배열에서 완결 객체만 순서대로 추출
    out, s = [], text[i + 1:]
    while True:
        j = s.find("{")
        if j == -1:
            break
        try:
            obj, end = dec.raw_decode(s[j:])
        except ValueError:
            break
        if isinstance(obj, dict):
            out.append(obj)
        s = s[j + end:]
    return out


def _default_call(digests):
    """실제 Anthropic 호출. TRIAGE_ANTHROPIC_API_KEY → ANTHROPIC_API_KEY, 모델 TRIAGE_CLAUDE_MODEL, 한 번의 create 호출."""
    import anthropic  # 지연 import: 패키지 미설치·키 없을 때 결정론-only 로 살아남게
    client = anthropic.Anthropic(api_key=os.getenv(_api_key_name()))   # 값은 출력하지 않는다
    # 사건 수에 맞춰 출력 토큰 확보 — 배치가 크면 판정 JSON 이 1024 를 넘어 잘려 파싱 실패했음
    max_tokens = min(1024 + 256 * len(digests), 8000)
    msg = client.messages.create(
        model=_model(),
        max_tokens=max_tokens,
        system=_SYSTEM,
        messages=[{"role": "user", "content": json.dumps(digests, ensure_ascii=False)}],
    )
    usage = getattr(msg, "usage", None)
    if usage is not None:   # 모델 비교용 토큰 기록(값은 정수뿐, 키·내용 없음)
        print("[triage] 토큰 입력 %d·출력 %d (모델 %s, stop_reason=%s)"
              % (getattr(usage, "input_tokens", 0) or 0, getattr(usage, "output_tokens", 0) or 0,
                 _model(), getattr(msg, "stop_reason", None)))
    text = "".join(b.text for b in msg.content if b.type == "text")
    return _parse(text)


def llm_review(incidents, events=None, call=None, priorities=REVIEW_PRIORITIES, max_review=MAX_REVIEW):
    """triage() 결과 상위 사건에 llm_investigate(bool)·llm_reason(str) 를 덧붙인다.

    입력은 triage() 가 이미 만든 복사본 리스트라 제자리에서 필드만 추가한다(순서·점수 불변).
    events: 정규화 이벤트 리스트. 주면 raw_ref→명령어를 digest 에 실어 LLM 오탐 판별을 정밀화.
    call: 주입 가능한 호출 함수(digests -> [{incident_id,investigate,reason}]). 테스트/대체용.
          None 이면 실제 Haiku 호출. 키 없거나 예외 발생 시 조용히 결정론-only 로 통과.
    """
    targets = [i for i in incidents if i.get("priority") in priorities][:max_review]
    if not targets:
        return incidents
    if call is None:
        key_name = _api_key_name()
        if not key_name:
            print("[triage] %s 없음 → LLM 재검토 생략, 결정론 결과만 사용" % " / ".join(API_KEY_ENV_NAMES))
            return incidents            # 키 없음 → 안전장치로 결정론-only
        print("[triage] LLM 재검토 모델 %s (API 키: %s)" % (_model(), key_name))
        call = _default_call
    by_ref = {e["raw_ref"]: e for e in events if e.get("raw_ref")} if events else None
    try:
        verdicts = call([_digest(i, by_ref) for i in targets])
    except Exception as exc:             # 네트워크/한도/파싱 실패 → 파이프라인 유지
        print("[triage] LLM 재검토 생략(%s)" % exc)
        return incidents
    by_id = {v.get("incident_id"): v for v in (verdicts or []) if isinstance(v, dict)}
    for inc in targets:
        v = by_id.get(inc.get("incident_id"))
        if v is None:
            continue
        inv = v.get("investigate")
        if isinstance(inv, str):  # "false"/"true" 문자열도 올바로 해석(비어있지않은 문자열=True 방지)
            inv = inv.strip().lower() in ("true", "1", "yes", "y")
        inc["llm_investigate"] = bool(inv)
        inc["llm_reason"] = (v.get("reason") or "").strip()[:200]
    return incidents
