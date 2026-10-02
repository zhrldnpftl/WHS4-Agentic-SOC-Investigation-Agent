# LLM 모델 비교 (eval/)

트리아지·조사 에이전트·ATT&CK 매핑에 쓸 LLM 모델을 고르기 위한 비교 도구입니다.
설정 이름 규칙(`TRIAGE_`/`MAPPING_`/`INVESTIGATION_`)은 [docs/LLM-역할별-설정-가이드.md](../docs/LLM-역할별-설정-가이드.md)를 봅니다.

## 원칙

- **한 단계씩 바꾸고 나머지는 고정합니다.** 판정이 달라졌을 때 어느 단계 때문인지 가릴 수 있게 하려는 거예요.

  | 비교 단계 | 바꾸는 것 | 고정하는 것 |
  | --- | --- | --- |
  | 트리아지 | `TRIAGE_` 모델 | 로그 구간 |
  | 조사 에이전트 | `INVESTIGATION_` 모델 | 평가 사건 파일, 매핑 모델(기본 haiku) |
  | 매핑 | `MAPPING_` 모델 | 조사 결과 묶음 하나 |

- **로그를 고정합니다.** `/var/log`는 계속 쌓이고 교체되므로 한 번 복사한 `eval/logs/`만 씁니다.
  합성 시나리오를 붙일 때도 복사본에 붙여, 실제 로그·운영 탐지에는 영향이 없게 합니다.
- **`.env`는 고치지 않습니다.** 모델·로그 경로는 `run_eval.sh`가 실행할 때 환경변수로 넘깁니다.
- **응답이 거절돼도 다른 모델로 다시 보내지 않습니다.** 비교 중에는 재요청을 `none`으로 끄므로, 거절도 그 모델의 결과로 기록됩니다.
- `eval/logs`, `eval/runs`, `eval/incidents`에는 실제 트래픽이 들어 있어 git에 올리지 않습니다(`eval/.gitignore`).

## 순서

```bash
source .venv/bin/activate

# 1. 로그 고정 (처음 한 번) — 최근 4일 안에 수정된 로그 파일을 eval/logs/에 복사
bash eval/snapshot_logs.sh 4

# 2. 후보 사건 목록 (LLM 호출 없음)
bash eval/run_eval.sh detect
python eval/eval_tool.py candidates            # --min-priority P2 로 줄여 볼 수 있음

# 3. 평가 사건 고르기 → eval/incidents/eval_set.jsonl, labels.csv
python eval/eval_tool.py pick INC-aaaa INC-bbbb ...
#    labels.csv의 정답 칸을 채운다: expected_investigate, expected_verdict, expected_techniques(세미콜론 구분)

# 4. 트리아지 비교 (회당 LLM 호출 1번)
bash eval/run_eval.sh triage claude-haiku-4-5 1
bash eval/run_eval.sh triage claude-sonnet-4-6 1

# 5. 조사 에이전트 비교 (사건마다 LLM 여러 번, 사건당 약 2~4분). 매핑은 MAPPING_MODEL(기본 haiku)로 고정
bash eval/run_eval.sh investigation claude-haiku-4-5 1
bash eval/run_eval.sh investigation claude-sonnet-4-6 1
bash eval/run_eval.sh investigation claude-sonnet-5 1
bash eval/run_eval.sh investigation claude-sonnet-5-5 1
#    같은 모델을 다시 돌리면 회차 번호를 올린다: ... claude-sonnet-5 2

# 6. 매핑 비교 — 조사 결과 묶음 하나를 고정해서
SOURCE=investigation/claude-sonnet-5/run1 bash eval/run_eval.sh mapping claude-haiku-4-5 1
SOURCE=investigation/claude-sonnet-5/run1 bash eval/run_eval.sh mapping claude-sonnet-4-6 1

# 7. 요약 — 화면에 모델별 표, eval/summary_<단계>.csv에 사건별 자세히
python eval/eval_tool.py summarize
```

오래 걸리는 5번은 SSH가 끊겨도 계속 돌도록 `tmux`나 `nohup`으로 실행하는 걸 권장합니다.

## 결과 폴더

```
eval/runs/<단계>/<모델>/run<회차>/
  meta.env          모델·회차·고정 시각·git 커밋·걸린 시간
  run.log           실행 출력 전체
  incidents.jsonl                       (트리아지) 사건별 llm_investigate·llm_reason
  results/investigation_agent/*.json    (조사) 조사 결과
  results/attack_mapping/*.json         (조사) 매핑·최종 보고서
  results/llm_usage/*.json              (조사) 사건별·역할별 토큰과 걸린 시간
  attack_mapping/*.json                 (매핑) 매핑 결과
```

같은 실행 폴더가 이미 있으면 덮어쓰지 않고 멈춥니다. 회차 번호를 바꿔서 다시 돌리세요.

## 요약 지표

| 단계 | 지표 |
| --- | --- |
| 트리아지 | 정답(조사할지) 일치율, **놓친 공격**(정답 true인데 false), 반복 일관성, 회당 토큰·시간 |
| 조사 에이전트 | 판정 일치율, 반복 일관성, provenance 통과율(원본 근거 인용), 미완료·거절·해석 실패 수, 평균 시간·LLM 호출·토큰, 매핑 기법 일치 |
| 매핑 | 기법 완전 일치율, 평균 겹침(Jaccard), 반복 일관성, mapping_status 분포 |

- 비용은 토큰 수에 모델별 단가를 곱해 계산합니다(단가는 Anthropic 가격표 기준).
- 매핑 단계 단독 실행(6번)은 매핑 CLI가 토큰을 기록하지 않아, 비용은 Anthropic 콘솔 사용량으로 봅니다.

## 지금 한계

- 트리아지는 Claude만 지원합니다. GPT 비교는 트리아지 코드 수정이 필요합니다(가이드 문서 "추후 과제").
- `run_eval.sh`는 Anthropic 모델만 넘깁니다. GPT 클라이언트를 추가할 때 provider 선택을 함께 넣습니다.
