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

## 추론 강도(effort) 비교

같은 모델을 effort만 바꿔 비교할 때는 앞에 `EFFORT=`를 붙입니다. 결과 폴더와 요약 표의 모델 이름이 `<모델>@<effort>`로
나뉘어 기존 결과(모델 기본값)와 섞이지 않습니다. Claude는 `<역할>_CLAUDE_EFFORT`, GPT는 `<역할>_OPENAI_REASONING_EFFORT`로
넘기고, `.env`에 적힌 effort는 비교 실행에 끼어들지 않습니다. haiku-4-5와 Gemini는 effort를 지원하지 않습니다.
GPT는 `none`(추론 끔)도 됩니다.

```bash
EFFORT=low bash eval/run_eval.sh investigation claude-sonnet-5-5 1                                  # 조사 에이전트
EFFORT=low SOURCE=investigation/claude-sonnet-5-5/run1 bash eval/run_eval.sh mapping claude-sonnet-5-5 1   # 매핑
```

Haiku 4.5는 effort 대신 생각 예산(토큰)으로 생각을 켭니다: `THINKING_BUDGET=4000 bash eval/run_eval.sh ...`
(1024 이상 16000 미만, 결과 폴더 `<모델>@think4000`).

### 여러 설정 한 번에 (models.yaml)

[models.yaml](models.yaml)에 트리아지 팀원 비교와 같은 8개 설정(sonnet5 low/high, gpt-5.4 none/high,
haiku45 off/think, gpt-5.4-mini none/high)이 있습니다. `run_matrix.py`가 위에서부터 차례로 `run_eval.sh`를 부르고,
결과 폴더는 yaml의 `name`(예: `eval/runs/mapping/sonnet5-low/run1`)입니다.

```bash
python eval/run_matrix.py mapping --source investigation/claude-sonnet-5-5/run1 --dry-run   # 목록만 보기
python eval/run_matrix.py mapping --source investigation/claude-sonnet-5-5/run1
python eval/run_matrix.py investigation --only sonnet5-low,haiku45-off,gpt54mini-none     # 일부만
python eval/eval_tool.py summarize
```

이미 있는 결과 폴더는 건너뛰므로, 중간에 멈추면 반쯤 찬 폴더만 지우고 같은 명령을 다시 실행하면 됩니다.
한 설정이 실패해도 다음 설정으로 넘어가고 끝에 실패 목록을 보여 줍니다.

### 미완료 사건만 다시 돌리기

API 잔액 부족 등으로 일부 사건이 미완료(`llm_unavailable`)로 끝났으면 그 사건만 다른 폴더에 다시 돌린 뒤 옮겨 합칩니다.

```bash
INCIDENTS=INC-aaaa,INC-bbbb EFFORT=high NAME=gpt54-high-retry \
  bash eval/run_eval.sh investigation gpt-5.4-2026-03-05 1
```

## GPT 모델 비교

`run_eval.sh`는 모델 이름이 `gpt-*` 또는 `o<숫자>*`이면 OpenAI(GPT)로, 그 밖은 Claude로 넘깁니다
(다른 이름이면 `PROVIDER=openai`를 앞에 붙입니다). 매핑은 그대로 `MAPPING_MODEL`(기본 Claude haiku)로 고정됩니다.

```bash
# 1. .env에 OpenAI API 키 추가 (ChatGPT 구독이 아니라 platform.openai.com API 키)
echo 'OPENAI_API_KEY=발급받은_키' >> .env

# 2. 쓸 수 있는 모델 이름 조회 (비용 없음) — 이름을 짐작하지 말고 여기서 고른다
python -c "
from dotenv import load_dotenv; load_dotenv('.env')
from openai import OpenAI
print('\n'.join(sorted(m.id for m in OpenAI().models.list() if m.id.startswith(('gpt', 'o')))))"

# 3. Claude와 같은 사건 9건으로 실행 → 요약
bash eval/run_eval.sh investigation <GPT mini 모델 이름> 1
bash eval/run_eval.sh investigation <GPT 상위 모델 이름> 1
python eval/eval_tool.py summarize
```

GPT 결과도 `results/llm_usage/`에 같은 키(입력·출력·캐시 읽기 토큰)로 기록돼 Claude와 한 표에서 비교됩니다.
GPT 단가는 OpenAI 가격표 기준으로 따로 계산합니다.

## Gemini 모델 비교

모델 이름이 `gemini-*`이면 Gemini로 넘깁니다. `.env`에 `GEMINI_API_KEY`(Google AI Studio 키)가 필요합니다.
무료 티어는 하루 요청 한도가 있고 503(과부하)이 잦아, 재시도로 시간이 더 걸리거나 사건이 미완료로 끝날 수 있습니다.

```bash
bash eval/run_eval.sh investigation gemini-3.5-flash-lite 1
```

Gemini도 토큰(입력·출력·캐시 읽기, 생각 토큰은 출력에 포함)과 안전 필터 차단(거절)이 같은 표에 기록됩니다.

## 지금 한계

- 트리아지는 Claude만 지원합니다. GPT 비교는 트리아지 코드 수정이 필요합니다(가이드 문서 "추후 과제").
- GPT는 거절 시 다른 모델로 다시 보내지 않습니다(Claude도 비교 중에는 끔).
