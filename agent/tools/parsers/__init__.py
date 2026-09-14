"""팀원들이 실제 로그 포맷을 실측해서 만든 순수 파싱 로직 모음.

agent/tools/real/의 tool 파일들이 여기서 파싱 함수를 가져다 쓴다. 이 폴더의
파일들은 agent/tools/registry.py의 자동 탐색 대상이 아니다 (자동 탐색은
agent/tools/real/<도구이름>.py만 본다) — 여긴 그냥 재사용되는 라이브러리 코드.

- audit_parser.py  : auditd ENRICHED 포맷 파싱 (fetch_audit_log.py + raw_log_ingestion.py에서 사용)
- apache_parser.py : apache/nginx access 로그 파싱 (fetch_web_log.py + raw_log_ingestion.py에서 사용)
"""