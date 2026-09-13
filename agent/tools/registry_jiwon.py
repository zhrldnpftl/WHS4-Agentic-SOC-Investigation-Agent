"""
tools/registry.py
도구들을 등록하고 이름으로 찾는 "명부".
- register: 도구를 명부에 올림 (데코레이터로 간편하게)
- get_tool: 이름으로 실제 함수를 꺼냄
- get_schemas: 등록된 모든 도구의 스키마 목록 (모델에게 전달용)
"""

# ======= 지원님 코드 ===============


# 등록된 도구를 담는 명부 (이름 -> {함수, 스키마})
_registry: dict = {}


def register(name: str, description: str, input_schema: dict): # 1. 데코레이터의 '인자'를 받음
    def decorator(func):                                       # 2. 데코레이팅될 '함수'를 받음
        _registry[name] = {
            "func": func,              # 실제 실행할 함수
            "schema": {                # 모델에게 줄 설명서
                "name": name,
                "description": description,
                "input_schema": input_schema, # 2. decorator를 돌려줌
            },
        }
        return func   # 함수는 그대로 돌려줌 (원래대로 쓸 수 있게)
    return decorator #


# 이름으로 실제 함수를 꺼낸다. 없으면 None.
# 에이전트가 실제 함수를 사용할 때 호출
def get_tool(name: str):
    entry = _registry.get(name)
    return entry["func"] if entry else None #삼향 연산자


# 등록된 모든 도구의 스키마 목록 (모델 전달용)
def get_schemas() -> list:
    return [entry["schema"] for entry in _registry.values()] #리스트 컴프리헨션


# 등록된 도구 이름 목록 (확인용)
def list_tools() -> list:
    return list(_registry.keys())