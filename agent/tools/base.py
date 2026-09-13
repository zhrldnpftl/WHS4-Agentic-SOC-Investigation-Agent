"""
tools/base.py
모든 도구가 공통으로 사용하는 출력 포맷과 헬퍼.
도구는 결과를 직접 dict로 만들지 말고, 아래 success()/failure()를 써서 반환한다.
그래야 모든 도구의 반환 모양이 똑같아진다.
"""

# ======== 지원님 코드 =============


#모든 타입의 값이 허용됨을 나타내는 특별한 타입 힌트
from typing import Any

#도구 실행이 성공했을 때 쓰는 반환 형식
def success(data: Any) -> dict:
    return {
        "success": True,
        "data": data,
        "error": None,
    }

#도구 실행이 실패했을 때 쓰는 반환 형식
def failure(reason: str) -> dict:
    return {
        "success": False,
        "data": None,
        "error": reason,
    }