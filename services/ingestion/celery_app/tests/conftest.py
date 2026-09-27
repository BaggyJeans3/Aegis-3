"""
SOAR worker(tasks.py) 테스트 공통 설정.
- celery_app 디렉터리를 sys.path 에 추가 (Dockerfile WORKDIR 과 동일하게 `import tasks`)
- google-genai 미설치 환경(CI)에서도 ai_engine import 가 되도록 스텁
- Redis/Mongo/HTTP 는 전부 가짜 객체로 대체 — 외부 서비스 없이 실행
"""
import os
import sys
import types

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

try:
    import google.genai  # noqa: F401
except Exception:
    google_mod = sys.modules.setdefault("google", types.ModuleType("google"))
    genai = types.ModuleType("google.genai")
    genai.Client = lambda **kw: None
    genai_types = types.ModuleType("google.genai.types")
    genai_types.GenerateContentConfig = lambda **kw: None
    genai.types = genai_types
    google_mod.genai = genai
    sys.modules["google.genai"] = genai
    sys.modules["google.genai.types"] = genai_types
