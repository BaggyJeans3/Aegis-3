"""
고객사 API 명세(spec_text) -> routers 테이블용 경로 목록 파서.

입력은 OpenAPI/Swagger JSON 문자열이어야 한다. 다른 형식(마크다운 표, 자유 텍스트 등)은
파싱하지 않고 빈 리스트를 반환한다 — 호출 측(customers.py)은 이 경우 캐치올(/*) +
디코이만 등록하는 것으로 안전하게 degrade한다.

proxy/app.js 의 matchPath()가 "정확 일치" 또는 "'/prefix/*' 접두사"만 지원하므로,
OpenAPI 경로의 {param} 세그먼트는 그 직전까지를 접두사로 잘라 '/*'를 붙인다.
  예) /api/catalogue/{id}       -> /api/catalogue/*
      /api/carts/{id}/items     -> /api/carts/*
      /api/catalogue (파라미터 없음) -> /api/catalogue (그대로, 정확 일치)
"""
import json

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

# 실제 명세에는 없는 경로로 스캐너/공격자를 유인하는 기본 디코이 세트.
# 고객사 명세에 우연히 같은 경로가 있으면 customers.py 쪽에서 걸러낸다.
DEFAULT_DECOY_ROUTES = [
    {"path_pattern": "/api/admin", "description": "존재하지 않는 관리자 API 미끼"},
    {"path_pattern": "/api/admin/*", "description": "관리자 하위 경로 미끼"},
    {"path_pattern": "/api/debug", "description": "디버그 엔드포인트 미끼"},
    {"path_pattern": "/api/config", "description": "설정 노출 미끼"},
    {"path_pattern": "/api/backup", "description": "백업 파일 미끼"},
    {"path_pattern": "/api/v1/*", "description": "구버전 API 미끼"},
    {"path_pattern": "/.env", "description": "환경변수 탈취 공격 방어용 허니팟"},
    {"path_pattern": "/.git/config", "description": "소스코드/설정 유출 미끼"},
    {"path_pattern": "/api/swagger.json", "description": "API 명세 유출 미끼"},
]


def _to_route_pattern(openapi_path: str) -> str:
    segments = openapi_path.split("/")
    prefix_segments = []
    has_param = False
    for seg in segments:
        if seg.startswith("{") and seg.endswith("}"):
            has_param = True
            break
        prefix_segments.append(seg)

    if not has_param:
        return openapi_path or "/"

    prefix = "/".join(prefix_segments)
    return f"{prefix}/*" if prefix else "/*"


def parse_openapi_spec(spec_text: str) -> list[dict]:
    """OpenAPI/Swagger JSON 문자열을 [{path_pattern, methods, description}, ...] 로 변환.
    파싱 불가(빈 값, JSON 아님, paths 없음)면 빈 리스트를 반환한다."""
    if not spec_text:
        return []

    try:
        spec = json.loads(spec_text)
    except (json.JSONDecodeError, TypeError):
        return []

    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []

    grouped: dict[str, dict] = {}

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        pattern = _to_route_pattern(raw_path)
        methods = set()
        description = None

        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            methods.add(method.upper())
            if not description:
                description = operation.get("summary") or operation.get("description")

        if not methods:
            continue

        entry = grouped.setdefault(pattern, {"methods": set(), "description": None})
        entry["methods"] |= methods
        if not entry["description"] and description:
            entry["description"] = description

    return [
        {
            "path_pattern": pattern,
            "methods": sorted(data["methods"]),
            "description": data["description"] or pattern,
        }
        for pattern, data in grouped.items()
    ]
