"""
Supabase JWT 검증 + 권한(role) 판별.

흐름:
  1. 프론트가 Authorization: Bearer <token> 헤더로 토큰을 보냄
  2. Supabase JWKS(공개키)로 토큰 서명 검증
  3. 토큰의 sub(user_id) 로 Supabase user_profiles 테이블의 role 조회
  4. role 결과를 5분간 캐시 (매 요청마다 Supabase 호출 방지)
  5. AuthContext 에 user_id, email, role, is_admin 채워서 엔드포인트로 전달

설계 결정:
  - Custom Access Token Hook 이 동작 안 하는 환경 대응 (Free Plan 제약 등)
  - role 의 단일 진실의 출처 = user_profiles 테이블
  - role 변경 시 토큰 재발급 안 기다림 (최대 캐시 만료 5분 후 반영)

사용법:
  from .auth import get_auth_context, AuthContext

  @app.get("/api/example")
  async def example(ctx: AuthContext = Depends(get_auth_context)):
      if ctx.is_admin:
          ...

환경변수:
  SUPABASE_URL                 - 프로젝트 URL (JWKS, REST API 공통)
  SUPABASE_JWT_AUDIENCE        - 토큰 aud 값 (보통 'authenticated')
  SUPABASE_SERVICE_ROLE_KEY    - REST API 호출용 비밀 키. user_profiles 조회 시 RLS 우회.
                                 노출 절대 금지.
"""
import os
import time

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_AUDIENCE = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# Supabase 공개키 URL (JWT 서명 검증용)
_JWKS_URL = f"{SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"

# 토큰 발급자(issuer) 값
_ISSUER = f"{SUPABASE_URL.rstrip('/')}/auth/v1"

# user_profiles 테이블 REST 엔드포인트
_USER_PROFILES_URL = f"{SUPABASE_URL.rstrip('/')}/rest/v1/user_profiles"

# JWKS 클라이언트 (공개키 자동 캐시)
_jwks_client = PyJWKClient(_JWKS_URL) if SUPABASE_URL else None

# FastAPI 의 Authorization 헤더 추출기
_bearer_scheme = HTTPBearer(auto_error=False)

# role 캐시: user_id -> (role, expires_at_unix_ts)
# 같은 사용자가 짧은 시간에 여러 번 호출해도 Supabase 호출 1회로 줄임.
_ROLE_CACHE: dict[str, tuple[str, float]] = {}
_ROLE_CACHE_TTL_SECONDS = 300  # 5분


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> dict:
    """
    Authorization 헤더의 Bearer 토큰을 검증하고 payload(클레임)를 반환.
    실패 시 401.

    user["sub"] = Supabase user_id (UUID 문자열)
    """
    if _jwks_client is None:
        raise _unauthorized("Supabase 설정 누락 (SUPABASE_URL)")

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized("Authorization 헤더 없음 또는 형식 오류")

    token = credentials.credentials

    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token).key

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["ES256"],
            audience=SUPABASE_AUDIENCE,
            issuer=_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("토큰 만료됨")
    except jwt.InvalidAudienceError:
        raise _unauthorized("토큰 audience 불일치")
    except jwt.InvalidIssuerError:
        raise _unauthorized("토큰 issuer 불일치")
    except jwt.InvalidTokenError as e:
        raise _unauthorized(f"토큰 검증 실패: {e}")
    except Exception as e:
        raise _unauthorized(f"토큰 처리 오류: {e}")

    return payload


# ===== 권한(role) 판별 - user_profiles 조회 기반 =====

async def _fetch_role_from_supabase(user_id: str) -> str:
    """
    Supabase REST API 로 user_profiles 테이블에서 role 조회.
    Service Role Key 를 사용하므로 RLS 우회됨.
    """
    if not SUPABASE_SERVICE_ROLE_KEY or not SUPABASE_URL:
        # 설정 누락 - 안전하게 CUSTOMER 로 fallback
        return "CUSTOMER"

    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Accept": "application/json",
    }
    params = {
        "id": f"eq.{user_id}",
        "select": "role",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                _USER_PROFILES_URL,
                headers=headers,
                params=params,
            )
            resp.raise_for_status()
            rows = resp.json()
            if rows and isinstance(rows, list) and len(rows) > 0:
                role = rows[0].get("role")
                if role:
                    return str(role).upper()
    except (httpx.HTTPError, ValueError, KeyError):
        # 네트워크 오류, 파싱 오류 등 - 안전하게 CUSTOMER 로 fallback
        pass

    return "CUSTOMER"


async def get_role_for_user(user_id: str) -> str:
    """
    user_id 의 role 을 반환. 캐시 우선, 만료/미존재 시 Supabase 조회.
    """
    if not user_id:
        return "CUSTOMER"

    now = time.time()
    cached = _ROLE_CACHE.get(user_id)
    if cached is not None:
        role, expires_at = cached
        if now < expires_at:
            return role

    # 캐시 미스 또는 만료 -> Supabase 조회
    role = await _fetch_role_from_supabase(user_id)
    _ROLE_CACHE[user_id] = (role, now + _ROLE_CACHE_TTL_SECONDS)
    return role


class AuthContext:
    """
    인증된 사용자 정보. 엔드포인트에서 ctx = Depends(get_auth_context) 로 받음.
    """
    def __init__(self, payload: dict, role: str):
        self.payload = payload
        self.user_id: str = payload.get("sub", "")
        self.email: str = payload.get("email", "")
        self.role: str = role
        self.is_admin: bool = role == "ADMIN"


async def get_auth_context(
    payload: dict = Depends(get_current_user),
) -> AuthContext:
    """
    토큰 검증 + user_profiles 조회로 role 결정.
    """
    user_id = payload.get("sub", "")
    role = await get_role_for_user(user_id)
    return AuthContext(payload, role)


# ===== 하위 호환용 (기존 코드가 import 하던 함수들) =====

def get_user_role(payload: dict) -> str:
    """
    하위 호환용. 이제는 토큰 payload 만으로는 role 판별 안 함.
    AuthContext 의 role 을 쓰는 게 정확함. 이 함수는 토큰의 app_metadata 만 봄.
    """
    app_meta = payload.get("app_metadata") or {}
    return app_meta.get("user_role", "CUSTOMER")


def is_admin(payload: dict) -> bool:
    """하위 호환용. 가급적 AuthContext.is_admin 사용 권장."""
    return get_user_role(payload) == "ADMIN"