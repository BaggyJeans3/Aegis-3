-- =============================================================
-- Aegis-3 PostgreSQL 초기화 스크립트
-- =============================================================
-- 컨테이너 첫 기동 시 docker-entrypoint-initdb.d/init.sql 로 자동 실행됨.
-- 변경 후 재적용하려면 볼륨 삭제 필요: docker compose down -v

-- UUID 자동 생성을 위한 확장 모듈 활성화
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. tenants 테이블
CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    plan_type VARCHAR(50) DEFAULT 'FREE',
    status VARCHAR(30) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    -- Supabase 회원과 연결: 이 고객사가 어느 회원 소유인지
    supabase_user_id UUID,
    -- API 명세서 원문(텍스트). OpenAPI/Swagger 내용을 통째로 저장
    spec_text TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 2. routers 테이블
CREATE TABLE routers (
    route_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    inbound_domain VARCHAR(255) NOT NULL,
    path_pattern VARCHAR(255) DEFAULT '/*',
    target_origin VARCHAR(255),
    priority INTEGER NOT NULL DEFAULT 100,
    allowed_methods TEXT[] NOT NULL DEFAULT ARRAY['GET', 'POST', 'PUT', 'DELETE'],
    action_on_match VARCHAR(30) NOT NULL DEFAULT 'proxy' CHECK (action_on_match IN ('proxy', 'block', 'honeypot', 'log_only')),
    is_active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 인덱스 생성
CREATE INDEX idx_routers_domain_active ON routers(inbound_domain) WHERE is_active = TRUE;
-- supabase_user_id 로 고객사 조회가 잦으므로 인덱스 추가
CREATE INDEX idx_tenants_supabase_user ON tenants(supabase_user_id);

-- =============================================================
-- 테스트 데이터
-- =============================================================
-- 팀원이 구축한 고객사 테스트 서버(http://168.110.101.66:81)를
-- Aegis-3 백엔드로 등록. curl http://localhost/... 로 진입.

INSERT INTO tenants (company_name, api_key, status)
VALUES ('Test Company', 'test-api-key-1234', 'active');

-- [라우트 1] 허니팟: .env 같은 민감 경로는 백엔드로 안 보내고 가짜 응답
--   priority 10 (낮을수록 먼저 매칭) → 일반 proxy보다 우선
INSERT INTO routers (
    tenant_id, inbound_domain, target_origin, path_pattern,
    priority, allowed_methods, action_on_match, description
)
VALUES (
    (SELECT tenant_id FROM tenants LIMIT 1),
    'localhost',
    NULL,
    '/.env',
    10,
    ARRAY['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'honeypot',
    '환경변수 탈취 공격 방어용 허니팟'
);

-- [라우트 2] 정상 프록시: 그 외 모든 경로는 팀원 테스트 서버로 전달
--   path_pattern '/*' 로 catch-all, Coraza가 통과시킨 트래픽만 도달
INSERT INTO routers (
    tenant_id, inbound_domain, target_origin, path_pattern,
    priority, allowed_methods, action_on_match, description
)
VALUES (
    (SELECT tenant_id FROM tenants LIMIT 1),
    'localhost',
    'http://168.110.101.66:81',
    '/*',
    100,
    ARRAY['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'proxy',
    '팀원 구축 고객사 테스트 서버 라우팅'
);
