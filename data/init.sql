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

-- 테스트 데이터 삽입
INSERT INTO tenants (company_name, api_key, status) 
VALUES ('Test Company', 'test-api-key-1234', 'active');

INSERT INTO routers (tenant_id, inbound_domain, target_origin, path_pattern, priority, action_on_match, description)
VALUES ((SELECT tenant_id FROM tenants LIMIT 1), 'api.test.com', 'http://10.0.1.100', '/api/v1/*', 100, 'proxy', '정상적인 API 프록시 라우팅');

INSERT INTO routers (tenant_id, inbound_domain, target_origin, path_pattern, priority, action_on_match, description)
VALUES ((SELECT tenant_id FROM tenants LIMIT 1), 'api.test.com', NULL, '/.env', 10, 'honeypot', '환경변수 탈취 공격 방어용 허니팟');