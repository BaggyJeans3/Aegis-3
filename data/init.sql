-- UUID 자동 생성을 위한 확장 모듈 활성화
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. tenants 테이블 
CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    plan_type VARCHAR(50) DEFAULT 'FREE',
    status VARCHAR(30) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
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

-- 테스트 데이터 삽입
INSERT INTO tenants (company_name, api_key, status) 
VALUES ('Test Company', 'test-api-key-1234', 'active');

INSERT INTO routers (tenant_id, inbound_domain, target_origin, path_pattern, priority, action_on_match, description)
VALUES ((SELECT tenant_id FROM tenants LIMIT 1), 'api.test.com', 'http://10.0.1.100', '/api/v1/*', 100, 'proxy', '정상적인 API 프록시 라우팅');

INSERT INTO routers (tenant_id, inbound_domain, target_origin, path_pattern, priority, action_on_match, description)
VALUES ((SELECT tenant_id FROM tenants LIMIT 1), 'api.test.com', NULL, '/.env', 10, 'honeypot', '환경변수 탈취 공격 방어용 허니팟');