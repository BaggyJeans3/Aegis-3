"""
Flask API + 이벤트 계약(정합) 테스트.

- 실제 생산자(proxy/app.js, nginx/sidecar.js, scripts/demo/demo.sh)가 Redis 에 넣는 이벤트 모양 그대로 /analyze 에 넣어본다.
- worker(tasks.build_mongo_document)가 읽는 응답 필드가 항상 있는지 확인한다.
"""
import json
import os
import subprocess
import sys
import threading

import pytest

from soar.risk_score_engine import app as app_module
from soar.risk_score_engine.app import app, analyze_log
from soar.risk_score_engine.state import ALL_STATE_STORES, purge_idle_keys

# conftest 를 직접 import 하지 않는다 (CI 에서 worker 테스트와 함께 돌 때 conftest 이름 충돌 방지)
from datetime import datetime

BASE_TIME = datetime(2026, 9, 27, 10, 0, 0)  # conftest.BASE_TIME 과 동일
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# worker 가 detection_result 에서 읽는 키 (services/ingestion/celery_app/tasks.py)
WORKER_REQUIRED_KEYS = {"risk_score", "level", "alert", "rule_hits", "reasons", "analysis_profile", "action_on_match"}


def _proxy_event(event_type, profile, status, action, path="/", **extra):
    e = {
        "event_id": "e-1", "trace_id": "t-1", "timestamp": "2026-09-27T01:00:00.000Z",
        "event_type": event_type, "analysis_profile": profile,
        "tenant_id": "11111111-1111-1111-1111-111111111111", "company_name": "Test Company",
        "ip": "203.0.113.7", "session_id": "unknown", "method": "GET", "host": "test.aegis3.cloud",
        "path": path, "query": "",
        "headers": {"user-agent": "Mozilla/5.0", "x-forwarded-for": "203.0.113.7, 127.0.0.1",
                    "cf-connecting-ip": None, "authorization": None, "content-type": None},
        "body": "", "status_code": status, "action_on_match": action, "route_id": None, "route_description": None,
    }
    e.update(extra)
    return e


PRODUCER_EVENTS = {
    "proxy.access_event": _proxy_event("access_event", "rate_only", 0, "proxy", "/index.html"),
    "proxy.honeypot_hit": _proxy_event("honeypot_hit", "full", 200, "honeypot", "/.env"),
    "proxy.blocked_request": _proxy_event("blocked_request", "full", 403, "block", "/admin"),
    "proxy.log_only_event": _proxy_event("log_only_event", "full", 0, "log_only", "/api/v1/x"),
    "proxy.no_matching_route": _proxy_event("no_matching_route", "full", 404, "no_route", "/nope", tenant_id=None),
    "sidecar.waf_blocked": {
        "event_id": "waf-1", "trace_id": "trace-waf-1", "timestamp": "2026-09-27T01:00:00.000Z",
        "event_type": "waf_blocked", "analysis_profile": "full", "tenant_id": None, "company_name": None,
        "ip": "203.0.113.8", "session_id": "unknown", "method": "GET", "host": "test.aegis3.cloud",
        "path": "/", "query": "id=1%27%20OR%20%271%27%3D%271", "headers": {}, "body": "",
        "status_code": 403, "action_on_match": "block", "waf_rule_hits": ["942100", "949110"],
    },
    "demo.F_injected": {
        "event_id": "demo-1", "trace_id": "trace-demo-1", "tenant_id": "", "company_name": "Demo Corp",
        "ip": "10.1.2.3", "path": "/admin/login", "method": "POST",
        "query": "id=1 UNION SELECT password FROM users--", "headers": {"user-agent": "sqlmap/1.5"},
        "body": "", "analysis_profile": "full", "action_on_match": "block", "event_type": "blocked_request",
        "status_code": 403,
    },
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ALERT_EVENTS_PATH", str(tmp_path / "alerts.jsonl"))
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.mark.parametrize("name", list(PRODUCER_EVENTS))
def test_producer_event_contract(client, name):
    resp = client.post("/analyze", json=PRODUCER_EVENTS[name])
    assert resp.status_code == 200, name
    body = resp.get_json()
    assert WORKER_REQUIRED_KEYS <= set(body["detection_result"]), name
    assert 0 <= body["detection_result"]["risk_score"] <= 100
    # 프록시 체인 IP 헤더만으로 SSRF 가 붙으면 안 된다
    assert "R-PAYLOAD-002" not in body["detection_result"]["rule_hits"], name


def test_demo_F_event_scores_for_demo_threshold(client):
    """demo_setup.sh 는 AI_RULE_THRESHOLD=30 으로 시연한다. demo F 이벤트가 그 이상이어야 LLM 경로가 탄다."""
    r = client.post("/analyze", json=PRODUCER_EVENTS["demo.F_injected"]).get_json()["detection_result"]
    assert r["risk_score"] >= 30
    assert "R-ASSET-001" in r["rule_hits"]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "tracked_keys" in data


def test_root_health_kept(client):
    assert client.get("/").get_json()["status"] == "running"


@pytest.mark.parametrize("payload", [None, "not-json", "[1,2]"])
def test_analyze_rejects_bad_body(client, payload):
    if payload is None:
        resp = client.post("/analyze")
    else:
        resp = client.post("/analyze", data=payload, content_type="application/json")
    assert resp.status_code == 400
    assert resp.get_json()["error"]


def test_alert_event_written_when_critical(client, tmp_path):
    e = PRODUCER_EVENTS["proxy.honeypot_hit"].copy()
    e["query"] = "u=http://169.254.169.254/"
    body = client.post("/analyze", json=e).get_json()
    assert body["detection_result"]["alert"] is True
    assert body["alert_event"]["action_required"] == "SEND_TO_LLM_ANALYSIS"
    lines = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["event_id"] == e["event_id"]


def test_no_alert_event_when_not_critical(client, tmp_path):
    body = client.post("/analyze", json=PRODUCER_EVENTS["proxy.access_event"]).get_json()
    assert body["alert_event"] is None
    assert not (tmp_path / "alerts.jsonl").exists()


def test_concurrent_analyze_is_consistent(ev):
    """8 스레드가 같은 IP 로 동시에 분석해도 예외 없이, 요청 수가 정확히 집계되어야 한다."""
    errors = []

    def worker(tid):
        try:
            for i in range(250):
                analyze_log(ev(i * 0.001, ip="198.51.100.1", path=f"/t{tid}-{i}", status_code=404))
        except Exception as exc:  # pragma: no cover - 실패 시 원인 보고용
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    from soar.risk_score_engine.state import ip_requests_fast, ip_404_paths_fast
    assert len(ip_requests_fast["198.51.100.1"]) == 2000
    assert len(ip_404_paths_fast["198.51.100.1"]) == 2000


def test_purge_idle_keys(ev):
    from datetime import timedelta
    for i in range(50):
        analyze_log(ev(0, ip=f"192.0.2.{i}", path="/.env"))
    assert sum(len(s) for s in ALL_STATE_STORES) > 0
    removed = purge_idle_keys(BASE_TIME + timedelta(seconds=601), 600)
    assert removed >= 50
    assert sum(len(s) for s in ALL_STATE_STORES) == 0


def test_purge_keeps_recent_keys(ev):
    from datetime import timedelta
    analyze_log(ev(0, ip="192.0.2.200", path="/.env"))
    purge_idle_keys(BASE_TIME + timedelta(seconds=30), 600)
    from soar.risk_score_engine.state import ip_sensitive_categories
    assert "192.0.2.200" in ip_sensitive_categories


def test_thresholds_overridable_by_env():
    """k6 결과 조정용: 환경변수로 임계값을 바꾸면 detector 가 그 값을 쓴다 (별도 프로세스에서 확인)."""
    code = (
        "from soar.risk_score_engine.app import analyze_log\n"
        "r=None\n"
        "for i in range(5):\n"
        "    r=analyze_log({'timestamp':'2026-09-27T10:00:0%dZ'%i,'ip':'1.1.1.1','path':'/p%d'%i,'status_code':404})\n"
        "print(','.join(r['rule_hits']))\n"
    )
    env = dict(os.environ, SCAN_FAST_LOW="5", PYTHONPATH=REPO_ROOT)
    out = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "R-SCAN-001"


def test_invalid_env_value_falls_back_to_default():
    code = "from soar.risk_score_engine import config; print(config.SCAN_FAST_LOW)"
    env = dict(os.environ, SCAN_FAST_LOW="abc", PYTHONPATH=REPO_ROOT)
    out = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True)
    assert out.stdout.strip().splitlines()[-1] == "15"
