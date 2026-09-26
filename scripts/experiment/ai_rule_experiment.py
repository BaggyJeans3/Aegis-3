#!/usr/bin/env python3
"""
AI 룰 탐지율·오탐율 실험 (논문 실험 데이터 수집용)

실행 중인 docker compose 스택(시연값 권장: AI_RULE_THRESHOLD=30, SHADOW_DURATION=30,
TTL_SECONDS=60)에 라벨이 붙은 공격/정상 트래픽을 흘리고, MongoDB ai_rule_events 로그로
지표를 계산한다. 외부 의존성 없음(표준 라이브러리 + docker CLI).

  python scripts/experiment/ai_rule_experiment.py run [--n-attack 10] [--n-normal 40]

흐름: 실험 전용 도메인/테넌트/허니팟 경로 등록 → 공격자·정상 사용자 컨테이너(서로 다른 IP)
      → 트리거(허니팟 접근 / 쿠폰 악용 이벤트 주입) → AI 룰 생성 대기 → 관찰 단계 트래픽
      → 승격·보관 판정 대기 → 차단 단계 트래픽 → 집계 → 정리
결과: scripts/experiment/results/<run_id>/ (requests.jsonl, events.json, summary.json, summary.md)

정답 라벨: 모든 요청에 exp=<run>.<a|n>.<scenario>.<phase>.<i> 쿼리를 붙이고, 사이드카가 남긴
shadow_match/live_match 이벤트의 query 에서 이 꼬리표를 읽어 요청과 1:1 로 맞춘다.
"""
import argparse
import json
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1] if len(HERE.parents) > 1 else HERE  # 컨테이너(/exp) 안에서는 send 만 쓰므로 무관

EXP_HOST = "exp-shop.aegis3.test"
EXP_TENANT = "00000000-0000-4000-8000-00000000e0e0"
EXP_ORIGIN = "http://mock-backend:9100"  # docker-compose 의 mock-backend (정상 요청 목적지)
IMAGE = "python:3.12-slim"
ATTACKER, NORMAL = "aegis-exp-attacker", "aegis-exp-normal"
# 정상 요청은 rate detector(IP당 60초 100회) 아래로 보낸다 → 정상 IP 가 오탐으로 차단되지 않게
NORMAL_PACE_S, ATTACK_PACE_S = 0.6, 0.3
# 주입 트리거용 IP (문서용 TEST-NET, 실행마다 새로 뽑음). 공격자 컨테이너 IP 는 허니팟 트리거 직후
# 차단목록에 올라 같은 IP 로 주입하면 LLM 이 생략되고, 같은 IP 를 재사용하면 위험도 엔진의 10분 누적
# 경로 열거 점수가 쌓여 채우기용 이벤트까지 LLM 을 호출하므로 분리한다.
INJECT_IP = None

# 시나리오: CRS·정적 커스텀 룰이 막지 않는 공격만 (막히는 공격엔 AI 룰이 매칭될 기회가 없음)
#  trigger=honeypot → 허니팟 경로로 등록, 공격자가 실제로 접근해 룰 생성
#  trigger=inject   → 탐지 이벤트를 Redis 큐에 직접 주입 (실트래픽으로는 점수를 받을 수 없는 공격)
SCENARIOS = {
    "hp_session_dump": {
        "trigger": "honeypot",
        "path": "/shop/debug/session-dump",
        "attack": ["/shop/debug/session-dump", "/shop/debug/session-dump?sid={n}",
                   "/shop/debug/session-dump?user=admin&n={n}"],
    },
    "hp_internal_report": {
        "trigger": "honeypot",
        "path": "/shop/internal-report",
        "attack": ["/shop/internal-report", "/shop/internal-report?q=revenue&y=20{n}",
                   "/shop/internal-report?format=csv&page={n}"],
    },
    "coupon_stacking": {
        "trigger": "inject",
        "path": "/shop/coupon/stack",
        "trigger_query": "code=FREE100&repeat=50",
        "attack": ["/shop/coupon/stack?code=FREE100&repeat={n}",
                   "/shop/coupon/stack?code=SALE{n}&repeat=99",
                   "/shop/coupon/stack?repeat={n}&code=WELCOME10"],
    },
}

# 정상 요청: 일반 쇼핑 흐름 + 공격 경로와 헷갈리기 쉬운 경로(near-miss, 과도한 정규식 검출용)
NORMAL_REQUESTS = [
    "/shop/products?page={n}", "/shop/products/{n}", "/shop/cart", "/shop/search?q=running+shoes",
    "/shop/orders/history?page={n}", "/shop/coupon/apply?code=WELCOME10",
    "/shop/coupon/stack?code=FREE100",            # 쿠폰 1회 적용 (repeat 없음)
    "/shop/coupon/stack-guide",                   # near-miss
    "/shop/debug-help", "/shop/debug/session-dump-guide",  # near-miss
    "/shop/internal-reports-faq",                 # near-miss
]


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(*args, check=True, input=None):
    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", input=input)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])}... 실패: {r.stderr.strip()[:500]}")
    return r.stdout


def env_value(key):
    for line in (REPO / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f".env 에 {key} 가 없습니다")


def psql(sql):
    return sh("docker", "exec", "aegis-postgres", "psql", "-U", "aegis_admin", "-d", "aegis_proxy",
              "-v", "ON_ERROR_STOP=1", "-qtAc", sql)


def mongo_eval(js):
    out = sh("docker", "exec", "aegis-mongodb", "mongosh", "-u", "aegis_user", "-p", env_value("MONGO_PASSWORD"),
             "--authenticationDatabase", "admin", "--quiet", "aegis_logs", "--eval", js)
    return json.loads(out)


def rule_events_since(ts):
    return mongo_eval(
        f'EJSON.stringify(db.ai_rule_events.find({{ts:{{$gte:"{ts}"}}}},{{_id:0}}).sort({{ts:1}}).toArray(),'
        f'{{relaxed:true}})'
    )


def sidecar_rules():
    out = sh("docker", "exec", "aegis-nginx", "node", "-e",
             "require('http').get('http://localhost:4000/api/v1/rules',r=>r.pipe(process.stdout))")
    return {int(r["id"]): r["status"] for r in json.loads(out)["rules"]}


# ── 준비 / 정리 ────────────────────────────────────────────────

def setup_routes():
    psql(f"insert into tenants (tenant_id, company_name, api_key) values "
         f"('{EXP_TENANT}', 'AI Rule Experiment', 'exp-{EXP_TENANT}') on conflict do nothing")
    psql(f"delete from routers where tenant_id = '{EXP_TENANT}'")
    rows = [f"('{EXP_TENANT}','{EXP_HOST}','{s['path']}','',5,'{{GET,POST}}','honeypot',true,'exp {name}')"
            for name, s in SCENARIOS.items() if s["trigger"] == "honeypot"]
    rows.append(f"('{EXP_TENANT}','{EXP_HOST}','/*','{EXP_ORIGIN}',100,'{{GET,POST}}','proxy',true,'exp origin')")
    psql("insert into routers (tenant_id, inbound_domain, path_pattern, target_origin, priority, "
         "allowed_methods, action_on_match, is_active, description) values " + ",".join(rows))


def teardown(keep_routes):
    sh("docker", "rm", "-f", ATTACKER, NORMAL, check=False)
    if not keep_routes:
        psql(f"delete from tenants where tenant_id = '{EXP_TENANT}'")  # routers 는 CASCADE


def start_clients():
    net = sh("docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}",
             "aegis-nginx").strip()
    ips = {}
    for name in (ATTACKER, NORMAL):
        sh("docker", "rm", "-f", name, check=False)
        sh("docker", "run", "-d", "--name", name, "--network", net, "-v", f"{HERE}:/exp:ro",
           IMAGE, "sleep", "infinity")
        ips[name] = sh("docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{net}").IPAddress}}}}',
                       name).strip()
    return ips


# ── 트래픽 ────────────────────────────────────────────────────

def fill(template, rng):
    return template.format(n=rng.randint(1, 9999))


def tagged(url, tag):
    return f"{url}{'&' if '?' in url else '?'}exp={tag}"


def build_plan(run_id, phase, n_attack, n_normal, rng):
    attack, normal = [], []
    for name, s in SCENARIOS.items():
        for i in range(n_attack):
            tag = f"{run_id}.a.{name}.{phase}.{i}"
            attack.append({"url": tagged(fill(s["attack"][i % len(s["attack"])], rng), tag),
                           "label": "attack", "scenario": name, "phase": phase, "tag": tag})
    for i in range(n_normal):
        tag = f"{run_id}.n.normal.{phase}.{i}"
        normal.append({"url": tagged(fill(NORMAL_REQUESTS[i % len(NORMAL_REQUESTS)], rng), tag),
                       "label": "normal", "scenario": "normal", "phase": phase, "tag": tag})
    rng.shuffle(attack)
    return attack, normal


def send_from(container, run_dir, name, reqs, pace):
    """컨테이너 안에서 이 스크립트의 send 서브커맨드를 실행 (백그라운드)."""
    plan = run_dir / f"plan_{name}.json"
    plan.write_text(json.dumps({"pace": pace, "requests": reqs}), encoding="utf-8")
    rel = plan.relative_to(HERE).as_posix()
    return subprocess.Popen(["docker", "exec", container, "python", "/exp/ai_rule_experiment.py", "send",
                             f"/exp/{rel}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8")


def collect(procs):
    rows = []
    for p in procs:
        out, err = p.communicate()
        if p.returncode != 0:
            raise RuntimeError(f"sender 실패: {err[:500]}")
        rows += [json.loads(line) for line in out.splitlines() if line.strip()]
    return rows


def cmd_send(plan_path):
    """(컨테이너 내부) 요청을 보내고 결과를 JSONL 로 출력."""
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    for r in plan["requests"]:
        req = urllib.request.Request("http://nginx:80" + r["url"], headers={"Host": EXP_HOST})
        try:
            status = urllib.request.urlopen(req, timeout=10).status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception as e:  # 네트워크 오류도 기록
            status = f"error:{e}"
        print(json.dumps({**r, "status": status, "ts": datetime.now(timezone.utc).isoformat()}), flush=True)
        time.sleep(plan["pace"])


def inject_coupon_trigger(name, s):
    """쿠폰 악용은 실트래픽으로 점수를 못 받으므로 시연 스크립트와 같은 방식으로 이벤트 주입.
    경로 열거(404 30개/60초 → +40점)를 만든 뒤 마지막에 공격 이벤트를 넣는다."""
    base = {"trace_id": "t", "ip": INJECT_IP, "method": "GET", "host": EXP_HOST, "query": "", "body": "",
            "headers": {"user-agent": "Mozilla/5.0"}, "analysis_profile": "full",
            "event_type": "request", "status_code": 404}
    for i in range(29):
        ev = {**base, "event_id": f"exp-scan-{name}-{i}", "path": f"/shop/p-{random.randint(1, 10**9)}"}
        sh("docker", "exec", "aegis-redis", "redis-cli", "LPUSH", "aegis:security-events", json.dumps(ev))
    time.sleep(8)  # 앞선 이벤트가 먼저 처리되도록
    ev = {**base, "event_id": f"exp-trigger-{name}", "path": s["path"], "query": s["trigger_query"]}
    sh("docker", "exec", "aegis-redis", "redis-cli", "LPUSH", "aegis:security-events", json.dumps(ev))


# ── 대기 ──────────────────────────────────────────────────────

def wait_for_rules(start_ts, trigger_ips, timeout):
    """시나리오별 룰 확보 이벤트를 기다려 scenario → rule_id 매핑.
    이전 실행이 같은 공격 지문으로 룰을 만들었다면 LLM 대신 auto_rearm 이 일어난다."""
    deadline = time.time() + timeout
    while True:
        gens = [e for e in rule_events_since(start_ts)
                if e.get("source") == "worker" and e.get("ip") in trigger_ips
                and e.get("type") in ("generated", "generation_failed", "auto_rearm")]
        by_path = {}
        for e in gens:
            by_path.setdefault(e.get("path"), e)
        mapping = {name: by_path.get(s["path"]) for name, s in SCENARIOS.items()}
        if all(mapping.values()) or time.time() > deadline:
            return {n: (e or {}).get("rule_id") for n, e in mapping.items()}, gens
        time.sleep(5)


def wait_for_judgement(rule_ids, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = sidecar_rules()
        if not any(status.get(r) == "shadow" for r in rule_ids):
            return status
        time.sleep(5)
    return sidecar_rules()


# ── 집계 ──────────────────────────────────────────────────────

def pct(a, b):
    return round(100.0 * a / b, 2) if b else None


def exp_tag(event):
    return (parse_qs(event.get("query") or "").get("exp") or [None])[0]


def summarize(run_id, requests, events, rule_map, attacker_ip, params):
    rule_ids = {r for r in rule_map.values() if r}
    rule_to_scn = {r: n for n, r in rule_map.items() if r}
    by_tag = {r["tag"]: r for r in requests}

    gens = [e for e in events if e.get("source") == "worker" and e.get("ip") in (attacker_ip, INJECT_IP)
            and e.get("type") in ("generated", "generation_failed")]
    ok = [e for e in gens if e["type"] == "generated"]
    lat = sorted(e["llm_latency_ms"] for e in ok if e.get("llm_latency_ms") is not None)
    generation = {
        "triggers": len(SCENARIOS), "generated": len(ok), "failed": len(gens) - len(ok),
        "success_rate_pct": pct(len(ok), len(gens)),
        "model": ok[0].get("model") if ok else None,
        "attempts_avg": round(sum(e.get("attempts", 0) for e in ok) / len(ok), 2) if ok else None,
        "latency_ms": {"min": lat[0], "median": lat[len(lat) // 2], "max": lat[-1]} if lat else None,
        "error_kinds": dict(Counter(err["kind"] for e in gens for err in e.get("errors", []))),
        "auto_rearmed": len([e for e in events if e.get("type") == "auto_rearm"
                             and e.get("ip") in (attacker_ip, INJECT_IP)]),
        "rules": {n: {"rule_id": r, "regex": next((e.get("regex") for e in ok if e.get("rule_id") == r), None)}
                  for n, r in rule_map.items()},
    }

    lifecycle = {n: [{k: e.get(k) for k in ("type", "reason", "stats", "observed_s") if e.get(k) is not None}
                     for e in events if e.get("rule_id") == r and e.get("source") == "sidecar"
                     and e["type"] in ("promoted", "archived", "rearmed")]
                 for n, r in rule_map.items() if r}

    # 관찰 단계: 사이드카의 판정(verdict) vs 정답 라벨
    confusion = Counter()
    for e in events:
        if e.get("type") == "shadow_match" and e.get("rule_id") in rule_ids and exp_tag(e) in by_tag:
            confusion[(by_tag[exp_tag(e)]["label"], e.get("verdict"))] += 1
    shadow = {f"{label}->{verdict}": n for (label, verdict), n in sorted(confusion.items())}

    # 차단 단계: AI 룰(이번 실행에서 생성된 룰)이 막은 요청
    blocked = defaultdict(set)  # tag -> 막은 rule_id
    for e in events:
        if e.get("type") == "live_match" and e.get("rule_id") in rule_ids and exp_tag(e) in by_tag:
            blocked[exp_tag(e)].add(e["rule_id"])
    live = [r for r in requests if r["phase"] == "live"]
    per_scn = {}
    for name in SCENARIOS:
        sent = [r for r in live if r["scenario"] == name]
        hit = [r for r in sent if r["tag"] in blocked]
        per_scn[name] = {"sent": len(sent), "blocked_by_ai_rule": len(hit), "detection_rate_pct": pct(len(hit), len(sent))}
    normal_live = [r for r in live if r["label"] == "normal"]
    fp = [r for r in normal_live if r["tag"] in blocked]
    attack_live = [r for r in live if r["label"] == "attack"]
    detection = {
        "attack_sent": len(attack_live),
        "attack_blocked_by_ai_rule": sum(r["tag"] in blocked for r in attack_live),
        "detection_rate_pct": pct(sum(r["tag"] in blocked for r in attack_live), len(attack_live)),
        "normal_sent": len(normal_live),
        "normal_blocked_by_ai_rule": len(fp),
        "false_positive_rate_pct": pct(len(fp), len(normal_live)),
        "false_positive_examples": sorted({r["url"].split("exp=")[0].rstrip("?&") for r in fp})[:10],
        "normal_http_status": dict(Counter(str(r["status"]) for r in normal_live)),
        "per_scenario": per_scn,
    }

    return {"run_id": run_id, "params": params, "generation": generation, "lifecycle": lifecycle,
            "shadow_classification": shadow, "live": detection,
            "events_by_type": dict(Counter(e.get("type") for e in events
                                           if e.get("rule_id") in rule_ids or e.get("ip") in (attacker_ip, INJECT_IP)))}


def to_markdown(s):
    g, lv = s["generation"], s["live"]
    lines = [f"# AI 룰 실험 결과 {s['run_id']}", "",
             f"- 설정: {json.dumps(s['params'], ensure_ascii=False)}",
             f"- 룰 생성: {g['generated']}/{g['triggers']} (성공률 {g['success_rate_pct']}%), 모델 {g['model']}, "
             f"평균 시도 {g['attempts_avg']}, 지연 {g['latency_ms']}, 오류 {g['error_kinds']}, "
             f"자동 재무장 {g['auto_rearmed']}건",
             f"- **탐지율: {lv['detection_rate_pct']}%** ({lv['attack_blocked_by_ai_rule']}/{lv['attack_sent']})",
             f"- **오탐율: {lv['false_positive_rate_pct']}%** ({lv['normal_blocked_by_ai_rule']}/{lv['normal_sent']})"
             + (f", 예: {', '.join(lv['false_positive_examples'])}" if lv["false_positive_examples"] else ""),
             f"- 관찰 판정(정답->판정): {s['shadow_classification']}", "",
             "| 시나리오 | rule_id | 정규식 | 생애주기 | 차단 단계 탐지율 |", "| --- | --- | --- | --- | --- |"]
    for n in SCENARIOS:
        r = g["rules"][n]
        life = " → ".join(f"{x['type']}({x.get('reason', '')})".replace("()", "") for x in s["lifecycle"].get(n, []))
        d = lv["per_scenario"][n]
        lines.append(f"| {n} | {r['rule_id']} | `{r['regex']}` | {life or '-'} | "
                     f"{d['detection_rate_pct']}% ({d['blocked_by_ai_rule']}/{d['sent']}) |")
    return "\n".join(lines) + "\n"


# ── 실행 ──────────────────────────────────────────────────────

def cmd_run(a):
    global INJECT_IP
    INJECT_IP = f"198.51.100.{random.randint(1, 254)}"
    run_id = a.run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
    rng = random.Random(a.seed)
    run_dir = HERE / "results" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    params = {"n_attack_per_scenario": a.n_attack, "n_normal": a.n_normal, "seed": a.seed,
              "worker_env": sh("docker", "exec", "aegis-soar-worker", "sh", "-c",
                               "echo $AI_RULE_THRESHOLD $GEMINI_MODEL").split(),
              "sidecar_env": sh("docker", "exec", "aegis-nginx", "sh", "-c",
                                "echo $SHADOW_DURATION $TTL_SECONDS").split()}
    log(f"실행 {run_id} → {run_dir}")
    try:
        log("1/7 실험 도메인·허니팟 경로 등록 (프록시 자동 갱신 30초 대기)")
        setup_routes()
        ips = start_clients()
        attacker_ip = ips[ATTACKER]
        log(f"    공격자 IP {attacker_ip}, 정상 사용자 IP {ips[NORMAL]}")
        # 이전 실행에서 차단목록에 오른 실험용 IP 만 해제 (차단된 IP 는 허니팟 앞에서 막히고 LLM 도 생략됨)
        for ip in (attacker_ip, ips[NORMAL], INJECT_IP):
            sh("docker", "exec", "aegis-redis", "redis-cli", "DEL", f"aegis:blacklist:{ip}")
        time.sleep(32)

        start_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        log("2/7 트리거 (허니팟 접근 / 쿠폰 악용 이벤트 주입)")
        trig = [{"url": s["path"], "label": "attack", "scenario": n, "phase": "trigger", "tag": ""}
                for n, s in SCENARIOS.items() if s["trigger"] == "honeypot"]
        requests = collect([send_from(ATTACKER, run_dir, "trigger", trig, 0.2)])  # 차단목록 등록 전에 모두 도착하도록 빠르게
        for n, s in SCENARIOS.items():
            if s["trigger"] == "inject":
                inject_coupon_trigger(n, s)

        log("3/7 AI 룰 생성 대기")
        rule_map, _ = wait_for_rules(start_ts, {attacker_ip, INJECT_IP}, a.gen_timeout)
        log(f"    {rule_map}")
        rule_ids = [r for r in rule_map.values() if r]

        for phase, wait in (("shadow", "4/7 관찰 단계 트래픽"), ("live", "6/7 차단 단계 트래픽")):
            if phase == "live":
                log("5/7 승격·보관 판정 대기")
                log(f"    {wait_for_judgement(rule_ids, a.judge_timeout)}")
            log(wait)
            att, nor = build_plan(run_id, phase, a.n_attack, a.n_normal, rng)
            requests += collect([send_from(ATTACKER, run_dir, f"{phase}_attack", att, ATTACK_PACE_S),
                                 send_from(NORMAL, run_dir, f"{phase}_normal", nor, NORMAL_PACE_S)])

        log("7/7 로그 적재 대기 후 집계")
        time.sleep(15)
        events = rule_events_since(start_ts)
    finally:
        teardown(a.keep_routes)

    summary = summarize(run_id, requests, events, rule_map, attacker_ip, params)
    (run_dir / "requests.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in requests),
                                            encoding="utf-8")
    (run_dir / "events.json").write_text(json.dumps(events, ensure_ascii=False, indent=1), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    md = to_markdown(summary)
    (run_dir / "summary.md").write_text(md, encoding="utf-8")
    print("\n" + md)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="실험 1회 실행")
    r.add_argument("--run-id")
    r.add_argument("--n-attack", type=int, default=10, help="단계·시나리오별 공격 요청 수")
    r.add_argument("--n-normal", type=int, default=40, help="단계별 정상 요청 수 (60초 100회 미만 유지)")
    r.add_argument("--seed", type=int, default=42)
    r.add_argument("--gen-timeout", type=int, default=240)
    r.add_argument("--judge-timeout", type=int, default=120)
    r.add_argument("--keep-routes", action="store_true", help="실험 도메인/경로를 지우지 않음")
    s = sub.add_parser("send", help="(내부용) 컨테이너 안에서 요청 전송")
    s.add_argument("plan")
    a = p.parse_args()
    if a.cmd == "send":
        cmd_send(a.plan)
    else:
        cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
