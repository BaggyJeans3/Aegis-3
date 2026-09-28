# SOAR 담당 점검 보고서 (탐지 + 큐/파이프라인)

작성: 장재원 · 브랜치 `soar/ci-perf-hardening` · 기준 커밋 `84fcb52`

탐지 로직은 재작성하지 않았습니다. `test_detectors.py`를 수정 전 detector 코드에 돌리면 **탐지 동작 테스트 79개는 그대로 통과**하고, 버그 3건(B1~B3)에 대한 회귀 테스트 6개만 실패합니다. 즉 탐지 쪽에서 바뀐 동작은 버그 수정뿐입니다(큐·알림 쪽 변경은 §2 참고).

---

## 요약

| 항목 | 결과 |
|---|---|
| 1. detector 검증 | 기존 자동 테스트 **0건** → pytest 124개 추가 (detector 105 + worker 19). 버그 5건 발견·수정 |
| 2. 큐 처리량/정합 | 소비 상한 **50 eps 고정**(Beat 2초당 100건) 확인 → 수정 후 **최대 약 410 eps**. 중복 저장 버그 확인·수정 |
| 3. CI 편입 | `.github/workflows/ci.yml`에 `soar-tests`, `soar-engine-image` job 추가 (대시보드 ci.yml에 그대로 옮기면 됨) |
| 4. E2E 데모 | 엔진 룰 11종 트리거 확인 스크립트 `scripts/demo/check_detection.sh`. **[E] 허니팟 단계가 403이 될 가능성** 발견(EC2 확인 필요) |
| 5. k6 임계값 사전 점검 | 운영값(80)은 안전. **시연값(30)이 켜진 상태에서 k6를 돌리면 수 초 안에 k6 IP 자가차단 + Slack/Email 폭주** |
| 6. 임계값 조정 준비 | 모든 detector 임계값을 환경변수로 조정 가능(기본값은 기존과 동일). 9/28 k6 결과에 따라 아래 표대로 조정 |
| 7. 부하 측정 | 로컬 2 vCPU 측정 완료. EC2 측정 명령은 아래 런북에 정리 |
| 8. 프리즈 | 테스트 124/124 통과, CI 재현·actionlint·shellcheck 통과 |

---

## 1. detector 검증 — 부족했던 것과 추가한 것

**기존 검증 내역:** detector에 대한 자동 테스트는 없었습니다. 수동 검증 수단은 `demo.sh` [F] 단계(이벤트 1건 직접 주입)와 `test_waf.py`뿐이었는데, `test_waf.py`는 `process_security_log.delay(log_data="1' OR ...")`처럼 문자열을 넣어 `json.loads`에서 실패하는 상태였습니다.

**추가한 테스트** (`soar/risk_score_engine/tests/`)
- 룰별 경계값: 임계값 바로 아래 / 정확히 / 위 (R-SCAN, R-BOLA, R-ASSET, R-RATE, R-AUTH, R-PAYLOAD 전부)
- 등급 경계 (24/25, 49/50, 80/81) · 점수 상한 100 · 60초/10분 시간창 만료
- **이벤트 계약 테스트**: proxy 5종, sidecar `waf_blocked`, demo [F] 이벤트를 실제 모양 그대로 `/analyze`에 넣고, worker가 읽는 필드가 전부 있는지 확인
- 동시성: 8개 스레드 × 250건 동시 분석 시 집계가 정확한지
- 환경변수 임계값 덮어쓰기 · 잘못된 값이 들어오면 기본값으로 동작하는지

**발견·수정한 버그**

| # | 버그 | 영향 | 수정 |
|---|---|---|---|
| B1 | **X-Forwarded-For에 들어간 사설/루프백 IP가 SSRF(+60)로 탐지됨.** nginx 2-pass(:80 → 127.0.0.1:8081 → proxy) 때문에 XFF가 항상 `"<client>, 127.0.0.1"` | **운영 포함 full 분석 이벤트 전부**에 R-PAYLOAD-002 오탐. `/.env` 1회 접근이 100점(CRITICAL)이 됨 | payload 검사 대상에서 프록시 체인 IP 헤더(XFF, X-Real-IP, CF-Connecting-IP 등) 제외 (`utils.py`) |
| B2 | `..%5c` 정규식의 점이 이스케이프되지 않음 | `ab%5c` 같은 평범한 문자열도 path traversal(+50)로 탐지 | `\.\.%5c` |
| B3 | `status_code`가 null이나 문자열이면 `int()` 예외 → 500 | worker가 4번 재시도한 뒤 이벤트를 버림 | `safe_int` |
| B4 | `/health` 라우트 없음 | `demo_setup.sh`의 엔진 점검이 항상 ⚠(404) | `/health` 추가 (상태 키 수, 분석 건수 노출) |
| B5 | Flask 멀티스레드에서 deque 동시 수정 · IP/세션 키가 영원히 남음 | 부하 시 `deque mutated during iteration` 위험. 메모리가 계속 증가: 1시간 시뮬레이션 기준 원본 515MB(계속 증가) → 수정 88MB(평탄) | `STATE_LOCK` + 1000건마다 10분 넘게 idle인 키 정리 |

**문서와 실제 값의 차이 (코드는 의도대로 동작, 발표 자료 확인용):** 요청량 룰의 실효 임계값은 docstring의 100/200회가 아니라 `max(100, p95 50×3) = 150회`, `max(200, 50×6) = 300회`/60초입니다.

---

## 2. Celery/Redis 큐 — 처리량 점검 준비와 정합

**점검 도구:** `scripts/soar_bench/queue_bench.py`
- proxy/sidecar와 같은 모양의 합성 이벤트를 큐에 넣고 Mongo 저장까지 추적합니다. 소비 eps, 최대 적체, E2E 지연(p50/p95/p99), **정합(유실·중복·필드 누락·점수-등급 불일치)**을 측정합니다.
- 기본 이벤트 믹스는 LLM을 부르지 않도록 구성했습니다. `event_id`는 `bench-<run>-` 접두어, IP는 벤치마크 전용 대역 198.18.0.0/15를 쓰고, `--cleanup`으로 측정 후 정리합니다.

**발견한 문제와 수정**

| # | 문제 | 수정 |
|---|---|---|
| Q1 | Beat 2초마다 **최대 100건만** RPOP → 소비 상한 **50 eps**. 원본 측정 결과 정확히 50.4 eps였고, 워커는 대부분 놀고 있었음(브로커 적체 71건) | `CONSUME_BATCH_SIZE`(기본 1000) + `RPOP count`로 한 번에 여러 건 |
| Q2 | 이벤트마다 Celery 결과를 Redis에 **24시간** 저장(1건 ≈ 511B) → 50 eps에서도 **하루 ~2.2GB**. t3.small(2GB)에서 Redis OOM 위험이고, OOM이 나면 블랙리스트·브로커까지 같이 멈춤 | 파이프라인 태스크 `ignore_result=True`, `result_expires` 1h. 측정 후 결과 키 0개 |
| Q3 | **LLM 단계 예외가 태스크 전체 재시도로 번짐** → Mongo 중복 저장, analyzer(CF/Slack/Email) 보고 최대 4회, 엔진 상태 중복 누적. GEMINI 키가 없는 환경에서 원본 지속 부하 7500건 중 **중복 687건** | LLM 호출만 try로 감쌈 (블랙리스트 등록 등 기존 흐름은 유지) |
| Q4 | 태스크마다 `MongoClient` 새로 생성, 닫지 않음 → 매번 TCP 연결·인증, 모니터 스레드 누적 | 프로세스당 1개 재사용 (fork 이후 PID 기준으로 생성) |
| Q5 | 고위험 이벤트마다 analyzer 보고 → 한 IP의 반복 공격이 Slack/Email/CF API 폭주로 이어짐 | IP별 보고 쿨다운 `REPORT_COOLDOWN_SECONDS`(기본 600, 0이면 기존 동작). Redis 장애 시 fail-open. `demo_cleanup.sh`에서 쿨다운 키 초기화 |
| Q6 | 이벤트 전문을 로그에 출력 | 요약만 출력 |

**정합 확인 결과:** proxy·sidecar·demo 이벤트 필드명이 엔진 입력, worker의 `build_mongo_document`, 포털이 읽는 `security_analysis.*`와 일치합니다(계약 테스트로 고정). 모든 벤치에서 유실 0, 수정 후 중복 0, 필드 누락 0, 점수-등급 불일치 0이었습니다.

---

## 3. CI 편입

`.github/workflows/ci.yml` — 대시보드 담당 ci.yml과 합칠 때는 `jobs:` 아래 **`soar-tests`, `soar-engine-image` 두 블록만 옮기면 됩니다**(다른 job과 의존 관계 없음, 서비스 컨테이너·시크릿 불필요).
- `soar-tests`: Python 3.11, `pip install -r soar/risk_score_engine/requirements-test.txt` 후 detector·worker 테스트를 실행하고 JUnit 리포트를 업로드합니다. google-genai는 스텁 처리해서 설치하지 않습니다.
- `soar-engine-image`: detection-engine 이미지를 빌드해 `/health`와 `/analyze`를 스모크 테스트합니다(XFF 오탐 회귀도 확인).
- 로컬 검증: 깨끗한 venv에서 CI 명령 그대로 105 + 16 통과(이후 쿨다운 테스트 3개 추가, 총 124). actionlint 통과. 이미지 빌드는 레지스트리 접근이 막혀 같은 CMD(gunicorn)로 대신 검증했습니다.
- CI가 실패하면 배포를 막으려면 저장소 Settings → Branches → main 보호 규칙에서 두 체크를 required로 지정해야 합니다.

---

## 4. E2E 데모 — 탐지 트리거

`scripts/demo/check_detection.sh` (EC2에서 실행)
- `engine` 모드: 배포된 detection-engine에 룰별 대표 이벤트 11종을 보내 트리거를 확인합니다. 부작용이 없고, 구버전 엔진이 배포돼 있으면 `/health` 또는 XFF 오탐 체크에서 실패합니다.
- 기본 모드: demo.sh와 같은 요청을 보내고 Mongo(traffic_logs)까지 도달했는지, 어떤 event_type/level/rule_hits로 저장됐는지 확인합니다.

**데모 단계별 트리거 (정적 분석 + 엔진 실측)**

| 단계 | 큐 이벤트 | 엔진 점수 | Mongo 표시 | 시연 임계값 30에서 SOAR |
|---|---|---|---|---|
| [A] 정상 | access_event | 0 | LOW | - |
| [C] SQLi / [D] XSS | waf_blocked (CRS 949110) | 0 | CRITICAL(확정 악성 격상) | 트리거 안 됨(엔진 점수 기준) |
| [E] /.env | **⚠ 아래 참고** | 40 (수정 전 100) | CRITICAL | 이벤트가 오면 트리거 |
| [F] 직접 주입 | blocked_request | 40 (R-ASSET-001) | CRITICAL | **트리거** → LLM → 룰 주입 → [I] 블랙리스트 (변경 영향 없음) |

**⚠ [E] 확인 필요:** 커스텀 룰 `130010`(`\.env`)이 phase 1에서 바로 deny하는데, 사이드카는 CRS 차단 신호(949110/959100)가 있을 때만 큐에 적재합니다. 949110은 phase 2에서만 평가되고 early blocking은 꺼져 있습니다. 따라서 **`/.env`는 허니팟(200)에 도달하지 못하고 403이 되며, SOAR/대시보드에도 기록되지 않을 가능성이 높습니다.** demo.sh는 응답과 상관없이 ✓를 출력해서 드러나지 않습니다. 같은 이유로 `/actuator`, `/api/v1/admin`, 스캐너 UA 등 **커스텀 룰 차단 전체가 대시보드에 안 보입니다.** → EC2에서 `check_detection.sh`로 확인하고, 맞다면 nginx 담당과 아래 중 하나를 결정해야 합니다.
  - (a) `BLOCK_SIGNAL_RULE_IDS`에 커스텀 룰 ID 추가 (환경변수라 코드 변경 없음)
  - (b) 데모 [E]를 허니팟 전용 경로(예: Coraza 예외 처리된 경로)로 변경

---

## 5~6. k6 대비 임계값 사전 점검 → 조정 준비

`scripts/soar_bench/k6_threshold_sim.py` — k6 시나리오별로 큐에 들어올 이벤트 흐름을 재현해 detector에 흘려봅니다.

| 시나리오 | 큐 이벤트 | 등급 분포 | 임계값 80 보고 | 임계값 30 보고 |
|---|---|---|---|---|
| normal | 32,250 | HIGH 99% (R-RATE-002) | 0 | **32,101 (13초 시점부터)** |
| attack | 6,765 | HIGH 96% | 0 | 6,616 |
| mixed | 34,170 | HIGH 99% | 0 | 34,021 |
| mixed + `SPREAD_IPS=1024` | 34,083 | **LOW 93%** | 0 | 2,363 |

(쿨다운 적용 전 호출 수입니다. 수정 후에는 IP당 10분에 1회로 줄어듭니다.)

**결론 / k6 실행 전 체크리스트**
1. **`AI_RULE_THRESHOLD`가 80인지 반드시 확인** (`sudo docker exec aegis-soar-worker printenv AI_RULE_THRESHOLD`). demo_setup.sh 이후 demo_restore.sh를 실행하지 않았다면 30입니다 → 단일 IP 요청량만으로 트리거되어 k6 IP가 블랙리스트(24h) + Cloudflare 차단되고, k6 정상 요청이 403을 받아 `aegis_correct_verdict` 기준이 깨집니다.
2. 모든 VU가 IP 하나를 공유하므로 정상 트래픽이 HIGH로 찍히는 것은 탐지가 정상 동작한 결과입니다. "다수 사용자" 부하는 `-e SPREAD_IPS=1024`로 따로 측정하세요.
3. k6 공격 요청 6종 중 큐에 도달하는 것은 SQLi·XSS 2종뿐입니다(나머지 4종은 커스텀 룰 phase 1 차단 → §4 ⚠와 같은 원인).

**9/28 k6 결과 → 조정 가이드** (전부 soar-worker / detection-engine 환경변수, 코드 수정 불필요)

| k6에서 보이는 현상 | 조정 |
|---|---|
| `SPREAD_IPS` 정상 트래픽인데 R-RATE가 뜸 | `NORMAL_P95_PER_MINUTE` 상향 (기본 50 → 실효 150/300회) |
| 대시보드가 k6 트래픽으로 HIGH 도배 | k6 전용 시간대에 한해 `RATE_HIGH_MIN` 상향, 또는 `SPREAD_IPS` 사용 |
| 정상 404가 많은 사이트에서 R-SCAN 오탐 | `SCAN_FAST_LOW`/`SCAN_FAST_HIGH` 상향 |
| 큐 적체가 줄지 않음 | `CELERY_CONCURRENCY`(기본 4), `CONSUME_BATCH_SIZE`, `BEAT_CONSUME_INTERVAL` |
| Slack 알림이 너무 많음/적음 | `REPORT_COOLDOWN_SECONDS` |

임계값을 바꾸면 `soar/risk_score_engine/tests`의 경계 테스트도 같이 실패합니다(의도한 변경인지 확인하는 안전장치). 기본값을 바꿀 때는 테스트 기대값도 함께 수정하세요.

---

## 7. 큐 처리량 부하 측정 (로컬)

환경: 2 vCPU / 8GB(t3.small과 같은 코어 수), Redis·detection-engine·worker·부하 발생기가 한 머신에 있음. **Mongo는 이미지 다운로드가 막혀 Redis 리스트 싱크(저장 1건당 2ms 지연)로 대체**했습니다. 실제 Mongo 연결 비용은 반영되지 않았습니다.

| 구성 | 버스트 5000건 소비 eps | 비고 |
|---|---|---|
| 원본 | **50** | Beat 상한 |
| 수정, 동시성 2, Flask | 272 | |
| 수정, 동시성 4, Flask | 381 | |
| 수정, 동시성 6, Flask | 375 | 4 초과는 이득 없음(CPU 한계) |
| 수정, 동시성 2, gunicorn | 312 | |
| **수정, 동시성 4, gunicorn (최종)** | **414** | |

| 지속 부하 | 원본 | 최종 |
|---|---|---|
| 250 eps | 소비 49.9 eps, 적체 6,000건(계속 증가), E2E p95 **114초**, 중복 687 | 적체 최대 215건, p95 **1.5초**, 중복 0 |
| 400 eps | - | 적체 최대 262건, p95 1.5초 |
| 550 eps | - | 소비 409 eps(한계), 적체 증가, 유실 0 |

E2E p95 1.5초는 대부분 Beat 2초 주기 대기 시간입니다. k6 normal 최대 부하(100 VU ≈ 250 RPS)를 원본은 감당하지 못하고(4분 테스트 이벤트 약 3.2만 건 중 테스트가 끝날 때 약 2만 건이 적체, 해소까지 약 7분 더 걸리고 그동안 대시보드가 지연), 수정본은 감당합니다.

**EC2 측정 런북 (9/29)**
```bash
# 1) 배포 후 엔진 확인
curl -s localhost:5001/health
./scripts/demo/check_detection.sh engine
# 2) 큐 벤치 (워커 컨테이너 안에서 실행 — mongodb 포트는 호스트에 노출돼 있지 않음)
sudo docker cp scripts/soar_bench/queue_bench.py aegis-soar-worker:/tmp/
sudo docker exec aegis-soar-worker python /tmp/queue_bench.py \
  --redis redis://redis:6379/0 --mongo-from-env --count 5000 --cleanup            # 버스트
sudo docker exec aegis-soar-worker python /tmp/queue_bench.py \
  --redis redis://redis:6379/0 --mongo-from-env --count 30000 --rate 250 --cleanup # 지속
# 3) 관찰
sudo docker stats --no-stream; sudo docker exec aegis-redis redis-cli info memory | grep used_memory_human
```

---

## 8. 코드 프리즈 체크리스트

- [x] 테스트 124/124 통과 (detector 105, worker 19)
- [x] CI 워크플로 로컬 재현 · actionlint · shellcheck 통과
- [x] 변경 파일 줄바꿈(LF/CRLF)을 원본과 동일하게 유지 → diff에 실제 변경만 포함
- [ ] 대시보드 담당 ci.yml에 두 job 병합
- [ ] EC2 배포 후 `check_detection.sh` 실행 (특히 §4 ⚠ [E])
- [ ] k6 전 `AI_RULE_THRESHOLD=80` 확인
- [ ] 9/29 EC2 큐 벤치 수치로 §7 표 갱신

**롤백:** detection-engine은 Dockerfile CMD를 `python -m soar.risk_score_engine.app`로 되돌리면 되고, worker 설정은 환경변수로 기존 값 복원이 가능합니다(`CONSUME_BATCH_SIZE=100`, `CELERY_CONCURRENCY=2`, `REPORT_COOLDOWN_SECONDS=0`).

---

## 팀 결정이 필요한 사항 (SOAR 범위 밖이거나 동작 정책 변경)

1. **허니팟 단건 접근의 SOAR 자동 대응 (운영 임계값 80).** 기존에는 B1 오탐 덕분에 우연히 100점이 되어 대응이 발동했습니다. 수정 후에는 40점이라 발동하지 않습니다(시연 설정 30에서는 발동). 허니팟 접근을 확정 악성으로 보고 대응하려면 worker에서 `honeypot_hit`의 AI 판정 점수를 격상하는 정책 추가가 필요합니다(1줄, 결정 후 적용).
2. **점수 80 경계 불일치.** 엔진은 `alert`를 80 **초과**로 판정(80 = HIGH)하는데, worker의 AI/보고는 80 **이상**에서 발동합니다. 정확히 80점(예: 관리자 경로 + 로그인 실패 10회)이면 alert=False인데 CF 차단은 실행됩니다. `AI_RULE_THRESHOLD=81`로 맞출지 결정이 필요합니다.
3. **X-Forwarded-For 스푸핑 (proxy 담당, 보안 이슈).** proxy는 XFF 첫 값을 client IP로 믿습니다. Cloudflare 뒤에서도 공격자가 `X-Forwarded-For: <피해자 IP>`를 보내면 블랙리스트를 우회할 수 있고, **피해자 IP가 Cloudflare 차단**될 수 있습니다. 운영에서는 `CF-Connecting-IP`를 우선 쓰는 것을 권장합니다. 단, demo.sh가 XFF로 공격자 IP를 흉내 내므로 시연 이후에 바꾸는 것이 안전합니다.
4. **커스텀 룰 차단의 대시보드 누락 (nginx 담당).** §4 ⚠ 참고.

**알려진 한계 (프리즈 이후 과제):** Celery 기본 설정(early ack)과 RPOP 이후 `.delay` 사이에 워커가 죽으면 해당 이벤트가 유실될 수 있습니다. 또 동시 처리로 이벤트 도착 순서가 섞이면 시간창 정리가 약간 부정확해질 수 있습니다(영향 작음).
