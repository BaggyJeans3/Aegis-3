# Aegis-3 마스킹 효과 검증 결과 (5×4 매트릭스)

자동 생성: `tests/masking/run_matrix.py` (프론트 nginx :8080 → 2-pass → 모의 백엔드)

## 검증 결론

응답 본문 위치 5종 × 개인정보 4종 매트릭스로 마스킹 누락을 발굴했다.
JSON(top/nested)·HTML·chunked 는 전 항목 마스킹 성공, gzip 압축 응답만 구조적
한계로 미적용(아래 한계 4). 4KB 를 넘는 대형 응답도 정상 마스킹된다(대형 본문 검증 절 참고).

## 핵심 발견 — Coraza 응답 본문 필터 ↔ subs_filter 충돌

- **발견**: subs_filter 마스킹을 켠 뒤, 응답 본문이 nginx proxy 버퍼(4096B)를 넘는
  순간 응답이 0바이트로 잘렸다. nginx 로그에 `zero size buf in writer` alert.
- **분석(격리 실험)**: subs 단독(Coraza off)은 8KB·60KB 모두 정상 마스킹, Coraza
  단독(subs off)도 정상. **둘을 같은 pass 에 켜야만** 실패. 진단 로그로 subs 출력
  체인(`ctx->out`)은 정상(4096+나머지, 빈 버퍼 없음)인데 writer 는 빈 버퍼를 봄 →
  **subs 가 만든 recycled 버퍼를 같은 pass 의 Coraza response body 필터가 받아 깨뜨림**.
  coraza-nginx 0.11.0 은 `SecResponseBodyAccess Off` 로도 body 필터를 체인에서 빼지
  못하고(실측 확인), 응답 본문만 끄는 디렉티브도 없다(`coraza on|off` 이진뿐, off 는
  요청 WAF 까지 끔).
- **결정**: 두 필터를 **서로 다른 server(pass)로 분리**(nginx.conf 2-pass 구조).
  프론트 server(:80, coraza on)는 요청측 WAF 전담, 내부 server(:8081, coraza off)는
  subs 마스킹 전담. 내부 server 가 이미 마스킹한 평문을 프론트로 올려보내므로 프론트의
  Coraza 필터는 일반 버퍼만 다뤄 충돌하지 않는다.
- **효과**: (1) 4KB 초과 대형 응답 마스킹 정상화, (2) 요청측 WAF 유지(공격 403),
  (3) Coraza 응답 본문 검사 비활성화로 부하 테스트 잔여 과제였던 응답 본문 버퍼링
  p95 지연도 함께 해소.

## 5×4 매트릭스

|   | 전화번호 | 주민번호 | 카드번호 | 이메일 | 비고 |
|---|---|---|---|---|------|
| ① JSON top-level | ✅ | ✅ | ✅ | ✅ | - |
| ② JSON nested | ✅ | ✅ | ✅ | ✅ | - |
| ③ HTML | ✅ | ✅ | ✅ | ✅ | - |
| ④ gzip 압축 응답 | ❌ | ❌ | ❌ | ❌ | 한계 4(gzip): Accept-Encoding 비우는 정상 경로에선 발생 불가. 백엔드가 gzip 강제 시 본문 필터가 압축 바디를 검사 못해 마스킹 미적용. 누출: 010-1234-5678, 010-9876-5432, 031-555-7777, 4532-1234-5678-9010, 5500-0000-0000-0004, 850715-2345678, 900101-1234567, kim.jaewon+work@aegis-3.cloud, user@example.com |
| ⑤ chunked transfer | ✅ | ✅ | ✅ | ✅ | 한계 5(chunked): 20KB 대형 본문을 1300B chunk 로 전송, 각 값을 nginx 내부 proxy 버퍼(4096/8192/12288B) 경계에 가로지르도록 배치해 검증. |

범례: ✅ 마스킹됨(원본 미노출) / ❌ 누출 / ⚠️ 부분 누출 / ⛔ 비정상 응답

<details><summary>raw status</summary>

```
1A=200 1B=200 1C=200 1D=200
2A=200 2B=200 2C=200 2D=200
3A=200 3B=200 3C=200 3D=200
4A=200 4B=200 4C=200 4D=200
5A=200 5B=200 5C=200 5D=200
```
</details>

## 대형 본문 검증 (zero-size-buf 회귀 방지)

proxy 버퍼(4096B)를 넘는 응답에서 마스킹이 적용되고 응답이 끊기지 않는지 확인.
(2-pass 분리 전에는 4096B 이상에서 `zero size buf in writer` 로 0바이트 잘림)

| 본문 크기 | HTTP | 수신 바이트 | 원본 전화번호 누출 |
|---|---|---|---|
| 3,900B | 200 | 3,901 | ✅ 0 |
| 4,096B | 200 | 4,097 | ✅ 0 |
| 8,000B | 200 | 8,001 | ✅ 0 |
| 60,000B | 200 | 60,001 | ✅ 0 |
| 200,000B | 200 | 200,001 | ✅ 0 |
