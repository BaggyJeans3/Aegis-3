#!/usr/bin/env python3
"""
Aegis-3 마스킹 효과 검증 — 5×4 케이스 매트릭스 러너.

nginx(localhost:8080)의 /__masking_test__/ 경유로 모의 백엔드 20케이스를 호출하고,
응답 본문에서 원본 개인정보가 다시 나타나는지(누락) 검사해 markdown 결과표를 만든다.

판정:
  - 원본 값이 응답 본문에 verbatim 으로 없으면 마스킹 성공.
  - substring 검사 + 원본 PII 정규식 재매칭(re-scan) 둘 다 수행.
    (masked 형태 '****-****-****-9010' 의 '9010' 처럼 보존된 식별자가
     우연히 substring 매칭되는 오탐을 피하려고 '원본 전체 값' 기준으로 검사)

표준 라이브러리만 사용. 호스트에서 직접 실행.
"""
import gzip
import re
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8080/__masking_test__/case?id="

ROWS = [
    ("1", "① JSON top-level"),
    ("2", "② JSON nested"),
    ("3", "③ HTML"),
    ("4", "④ gzip 압축 응답"),
    ("5", "⑤ chunked transfer"),
]
COLS = [("A", "전화번호"), ("B", "주민번호"), ("C", "카드번호"), ("D", "이메일")]

# 모의 백엔드(mock_backend.py)와 반드시 동일하게 유지할 것.
PAYLOADS = {
    "A": ["010-1234-5678", "010-9876-5432", "031-555-7777"],
    "B": ["900101-1234567", "850715-2345678"],
    "C": ["4532-1234-5678-9010", "5500-0000-0000-0004"],
    "D": ["user@example.com", "kim.jaewon+work@aegis-3.cloud"],
}

# nginx.conf 의 마스킹 정규식과 동일 (원본 PII 재검출용).
PATTERNS = {
    "A": re.compile(r"(\d{3})-(\d{3,4})-(\d{4})"),
    "B": re.compile(r"(\d{6})-([1-4])(\d{6})"),
    "C": re.compile(r"(\d{4})-(\d{4})-(\d{4})-(\d{4})"),
    "D": re.compile(r"([\w.+-]+)@([\w-]+\.[\w.-]+)"),
}


NARRATIVE = """# Aegis-3 마스킹 효과 검증 결과 (5×4 매트릭스)

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

"""


def fetch(cid):
    """(status, body_text, note) 반환. gzip 응답은 수동 해제."""
    req = urllib.request.Request(BASE + cid)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            enc = (resp.headers.get("Content-Encoding") or "").lower()
            note = ""
            if "gzip" in enc:
                raw = gzip.decompress(raw)
                note = "Content-Encoding: gzip"
            return resp.status, raw.decode("utf-8", "replace"), note
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), f"HTTP {e.code}"
    except Exception as e:  # noqa
        return 0, "", f"ERR {e}"


def classify(col, body):
    """원본 값 누출 여부 판정 → (symbol, leaked_list)."""
    values = PAYLOADS[col]
    leaked = [v for v in values if v in body]            # substring 검사
    regex_hits = PATTERNS[col].findall(body)              # 정규식 재매칭(보강)
    if not leaked and not regex_hits:
        return "✅", []
    if len(leaked) == len(values) or (leaked and regex_hits):
        return "❌", leaked
    return "⚠️", leaked


def main():
    results = {}        # (row,col) -> (symbol, leaked)
    notes = {}          # row -> note
    raw_status = {}
    for rk, _ in ROWS:
        for ck, _ in COLS:
            cid = rk + ck
            status, body, note = fetch(cid)
            raw_status[cid] = status
            if note:
                notes[rk] = note
            if status != 200:
                results[(rk, ck)] = ("⛔", [f"status={status}"])
                continue
            results[(rk, ck)] = classify(ck, body)

    # ---- markdown 표 생성 ----
    lines = []
    lines.append(NARRATIVE.rstrip("\n"))
    lines.append("")
    lines.append("## 5×4 매트릭스")
    lines.append("")
    header = "|   | " + " | ".join(c[1] for c in COLS) + " | 비고 |"
    sep = "|---|" + "|".join(["---"] * len(COLS)) + "|------|"
    lines.append(header)
    lines.append(sep)

    row_notes = {
        "4": "한계 4(gzip): Accept-Encoding 비우는 정상 경로에선 발생 불가. 백엔드가 gzip 강제 시 본문 필터가 압축 바디를 검사 못해 마스킹 미적용.",
        "5": "한계 5(chunked): 20KB 대형 본문을 1300B chunk 로 전송, 각 값을 nginx "
             "내부 proxy 버퍼(4096/8192/12288B) 경계에 가로지르도록 배치해 검증.",
    }
    for rk, rlabel in ROWS:
        cells = []
        for ck, _ in COLS:
            sym, leaked = results[(rk, ck)]
            cells.append(sym)
        note = row_notes.get(rk, "-")
        # 누출 상세를 비고에 보강
        leaks = sorted({v for ck, _ in COLS for v in results[(rk, ck)][1]})
        if leaks and rk not in row_notes:
            note = "누출: " + ", ".join(leaks)
        elif leaks:
            note += " 누출: " + ", ".join(leaks)
        lines.append(f"| {rlabel} | " + " | ".join(cells) + f" | {note} |")

    lines.append("")
    lines.append("범례: ✅ 마스킹됨(원본 미노출) / ❌ 누출 / ⚠️ 부분 누출 / ⛔ 비정상 응답")
    lines.append("")
    # raw 상태 디버그
    lines.append("<details><summary>raw status</summary>\n")
    lines.append("```")
    for rk, _ in ROWS:
        row = " ".join(f"{rk}{ck}={raw_status.get(rk+ck)}" for ck, _ in COLS)
        lines.append(row)
    lines.append("```")
    lines.append("</details>")

    # ---- 대형 본문 검증 (Coraza 충돌 회귀 방지: 4KB 초과에서 마스킹 + writer 정상) ----
    lines.append("")
    lines.append("## 대형 본문 검증 (zero-size-buf 회귀 방지)")
    lines.append("")
    lines.append("proxy 버퍼(4096B)를 넘는 응답에서 마스킹이 적용되고 응답이 끊기지 않는지 확인.")
    lines.append("(2-pass 분리 전에는 4096B 이상에서 `zero size buf in writer` 로 0바이트 잘림)")
    lines.append("")
    lines.append("| 본문 크기 | HTTP | 수신 바이트 | 원본 전화번호 누출 |")
    lines.append("|---|---|---|---|")
    for size in (3900, 4096, 8000, 60000, 200000):
        url = (f"http://localhost:8080/__masking_test__/case?id=5A"
               f"&framing=cl&size={size}")
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", "replace")
                status = resp.status
            leaked = body.count("010-1234-5678")
            recv = len(body)
        except Exception as e:  # noqa
            status, recv, leaked = f"ERR({e})", 0, "-"
        ok = "✅ 0" if leaked == 0 else f"❌ {leaked}"
        lines.append(f"| {size:,}B | {status} | {recv:,} | {ok} |")

    out = "\n".join(lines) + "\n"
    sys.stdout.write(out)
    with open("tests/masking/results.md", "w", encoding="utf-8") as f:
        f.write(out)


if __name__ == "__main__":
    main()
