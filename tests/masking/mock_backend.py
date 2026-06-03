#!/usr/bin/env python3
"""
Aegis-3 마스킹 검증용 모의 백엔드.

nginx 의 subs_filter(개인정보 마스킹) 모듈 자체를 기능 검증하기 위한 임시 upstream.
MuShop 통합이 아니라 마스킹 모듈의 응답 본문 처리만 검증하는 것이 목적이므로,
stdlib 만으로 5종 응답 framing(① JSON top-level / ② JSON nested / ③ HTML /
④ gzip / ⑤ chunked) × 4종 개인정보(전화/주민/카드/이메일) 페이로드를 서빙한다.

요청: GET /case?id=<row><col>   (예: 1A, 2B, 5D)
  row: 1=JSON top-level, 2=JSON nested, 3=HTML, 4=gzip, 5=chunked
  col: A=전화, B=주민, C=카드, D=이메일

의존성 없음(표준 라이브러리만) → python:3.12-alpine 에서 빌드 없이 바로 구동.
"""
import gzip
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 9100

# 마스킹 누락 발굴이 목적이므로 변형(3자리 지역번호, +태그 이메일 등)을 섞는다.
PAYLOADS = {
    "A": ["010-1234-5678", "010-9876-5432", "031-555-7777"],          # 전화
    "B": ["900101-1234567", "850715-2345678"],                        # 주민
    "C": ["4532-1234-5678-9010", "5500-0000-0000-0004"],              # 카드
    "D": ["user@example.com", "kim.jaewon+work@aegis-3.cloud"],       # 이메일
}

COL_KEY = {"A": "phone", "B": "rrn", "C": "card", "D": "email"}


def _json_top(values):
    obj = {f"{_key}_{i}": v for _key in ["value"] for i, v in enumerate(values)}
    return json.dumps(obj, ensure_ascii=False)


def _json_nested(values, col):
    return json.dumps(
        {
            "customer": {
                "profile": {
                    "label": COL_KEY[col],
                    "records": [{"value": v} for v in values],
                }
            }
        },
        ensure_ascii=False,
    )


def _html(values):
    items = "".join(f"<li>{v}</li>" for v in values)
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>"
        f"<body><h1>customer</h1><ul>{items}</ul></body></html>"
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # chunked 응답을 위해 필수

    def log_message(self, *args):  # 조용히
        pass

    def _send_plain(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_gzip(self, body: bytes, ctype: str):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(body)
        gzbytes = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        # Accept-Encoding 과 무관하게 무조건 gzip 강제 → gzip 한계(매트릭스 ④) 정직 검증.
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(gzbytes)))
        self.end_headers()
        self.wfile.write(gzbytes)

    def _send_chunked(self, chunks, ctype: str):
        """chunks: 바이트 조각 리스트를 chunked 프레이밍으로 전송."""
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for c in chunks:
            if not c:
                continue
            self.wfile.write(f"{len(c):X}\r\n".encode())
            self.wfile.write(c)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") not in ("/case", ""):
            self._send_plain(b"not found", "text/plain")
            return
        qs = parse_qs(parsed.query)
        cid = (qs.get("id", ["1A"])[0]).upper()
        if len(cid) != 2 or cid[0] not in "12345" or cid[1] not in "ABCD":
            self._send_plain(b'{"error":"bad id"}', "application/json")
            return
        row, col = cid[0], cid[1]
        values = PAYLOADS[col]

        if row == "1":  # JSON top-level
            self._send_plain(_json_top(values).encode("utf-8"), "application/json")
        elif row == "2":  # JSON nested
            self._send_plain(_json_nested(values, col).encode("utf-8"), "application/json")
        elif row == "3":  # HTML
            self._send_plain(_html(values).encode("utf-8"), "text/html; charset=utf-8")
        elif row == "4":  # gzip
            self._send_gzip(_json_top(values).encode("utf-8"), "application/json")
        elif row == "5":  # chunked + 대형 본문: nginx 내부 proxy 버퍼 경계 정직 검증
            # 한계 5의 진짜 관심사는 upstream 청크 프레이밍이 아니라 nginx 내부
            # proxy_buffer(~4KB) 경계다. 각 값을 4096/8192/12288 byte 경계를
            # 가로지르도록 배치하고 chunked 로 보낸다. 경계에 걸친 값이
            # 마스킹되지 않으면(또는 nginx writer 가 깨지면) 한계로 검출된다.
            #   ?ctrl=1 : control. 값을 버퍼 경계에서 떨어진 안전 위치에 배치
            #             (대형 본문 자체의 영향과 경계 효과를 분리하기 위함).
            ctrl = qs.get("ctrl", ["0"])[0] == "1"
            size = int(qs.get("size", ["20000"])[0])
            filler = ("Aegis-3 masking load body. customer record line. ")
            buf = bytearray((filler * (size // len(filler) + 1))[:size].encode("utf-8"))
            boundaries = [4096, 8192, 12288, 16384]
            place = [] if qs.get("nopii", ["0"])[0] == "1" else values
            for i, v in enumerate(place):
                vb = v.encode("utf-8")
                b = boundaries[i % len(boundaries)]
                start = (b + 600) if ctrl else (b - len(vb) // 2)
                start = max(0, min(start, size - len(vb) - 1))  # 작은 size 안전 처리
                buf[start:start + len(vb)] = vb
            raw = bytes(buf)
            if qs.get("framing", ["chunked"])[0] == "cl":
                # 동일 대형 본문을 Content-Length 로 전송 (chunked 격리 비교용)
                self._send_plain(raw, "text/plain; charset=utf-8")
            else:
                chunks = [raw[i:i + 1300] for i in range(0, len(raw), 1300)]
                self._send_chunked(chunks, "text/plain; charset=utf-8")


if __name__ == "__main__":
    print(f"[mock-backend] listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
