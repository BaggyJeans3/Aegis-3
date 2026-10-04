#!/usr/bin/env bash
# Cloudflare IP 대역으로 nginx.conf 의 set_real_ip_from 목록(BEGIN/END cloudflare-ips 사이)을 다시 생성한다.
# 대역이 바뀌었는데 갱신하지 않으면 새 엣지에서 온 요청의 방문자 IP 가 복원되지 않아
# rate limit·블랙리스트가 엣지 IP 단위로 걸린다.
#
# 사용(EC2, 저장소 루트):
#   bash scripts/ops/update_cloudflare_ips.sh            # 변경 내용 확인 후 nginx.conf 갱신 + reload
#   DRY_RUN=1 bash scripts/ops/update_cloudflare_ips.sh  # 비교만
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONF="$REPO_ROOT/nginx/nginx.conf"
TMP="$(mktemp)"
trap 'rm -f "$TMP" "$TMP.ips"' EXIT

for v in v4 v6; do
  curl -fsS --max-time 10 "https://www.cloudflare.com/ips-$v"
  echo
done | sed '/^\s*$/d' > "$TMP.ips"

# 응답이 비었거나 CIDR 이 아닌 줄이 있으면(장애·캡티브 포털 등) 아무것도 바꾸지 않는다.
if [ "$(wc -l < "$TMP.ips")" -lt 10 ] || grep -qvE '^[0-9a-fA-F:.]+/[0-9]+$' "$TMP.ips"; then
  echo "✗ Cloudflare 대역 응답이 비정상이라 중단합니다:" >&2
  cat "$TMP.ips" >&2
  exit 1
fi

awk -v ipfile="$TMP.ips" '
  /# BEGIN cloudflare-ips/ {
    print
    while ((getline ip < ipfile) > 0) printf "    set_real_ip_from %s;\n", ip
    skip = 1
    next
  }
  /# END cloudflare-ips/ { skip = 0 }
  !skip
' "$CONF" > "$TMP"

if cmp -s "$CONF" "$TMP"; then
  echo "✓ 변경 없음 (nginx.conf 대역이 최신)"
  exit 0
fi

diff -u "$CONF" "$TMP" || true
if [ -n "${DRY_RUN:-}" ]; then
  echo "(DRY_RUN) nginx.conf 는 바꾸지 않았습니다."
  exit 0
fi

# 바인드 마운트된 파일이라 inode 를 유지하도록 cat 으로 덮어쓴다(mv 하면 컨테이너가 옛 파일을 본다).
cat "$TMP" > "$CONF"
sudo docker exec aegis-nginx nginx -t
sudo docker exec aegis-nginx nginx -s reload
echo "✓ Cloudflare 대역 갱신 + nginx reload 완료. 변경된 nginx.conf 를 커밋하세요."
