#!/bin/sh
set -e

mkdir -p /etc/nginx/rules /var/log/coraza

# Sync static rule files from image baseline into the nginx_dynamic_rules
# volume on every start. Without this, a pre-existing volume keeps the OLD
# rules even after the image is rebuilt with new files.
#
# dynamic.conf is owned by the sidecar (AI WAF rule generator) and MUST be
# preserved across restarts, so it is explicitly skipped.
if [ -d /opt/aegis-rules-baseline ]; then
    for f in /opt/aegis-rules-baseline/*.conf; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        [ "$name" = "dynamic.conf" ] && continue
        cp -f "$f" "/etc/nginx/rules/$name"
    done
fi

[ -f /etc/nginx/rules/dynamic.conf ] || touch /etc/nginx/rules/dynamic.conf

# Sidecar (룰 주입 API) 백그라운드 기동
node /opt/sidecar/sidecar.js &
SIDECAR_PID=$!

cleanup() {
    kill -TERM "$SIDECAR_PID" 2>/dev/null || true
}
trap cleanup TERM INT

# Nginx foreground
nginx -g 'daemon off;' &
NGINX_PID=$!

wait "$NGINX_PID"
EXIT=$?
cleanup
exit "$EXIT"
