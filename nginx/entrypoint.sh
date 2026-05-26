#!/bin/sh
set -e

mkdir -p /etc/nginx/rules /var/log/coraza
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