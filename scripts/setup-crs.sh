#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX_DIR="$ROOT_DIR/nginx"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[Aegis-3] Downloading OWASP Core Rule Set..."
git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$TMP_DIR/coreruleset"

echo "[Aegis-3] Installing CRS into nginx/crs..."
rm -rf "$NGINX_DIR/crs"
mkdir -p "$NGINX_DIR/crs"
cp -R "$TMP_DIR/coreruleset/"* "$NGINX_DIR/crs/"
cp "$NGINX_DIR/crs/crs-setup.conf.example" "$NGINX_DIR/crs-setup.conf"

echo "[Aegis-3] CRS installed."
echo "- CRS directory: $NGINX_DIR/crs"
echo "- CRS setup:     $NGINX_DIR/crs-setup.conf"
echo
echo "Next: docker compose down && docker compose up -d --build"
