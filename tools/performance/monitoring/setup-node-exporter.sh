#!/bin/bash
#
# setup-node-exporter.sh — install Prometheus node_exporter as a systemd service
# on the INDEXER host (Tracks B/C). Runs from boot, so host CPU/RAM/disk are
# captured from t=0 — before the indexer service is even started — which is what
# lets Track C measure the indexer's cold start.
#
#   sudo ./setup-node-exporter.sh [--version 1.8.2]
#
set -e

NE_VERSION="1.8.2"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) NE_VERSION="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version X.Y.Z]"; exit 1 ;;
    esac
done

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) NE_ARCH="amd64" ;;
    aarch64|arm64) NE_ARCH="arm64" ;;
    *) echo "[ERROR] Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

URL="https://github.com/prometheus/node_exporter/releases/download/v${NE_VERSION}/node_exporter-${NE_VERSION}.linux-${NE_ARCH}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[INFO] Downloading node_exporter ${NE_VERSION} (${NE_ARCH})"
curl -sS --fail -L "$URL" -o "$TMP/node_exporter.tar.gz"
tar -xzf "$TMP/node_exporter.tar.gz" -C "$TMP"
install -m 0755 "$TMP/node_exporter-${NE_VERSION}.linux-${NE_ARCH}/node_exporter" /usr/local/bin/node_exporter

useradd --no-create-home --shell /usr/sbin/nologin node_exporter 2>/dev/null || true

cat > /etc/systemd/system/node_exporter.service <<'EOF'
[Unit]
Description=Prometheus node_exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now node_exporter

echo "[INFO] node_exporter running on :9100 (enabled at boot)."
echo "[INFO] Verify: curl -s http://localhost:9100/metrics | head"
